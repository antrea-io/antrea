// Copyright 2026 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ringbuffer

import (
	"sync"
	"sync/atomic"
	"time"
)

// nextPowerOf2 rounds v up to the nearest power of 2.
// A power-of-2 capacity lets us replace the expensive modulo operation
// (writePos % capacity) with a bitwise AND (writePos & mask), where
// mask = capacity - 1. This is used on every Produce and Consume call.
func nextPowerOf2(v int) int {
	if v <= 1 {
		return 1
	}
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v |= v >> 32
	v++
	return v
}

// slot wraps a single buffer element so that the producer and consumers can
// access it without a data race, even when the producer laps a slow consumer
// and overwrites the slot concurrently. Uses atomic.Value for race-free
// load/store of arbitrary types.
type slot[T any] struct {
	v atomic.Value
}

func (s *slot[T]) store(val T) {
	s.v.Store(val)
}

func (s *slot[T]) load() T {
	return s.v.Load().(T)
}

// broadcastBuffer is an SPMC ring buffer. It assumes a single producer
// goroutine; concurrent calls to Produce / ProduceMultiple / Shutdown are
// not safe (the caller must serialize them).
//
// writePos and closed are atomic so that consumers can check for available
// data and shutdown without acquiring the mutex. The mutex is only needed
// for cond.Wait() when a consumer must park, and for cond.Broadcast() to
// prevent lost wakeups. This dramatically reduces contention: the fast path
// (data already available) is lock-free for consumers, and the producer
// only briefly acquires the mutex for Broadcast — never during writes.
//
// Shutdown() must be called to release the background ticker goroutine.
// If the buffer is abandoned without Shutdown, the ticker goroutine leaks.
type broadcastBuffer[T any] struct {
	writePos atomic.Int64
	closed   atomic.Bool

	// mu + cond are only used for parking / waking consumers.
	mu   sync.Mutex
	cond *sync.Cond

	buf  []slot[T]
	mask int64

	// wakeInterval is the minimum maxConsumeDeadline across all consumers.
	// Zero means no consumer has a deadline, so no ticker is needed.
	wakeInterval time.Duration
	tickerStop   chan struct{}
}

// NewBroadcastBuffer creates a new broadcast ring buffer.
func NewBroadcastBuffer[T any](capacity int) BroadcastBuffer[T] {
	cap := nextPowerOf2(capacity)
	b := &broadcastBuffer[T]{
		buf:  make([]slot[T], cap),
		mask: int64(cap - 1),
	}
	b.cond = sync.NewCond(&b.mu)
	return b
}

// updateTicker recalculates the ticker interval based on the new consumer's
// deadline. Must be called with b.mu held.
func (b *broadcastBuffer[T]) updateTicker(deadline time.Duration) {
	if deadline <= 0 || b.closed.Load() {
		return
	}
	if b.wakeInterval == 0 || deadline < b.wakeInterval {
		oldInterval := b.wakeInterval
		b.wakeInterval = deadline

		if oldInterval > 0 && b.tickerStop != nil {
			close(b.tickerStop)
		}

		b.tickerStop = make(chan struct{})
		go b.periodicWake(b.wakeInterval, b.tickerStop)
	}
}

func (b *broadcastBuffer[T]) periodicWake(d time.Duration, stop chan struct{}) {
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			b.cond.Broadcast()
		case <-stop:
			return
		}
	}
}

// Produce writes a single item. Panics if called after Shutdown.
// Must only be called from the single producer goroutine.
func (b *broadcastBuffer[T]) Produce(v T) {
	if b.closed.Load() {
		panic("Produce called after Shutdown")
	}
	pos := b.writePos.Load()
	b.buf[pos&b.mask].store(v)
	b.writePos.Store(pos + 1)
	// Acquire the mutex around Broadcast so that no consumer can be between
	// its writePos check and cond.Wait(), which would cause a lost wakeup.
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cond.Broadcast()
}

// ProduceMultiple writes a batch of items atomically: consumers see either
// all or none of the items (writePos is updated once after all slot writes).
// This is intentional — it prevents consumers from observing a half-written
// batch. Must only be called from the single producer goroutine.
func (b *broadcastBuffer[T]) ProduceMultiple(items []T) {
	if b.closed.Load() {
		panic("ProduceMultiple called after Shutdown")
	}
	pos := b.writePos.Load()
	for _, v := range items {
		b.buf[pos&b.mask].store(v)
		pos++
	}
	b.writePos.Store(pos)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cond.Broadcast()
}

func (b *broadcastBuffer[T]) Shutdown() {
	if b.closed.Swap(true) {
		panic("Shutdown called more than once")
	}
	// Hold the mutex for both the broadcast and the ticker teardown.
	// - Broadcast under mu: prevents consumers from being between their
	//   closed/writePos check and cond.Wait(), which would cause a lost wakeup.
	// - tickerStop under mu: updateTicker also runs under mu, so this
	//   prevents a data race on the tickerStop field.
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cond.Broadcast()
	if b.tickerStop != nil {
		close(b.tickerStop)
		b.tickerStop = nil
	}
}

func (b *broadcastBuffer[T]) NewConsumer(opts ...ConsumerOption) Consumer[T] {
	var cfg consumerConfig
	for _, o := range opts {
		o(&cfg)
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.updateTicker(cfg.maxConsumeDeadline)

	wp := b.writePos.Load()
	pos := wp
	if cfg.readFromBeginning {
		capacity := b.mask + 1
		oldest := wp - capacity
		if oldest < 0 {
			oldest = 0
		}
		pos = oldest
	}
	return &consumer[T]{
		rb:       b,
		readPos:  pos,
		deadline: cfg.maxConsumeDeadline,
	}
}

type consumer[T any] struct {
	rb       *broadcastBuffer[T]
	readPos  int64
	deadline time.Duration
}

// computeLost adjusts readPos if the producer has overwritten unread slots.
// wp is a snapshot of writePos; readPos is consumer-local (no lock needed).
//
// Using a snapshot (rather than a fresh writePos load) is deliberate: it keeps
// the lost calculation consistent with the range of slots we're about to read.
// If the producer advances further between the snapshot and the read, those
// additional overwrites are detected on the next Consume/ConsumeMultiple call.
func (c *consumer[T]) computeLost(wp int64) int64 {
	capacity := c.rb.mask + 1
	oldest := wp - capacity
	if c.readPos < oldest {
		lost := oldest - c.readPos
		c.readPos = oldest
		return lost
	}
	return 0
}

// readAvailable copies available items into out[offset:] given a writePos
// snapshot. Each slot is read via an atomic load, so a concurrent overwrite
// by the producer is race-free (no data race). Overwritten items are
// accounted for as lost via computeLost.
//
// Invariant: readPos is always >= (writePos - capacity), enforced by
// computeLost. This guarantees every slot in [readPos, wp) has been written
// at least once, so slot.load() never hits an uninitialized atomic.Value.
//
// Note: if the producer laps this consumer during the read loop (i.e. wraps
// around and overwrites a slot between the wp snapshot and the actual load),
// the consumer may read a value from a newer generation of that slot. This
// is inherent to lossy ring buffers without per-slot sequence numbers.
// The value is still valid (just from a later Produce call); the next
// computeLost call will account for the skipped items.
func (c *consumer[T]) readAvailable(wp int64, out []T, offset int) (n int, lost int64) {
	lost = c.computeLost(wp)

	avail := int(wp - c.readPos)
	remaining := len(out) - offset
	if avail > remaining {
		avail = remaining
	}
	for i := 0; i < avail; i++ {
		out[offset+i] = c.rb.buf[c.readPos&c.rb.mask].load()
		c.readPos++
	}
	return avail, lost
}

// waitForData parks the consumer until writePos advances past readPos,
// shutdown occurs, or the deadline expires. Returns a fresh writePos snapshot
// and whether the consumer should stop (shutdown with nothing to read, or
// deadline expired).
func (c *consumer[T]) waitForData(hasDeadline bool, start time.Time) (wp int64, done bool) {
	b := c.rb

	// Fast path: check without lock.
	wp = b.writePos.Load()
	if wp > c.readPos {
		return wp, false
	}
	if b.closed.Load() {
		return wp, wp <= c.readPos
	}

	// Slow path: must park via cond.Wait (requires mutex).
	b.mu.Lock()
	for {
		wp = b.writePos.Load()
		if wp > c.readPos {
			b.mu.Unlock()
			return wp, false
		}
		if b.closed.Load() {
			b.mu.Unlock()
			return wp, wp <= c.readPos
		}
		if hasDeadline && time.Since(start) >= c.deadline {
			b.mu.Unlock()
			return wp, true
		}
		b.cond.Wait()
	}
}

func (c *consumer[T]) Consume() (val T, n int, lost int64, shutdown bool) {
	hasDeadline := c.deadline > 0
	start := time.Now()

	wp, done := c.waitForData(hasDeadline, start)
	if done {
		var zero T
		if c.rb.closed.Load() && wp <= c.readPos {
			return zero, 0, 0, true
		}
		return zero, 0, 0, false
	}

	lost = c.computeLost(wp)
	val = c.rb.buf[c.readPos&c.rb.mask].load()
	c.readPos++

	// A fresh writePos load is safe here: once closed is true, the single
	// producer has stopped and writePos is frozen, so the load returns its
	// final value. Using a fresh load (rather than the wp snapshot) also
	// correctly handles the edge case where readPos has advanced past wp
	// due to computeLost adjustments.
	if c.rb.closed.Load() && c.rb.writePos.Load() <= c.readPos {
		return val, 1, lost, true
	}
	return val, 1, lost, false
}

func (c *consumer[T]) ConsumeMultiple(out []T) (n int, lost int64, shutdown bool) {
	b := c.rb
	hasDeadline := c.deadline > 0
	var start time.Time
	if hasDeadline {
		start = time.Now()
	}
	totalLost := int64(0)

	for {
		// Snapshot writePos (atomic, no lock) and read available data.
		wp := b.writePos.Load()
		if wp > c.readPos {
			read, readLost := c.readAvailable(wp, out, n)
			totalLost += readLost
			n += read
		}

		if n >= len(out) {
			break
		}

		// Fresh writePos loads in shutdown checks are safe: once closed is
		// true the single producer has stopped and writePos is frozen. See
		// the equivalent comment in Consume.
		if b.closed.Load() && b.writePos.Load() <= c.readPos {
			return n, totalLost, true
		}

		// Without a deadline: return as soon as we have at least one item.
		if !hasDeadline {
			if n > 0 {
				break
			}
			// Park via waitForData (acquires mutex only for cond.Wait).
			_, done := c.waitForData(false, start)
			if done && b.closed.Load() {
				return n, totalLost, true
			}
			continue
		}

		// With a deadline: keep accumulating until the deadline is reached.
		if time.Since(start) >= c.deadline {
			break
		}
		// Park briefly; waitForData returns as soon as new data or deadline.
		_, done := c.waitForData(true, start)
		if done {
			if b.closed.Load() && b.writePos.Load() <= c.readPos {
				return n, totalLost, true
			}
			break
		}
	}

	if b.closed.Load() && b.writePos.Load() <= c.readPos {
		shutdown = true
	}
	return n, totalLost, shutdown
}
