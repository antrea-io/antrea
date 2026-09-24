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

import "time"

// Producer defines the write-side operations for the ring buffer.
// In an SPMC setup, only one goroutine should hold this interface.
type Producer[T any] interface {
	// Produce does not block: if buffer is full, the oldest items are overwritten.
	// Panics if called after Shutdown.
	Produce(v T)
	// ProduceMultiple supports writing multiple items at once.
	// Panics if called after Shutdown.
	ProduceMultiple(items []T)
	// Shutdown signals that no more items will be produced.
	// Consumers will continue to drain remaining items before observing shutdown.
	// Panics if called more than once.
	Shutdown()
}

// Consumer defines the read-side operations for a single attached reader.
// Multiple goroutines can each hold their own distinct Consumer instance.
type Consumer[T any] interface {
	// Consume blocks until an item is available, the consumer's deadline expires,
	// or shutdown is observed (after draining).
	// When n == 0 and shutdown is false, the deadline expired: either with no data available, or,
	// if lost > 0, after every available item was overwritten before it could be read.
	// end has the same meaning as in ConsumeMultiple.
	Consume() (val T, n int, lost int64, end int64, shutdown bool)
	// ConsumeMultiple blocks until at least one item is available, the consumer's
	// deadline expires, or shutdown is observed (after draining).
	// It accumulates items over time: on each wake-up it reads what is available,
	// and returns when the output slice is full or the deadline would be exceeded
	// by the next wake cycle. n can be 0 if the deadline expired with no data available, and also
	// with lost > 0 if every available item was overwritten before it could be read: a caller must
	// not read n == 0 alone as "the buffer is drained".
	//
	// end is the absolute buffer position just past everything the call accounted for, whether by
	// delivering it in out or by counting it in lost; it advances on eviction too, so it moves even
	// when n == 0 and lost > 0. Positions are assigned once, by Produce/ProduceMultiple, in write
	// order starting at 0 for the first item the buffer ever holds, and are stable across the item's
	// lifetime in the buffer: two consumers agree on the position of a given item regardless of when
	// each of them reads it, which is what lets a position be handed to a different, later consumer
	// (see WithReadFromSequenceNumber) as a resume point that means the same thing it did when it
	// was issued.
	//
	// out[0:n] is always exactly the contiguous run of positions [end-n, end), never a mix of two
	// disjoint ranges; a producer lapping the consumer mid-call ends the batch there instead of
	// folding the newer range in. lost, similarly, is always the run immediately before that:
	// callers can rely on [end-n-lost, end-n) being exactly what was lost.
	ConsumeMultiple(out []T) (n int, lost int64, end int64, shutdown bool)
}

// ConsumerOption configures a new consumer created by NewConsumer.
type ConsumerOption func(*consumerConfig)

type consumerConfig struct {
	maxConsumeDeadline time.Duration
	readFromBeginning  bool
	// readFromSet distinguishes "resume from position 0" from "no resume point given", which
	// readFrom alone cannot: 0 is a real position, the first one the buffer ever holds.
	readFromSet bool
	readFrom    int64
}

// WithMaxConsumeDeadline caps how long Consume / ConsumeMultiple will block
// before returning (possibly with n == 0). A zero or omitted value means the
// consumer blocks indefinitely until data or shutdown.
//
// Deadlines are approximate: a single background ticker wakes all consumers
// at the minimum deadline interval. A consumer woken just before its deadline
// may re-park and wait up to one additional tick, so actual blocking time can
// slightly exceed the requested deadline.
func WithMaxConsumeDeadline(d time.Duration) ConsumerOption {
	return func(c *consumerConfig) {
		c.maxConsumeDeadline = d
	}
}

// WithReadFromBeginning positions the consumer at the oldest available slot
// in the buffer rather than the current write position. This lets the consumer
// read historical items that are still in the buffer.
//
// The starting position is a best-effort snapshot. If the producer advances
// past it before the consumer's first read, computeLost will detect and
// account for the overwritten items, so correctness is maintained.
func WithReadFromBeginning() ConsumerOption {
	return func(c *consumerConfig) {
		c.readFromBeginning = true
	}
}

// WithReadFromSequenceNumber positions the consumer just past seq, so that the first item it reads
// is the one at seq+1. seq is a position already accounted for elsewhere — typically the end-1 of a
// previous consumer's last read (see Consumer.ConsumeMultiple) — and this consumer picks up exactly
// where that left off. A seq of -1 means nothing has been accounted for yet, so the consumer starts
// at position 0.
//
// A consumer whose resume point has already been overwritten is deliberately not clamped forward to
// the oldest slot still held: it stays positioned behind the buffer, so its first read reports the
// whole evicted span through lost. "Your resume point fell out of the buffer" and "you got lapped
// mid-stream" are the same event, and clamping here would absorb the gap silently instead.
//
// A seq at or beyond the current write position cannot name an item this buffer ever held, so it is
// clamped back to that position and the consumer behaves like a default one, reading only what is
// produced from now on. A caller that wants such a value reported rather than absorbed should test
// it against Tip() first.
//
// This option and WithReadFromBeginning are mutually exclusive; if both are given,
// WithReadFromBeginning wins.
func WithReadFromSequenceNumber(seq int64) ConsumerOption {
	return func(c *consumerConfig) {
		c.readFromSet = true
		c.readFrom = seq
	}
}

// BroadcastBuffer represents the complete system: the producer methods
// plus the factory method to spawn new consumers.
//
// Shutdown must be called when the buffer is no longer needed; it releases
// the background ticker goroutine (if any). Dropping a BroadcastBuffer
// without calling Shutdown will leak the goroutine.
type BroadcastBuffer[T any] interface {
	Producer[T]
	// NewConsumer creates a new independent consumer.
	NewConsumer(opts ...ConsumerOption) Consumer[T]
	// Tip returns the position the next produced item will occupy: one past the most recently
	// produced item, or 0 if nothing has been produced yet. It is the position a freshly created
	// default consumer starts reading at; it is exposed directly so a caller can test a resume point
	// against it (see WithReadFromSequenceNumber) without creating and discarding a consumer.
	Tip() int64
	// Capacity returns how many items the buffer holds before the oldest is overwritten. It never
	// changes, so max(Tip()-Capacity(), 0) is the position of the oldest item still held.
	Capacity() int64
}
