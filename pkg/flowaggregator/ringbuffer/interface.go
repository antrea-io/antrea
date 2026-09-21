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
	// When n == 0 and shutdown is false, the deadline expired with no data available.
	Consume() (val T, n int, lost int64, shutdown bool)
	// ConsumeMultiple blocks until at least one item is available, the consumer's
	// deadline expires, or shutdown is observed (after draining).
	// It accumulates items over time: on each wake-up it reads what is available,
	// and returns when the output slice is full or the deadline would be exceeded
	// by the next wake cycle.
	// n can be 0 if the deadline expired with no data available.
	// out[0:n] is always exactly the contiguous run of positions [Position()-n, Position()),
	// never a mix of two disjoint ranges; a producer lapping the consumer mid-call
	// ends the batch there instead of folding the newer range in, so a caller can
	// always derive the batch's start position from n alone.
	// lost, similarly, is always the sequence immediately before that: callers can
	// rely on [Position()-n-lost, Position()-n) being exactly what was lost.
	ConsumeMultiple(out []T) (n int, lost int64, shutdown bool)
	// Position returns the absolute buffer position of the next item this consumer will read.
	// Positions are assigned once, by Produce/ProduceMultiple, in write order starting at 0 for the
	// first item the buffer ever holds, and are stable across the item's lifetime in the buffer:
	// two consumers agree on the position of a given item regardless of when each of them reads it,
	// which is what lets a position be handed to a different, later consumer (see NewConsumer's
	// WithReadFromBeginning) as a resume point that means the same thing it did when it was issued.
	Position() int64
}

// ConsumerOption configures a new consumer created by NewConsumer.
type ConsumerOption func(*consumerConfig)

type consumerConfig struct {
	maxConsumeDeadline time.Duration
	readFromBeginning  bool
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
	// produced item, or 0 if nothing has been produced yet. It is the same value a freshly created
	// default consumer's Position() would report; it is exposed directly so a caller can learn it
	// without creating and discarding a consumer.
	Tip() int64
}
