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
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test data types
// ---------------------------------------------------------------------------

type bar struct {
	X int64
	Y int64
	S string
}

type foo struct {
	A    int64
	B    int64
	C    int64
	D    int64
	Name string
	Bar  *bar
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

func TestProduceConsumeSingle(t *testing.T) {
	buf := NewBroadcastBuffer[int](8)
	c := buf.NewConsumer()

	buf.Produce(42)

	val, n, lost, shutdown := c.Consume()
	require.False(t, shutdown, "unexpected shutdown")
	require.Equal(t, 1, n)
	assert.Equal(t, int64(0), lost)
	assert.Equal(t, 42, val)
}

func TestProduceMultipleConsumeMultiple(t *testing.T) {
	buf := NewBroadcastBuffer[int](16)
	c := buf.NewConsumer()

	items := []int{1, 2, 3, 4, 5}
	buf.ProduceMultiple(items)

	out := make([]int, 10)
	n, lost, shutdown := c.ConsumeMultiple(out)
	require.False(t, shutdown, "unexpected shutdown")
	assert.Equal(t, int64(0), lost)
	require.Equal(t, 5, n)
	for i := 0; i < n; i++ {
		assert.Equal(t, i+1, out[i], "out[%d]", i)
	}
}

func TestConsumerBlocksUntilProduce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := NewBroadcastBuffer[int](8)
		c := buf.NewConsumer()

		var val int
		go func() {
			val, _, _, _ = c.Consume()
		}()

		synctest.Wait()
		buf.Produce(99)
		synctest.Wait()

		assert.Equal(t, 99, val)
	})
}

func TestOverwriteReportsLost(t *testing.T) {
	buf := NewBroadcastBuffer[int](4)
	c := buf.NewConsumer()

	for i := 0; i < 8; i++ {
		buf.Produce(i)
	}

	out := make([]int, 10)
	n, lost, shutdown := c.ConsumeMultiple(out)
	require.False(t, shutdown, "unexpected shutdown")
	assert.Equal(t, int64(4), lost)
	require.Equal(t, 4, n)
	for i := 0; i < n; i++ {
		assert.Equal(t, i+4, out[i], "out[%d]", i)
	}
}

func TestMultipleConsumersIndependent(t *testing.T) {
	buf := NewBroadcastBuffer[int](16)
	c1 := buf.NewConsumer()
	c2 := buf.NewConsumer()

	for i := 0; i < 5; i++ {
		buf.Produce(i)
	}

	for _, c := range []Consumer[int]{c1, c2} {
		out := make([]int, 10)
		n, lost, shutdown := c.ConsumeMultiple(out)
		require.False(t, shutdown, "unexpected shutdown")
		assert.Equal(t, int64(0), lost)
		assert.Equal(t, 5, n)
	}
}

func TestPowerOfTwoRoundup(t *testing.T) {
	buf := NewBroadcastBuffer[int](5)
	c := buf.NewConsumer()

	for i := 0; i < 8; i++ {
		buf.Produce(i)
	}

	out := make([]int, 16)
	n, _, _ := c.ConsumeMultiple(out)
	assert.Equal(t, 8, n)
}

func TestShutdownDrainsFirst(t *testing.T) {
	buf := NewBroadcastBuffer[int](16)
	c := buf.NewConsumer()

	buf.Produce(1)
	buf.Produce(2)
	buf.Produce(3)
	buf.Shutdown()

	for expected := 1; expected <= 3; expected++ {
		val, n, _, shutdown := c.Consume()
		if shutdown && n == 0 {
			require.Fail(t, "got shutdown before draining item", "item %d", expected)
		}
		require.Equal(t, 1, n)
		assert.Equal(t, expected, val)
	}

	_, n, _, shutdown := c.Consume()
	assert.True(t, shutdown, "expected shutdown after draining all items")
	assert.Equal(t, 0, n, "expected n=0 after draining all items")
}

func TestShutdownDrainsFirstConsumeMultiple(t *testing.T) {
	buf := NewBroadcastBuffer[int](16)
	c := buf.NewConsumer()

	buf.Produce(10)
	buf.Produce(20)
	buf.Shutdown()

	out := make([]int, 10)
	n, _, shutdown := c.ConsumeMultiple(out)
	require.Equal(t, 2, n)
	if !shutdown {
		n, _, shutdown = c.ConsumeMultiple(out)
		assert.True(t, shutdown)
		assert.Equal(t, 0, n)
	}
}

func TestShutdownUnblocksWaitingConsumer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := NewBroadcastBuffer[int](8)
		c := buf.NewConsumer()

		var shutdown bool
		go func() {
			_, _, _, shutdown = c.Consume()
		}()

		synctest.Wait()
		buf.Shutdown()
		synctest.Wait()

		assert.True(t, shutdown, "expected shutdown=true")
	})
}

func TestProduceAfterShutdownPanics(t *testing.T) {
	buf := NewBroadcastBuffer[int](8)
	buf.Shutdown()

	assert.Panics(t, func() {
		buf.Produce(1)
	}, "expected panic from Produce after Shutdown")
}

func TestProduceMultipleAfterShutdownPanics(t *testing.T) {
	buf := NewBroadcastBuffer[int](8)
	buf.Shutdown()

	assert.Panics(t, func() {
		buf.ProduceMultiple([]int{1, 2})
	}, "expected panic from ProduceMultiple after Shutdown")
}

func TestDoubleShutdownPanics(t *testing.T) {
	buf := NewBroadcastBuffer[int](8)
	buf.Shutdown()

	assert.Panics(t, func() {
		buf.Shutdown()
	}, "expected panic from double Shutdown")
}

func TestConsumeAfterShutdownReturnsImmediately(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := NewBroadcastBuffer[int](8)
		c := buf.NewConsumer()
		buf.Produce(1)
		buf.Produce(2)
		buf.Shutdown()

		val, n, _, shutdown := c.Consume()
		require.Equal(t, 1, n)
		assert.Equal(t, 1, val)
		assert.False(t, shutdown)

		val, n, _, shutdown = c.Consume()
		require.Equal(t, 1, n)
		assert.Equal(t, 2, val)
		assert.True(t, shutdown)

		var n2 int
		var shutdown2 bool
		go func() {
			_, n2, _, shutdown2 = c.Consume()
		}()
		synctest.Wait()

		assert.Equal(t, 0, n2)
		assert.True(t, shutdown2)
	})
}

func TestNewConsumerAfterShutdownReturnsImmediately(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := NewBroadcastBuffer[int](8)
		buf.Produce(1)
		buf.Shutdown()

		c := buf.NewConsumer()

		var n int
		var shutdown bool
		go func() {
			_, n, _, shutdown = c.Consume()
		}()
		synctest.Wait()

		assert.Equal(t, 0, n)
		assert.True(t, shutdown)

		c2 := buf.NewConsumer()
		out := make([]int, 10)
		n, _, shutdown = c2.ConsumeMultiple(out)
		assert.Equal(t, 0, n)
		assert.True(t, shutdown)
	})
}

func TestNewConsumerAfterShutdownWithDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := NewBroadcastBuffer[int](8)
		buf.Shutdown()

		c := buf.NewConsumer(WithMaxConsumeDeadline(50 * time.Millisecond))

		var n int
		var shutdown bool
		go func() {
			_, n, _, shutdown = c.Consume()
		}()
		synctest.Wait()

		assert.Equal(t, 0, n)
		assert.True(t, shutdown)
	})
}

func TestConcurrentProduceConsume(t *testing.T) {
	const (
		numItems    = 10_000
		numConsumer = 4
		bufSize     = 1024
	)
	buf := NewBroadcastBuffer[int](bufSize)

	var wg sync.WaitGroup

	for ci := 0; ci < numConsumer; ci++ {
		wg.Add(1)
		c := buf.NewConsumer()
		go func() {
			defer wg.Done()
			out := make([]int, 64)
			for {
				_, _, shutdown := c.ConsumeMultiple(out)
				if shutdown {
					return
				}
			}
		}()
	}

	for i := 0; i < numItems; i++ {
		buf.Produce(i)
	}
	buf.Shutdown()

	wg.Wait()
}

// TestNoLostWakeup stresses the Produce→Broadcast path to detect lost wakeups.
// Consumers use no deadline (no ticker), so if Broadcast is missed, they hang.
// Runs multiple rounds to increase the chance of hitting the race window.
// This test intentionally uses real time and scheduling to trigger race conditions.
func TestNoLostWakeup(t *testing.T) {
	for round := 0; round < 50; round++ {
		buf := NewBroadcastBuffer[int](16)
		c := buf.NewConsumer()

		done := make(chan struct{})
		go func() {
			for {
				_, _, _, shutdown := c.Consume()
				if shutdown {
					close(done)
					return
				}
			}
		}()

		for i := 0; i < 100; i++ {
			buf.Produce(i)
			runtime.Gosched()
		}
		buf.Shutdown()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			require.Fail(t, "consumer hung (likely lost wakeup)", "round %d", round)
		}
	}
}

func TestProducerLapsSlowConsumer(t *testing.T) {
	const bufSize = 64
	buf := NewBroadcastBuffer[int](bufSize)
	c := buf.NewConsumer()

	total := bufSize * 4
	for i := 0; i < total; i++ {
		buf.Produce(i)
	}
	buf.Shutdown()

	var totalRead, totalLost int
	out := make([]int, 32)
	for {
		n, lost, shutdown := c.ConsumeMultiple(out)
		totalRead += n
		totalLost += int(lost)
		if shutdown {
			break
		}
	}

	assert.NotZero(t, totalLost, "expected items to be lost when producer laps consumer")
	assert.Equal(t, total, totalRead+totalLost, "read + lost != produced")
	t.Logf("produced=%d read=%d lost=%d", total, totalRead, totalLost)
}

func TestReadFromBeginningPartialBuffer(t *testing.T) {
	const bufSize = 16
	buf := NewBroadcastBuffer[int](bufSize)

	for i := 0; i < 5; i++ {
		buf.Produce(i)
	}

	c := buf.NewConsumer(WithReadFromBeginning())
	out := make([]int, 20)
	buf.Shutdown()

	n, lost, shutdown := c.ConsumeMultiple(out)
	assert.Equal(t, int64(0), lost)
	require.Equal(t, 5, n)
	for i := 0; i < n; i++ {
		assert.Equal(t, i, out[i], "out[%d]", i)
	}
	assert.True(t, shutdown)
}

func TestReadFromBeginningFullBuffer(t *testing.T) {
	const bufSize = 8
	buf := NewBroadcastBuffer[int](bufSize)

	for i := 0; i < bufSize; i++ {
		buf.Produce(i)
	}

	c := buf.NewConsumer(WithReadFromBeginning())
	out := make([]int, 20)
	buf.Shutdown()

	n, lost, _ := c.ConsumeMultiple(out)
	assert.Equal(t, int64(0), lost)
	require.Equal(t, bufSize, n)
	for i := 0; i < n; i++ {
		assert.Equal(t, i, out[i], "out[%d]", i)
	}
}

func TestReadFromBeginningWrappedBuffer(t *testing.T) {
	const bufSize = 8
	buf := NewBroadcastBuffer[int](bufSize)

	total := bufSize * 3
	for i := 0; i < total; i++ {
		buf.Produce(i)
	}

	c := buf.NewConsumer(WithReadFromBeginning())
	out := make([]int, 20)
	buf.Shutdown()

	n, lost, _ := c.ConsumeMultiple(out)
	require.Equal(t, bufSize, n)
	assert.Equal(t, int64(0), lost, "consumer starts at oldest available")
	for i := 0; i < n; i++ {
		expected := total - bufSize + i
		assert.Equal(t, expected, out[i], "out[%d]", i)
	}
	t.Logf("produced=%d read=%d lost=%d", total, n, lost)
}

func TestReadFromBeginningLostDuringRead(t *testing.T) {
	const bufSize = 8
	buf := NewBroadcastBuffer[int](bufSize)

	for i := 0; i < 4; i++ {
		buf.Produce(i)
	}
	c := buf.NewConsumer(WithReadFromBeginning())

	for i := 4; i < 4+bufSize+2; i++ {
		buf.Produce(i)
	}
	buf.Shutdown()

	var totalRead, totalLost int
	out := make([]int, 20)
	for {
		n, lost, shutdown := c.ConsumeMultiple(out)
		totalRead += n
		totalLost += int(lost)
		if shutdown {
			break
		}
	}

	assert.NotZero(t, totalLost, "expected some items to be lost after producer wrapped past consumer")
	t.Logf("read=%d lost=%d", totalRead, totalLost)
}

func TestReadFromBeginningVsDefault(t *testing.T) {
	const bufSize = 16
	buf := NewBroadcastBuffer[int](bufSize)

	for i := 0; i < 10; i++ {
		buf.Produce(i)
	}

	cDefault := buf.NewConsumer()
	cBegin := buf.NewConsumer(WithReadFromBeginning())

	buf.Produce(99)
	buf.Shutdown()

	out := make([]int, 20)
	n, _, _ := cDefault.ConsumeMultiple(out)
	require.Equal(t, 1, n)
	assert.Equal(t, 99, out[0])

	n, _, _ = cBegin.ConsumeMultiple(out)
	assert.Equal(t, 11, n)
}

func TestPositionStartsAtZero(t *testing.T) {
	buf := NewBroadcastBuffer[int](8)
	c := buf.NewConsumer()
	assert.Equal(t, int64(0), c.Position())
}

func TestPositionAdvancesWithReads(t *testing.T) {
	buf := NewBroadcastBuffer[int](8)
	c := buf.NewConsumer()

	buf.ProduceMultiple([]int{1, 2, 3})
	out := make([]int, 10)
	n, _, _ := c.ConsumeMultiple(out)
	require.Equal(t, 3, n)
	assert.Equal(t, int64(3), c.Position())
}

func TestPositionReflectsReadFromBeginningStart(t *testing.T) {
	const bufSize = 8
	buf := NewBroadcastBuffer[int](bufSize)

	total := bufSize * 3
	for i := 0; i < total; i++ {
		buf.Produce(i)
	}

	c := buf.NewConsumer(WithReadFromBeginning())
	// Position reflects the starting point immediately, before any read: the buffer has wrapped
	// bufSize*3/bufSize = 3 times, so the oldest item it still holds is at total-bufSize.
	assert.Equal(t, int64(total-bufSize), c.Position())

	out := make([]int, bufSize)
	n, _, _ := c.ConsumeMultiple(out)
	require.Equal(t, bufSize, n)
	assert.Equal(t, int64(total), c.Position())
}

func TestPositionAdvancesPastLostItems(t *testing.T) {
	const bufSize = 4
	buf := NewBroadcastBuffer[int](bufSize)
	c := buf.NewConsumer()

	for i := 0; i < 2*bufSize; i++ {
		buf.Produce(i)
	}

	out := make([]int, 10)
	n, lost, _ := c.ConsumeMultiple(out)
	require.Equal(t, bufSize, n)
	assert.Equal(t, int64(bufSize), lost)
	// Position reflects readPos having jumped forward past the lost items before reading the
	// batch, landing at the tip once the batch itself (bufSize items) is accounted for too.
	assert.Equal(t, int64(2*bufSize), c.Position())
}

// ---------------------------------------------------------------------------
// Per-slot sequence number tests
// ---------------------------------------------------------------------------

func TestSlotTryLoadDetectsOverwrite(t *testing.T) {
	var s slot[string]

	s.store(5, "v5")
	v, ok := s.tryLoad(5)
	require.True(t, ok)
	assert.Equal(t, "v5", v)

	_, ok = s.tryLoad(4)
	assert.False(t, ok, "a position the slot never held must not match")

	s.store(13, "v13")
	_, ok = s.tryLoad(5)
	assert.False(t, ok, "the slot was overwritten; the old position must no longer be readable")
	v, ok = s.tryLoad(13)
	require.True(t, ok)
	assert.Equal(t, "v13", v)
}

// TestReadAvailableStopsAtGapWithoutSpanningIt exercises readAvailable directly (whitebox) to verify
// the fix for two of the correctness issues on positions and sequence numbers disagreeing: an
// overwrite is always caught via the slot's own sequence number rather than trusted blindly, and a
// call that does jump forward reads only the fresh, contiguous range after the jump — never a mix of
// pre- and post-jump items.
func TestReadAvailableStopsAtGapWithoutSpanningIt(t *testing.T) {
	const bufSize = 8
	rb := NewBroadcastBuffer[int](bufSize)
	buf := rb.(*broadcastBuffer[int])
	c := buf.NewConsumer().(*consumer[int])
	buf.Produce(0)

	out := make([]int, 10)
	n, lost, gap := c.readAvailable(buf.writePos.Load(), out, 0)
	require.Equal(t, 1, n)
	assert.Equal(t, int64(0), lost)
	assert.False(t, gap)
	assert.Equal(t, 0, out[0])
	assert.Equal(t, int64(1), c.readPos)

	// Lap the consumer well past capacity before its next read.
	for i := 1; i <= bufSize*3; i++ {
		buf.Produce(i)
	}
	wp := buf.writePos.Load()

	n2, lost2, gap2 := c.readAvailable(wp, out, 0)
	require.True(t, gap2)
	wantOldest := wp - int64(bufSize)
	assert.Equal(t, wantOldest-1, lost2, "1 is readPos going into this call")
	require.Equal(t, bufSize, n2)
	for i := 0; i < n2; i++ {
		assert.Equal(t, int(wantOldest)+i, out[i], "out[%d]", i)
	}
	assert.Equal(t, wp, c.readPos)
}

// overwriteOldestSlot puts the buffer into the state a producer passes through while lapping a
// consumer sitting at the oldest position: the slot has already been rewritten with the position
// one past the tip, but writePos has not been published yet. A single Produce is in this state
// between its slot write and its writePos store; ProduceMultiple holds it for a whole batch.
func overwriteOldestSlot(b *broadcastBuffer[int], v int) {
	wp := b.writePos.Load()
	b.buf[wp&b.mask].store(wp, v)
}

// TestReadAvailableSkipsOverwrittenHeadRatherThanStalling covers the first slot of the read range
// being overwritten right as it is about to be read. With nothing in the batch yet there is no
// contiguous range to protect, so the position must be counted as lost and the scan must carry on:
// stopping would report n == 0 while the rest of the buffer is still readable, which a caller
// cannot tell apart from a drained buffer.
func TestReadAvailableSkipsOverwrittenHeadRatherThanStalling(t *testing.T) {
	const bufSize = 8
	rb := NewBroadcastBuffer[int](bufSize)
	buf := rb.(*broadcastBuffer[int])
	c := buf.NewConsumer(WithReadFromBeginning()).(*consumer[int])
	for i := 0; i < bufSize; i++ {
		buf.Produce(i)
	}
	wp := buf.writePos.Load()
	require.Equal(t, int64(0), c.readPos)
	overwriteOldestSlot(buf, 100)

	out := make([]int, bufSize)
	n, lost, gap := c.readAvailable(wp, out, 0)
	assert.True(t, gap)
	assert.Equal(t, int64(1), lost, "position 0 was overwritten, so it is lost")
	require.Equal(t, bufSize-1, n, "positions 1 onwards are still readable and must not be withheld")
	assert.Equal(t, []int{1, 2, 3, 4, 5, 6, 7}, out[:n])
	assert.Equal(t, wp, c.readPos)
}

// TestConsumeMultipleDoesNotReportEmptyWhileDataRemains is the same case at the ConsumeMultiple
// level, where it matters to callers: n == 0 is how a caller learns the buffer is drained
// (FlowStreamService ends a non-follow stream on it), so an overwritten head must not produce it
// while readable positions remain. The batch must also still be the contiguous run ending at
// Position(), with the lost position sitting immediately before it.
func TestConsumeMultipleDoesNotReportEmptyWhileDataRemains(t *testing.T) {
	const bufSize = 8
	rb := NewBroadcastBuffer[int](bufSize)
	buf := rb.(*broadcastBuffer[int])
	c := buf.NewConsumer(WithReadFromBeginning())
	for i := 0; i < bufSize; i++ {
		buf.Produce(i)
	}
	overwriteOldestSlot(buf, 100)

	out := make([]int, bufSize)
	n, lost, shutdown := c.ConsumeMultiple(out)
	assert.False(t, shutdown)
	assert.Equal(t, int64(1), lost)
	require.Equal(t, bufSize-1, n)
	assert.Equal(t, []int{1, 2, 3, 4, 5, 6, 7}, out[:n])
	assert.Equal(t, int64(bufSize), c.Position())
	assert.Equal(t, int64(1), c.Position()-int64(n), "batch starts at position 1, right after the lost one")
}

// TestConsumeSkipsOverwrittenPositionRatherThanReturningEmpty is the same case for Consume, whose
// callers read n == 0 with shutdown unset as "the deadline expired with no data available".
func TestConsumeSkipsOverwrittenPositionRatherThanReturningEmpty(t *testing.T) {
	const bufSize = 8
	rb := NewBroadcastBuffer[int](bufSize)
	buf := rb.(*broadcastBuffer[int])
	c := buf.NewConsumer(WithReadFromBeginning())
	for i := 0; i < bufSize; i++ {
		buf.Produce(i)
	}
	overwriteOldestSlot(buf, 100)

	val, n, lost, shutdown := c.Consume()
	assert.False(t, shutdown)
	require.Equal(t, 1, n, "position 0 is gone, but position 1 is readable and must be returned")
	assert.Equal(t, 1, val)
	assert.Equal(t, int64(1), lost)
	assert.Equal(t, int64(2), c.Position())
}

// TestReadAvailableRejectsOverwrittenHeadOfLaterSubCall covers a second readAvailable call within
// the same ConsumeMultiple invocation (offset > 0, e.g. a deadline accumulating over several
// wake-ups) whose very first position is overwritten before it can be read. This call's own local n
// is 0 at that point — indistinguishable, looking at n alone, from the truly-empty-batch case that
// TestReadAvailableSkipsOverwrittenHeadRatherThanStalling exercises — but offset > 0 means the
// caller's batch is not actually empty, so folding this position in as skip-and-count-lost would
// place a lost position after already-read items instead of before them, breaking the very
// contiguity invariant this fix exists to protect.
func TestReadAvailableRejectsOverwrittenHeadOfLaterSubCall(t *testing.T) {
	const bufSize = 8
	rb := NewBroadcastBuffer[int](bufSize)
	buf := rb.(*broadcastBuffer[int])
	c := buf.NewConsumer(WithReadFromBeginning()).(*consumer[int])
	buf.Produce(0)
	buf.Produce(1)

	// First sub-call: a normal, uneventful read of everything available so far.
	out := make([]int, bufSize)
	n1, lost1, gap1 := c.readAvailable(buf.writePos.Load(), out, 0)
	require.Equal(t, 2, n1)
	assert.Equal(t, int64(0), lost1)
	assert.False(t, gap1)
	assert.Equal(t, int64(2), c.readPos)

	// Simulate the race for the second sub-call: the caller's wp snapshot says position 2 exists
	// (readPos < wp), but by the time readAvailable actually gets to it, the slot has already been
	// overwritten by a producer that outran the snapshot — the same race waitForData's fast path
	// leaves open between loading writePos and this call. wp is deliberately a stale value (one
	// past readPos), distinct from the slot's own new, higher sequence number.
	wp := c.readPos + 1
	buf.buf[2&buf.mask].store(2+bufSize, 999)

	n2, lost2, gap2 := c.readAvailable(wp, out, n1)
	assert.True(t, gap2)
	assert.Equal(t, 0, n2, "position 2 must not be skipped past: n1 > 0 already, so this is not an empty batch")
	assert.Equal(t, int64(0), lost2, "position 2 is deferred to the next ConsumeMultiple call, not counted lost here")
	assert.Equal(t, int64(2), c.readPos, "readPos must not advance past the undelivered position 2")
}

// TestConsumeMultipleBatchIsAlwaysContiguous stresses ConsumeMultiple across a producer that laps it
// call returns, out[0:n] must be exactly the run of positions ending at Position(), i.e.
// out[k] == Position()-n+k. Before the fix, a gap found partway through a deadline-accumulation call
// could be folded into the same batch as data read earlier in that call, breaking this invariant
// (and, in FlowStreamService, corrupting the resume token derived from it).
func TestConsumeMultipleBatchIsAlwaysContiguous(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const bufSize = 8
		buf := NewBroadcastBuffer[int](bufSize)
		c := buf.NewConsumer(WithMaxConsumeDeadline(200 * time.Millisecond))

		buf.Produce(0)
		go func() {
			time.Sleep(20 * time.Millisecond)
			for i := 1; i <= bufSize*3; i++ {
				buf.Produce(i)
			}
			buf.Shutdown()
		}()

		out := make([]int, 100)
		var totalRead, totalLost int64
		for {
			n, lost, shutdown := c.ConsumeMultiple(out)
			start := c.Position() - int64(n)
			for k := 0; k < n; k++ {
				require.Equal(t, int(start)+k, out[k], "batch must be one contiguous run (index %d)", k)
			}
			totalRead += int64(n)
			totalLost += lost
			if shutdown {
				break
			}
		}

		assert.Equal(t, int64(1+bufSize*3), totalRead+totalLost, "every produced position is read or accounted as lost")
	})
}

func TestConsumeDeadlineReturnsEmpty(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := NewBroadcastBuffer[int](8)
		c := buf.NewConsumer(WithMaxConsumeDeadline(50 * time.Millisecond))

		_, n, _, shutdown := c.Consume()
		require.False(t, shutdown, "unexpected shutdown")
		assert.Equal(t, 0, n)

		buf.Shutdown()
	})
}

func TestConsumeMultipleAccumulatesOverTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := NewBroadcastBuffer[int](64)
		c := buf.NewConsumer(WithMaxConsumeDeadline(200 * time.Millisecond))

		go func() {
			buf.ProduceMultiple([]int{1, 2, 3})
			time.Sleep(50 * time.Millisecond)
			buf.ProduceMultiple([]int{4, 5})
		}()

		out := make([]int, 100)
		n, _, shutdown := c.ConsumeMultiple(out)

		require.False(t, shutdown, "unexpected shutdown")
		assert.GreaterOrEqual(t, n, 5, "expected at least 5 items")

		buf.Shutdown()
	})
}

func TestConsumeMultipleDeadlineReturnsEmpty(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := NewBroadcastBuffer[int](8)
		c := buf.NewConsumer(WithMaxConsumeDeadline(50 * time.Millisecond))

		n, _, shutdown := c.ConsumeMultiple(make([]int, 10))

		require.False(t, shutdown, "unexpected shutdown")
		assert.Equal(t, 0, n)

		buf.Shutdown()
	})
}

func TestConsumeMultipleReturnWhenFull(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := NewBroadcastBuffer[int](64)
		c := buf.NewConsumer(WithMaxConsumeDeadline(500 * time.Millisecond))

		for i := 0; i < 10; i++ {
			buf.Produce(i)
		}

		out := make([]int, 5)
		n, _, _ := c.ConsumeMultiple(out)

		assert.Equal(t, 5, n, "slice should be full")

		buf.Shutdown()
	})
}

func TestMixedDeadlineConsumers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := NewBroadcastBuffer[int](16)
		cFast := buf.NewConsumer(WithMaxConsumeDeadline(50 * time.Millisecond))
		cSlow := buf.NewConsumer()

		var fastN int
		go func() {
			_, fastN, _, _ = cFast.Consume()
		}()
		synctest.Wait()

		assert.Equal(t, 0, fastN, "fast consumer should return n=0 on deadline")

		var slowVal int
		go func() {
			slowVal, _, _, _ = cSlow.Consume()
		}()

		synctest.Wait()
		buf.Produce(42)
		synctest.Wait()

		assert.Equal(t, 42, slowVal)

		buf.Shutdown()
	})
}

// ---------------------------------------------------------------------------
// Benchmark helpers
// ---------------------------------------------------------------------------

const (
	benchBufSize      = 32 * 1024
	benchNumConsumers = 10
	benchBatchSize    = 100
	benchTotalItems   = 512 * 1024
	benchBackpressure = benchBufSize / 2 // 16K

	benchConsumerDeadline = 100 * time.Millisecond
)

var fixedString100 = strings.Repeat("x", 100)

func generateItems(n int) []*foo {
	items := make([]*foo, n)
	for i := range items {
		items[i] = &foo{
			A:    int64(i),
			B:    int64(i * 2),
			C:    int64(i * 3),
			D:    int64(i * 4),
			Name: fixedString100,
			Bar: &bar{
				X: int64(i * 5),
				Y: int64(i * 6),
				S: fixedString100,
			},
		}
	}
	return items
}

type consumerProgress struct {
	counts []atomic.Int64
}

func newConsumerProgress(n int) *consumerProgress {
	return &consumerProgress{counts: make([]atomic.Int64, n)}
}

func (cp *consumerProgress) add(id int, delta int) {
	cp.counts[id].Add(int64(delta))
}

func (cp *consumerProgress) minConsumed() int64 {
	min := cp.counts[0].Load()
	for i := 1; i < len(cp.counts); i++ {
		v := cp.counts[i].Load()
		if v < min {
			min = v
		}
	}
	return min
}

type consumeStats struct {
	totalItems atomic.Int64
	totalCalls atomic.Int64
}

func (s *consumeStats) record(n int) {
	s.totalItems.Add(int64(n))
	s.totalCalls.Add(1)
}

func (s *consumeStats) avgBatchSize() float64 {
	calls := s.totalCalls.Load()
	if calls == 0 {
		return 0
	}
	return float64(s.totalItems.Load()) / float64(calls)
}

type batchHandler func(batch []*foo)

func jsonBatchHandler() batchHandler {
	enc := json.NewEncoder(io.Discard)
	return func(batch []*foo) {
		_ = enc.Encode(batch)
	}
}

func noopBatchHandler() batchHandler {
	return func([]*foo) {}
}

func runBenchConsumer(
	c Consumer[*foo],
	id int,
	progress *consumerProgress,
	stats *consumeStats,
	handler batchHandler,
) {
	out := make([]*foo, benchBatchSize)

	for {
		n, lost, shutdown := c.ConsumeMultiple(out)
		if lost > 0 {
			panic(fmt.Sprintf("consumer %d: lost %d items", id, lost))
		}
		stats.record(n)
		if n > 0 {
			handler(out[:n])
			progress.add(id, n)
		}
		if shutdown {
			return
		}
	}
}

func runBenchConsumerSingle(
	c Consumer[*foo],
	id int,
	progress *consumerProgress,
	stats *consumeStats,
	handler batchHandler,
) {
	out := make([]*foo, 0, benchBatchSize)

	for {
		out = out[:0]
		var shutdown bool
		for range benchBatchSize {
			val, n, lost, s := c.Consume()
			if lost > 0 {
				panic(fmt.Sprintf("consumer %d: lost %d items", id, lost))
			}
			if n > 0 {
				out = append(out, val)
			}
			if s {
				shutdown = true
				break
			}
		}
		stats.record(len(out))
		if len(out) > 0 {
			handler(out)
			progress.add(id, len(out))
		}
		if shutdown {
			return
		}
	}
}

func benchmarkSingleProduceConsumeMultiple(b *testing.B, newHandler func() batchHandler) {
	items := generateItems(benchTotalItems)
	var stats consumeStats
	b.ResetTimer()

	for b.Loop() {
		buf := NewBroadcastBuffer[*foo](benchBufSize)
		progress := newConsumerProgress(benchNumConsumers)

		var wg sync.WaitGroup
		for ci := 0; ci < benchNumConsumers; ci++ {
			wg.Add(1)
			c := buf.NewConsumer(WithMaxConsumeDeadline(benchConsumerDeadline))
			id := ci
			handler := newHandler()
			go func() {
				defer wg.Done()
				runBenchConsumer(c, id, progress, &stats, handler)
			}()
		}

		produced := 0
		for produced < benchTotalItems {
			minConsumed := progress.minConsumed()
			pending := int64(produced) - minConsumed
			if pending >= benchBackpressure {
				runtime.Gosched()
				continue
			}
			buf.Produce(items[produced])
			produced++
		}
		buf.Shutdown()

		wg.Wait()
	}

	b.Logf("avg ConsumeMultiple batch size: %.1f", stats.avgBatchSize())
}

func benchmarkBatchProduceConsumeMultiple(b *testing.B, newHandler func() batchHandler) {
	items := generateItems(benchTotalItems)
	var stats consumeStats
	b.ResetTimer()

	for b.Loop() {
		buf := NewBroadcastBuffer[*foo](benchBufSize)
		progress := newConsumerProgress(benchNumConsumers)

		var wg sync.WaitGroup
		for ci := 0; ci < benchNumConsumers; ci++ {
			wg.Add(1)
			c := buf.NewConsumer(WithMaxConsumeDeadline(benchConsumerDeadline))
			id := ci
			handler := newHandler()
			go func() {
				defer wg.Done()
				runBenchConsumer(c, id, progress, &stats, handler)
			}()
		}

		produced := 0
		for produced < benchTotalItems {
			minConsumed := progress.minConsumed()
			pending := int64(produced) - minConsumed
			if pending >= benchBackpressure {
				runtime.Gosched()
				continue
			}
			end := produced + benchBatchSize
			if end > benchTotalItems {
				end = benchTotalItems
			}
			batch := items[produced:end]
			buf.ProduceMultiple(batch)
			produced += len(batch)
		}
		buf.Shutdown()

		wg.Wait()
	}

	b.Logf("avg ConsumeMultiple batch size: %.1f", stats.avgBatchSize())
}

func benchmarkSingleProduceConsumeSingle(b *testing.B, newHandler func() batchHandler) {
	items := generateItems(benchTotalItems)
	var stats consumeStats
	b.ResetTimer()

	for b.Loop() {
		buf := NewBroadcastBuffer[*foo](benchBufSize)
		progress := newConsumerProgress(benchNumConsumers)

		var wg sync.WaitGroup
		for ci := 0; ci < benchNumConsumers; ci++ {
			wg.Add(1)
			c := buf.NewConsumer(WithMaxConsumeDeadline(benchConsumerDeadline))
			id := ci
			handler := newHandler()
			go func() {
				defer wg.Done()
				runBenchConsumerSingle(c, id, progress, &stats, handler)
			}()
		}

		produced := 0
		for produced < benchTotalItems {
			minConsumed := progress.minConsumed()
			pending := int64(produced) - minConsumed
			if pending >= benchBackpressure {
				runtime.Gosched()
				continue
			}
			buf.Produce(items[produced])
			produced++
		}
		buf.Shutdown()

		wg.Wait()
	}

	b.Logf("avg Consume batch size: %.1f", stats.avgBatchSize())
}

func benchmarkBatchProduceConsumeSingle(b *testing.B, newHandler func() batchHandler) {
	items := generateItems(benchTotalItems)
	var stats consumeStats
	b.ResetTimer()

	for b.Loop() {
		buf := NewBroadcastBuffer[*foo](benchBufSize)
		progress := newConsumerProgress(benchNumConsumers)

		var wg sync.WaitGroup
		for ci := 0; ci < benchNumConsumers; ci++ {
			wg.Add(1)
			c := buf.NewConsumer(WithMaxConsumeDeadline(benchConsumerDeadline))
			id := ci
			handler := newHandler()
			go func() {
				defer wg.Done()
				runBenchConsumerSingle(c, id, progress, &stats, handler)
			}()
		}

		produced := 0
		for produced < benchTotalItems {
			minConsumed := progress.minConsumed()
			pending := int64(produced) - minConsumed
			if pending >= benchBackpressure {
				runtime.Gosched()
				continue
			}
			end := produced + benchBatchSize
			if end > benchTotalItems {
				end = benchTotalItems
			}
			batch := items[produced:end]
			buf.ProduceMultiple(batch)
			produced += len(batch)
		}
		buf.Shutdown()

		wg.Wait()
	}

	b.Logf("avg Consume batch size: %.1f", stats.avgBatchSize())
}

// ---------------------------------------------------------------------------
// Benchmark entry points
// ---------------------------------------------------------------------------

// ConsumeMultiple-based consumers.

func BenchmarkSingleProduceConsumeMultipleJSON(b *testing.B) {
	benchmarkSingleProduceConsumeMultiple(b, jsonBatchHandler)
}

func BenchmarkBatchProduceConsumeMultipleJSON(b *testing.B) {
	benchmarkBatchProduceConsumeMultiple(b, jsonBatchHandler)
}

func BenchmarkSingleProduceConsumeMultipleNoop(b *testing.B) {
	benchmarkSingleProduceConsumeMultiple(b, noopBatchHandler)
}

func BenchmarkBatchProduceConsumeMultipleNoop(b *testing.B) {
	benchmarkBatchProduceConsumeMultiple(b, noopBatchHandler)
}

// Consume-based consumers (benchBatchSize calls per handler invocation).

func BenchmarkSingleProduceConsumeJSON(b *testing.B) {
	benchmarkSingleProduceConsumeSingle(b, jsonBatchHandler)
}

func BenchmarkBatchProduceConsumeJSON(b *testing.B) {
	benchmarkBatchProduceConsumeSingle(b, jsonBatchHandler)
}

func BenchmarkSingleProduceConsumeNoop(b *testing.B) {
	benchmarkSingleProduceConsumeSingle(b, noopBatchHandler)
}

func BenchmarkBatchProduceConsumeNoop(b *testing.B) {
	benchmarkBatchProduceConsumeSingle(b, noopBatchHandler)
}
