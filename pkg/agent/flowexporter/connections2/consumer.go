package connections2

import (
	"container/heap"
	"fmt"
	"time"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
)

type dueItem struct {
	key   connection.ConnKey
	dueMs int64
	index int
}
type dueHeap []*dueItem

func (h dueHeap) Len() int           { return len(h) }
func (h dueHeap) Less(i, j int) bool { return h[i].dueMs < h[j].dueMs }
func (h dueHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *dueHeap) Push(x interface{}) { *h = append(*h, x.(*dueItem)) }
func (h *dueHeap) Pop() interface{} {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}

type Consumer struct {
	name      string
	timeoutMs int64
	store     *Store
	sub       *subscriber

	// scheduling
	heap dueHeap
	idx  map[connection.ConnKey]*dueItem
	last map[connection.ConnKey]uint32 // last sent version

	// send handler
	send func([]connection.FullRecord)

	// internals
	resyncTicker *time.Ticker
	stopCh       chan struct{}
	batchMax     int
}

func NewConsumer(s *Store, timeout time.Duration, name string) *Consumer {
	sub := s.RegisterConsumer()
	c := &Consumer{
		name:         name,
		timeoutMs:    timeout.Milliseconds(),
		store:        s,
		sub:          sub,
		idx:          make(map[connection.ConnKey]*dueItem, 4096),
		last:         make(map[connection.ConnKey]uint32, 4096),
		resyncTicker: time.NewTicker(3 * time.Second),
		stopCh:       make(chan struct{}),
		batchMax:     128,
		send: func(batch []connection.FullRecord) {
			// default send: print
			for _, r := range batch {
				fmt.Printf("[%s] SEND key proto=%d src=%v:%d dst=%v:%d ver=%d metaID=%d\n",
					name, r.Entry.Key.Proto,
					r.Entry.Key.SrcIP, r.Entry.Key.SrcPort,
					r.Entry.Key.DstIP, r.Entry.Key.DstPort,
					r.Entry.Version,
					func() uint32 {
						if r.Meta != nil {
							return r.Meta.ID
						}
						return 0
					}(),
				)
			}
		},
	}
	heap.Init(&c.heap)
	go c.run()
	return c
}

func (c *Consumer) SetSender(f func([]connection.FullRecord)) { c.send = f }

func (c *Consumer) Stop() {
	close(c.stopCh)
	c.store.UnregisterConsumer(c.sub)
}

func (c *Consumer) run() {
	batch := make([]connection.FullRecord, 0, c.batchMax)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		c.send(batch)
		batch = batch[:0]
	}

	flushTicker := time.NewTicker(500 * time.Millisecond)
	defer flushTicker.Stop()

	for {
		now := nowMs()
		// pop due items
		for c.heap.Len() > 0 && c.heap[0].dueMs <= now {
			it := heap.Pop(&c.heap).(*dueItem)
			delete(c.idx, it.key)

			ss := c.store.snap.Load()
			e, ok := ss.ents[it.key]
			if !ok {
				// gone, nothing to do
				delete(c.last, it.key)
				continue
			}
			lastVer := c.last[it.key]
			if e.Version != lastVer {
				// changed -> send full record (merge hot+meta pointer)
				batch = append(batch, connection.FullRecord{Entry: e, Meta: e.Meta})
				c.last[it.key] = e.Version
				if len(batch) >= c.batchMax {
					flush()
				}
			}
			// reschedule according to latest LastUpdateMs (maintain semantics)
			newDue := e.LastUpdateMs + c.timeoutMs
			ni := &dueItem{key: it.key, dueMs: newDue}
			c.idx[it.key] = ni
			heap.Push(&c.heap, ni)
		}

		select {
		case u := <-c.sub.ch:
			if u.deleted {
				// remove schedule & last
				if it := c.idx[u.key]; it != nil {
					heap.Remove(&c.heap, it.index)
					delete(c.idx, u.key)
				}
				delete(c.last, u.key)
				break
			}
			// schedule or update due time
			due := u.lastMs + c.timeoutMs
			if it := c.idx[u.key]; it == nil {
				ni := &dueItem{key: u.key, dueMs: due}
				c.idx[u.key] = ni
				heap.Push(&c.heap, ni)
			} else {
				it.dueMs = due
				heap.Fix(&c.heap, it.index)
			}

		case <-c.resyncTicker.C:
			if c.sub.dirty.Swap(0) == 1 {
				// light resync: rebuild/add missing schedules using snapshot
				ss := c.store.snap.Load()
				for k, e := range ss.ents {
					if _, ok := c.idx[k]; !ok {
						ni := &dueItem{key: k, dueMs: e.LastUpdateMs + c.timeoutMs}
						c.idx[k] = ni
						heap.Push(&c.heap, ni)
					}
				}
			}

		case <-flushTicker.C:
			flush()

		case <-c.stopCh:
			flush()
			return

		default:
			// small sleep to avoid tight loop
			time.Sleep(2 * time.Millisecond)
		}
	}
}
