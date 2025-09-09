package connections

import (
	"container/heap"
	"sync"
	"time"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"k8s.io/klog/v2"
)

type CTStore interface {
	Run(stopCh <-chan struct{})
	SubmitConnections(batch []*connection.Connection)

	HasConn(*connection.Connection) bool

	Subscribe() *subscriber
	Unsubscribe(*subscriber)
}

type UpdateMsg struct {
	Conns   []*connection.Connection
	Deleted bool
}

type subscriber struct {
	ch chan UpdateMsg // Same channel as C used by store to notify subscriber
}

func (s *subscriber) C() <-chan UpdateMsg {
	return s.ch
}

var _ CTStore = (*connStore)(nil)

type connStore struct {
	updateCh chan []*connection.Connection // Used to receive new connections
	addSubCh chan *subscriber
	delSubCh chan *subscriber
	subs     map[*subscriber]struct{}

	entries      map[connection.ConnectionKey]*connection.Connection
	entriesMutex sync.RWMutex

	// TODO Andrew: What is a stale connection?
	staleConnectionTimeout time.Duration
	gc                     gcHeap
}

func NewConnStore(staleConnTimeout time.Duration) *connStore {
	store := &connStore{
		updateCh: make(chan []*connection.Connection, 10),
		addSubCh: make(chan *subscriber, 10),
		delSubCh: make(chan *subscriber, 10),
		subs:     make(map[*subscriber]struct{}),

		entries: make(map[connection.ConnectionKey]*connection.Connection, 1000),

		staleConnectionTimeout: staleConnTimeout,
	}

	return store
}

func (cs *connStore) Run(stopCh <-chan struct{}) {
	klog.V(5).Info("ConnStore started")

	gcStaleTicker := time.NewTicker(cs.staleConnectionTimeout)
	defer gcStaleTicker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case batch := <-cs.updateCh:
			cs.updateConnections(batch)
		case sub := <-cs.addSubCh:
			cs.subs[sub] = struct{}{}
		case sub := <-cs.delSubCh:
			delete(cs.subs, sub)
		case <-gcStaleTicker.C:
			cs.removeStaleConnections()
		}
	}
}

func (cs *connStore) removeStaleConnections() {
	now := time.Now().UnixNano()
	conns := []*connection.Connection{}
	for len(cs.gc) > 0 {
		top := cs.gc[0]
		if top.expiryMs > now {
			break
		}

		key := connection.NewConnectionKey(top.conn)

		heap.Pop(&cs.gc)
		conn, ok := cs.entries[key]
		if !ok { // Already deleted
			continue
		}

		lastUsedTime := conn.LastUsedTime.Load()
		// TODO Andrew: Do we need to care about "readyToDelete" connections?
		if lastUsedTime+cs.staleConnectionTimeout.Nanoseconds() <= now {
			delete(cs.entries, key)
		}

		conns = append(conns, conn)
	}

	cs.notify(conns, true)
}

func (cs *connStore) updateConnections(batch []*connection.Connection) {
	cs.entriesMutex.Lock()
	defer cs.entriesMutex.Unlock()
	updatedConns := make([]*connection.Connection, 0, len(batch))
	now := time.Now()
	for i := range batch {
		in := batch[i] // Copy the connection
		in.IsPresent = true
		in.LastUpdateTime = now

		key := connection.NewConnectionKey(in)
		e, ok := cs.entries[key]
		if !ok {
			e = in
			cs.entries[key] = e
		} else {
			e.IsPresent = in.IsPresent
			// TODO Andrew: Is this check necessary? Maybe the user of this conn should
			// be the one to determine usage and we focus on storing it.
			if utils.IsConnectionDying(e) {
				return
			}

			// There are some changes since the last update
			if (in.OriginalStats.Packets > e.OriginalStats.Packets) ||
				(in.OriginalStats.ReversePackets > e.OriginalStats.ReversePackets) ||
				(in.TCPState != e.TCPState) {
				e.LastUpdateTime = in.LastUpdateTime
			}

			e.OriginalStats = in.OriginalStats
			e.TCPState = in.TCPState
		}

		updatedConns = append(updatedConns, e)

		lastUsedTime := e.LastUsedTime.Load()
		if lastUsedTime == 0 {
			lastUsedTime = e.UpdateLastUsedTime()
		}

		heap.Push(&cs.gc, &gcItem{
			conn:     e,
			expiryMs: lastUsedTime + cs.staleConnectionTimeout.Nanoseconds(),
		})
	}

	cs.notify(updatedConns, false)
}

func (s *connStore) HasConn(conn *connection.Connection) bool {
	s.entriesMutex.RLock()
	defer s.entriesMutex.RUnlock()
	_, ok := s.entries[conn.FlowKey]
	return ok
}

func (s *connStore) Subscribe() *subscriber {
	sub := &subscriber{
		ch: make(chan UpdateMsg, 100),
	}
	s.addSubCh <- sub
	return sub
}

func (s *connStore) Unsubscribe(sub *subscriber) {
	if sub != nil {
		s.delSubCh <- sub
	}
}

func (s *connStore) SubmitConnections(conns []*connection.Connection) {
	if len(conns) == 0 {
		return
	}

	s.updateCh <- conns
}

func (cs *connStore) notify(conns []*connection.Connection, deleted bool) {
	if len(conns) == 0 {
		return
	}

	msg := UpdateMsg{
		Conns:   conns,
		Deleted: deleted,
	}

	for sub := range cs.subs {
		sub.ch <- msg
	}
}

type gcItem struct {
	conn     *connection.Connection
	expiryMs int64
	index    int
}
type gcHeap []*gcItem

func (h gcHeap) Len() int           { return len(h) }
func (h gcHeap) Less(i, j int) bool { return h[i].expiryMs < h[j].expiryMs }
func (h gcHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *gcHeap) Push(x any) { *h = append(*h, x.(*gcItem)) }
func (h *gcHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}
