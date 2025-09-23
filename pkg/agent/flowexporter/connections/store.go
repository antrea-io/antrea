package connections

import (
	"container/heap"
	"maps"
	"slices"
	"sync"
	"time"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"k8s.io/klog/v2"
)

type UpdateMsg struct {
	Conns    []*connection.Connection
	L7Events map[connection.ConnectionKey]L7ProtocolFields
	Deleted  bool
}

type submitMsg struct {
	conns      []*connection.Connection
	l7EventMap map[connection.ConnectionKey]L7ProtocolFields
}

type subscriber struct {
	ch chan UpdateMsg // Same channel as C used by store to notify subscriber
}

func (s *subscriber) C() <-chan UpdateMsg {
	return s.ch
}

var _ Store = (*store)(nil)

type store struct {
	updateCh chan submitMsg // Used to receive new connections
	addSubCh chan *subscriber
	delSubCh chan *subscriber
	subs     map[*subscriber]struct{}

	entries      map[connection.ConnectionKey]*connection.Connection
	entriesMutex sync.RWMutex

	staleConnectionTimeout time.Duration
	gc                     gcHeap
}

// HasConn implements Store.
func (s *store) HasConn(conn *connection.Connection) bool {
	s.entriesMutex.RLock()
	defer s.entriesMutex.RUnlock()
	_, ok := s.entries[conn.FlowKey]
	return ok
}

// Run implements Store.
func (s *store) Run(stopCh <-chan struct{}) {
	klog.V(5).Info("ConnStore started")

	gcStaleTicker := time.NewTicker(s.staleConnectionTimeout)
	defer gcStaleTicker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case batch := <-s.updateCh:
			s.updateConnections(batch.conns, batch.l7EventMap)
			s.getL7Conns(batch.l7EventMap)
		case sub := <-s.addSubCh:
			s.subs[sub] = struct{}{}
		case sub := <-s.delSubCh:
			delete(s.subs, sub)
		case <-gcStaleTicker.C:
			s.removeStaleConnections()
		}
	}
}

// SubmitConnections implements Store.
func (s *store) SubmitConnections(conns []*connection.Connection, l7EventMap map[connection.ConnectionKey]L7ProtocolFields) {
	if len(conns) == 0 {
		return
	}

	// Because of how packetin works, we will be receiving one connection at a time.
	s.updateCh <- submitMsg{
		conns:      conns,
		l7EventMap: l7EventMap,
	}
}

// Subscribe implements Store.
func (s *store) Subscribe() *subscriber {
	sub := &subscriber{
		ch: make(chan UpdateMsg, 100),
	}
	s.addSubCh <- sub
	return sub
}

// Unsubscribe implements Store.
func (s *store) Unsubscribe(sub *subscriber) {
	if sub != nil {
		s.delSubCh <- sub
	}
}

func (s *store) updateConnections(conns []*connection.Connection, l7EventMap map[connection.ConnectionKey]L7ProtocolFields) {
	now := time.Now()

	s.entriesMutex.Lock()
	defer s.entriesMutex.Unlock()

	updatedConns := make([]*connection.Connection, 0, len(conns)+len(l7EventMap))
	for i := range conns {
		in := conns[i]
		in.LastUpdateTime = now

		key := connection.NewConnectionKey(in)

		existing := s.entries[key]

		var conn *connection.Connection
		if in.IsDenyNetworkPolicy {
			conn = denyConnMerge(existing, in)
		} else {
			conn = ctConnMerge(existing, in)
		}

		s.entries[key] = conn

		updatedConns = append(updatedConns, conn)

		heap.Push(&s.gc, &gcItem{
			conn:       conn,
			expiryNano: now.UnixNano() + s.staleConnectionTimeout.Nanoseconds(),
		})
	}

	l7Conns := s.getL7Conns(l7EventMap)
	updatedConns = slices.DeleteFunc(updatedConns, func(c *connection.Connection) bool {
		key := connection.NewConnectionKey(c)
		_, ok := l7Conns[key]
		return ok
	})
	updatedConns = slices.AppendSeq(updatedConns, maps.Values(l7Conns))

	s.notify(updatedConns, l7EventMap, false)
}

func (s *store) getL7Conns(l7EventMap map[connection.ConnectionKey]L7ProtocolFields) map[connection.ConnectionKey]*connection.Connection {
	if len(l7EventMap) == 0 {
		return nil
	}

	l7Conns := make(map[connection.ConnectionKey]*connection.Connection, len(l7EventMap))

	for key := range l7EventMap {
		conn, ok := s.entries[key]
		if !ok {
			continue
		}

		l7Conns[key] = conn
	}

	return l7Conns
}

func (s *store) notify(conns []*connection.Connection, l7Events map[connection.ConnectionKey]L7ProtocolFields, deleted bool) {
	if len(conns) == 0 {
		return
	}

	msg := UpdateMsg{
		Conns:    conns,
		Deleted:  deleted,
		L7Events: l7Events,
	}

	for sub := range s.subs {
		sub.ch <- msg
	}
}

func NewStore(staleConnTimeout time.Duration) Store {
	return &store{
		updateCh: make(chan submitMsg, 10),
		addSubCh: make(chan *subscriber, 10),
		delSubCh: make(chan *subscriber, 10),
		subs:     make(map[*subscriber]struct{}),

		entries:                map[connection.ConnectionKey]*connection.Connection{},
		staleConnectionTimeout: staleConnTimeout,
	}
}

func ctConnMerge(existing, incoming *connection.Connection) *connection.Connection {
	if existing == nil {
		return incoming
	}

	if existing.IsDenyNetworkPolicy {
		// We sometimes see SYN packets trackked in CT even when the conn is denied
		return existing
	}

	if (incoming.OriginalStats.Packets > existing.OriginalStats.Packets) ||
		(incoming.OriginalStats.ReversePackets > existing.OriginalStats.ReversePackets) ||
		(incoming.TCPState != existing.TCPState) {
		existing.LastUpdateTime = incoming.LastUpdateTime
	}

	existing.OriginalStats = incoming.OriginalStats
	existing.TCPState = incoming.TCPState

	return existing
}

func denyConnMerge(existing, incoming *connection.Connection) *connection.Connection {
	if existing == nil {
		return incoming
	}

	existing.OriginalStats.Bytes += incoming.OriginalStats.Bytes
	existing.OriginalStats.Packets += incoming.OriginalStats.Packets
	existing.StopTime = incoming.StopTime
	existing.LastUpdateTime = incoming.LastUpdateTime

	return existing
}

func (s *store) removeStaleConnections() {
	now := time.Now().UnixNano()
	conns := []*connection.Connection{}
	for len(s.gc) > 0 {
		top := s.gc[0]
		if top.expiryNano > now {
			// The top connection is not ready to be deleted, since the connections are sorted
			// by expiry time we can exit here.
			break
		}

		key := connection.NewConnectionKey(top.conn)

		heap.Pop(&s.gc)
		conn, ok := s.entries[key]
		if !ok {
			// Already deleted
			continue
		}

		// This gc item was stale, there's been a recent update to the connection.
		// TODO Andrew: to be more efficient with our memory we should remove old items from
		// the heap before adding it. If we meet the condition that only one connection can
		// exist at a time in the heap, we can always remove it without this check.
		if conn.LastUpdateTime.UnixNano()+s.staleConnectionTimeout.Nanoseconds() > now {
			continue
		}

		delete(s.entries, key)
		conns = append(conns, conn)
	}

	s.notify(conns, nil, true)
}

type gcItem struct {
	conn       *connection.Connection
	expiryNano int64
	index      int
}
type gcHeap []*gcItem

func (h gcHeap) Len() int           { return len(h) }
func (h gcHeap) Less(i, j int) bool { return h[i].expiryNano < h[j].expiryNano }
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
