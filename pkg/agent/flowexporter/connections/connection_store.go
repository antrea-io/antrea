package connections

import (
	"sync"
	"time"

	"antrea.io/antrea/pkg/agent/controller/noderoute"
	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/agent/proxy"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/objectstore"
	"k8s.io/klog/v2"
)

type UpdateMsg struct {
	Conns    []*connection.Connection
	L7Events map[connection.ConnectionKey]L7ProtocolFields
	Deleted  bool
}

type subscription struct {
	ch chan UpdateMsg // Same channel as C used by store to notify subscriber
}

func (s *subscription) C() <-chan UpdateMsg {
	return s.ch
}

type MergeFunc func(existing, incoming *connection.Connection) *connection.Connection

func NewConnStore(
	staleConnTimeout time.Duration,
	ctFetcher *ConntrackFetcher,
	podStore objectstore.PodStore,
	proxier proxy.Proxier,
	npQuerier querier.AgentNetworkPolicyInfoQuerier,
	egressQuerier querier.EgressQuerier,
	nodeRouteController *noderoute.Controller,
	isNetworkPolicyOnly bool,
) *ConnStore {
	store := &ConnStore{
		subs:                   make(map[*subscription]struct{}, 5),
		entries:                make(map[connection.ConnectionKey]*connection.Connection, 100),
		ctFetcher:              ctFetcher,
		denyConnUpdates:        make(chan *connection.Connection),
		denyConnectionAugments: DenyConnAugments(podStore, proxier, npQuerier),
		ctConnectionAugments:   CTConnAugments(podStore, proxier, npQuerier, egressQuerier, nodeRouteController, isNetworkPolicyOnly),
	}

	return store
}

var _ (DenyStore) = (*ConnStore)(nil)
var _ (StoreSubscriber) = (*ConnStore)(nil)

type ConnStore struct {
	subs     map[*subscription]struct{}
	subMutex sync.Mutex

	entries      map[connection.ConnectionKey]*connection.Connection
	entriesMutex sync.RWMutex

	ctFetcher       *ConntrackFetcher
	denyConnUpdates chan *connection.Connection

	denyConnectionAugments []Augmenter
	ctConnectionAugments   []Augmenter
}

// HasDenyConn implements DenyStore.
func (s *ConnStore) HasDenyConn(key connection.ConnectionKey) bool {
	s.entriesMutex.RLock()
	defer s.entriesMutex.RUnlock()
	_, ok := s.entries[key]
	return ok
}

func (s *ConnStore) SubmitDenyConn(conn *connection.Connection) {
	if s.denyConnUpdates == nil {
		klog.V(2).InfoS("store can not accept deny connection updates")
		return
	}

	if conn == nil {
		return
	}

	s.denyConnUpdates <- conn
}

func (s *ConnStore) Run(stopCh <-chan struct{}) {
	var ctUpdates <-chan CTResult
	if s.ctFetcher != nil {
		ctUpdates = s.ctFetcher.Start(stopCh)
	}

	// Add stale connection cleanup
	for {
		select {
		case <-stopCh:
			return
		case update := <-ctUpdates:
			s.updateConns(update.conns, update.l7Events, s.ctConnectionAugments, ctConnMerge)
		case denyConn := <-s.denyConnUpdates:
			denyConn.IsDenyFlow = true
			s.updateConns([]*connection.Connection{denyConn}, nil, s.denyConnectionAugments, denyConnMerge)
		}
	}
}

func (s *ConnStore) updateConns(conns []*connection.Connection, l7Events map[connection.ConnectionKey]L7ProtocolFields, augments []Augmenter, mergeFn MergeFunc) {
	if len(conns) == 0 {
		return
	}

	updatedConns := make([]*connection.Connection, 0, len(conns)+len(l7Events))
	updatedConns = s.getL7Conns(updatedConns, l7Events)
	now := time.Now()

	for _, conn := range conns {
		if conn == nil {
			continue
		}

		key := connection.NewConnectionKey(conn)
		existing, ok := s.entries[key]

		if !ok {
			for _, augmenter := range augments {
				augmenter.Augment(conn)
			}
			if !acceptConnection(conn) {
				continue
			}
		} else if !conn.IsDenyFlow && utils.IsConnectionDying(conn) {
			// Dying CT connection
			continue
		}

		conn.LastUpdateTime = now

		updatedConn := mergeFn(existing, conn)
		s.entries[key] = updatedConn
		if _, ok := l7Events[key]; !ok {
			updatedConns = append(updatedConns, updatedConn)
		}
	}

	s.notify(updatedConns, l7Events, false)
}

func (s *ConnStore) getL7Conns(conns []*connection.Connection, l7EventMap map[connection.ConnectionKey]L7ProtocolFields) []*connection.Connection {
	if len(l7EventMap) == 0 {
		return nil
	}

	for key := range l7EventMap {
		conn, ok := s.entries[key]
		if !ok {
			continue
		}

		conns = append(conns, conn)
	}

	return conns
}

func (s *ConnStore) Subscribe() *subscription {
	s.subMutex.Lock()
	defer s.subMutex.Unlock()

	sub := &subscription{
		ch: make(chan UpdateMsg, 100),
	}
	s.subs[sub] = struct{}{}
	return sub
}

func (s *ConnStore) Unsubscribe(sub *subscription) {
	s.subMutex.Lock()
	defer s.subMutex.Unlock()

	if _, ok := s.subs[sub]; ok {
		delete(s.subs, sub)
		close(sub.ch)
	}
}

func (s *ConnStore) notify(conns []*connection.Connection, l7Events map[connection.ConnectionKey]L7ProtocolFields, deleted bool) {
	if len(conns) == 0 {
		return
	}

	s.subMutex.Lock()
	defer s.subMutex.Unlock()

	msg := UpdateMsg{
		Conns:    conns,
		Deleted:  deleted,
		L7Events: l7Events,
	}

	for sub := range s.subs {
		sub.ch <- msg
	}
}

func acceptConnection(conn *connection.Connection) bool {
	if conn.SourcePodName == "" && conn.DestinationPodName == "" {
		klog.V(5).InfoS("Skip this connection as we cannot map any of the connection IPs to a local Pod", "srcIP", conn.FlowKey.SourceAddress.String(), "dstIP", conn.FlowKey.DestinationAddress.String())
		return false
	}
	return true
}

func ctConnMerge(existing, incoming *connection.Connection) *connection.Connection {
	if existing == nil {
		return incoming
	}

	if existing.IsDenyFlow {
		// We sometimes see packets tracked in CT even when the conn is denied
		return existing
	}

	if (incoming.OriginalStats.Packets > existing.OriginalStats.Packets) ||
		(incoming.OriginalStats.ReversePackets > existing.OriginalStats.ReversePackets) ||
		(incoming.TCPState != existing.TCPState) {
		existing.LastUpdateTime = incoming.LastUpdateTime
	}

	existing.StopTime = incoming.StopTime
	existing.OriginalStats = incoming.OriginalStats
	existing.TCPState = incoming.TCPState

	return existing
}

func denyConnMerge(existing, incoming *connection.Connection) *connection.Connection {
	if existing == nil {
		return incoming
	}

	existing.StopTime = incoming.StopTime
	existing.OriginalStats.Bytes += incoming.OriginalStats.Bytes
	existing.OriginalStats.Packets += incoming.OriginalStats.Packets
	existing.LastUpdateTime = incoming.LastUpdateTime

	return existing
}
