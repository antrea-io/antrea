package connections

import (
	"sync/atomic"
	"time"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"k8s.io/klog/v2"
)

type CTStore interface {
	Run(stopCh <-chan struct{})
	GetEntries() map[connection.ConnectionKey]connection.Connection
	SubmitConnections(batch []connection.Connection)

	Subscribe() *subscriber
	Unsubscribe(*subscriber)
}

type snapshot struct {
	entries map[connection.ConnectionKey]connection.Connection
}

type subscriber struct {
	ch chan UpdateMsg
}

func (s *subscriber) C() <-chan UpdateMsg {
	return s.ch
}

type ctStore struct {
	updateCh chan []connection.Connection // Used to receive new connections
	addSubCh chan *subscriber
	delSubCh chan *subscriber

	entries map[connection.ConnectionKey]*connection.Connection

	staleConnectionTimeout time.Duration

	snapshot atomic.Pointer[snapshot]

	subs map[*subscriber]struct{}
}

func NewConntrackStore(staleConnTimeout time.Duration) *ctStore {
	store := &ctStore{
		updateCh: make(chan []connection.Connection, 10),
		addSubCh: make(chan *subscriber, 10),
		delSubCh: make(chan *subscriber, 10),

		entries:                make(map[connection.ConnectionKey]*connection.Connection, 1000),
		staleConnectionTimeout: staleConnTimeout,
		subs:                   make(map[*subscriber]struct{}),
	}

	store.snapshot.Store(&snapshot{
		entries: make(map[connection.ConnectionKey]connection.Connection),
	})

	return store
}

func (s *ctStore) Run(stopCh <-chan struct{}) {
	klog.V(5).Info("DEBUGX: ctStore started")

	for {
		select {
		case <-stopCh:
			return
		case batch := <-s.updateCh:
			klog.V(5).InfoS("DEBUGX2: received new ct batch", "len", len(batch))
			s.updateConnections(batch)
		case sub := <-s.addSubCh:
			s.subs[sub] = struct{}{}
		case sub := <-s.delSubCh:
			delete(s.subs, sub)
		}
	}
}

func (s *ctStore) GetEntries() map[connection.ConnectionKey]connection.Connection {
	return s.snapshot.Load().entries
}

func (s *ctStore) updateConnections(batch []connection.Connection) {
	msgs := make([]UpdateMsg, 0, len(batch))
	now := time.Now()
	for i := range batch {
		in := batch[i] // Copy the connection
		in.IsPresent = true
		in.LastUpdateTime = now

		key := connection.NewConnectionKey(&in)
		e, ok := s.entries[key]
		if !ok {
			e = &in
			s.entries[key] = e
		} else {
			e.IsPresent = in.IsPresent
			e.StopTime = in.StopTime
			e.OriginalPackets = in.OriginalPackets
			e.OriginalBytes = in.OriginalBytes
			e.ReversePackets = in.ReversePackets
			e.ReverseBytes = in.ReverseBytes
			e.TCPState = in.TCPState
			// There are some changes, we made an update.
			if (in.OriginalPackets > e.OriginalPackets) || (in.ReversePackets > e.ReversePackets) || (in.TCPState != e.TCPState) {
				klog.V(5).InfoS("DEBUGX4: Conn updated", "key", key)
				e.LastUpdateTime = in.LastUpdateTime
			}
		}

		// e.IsActive = utils.CheckConntrackConnActive(e)
		e.IsActive = time.Since(e.LastUpdateTime) > s.staleConnectionTimeout

		msgs = append(msgs, UpdateMsg{
			Key:     key,
			Deleted: false,
		})
	}

	ssEntries := make(map[connection.ConnectionKey]connection.Connection, len(s.entries))
	for k, v := range s.entries {
		ssEntries[k] = *v
	}

	s.snapshot.Store(&snapshot{
		entries: ssEntries,
	})

	for sub := range s.subs {
		for _, msg := range msgs {
			sub.ch <- msg
		}
	}
}

// AddConnections implements ConnStore.
func (s *ctStore) SubmitConnections(batch []connection.Connection) {
	if len(batch) == 0 {
		return
	}

	s.updateCh <- batch
}

type UpdateMsg struct {
	Key     connection.ConnectionKey
	Deleted bool
}

func (s *ctStore) Subscribe() *subscriber {
	sub := &subscriber{
		ch: make(chan UpdateMsg, 100),
	}
	s.addSubCh <- sub
	return sub
}

func (s *ctStore) Unsubscribe(sub *subscriber) {
	if sub != nil {
		s.delSubCh <- sub
	}
}
