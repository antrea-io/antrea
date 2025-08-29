package connections

import (
	"sync/atomic"
	"time"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
)

type snapshot struct {
	entries map[connection.ConnectionKey]connection.Connection
}

type ctStore struct {
	updateCh chan []connection.Connection // Used to receive new connections

	entries map[connection.ConnectionKey]*connection.Connection

	staleConnectionTimeout time.Duration

	snapshot atomic.Pointer[snapshot]
}

func NewConntrackStore(staleConnTimeout time.Duration) *ctStore {
	store := &ctStore{
		updateCh:               make(chan []connection.Connection, 10),
		entries:                map[connection.ConnectionKey]*connection.Connection{},
		staleConnectionTimeout: staleConnTimeout,
	}

	store.snapshot.Store(&snapshot{
		entries: make(map[connection.ConnectionKey]connection.Connection),
	})

	return store
}

func (s *ctStore) Run(stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		case batch := <-s.updateCh:
			s.updateConnections(batch)
		}
	}
}

func (s *ctStore) GetEntries() map[connection.ConnectionKey]connection.Connection {
	return s.snapshot.Load().entries
}

func (s *ctStore) updateConnections(batch []connection.Connection) {
	// now := time.Now().UnixMilli()
	for i := range batch {
		in := batch[i] // Copy the connection
		in.IsPresent = true

		key := connection.NewConnectionKey(&in)
		e, ok := s.entries[key]
		if !ok {
			s.entries[key] = &in
		} else {
			e.IsPresent = in.IsPresent
			e.StopTime = in.StopTime
			e.OriginalPackets = in.OriginalPackets
			e.OriginalBytes = in.OriginalBytes
			e.ReversePackets = in.ReversePackets
			e.ReverseBytes = in.ReverseBytes
			e.TCPState = in.TCPState

			e.IsActive = utils.CheckConntrackConnActive(e)
		}
	}

	ssEntries := make(map[connection.ConnectionKey]connection.Connection, len(s.entries))
	for k, v := range s.entries {
		ssEntries[k] = *v
	}

	s.snapshot.Store(&snapshot{
		entries: ssEntries,
	})
}

// AddConnections implements ConnStore.
func (s *ctStore) SubmitConnections(batch []connection.Connection) {
	if len(batch) == 0 {
		return
	}

	s.updateCh <- batch
}
