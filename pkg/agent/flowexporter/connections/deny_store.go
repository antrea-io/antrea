package connections

import (
	"sync"
	"time"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
)

var _ CTStore = (*DenyStore)(nil)

type DenyStore struct {
	updateCh chan submitMsg // Used to receive new connections
	addSubCh chan *subscriber
	delSubCh chan *subscriber
	subs     map[*subscriber]struct{}

	entries      map[connection.ConnectionKey]*connection.Connection
	entriesMutex sync.RWMutex

	staleConnectionTimeout time.Duration
}

func NewDenyStore(staleConnectionTimeout time.Duration) CTStore {
	return &DenyStore{
		updateCh:               make(chan submitMsg),
		addSubCh:               make(chan *subscriber),
		delSubCh:               make(chan *subscriber),
		subs:                   map[*subscriber]struct{}{},
		entries:                map[connection.ConnectionKey]*connection.Connection{},
		staleConnectionTimeout: staleConnectionTimeout,
	}
}

func (ds *DenyStore) Run(stopCh <-chan struct{}) {
	gcStaleTicker := time.NewTicker(ds.staleConnectionTimeout)
	defer gcStaleTicker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case batch := <-ds.updateCh:
			ds.updateConnection(batch.conns[0])
		case sub := <-ds.addSubCh:
			ds.subs[sub] = struct{}{}
		case sub := <-ds.delSubCh:
			delete(ds.subs, sub)
		case <-gcStaleTicker.C:
			ds.removeStaleConnections()
		}
	}
}

func (ds *DenyStore) updateConnection(in *connection.Connection) {
	now := time.Now()
	connKey := connection.NewConnectionKey(in)
	ds.entriesMutex.Lock()
	defer ds.entriesMutex.Unlock()

	in.LastUpdateTime = now

	conn, exists := ds.entries[connKey]
	if exists {
		conn.OriginalStats.Bytes += in.OriginalStats.Bytes
		conn.OriginalStats.Packets += in.OriginalStats.Packets
		conn.StopTime = in.StopTime
		conn.LastUpdateTime = in.LastUpdateTime
	} else {
		ds.entries[connKey] = in
	}

	ds.notify(conn, false)
}

func (ds *DenyStore) notify(conn *connection.Connection, deleted bool) {
	if len(ds.subs) == 0 {
		return
	}
	msg := UpdateMsg{
		Conns:   []*connection.Connection{conn},
		Deleted: deleted,
	}

	for sub := range ds.subs {
		sub.ch <- msg
	}
}

func (ds *DenyStore) removeStaleConnections() {
	// TODO Andrew: Add cleanup for stale connections
}

func (ds *DenyStore) SubmitConnections(conns []*connection.Connection, _ map[connection.ConnectionKey]L7ProtocolFields) {
	if len(conns) == 0 {
		return
	}

	// Because of how packetin works, we will be receiving one connection at a time.
	ds.updateCh <- submitMsg{
		conns:      conns,
		l7EventMap: nil,
	}
}

func (ds *DenyStore) HasConn(conn *connection.Connection) bool {
	ds.entriesMutex.RLock()
	defer ds.entriesMutex.RUnlock()
	_, ok := ds.entries[conn.FlowKey]
	return ok
}

func (ds *DenyStore) Subscribe() *subscriber {
	sub := &subscriber{
		ch: make(chan UpdateMsg, 100),
	}
	ds.addSubCh <- sub
	return sub
}

func (ds *DenyStore) Unsubscribe(sub *subscriber) {
	if sub != nil {
		ds.delSubCh <- sub
	}
}
