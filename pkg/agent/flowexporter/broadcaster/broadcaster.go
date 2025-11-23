package broadcaster

import (
	"sync"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"k8s.io/apimachinery/pkg/util/sets"
)

const subsciberBuffer = 2

type Payload struct {
	Conns  []*connection.Connection
	L7Data map[connection.ConnectionKey]connection.L7ProtocolFields
}

type subscription struct {
	ch chan Payload
}

func (s *subscription) C() <-chan Payload {
	return s.ch
}

type broadcaster struct {
	incoming chan Payload

	subscribers     sets.Set[*subscription]
	subscriberMutex sync.Mutex
}

func New() *broadcaster {
	b := &broadcaster{
		incoming:        make(chan Payload),
		subscribers:     sets.Set[*subscription]{},
		subscriberMutex: sync.Mutex{},
	}
	return b
}

func (b *broadcaster) Subscribe() *subscription {
	b.subscriberMutex.Lock()
	defer b.subscriberMutex.Unlock()

	sub := &subscription{
		ch: make(chan Payload, subsciberBuffer),
	}
	b.subscribers.Insert(sub)
	return sub
}

func (b *broadcaster) Unsubscribe(sub *subscription) {
	b.subscriberMutex.Lock()
	defer b.subscriberMutex.Unlock()

	b.subscribers.Delete(sub)
	close(sub.ch)
}

func (b *broadcaster) Publish(conns []*connection.Connection, l7EventMap map[connection.ConnectionKey]connection.L7ProtocolFields) {
	b.incoming <- Payload{
		Conns:  conns,
		L7Data: l7EventMap,
	}
}

func (b *broadcaster) PublishDeniedConnection(conn *connection.Connection) {
	b.Publish([]*connection.Connection{conn}, nil)
}

func (b *broadcaster) Start(stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		case payload := <-b.incoming:
			func() {
				b.subscriberMutex.Lock()
				defer b.subscriberMutex.Unlock()

				for k := range b.subscribers {
					// Make a new copy of each connection for every subscriber since each subscriber may modify the content.
					// TODO: This is very expensive given the size of each Connection struct. Optimize this by sharing part
					// of the data.
					conns := make([]*connection.Connection, 0, len(payload.Conns))
					for idx := range payload.Conns {
						conn := *payload.Conns[idx]
						conns = append(conns, &conn)
					}
					k.ch <- Payload{
						Conns:  conns,
						L7Data: payload.L7Data,
					}
				}
			}()
		}
	}
}
