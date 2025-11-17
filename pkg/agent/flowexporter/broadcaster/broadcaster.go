// Copyright 2025 Antrea Authors.
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

package broadcaster

import (
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
)

const subsciberBuffer = 2

type Payload struct {
	Conns []*connection.Connection
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

func (b *broadcaster) Publish(conns []*connection.Connection) {
	b.incoming <- Payload{
		Conns: conns,
	}
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
						Conns: conns,
					}
				}
			}()
		}
	}
}
