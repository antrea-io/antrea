// Copyright 2022 Antrea Authors
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

package channel

import (
	"time"

	"k8s.io/klog/v2"
)

const (
	// notifyTimeout is the timeout for failing to publish an event to the channel.
	notifyTimeout = time.Second
)

type eventHandler func(interface{})

type Subscriber interface {
	// Subscribe registers an eventHandler which will be called when an event is sent to the channel.
	// It's not thread-safe and it's supposed to be called serially before first event is published.
	// The eventHandler is supposed to execute quickly and not perform blocking operation. Blocking operation should be
	// deferred to a routine that is triggered by the eventHandler.
	Subscribe(h eventHandler)
}

type Notifier interface {
	// Notify sends an event to the channel.
	Notify(interface{}) bool
}

// SubscribableChannel is different from the Go channel which dispatches every event to only single consumer regardless
// of the number of consumers. Instead, it dispatches every event to all consumers by calling the eventHandlers they
// have registered.
type SubscribableChannel struct {
	// The name of the channel, used for logging purpose to differentiate multiple channels.
	name string
	// eventCh is the channel used for buffering the pending events.
	eventCh chan interface{}
	// handlers is a slice of callbacks registered by consumers.
	handlers []eventHandler
}

func NewSubscribableChannel(name string, bufferSize int) *SubscribableChannel {
	n := &SubscribableChannel{
		name:    name,
		eventCh: make(chan interface{}, bufferSize),
	}
	return n
}

func (n *SubscribableChannel) Subscribe(h eventHandler) {
	n.handlers = append(n.handlers, h)
}

func (n *SubscribableChannel) Notify(e interface{}) bool {
	timer := time.NewTimer(notifyTimeout)
	defer timer.Stop()
	select {
	case n.eventCh <- e:
		return true
	case <-timer.C:
		// This shouldn't happen as we expect handlers to execute quickly and eventCh can buffer some messages.
		// If the error is ever seen, either the buffer is too small, or some handlers have improper workload blocking
		// the event consumption.
		klog.ErrorS(nil, "Failed to send event to channel, will discard it", "name", n.name, "event", e)
		return false
	}
}

func (n *SubscribableChannel) Run(stopCh <-chan struct{}) {
	klog.InfoS("Starting SubscribableChannel", "name", n.name)
	for {
		select {
		case <-stopCh:
			klog.InfoS("Stopping SubscribableChannel", "name", n.name)
			return
		case obj := <-n.eventCh:
			for _, h := range n.handlers {
				h(obj)
			}
		}
	}
}
