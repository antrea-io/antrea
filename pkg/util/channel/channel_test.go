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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
)

type eventReceiver struct {
	receivedEvents sets.String
	mutex          sync.RWMutex
}

func newEventReceiver() *eventReceiver {
	return &eventReceiver{
		receivedEvents: sets.NewString(),
	}
}

func (r *eventReceiver) receive(e interface{}) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.receivedEvents.Insert(e.(string))
}

func (r *eventReceiver) received() sets.String {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	// Return a copy to prevent race condition
	return r.receivedEvents.Union(nil)
}

func TestSubscribe(t *testing.T) {
	c := NewSubscribableChannel("foo", 100)
	stopCh := make(chan struct{})
	defer close(stopCh)
	go c.Run(stopCh)

	var eventReceivers []*eventReceiver
	for i := 0; i < 100; i++ {
		receiver := newEventReceiver()
		c.Subscribe(receiver.receive)
		eventReceivers = append(eventReceivers, receiver)
	}

	desiredEvents := sets.NewString()
	for i := 0; i < 1000; i++ {
		e := fmt.Sprintf("event-%d", i)
		c.Notify(e)
		desiredEvents.Insert(e)
	}

	var errReceiver int
	var errReceivedEvents sets.String
	assert.NoError(t, wait.PollImmediate(10*time.Millisecond, 100*time.Millisecond, func() (done bool, err error) {
		for i, r := range eventReceivers {
			receivedEvents := r.received()
			if !receivedEvents.Equal(desiredEvents) {
				errReceiver = i
				errReceivedEvents = receivedEvents
				return false, nil
			}
		}
		return true, nil
	}), "Receiver %d failed to receive all events, expected %d events, got %d events", errReceiver, len(desiredEvents), len(errReceivedEvents))
}

func TestNotify(t *testing.T) {
	bufferSize := 100
	c := NewSubscribableChannel("foo", bufferSize)
	stopCh := make(chan struct{})
	defer close(stopCh)
	// Do not run the channel so first N events should be published successfully and later events should fail.
	for i := 0; i < bufferSize; i++ {
		e := fmt.Sprintf("event-%d", i)
		assert.True(t, c.Notify(e), "Failed to publish event when it doesn't exceed the buffer's capacity")
	}

	notifyRes := make(chan bool)
	defer close(notifyRes)
	go func() {
		notifyRes <- c.Notify("foo")
	}()
	select {
	case res := <-notifyRes:
		assert.False(t, res)
	case <-time.After(notifyTimeout + time.Second):
		t.Errorf("Notify() didn't return in time")
	}
}
