// Copyright 2019 Antrea Authors
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

package ram

import (
	"context"
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	"antrea.io/antrea/pkg/apiserver/storage"
)

type bookmarkEvent struct {
	resourceVersion uint64
	object          runtime.Object
}

func (b *bookmarkEvent) ToWatchEvent(selectors *storage.Selectors, isInitEvent bool) *watch.Event {
	return &watch.Event{Type: watch.Bookmark, Object: b.object}
}

func (b *bookmarkEvent) GetResourceVersion() uint64 {
	return b.resourceVersion
}

// storeWatcher implements watch.Interface
type storeWatcher struct {
	// input represents the channel for incoming internal events that should be processed.
	input chan storage.InternalEvent
	// result represents the channel for outgoing events that will be sent to the client.
	result chan watch.Event
	done   chan struct{}
	// selectors represent a watcher's conditions to select objects.
	selectors *storage.Selectors
	// forget is used to cleanup the watcher.
	forget func()
	// stopOnce guarantees Stop function will perform exactly once.
	stopOnce sync.Once
	// newFunc is a function that creates new empty object of this type.
	newFunc func() runtime.Object
}

func newStoreWatcher(chanSize int, selectors *storage.Selectors, forget func(), newFunc func() runtime.Object) *storeWatcher {
	return &storeWatcher{
		input:     make(chan storage.InternalEvent, chanSize),
		result:    make(chan watch.Event, chanSize),
		done:      make(chan struct{}),
		selectors: selectors,
		forget:    forget,
		newFunc:   newFunc,
	}
}

// nonBlockingAdd tries to send event to channel input without blocking.
// It returns true if successful, otherwise false.
func (w *storeWatcher) nonBlockingAdd(event storage.InternalEvent) bool {
	select {
	case w.input <- event:
		return true
	default:
		return false
	}
}

// add tries to send event to channel input. It will first use non blocking
// way, then block until the provided timer fires, if the timer is not nil.
// It returns true if successful, otherwise false.
func (w *storeWatcher) add(event storage.InternalEvent, timer clock.Timer) bool {
	// Try to send the event without blocking regardless of timer is fired or not.
	// This gives the watcher a chance when other watchers exhaust the time slices.
	if w.nonBlockingAdd(event) {
		return true
	}

	if timer == nil {
		return false
	}

	select {
	case w.input <- event:
		return true
	case <-timer.C():
		return false
	}
}

// process first sends initEvents and then keeps sending events got from channel input
// if they are newer than the specified resourceVersion.
func (w *storeWatcher) process(ctx context.Context, initEvents []storage.InternalEvent, resourceVersion uint64) {
	for _, event := range initEvents {
		w.sendWatchEvent(event, true)
	}
	// Send a dummy bookmark event to indicate the end of initEvents. This is
	// an unusual way to use the bookmark event, as it is meant to be used to
	// refresh the last resource version of a client. In Antrea we do not use
	// resource version when restarting a watch, but we need a way to
	// communicate to clients what the initial set of objects is, so that
	// stale objects whose delete events were missed by the client (because
	// the watch was down) can be deleted.
	w.sendWatchEvent(&bookmarkEvent{resourceVersion, w.newFunc()}, true)
	defer close(w.result)
	for {
		select {
		case event, ok := <-w.input:
			if !ok {
				klog.V(4).Info("The input channel has been closed, stopping process for watcher")
				return
			}
			if event.GetResourceVersion() > resourceVersion {
				w.sendWatchEvent(event, false)
			}
		case <-ctx.Done():
			klog.V(4).Info("The context has been canceled, stopping process for watcher")
			return
		}
	}
}

// sendWatchEvent converts an InternalEvent to watch.Event based on the watcher's selectors.
// It sends the converted event to result channel, if not nil.
func (w *storeWatcher) sendWatchEvent(event storage.InternalEvent, isInitEvent bool) {
	watchEvent := event.ToWatchEvent(w.selectors, isInitEvent)
	if watchEvent == nil {
		// Watcher is not interested in that object.
		return
	}

	select {
	case <-w.done:
		return
	default:
	}

	select {
	case w.result <- *watchEvent:
	case <-w.done:
	}
}

// ResultChan returns the channel for outgoing events to the client.
func (w *storeWatcher) ResultChan() <-chan watch.Event {
	return w.result
}

// Stop stops this watcher.
// It must be idempotent and thread safe as it could be called by apiserver endpoint handler
// and dispatchEvent concurrently.
func (w *storeWatcher) Stop() {
	w.stopOnce.Do(func() {
		w.forget()
		close(w.done)
		// forget removes this watcher from the store's watcher list, there won't
		// be events sent to its input channel so we are safe to close it.
		close(w.input)
	})
}
