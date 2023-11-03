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
	"fmt"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	antreastorage "antrea.io/antrea/pkg/apiserver/storage"
)

const (
	// watcherChanSize is the buffer size of watchers.
	watcherChanSize = 1000
	// watcherAddTimeout is the timeout of sending one event to all watchers.
	// Watchers whose buffer can't be available in it will be terminated.
	watcherAddTimeout = 50 * time.Millisecond
)

type watchersMap map[int]*storeWatcher

// store implements ram.Interface, serving the requests for a given resource from its internal cache storage.
type store struct {
	// watcherMutex protects the watchers map from concurrent access during watcher insertion and deletion.
	watcherMutex sync.RWMutex
	// eventMutex is used to avoid race condition when generating events.
	eventMutex sync.RWMutex
	// incomingHWM is HighWaterMark for performance debugging.
	// It records the maximum number of events backed up in incoming channel that have been seen.
	incomingHWM storage.HighWaterMark
	// incoming stores the incoming events that should be dispatched to watchers.
	incoming chan antreastorage.InternalEvent

	// storage is the underlying storage.
	storage cache.Indexer
	// keyFunc is used to get a key in the underlying storage for a given object.
	keyFunc cache.KeyFunc
	// selectFunc is used to check whether a watcher is interested in a given object.
	selectFunc antreastorage.SelectFunc
	// genEventFunc is used to generate InternalEvent from update of an object.
	genEventFunc antreastorage.GenEventFunc
	// newFunc is a function that creates new empty object of this type.
	newFunc func() runtime.Object

	// resourceVersion up to which the store has generated.
	resourceVersion uint64
	// watcherIdx is the index that will be allocated to next watcher and used as key in watchersMap
	// so that a watcher can be deleted from the map according to its index later.
	watcherIdx int
	// watchers is a mapping from the index of a watcher to the watcher.
	watchers watchersMap

	stopCh chan struct{}
	// timer is used when sending events to watchers. Hold it here to avoid unnecessary
	// re-allocation for each event.
	timer clock.Timer
}

func newStoreWithClock(keyFunc cache.KeyFunc, indexers cache.Indexers, genEventFunc antreastorage.GenEventFunc, selectorFunc antreastorage.SelectFunc, newFunc func() runtime.Object, clock clock.Clock) *store {
	stopCh := make(chan struct{})
	storage := cache.NewIndexer(keyFunc, indexers)
	timer := clock.NewTimer(time.Duration(0))
	// Ensure the timer is stopped and drain the channel.
	if !timer.Stop() {
		<-timer.C()
	}
	s := &store{
		incoming:     make(chan antreastorage.InternalEvent, 100),
		storage:      storage,
		stopCh:       stopCh,
		watchers:     make(map[int]*storeWatcher),
		keyFunc:      keyFunc,
		genEventFunc: genEventFunc,
		selectFunc:   selectorFunc,
		timer:        timer,
		newFunc:      newFunc,
	}

	go s.dispatchEvents()
	return s
}

// NewStore creates a store based on the provided KeyFunc, Indexers, and GenEventFunc.
// KeyFunc decides how to get the key from an object.
// Indexers decides how to build indices for an object.
// GenEventFunc decides how to generate InternalEvent for an update of an object.
func NewStore(keyFunc cache.KeyFunc, indexers cache.Indexers, genEventFunc antreastorage.GenEventFunc, selectorFunc antreastorage.SelectFunc, newFunc func() runtime.Object) *store {
	return newStoreWithClock(keyFunc, indexers, genEventFunc, selectorFunc, newFunc, clock.RealClock{})
}

// nextResourceVersion increments the resourceVersion and returns it.
// It is not thread safe and should be called while holding a lock on eventMutex.
func (s *store) nextResourceVersion() uint64 {
	s.resourceVersion++
	return s.resourceVersion
}

func (s *store) processEvent(event antreastorage.InternalEvent) {
	if curLen := int64(len(s.incoming)); s.incomingHWM.Update(curLen) {
		// Monitor if this gets backed up, and how much.
		klog.V(1).Infof("%v objects queued in incoming channel", curLen)
	}
	s.incoming <- event
}

// Get returns the object matching the provided key along with a boolean value
// indicating of its presence in the store and an error, if any.
func (s *store) Get(key string) (interface{}, bool, error) {
	return s.storage.GetByKey(key)
}

// GetByIndex returns the objects which match the indexer or the error encountered.
func (s *store) GetByIndex(indexName, indexKey string) ([]interface{}, error) {
	return s.storage.ByIndex(indexName, indexKey)
}

// Create stores the object in internal cache storage.
func (s *store) Create(obj interface{}) error {
	key, err := s.keyFunc(obj)
	if err != nil {
		return fmt.Errorf("couldn't get key for object %+v: %v", obj, err)
	}

	s.eventMutex.Lock()
	defer s.eventMutex.Unlock()
	_, exists, _ := s.storage.GetByKey(key)
	if exists {
		return fmt.Errorf("object %+v already exists in storage", obj)
	}

	var event antreastorage.InternalEvent
	if s.genEventFunc != nil {
		event, err = s.genEventFunc(key, nil, obj, s.nextResourceVersion())
		if err != nil {
			return fmt.Errorf("error generating event for Create operation of object %+v: %v", obj, err)
		}
	}

	// The object has been verified with keyFunc in the beginning, can never encounter any error.
	s.storage.Add(obj)
	if event != nil {
		s.processEvent(event)
	}
	return nil
}

// Update updates the store with the latest copy of the object, if it exists.
func (s *store) Update(obj interface{}) error {
	key, err := s.keyFunc(obj)
	if err != nil {
		return fmt.Errorf("couldn't get key for object %+v: %v", obj, err)
	}

	s.eventMutex.Lock()
	defer s.eventMutex.Unlock()
	prevObj, exists, _ := s.storage.GetByKey(key)
	if !exists {
		return fmt.Errorf("object %+v not found in storage", obj)
	}

	var event antreastorage.InternalEvent
	if s.genEventFunc != nil {
		event, err = s.genEventFunc(key, prevObj, obj, s.nextResourceVersion())
		if err != nil {
			return fmt.Errorf("error generating event for Update operation of object %+v: %v", obj, err)
		}
	}

	s.storage.Update(obj)
	if event != nil {
		s.processEvent(event)
	}
	return nil
}

// List returns a list of all the objects.
func (s *store) List() []interface{} {
	return s.storage.List()
}

// Delete deletes the object from internal cache storage.
func (s *store) Delete(key string) error {
	s.eventMutex.Lock()
	defer s.eventMutex.Unlock()
	prevObj, exists, _ := s.storage.GetByKey(key)
	if !exists {
		return fmt.Errorf("object %+v not found in storage", key)
	}

	var event antreastorage.InternalEvent
	var err error
	if s.genEventFunc != nil {
		event, err = s.genEventFunc(key, prevObj, nil, s.nextResourceVersion())
		if err != nil {
			return fmt.Errorf("error generating event for Delete operation: %v", err)
		}
	}

	s.storage.Delete(prevObj)
	if event != nil {
		s.processEvent(event)
	}
	return nil
}

// Watch creates a watcher based on the key, label selector and field selector.
func (s *store) Watch(ctx context.Context, key string, labelSelector labels.Selector, fieldSelector fields.Selector) (watch.Interface, error) {
	if s.genEventFunc == nil {
		return nil, fmt.Errorf("genEventFunc must be set to support watching")
	}
	// Locks eventMutex for reading so that no new events will be generated in the meantime
	// while other watchers won't be blocked.
	s.eventMutex.RLock()
	defer s.eventMutex.RUnlock()

	selectors := &antreastorage.Selectors{
		Key:   key,
		Label: labelSelector,
		Field: fieldSelector,
	}

	allObjects := s.storage.List()
	initEvents := make([]antreastorage.InternalEvent, 0, len(allObjects))
	for _, obj := range allObjects {
		// Objects retrieved from storage have been verified with keyFunc when they are inserted.
		key, _ := s.keyFunc(obj)
		// Check whether the watcher is interested in this object, don't generate an initEvent if not.
		if s.selectFunc != nil && !s.selectFunc(selectors, key, obj) {
			continue
		}

		event, err := s.genEventFunc(key, nil, obj, s.resourceVersion)
		if err != nil {
			return nil, err
		}
		initEvents = append(initEvents, event)
	}

	watcher := func() *storeWatcher {
		s.watcherMutex.Lock()
		defer s.watcherMutex.Unlock()

		w := newStoreWatcher(watcherChanSize, selectors, forgetWatcher(s, s.watcherIdx), s.newFunc)
		s.watchers[s.watcherIdx] = w
		s.watcherIdx++
		return w
	}()

	// Specify current resourceVersion so that old events that were currently buffered in incoming channel won't be
	// delivered to the watcher twice when initEvents already have them.
	go watcher.process(ctx, initEvents, s.resourceVersion)
	return watcher, nil
}

// GetWatchersNum gets the number of watchers for the store.
func (s *store) GetWatchersNum() int {
	s.watcherMutex.RLock()
	defer s.watcherMutex.RUnlock()

	return len(s.watchers)
}

func forgetWatcher(s *store, index int) func() {
	return func() {
		s.watcherMutex.Lock()
		defer s.watcherMutex.Unlock()

		delete(s.watchers, index)
	}
}

func (s *store) dispatchEvents() {
	for {
		select {
		case event, ok := <-s.incoming:
			if !ok {
				return
			}
			s.dispatchEvent(event)
		case <-s.stopCh:
			return
		}
	}
}

func (s *store) dispatchEvent(event antreastorage.InternalEvent) {
	var failedWatchers []*storeWatcher

	func() {
		s.watcherMutex.RLock()
		defer s.watcherMutex.RUnlock()

		// First try to send events without blocking, to avoid setting up a timer
		// for every event.
		// blockedWatchers keeps watchers whose buffer are full.
		var blockedWatchers []*storeWatcher
		// TODO: Optimize this to dispatch the event based on watchers' selector.
		for _, watcher := range s.watchers {
			if !watcher.nonBlockingAdd(event) {
				blockedWatchers = append(blockedWatchers, watcher)
			}
		}
		if len(blockedWatchers) == 0 {
			return
		}
		klog.V(2).Infof("%d watchers were not available to receive event %+v immediately", len(blockedWatchers), event)

		// Then try to send events to blocked watchers with a timeout. If it
		// timeouts, it means the watcher is too slow to consume the events or the
		// underlying connection is already dead, terminate the watcher in this case.
		// antrea-agent will start a new watch after it's disconnected.
		s.timer.Reset(watcherAddTimeout)
		timer := s.timer

		for _, watcher := range blockedWatchers {
			if !watcher.add(event, timer) {
				failedWatchers = append(failedWatchers, watcher)
				// setting timer to nil to let watcher know know the timer has fired.
				timer = nil
			}
		}

		// Stop the timer and drain its channel if it is not fired.
		if timer != nil && !timer.Stop() {
			<-timer.C()
		}
	}()

	// Terminate unresponsive watchers, this must be executed without watcherMutex as
	// watcher.Stop will require the lock itself.
	for _, watcher := range failedWatchers {
		klog.Warningf("Forcing stopping watcher (selectors: %v) due to unresponsiveness", watcher.selectors)
		watcher.Stop()
	}
}

func (s *store) Stop() {
	close(s.stopCh)
}
