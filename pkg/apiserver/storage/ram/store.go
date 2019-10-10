// Copyright 2019 OKN Authors
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

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	oknstorage "okn/pkg/apiserver/storage"
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
	incoming chan oknstorage.InternalEvent

	// storage is the underlying storage.
	storage cache.Indexer
	// keyFunc is used to get a key in the underlying storage for a given object.
	keyFunc cache.KeyFunc
	// genEventFunc is used to generate InternalEvent from update of an object.
	genEventFunc oknstorage.GenEventFunc

	// resourceVersion up to which the store has generated.
	resourceVersion uint64
	// watcherIdx is the index that will be allocated to next watcher and used as key in watchersMap
	// so that a watcher can be deleted from the map according to its index later.
	watcherIdx int
	// watchers is a mapping from the index of a watcher to the watcher.
	watchers watchersMap

	stopCh chan struct{}
}

// NewStore creates a store based on the provided KeyFunc, Indexers, and GenEventFunc.
// KeyFunc decides how to get the key from an object.
// Indexers decides how to build indices for an object.
// GenEventFunc decides how to generate InternalEvent for an update of an object.
func NewStore(keyFunc cache.KeyFunc, indexers cache.Indexers, genEventFunc oknstorage.GenEventFunc) *store {
	stopCh := make(chan struct{})
	storage := cache.NewIndexer(keyFunc, indexers)
	s := &store{
		incoming:     make(chan oknstorage.InternalEvent, 100),
		storage:      storage,
		stopCh:       stopCh,
		watchers:     make(map[int]*storeWatcher),
		keyFunc:      keyFunc,
		genEventFunc: genEventFunc,
	}

	go s.dispatchEvents()
	return s
}

// nextResourceVersion increments the resourceVersion and returns it.
// It is not thread safe and should be called while holding a lock on eventMutex.
func (s *store) nextResourceVersion() uint64 {
	s.resourceVersion++
	return s.resourceVersion
}

func (s *store) processEvent(event oknstorage.InternalEvent) {
	if curLen := int64(len(s.incoming)); s.incomingHWM.Update(curLen) {
		// Monitor if this gets backed up, and how much.
		klog.V(1).Infof("%v objects queued in incoming channel", curLen)
	}
	s.incoming <- event
}

// Get returns the object matching the provided key along with a boolean value
// indicating of its presence in the store and an error, if any.
func (s *store) Get(key string) (runtime.Object, bool, error) {
	item, exists, err := s.storage.GetByKey(key)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, exists, nil
	}
	return item.(runtime.Object), true, nil
}

// GetByIndex returns the objects which match the indexer or the error encountered.
func (s *store) GetByIndex(indexName, indexKey string) ([]runtime.Object, error) {
	items, err := s.storage.ByIndex(indexName, indexKey)
	if err != nil {
		return nil, err
	}
	objs := make([]runtime.Object, len(items))
	for i, item := range items {
		objs[i] = item.(runtime.Object)
	}
	return objs, nil
}

// Create stores the object in internal cache storage.
func (s *store) Create(obj runtime.Object) error {
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

	event, err := s.genEventFunc(key, nil, obj, s.nextResourceVersion())
	if err != nil {
		return err
	}

	// The object has been verified with keyFunc in the beginning, can never encounter any error.
	s.storage.Add(obj)
	s.processEvent(event)
	return nil
}

// Update updates the store with the latest copy of the object, if it exists.
func (s *store) Update(obj runtime.Object) error {
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

	event, err := s.genEventFunc(key, prevObj.(runtime.Object), obj, s.nextResourceVersion())
	if err != nil {
		return err
	}

	s.storage.Update(obj)
	if event != nil {
		s.processEvent(event)
	}
	return nil
}

// List returns a list of all the objects.
func (s *store) List() []runtime.Object {
	items := s.storage.List()
	objs := make([]runtime.Object, len(items))
	for i, item := range items {
		objs[i] = item.(runtime.Object)
	}
	return objs
}

// Delete deletes the object from internal cache storage.
func (s *store) Delete(key string) error {
	s.eventMutex.Lock()
	defer s.eventMutex.Unlock()
	prevObj, exists, _ := s.storage.GetByKey(key)
	if !exists {
		return fmt.Errorf("object %+v not found in storage", key)
	}
	event, err := s.genEventFunc(key, prevObj.(runtime.Object), nil, s.nextResourceVersion())
	if err != nil {
		return err
	}

	s.storage.Delete(prevObj)
	s.processEvent(event)
	return nil
}

// Watch creates a watcher based on the key, label selector and field selector.
func (s *store) Watch(ctx context.Context, key string, labelSelector labels.Selector, fieldSelector fields.Selector) (watch.Interface, error) {
	// Locks eventMutex for reading so that no new events will be generated in the meantime
	// while other watchers won't be blocked.
	s.eventMutex.RLock()
	defer s.eventMutex.RUnlock()
	allObjects := s.storage.List()
	initEvents := make([]oknstorage.InternalEvent, len(allObjects))
	for i, obj := range allObjects {
		// Objects retrieved from storage have been verified with keyFunc when they are inserted.
		key, _ := s.keyFunc(obj)
		event, err := s.genEventFunc(key, nil, obj.(runtime.Object), s.resourceVersion)
		if err != nil {
			return nil, err
		}
		initEvents[i] = event
	}

	watcher := func() *storeWatcher {
		s.watcherMutex.Lock()
		defer s.watcherMutex.Unlock()

		w := newStoreWatcher(10, &oknstorage.Selectors{key, labelSelector, fieldSelector}, forgetWatcher(s, s.watcherIdx))
		s.watchers[s.watcherIdx] = w
		s.watcherIdx++
		return w
	}()

	// Specify current resourceVersion so that old events that were currently buffered in incoming channel won't be
	// delivered to the watcher twice when initEvents already have them.
	go watcher.process(ctx, initEvents, s.resourceVersion)
	return watcher, nil
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

func (s *store) dispatchEvent(event oknstorage.InternalEvent) {
	s.watcherMutex.Lock()
	defer s.watcherMutex.Unlock()
	// TODO: Optimize this to dispatch the event based on watchers' selector.
	for _, watcher := range s.watchers {
		watcher.add(event)
	}
}
