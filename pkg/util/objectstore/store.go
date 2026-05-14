// Copyright 2025 Antrea Authors
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

package objectstore

import (
	"context"
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

const delayTime = time.Minute * 5

// uidGetter is the interface required for objects to be added to / deleted from the indexer
type uidGetter interface {
	GetUID() types.UID
}

// Object defines the minimum interface required for objects stored in ObjectStore
type Object interface {
	uidGetter      // GetUID()
	klog.KMetadata // GetName(), GetNamespace()
	GetCreationTimestamp() metav1.Time
}

// ObjectStore is a generic store for any Kubernetes object type
type ObjectStore[T Object] struct {
	objects         cache.Indexer
	objectsToDelete workqueue.TypedDelayingInterface[types.UID]
	delayTime       time.Duration
	// Mapping object.uuid to objectTimestamps
	timestampMap map[types.UID]*objectTimestamps
	clock        clock.Clock
	mutex        sync.RWMutex
	hasSynced    func() bool
	// Function to get object creation timestamp
	getObjectCreationTimestamp func(T, time.Time) time.Time
}

type objectTimestamps struct {
	CreationTimestamp time.Time
	// DeletionTimestamp is nil if an Object is not deleted.
	DeletionTimestamp *time.Time
}

// StoreConfig holds configuration for creating an ObjectStore
type StoreConfig[T Object] struct {
	// Provide a custom clock for the object store.
	// If omitted (nil), RealClock will be used.
	Clock clock.WithTicker
	// Provide a custom name for the deletion workqueue.
	// If omitted, a generic name will be used.
	DeleteQueueName string
	// Indexers to be added to the store.
	// If omitted, no index will be available.
	Indexers cache.Indexers
	// Filter function to use when receiving events from the informer.
	// If omitted, all objects will always be considered.
	FilterFunc func(T) bool
	// GetObjectCreationTimestamp can be used to customize how the creation timestamp is
	// determined for each object.
	// If omitted, GetCreationTimestamp will be called on the object.
	GetObjectCreationTimestamp func(T, time.Time) time.Time
}

// objectKeyFunc creates a key function that uses the object's UID
func objectKeyFunc(obj interface{}) (string, error) {
	storeObj, ok := obj.(uidGetter)
	if !ok {
		return "", fmt.Errorf("invalid object: %v", obj)
	}
	return string(storeObj.GetUID()), nil
}

func NewObjectStore[T Object](informer cache.SharedIndexInformer, config StoreConfig[T]) *ObjectStore[T] {
	deleteQueueName := config.DeleteQueueName
	if deleteQueueName == "" {
		deleteQueueName = "objectsToDelete"
	}
	clockWithTicker := config.Clock
	if clockWithTicker == nil {
		clockWithTicker = clock.RealClock{}
	}
	getObjectCreationTimestamp := config.GetObjectCreationTimestamp
	if getObjectCreationTimestamp == nil {
		getObjectCreationTimestamp = func(obj T, now time.Time) time.Time {
			return obj.GetCreationTimestamp().Time
		}
	}
	s := &ObjectStore[T]{
		objects: cache.NewIndexer(objectKeyFunc, config.Indexers),
		objectsToDelete: workqueue.NewTypedDelayingQueueWithConfig(workqueue.TypedDelayingQueueConfig[types.UID]{
			Name:  deleteQueueName,
			Clock: clockWithTicker,
		}),
		delayTime:                  delayTime,
		clock:                      clockWithTicker,
		timestampMap:               map[types.UID]*objectTimestamps{},
		getObjectCreationTimestamp: getObjectCreationTimestamp,
	}

	registration, _ := informer.AddEventHandler(cache.FilteringResourceEventHandler{
		FilterFunc: func(obj interface{}) bool {
			if config.FilterFunc == nil {
				return true
			}
			if object, ok := obj.(T); ok {
				return config.FilterFunc(object)
			}
			if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				if object, ok := tombstone.Obj.(T); ok {
					return config.FilterFunc(object)
				}
			}
			// Invalid objects will be rejected by event handlers
			return true
		},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    s.onObjectCreate,
			UpdateFunc: s.onObjectUpdate,
			DeleteFunc: s.onObjectDelete,
		},
	})
	// registration.HasSynced returns true when event handlers have been called for the initial list.
	s.hasSynced = registration.HasSynced
	return s
}

func (s *ObjectStore[T]) onObjectUpdate(oldObj interface{}, newObj interface{}) {
	oldObject, ok := oldObj.(T)
	if !ok {
		klog.ErrorS(nil, "Received unexpected object", "oldObj", oldObj)
		return
	}
	newObject, ok := newObj.(T)
	if !ok {
		klog.ErrorS(nil, "Received unexpected object", "newObj", newObj)
		return
	}

	// From https://pkg.go.dev/k8s.io/client-go/tools/cache#SharedInformer:
	// Because `ObjectMeta.UID` has no role in identifying objects, it is possible that when (1)
	// object O1 with ID (e.g. namespace and name) X and `ObjectMeta.UID` U1 in the
	// SharedInformer's local cache is deleted and later (2) another object O2 with ID X and
	// ObjectMeta.UID U2 is created the informer's clients are not notified of (1) and (2) but
	// rather are notified only of an update from O1 to O2. Clients that need to detect such
	// cases might do so by comparing the `ObjectMeta.UID` field of the old and the new object
	// in the code that handles update notifications (i.e. `OnUpdate` method of
	// ResourceEventHandler).
	if oldObject.GetUID() != newObject.GetUID() {
		if err := s.deleteObject(oldObject); err != nil {
			klog.ErrorS(err, "Error when deleting object from store", "obj", klog.KObj(oldObject), "UID", oldObject.GetUID())
		}
		if err := s.addObject(newObject); err != nil {
			klog.ErrorS(err, "Error when adding object to store", "obj", klog.KObj(newObject), "UID", newObject.GetUID())
		}
	} else {
		if err := s.updateObject(newObject); err != nil {
			klog.ErrorS(err, "Error when updating object in store", "obj", klog.KObj(newObject), "UID", newObject.GetUID())
		}
	}
	klog.V(4).InfoS("Processed object update event", "obj", klog.KObj(newObject))
}

func (s *ObjectStore[T]) onObjectCreate(obj interface{}) {
	object, ok := obj.(T)
	if !ok {
		klog.ErrorS(nil, "Received unexpected object", "obj", obj)
		return
	}
	if err := s.addObject(object); err != nil {
		klog.ErrorS(err, "Error when adding object to store", "obj", klog.KObj(object), "UID", object.GetUID())
	}
	klog.V(4).InfoS("Processed object create event", "obj", klog.KObj(object))
}

func (s *ObjectStore[T]) onObjectDelete(obj interface{}) {
	object, ok := obj.(T)
	if !ok {
		var err error
		object, err = s.checkDeletedObject(obj)
		if err != nil {
			klog.ErrorS(err, "Got error while processing Delete Event")
			return
		}
	}
	if err := s.deleteObject(object); err != nil {
		klog.ErrorS(err, "Error when deleting object from store", "obj", klog.KObj(object), "UID", object.GetUID())
	}
	klog.V(4).InfoS("Processed object delete event", "obj", klog.KObj(object))
}

func (s *ObjectStore[T]) addObject(object T) error {
	timeNow := s.clock.Now()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	err := s.objects.Add(object)
	if err != nil {
		return fmt.Errorf("error when adding Object to index: %w", err)
	}

	// Use configurable creation timestamp function
	s.timestampMap[object.GetUID()] = &objectTimestamps{CreationTimestamp: s.getObjectCreationTimestamp(object, timeNow)}
	return nil
}

func (s *ObjectStore[T]) updateObject(object T) error {
	if err := s.objects.Update(object); err != nil {
		return fmt.Errorf("error when updating Object in index: %w", err)
	}
	return nil
}

func (s *ObjectStore[T]) deleteObject(object T) error {
	timeNow := s.clock.Now()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	timestamp, ok := s.timestampMap[object.GetUID()]
	if !ok {
		return fmt.Errorf("cannot find objectTimestamps in timestampMap")
	}
	timestamp.DeletionTimestamp = &timeNow
	s.objectsToDelete.AddAfter(object.GetUID(), s.delayTime)
	return nil
}

func (s *ObjectStore[T]) checkDeletedObject(obj interface{}) (T, error) {
	deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		return *new(T), fmt.Errorf("received unexpected object: %v", obj)
	}
	object, ok := deletedState.Obj.(T)
	if !ok {
		return *new(T), fmt.Errorf("DeletedFinalStateUnknown object is not of expected type: %v", deletedState.Obj)
	}
	return object, nil
}

func (s *ObjectStore[T]) GetObjectByIndexAndTime(indexName, indexedValue string, time time.Time) (T, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	objects, _ := s.objects.ByIndex(indexName, indexedValue)
	if len(objects) == 0 {
		return *new(T), false
	} else if len(objects) == 1 {
		object := objects[0].(T)
		// In case the clocks may be skewed between different Nodes in the cluster, we directly return the object if there is only
		// one object in the indexer. Otherwise, we check the timestamp for objects in the indexer.
		klog.V(4).InfoS("Matched object to object from indexer", "indexName", indexName, "indexedValue", indexedValue, "obj", klog.KObj(object))
		return object, true
	}
	for _, obj := range objects {
		object := obj.(T)
		timestamp, ok := s.timestampMap[object.GetUID()]
		if !ok {
			continue
		}
		if timestamp.CreationTimestamp.Before(time) && (timestamp.DeletionTimestamp == nil || time.Before(*timestamp.DeletionTimestamp)) {
			klog.V(4).InfoS("Matched object and time to object from indexer", "indexName", indexName, "indexedValue", indexedValue, "time", time, "obj", klog.KObj(object))
			return object, true
		}
	}
	return *new(T), false
}

func (s *ObjectStore[T]) Run(stopCh <-chan struct{}) {
	defer s.objectsToDelete.ShutDown()
	go wait.Until(s.worker, time.Second, stopCh)
	<-stopCh
}

type objectKey struct {
	uid types.UID
}

func (k *objectKey) GetUID() types.UID {
	return k.uid
}

// objectKey implements the uidGetter interface
var _ uidGetter = &objectKey{}

// worker runs a worker thread that just dequeues item from deleteQueue and
// remove the item from prevObject.
func (s *ObjectStore[T]) worker() {
	// Use the same object in each worker to delete from the indexer by key
	// (UID), as there is no reason to allocate a new object for each call
	// to processDeleteQueueItem.
	objectDeletionKey := &objectKey{}
	for s.processDeleteQueueItem(objectDeletionKey) {
	}
}

func (s *ObjectStore[T]) processDeleteQueueItem(objectDeletionKey *objectKey) bool {
	objectUID, quit := s.objectsToDelete.Get()
	if quit {
		return false
	}
	defer s.objectsToDelete.Done(objectUID)

	objectDeletionKey.uid = objectUID

	s.mutex.Lock()
	defer s.mutex.Unlock()
	if err := s.objects.Delete(objectDeletionKey); err != nil {
		klog.ErrorS(err, "Error when deleting object from store", "key", objectUID)
		return true
	}
	delete(s.timestampMap, objectUID)
	klog.V(4).InfoS("Removed object from store", "UID", objectUID)
	return true
}

// HasSynced returns true when the event handler has been called for the initial list of Objects.
func (s *ObjectStore[T]) HasSynced() bool {
	return s.hasSynced()
}

// WaitForStoreSyncs waits for stores to sync. It returns an error if the context is cancelled. You
// need to provide the HasSynced method for each store you want to wait on.
func WaitForStoreSyncs(ctx context.Context, storeSyncs ...func() bool) error {
	const storeSyncPollInterval = 100 * time.Millisecond
	return wait.PollUntilContextCancel(ctx, storeSyncPollInterval, true, func(ctx context.Context) (done bool, err error) {
		for _, synced := range storeSyncs {
			if !synced() {
				return false, nil
			}
		}
		return true, nil
	})
}
