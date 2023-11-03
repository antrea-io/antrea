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
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	antreastorage "antrea.io/antrea/pkg/apiserver/storage"
)

// testEvent implements InternalEvent.
type testEvent struct {
	Type            watch.EventType
	Object          runtime.Object
	ObjLabels       labels.Set
	ObjFields       fields.Set
	PrevObject      runtime.Object
	PrevObjLabels   labels.Set
	PrevObjFields   fields.Set
	Key             string
	ResourceVersion uint64
}

func testFilter(s *antreastorage.Selectors, key string, labels labels.Set, fields fields.Set) bool {
	if s.Key != "" && key != s.Key {
		return false
	}
	if s.Label.Empty() && s.Field.Empty() {
		return true
	}
	if !s.Label.Matches(labels) {
		return false
	}
	return s.Field.Matches(fields)
}

func (event *testEvent) ToWatchEvent(selectors *antreastorage.Selectors, isInitEvent bool) *watch.Event {
	curObjPasses := event.Type != watch.Deleted && testFilter(selectors, event.Key, event.ObjLabels, event.ObjFields)
	oldObjPasses := false
	if event.PrevObject != nil {
		oldObjPasses = testFilter(selectors, event.Key, event.PrevObjLabels, event.PrevObjFields)
	}
	if !curObjPasses && !oldObjPasses {
		// Watcher is not interested in that object.
		return nil
	}

	switch {
	case curObjPasses && !oldObjPasses:
		return &watch.Event{Type: watch.Added, Object: event.Object.DeepCopyObject()}
	case curObjPasses && oldObjPasses:
		return &watch.Event{Type: watch.Modified, Object: event.Object.DeepCopyObject()}
	case !curObjPasses && oldObjPasses:
		// return a delete event with the previous object content
		return &watch.Event{Type: watch.Deleted, Object: event.PrevObject.DeepCopyObject()}
	}
	return nil
}

func (event *testEvent) GetResourceVersion() uint64 {
	return event.ResourceVersion
}

// testGenEvent generates *testEvent
func testGenEvent(key string, prevObj, obj interface{}, resourceVersion uint64) (antreastorage.InternalEvent, error) {
	if reflect.DeepEqual(prevObj, obj) {
		return nil, nil
	}
	event := &testEvent{Key: key, ResourceVersion: resourceVersion}
	if prevObj != nil {
		prevObjLabels, prevObjFields, err := storage.DefaultClusterScopedAttr(prevObj.(runtime.Object))
		if err != nil {
			return nil, err
		}
		event.PrevObject = prevObj.(runtime.Object)
		event.PrevObjLabels = prevObjLabels
		event.PrevObjFields = prevObjFields
	}
	if obj != nil {
		objLabels, objFields, err := storage.DefaultClusterScopedAttr(obj.(runtime.Object))
		if err != nil {
			return nil, err
		}
		event.Object = obj.(runtime.Object)
		event.ObjLabels = objLabels
		event.ObjFields = objFields
	}
	if prevObj == nil && obj != nil {
		event.Type = watch.Added
	} else if prevObj != nil && obj == nil {
		event.Type = watch.Deleted
	} else {
		event.Type = watch.Modified
	}
	return event, nil
}

func testSelectFunc(selectors *antreastorage.Selectors, key string, obj interface{}) bool {
	objLabels, objFields, _ := storage.DefaultClusterScopedAttr(obj.(runtime.Object))
	return testFilter(selectors, key, objLabels, objFields)
}

func TestRamStoreCRUD(t *testing.T) {
	key := "pod1"
	testCases := []struct {
		// The operations that will be executed on the storage
		operations func(*store)
		// The object expected to be got by the key
		expected runtime.Object
	}{
		{
			operations: func(store *store) {
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: key, Labels: map[string]string{"app": "nginx1"}}})
			},
			expected: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: key, Labels: map[string]string{"app": "nginx1"}}},
		},
		{
			operations: func(store *store) {
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: key, Labels: map[string]string{"app": "nginx1"}}})
				store.Update(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: key, Labels: map[string]string{"app": "nginx2"}}})
			},
			expected: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: key, Labels: map[string]string{"app": "nginx2"}}},
		},
		{
			operations: func(store *store) {
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: key, Labels: map[string]string{"app": "nginx1"}}})
				store.Update(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: key, Labels: map[string]string{"app": "nginx2"}}})
				store.Delete(key)
			},
			expected: nil,
		},
	}
	for i, testCase := range testCases {
		store := NewStore(cache.MetaNamespaceKeyFunc, cache.Indexers{}, nil, nil, func() runtime.Object { return new(v1.Pod) })

		testCase.operations(store)
		obj, _, err := store.Get(key)
		if err != nil {
			t.Errorf("%d: failed to get object: %v", i, err)
		}
		if !reflect.DeepEqual(obj, testCase.expected) {
			t.Errorf("%d: get unexpected object: %v", i, obj)
		}
	}
}

func TestRamStoreGetByIndex(t *testing.T) {
	indexName := "nodeName"
	indexKey := "node1"
	indexers := cache.Indexers{
		indexName: func(obj interface{}) ([]string, error) {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				return []string{}, nil
			}
			if len(pod.Spec.NodeName) == 0 {
				return []string{}, nil
			}
			return []string{pod.Spec.NodeName}, nil
		},
	}
	testCases := []struct {
		// The operations that will be executed on the storage
		operations func(*store)
		// The objects expected to be got by the indexName and indexKey
		expected []runtime.Object
	}{
		{
			operations: func(store *store) {
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}, Spec: v1.PodSpec{NodeName: indexKey}})
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Labels: map[string]string{"app": "nginx2"}}, Spec: v1.PodSpec{NodeName: indexKey}})
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod3", Labels: map[string]string{"app": "nginx3"}}, Spec: v1.PodSpec{NodeName: "othernode"}})
			},
			expected: []runtime.Object{
				&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}, Spec: v1.PodSpec{NodeName: indexKey}},
				&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Labels: map[string]string{"app": "nginx2"}}, Spec: v1.PodSpec{NodeName: indexKey}},
			},
		},
		{
			operations: func(store *store) {
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}, Spec: v1.PodSpec{NodeName: indexKey}})
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Labels: map[string]string{"app": "nginx2"}}, Spec: v1.PodSpec{NodeName: indexKey}})
				store.Delete("pod2")
			},
			expected: []runtime.Object{
				&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}, Spec: v1.PodSpec{NodeName: indexKey}},
			},
		},
		{
			operations: func(store *store) {
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}, Spec: v1.PodSpec{NodeName: indexKey}})
				store.Update(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx2"}}, Spec: v1.PodSpec{NodeName: indexKey}})
			},
			expected: []runtime.Object{
				&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx2"}}, Spec: v1.PodSpec{NodeName: indexKey}},
			},
		},
	}
	for i, testCase := range testCases {
		store := NewStore(cache.MetaNamespaceKeyFunc, indexers, testGenEvent, nil, func() runtime.Object { return new(v1.Pod) })

		testCase.operations(store)
		objs, err := store.GetByIndex(indexName, indexKey)
		if err != nil {
			t.Errorf("%d: failed to get object by index: %v", i, err)
		}
		if !assert.ElementsMatch(t, testCase.expected, objs) {
			t.Errorf("%d: Expected objects:\n %v\n do not match objects retrieved from GetByIndex operation:\n %v", i, testCase.expected, objs)
		}
	}
}

func TestRamStoreList(t *testing.T) {
	testCases := []struct {
		// The operations that will be executed on the storage
		operations func(*store)
		// The objects expected to be got by the List
		expected []runtime.Object
	}{
		{
			operations: func(store *store) {
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}, Spec: v1.PodSpec{}})
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Labels: map[string]string{"app": "nginx2"}}, Spec: v1.PodSpec{}})
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod3", Labels: map[string]string{"app": "nginx3"}}, Spec: v1.PodSpec{}})
			},
			expected: []runtime.Object{
				&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}, Spec: v1.PodSpec{}},
				&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Labels: map[string]string{"app": "nginx2"}}, Spec: v1.PodSpec{}},
				&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod3", Labels: map[string]string{"app": "nginx3"}}, Spec: v1.PodSpec{}},
			},
		},
		{
			operations: func(store *store) {
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}, Spec: v1.PodSpec{}})
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Labels: map[string]string{"app": "nginx2"}}, Spec: v1.PodSpec{}})
				store.Delete("pod2")
			},
			expected: []runtime.Object{
				&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}, Spec: v1.PodSpec{}},
			},
		},
	}
	for i, testCase := range testCases {
		store := NewStore(cache.MetaNamespaceKeyFunc, cache.Indexers{}, testGenEvent, nil, func() runtime.Object { return new(v1.Pod) })

		testCase.operations(store)
		objs := store.List()
		if len(objs) != len(testCase.expected) {
			t.Errorf("%d: Unexpected number of objects returned for List operation. %d != %d", i, len(objs), len(testCase.expected))
		}
		if !assert.ElementsMatch(t, testCase.expected, objs) {
			t.Errorf("%d: Expected objects:\n %v\n do not match objects retrieved from List operation:\n %v", i, testCase.expected, objs)
		}
	}
}

func TestRamStoreWatchAll(t *testing.T) {
	testCases := []struct {
		// The operations that will be executed on the storage
		operations func(*store)
		// The events expected to see
		expected []watch.Event
	}{
		{
			operations: func(store *store) {
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}})
				store.Update(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx2"}}})
			},
			expected: []watch.Event{
				{Type: watch.Bookmark, Object: &v1.Pod{}},
				{Type: watch.Added, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}}},
				{Type: watch.Modified, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx2"}}}},
			},
		},
		{
			operations: func(store *store) {
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}})
				store.Delete("pod1")
			},
			expected: []watch.Event{
				{Type: watch.Bookmark, Object: &v1.Pod{}},
				{Type: watch.Added, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}}},
				{Type: watch.Deleted, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}}},
			},
		},
	}
	for i, testCase := range testCases {
		store := NewStore(cache.MetaNamespaceKeyFunc, cache.Indexers{}, testGenEvent, testSelectFunc, func() runtime.Object { return new(v1.Pod) })
		w, err := store.Watch(context.Background(), "", labels.Everything(), fields.Everything())
		if err != nil {
			t.Errorf("%d: failed to watch object: %v", i, err)
		}
		testCase.operations(store)
		ch := w.ResultChan()
		for j, expectedEvent := range testCase.expected {
			actualEvent := <-ch
			if !reflect.DeepEqual(actualEvent, expectedEvent) {
				t.Errorf("%d: unexpected event %d", i, j)
			}
		}
		select {
		case obj, ok := <-ch:
			t.Errorf("%d: unexpected excess event: %#v %t", i, obj, ok)
		default:
		}
	}
}

func TestRamStoreWatchWithInitOperations(t *testing.T) {
	testCases := []struct {
		// The operations that will be executed on the storage before watching
		initOperations func(*store)
		// The operations that will be executed on the storage after watching
		operations func(*store)
		// We should see the initOperations merged and watched as "ADDED" events
		// before the events generated by operations
		expected []watch.Event
	}{
		{
			initOperations: func(store *store) {
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}})
				store.Update(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx2"}}})
				store.Update(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx3"}}})
			},
			operations: func(store *store) {
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Labels: map[string]string{"app": "nginx2"}}})
				store.Update(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Labels: map[string]string{"app": "nginx3"}}})
			},
			expected: []watch.Event{
				{Type: watch.Added, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx3"}}}},
				{Type: watch.Bookmark, Object: &v1.Pod{}},
				{Type: watch.Added, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Labels: map[string]string{"app": "nginx2"}}}},
				{Type: watch.Modified, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Labels: map[string]string{"app": "nginx3"}}}},
			},
		},
		{
			initOperations: func(store *store) {
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}})
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Labels: map[string]string{"app": "nginx2"}}})
				store.Delete("pod2")
			},
			operations: func(store *store) {
				store.Delete("pod1")
			},
			expected: []watch.Event{
				{Type: watch.Added, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}}},
				{Type: watch.Bookmark, Object: &v1.Pod{}},
				{Type: watch.Deleted, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}}},
			},
		},
	}
	for i, testCase := range testCases {
		store := NewStore(cache.MetaNamespaceKeyFunc, cache.Indexers{}, testGenEvent, testSelectFunc, func() runtime.Object { return new(v1.Pod) })
		// Init the storage before watching
		testCase.initOperations(store)
		w, err := store.Watch(context.Background(), "", labels.Everything(), fields.Everything())
		if err != nil {
			t.Errorf("%d: failed to watch object: %v", i, err)
		}
		testCase.operations(store)
		ch := w.ResultChan()
		for j, expectedEvent := range testCase.expected {
			actualEvent := <-ch
			if !reflect.DeepEqual(actualEvent, expectedEvent) {
				t.Errorf("%d: unexpected event %d", i, j)
			}
		}
		select {
		case obj, ok := <-ch:
			t.Errorf("%d: unexpected excess event: %#v %t", i, obj, ok)
		default:
		}
	}
}

func TestRamStoreWatchWithSelector(t *testing.T) {
	testCases := []struct {
		// The operations that will be executed on the storage before watching
		operations func(*store)
		// The label Selector that will be set when watching
		labelSelector labels.Selector
		// The events expected to see, there should be only events matching the labelSelector
		expected []watch.Event
	}{
		{
			operations: func(store *store) {
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}})
				store.Update(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx2"}}})
			},
			labelSelector: labels.SelectorFromSet(labels.Set{"app": "nginx1"}),
			expected: []watch.Event{
				{Type: watch.Bookmark, Object: &v1.Pod{}},
				{Type: watch.Added, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}}},
				{Type: watch.Deleted, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}}},
			},
		},
		{
			operations: func(store *store) {
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}})
				store.Update(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx2"}}})
			},
			labelSelector: labels.SelectorFromSet(labels.Set{"app": "nginx2"}),
			expected: []watch.Event{
				{Type: watch.Bookmark, Object: &v1.Pod{}},
				{Type: watch.Added, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx2"}}}},
			},
		},
		{
			operations: func(store *store) {
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}})
				store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Labels: map[string]string{"app": "nginx2"}}})
				store.Delete("pod1")
				store.Delete("pod2")
			},
			labelSelector: labels.SelectorFromSet(labels.Set{"app": "nginx1"}),
			expected: []watch.Event{
				{Type: watch.Bookmark, Object: &v1.Pod{}},
				{Type: watch.Added, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}}},
				{Type: watch.Deleted, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Labels: map[string]string{"app": "nginx1"}}}},
			},
		},
	}
	for i, testCase := range testCases {
		store := NewStore(cache.MetaNamespaceKeyFunc, cache.Indexers{}, testGenEvent, testSelectFunc, func() runtime.Object { return new(v1.Pod) })
		w, err := store.Watch(context.Background(), "", testCase.labelSelector, fields.Everything())
		if err != nil {
			t.Errorf("%d: failed to watch object: %v", i, err)
		}
		testCase.operations(store)
		ch := w.ResultChan()
		for j, expectedEvent := range testCase.expected {
			actualEvent := <-ch
			if !reflect.DeepEqual(actualEvent, expectedEvent) {
				t.Errorf("%d: unexpected event %d", i, j)
			}
		}
		select {
		case obj, ok := <-ch:
			t.Errorf("%d: unexpected excess event: %#v %t", i, obj, ok)
		default:
		}
	}
}

func TestRamStoreWatchTimeout(t *testing.T) {
	clock := clocktesting.NewFakeClock(time.Now())
	store := newStoreWithClock(cache.MetaNamespaceKeyFunc, cache.Indexers{}, testGenEvent, testSelectFunc, func() runtime.Object { return new(v1.Pod) }, clock)
	// watcherChanSize*2+1 events can fill a watcher's buffer: input channel buffer + result channel buffer + 1 in-flight.
	maxBuffered := watcherChanSize*2 + 1

	// w1 has consumer for its result chan.
	w1, err := store.Watch(context.Background(), "", labels.SelectorFromSet(labels.Set{"app": "nginx"}), fields.Everything())
	if err != nil {
		t.Errorf("Failed to watch object: %v", err)
	}

	w1Done := make(chan struct{})
	go func() {
		defer close(w1Done)
		ch := w1.ResultChan()
		// Skip the bookmark event.
		<-ch
		for i := 0; i < maxBuffered+1; i++ {
			actualEvent := <-ch
			expectedEvent := watch.Event{Type: watch.Added, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("pod%d", i), Labels: map[string]string{"app": "nginx"}}}}
			if !reflect.DeepEqual(actualEvent, expectedEvent) {
				t.Errorf("Unexpected event %d, got %#v, expected %#v ", i, actualEvent, expectedEvent)
			}
		}
		select {
		case obj, ok := <-ch:
			t.Errorf("Unexpected excess event: %#v %t", obj, ok)
		default:
		}
	}()

	// w2 has no consumer for its result chan.
	w2, err := store.Watch(context.Background(), "", labels.SelectorFromSet(labels.Set{"app": "nginx"}), fields.Everything())
	if err != nil {
		t.Errorf("Failed to watch object: %v", err)
	}
	// Skip the bookmark event.
	<-w2.ResultChan()
	assert.Equal(t, 2, store.GetWatchersNum(), "Unexpected watchers number")

	// Generate all events at once: w1 can take all events (eventually) as it has a consumer. w2
	// will not be able to take the last event as it has no consumer.
	for i := 0; i < maxBuffered+1; i++ {
		store.Create(&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("pod%d", i), Labels: map[string]string{"app": "nginx"}}})
	}

	// Give 1s for the consumer for w1 to receive all events. During that time, we do not
	// advance the fake clock.
	select {
	case <-w1Done:
	case <-time.After(1 * time.Second):
		t.Fatal("w1 consumer has not received all events")
	}

	// Make sure that w2 is not stopped yet.
	select {
	case <-w2.(*storeWatcher).done:
		t.Fatal("w2 was stopped, expected not stopped")
	default:
	}

	// After advancing the fake clock, w2 should be stopped. Because terminating watchers is
	// asynchronous, we leave 500ms of reaction time.
	clock.Step(watcherAddTimeout)

	select {
	case <-w2.(*storeWatcher).done:
	case <-time.After(500 * time.Millisecond):
		t.Error("w2 was not stopped, expected stopped")
	}

	assert.Equal(t, 1, store.GetWatchersNum(), "Unexpected watchers number")
}
