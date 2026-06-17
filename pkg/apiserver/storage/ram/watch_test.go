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
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/utils/clock"

	"antrea.io/antrea/v2/pkg/apiserver/storage"
	"antrea.io/antrea/v2/pkg/apiserver/storage/testutil"
)

// simpleInternalEvent simply construct watch.Event based on the provided Type and Object
type simpleInternalEvent struct {
	Type            watch.EventType
	Object          runtime.Object
	ResourceVersion uint64
}

func (e *simpleInternalEvent) ToWatchEvent(selectors *storage.Selectors, isInitEvent bool) *watch.Event {
	return &watch.Event{
		Type:   e.Type,
		Object: e.Object,
	}
}

func (e *simpleInternalEvent) GetResourceVersion() uint64 {
	return e.ResourceVersion
}

// emptyInternalEvent always get nil when converting to watch.Event,
// represents the case that the watcher is not interested in an object.
type emptyInternalEvent struct{}

func (e *emptyInternalEvent) ToWatchEvent(selectors *storage.Selectors, isInitEvent bool) *watch.Event {
	return nil
}

func (e *emptyInternalEvent) GetResourceVersion() uint64 {
	return 0
}

func TestEvents(t *testing.T) {
	testCases := []struct {
		initEvents  []storage.InternalEvent
		addedEvents []storage.InternalEvent
		expected    []watch.Event
	}{
		// No initEvents case
		{
			initEvents: []storage.InternalEvent{},
			addedEvents: []storage.InternalEvent{
				&simpleInternalEvent{
					Type:            watch.Added,
					Object:          &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1"}},
					ResourceVersion: 1,
				},
				&simpleInternalEvent{
					Type:            watch.Modified,
					Object:          &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2"}},
					ResourceVersion: 2,
				},
				&simpleInternalEvent{
					Type:            watch.Deleted,
					Object:          &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod3"}},
					ResourceVersion: 3,
				},
			},
			expected: []watch.Event{
				testutil.ExpectedInitBookmark(t, &v1.Pod{}, "0"),
				{Type: watch.Added, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1"}}},
				{Type: watch.Modified, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2"}}},
				{Type: watch.Deleted, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod3"}}},
			},
		},
		// initEvents + addedEvents case
		{
			initEvents: []storage.InternalEvent{
				&simpleInternalEvent{
					Type:            watch.Added,
					Object:          &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1"}},
					ResourceVersion: 0,
				},
			},
			addedEvents: []storage.InternalEvent{
				&simpleInternalEvent{
					Type:            watch.Modified,
					Object:          &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2"}},
					ResourceVersion: 1,
				},
				&simpleInternalEvent{
					Type:            watch.Deleted,
					Object:          &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod3"}},
					ResourceVersion: 2,
				},
			},
			expected: []watch.Event{
				{Type: watch.Added, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1"}}},
				testutil.ExpectedInitBookmark(t, &v1.Pod{}, "0"),
				{Type: watch.Modified, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2"}}},
				{Type: watch.Deleted, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod3"}}},
			},
		},
		// initEvents + addedEvents + emptyEvents
		{
			initEvents: []storage.InternalEvent{
				&simpleInternalEvent{
					Type:            watch.Added,
					Object:          &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1"}},
					ResourceVersion: 0,
				},
				&emptyInternalEvent{},
			},
			addedEvents: []storage.InternalEvent{
				&simpleInternalEvent{
					Type:            watch.Deleted,
					Object:          &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod3"}},
					ResourceVersion: 1,
				},
				&emptyInternalEvent{},
			},
			expected: []watch.Event{
				{Type: watch.Added, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1"}}},
				testutil.ExpectedInitBookmark(t, &v1.Pod{}, "0"),
				{Type: watch.Deleted, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod3"}}},
			},
		},
	}

	for i, testCase := range testCases {
		w := newStoreWatcher(10, &storage.Selectors{}, func() {}, func() runtime.Object { return new(v1.Pod) })
		go w.process(context.Background(), testCase.initEvents, 0)

		for _, event := range testCase.addedEvents {
			w.nonBlockingAdd(event)
		}
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
		w.Stop()
	}
}

func TestBookmarkEventToWatchEvent(t *testing.T) {
	b := &bookmarkEvent{resourceVersion: 5, object: &v1.Pod{}}

	// The bookmark marking the end of the initial events carries the resourceVersion and the
	// initial-events-end annotation.
	initEvent := b.ToWatchEvent(&storage.Selectors{}, true)
	assert.Equal(t, watch.Bookmark, initEvent.Type)
	initMeta, err := meta.Accessor(initEvent.Object)
	require.NoError(t, err)
	assert.Equal(t, "5", initMeta.GetResourceVersion())
	assert.Equal(t, map[string]string{metav1.InitialEventsAnnotationKey: "true"}, initMeta.GetAnnotations())

	// A non-init bookmark carries the resourceVersion but must not be labeled as the end of the
	// initial events, otherwise clients would prematurely consider their cache synced.
	nonInitEvent := b.ToWatchEvent(&storage.Selectors{}, false)
	assert.Equal(t, watch.Bookmark, nonInitEvent.Type)
	nonInitMeta, err := meta.Accessor(nonInitEvent.Object)
	require.NoError(t, err)
	assert.Equal(t, "5", nonInitMeta.GetResourceVersion())
	assert.NotContains(t, nonInitMeta.GetAnnotations(), metav1.InitialEventsAnnotationKey)

	// The InternalEvent must remain immutable during its conversion: the stored object should not
	// have been mutated by either conversion above.
	storedMeta, err := meta.Accessor(b.object)
	require.NoError(t, err)
	assert.Empty(t, storedMeta.GetResourceVersion())
	assert.Empty(t, storedMeta.GetAnnotations())

	// Even if the bookmark object already carries the initial-events-end annotation, a non-init
	// bookmark must have it stripped so clients don't mistake it for the end of the initial events.
	annotated := &bookmarkEvent{resourceVersion: 7, object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{
		Annotations: map[string]string{metav1.InitialEventsAnnotationKey: "true"},
	}}}
	annotatedEvent := annotated.ToWatchEvent(&storage.Selectors{}, false)
	annotatedMeta, err := meta.Accessor(annotatedEvent.Object)
	require.NoError(t, err)
	assert.NotContains(t, annotatedMeta.GetAnnotations(), metav1.InitialEventsAnnotationKey)
}

func TestAddTimeout(t *testing.T) {
	w := newStoreWatcher(1, &storage.Selectors{}, func() {}, func() runtime.Object { return new(v1.Pod) })
	events := []storage.InternalEvent{
		&simpleInternalEvent{
			Type:            watch.Added,
			Object:          &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1"}},
			ResourceVersion: 1,
		},
		&simpleInternalEvent{
			Type:            watch.Added,
			Object:          &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2"}},
			ResourceVersion: 2,
		},
	}
	clock := clock.RealClock{}
	timer := clock.NewTimer(watcherAddTimeout)
	if !w.add(events[0], timer) {
		t.Error("add() failed, expected success")
	}
	// Since channel size is 1 and there's no consumer, the second add should fail.
	timer = clock.NewTimer(watcherAddTimeout)
	if w.add(events[1], timer) {
		t.Error("add() succeeded, expected failure")
	}
}
