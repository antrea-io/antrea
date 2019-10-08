package ram

import (
	"context"
	"reflect"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"

	"okn/pkg/apiserver/storage"
)

// simpleInternalEvent simply construct watch.Event based on the provided Type and Object
type simpleInternalEvent struct {
	Type            watch.EventType
	Object          runtime.Object
	ResourceVersion uint64
}

func (e *simpleInternalEvent) ToWatchEvent(selectors *storage.Selectors) *watch.Event {
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

func (e *emptyInternalEvent) ToWatchEvent(selectors *storage.Selectors) *watch.Event {
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
				{Type: watch.Deleted, Object: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod3"}}},
			},
		},
	}

	for i, testCase := range testCases {
		w := newStoreWatcher(10, &storage.Selectors{}, func() {})
		go w.process(context.Background(), testCase.initEvents, 0)

		for _, event := range testCase.addedEvents {
			w.add(event)
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
