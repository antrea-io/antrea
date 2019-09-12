package storage

import (
	"context"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
)

// Patched is an EventType in addition to EventTypes defined in k8s.io/apimachinery/pkg/watch/watch.go.
// It indicates watch.Event contains an incremental update, not the object itself.
const Patched watch.EventType = "PATCHED"

// Selectors represent a watcher's conditions to select objects.
type Selectors struct {
	// The key of object the watcher interests, can be empty.
	Key   string
	Label labels.Selector
	Field fields.Selector
}

// InternalEvent is an internal event that can be converted to *watch.Event based on watcher's Selectors.
// For example, an internal event may be converted to an ADDED event for one watcher, and to a MODIFIED event
// for another.
type InternalEvent interface {
	// ToWatchEvent converts the InternalEvent to *watch.Event based on the provided Selectors.
	// It will be called once for all watchers that are interested in the event. Expensive computation that will repeat
	// for all watchers should be placed in GenEventFunc as pre-process. For example, the routine that groups a list of
	// pods by nodes is a potential candidate.
	ToWatchEvent(selectors *Selectors) *watch.Event
	// GetResourceVersion returns the resourceVersion of this event.
	// The resourceVersion is used to filter out previously buffered events when starting watching.
	GetResourceVersion() uint64
}

// GenEventFunc generates InternalEvent from the add/update/delete of an object.
// Only a single InternalEvent will be generated for each add/update/delete, and the InternalEvent itself should be
// immutable during its conversion to *watch.Event.
type GenEventFunc func(key string, prevObj, obj runtime.Object, resourceVersion uint64) (InternalEvent, error)

// Interface offers a common storage interface for runtime.Object.
// It's provided for network policy controller to store the translated network policy resources, then OKN apiserver can
// dispatch events to clients that watch them via the Watch function.
type Interface interface {
	// Create adds a new object unless it already exists.
	Create(obj runtime.Object) error

	// Update updates an object unless it doesn't exist.
	Update(obj runtime.Object) error

	// Get gets an object that has the specified key.
	Get(key string) (runtime.Object, bool, error)

	// GetByIndex gets a list of objects that has the specified index.
	GetByIndex(indexName, indexKey string) ([]runtime.Object, error)

	// Delete removes an object that has specified key.
	Delete(key string) error

	// Watch starts watching with the specified key and selectors. Events will be sent to the returned watch.Interface.
	// In particular, objects that exist before the watching starts will be sent in "ADDED" events.
	Watch(ctx context.Context, key string, labelSelector labels.Selector, fieldSelector fields.Selector) (watch.Interface, error)
}
