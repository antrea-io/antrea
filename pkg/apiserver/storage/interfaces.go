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

package storage

import (
	"context"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/watch"
)

// Selectors represent a watcher's conditions to select objects.
type Selectors struct {
	// Key is the identifier of the object the watcher monitors. It can be empty.
	Key string
	// Label filters objects based on LabelSelector.
	Label labels.Selector
	// Field filters objects based on the value of the resource fields.
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
	ToWatchEvent(selectors *Selectors, isInitEvent bool) *watch.Event
	// GetResourceVersion returns the resourceVersion of this event.
	// The resourceVersion is used to filter out previously buffered events when watcher is started.
	GetResourceVersion() uint64
}

// GenEventFunc generates InternalEvent from the add/update/delete of an object.
// Only a single InternalEvent will be generated for each add/update/delete, and the InternalEvent itself should be
// immutable during its conversion to *watch.Event.
type GenEventFunc func(key string, prevObj, obj interface{}, resourceVersion uint64) (InternalEvent, error)

// SelectFunc checks whether an object match the provided selectors.
type SelectFunc func(selectors *Selectors, key string, obj interface{}) bool

// Interface offers a common storage interface for runtime.Object.
// It's provided for Network Policy controller to store the translated Network Policy resources, then Antrea apiserver can
// dispatch events to clients that watch them via the Watch function.
type Interface interface {
	// Create adds a new object unless it already exists.
	Create(obj interface{}) error

	// Update updates an object unless it doesn't exist.
	Update(obj interface{}) error

	// Get gets an object that has the specified key.
	Get(key string) (interface{}, bool, error)

	// GetByIndex gets a list of objects that has the specified index.
	GetByIndex(indexName, indexKey string) ([]interface{}, error)

	// List gets a list of all objects.
	List() []interface{}

	// Delete removes an object that has specified key.
	Delete(key string) error

	// Watch starts watching with the specified key and selectors. Events will be sent to the returned watch.Interface.
	Watch(ctx context.Context, key string, labelSelector labels.Selector, fieldSelector fields.Selector) (watch.Interface, error)

	// GetWatchersNum gets the number of watchers for the store.
	GetWatchersNum() int
}
