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

package store

import (
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apiserver/storage"
	"antrea.io/antrea/pkg/apiserver/storage/ram"
	"antrea.io/antrea/pkg/controller/types"
)

// supportBundleCollectionEvent implements storage.InternalEvent.
type supportBundleCollectionEvent struct {
	// The current version of the stored SupportBundleCollection.
	currBundleCollection *types.SupportBundleCollection
	// The previous version of the stored SupportBundleCollection.
	prevBundleCollection *types.SupportBundleCollection
	// The key of this SupportBundleCollection.
	Key             string
	ResourceVersion uint64
}

// ToWatchEvent converts the supportBundleCollectionEvent to *watch.Event based on the provided Selectors. It has the following features:
// 1. Added event will be generated if the Selectors was not interested in the object but is now.
// 2. Deleted event will be generated if the Selectors was interested in the object but is not now.
func (event *supportBundleCollectionEvent) ToWatchEvent(selectors *storage.Selectors, isInitEvent bool) *watch.Event {
	prevObjSelected, currObjSelected := isSelected(event.Key, event.prevBundleCollection, event.currBundleCollection, selectors, isInitEvent)

	switch {
	case !currObjSelected && !prevObjSelected:
		// Watcher is not interested in that object.
		return nil
	case currObjSelected && !prevObjSelected:
		// Watcher was not interested in that object but is now, an added event will be generated.
		obj := new(controlplane.SupportBundleCollection)
		ToSupportBundleCollectionMsg(event.currBundleCollection, obj, true)
		return &watch.Event{Type: watch.Added, Object: obj}
	case !currObjSelected && prevObjSelected:
		// Watcher was interested in that object but is not interested now, a deleted event will be generated.
		obj := new(controlplane.SupportBundleCollection)
		ToSupportBundleCollectionMsg(event.prevBundleCollection, obj, false)
		return &watch.Event{Type: watch.Deleted, Object: obj}
	}
	return nil
}

func (event *supportBundleCollectionEvent) GetResourceVersion() uint64 {
	return event.ResourceVersion
}

var _ storage.GenEventFunc = genSupportBundleEvent

// genSupportBundleEvent generates InternalEvent from the given versions of an SupportBundleCollection.
func genSupportBundleEvent(key string, prevObj, currObj interface{}, rv uint64) (storage.InternalEvent, error) {
	if reflect.DeepEqual(prevObj, currObj) {
		return nil, nil
	}

	event := &supportBundleCollectionEvent{Key: key, ResourceVersion: rv}

	if prevObj != nil {
		event.prevBundleCollection = prevObj.(*types.SupportBundleCollection)
	}
	if currObj != nil {
		event.currBundleCollection = currObj.(*types.SupportBundleCollection)
	}

	return event, nil
}

// ToSupportBundleCollectionMsg converts the stored SupportBundleCollection to its message form.
// If includeBody is true, the detailed configurations are copied.
func ToSupportBundleCollectionMsg(in *types.SupportBundleCollection, out *controlplane.SupportBundleCollection, includeBody bool) {
	out.Name = in.Name
	out.UID = in.UID
	if !includeBody {
		return
	}
	out.ExpiredAt = in.ExpiredAt
	out.SinceTime = in.SinceTime
	out.FileServer = controlplane.BundleFileServer{
		URL: in.FileServer.URL,
	}
	out.Authentication = in.Authentication
}

// SupportBundleCollectionKeyFunc knows how to get the key of a SupportBundleCollection.
func SupportBundleCollectionKeyFunc(obj interface{}) (string, error) {
	bundle, ok := obj.(*types.SupportBundleCollection)
	if !ok {
		return "", fmt.Errorf("object is not *types.SupportBundleCollection: %v", obj)
	}
	return bundle.Name, nil
}

// NewSupportBundleCollectionStore creates a store of SupportBundleCollection.
func NewSupportBundleCollectionStore() storage.Interface {
	return ram.NewStore(SupportBundleCollectionKeyFunc, nil, genSupportBundleEvent, keyAndSpanSelectFunc, func() runtime.Object { return new(controlplane.SupportBundleCollection) })
}

// keyAndSpanSelectFunc returns whether the provided selectors match the key and/or the nodeNames.
func keyAndSpanSelectFunc(selectors *storage.Selectors, key string, obj interface{}) bool {
	// If Key is present in selectors, the provided key must match it.
	if selectors.Key != "" && key != selectors.Key {
		return false
	}
	// If nodeName is present in selectors' Field selector, the provided nodeNames must contain it.
	if nodeName, found := selectors.Field.RequiresExactMatch("nodeName"); found {
		if !obj.(types.Span).Has(nodeName) {
			return false
		}
	}
	return true
}

// isSelected determines if the previous and the current version of an object should be selected by the given selectors.
func isSelected(key string, prevObj, currObj interface{}, selectors *storage.Selectors, isInitEvent bool) (bool, bool) {
	// We have filtered out init events that we are not interested in, so the current object must be selected.
	if isInitEvent {
		return false, true
	}
	prevObjSelected := !reflect.ValueOf(prevObj).IsNil() && keyAndSpanSelectFunc(selectors, key, prevObj)
	currObjSelected := !reflect.ValueOf(currObj).IsNil() && keyAndSpanSelectFunc(selectors, key, currObj)
	return prevObjSelected, currObjSelected
}
