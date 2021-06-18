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

package store

import (
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apiserver/storage"
	"antrea.io/antrea/pkg/apiserver/storage/ram"
	"antrea.io/antrea/pkg/controller/types"
)

// addressGroupEvent implements storage.InternalEvent.
type addressGroupEvent struct {
	// The current version of the stored AddressGroup.
	CurrGroup *types.AddressGroup
	// The previous version of the stored AddressGroup.
	PrevGroup *types.AddressGroup
	// The current version of the transferred AddressGroup, which will be used in Added events.
	CurrObject *controlplane.AddressGroup
	// The previous version of the transferred AddressGroup, which will be used in Deleted events.
	// Note that only metadata will be set in Deleted events for efficiency.
	PrevObject *controlplane.AddressGroup
	// The patch object of the message for transferring, which will be used in Modified events.
	PatchObject *controlplane.AddressGroupPatch
	// The key of this AddressGroup.
	Key             string
	ResourceVersion uint64
}

// ToWatchEvent converts the addressGroupEvent to *watch.Event based on the provided Selectors. It has the following features:
// 1. Added event will be generated if the Selectors was not interested in the object but is now.
// 2. Modified event will be generated if the Selectors was and is interested in the object.
// 3. Deleted event will be generated if the Selectors was interested in the object but is not now.
func (event *addressGroupEvent) ToWatchEvent(selectors *storage.Selectors, isInitEvent bool) *watch.Event {
	prevObjSelected, currObjSelected := isSelected(event.Key, event.PrevGroup, event.CurrGroup, selectors, isInitEvent)

	switch {
	case !currObjSelected && !prevObjSelected:
		// Watcher is not interested in that object.
		return nil
	case currObjSelected && !prevObjSelected:
		// Watcher was not interested in that object but is now, an added event will be generated.
		return &watch.Event{Type: watch.Added, Object: event.CurrObject}
	case currObjSelected && prevObjSelected:
		// Watcher was and is interested in that object, a modified event will be generated, unless there's no address change.
		if event.PatchObject == nil {
			return nil
		}
		return &watch.Event{Type: watch.Modified, Object: event.PatchObject}
	case !currObjSelected && prevObjSelected:
		// Watcher was interested in that object but is not interested now, a deleted event will be generated.
		return &watch.Event{Type: watch.Deleted, Object: event.PrevObject}
	}
	return nil
}

func (event *addressGroupEvent) GetResourceVersion() uint64 {
	return event.ResourceVersion
}

// ToAddressGroupMsg converts the stored AddressGroup to its message form.
// If includeBody is true, IPAddresses will be copied.
func ToAddressGroupMsg(in *types.AddressGroup, out *controlplane.AddressGroup, includeBody bool) {
	out.Name = in.Name
	out.UID = in.UID
	if !includeBody {
		return
	}
	for _, member := range in.GroupMembers {
		out.GroupMembers = append(out.GroupMembers, *member)
	}
}

var _ storage.GenEventFunc = genAddressGroupEvent

// genAddressGroupEvent generates InternalEvent from the given versions of an AddressGroup.
// It converts the stored AddressGroup to its message form, and calculates the incremental
// message - an AddressGroupPatch object.
func genAddressGroupEvent(key string, prevObj, currObj interface{}, rv uint64) (storage.InternalEvent, error) {
	if reflect.DeepEqual(prevObj, currObj) {
		return nil, nil
	}

	event := &addressGroupEvent{Key: key, ResourceVersion: rv}

	if prevObj != nil {
		event.PrevGroup = prevObj.(*types.AddressGroup)
		event.PrevObject = new(controlplane.AddressGroup)
		ToAddressGroupMsg(event.PrevGroup, event.PrevObject, false)
	}

	if currObj != nil {
		event.CurrGroup = currObj.(*types.AddressGroup)
		event.CurrObject = new(controlplane.AddressGroup)
		ToAddressGroupMsg(event.CurrGroup, event.CurrObject, true)
	}

	// Calculate PatchObject in advance so that we don't need to do it for
	// each watcher when generating *event.Event.
	if event.PrevGroup != nil && event.CurrGroup != nil {
		var addedMembers, removedMembers []controlplane.GroupMember
		for memberHash, member := range event.CurrGroup.GroupMembers {
			if _, exists := event.PrevGroup.GroupMembers[memberHash]; !exists {
				addedMembers = append(addedMembers, *member)
			}
		}
		for memberHash, member := range event.PrevGroup.GroupMembers {
			if _, exists := event.CurrGroup.GroupMembers[memberHash]; !exists {
				removedMembers = append(removedMembers, *member)
			}
		}
		// PatchObject will not be generated when only span changes.
		if len(addedMembers)+len(removedMembers) > 0 {
			event.PatchObject = new(controlplane.AddressGroupPatch)
			event.PatchObject.UID = event.CurrGroup.UID
			event.PatchObject.Name = event.CurrGroup.Name
			event.PatchObject.AddedGroupMembers = addedMembers
			event.PatchObject.RemovedGroupMembers = removedMembers
		}
	}

	return event, nil
}

// AddressGroupKeyFunc knows how to get the key of an AddressGroup.
func AddressGroupKeyFunc(obj interface{}) (string, error) {
	group, ok := obj.(*types.AddressGroup)
	if !ok {
		return "", fmt.Errorf("object is not *types.AddressGroup: %v", obj)
	}
	return group.Name, nil
}

// NewAddressGroupStore creates a store of AddressGroup.
func NewAddressGroupStore() storage.Interface {
	indexers := cache.Indexers{
		cache.NamespaceIndex: func(obj interface{}) ([]string, error) {
			ag, ok := obj.(*types.AddressGroup)
			if !ok {
				return []string{}, nil
			}
			// ag.Selector.Namespace == "" means it's a cluster scoped group, we index it as it is.
			return []string{ag.Selector.Namespace}, nil
		},
	}
	return ram.NewStore(AddressGroupKeyFunc, indexers, genAddressGroupEvent, keyAndSpanSelectFunc, func() runtime.Object { return new(controlplane.AddressGroup) })
}
