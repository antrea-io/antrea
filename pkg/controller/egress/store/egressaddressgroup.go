// Copyright 2026 Antrea Authors
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
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"

	"antrea.io/antrea/v2/pkg/apis/controlplane"
	"antrea.io/antrea/v2/pkg/apiserver/storage"
	"antrea.io/antrea/v2/pkg/apiserver/storage/ram"
	"antrea.io/antrea/v2/pkg/controller/types"
)

// egressAddressGroupEvent implements storage.InternalEvent.
type egressAddressGroupEvent struct {
	// The current version of the stored EgressAddressGroup.
	CurrGroup *types.EgressAddressGroup
	// The previous version of the stored EgressAddressGroup.
	PrevGroup *types.EgressAddressGroup
	// The current version of the transferred EgressAddressGroup, which will be used in Added events.
	CurrObject *controlplane.EgressAddressGroup
	// The previous version of the transferred EgressAddressGroup, which will be used in Deleted events.
	// Note that only metadata will be set in Deleted events for efficiency.
	PrevObject *controlplane.EgressAddressGroup
	// The patch object of the message for transferring, which will be used in Modified events.
	PatchObject *controlplane.EgressAddressGroupPatch
	// The key of this EgressAddressGroup.
	Key             string
	ResourceVersion uint64
}

// ToWatchEvent converts the egressAddressGroupEvent to *watch.Event based on the provided Selectors. It has the
// following features:
// 1. Added event will be generated if the Selectors was not interested in the object but is now.
// 2. Modified event will be generated if the Selectors was and is interested in the object.
// 3. Deleted event will be generated if the Selectors was interested in the object but is not now.
// Unlike an EgressGroup, an EgressAddressGroup is not split by Node: every Node in its span receives all members.
func (event *egressAddressGroupEvent) ToWatchEvent(selectors *storage.Selectors, isInitEvent bool) *watch.Event {
	prevObjSelected, currObjSelected := isSelected(event.Key, event.PrevGroup, event.CurrGroup, selectors, isInitEvent)

	switch {
	case !currObjSelected && !prevObjSelected:
		// Watcher is not interested in that object.
		return nil
	case currObjSelected && !prevObjSelected:
		// Watcher was not interested in that object but is now, an added event will be generated.
		return &watch.Event{Type: watch.Added, Object: event.CurrObject}
	case currObjSelected && prevObjSelected:
		// Watcher was and is interested in that object, a modified event will be generated, unless neither the
		// members nor the Egresses changed.
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

func (event *egressAddressGroupEvent) GetResourceVersion() uint64 {
	return event.ResourceVersion
}

// ToEgressAddressGroupMsg converts the stored EgressAddressGroup to its message form.
// If includeBody is true, the Egresses and the GroupMembers will be copied.
func ToEgressAddressGroupMsg(in *types.EgressAddressGroup, out *controlplane.EgressAddressGroup, includeBody bool) {
	out.Name = in.Name
	out.UID = in.UID
	if !includeBody {
		return
	}
	if len(in.Egresses) > 0 {
		out.Egresses = sets.List(in.Egresses)
	}
	for _, member := range in.GroupMembers {
		out.GroupMembers = append(out.GroupMembers, *member)
	}
}

var _ storage.GenEventFunc = genEgressAddressGroupEvent

// genEgressAddressGroupEvent generates InternalEvent from the given versions of an EgressAddressGroup.
// It converts the stored EgressAddressGroup to its message form, and calculates the incremental
// message - an EgressAddressGroupPatch object.
func genEgressAddressGroupEvent(key string, prevObj, currObj interface{}, rv uint64) (storage.InternalEvent, error) {
	if reflect.DeepEqual(prevObj, currObj) {
		return nil, nil
	}

	event := &egressAddressGroupEvent{Key: key, ResourceVersion: rv}

	if prevObj != nil {
		event.PrevGroup = prevObj.(*types.EgressAddressGroup)
		event.PrevObject = new(controlplane.EgressAddressGroup)
		ToEgressAddressGroupMsg(event.PrevGroup, event.PrevObject, false)
	}

	if currObj != nil {
		event.CurrGroup = currObj.(*types.EgressAddressGroup)
		event.CurrObject = new(controlplane.EgressAddressGroup)
		ToEgressAddressGroupMsg(event.CurrGroup, event.CurrObject, true)
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
		// The patch carries the complete list of the Egresses, and only when it changes.
		var egresses []string
		if !event.CurrGroup.Egresses.Equal(event.PrevGroup.Egresses) {
			egresses = sets.List(event.CurrGroup.Egresses)
		}
		// PatchObject will not be generated when only span changes.
		if len(addedMembers)+len(removedMembers)+len(egresses) > 0 {
			event.PatchObject = new(controlplane.EgressAddressGroupPatch)
			event.PatchObject.UID = event.CurrGroup.UID
			event.PatchObject.Name = event.CurrGroup.Name
			event.PatchObject.Egresses = egresses
			event.PatchObject.AddedGroupMembers = addedMembers
			event.PatchObject.RemovedGroupMembers = removedMembers
		}
	}

	return event, nil
}

// EgressAddressGroupKeyFunc knows how to get the key of an EgressAddressGroup.
func EgressAddressGroupKeyFunc(obj interface{}) (string, error) {
	group, ok := obj.(*types.EgressAddressGroup)
	if !ok {
		return "", fmt.Errorf("object is not *types.EgressAddressGroup: %v", obj)
	}
	return group.Name, nil
}

// NewEgressAddressGroupStore creates a store of EgressAddressGroup.
func NewEgressAddressGroupStore() storage.Interface {
	return ram.NewStore(EgressAddressGroupKeyFunc, nil, genEgressAddressGroupEvent, keyAndSpanSelectFunc, func() runtime.Object { return new(controlplane.EgressAddressGroup) })
}
