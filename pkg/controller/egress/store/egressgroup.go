// Copyright 2021 Antrea Authors
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

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage/ram"
	"github.com/vmware-tanzu/antrea/pkg/controller/types"
)

// egressGroupEvent implements storage.InternalEvent.
type egressGroupEvent struct {
	// The current version of the stored EgressGroup.
	CurrGroup *types.EgressGroup
	// The previous version of the stored EgressGroup.
	PrevGroup *types.EgressGroup
	// The key of this EgressGroup.
	Key             string
	ResourceVersion uint64
}

/// ToWatchEvent converts the egressGroupEvent to *watch.Event based on the provided Selectors. It has the following features:
// 1. Added event will be generated if the Selectors was not interested in the object but is now.
// 2. Modified event will be generated if the Selectors was and is interested in the object.
// 3. Deleted event will be generated if the Selectors was interested in the object but is not now.
// 4. If nodeName is specified, only GroupMembers that hosted by the Node will be in the event.
func (event *egressGroupEvent) ToWatchEvent(selectors *storage.Selectors, isInitEvent bool) *watch.Event {
	prevObjSelected, currObjSelected := isSelected(event.Key, event.PrevGroup, event.CurrGroup, selectors, isInitEvent)

	// If nodeName is specified in selectors, only GroupMembers that hosted by the Node should be in the event.
	nodeName, nodeSpecified := selectors.Field.RequiresExactMatch("nodeName")

	switch {
	case !currObjSelected && !prevObjSelected:
		// Watcher is not interested in that object.
		return nil
	case currObjSelected && !prevObjSelected:
		// Watcher was not interested in that object but is now, an added event will be generated.
		obj := new(controlplane.EgressGroup)
		if nodeSpecified {
			ToEgressGroupMsg(event.CurrGroup, obj, true, &nodeName)
		} else {
			ToEgressGroupMsg(event.CurrGroup, obj, true, nil)
		}
		return &watch.Event{Type: watch.Added, Object: obj}
	case currObjSelected && prevObjSelected:
		// Watcher was and is interested in that object, a modified event will be generated.
		obj := new(controlplane.EgressGroupPatch)
		obj.UID = event.CurrGroup.UID
		obj.Name = event.CurrGroup.Name

		var currMembers, prevMembers controlplane.GroupMemberSet
		if nodeSpecified {
			currMembers = event.CurrGroup.GroupMemberByNode[nodeName]
			prevMembers = event.PrevGroup.GroupMemberByNode[nodeName]
		} else {
			currMembers = controlplane.GroupMemberSet{}
			for _, members := range event.CurrGroup.GroupMemberByNode {
				currMembers = currMembers.Union(members)
			}
			prevMembers = controlplane.GroupMemberSet{}
			for _, members := range event.PrevGroup.GroupMemberByNode {
				prevMembers = prevMembers.Union(members)
			}
		}
		for _, member := range currMembers.Difference(prevMembers) {
			obj.AddedGroupMembers = append(obj.AddedGroupMembers, *member)
		}
		for _, member := range prevMembers.Difference(currMembers) {
			obj.RemovedGroupMembers = append(obj.RemovedGroupMembers, *member)
		}

		if len(obj.AddedGroupMembers)+len(obj.RemovedGroupMembers) == 0 {
			// No change for the watcher.
			return nil
		}
		return &watch.Event{Type: watch.Modified, Object: obj}
	case !currObjSelected && prevObjSelected:
		// Watcher was interested in that object but is not interested now, a deleted event will be generated.
		obj := new(controlplane.EgressGroup)
		if nodeSpecified {
			ToEgressGroupMsg(event.PrevGroup, obj, false, &nodeName)
		} else {
			ToEgressGroupMsg(event.PrevGroup, obj, false, nil)
		}
		return &watch.Event{Type: watch.Deleted, Object: obj}
	}
	return nil
}

func (event *egressGroupEvent) GetResourceVersion() uint64 {
	return event.ResourceVersion
}

var _ storage.GenEventFunc = genEgressGroupEvent

// genEgressGroupEvent generates InternalEvent from the given versions of an EgressGroup.
func genEgressGroupEvent(key string, prevObj, currObj interface{}, rv uint64) (storage.InternalEvent, error) {
	if reflect.DeepEqual(prevObj, currObj) {
		return nil, nil
	}

	event := &egressGroupEvent{Key: key, ResourceVersion: rv}

	if prevObj != nil {
		event.PrevGroup = prevObj.(*types.EgressGroup)
	}
	if currObj != nil {
		event.CurrGroup = currObj.(*types.EgressGroup)
	}

	return event, nil
}

// ToEgressGroupMsg converts the stored EgressGroup to its message form.
// If includeBody is true, GroupMembers will be copied.
// If nodeName is provided, only GroupMembers that hosted by the Node will be copied.
func ToEgressGroupMsg(in *types.EgressGroup, out *controlplane.EgressGroup, includeBody bool, nodeName *string) {
	out.Name = in.Name
	out.UID = in.UID
	if !includeBody || in.GroupMemberByNode == nil {
		return
	}
	if nodeName != nil {
		if members, exists := in.GroupMemberByNode[*nodeName]; exists {
			for _, member := range members {
				out.GroupMembers = append(out.GroupMembers, *member)
			}
		}
	} else {
		for _, members := range in.GroupMemberByNode {
			for _, member := range members {
				out.GroupMembers = append(out.GroupMembers, *member)
			}
		}
	}
}

// EgressGroupKeyFunc knows how to get the key of an EgressGroup.
func EgressGroupKeyFunc(obj interface{}) (string, error) {
	group, ok := obj.(*types.EgressGroup)
	if !ok {
		return "", fmt.Errorf("object is not *types.EgressGroup: %v", obj)
	}
	return group.Name, nil
}

// NewEgressGroupStore creates a store of EgressGroup.
func NewEgressGroupStore() storage.Interface {
	return ram.NewStore(EgressGroupKeyFunc, nil, genEgressGroupEvent, keyAndSpanSelectFunc, func() runtime.Object { return new(controlplane.EgressGroup) })
}

// keyAndSpanSelectFunc returns whether the provided selectors matches the key and/or the nodeNames.
func keyAndSpanSelectFunc(selectors *storage.Selectors, key string, obj interface{}) bool {
	// If Key is present in selectors, the provided key must match it.
	if selectors.Key != "" && key != selectors.Key {
		return false
	}
	// If nodeName is present in selectors's Field selector, the provided nodeNames must contain it.
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
