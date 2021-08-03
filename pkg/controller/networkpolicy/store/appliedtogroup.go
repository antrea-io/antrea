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

// appliedToGroupEvent implements storage.InternalEvent.
type appliedToGroupEvent struct {
	// The current version of the stored AppliedToGroup.
	CurrGroup *types.AppliedToGroup
	// The previous version of the stored AppliedToGroup.
	PrevGroup *types.AppliedToGroup
	// The key of this AppliedToGroup.
	Key             string
	ResourceVersion uint64
}

// ToWatchEvent converts the appliedToGroupEvent to *watch.Event based on the provided Selectors. It has the following features:
// 1. Added event will be generated if the Selectors was not interested in the object but is now.
// 2. Modified event will be generated if the Selectors was and is interested in the object.
// 3. Deleted event will be generated if the Selectors was interested in the object but is not now.
// 4. If nodeName is specified, only GroupMembers that hosted by the Node will be in the event.
func (event *appliedToGroupEvent) ToWatchEvent(selectors *storage.Selectors, isInitEvent bool) *watch.Event {
	prevObjSelected, currObjSelected := isSelected(event.Key, event.PrevGroup, event.CurrGroup, selectors, isInitEvent)

	// If nodeName is specified in selectors, only GroupMembers that hosted by the Node should be in the event.
	nodeName, nodeSpecified := selectors.Field.RequiresExactMatch("nodeName")

	switch {
	case !currObjSelected && !prevObjSelected:
		// Watcher is not interested in that object.
		return nil
	case currObjSelected && !prevObjSelected:
		// Watcher was not interested in that object but is now, an added event will be generated.
		obj := new(controlplane.AppliedToGroup)
		if nodeSpecified {
			ToAppliedToGroupMsg(event.CurrGroup, obj, true, &nodeName)
		} else {
			ToAppliedToGroupMsg(event.CurrGroup, obj, true, nil)
		}
		return &watch.Event{Type: watch.Added, Object: obj}
	case currObjSelected && prevObjSelected:
		// Watcher was and is interested in that object, a modified event will be generated.
		obj := new(controlplane.AppliedToGroupPatch)
		obj.UID = event.CurrGroup.UID
		obj.Name = event.CurrGroup.Name

		var currMembers, prevMembers controlplane.GroupMemberSet
		if nodeSpecified {
			currMembers = event.CurrGroup.GroupMemberByNode[nodeName]
			prevMembers = event.PrevGroup.GroupMemberByNode[nodeName]
		} else {
			currMembers = controlplane.GroupMemberSet{}
			for _, members := range event.CurrGroup.GroupMemberByNode {
				currMembers.Merge(members)
			}
			prevMembers = controlplane.GroupMemberSet{}
			for _, members := range event.PrevGroup.GroupMemberByNode {
				prevMembers.Merge(members)
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
		obj := new(controlplane.AppliedToGroup)
		if nodeSpecified {
			ToAppliedToGroupMsg(event.PrevGroup, obj, false, &nodeName)
		} else {
			ToAppliedToGroupMsg(event.PrevGroup, obj, false, nil)
		}
		return &watch.Event{Type: watch.Deleted, Object: obj}
	}
	return nil
}

func (event *appliedToGroupEvent) GetResourceVersion() uint64 {
	return event.ResourceVersion
}

var _ storage.GenEventFunc = genAppliedToGroupEvent

// genAppliedToGroupEvent generates InternalEvent from the given versions of an AppliedToGroup.
func genAppliedToGroupEvent(key string, prevObj, currObj interface{}, rv uint64) (storage.InternalEvent, error) {
	if reflect.DeepEqual(prevObj, currObj) {
		return nil, nil
	}

	event := &appliedToGroupEvent{Key: key, ResourceVersion: rv}

	if prevObj != nil {
		event.PrevGroup = prevObj.(*types.AppliedToGroup)
	}
	if currObj != nil {
		event.CurrGroup = currObj.(*types.AppliedToGroup)
	}

	return event, nil
}

// ToAppliedToGroupMsg converts the stored AppliedToGroup to its message form.
// If includeBody is true, GroupMembers will be copied.
// If nodeName is provided, only GroupMembers that hosted by the Node will be copied.
func ToAppliedToGroupMsg(in *types.AppliedToGroup, out *controlplane.AppliedToGroup, includeBody bool, nodeName *string) {
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

// AppliedToGroupKeyFunc knows how to get the key of an AppliedToGroup.
func AppliedToGroupKeyFunc(obj interface{}) (string, error) {
	group, ok := obj.(*types.AppliedToGroup)
	if !ok {
		return "", fmt.Errorf("object is not *types.AppliedToGroup: %v", obj)
	}
	return group.Name, nil
}

// NewAppliedToGroupStore creates a store of AppliedToGroup.
func NewAppliedToGroupStore() storage.Interface {
	indexers := cache.Indexers{
		cache.NamespaceIndex: func(obj interface{}) ([]string, error) {
			atg, ok := obj.(*types.AppliedToGroup)
			if !ok {
				return []string{}, nil
			}
			return []string{atg.Selector.Namespace}, nil
		},
	}
	return ram.NewStore(AppliedToGroupKeyFunc, indexers, genAppliedToGroupEvent, keyAndSpanSelectFunc, func() runtime.Object { return new(controlplane.AppliedToGroup) })
}
