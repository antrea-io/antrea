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

	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"

	"github.com/vmware-tanzu/antrea/pkg/apis/networking"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage/ram"
	"github.com/vmware-tanzu/antrea/pkg/controller/types"
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
// 4. If nodeName is specified, only Pods that hosted by the Node will be in the event.
func (event *appliedToGroupEvent) ToWatchEvent(selectors *storage.Selectors) *watch.Event {
	prevObjSelected, currObjSelected := false, false
	if event.CurrGroup != nil {
		currObjSelected = filter(selectors, event.Key, event.CurrGroup.NodeNames)
	}
	if event.PrevGroup != nil {
		prevObjSelected = filter(selectors, event.Key, event.PrevGroup.NodeNames)
	}
	if !currObjSelected && !prevObjSelected {
		// Watcher is not interested in that object.
		return nil
	}

	// If nodeName is specified in selectors, only Pods that hosted by the Node should be in the event.
	nodeName, nodeSpecified := selectors.Field.RequiresExactMatch("nodeName")

	switch {
	case currObjSelected && !prevObjSelected:
		// Watcher was not interested in that object but is now, an added event will be generated.
		obj := new(networking.AppliedToGroup)
		if nodeSpecified {
			ToAppliedToGroupMsg(event.CurrGroup, obj, true, &nodeName)
		} else {
			ToAppliedToGroupMsg(event.CurrGroup, obj, true, nil)
		}
		return &watch.Event{Type: watch.Added, Object: obj}
	case currObjSelected && prevObjSelected:
		// Watcher was and is interested in that object, a modified event will be generated.
		obj := new(networking.AppliedToGroupPatch)
		obj.UID = event.CurrGroup.UID
		obj.Name = event.CurrGroup.Name

		var currPods, prevPods networking.GroupMemberPodSet
		if nodeSpecified {
			currPods = event.CurrGroup.PodsByNode[nodeName]
			prevPods = event.PrevGroup.PodsByNode[nodeName]
		} else {
			currPods = networking.GroupMemberPodSet{}
			for _, pods := range event.CurrGroup.PodsByNode {
				currPods = currPods.Union(pods)
			}
			prevPods = networking.GroupMemberPodSet{}
			for _, pods := range event.PrevGroup.PodsByNode {
				prevPods = prevPods.Union(pods)
			}
		}
		for _, pod := range currPods.Difference(prevPods) {
			obj.AddedPods = append(obj.AddedPods, *pod)
		}
		for _, pod := range prevPods.Difference(currPods) {
			obj.RemovedPods = append(obj.RemovedPods, *pod)
		}
		if len(obj.AddedPods)+len(obj.RemovedPods) == 0 {
			// No change for the watcher.
			return nil
		}
		return &watch.Event{Type: watch.Modified, Object: obj}
	case !currObjSelected && prevObjSelected:
		// Watcher was interested in that object but is not interested now, a deleted event will be generated.
		obj := new(networking.AppliedToGroup)
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
// If includeBody is true, Pods will be copied.
// If nodeName is provided, only Pods that hosted by the Node will be copied.
func ToAppliedToGroupMsg(in *types.AppliedToGroup, out *networking.AppliedToGroup, includeBody bool, nodeName *string) {
	out.Name = in.Name
	out.UID = in.UID
	if !includeBody || in.PodsByNode == nil {
		return
	}
	if nodeName != nil {
		if pods, exists := in.PodsByNode[*nodeName]; exists {
			for _, pod := range pods {
				out.Pods = append(out.Pods, *pod)
			}
		}
	} else {
		for _, pods := range in.PodsByNode {
			for _, pod := range pods {
				out.Pods = append(out.Pods, *pod)
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
	return ram.NewStore(AppliedToGroupKeyFunc, cache.Indexers{}, genAppliedToGroupEvent)
}
