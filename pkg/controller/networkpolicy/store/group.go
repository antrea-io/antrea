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
	"k8s.io/client-go/tools/cache"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage/ram"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

// groupEvent implements storage.InternalEvent.
type groupEvent struct {
	// The current version of the stored Group.
	CurrGroup *antreatypes.Group
	// The previous version of the stored Group.
	PrevGroup *antreatypes.Group
	// The current version of the transferred Group, which will be used in Added events.
	CurrObject *controlplane.Group
	// The previous version of the transferred Group, which will be used in Deleted events.
	// Note that only metadata will be set in Deleted events for efficiency.
	PrevObject *controlplane.Group
	// The key of this Group.
	Key             string
	ResourceVersion uint64
}

// ToWatchEvent converts the groupEvent to *watch.Event based on the provided Selectors. It has the following features:
// 1. Added event will be generated if the Selectors was not interested in the object but is now.
// 2. Modified event will be generated if the Selectors was and is interested in the object.
// 3. Deleted event will be generated if the Selectors was interested in the object but is not now.
func (event *groupEvent) ToWatchEvent(selectors *storage.Selectors, isInitEvent bool) *watch.Event {
	prevObjSelected, currObjSelected := isSelected(event.Key, event.PrevGroup, event.CurrGroup, selectors, isInitEvent)

	switch {
	case !currObjSelected && !prevObjSelected:
		// Watcher is not interested in that object.
		return nil
	case currObjSelected && !prevObjSelected:
		// Watcher was not interested in that object but is now, an added event will be generated.
		return &watch.Event{Type: watch.Added, Object: event.CurrObject}
	case currObjSelected && prevObjSelected:
		// Watcher was and is interested in that object, a modified event will be generated, with current object.
		return &watch.Event{Type: watch.Modified, Object: event.CurrObject}
	case !currObjSelected && prevObjSelected:
		// Watcher was interested in that object but is not interested now, a deleted event will be generated.
		return &watch.Event{Type: watch.Deleted, Object: event.PrevObject}
	}
	return nil
}

func (event *groupEvent) GetResourceVersion() uint64 {
	return event.ResourceVersion
}

var _ storage.GenEventFunc = genGroupEvent

// genGroupEvent generates InternalEvent from the given versions of an Group.
func genGroupEvent(key string, prevObj, currObj interface{}, rv uint64) (storage.InternalEvent, error) {
	if reflect.DeepEqual(prevObj, currObj) {
		return nil, nil
	}

	event := &groupEvent{Key: key, ResourceVersion: rv}

	if prevObj != nil {
		event.PrevGroup = prevObj.(*antreatypes.Group)
		event.PrevObject = new(controlplane.Group)
		ToGroupMsg(event.PrevGroup, event.PrevObject, false)
	}

	if currObj != nil {
		event.CurrGroup = currObj.(*antreatypes.Group)
		event.CurrObject = new(controlplane.Group)
		ToGroupMsg(event.CurrGroup, event.CurrObject, true)
	}

	return event, nil
}

// ToGroupMsg converts the stored Group to its message form.
// If includeBody is true, GroupMembers will be copied.
func ToGroupMsg(in *antreatypes.Group, out *controlplane.Group, includeBody bool) {
	out.UID = in.UID
	if !includeBody {
		return
	}
	for _, member := range in.GroupMembers {
		out.GroupMembers = append(out.GroupMembers, *member)
	}
}

// GroupKeyFunc knows how to get the key of an Group.
func GroupKeyFunc(obj interface{}) (string, error) {
	group, ok := obj.(*antreatypes.Group)
	if !ok {
		return "", fmt.Errorf("object is not *types.Group: %v", obj)
	}
	return string(group.UID), nil
}

// NewGroupStore creates a store of Group.
func NewGroupStore() storage.Interface {
	indexers := cache.Indexers{
		cache.NamespaceIndex: func(obj interface{}) ([]string, error) {
			g, ok := obj.(*antreatypes.Group)
			if !ok {
				return []string{}, nil
			}
			return []string{g.Selector.Namespace}, nil
		},
	}
	return ram.NewStore(GroupKeyFunc, indexers, genGroupEvent, keyAndSpanSelectFunc, func() runtime.Object { return new(controlplane.Group) })
}
