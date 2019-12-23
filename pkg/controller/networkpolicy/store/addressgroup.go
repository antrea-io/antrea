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

// addressGroupEvent implements storage.InternalEvent.
type addressGroupEvent struct {
	// The current version of the stored AddressGroup.
	CurrGroup *types.AddressGroup
	// The previous version of the stored AddressGroup.
	PrevGroup *types.AddressGroup
	// The current version of the transferred AddressGroup, which will be used in Added events.
	CurrObject *networking.AddressGroup
	// The previous version of the transferred AddressGroup, which will be used in Deleted events.
	// Note that only metadata will be set in Deleted events for efficiency.
	PrevObject *networking.AddressGroup
	// The patch object of the message for transferring, which will be used in Modified events.
	PatchObject *networking.AddressGroupPatch
	// The key of this AddressGroup.
	Key             string
	ResourceVersion uint64
}

// ToWatchEvent converts the addressGroupEvent to *watch.Event based on the provided Selectors. It has the following features:
// 1. Added event will be generated if the Selectors was not interested in the object but is now.
// 2. Modified event will be generated if the Selectors was and is interested in the object.
// 3. Deleted event will be generated if the Selectors was interested in the object but is not now.
func (event *addressGroupEvent) ToWatchEvent(selectors *storage.Selectors) *watch.Event {
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

	switch {
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
func ToAddressGroupMsg(in *types.AddressGroup, out *networking.AddressGroup, includeBody bool) {
	out.Name = in.Name
	out.UID = in.UID
	if !includeBody {
		return
	}
	for a := range in.Addresses {
		out.IPAddresses = append(out.IPAddresses, IPStrToIPAddress(a))
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
		event.PrevObject = new(networking.AddressGroup)
		ToAddressGroupMsg(event.PrevGroup, event.PrevObject, false)
	}

	if currObj != nil {
		event.CurrGroup = currObj.(*types.AddressGroup)
		event.CurrObject = new(networking.AddressGroup)
		ToAddressGroupMsg(event.CurrGroup, event.CurrObject, true)
	}

	// Calculate PatchObject in advance so that we don't need to do it for
	// each watcher when generating *event.Event.
	if event.PrevGroup != nil && event.CurrGroup != nil {
		var addedAddresses, removedAddresses []networking.IPAddress

		for _, a := range event.CurrGroup.Addresses.List() {
			if _, exists := event.PrevGroup.Addresses[a]; !exists {
				addedAddresses = append(addedAddresses, IPStrToIPAddress(a))
			}
		}
		for _, a := range event.PrevGroup.Addresses.List() {
			if _, exists := event.CurrGroup.Addresses[a]; !exists {
				removedAddresses = append(removedAddresses, IPStrToIPAddress(a))
			}
		}
		// PatchObject will not be generated when only span changes.
		if len(addedAddresses)+len(removedAddresses) > 0 {
			event.PatchObject = new(networking.AddressGroupPatch)
			event.PatchObject.UID = event.CurrGroup.UID
			event.PatchObject.Name = event.CurrGroup.Name
			event.PatchObject.AddedIPAddresses = addedAddresses
			event.PatchObject.RemovedIPAddresses = removedAddresses
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
	return ram.NewStore(AddressGroupKeyFunc, cache.Indexers{}, genAddressGroupEvent)
}
