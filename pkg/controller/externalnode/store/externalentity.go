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
	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apiserver/storage"
	"antrea.io/antrea/pkg/apiserver/storage/ram"
	"antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/util/k8s"
	"fmt"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"reflect"
)

// externalEntityEvent implements storage.InternalEvent.
type externalEntityEvent struct {
	// The current version of the stored ExternalEntity.
	CurEE *types.ExternalEntity
	// The previous version of the stored ExternalEntity.
	PreEE *types.ExternalEntity
	// The current version of the transferred ExternalEntity, which will be used in Added and Modified events.
	CurObject *controlplane.ExternalEntity
	// The previous version of the transferred ExternalEntity, which will be used in Deleted events.
	// Note that only metadata will be set in Deleted events for efficiency.
	PreObject *controlplane.ExternalEntity
	// The key of this ExternalEntity.
	Key             string
	ResourceVersion uint64
}

// ToWatchEvent converts the externalEntityEvent to *watch.Event based on the provided Selectors. It has the following features:
// 1. Added event will be generated if the Selectors was not interested in the object but is now.
// 2. Modified event will be generated if the Selectors was and is interested in the object.
// 3. Deleted event will be generated if the Selectors was interested in the object but is not now.
func (event *externalEntityEvent) ToWatchEvent(selectors *storage.Selectors, isInitEvent bool) *watch.Event {
	prevObjSelected, currObjSelected := isSelected(event.Key, event.PreEE, event.CurEE, selectors, isInitEvent)

	switch {
	case !currObjSelected && !prevObjSelected:
		return nil
	case currObjSelected && !prevObjSelected:
		return &watch.Event{Type: watch.Added, Object: event.CurObject}
	case currObjSelected && prevObjSelected:
		return &watch.Event{Type: watch.Modified, Object: event.CurObject}
	case !currObjSelected && prevObjSelected:
		return &watch.Event{Type: watch.Deleted, Object: event.PreObject}
	}
	return nil
}

func (event *externalEntityEvent) GetResourceVersion() uint64 {
	return event.ResourceVersion
}

// ExternalEntityKeyFunc knows how to get the key of an ExternalEntity.
func ExternalEntityKeyFunc(obj interface{}) (string, error) {
	ee, ok := obj.(*types.ExternalEntity)
	if !ok {
		return "", fmt.Errorf("object is not *types.ExternalEntity: %v", obj)
	}
	return k8s.NamespacedName(ee.Namespace, ee.Name), nil
}

var _ storage.GenEventFunc = genExternalEntityEvent

// genExternalEntityEvent generates InternalEvent from the given versions of an ExternalEntity.
// It converts the stored ExternalEntity to its message form.
func genExternalEntityEvent(key string, preObj, curObj interface{}, rv uint64) (storage.InternalEvent, error) {
	if reflect.DeepEqual(preObj, curObj) {
		return nil, nil
	}

	event := &externalEntityEvent{Key: key, ResourceVersion: rv}

	if preObj != nil {
		event.PreEE = preObj.(*types.ExternalEntity)
		event.PreObject = new(controlplane.ExternalEntity)
		ToExternalEntityMsg(event.PreEE, event.PreObject)
	}

	if curObj != nil {
		event.CurEE = curObj.(*types.ExternalEntity)
		event.CurObject = new(controlplane.ExternalEntity)
		ToExternalEntityMsg(event.CurEE, event.CurObject)
	}

	return event, nil
}

// ToExternalEntityMsg converts the stored ExternalEntity to its message form.
func ToExternalEntityMsg(in *types.ExternalEntity, out *controlplane.ExternalEntity) {
	out.UID = in.UID
	out.Name = in.Name
	out.Namespace = in.Namespace
	out.Endpoints = in.Endpoints
	out.Ports = in.Ports
	out.ExternalNode = in.ExternalNode
}

// NewExternalEntityStore creates a store of ExternalEntity.
func NewExternalEntityStore() storage.Interface {
	return ram.NewStore(ExternalEntityKeyFunc, nil, genExternalEntityEvent, selectFunc, func() runtime.Object { return new(controlplane.ExternalEntity) })
}

// selectFunc returns whether the provided selectors match the key, namespace and nodeName.
func selectFunc(selectors *storage.Selectors, key string, obj interface{}) bool {
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
	// If namespace is present in selectors's Field selector, the provided namespace must contain it.
	if namespace, found := selectors.Field.RequiresExactMatch("metadata.namespace"); found {
		if obj.(*types.ExternalEntity).Namespace != namespace {
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
	prevObjSelected := !reflect.ValueOf(prevObj).IsNil() && selectFunc(selectors, key, prevObj)
	currObjSelected := !reflect.ValueOf(currObj).IsNil() && selectFunc(selectors, key, currObj)
	return prevObjSelected, currObjSelected
}
