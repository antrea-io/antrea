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

const (
	AppliedToGroupIndex   = "appliedToGroup"
	AddressGroupIndex     = "addressGroup"
	PerNamespaceRuleIndex = "perNamespaceRule"
	HasPerNamespaceRule   = "hasPerNamespaceRule"
)

// networkPolicyEvent implements storage.InternalEvent.
type networkPolicyEvent struct {
	// The current version of the stored NetworkPolicy.
	CurrPolicy *types.NetworkPolicy
	// The previous version of the stored NetworkPolicy.
	PrevPolicy *types.NetworkPolicy
	// The current version of the transferred NetworkPolicy, which will be used in Added and Modified events.
	CurrObject *controlplane.NetworkPolicy
	// The previous version of the transferred NetworkPolicy, which will be used in Deleted events.
	// Note that only metadata will be set in Deleted events for efficiency.
	PrevObject *controlplane.NetworkPolicy
	// The key of this NetworkPolicy.
	Key             string
	ResourceVersion uint64
}

// ToWatchEvent converts the networkPolicyEvent to *watch.Event based on the provided Selectors. It has the following features:
// 1. Added event will be generated if the Selectors was not interested in the object but is now.
// 2. Modified event will be generated if the Selectors was and is interested in the object.
// 3. Deleted event will be generated if the Selectors was interested in the object but is not now.
func (event *networkPolicyEvent) ToWatchEvent(selectors *storage.Selectors, isInitEvent bool) *watch.Event {
	prevObjSelected, currObjSelected := isSelected(event.Key, event.PrevPolicy, event.CurrPolicy, selectors, isInitEvent)

	switch {
	case !currObjSelected && !prevObjSelected:
		return nil
	case currObjSelected && !prevObjSelected:
		return &watch.Event{Type: watch.Added, Object: event.CurrObject}
	case currObjSelected && prevObjSelected:
		return &watch.Event{Type: watch.Modified, Object: event.CurrObject}
	case !currObjSelected && prevObjSelected:
		return &watch.Event{Type: watch.Deleted, Object: event.PrevObject}
	}
	return nil
}

func (event *networkPolicyEvent) GetResourceVersion() uint64 {
	return event.ResourceVersion
}

var _ storage.GenEventFunc = genNetworkPolicyEvent

// genNetworkPolicyEvent generates InternalEvent from the given versions of a NetworkPolicy.
// It converts the stored NetworkPolicy to its message form.
func genNetworkPolicyEvent(key string, prevObj, currObj interface{}, rv uint64) (storage.InternalEvent, error) {
	if reflect.DeepEqual(prevObj, currObj) {
		return nil, nil
	}

	event := &networkPolicyEvent{Key: key, ResourceVersion: rv}

	if prevObj != nil {
		event.PrevPolicy = prevObj.(*types.NetworkPolicy)
		event.PrevObject = new(controlplane.NetworkPolicy)
		ToNetworkPolicyMsg(event.PrevPolicy, event.PrevObject, false)
	}

	if currObj != nil {
		event.CurrPolicy = currObj.(*types.NetworkPolicy)
		event.CurrObject = new(controlplane.NetworkPolicy)
		ToNetworkPolicyMsg(event.CurrPolicy, event.CurrObject, true)
	}

	return event, nil
}

// ToNetworkPolicyMsg converts the stored NetworkPolicy to its message form.
// If includeBody is true, Rules and AppliedToGroups will be copied.
func ToNetworkPolicyMsg(in *types.NetworkPolicy, out *controlplane.NetworkPolicy, includeBody bool) {
	out.Name = in.Name
	out.UID = in.UID
	out.SourceRef = in.SourceRef
	out.Generation = in.Generation
	if !includeBody {
		return
	}
	// Since stored objects are immutable, we just reference the fields here.
	out.Rules = in.Rules
	// AppliedToGroups at policy level only need to be populated to controlplane msg if
	// appliedTo is not set per rule. Otherwise, the agent will read appliedTo from each
	// rule, and in that case, the policy level appliedTo only contains span information,
	// which the Antrea agent does not care about.
	if !in.AppliedToPerRule {
		out.AppliedToGroups = in.AppliedToGroups
	}
	out.Priority = in.Priority
	out.TierPriority = in.TierPriority
}

// NetworkPolicyKeyFunc knows how to get the key of a NetworkPolicy.
func NetworkPolicyKeyFunc(obj interface{}) (string, error) {
	policy, ok := obj.(*types.NetworkPolicy)
	if !ok {
		return "", fmt.Errorf("object is not *types.NetworkPolicy: %v", obj)
	}
	return policy.Name, nil
}

// NewNetworkPolicyStore creates a store of NetworkPolicy.
func NewNetworkPolicyStore() storage.Interface {
	// Build indices with the appliedToGroups and the addressGroups so that
	// it's efficient to get network policies that have references to specified
	// appliedToGroups or addressGroups.
	indexers := cache.Indexers{
		AppliedToGroupIndex: func(obj interface{}) ([]string, error) {
			fp, ok := obj.(*types.NetworkPolicy)
			if !ok {
				return []string{}, nil
			}
			if len(fp.AppliedToGroups) == 0 {
				return []string{}, nil
			}
			return fp.AppliedToGroups, nil
		},
		AddressGroupIndex: func(obj interface{}) ([]string, error) {
			fp, ok := obj.(*types.NetworkPolicy)
			var groupNames []string
			if !ok {
				return []string{}, nil
			}
			if len(fp.Rules) == 0 {
				return []string{}, nil
			}
			for _, rule := range fp.Rules {
				if rule.Direction == controlplane.DirectionIn {
					groupNames = append(groupNames, rule.From.AddressGroups...)
				} else if rule.Direction == controlplane.DirectionOut {
					groupNames = append(groupNames, rule.To.AddressGroups...)
				}
			}
			return groupNames, nil
		},
		PerNamespaceRuleIndex: func(obj interface{}) ([]string, error) {
			fp, ok := obj.(*types.NetworkPolicy)
			if !ok {
				return []string{}, nil
			}
			if len(fp.PerNamespaceSelectors) > 0 {
				return []string{HasPerNamespaceRule}, nil
			}
			return []string{}, nil
		},
	}
	return ram.NewStore(NetworkPolicyKeyFunc, indexers, genNetworkPolicyEvent, keyAndSpanSelectFunc, func() runtime.Object { return new(controlplane.NetworkPolicy) })
}
