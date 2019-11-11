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

package types

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/vmware-tanzu/antrea/pkg/apis/networkpolicy"
)

// SpanMeta describes the span information of an object.
type SpanMeta struct {
	// NodeNames is a set of node names that this object should be sent to.
	NodeNames sets.String
}

// PodSet is a set of Pod references.
type PodSet map[networkpolicy.PodReference]sets.Empty

// Difference returns a set of Pod references that are not in s2.
func (s PodSet) Difference(s2 PodSet) PodSet {
	result := PodSet{}
	for key := range s {
		if _, contained := s2[key]; !contained {
			result[key] = sets.Empty{}
		}
	}
	return result
}

// Union returns a new set which includes items in either s1 or s2.
func (s PodSet) Union(o PodSet) PodSet {
	result := PodSet{}
	for key := range s {
		result.Insert(key)
	}
	for key := range o {
		result.Insert(key)
	}
	return result
}

// Insert adds items to the set.
func (s PodSet) Insert(items ...networkpolicy.PodReference) {
	for _, item := range items {
		s[item] = sets.Empty{}
	}
}

// GroupSelector describes how to select pods.
type GroupSelector struct {
	// The normalized name is calculated from Namespace, PodSelector, and NamespaceSelector.
	// If multiple policies have same selectors, they should share this group by comparing NormalizedName.
	// It's also used to generate Name and UUID of group.
	NormalizedName string
	// If Namespace is set, NamespaceSelector can not be set. It means only pods in this namespace will be matched.
	Namespace string
	// This is a label selector which selects pods. If Namespace is also set, it selects the pods in the namespace.
	// If NamespaceSelector is also set, it selects the pods in the namespaces selected by NamespaceSelector.
	PodSelector *metav1.LabelSelector
	// This is a label selector which selects namespaces. It this field is set, Namespace can not be set.
	NamespaceSelector *metav1.LabelSelector
}

// AppliedToGroup describes a set of Pods to apply Network Policies to.
type AppliedToGroup struct {
	SpanMeta
	// UID is generated from the hash value of GroupSelector.NormalizedName.
	UID types.UID
	// Name of this group, currently it's same as UID.
	Name string
	// Selector describes how the group selects pods.
	Selector GroupSelector
	// PodsByNode is a mapping from nodeName to a set of Pods on the Node.
	// It will be converted to a slice of PodReference for transferring according
	// to client's selection.
	PodsByNode map[string]PodSet
}

// AddressGroup describes a set of addresses used as source or destination of Network Policy rules.
type AddressGroup struct {
	SpanMeta
	// UID is generated from the hash value of GroupSelector.NormalizedName.
	UID types.UID
	// Name of this group, currently it's same as UID.
	Name string
	// Selector describes how the group selects pods to get their addresses.
	Selector GroupSelector
	// Addresses is a set of IP addresses selected by this group.
	// Use sets.String here to calculate diff efficiently when generating events.
	// It will be converted to a slice of IPAddress ([]byte) for transferring.
	Addresses sets.String
}

// NetworkPolicy describes what network traffic is allowed for a set of Pods.
type NetworkPolicy struct {
	SpanMeta
	// UID of the original K8s Network Policy.
	UID types.UID
	// Name of the original K8s Network Policy.
	Name string
	// Namespace of the original K8s Network Policy.
	Namespace string
	// Rules is a list of rules to be applied to the selected Pods.
	Rules []networkpolicy.NetworkPolicyRule
	// AppliedToGroups is a list of names of AppliedToGroups to which this policy applies.
	AppliedToGroups []string
}
