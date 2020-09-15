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
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
)

// SpanMeta describes the span information of an object.
type SpanMeta struct {
	// NodeNames is a set of node names that this object should be sent to.
	NodeNames sets.String
}

// Span provides methods to work with SpanMeta and objects composed of it.
type Span interface {
	Has(nodeName string) bool
}

func (meta *SpanMeta) Has(nodeName string) bool {
	return meta.NodeNames.Has(nodeName)
}

const (
	TierEmergency controlplane.TierPriority = iota + 1
	TierSecurityOps
	TierNetworkOps
	TierPlatform
	TierApplication
)

// GroupSelector describes how to select Pods.
type GroupSelector struct {
	// The normalized name is calculated from Namespace, PodSelector, ExternalEntitySelector and NamespaceSelector.
	// If multiple policies have same selectors, they should share this group by comparing NormalizedName.
	// It's also used to generate Name and UUID of group.
	NormalizedName string
	// If Namespace is set, NamespaceSelector can not be set. It means only Pods in this Namespace will be matched.
	Namespace string
	// This is a label selector which selects Pods. If Namespace is also set, it selects the Pods in the Namespace.
	// If NamespaceSelector is set instead, it selects the Pods in the Namespaces selected by NamespaceSelector.
	// If Namespace and NamespaceSelector both are unset, it selects the Pods in all the Namespaces.
	PodSelector labels.Selector
	// This is a label selector which selects Namespaces. It this field is set, Namespace can not be set.
	NamespaceSelector labels.Selector
	// This is a label selector which selects ExternalEntities. Within a group, ExternalEntitySelector cannot be
	// set concurrently with PodSelector. If Namespace is also set, it selects the ExternalEntities in the Namespace.
	// If NamespaceSelector is set instead, it selects ExternalEntities in the Namespaces selected by NamespaceSelector.
	// If Namespace and NamespaceSelector both are unset, it selects the ExternalEntities in all the Namespaces.
	// TODO: Add validation in API to not allow externalEntitySelector and podSelector in the same group.
	ExternalEntitySelector labels.Selector
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
	// It will be converted to a slice of GroupMemberPod for transferring according
	// to client's selection.
	PodsByNode map[string]controlplane.GroupMemberPodSet
	// ExternalEntityByNode is a mapping from externalNodeName to a set of GroupMembers on that externalNode
	GroupMemberByNode map[string]controlplane.GroupMemberSet
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
	// Pods is a set of Pods selected by this group.
	// It will be converted to a slice of GroupMemberPod for transferring according
	// to client's selection.
	Pods controlplane.GroupMemberPodSet
	// GroupMembers is a set of GroupMembers selected by this group
	// TODO: Eventually Pods should be unified into the GroupMembers field
	GroupMembers controlplane.GroupMemberSet
}

// NetworkPolicy describes what network traffic is allowed for a set of Pods.
type NetworkPolicy struct {
	SpanMeta
	// UID of the internal Network Policy.
	UID types.UID
	// Name of the internal Network Policy.
	Name string
	// Namespace of the original K8s Network Policy.
	// An empty value indicates that the Network Policy is Cluster scoped.
	Namespace string
	// Reference to the original Network Policy.
	SourceRef *controlplane.NetworkPolicyReference
	// Priority represents the relative priority of this Network Policy as compared to
	// other Network Policies. Priority will be unset (nil) for K8s Network Policy.
	Priority *float64
	// Rules is a list of rules to be applied to the selected Pods.
	Rules []controlplane.NetworkPolicyRule
	// AppliedToGroups is a list of names of AppliedToGroups to which this policy applies.
	AppliedToGroups []string
	// TierPriority represents the priority of the Tier associated with this Network
	// Policy.
	TierPriority *controlplane.TierPriority
}
