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

	"antrea.io/antrea/pkg/apis/controlplane"
)

// SpanMeta describes the span information of an object.
type SpanMeta struct {
	// NodeNames is a set of node names that this object should be sent to.
	// nil means it's not calculated yet while empty set means the span is 0 Node.
	NodeNames sets.String
}

// Span provides methods to work with SpanMeta and objects composed of it.
type Span interface {
	Has(nodeName string) bool
}

func (meta *SpanMeta) Has(nodeName string) bool {
	return meta.NodeNames.Has(nodeName)
}

// AppliedToGroup describes a set of GroupMembers to apply Network Policies to.
type AppliedToGroup struct {
	SpanMeta
	// UID is generated from the hash value of GroupSelector.NormalizedName.
	// In case the AppliedToGroup is created for a ClusterGroup, the UID is
	// that of the corresponding ClusterGroup.
	UID types.UID
	// Name of this group, currently it's same as UID.
	Name string
	// Selector describes how the group selects pods.
	Selector GroupSelector
	// GroupMemberByNode is a mapping from nodeName to a set of GroupMembers on the Node,
	// either GroupMembers or ExternalEntity on the external node.
	// It will be converted to a slice of GroupMember for transferring according
	// to client's selection.
	GroupMemberByNode map[string]controlplane.GroupMemberSet
}

// AddressGroup describes a set of addresses used as source or destination of Network Policy rules.
type AddressGroup struct {
	SpanMeta
	// UID is generated from the hash value of GroupSelector.NormalizedName.
	// In case the AddressGroup is created for a ClusterGroup, the UID is
	// that of the corresponding ClusterGroup.
	UID types.UID
	// Name of this group, currently it's same as UID.
	Name string
	// Selector describes how the group selects pods to get their addresses.
	Selector GroupSelector
	// GroupMembers is a set of GroupMembers selected by this group.
	// It will be converted to a slice of GroupMember for transferring according
	// to client's selection.
	GroupMembers controlplane.GroupMemberSet
}

// NetworkPolicy describes what network traffic is allowed for a set of GroupMembers.
type NetworkPolicy struct {
	SpanMeta
	// UID of the internal NetworkPolicy.
	UID types.UID
	// Name of the internal Network Policy, must be unique across all Network Policy types.
	Name string
	// Generation of the internal Network Policy. It's inherited from the original Network Policy.
	Generation int64
	// Reference to the original Network Policy.
	SourceRef *controlplane.NetworkPolicyReference
	// Priority represents the relative priority of this NetworkPolicy as compared to
	// other NetworkPolicies. Priority will be unset (nil) for K8s NetworkPolicy.
	Priority *float64
	// Rules is a list of rules to be applied to the selected GroupMembers.
	Rules []controlplane.NetworkPolicyRule
	// AppliedToGroups is a list of names of AppliedToGroups to which this policy applies.
	AppliedToGroups []string
	// TierPriority represents the priority of the Tier associated with this Network
	// Policy.
	TierPriority *int32
	// AppliedToPerRule tracks if appliedTo is set per rule basis rather than in policy spec.
	// Must be false for K8s NetworkPolicy.
	AppliedToPerRule bool
	// PerNamespaceSelectors maintains a list of unique Namespace selectors of appliedTo groups
	// of the NetworkPolicy, for which a per-namespace rule is created.
	// It is used as an index so that namespace updates can trigger corresponding rules
	// to re-calculate affected namespaces.
	// This can be non-empty only for NetworkPolicy created for Antrea ClusterNetworkPolicy.
	PerNamespaceSelectors []labels.Selector
}
