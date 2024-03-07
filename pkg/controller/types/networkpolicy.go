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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/apis/controlplane"
)

// SpanMeta describes the span information of an object.
type SpanMeta struct {
	// NodeNames is a set of node names that this object should be sent to.
	// nil means it's not calculated yet while empty set means the span is 0 Node.
	NodeNames sets.Set[string]
}

// Span provides methods to work with SpanMeta and objects composed of it.
type Span interface {
	Has(nodeName string) bool
}

func (meta *SpanMeta) Has(nodeName string) bool {
	return meta.NodeNames.Has(nodeName)
}

// AppliedToGroup describes a set of GroupMembers or a Service to apply Network Policies to.
type AppliedToGroup struct {
	SpanMeta
	// If the AppliedToGroup is created from GroupSelector, UID is generated from the hash value of GroupSelector.NormalizedName.
	// If the AppliedToGroup is created for a ClusterGroup/Group, the UID is that of the corresponding ClusterGroup/Group.
	// If the AppliedToGroup is created for a Service, the UID is generated from the hash value of NamespacedName of the Service.
	UID types.UID
	// In case the AddressGroup is created for a ClusterGroup, it's the Name of the corresponding ClusterGroup.
	// In case the AddressGroup is created for a Group, it's the Namespace/Name of the corresponding Group.
	// Otherwise, it's same as UID.
	Name string

	// Selector, Service, and SourceGroup are mutually exclusive ways of selecting GroupMembers for the AppliedToGroup.
	// For any AppliedToGroup, only one must be set.
	// Selector describes how the group selects pods using selector.
	Selector *GroupSelector
	// Service refers to the Service this group selects. Only a NodePort type Service
	// can be referred by this field.
	Service *controlplane.ServiceReference
	// SourceGroup refers to the ClusterGroup or Group the AppliedToGroup is derived from.
	SourceGroup string

	// GroupMemberByNode is a mapping from nodeName to a set of GroupMembers on the Node,
	// either GroupMembers or ExternalEntity on the external node.
	// It will be converted to a slice of GroupMember for transferring according
	// to client's selection.
	GroupMemberByNode map[string]controlplane.GroupMemberSet
	// SyncError is the Error encountered when syncing this AppliedToGroup.
	SyncError error
}

// AddressGroup describes a set of addresses used as source or destination of Network Policy rules.
type AddressGroup struct {
	SpanMeta
	// If the AddressGroup is created from GroupSelector, UID is generated from the hash value of GroupSelector.NormalizedName.
	// If the AddressGroup is created for a ClusterGroup/Group, the UID is that of the corresponding ClusterGroup/Group.
	UID types.UID
	// In case the AddressGroup is created for a ClusterGroup, it's the Name of the corresponding ClusterGroup.
	// In case the AddressGroup is created for a Group, it's the Namespace/Name of the corresponding ClusterGroup.
	// Otherwise, it's same as UID.
	Name string

	// Selector and SourceGroup are mutually exclusive ways of selecting GroupMembers for the AddressGroup.
	// For any AddressGroup, only one must be set.
	// Selector describes how the group selects pods to get their addresses.
	Selector *GroupSelector
	// SourceGroup refers to the ClusterGroup or Group the AddressGroup is derived from.
	SourceGroup string

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
	// SyncError is the Error encountered when syncing this NetworkPolicy.
	SyncError error
}

// GetAddressGroups returns AddressGroups used by this NetworkPolicy.
func (p *NetworkPolicy) GetAddressGroups() sets.Set[string] {
	addressGroups := sets.New[string]()
	for _, rule := range p.Rules {
		addressGroups.Insert(rule.From.AddressGroups...)
		addressGroups.Insert(rule.To.AddressGroups...)
	}
	return addressGroups
}

// GetAppliedToGroups returns AppliedToGroups used by this NetworkPolicy.
func (p *NetworkPolicy) GetAppliedToGroups() sets.Set[string] {
	return sets.New[string](p.AppliedToGroups...)
}

// RuleInfo stores the original NetworkPolicy info, index of this rule in the NetworkPolicy
// corresponding ingress/egress rules, and the original rule info.
type RuleInfo struct {
	Policy *NetworkPolicy
	Index  int
	Rule   *controlplane.NetworkPolicyRule
}

// EndpointNetworkPolicyRules records policies applied to this endpoint, and rules
// that refer this endpoint in their address groups.
type EndpointNetworkPolicyRules struct {
	Namespace                 string
	Name                      string
	AppliedPolicies           []*NetworkPolicy
	EndpointAsIngressSrcRules []*RuleInfo
	EndpointAsEgressDstRules  []*RuleInfo
}
