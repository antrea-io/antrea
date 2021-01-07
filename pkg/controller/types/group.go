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

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
)

type GroupReference struct {
	// Namespace of the Group. It's empty for ClusterGroup.
	Namespace string
	// Name of the Group.
	Name string
}

// GroupSelector describes how to select GroupMembers.
type GroupSelector struct {
	// The normalized name is calculated from Namespace, PodSelector, ExternalEntitySelector and NamespaceSelector.
	// If multiple policies have same selectors, they should share this group by comparing NormalizedName.
	// It's also used to generate Name and UUID of group.
	NormalizedName string
	// If Namespace is set, NamespaceSelector can not be set. It means only GroupMembers in this Namespace will be matched.
	Namespace string
	// This is a label selector which selects GroupMembers. If Namespace is also set, it selects the GroupMembers in the Namespace.
	// If NamespaceSelector is set instead, it selects the GroupMembers in the Namespaces selected by NamespaceSelector.
	// If Namespace and NamespaceSelector both are unset, it selects the GroupMembers in all the Namespaces.
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

// Group describes a set of GroupMembers which can be referenced in Antrea-native NetworkPolicies. These Groups can
// then be converted to AppliedToGroup or AddressGroup.
type Group struct {
	// UID is string representation of the Group/ClusterGroup CRD UID.
	UID types.UID
	// Reference to the original Group or ClusterGroup.
	SourceRef *GroupReference
	// Selector describes how the group selects Pods to get their addresses.
	Selector GroupSelector
	// GroupMembers is a set of GroupMembers selected by this group.
	// It will be converted to a slice of GroupMember for transferring according
	// to client's selection.
	GroupMembers controlplane.GroupMemberSet
	IPBlock      *controlplane.IPBlock
}
