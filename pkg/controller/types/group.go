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

package types

import (
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/pkg/apis/controlplane"
)

// GroupSelector describes how to select GroupMembers.
type GroupSelector struct {
	// The normalized name is calculated from Namespace, PodSelector, ExternalEntitySelector and NamespaceSelector.
	// If multiple policies have same standalone selectors, they should share this group by comparing NormalizedName.
	// It's also used to generate Name and UUID of AddressGroup or AppliedToGroup.
	// Internal Groups corresponding to the ClusterGroups use the NormalizedName to detect if there is a change in
	// the selectors.
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

func NewGroupSelector(namespace string, podSelector, nsSelector, extEntitySelector *metav1.LabelSelector) *GroupSelector {
	groupSelector := GroupSelector{}
	if podSelector != nil {
		pSelector, _ := metav1.LabelSelectorAsSelector(podSelector)
		groupSelector.PodSelector = pSelector
	}
	if extEntitySelector != nil {
		eSelector, _ := metav1.LabelSelectorAsSelector(extEntitySelector)
		groupSelector.ExternalEntitySelector = eSelector
	}
	if nsSelector == nil {
		// No namespaceSelector indicates that the pods must be selected within
		// the NetworkPolicy's Namespace.
		groupSelector.Namespace = namespace
	} else {
		nSelector, _ := metav1.LabelSelectorAsSelector(nsSelector)
		groupSelector.NamespaceSelector = nSelector
	}
	name := generateNormalizedName(groupSelector.Namespace, groupSelector.PodSelector, groupSelector.NamespaceSelector, groupSelector.ExternalEntitySelector)
	groupSelector.NormalizedName = name
	return &groupSelector
}

// generateNormalizedName generates a string, based on the selectors, in
// the following format: "namespace=NamespaceName And podSelector=normalizedPodSelector".
// Note: Namespace and nsSelector may or may not be set depending on the
// selector. However, they cannot be set simultaneously.
func generateNormalizedName(namespace string, podSelector, nsSelector, eeSelector labels.Selector) string {
	normalizedName := []string{}
	if nsSelector != nil {
		normalizedName = append(normalizedName, fmt.Sprintf("namespaceSelector=%s", nsSelector.String()))
	} else if namespace != "" {
		normalizedName = append(normalizedName, fmt.Sprintf("namespace=%s", namespace))
	}
	if podSelector != nil {
		normalizedName = append(normalizedName, fmt.Sprintf("podSelector=%s", podSelector.String()))
	}
	if eeSelector != nil {
		normalizedName = append(normalizedName, fmt.Sprintf("eeSelector=%s", eeSelector.String()))
	}
	sort.Strings(normalizedName)
	return strings.Join(normalizedName, " And ")
}

// Group describes a set of GroupMembers which can be referenced in Antrea-native NetworkPolicies. These Groups can
// then be converted to AppliedToGroup or AddressGroup. Each internal Group corresponds to a single ClusterGroup,
// i.e. unlike AppliedTo/AddressGroups created for standalone selectors, these internal Groups are not shared by
// ClusterGroups created with same selectors.
type Group struct {
	// UID is a unique identifier of this internal Group. It is same as that of the ClusterGroup
	// resource UID.
	UID types.UID
	// Name of the ClusterGroup for which this internal Group is created.
	Name string
	// Selector describes how the internal group selects Pods to get their addresses.
	// Selector is nil if Group is defined with ipBlock, or if it has ServiceReference
	// and has not been processed by the controller yet / Service cannot be found.
	Selector *GroupSelector
	IPBlocks []controlplane.IPBlock
	// ServiceReference is reference to a v1.Service, which this Group keeps in sync
	// and updates Selector based on the Service's selector.
	ServiceReference *controlplane.ServiceReference
	// ChildGroups is the list of Group names that belongs to this Group.
	ChildGroups []string
}
