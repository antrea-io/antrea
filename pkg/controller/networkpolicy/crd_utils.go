// Copyright 2020 Antrea Authors
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

package networkpolicy

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

var (
	// matchAllPodsPeerCrd is a secv1alpha1.NetworkPolicyPeer matching all
	// Pods from all Namespaces.
	matchAllPodsPeerCrd = secv1alpha1.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{},
	}
)

// toAntreaServicesForCRD converts a slice of secv1alpha1.NetworkPolicyPort
// objects to a slice of Antrea Service objects. A bool is returned along with
// the Service objects to indicate whether any named port exists.
func toAntreaServicesForCRD(npPorts []secv1alpha1.NetworkPolicyPort) ([]controlplane.Service, bool) {
	var antreaServices []controlplane.Service
	var namedPortExists bool
	for _, npPort := range npPorts {
		if npPort.Port != nil && npPort.Port.Type == intstr.String {
			namedPortExists = true
		}
		antreaService := controlplane.Service{
			Protocol: toAntreaProtocol(npPort.Protocol),
			Port:     npPort.Port,
		}
		antreaServices = append(antreaServices, antreaService)
	}
	return antreaServices, namedPortExists
}

// toAntreaIPBlockForCRD converts a secv1alpha1.IPBlock to an Antrea IPBlock.
func toAntreaIPBlockForCRD(ipBlock *secv1alpha1.IPBlock) (*controlplane.IPBlock, error) {
	// Convert the allowed IPBlock to networkpolicy.IPNet.
	ipNet, err := cidrStrToIPNet(ipBlock.CIDR)
	if err != nil {
		return nil, err
	}
	antreaIPBlock := &controlplane.IPBlock{
		CIDR: *ipNet,
		// secv1alpha.IPBlock does not have the Except slices.
		Except: []controlplane.IPNet{},
	}
	return antreaIPBlock, nil
}

func (n *NetworkPolicyController) toAntreaPeerForCRD(peers []secv1alpha1.NetworkPolicyPeer,
	np metav1.Object, dir controlplane.Direction, namedPortExists bool) *controlplane.NetworkPolicyPeer {
	var addressGroups []string
	// Empty NetworkPolicyPeer is supposed to match all addresses.
	// It's treated as an IPBlock "0.0.0.0/0".
	if len(peers) == 0 {
		// For an egress Peer that specifies any named ports, it creates or
		// reuses the AddressGroup matching all Pods in all Namespaces and
		// appends the AddressGroup UID to the returned Peer such that it can be
		// used to resolve the named ports.
		// For other cases it uses the IPBlock "0.0.0.0/0" to avoid the overhead
		// of handling member updates of the AddressGroup.
		if dir == controlplane.DirectionIn || !namedPortExists {
			return &matchAllPeer
		}
		allPodsGroupUID := n.createAddressGroupForCRD(matchAllPodsPeerCrd, np)
		podsPeer := matchAllPeer
		podsPeer.AddressGroups = append(addressGroups, allPodsGroupUID)
		return &podsPeer
	}
	var ipBlocks []controlplane.IPBlock
	for _, peer := range peers {
		// A secv1alpha1.NetworkPolicyPeer will either have an IPBlock or a
		// podSelector and/or namespaceSelector set.
		if peer.IPBlock != nil {
			ipBlock, err := toAntreaIPBlockForCRD(peer.IPBlock)
			if err != nil {
				klog.Errorf("Failure processing Antrea NetworkPolicy %s/%s IPBlock %v: %v", np.GetNamespace(), np.GetName(), peer.IPBlock, err)
				continue
			}
			ipBlocks = append(ipBlocks, *ipBlock)
		} else {
			normalizedUID := n.createAddressGroupForCRD(peer, np)
			addressGroups = append(addressGroups, normalizedUID)
		}
	}
	return &controlplane.NetworkPolicyPeer{AddressGroups: addressGroups, IPBlocks: ipBlocks}
}

// createAddressGroupForCRD creates an AddressGroup object corresponding to a
// secv1alpha1.NetworkPolicyPeer object in Antrea NetworkPolicyRule. This
// function simply creates the object without actually populating the
// PodAddresses as the affected Pods are calculated during sync process.
func (n *NetworkPolicyController) createAddressGroupForCRD(peer secv1alpha1.NetworkPolicyPeer, np metav1.Object) string {
	groupSelector := toGroupSelector(np.GetNamespace(), peer.PodSelector, peer.NamespaceSelector, peer.ExternalEntitySelector)
	normalizedUID := getNormalizedUID(groupSelector.NormalizedName)
	// Get or create an AddressGroup for the generated UID.
	_, found, _ := n.addressGroupStore.Get(normalizedUID)
	if found {
		return normalizedUID
	}
	// Create an AddressGroup object per Peer object.
	addressGroup := &antreatypes.AddressGroup{
		UID:      types.UID(normalizedUID),
		Name:     normalizedUID,
		Selector: *groupSelector,
	}
	klog.V(2).Infof("Creating new AddressGroup %s with selector (%s)", addressGroup.Name, addressGroup.Selector.NormalizedName)
	n.addressGroupStore.Create(addressGroup)
	return normalizedUID
}

// getTierPriority retrieves the priority associated with the input Tier name.
// If the Tier name is empty, by default, the lowest priority Application Tier
// is returned.
func (n *NetworkPolicyController) getTierPriority(tier string) int32 {
	if tier == "" {
		return defaultTierPriority
	}
	// If the tier name is part of the static tier name set, we need to convert
	// tier name to lowercase to match the corresponding Tier CRD name. This is
	// possible in case of upgrade where in a previously created Antrea Policy
	// CRD was referring to an old static tier. Static tiers were introduced in
	// release 0.9.0 and deprecated in 0.10.0. So any upgrade from 0.9.0 to a
	// later release will undergo this conversion.
	if staticTierSet.Has(tier) {
		tier = strings.ToLower(tier)
	}
	t, err := n.tierLister.Get(tier)
	if err != nil {
		// This error should ideally not occur as we perform validation.
		klog.Errorf("Failed to retrieve Tier %s. Setting default tier priority: %v", tier, err)
		return defaultTierPriority
	}
	return t.Spec.Priority
}
