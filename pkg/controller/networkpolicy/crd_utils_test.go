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
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	crdv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha2 "github.com/vmware-tanzu/antrea/pkg/apis/crd/v1alpha2"
)

func TestToAntreaServicesForCRD(t *testing.T) {
	tables := []struct {
		ports              []crdv1alpha1.NetworkPolicyPort
		expServices        []controlplane.Service
		expNamedPortExists bool
	}{
		{
			ports: []crdv1alpha1.NetworkPolicyPort{
				{
					Protocol: &k8sProtocolTCP,
					Port:     &int80,
				},
			},
			expServices: []controlplane.Service{
				{
					Protocol: toAntreaProtocol(&k8sProtocolTCP),
					Port:     &int80,
				},
			},
			expNamedPortExists: false,
		},
		{
			ports: []crdv1alpha1.NetworkPolicyPort{
				{
					Protocol: &k8sProtocolTCP,
					Port:     &strHTTP,
				},
			},
			expServices: []controlplane.Service{
				{
					Protocol: toAntreaProtocol(&k8sProtocolTCP),
					Port:     &strHTTP,
				},
			},
			expNamedPortExists: true,
		},
		{
			ports: []crdv1alpha1.NetworkPolicyPort{
				{
					Protocol: &k8sProtocolTCP,
					Port:     &int1000,
					EndPort:  &int32For1999,
				},
			},
			expServices: []controlplane.Service{
				{
					Protocol: toAntreaProtocol(&k8sProtocolTCP),
					Port:     &int1000,
					EndPort:  &int32For1999,
				},
			},
			expNamedPortExists: false,
		},
	}
	for _, table := range tables {
		services, namedPortExist := toAntreaServicesForCRD(table.ports)
		assert.Equal(t, table.expServices, services)
		assert.Equal(t, table.expNamedPortExists, namedPortExist)
	}
}

func TestToAntreaIPBlockForCRD(t *testing.T) {
	expIPNet := controlplane.IPNet{
		IP:           ipStrToIPAddress("10.0.0.0"),
		PrefixLength: 24,
	}
	tables := []struct {
		ipBlock  *crdv1alpha1.IPBlock
		expValue controlplane.IPBlock
		err      error
	}{
		{
			&crdv1alpha1.IPBlock{
				CIDR: "10.0.0.0/24",
			},
			controlplane.IPBlock{
				CIDR: expIPNet,
			},
			nil,
		},
		{
			&crdv1alpha1.IPBlock{
				CIDR: "10.0.0.0",
			},
			controlplane.IPBlock{},
			fmt.Errorf("invalid format for IPBlock CIDR: 10.0.0.0"),
		},
	}
	for _, table := range tables {
		antreaIPBlock, err := toAntreaIPBlockForCRD(table.ipBlock)
		if err != nil {
			if err.Error() != table.err.Error() {
				t.Errorf("Unexpected error in Antrea IPBlock conversion. Expected %v, got %v", table.err, err)
			}
		}
		if antreaIPBlock == nil {
			continue
		}
		ipNet := antreaIPBlock.CIDR
		if bytes.Compare(ipNet.IP, table.expValue.CIDR.IP) != 0 {
			t.Errorf("Unexpected IP in Antrea IPBlock conversion. Expected %v, got %v", table.expValue.CIDR.IP, ipNet.IP)
		}
		if table.expValue.CIDR.PrefixLength != ipNet.PrefixLength {
			t.Errorf("Unexpected PrefixLength in Antrea IPBlock conversion. Expected %v, got %v", table.expValue.CIDR.PrefixLength, ipNet.PrefixLength)
		}
	}
}

func TestToAntreaPeerForCRD(t *testing.T) {
	testCNPObj := &crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cnpA",
		},
	}
	cidr := "10.0.0.0/16"
	cidrIPNet, _ := cidrStrToIPNet(cidr)
	selectorIP := crdv1alpha1.IPBlock{CIDR: cidr}
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorAll := metav1.LabelSelector{}
	matchAllPodsPeer := matchAllPeer
	matchAllPodsPeer.AddressGroups = []string{getNormalizedUID(toGroupSelector("", nil, &selectorAll, nil).NormalizedName)}
	// cgA with selector present in cache
	cgA := crdv1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec: crdv1alpha2.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	tests := []struct {
		name            string
		inPeers         []crdv1alpha1.NetworkPolicyPeer
		outPeer         controlplane.NetworkPolicyPeer
		direction       controlplane.Direction
		namedPortExists bool
		cgExists        bool
	}{
		{
			name: "pod-ns-selector-peer-ingress",
			inPeers: []crdv1alpha1.NetworkPolicyPeer{
				{
					PodSelector:       &selectorA,
					NamespaceSelector: &selectorB,
				},
				{
					PodSelector: &selectorC,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				AddressGroups: []string{
					getNormalizedUID(toGroupSelector("", &selectorA, &selectorB, nil).NormalizedName),
					getNormalizedUID(toGroupSelector("", &selectorC, nil, nil).NormalizedName),
				},
			},
			direction: controlplane.DirectionIn,
		},
		{
			name: "pod-ns-selector-peer-egress",
			inPeers: []crdv1alpha1.NetworkPolicyPeer{
				{
					PodSelector:       &selectorA,
					NamespaceSelector: &selectorB,
				},
				{
					PodSelector: &selectorC,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				AddressGroups: []string{
					getNormalizedUID(toGroupSelector("", &selectorA, &selectorB, nil).NormalizedName),
					getNormalizedUID(toGroupSelector("", &selectorC, nil, nil).NormalizedName),
				},
			},
			direction: controlplane.DirectionOut,
		},
		{
			name: "ipblock-selector-peer-ingress",
			inPeers: []crdv1alpha1.NetworkPolicyPeer{
				{
					IPBlock: &selectorIP,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR: *cidrIPNet,
					},
				},
			},
			direction: controlplane.DirectionIn,
		},
		{
			name: "ipblock-selector-peer-egress",
			inPeers: []crdv1alpha1.NetworkPolicyPeer{
				{
					IPBlock: &selectorIP,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR: *cidrIPNet,
					},
				},
			},
			direction: controlplane.DirectionOut,
		},
		{
			name:      "empty-peer-ingress",
			inPeers:   []crdv1alpha1.NetworkPolicyPeer{},
			outPeer:   matchAllPeer,
			direction: controlplane.DirectionIn,
		},
		{
			name: "peer-ingress-with-cg",
			inPeers: []crdv1alpha1.NetworkPolicyPeer{
				{
					Group: cgA.Name,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				AddressGroups: []string{cgA.Name},
			},
			direction: controlplane.DirectionIn,
		},
		{
			name:            "empty-peer-egress-with-named-port",
			inPeers:         []crdv1alpha1.NetworkPolicyPeer{},
			outPeer:         matchAllPodsPeer,
			direction:       controlplane.DirectionOut,
			namedPortExists: true,
		},
		{
			name:      "empty-peer-egress-without-named-port",
			inPeers:   []crdv1alpha1.NetworkPolicyPeer{},
			outPeer:   matchAllPeer,
			direction: controlplane.DirectionOut,
		},
		{
			name: "peer-egress-with-cg",
			inPeers: []crdv1alpha1.NetworkPolicyPeer{
				{
					Group: cgA.Name,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				AddressGroups: []string{cgA.Name},
			},
			direction: controlplane.DirectionOut,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			npc.addClusterGroup(&cgA)
			npc.cgStore.Add(&cgA)
			actualPeer := npc.toAntreaPeerForCRD(tt.inPeers, testCNPObj, tt.direction, tt.namedPortExists)
			if !reflect.DeepEqual(tt.outPeer.AddressGroups, actualPeer.AddressGroups) {
				t.Errorf("Unexpected AddressGroups in Antrea Peer conversion. Expected %v, got %v", tt.outPeer.AddressGroups, actualPeer.AddressGroups)
			}
			if len(tt.outPeer.IPBlocks) != len(actualPeer.IPBlocks) {
				t.Errorf("Unexpected number of IPBlocks in Antrea Peer conversion. Expected %v, got %v", len(tt.outPeer.IPBlocks), len(actualPeer.IPBlocks))
			}
			for i := 0; i < len(tt.outPeer.IPBlocks); i++ {
				if !compareIPBlocks(&(tt.outPeer.IPBlocks[i]), &(actualPeer.IPBlocks[i])) {
					t.Errorf("Unexpected IPBlocks in Antrea Peer conversion. Expected %v, got %v", tt.outPeer.IPBlocks[i], actualPeer.IPBlocks[i])
				}
			}
		})
	}
}
