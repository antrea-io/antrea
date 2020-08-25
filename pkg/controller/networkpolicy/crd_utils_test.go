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

	"github.com/vmware-tanzu/antrea/pkg/apis/networking"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
)

func TestToAntreaServicesForCRD(t *testing.T) {
	tables := []struct {
		ports              []secv1alpha1.NetworkPolicyPort
		expServices        []networking.Service
		expNamedPortExists bool
	}{
		{
			ports: []secv1alpha1.NetworkPolicyPort{
				{
					Protocol: &k8sProtocolTCP,
					Port:     &int80,
				},
			},
			expServices: []networking.Service{
				{
					Protocol: toAntreaProtocol(&k8sProtocolTCP),
					Port:     &int80,
				},
			},
			expNamedPortExists: false,
		},
		{
			ports: []secv1alpha1.NetworkPolicyPort{
				{
					Protocol: &k8sProtocolTCP,
					Port:     &strHTTP,
				},
			},
			expServices: []networking.Service{
				{
					Protocol: toAntreaProtocol(&k8sProtocolTCP),
					Port:     &strHTTP,
				},
			},
			expNamedPortExists: true,
		},
	}
	for _, table := range tables {
		services, namedPortExist := toAntreaServicesForCRD(table.ports)
		assert.Equal(t, table.expServices, services)
		assert.Equal(t, table.expNamedPortExists, namedPortExist)
	}
}

func TestToAntreaIPBlockForCRD(t *testing.T) {
	expIPNet := networking.IPNet{
		IP:           ipStrToIPAddress("10.0.0.0"),
		PrefixLength: 24,
	}
	tables := []struct {
		ipBlock  *secv1alpha1.IPBlock
		expValue networking.IPBlock
		err      error
	}{
		{
			&secv1alpha1.IPBlock{
				CIDR: "10.0.0.0/24",
			},
			networking.IPBlock{
				CIDR: expIPNet,
			},
			nil,
		},
		{
			&secv1alpha1.IPBlock{
				CIDR: "10.0.0.0",
			},
			networking.IPBlock{},
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
	testCNPObj := &secv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cnpA",
		},
	}
	cidr := "10.0.0.0/16"
	cidrIPNet, _ := cidrStrToIPNet(cidr)
	selectorIP := secv1alpha1.IPBlock{CIDR: cidr}
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorAll := metav1.LabelSelector{}
	matchAllPodsPeer := matchAllPeer
	matchAllPodsPeer.AddressGroups = []string{getNormalizedUID(toGroupSelector("", nil, &selectorAll).NormalizedName)}
	tests := []struct {
		name            string
		inPeers         []secv1alpha1.NetworkPolicyPeer
		outPeer         networking.NetworkPolicyPeer
		direction       networking.Direction
		namedPortExists bool
	}{
		{
			name: "pod-ns-selector-peer-ingress",
			inPeers: []secv1alpha1.NetworkPolicyPeer{
				{
					PodSelector:       &selectorA,
					NamespaceSelector: &selectorB,
				},
				{
					PodSelector: &selectorC,
				},
			},
			outPeer: networking.NetworkPolicyPeer{
				AddressGroups: []string{
					getNormalizedUID(toGroupSelector("", &selectorA, &selectorB).NormalizedName),
					getNormalizedUID(toGroupSelector("", &selectorC, nil).NormalizedName),
				},
			},
			direction: networking.DirectionIn,
		},
		{
			name: "pod-ns-selector-peer-egress",
			inPeers: []secv1alpha1.NetworkPolicyPeer{
				{
					PodSelector:       &selectorA,
					NamespaceSelector: &selectorB,
				},
				{
					PodSelector: &selectorC,
				},
			},
			outPeer: networking.NetworkPolicyPeer{
				AddressGroups: []string{
					getNormalizedUID(toGroupSelector("", &selectorA, &selectorB).NormalizedName),
					getNormalizedUID(toGroupSelector("", &selectorC, nil).NormalizedName),
				},
			},
			direction: networking.DirectionOut,
		},
		{
			name: "ipblock-selector-peer-ingress",
			inPeers: []secv1alpha1.NetworkPolicyPeer{
				{
					IPBlock: &selectorIP,
				},
			},
			outPeer: networking.NetworkPolicyPeer{
				IPBlocks: []networking.IPBlock{
					{
						CIDR: *cidrIPNet,
					},
				},
			},
			direction: networking.DirectionIn,
		},
		{
			name: "ipblock-selector-peer-egress",
			inPeers: []secv1alpha1.NetworkPolicyPeer{
				{
					IPBlock: &selectorIP,
				},
			},
			outPeer: networking.NetworkPolicyPeer{
				IPBlocks: []networking.IPBlock{
					{
						CIDR: *cidrIPNet,
					},
				},
			},
			direction: networking.DirectionOut,
		},
		{
			name:      "empty-peer-ingress",
			inPeers:   []secv1alpha1.NetworkPolicyPeer{},
			outPeer:   matchAllPeer,
			direction: networking.DirectionIn,
		},
		{
			name:            "empty-peer-egress-with-named-port",
			inPeers:         []secv1alpha1.NetworkPolicyPeer{},
			outPeer:         matchAllPodsPeer,
			direction:       networking.DirectionOut,
			namedPortExists: true,
		},
		{
			name:      "empty-peer-egress-without-named-port",
			inPeers:   []secv1alpha1.NetworkPolicyPeer{},
			outPeer:   matchAllPeer,
			direction: networking.DirectionOut,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			actualPeer := npc.toAntreaPeerForCRD(tt.inPeers, testCNPObj, tt.direction, tt.namedPortExists)
			if !reflect.DeepEqual(tt.outPeer.AddressGroups, (*actualPeer).AddressGroups) {
				t.Errorf("Unexpected AddressGroups in Antrea Peer conversion. Expected %v, got %v", tt.outPeer.AddressGroups, (*actualPeer).AddressGroups)
			}
			if len(tt.outPeer.IPBlocks) != len((*actualPeer).IPBlocks) {
				t.Errorf("Unexpected number of IPBlocks in Antrea Peer conversion. Expected %v, got %v", len(tt.outPeer.IPBlocks), len((*actualPeer).IPBlocks))
			}
			for i := 0; i < len(tt.outPeer.IPBlocks); i++ {
				if !compareIPBlocks(&(tt.outPeer.IPBlocks[i]), &((*actualPeer).IPBlocks[i])) {
					t.Errorf("Unexpected IPBlocks in Antrea Peer conversion. Expected %v, got %v", tt.outPeer.IPBlocks[i], (*actualPeer).IPBlocks[i])
				}
			}
		})
	}
}
