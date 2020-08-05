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

package networkpolicy

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/vmware-tanzu/antrea/pkg/apis/networking"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

func TestToAntreaServicesForCRD(t *testing.T) {
	tcpProto := v1.ProtocolTCP
	portNum := intstr.FromInt(80)
	tables := []struct {
		ports     []secv1alpha1.NetworkPolicyPort
		expValues []networking.Service
	}{
		{
			getCNPPorts(tcpProto),
			[]networking.Service{
				{
					Protocol: toAntreaProtocol(&tcpProto),
					Port:     &portNum,
				},
			},
		},
	}
	for _, table := range tables {
		services := toAntreaServicesForCRD(table.ports)
		service := services[0]
		expValue := table.expValues[0]
		if *service.Protocol != *expValue.Protocol {
			t.Errorf("Unexpected Antrea Protocol in Antrea Service. Expected %v, got %v", *expValue.Protocol, *service.Protocol)
		}
		if *service.Port != *expValue.Port {
			t.Errorf("Unexpected Antrea Port in Antrea Service. Expected %v, got %v", *expValue.Port, *service.Port)
		}
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
		name      string
		inPeers   []secv1alpha1.NetworkPolicyPeer
		outPeer   networking.NetworkPolicyPeer
		direction networking.Direction
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
			name:      "empty-peer-egress",
			inPeers:   []secv1alpha1.NetworkPolicyPeer{},
			outPeer:   matchAllPodsPeer,
			direction: networking.DirectionOut,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			actualPeer := npc.toAntreaPeerForCRD(tt.inPeers, testCNPObj, tt.direction)
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

func TestProcessClusterNetworkPolicy(t *testing.T) {
	p10 := float64(10)
	appTier := antreatypes.TierApplication
	allowAction := secv1alpha1.RuleActionAllow
	protocolTCP := networking.ProtocolTCP
	intstr80, intstr81 := intstr.FromInt(80), intstr.FromInt(81)
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	tests := []struct {
		name                    string
		inputPolicy             *secv1alpha1.ClusterNetworkPolicy
		expectedPolicy          *antreatypes.NetworkPolicy
		expectedAppliedToGroups int
		expectedAddressGroups   int
	}{
		{
			name: "rules-with-same-selectors",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpA", UID: "uidA"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &intstr80,
								},
							},
							From: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
							Action: &allowAction,
						},
					},
					Egress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &intstr81,
								},
							},
							To: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:          "uidA",
				Name:         "cnpA",
				Namespace:    "",
				Priority:     &p10,
				TierPriority: &appTier,
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &intstr80,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
					{
						Direction: networking.DirectionOut,
						To: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &intstr81,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "rules-with-different-selectors",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "", Name: "cnpA", UID: "uidA"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &intstr80,
								},
							},
							From: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
							Action: &allowAction,
						},
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &intstr81,
								},
							},
							From: []secv1alpha1.NetworkPolicyPeer{
								{
									NamespaceSelector: &selectorC,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:          "uidA",
				Name:         "cnpA",
				Namespace:    "",
				Priority:     &p10,
				TierPriority: &appTier,
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, nil).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &intstr80,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", nil, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &intstr81,
							},
						},
						Priority: 1,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController()

			if actualPolicy := c.processClusterNetworkPolicy(tt.inputPolicy); !reflect.DeepEqual(actualPolicy, tt.expectedPolicy) {
				t.Errorf("processClusterNetworkPolicy() got %v, want %v", actualPolicy, tt.expectedPolicy)
			}

			if actualAddressGroups := len(c.addressGroupStore.List()); actualAddressGroups != tt.expectedAddressGroups {
				t.Errorf("len(addressGroupStore.List()) got %v, want %v", actualAddressGroups, tt.expectedAddressGroups)
			}

			if actualAppliedToGroups := len(c.appliedToGroupStore.List()); actualAppliedToGroups != tt.expectedAppliedToGroups {
				t.Errorf("len(appliedToGroupStore.List()) got %v, want %v", actualAppliedToGroups, tt.expectedAppliedToGroups)
			}
		})
	}
}

func TestAddCNP(t *testing.T) {
	p10 := float64(10)
	appTier := antreatypes.TierApplication
	secOpsTier := antreatypes.TierSecurityOps
	netOpsTier := antreatypes.TierNetworkOps
	platformTier := antreatypes.TierPlatform
	emergencyTier := antreatypes.TierEmergency
	allowAction := secv1alpha1.RuleActionAllow
	protocolTCP := networking.ProtocolTCP
	intstr80, intstr81 := intstr.FromInt(80), intstr.FromInt(81)
	int80, int81 := intstr.FromInt(80), intstr.FromInt(81)
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorAll := metav1.LabelSelector{}
	matchAllPeerEgress := matchAllPeer
	matchAllPeerEgress.AddressGroups = []string{getNormalizedUID(toGroupSelector("", nil, &selectorAll).NormalizedName)}
	tests := []struct {
		name               string
		inputPolicy        *secv1alpha1.ClusterNetworkPolicy
		expPolicy          *antreatypes.NetworkPolicy
		expAppliedToGroups int
		expAddressGroups   int
	}{
		{
			name: "application-tier-policy",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpA", UID: "uidA"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Tier:     "Application",
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &intstr80,
								},
							},
							From: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expPolicy: &antreatypes.NetworkPolicy{
				UID:          "uidA",
				Name:         "cnpA",
				Namespace:    "",
				Priority:     &p10,
				TierPriority: &appTier,
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "secops-tier-policy",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpB", UID: "uidB"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Tier:     "SecurityOps",
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &intstr80,
								},
							},
							From: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expPolicy: &antreatypes.NetworkPolicy{
				UID:          "uidB",
				Name:         "cnpB",
				Namespace:    "",
				Priority:     &p10,
				TierPriority: &secOpsTier,
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "netops-tier-policy",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpC", UID: "uidC"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Tier:     "NetworkOps",
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &intstr80,
								},
							},
							From: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expPolicy: &antreatypes.NetworkPolicy{
				UID:          "uidC",
				Name:         "cnpC",
				Namespace:    "",
				Priority:     &p10,
				TierPriority: &netOpsTier,
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "emergency-tier-policy",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpD", UID: "uidD"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Tier:     "Emergency",
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &intstr80,
								},
							},
							From: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expPolicy: &antreatypes.NetworkPolicy{
				UID:          "uidD",
				Name:         "cnpD",
				Namespace:    "",
				Priority:     &p10,
				TierPriority: &emergencyTier,
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "inter-tenant-tier-policy",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpE", UID: "uidE"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Tier:     "Platform",
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &intstr80,
								},
							},
							From: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expPolicy: &antreatypes.NetworkPolicy{
				UID:          "uidE",
				Name:         "cnpE",
				Namespace:    "",
				Priority:     &p10,
				TierPriority: &platformTier,
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "rules-with-same-selectors",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "npE", UID: "uidE"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &intstr80,
								},
							},
							From: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
							Action: &allowAction,
						},
					},
					Egress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &intstr81,
								},
							},
							To: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expPolicy: &antreatypes.NetworkPolicy{
				UID:          "uidE",
				Name:         "npE",
				Namespace:    "",
				Priority:     &p10,
				TierPriority: &appTier,
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
					{
						Direction: networking.DirectionOut,
						To: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "rules-with-different-selectors",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "npF", UID: "uidF"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &intstr80,
								},
							},
							From: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
							Action: &allowAction,
						},
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &intstr81,
								},
							},
							From: []secv1alpha1.NetworkPolicyPeer{
								{
									NamespaceSelector: &selectorC,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expPolicy: &antreatypes.NetworkPolicy{
				UID:          "uidF",
				Name:         "npF",
				Namespace:    "",
				Priority:     &p10,
				TierPriority: &appTier,
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, nil).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", nil, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
						Priority: 1,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			npc.addCNP(tt.inputPolicy)
			key, _ := keyFunc(tt.inputPolicy)
			actualPolicyObj, _, _ := npc.internalNetworkPolicyStore.Get(key)
			actualPolicy := actualPolicyObj.(*antreatypes.NetworkPolicy)
			if !reflect.DeepEqual(actualPolicy, tt.expPolicy) {
				t.Errorf("addCNP() got %v, want %v", actualPolicy, tt.expPolicy)
			}

			if actualAddressGroups := len(npc.addressGroupStore.List()); actualAddressGroups != tt.expAddressGroups {
				t.Errorf("len(addressGroupStore.List()) got %v, want %v", actualAddressGroups, tt.expAddressGroups)
			}

			if actualAppliedToGroups := len(npc.appliedToGroupStore.List()); actualAppliedToGroups != tt.expAppliedToGroups {
				t.Errorf("len(appliedToGroupStore.List()) got %v, want %v", actualAppliedToGroups, tt.expAppliedToGroups)
			}
		})
	}
	_, npc := newController()
	for _, tt := range tests {
		npc.addCNP(tt.inputPolicy)
	}
	assert.Equal(t, 7, npc.GetNetworkPolicyNum(), "number of NetworkPolicies do not match")
	assert.Equal(t, 3, npc.GetAddressGroupNum(), "number of AddressGroups do not match")
	assert.Equal(t, 1, npc.GetAppliedToGroupNum(), "number of AppliedToGroups do not match")
}

func TestDeleteCNP(t *testing.T) {
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	cnpObj := getCNP()
	apgID := getNormalizedUID(toGroupSelector("", &selectorA, nil).NormalizedName)
	_, npc := newController()
	npc.addCNP(cnpObj)
	npc.deleteCNP(cnpObj)
	_, found, _ := npc.appliedToGroupStore.Get(apgID)
	assert.False(t, found, "expected AppliedToGroup to be deleted")
	adgs := npc.addressGroupStore.List()
	assert.Len(t, adgs, 0, "expected empty AddressGroup list")
	key, _ := keyFunc(cnpObj)
	_, found, _ = npc.internalNetworkPolicyStore.Get(key)
	assert.False(t, found, "expected internal NetworkPolicy to be deleted")
}

// util functions for testing.

func getCNP() *secv1alpha1.ClusterNetworkPolicy {
	p10 := float64(10)
	allowAction := secv1alpha1.RuleActionAllow
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	ingressRules := []secv1alpha1.Rule{
		{
			From: []secv1alpha1.NetworkPolicyPeer{
				{
					NamespaceSelector: &selectorB,
				},
			},
			Action: &allowAction,
		},
	}
	egressRules := []secv1alpha1.Rule{
		{
			To: []secv1alpha1.NetworkPolicyPeer{
				{
					PodSelector: &selectorC,
				},
			},
			Action: &allowAction,
		},
	}
	npObj := &secv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cnp"},
		Spec: secv1alpha1.ClusterNetworkPolicySpec{
			AppliedTo: []secv1alpha1.NetworkPolicyPeer{
				{PodSelector: &selectorA},
			},
			Priority: p10,
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
	return npObj

}

func getCNPPorts(proto v1.Protocol) []secv1alpha1.NetworkPolicyPort {
	portNum := intstr.FromInt(80)
	port := secv1alpha1.NetworkPolicyPort{
		Protocol: &proto,
		Port:     &portNum,
	}
	ports := []secv1alpha1.NetworkPolicyPort{port}
	return ports
}
