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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	antreatypes "antrea.io/antrea/pkg/controller/types"
)

var (
	selectorA = metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB = metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC = metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}

	icmpType8 = int32(8)
	icmpCode0 = int32(0)
)

func TestProcessAntreaNetworkPolicy(t *testing.T) {
	p10 := float64(10)
	svcA := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc1",
			Namespace: "ns5",
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Port:       80,
					TargetPort: int80,
				},
			},
		},
	}
	allowAction := crdv1beta1.RuleActionAllow
	protocolTCP := controlplane.ProtocolTCP
	tests := []struct {
		name                    string
		inputPolicy             *crdv1beta1.NetworkPolicy
		expectedPolicy          *antreatypes.NetworkPolicy
		expectedAppliedToGroups int
		expectedAddressGroups   int
	}{
		{
			name: "rules-with-same-selectors",
			inputPolicy: &crdv1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "npA", UID: "uidA"},
				Spec: crdv1beta1.NetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []crdv1beta1.Rule{
						{
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									Port: &int80,
								},
							},
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
							Action: &allowAction,
						},
					},
					Egress: []crdv1beta1.Rule{
						{
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									Port: &int81,
								},
							},
							To: []crdv1beta1.NetworkPolicyPeer{
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
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.AntreaNetworkPolicy,
					Namespace: "ns1",
					Name:      "npA",
					UID:       "uidA",
				},
				Priority:     &p10,
				TierPriority: ptr.To(crdv1beta1.DefaultTierPriority),
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, &selectorC, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, &selectorC, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("ns1", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "rules-with-different-selectors",
			inputPolicy: &crdv1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns2", Name: "npB", UID: "uidB"},
				Spec: crdv1beta1.NetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []crdv1beta1.Rule{
						{
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									Port: &int80,
								},
							},
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
							Action: &allowAction,
						},
						{
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									Port: &int81,
								},
							},
							From: []crdv1beta1.NetworkPolicyPeer{
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
				UID:  "uidB",
				Name: "uidB",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.AntreaNetworkPolicy,
					Namespace: "ns2",
					Name:      "npB",
					UID:       "uidB",
				},
				Priority:     &p10,
				TierPriority: ptr.To(crdv1beta1.DefaultTierPriority),
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("ns2", &selectorB, nil, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorC, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
						Priority: 1,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("ns2", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   2,
		},
		{
			name: "appliedTo-per-rule",
			inputPolicy: &crdv1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns3", Name: "npC", UID: "uidC"},
				Spec: crdv1beta1.NetworkPolicySpec{
					AppliedTo: nil,
					Priority:  p10,
					Ingress: []crdv1beta1.Rule{
						{
							AppliedTo: []crdv1beta1.AppliedTo{
								{
									PodSelector: &selectorA,
								},
							},
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									Port: &int80,
								},
							},
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
							Action: &allowAction,
						},
						{
							AppliedTo: []crdv1beta1.AppliedTo{
								{
									PodSelector: &selectorB,
								},
							},
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									Port: &int81,
								},
							},
							From: []crdv1beta1.NetworkPolicyPeer{
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
				UID:  "uidC",
				Name: "uidC",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.AntreaNetworkPolicy,
					Namespace: "ns3",
					Name:      "npC",
					UID:       "uidC",
				},
				Priority:     &p10,
				TierPriority: ptr.To(crdv1beta1.DefaultTierPriority),
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction:       controlplane.DirectionIn,
						AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("ns3", &selectorA, nil, nil, nil).NormalizedName)},
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("ns3", &selectorB, nil, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
					{
						Direction:       controlplane.DirectionIn,
						AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("ns3", &selectorB, nil, nil, nil).NormalizedName)},
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorC, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
						Priority: 1,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{
					getNormalizedUID(antreatypes.NewGroupSelector("ns3", &selectorB, nil, nil, nil).NormalizedName),
					getNormalizedUID(antreatypes.NewGroupSelector("ns3", &selectorA, nil, nil, nil).NormalizedName),
				},
				AppliedToPerRule: true,
			},
			expectedAppliedToGroups: 2,
			expectedAddressGroups:   2,
		},
		{
			name: "with-port-range",
			inputPolicy: &crdv1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns4", Name: "npD", UID: "uidD"},
				Spec: crdv1beta1.NetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []crdv1beta1.Rule{
						{
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									Protocol: &k8sProtocolTCP,
									Port:     &int1000,
									EndPort:  &int32For1999,
								},
							},
							From: []crdv1beta1.NetworkPolicyPeer{
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
				UID:  "uidD",
				Name: "uidD",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.AntreaNetworkPolicy,
					Namespace: "ns4",
					Name:      "npD",
					UID:       "uidD",
				},
				Priority:     &p10,
				TierPriority: ptr.To(crdv1beta1.DefaultTierPriority),
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, &selectorC, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: toAntreaProtocol(&k8sProtocolTCP),
								Port:     &int1000,
								EndPort:  &int32For1999,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("ns4", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "rules-with-to-services",
			inputPolicy: &crdv1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns5", Name: "npE", UID: "uidE"},
				Spec: crdv1beta1.NetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Egress: []crdv1beta1.Rule{
						{
							ToServices: []crdv1beta1.PeerService{
								{
									Namespace: "ns5",
									Name:      "svc1",
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidE",
				Name: "uidE",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.AntreaNetworkPolicy,
					Namespace: "ns5",
					Name:      "npE",
					UID:       "uidE",
				},
				Priority:     &p10,
				TierPriority: ptr.To(crdv1beta1.DefaultTierPriority),
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							ToServices: []controlplane.ServiceReference{
								{
									Namespace: "ns5",
									Name:      "svc1",
								},
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("ns5", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   0,
		},
		{
			name: "rules-with-to-mc-services",
			inputPolicy: &crdv1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns5", Name: "npE2", UID: "uidE2"},
				Spec: crdv1beta1.NetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Egress: []crdv1beta1.Rule{
						{
							ToServices: []crdv1beta1.PeerService{
								{
									Name:  "svc1",
									Scope: crdv1beta1.ScopeClusterSet,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidE2",
				Name: "uidE2",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.AntreaNetworkPolicy,
					Namespace: "ns5",
					Name:      "npE2",
					UID:       "uidE2",
				},
				Priority:     &p10,
				TierPriority: ptr.To(crdv1beta1.DefaultTierPriority),
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							ToServices: []controlplane.ServiceReference{
								{
									Namespace: "ns5",
									Name:      common.ToMCResourceName("svc1"),
								},
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("ns5", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   0,
		},
		{
			name: "rules-with-nodeSelector",
			inputPolicy: &crdv1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns6", Name: "npF", UID: "uidF"},
				Spec: crdv1beta1.NetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Egress: []crdv1beta1.Rule{
						{
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									Port: &int81,
								},
							},
							To: []crdv1beta1.NetworkPolicyPeer{
								{
									NodeSelector: &selectorB,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidF",
				Name: "uidF",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.AntreaNetworkPolicy,
					Namespace: "ns6",
					Name:      "npF",
					UID:       "uidF",
				},
				Priority:     &p10,
				TierPriority: ptr.To(crdv1beta1.DefaultTierPriority),
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, nil, nil, &selectorB).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("ns6", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "rules-with-icmp-protocol",
			inputPolicy: &crdv1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns7", Name: "npG", UID: "uidG"},
				Spec: crdv1beta1.NetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Egress: []crdv1beta1.Rule{
						{
							Protocols: []crdv1beta1.NetworkPolicyProtocol{
								{
									ICMP: &crdv1beta1.ICMPProtocol{
										ICMPType: &icmpType8,
										ICMPCode: &icmpCode0,
									},
								},
							},
							To: []crdv1beta1.NetworkPolicyPeer{
								{
									NodeSelector: &selectorB,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidG",
				Name: "uidG",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.AntreaNetworkPolicy,
					Namespace: "ns7",
					Name:      "npG",
					UID:       "uidG",
				},
				Priority:     &p10,
				TierPriority: ptr.To(crdv1beta1.DefaultTierPriority),
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, nil, nil, &selectorB).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolICMP,
								ICMPType: &icmpType8,
								ICMPCode: &icmpCode0,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("ns7", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "with-l7Protocol",
			inputPolicy: &crdv1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns8", Name: "npH", UID: "uidH"},
				Spec: crdv1beta1.NetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []crdv1beta1.Rule{
						{
							L7Protocols: []crdv1beta1.L7Protocol{{HTTP: &crdv1beta1.HTTPProtocol{Host: "test.com", Method: "GET", Path: "/admin"}}},
							From: []crdv1beta1.NetworkPolicyPeer{
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
				UID:  "uidH",
				Name: "uidH",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.AntreaNetworkPolicy,
					Namespace: "ns8",
					Name:      "npH",
					UID:       "uidH",
				},
				Priority:     &p10,
				TierPriority: ptr.To(crdv1beta1.DefaultTierPriority),
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, &selectorC, nil, nil).NormalizedName)},
						},
						L7Protocols: []controlplane.L7Protocol{{HTTP: &controlplane.HTTPProtocol{Host: "test.com", Method: "GET", Path: "/admin"}}},
						Priority:    0,
						Action:      &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("ns8", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "with-log-label",
			inputPolicy: &crdv1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns9", Name: "npI", UID: "uidI"},
				Spec: crdv1beta1.NetworkPolicySpec{
					AppliedTo: []crdv1beta1.AppliedTo{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []crdv1beta1.Rule{
						{
							Ports: []crdv1beta1.NetworkPolicyPort{
								{
									Port: &int80,
								},
							},
							From: []crdv1beta1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
							Action:        &allowAction,
							EnableLogging: true,
							LogLabel:      "test-log-label",
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidI",
				Name: "uidI",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.AntreaNetworkPolicy,
					Namespace: "ns9",
					Name:      "npI",
					UID:       "uidI",
				},
				Priority:     &p10,
				TierPriority: ptr.To(crdv1beta1.DefaultTierPriority),
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, &selectorC, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
						Priority:      0,
						Action:        &allowAction,
						EnableLogging: true,
						LogLabel:      "test-log-label",
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("ns9", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController(nil, nil)
			c.serviceStore.Add(&svcA)
			actualPolicy, actualAppliedToGroups, actualAddressGroups := c.processAntreaNetworkPolicy(tt.inputPolicy)
			assert.Equal(t, tt.expectedPolicy, actualPolicy)
			assert.Equal(t, tt.expectedAddressGroups, len(actualAddressGroups))
			assert.Equal(t, tt.expectedAppliedToGroups, len(actualAppliedToGroups))
		})
	}
}

func TestAddANNP(t *testing.T) {
	_, npc := newController(nil, nil)
	annp := getANNP()
	npc.addANNP(annp)
	require.Equal(t, 1, npc.internalNetworkPolicyQueue.Len())
	key, done := npc.internalNetworkPolicyQueue.Get()
	expectedKey := getANNPReference(annp)
	assert.Equal(t, *expectedKey, key)
	assert.False(t, done)
}

func TestUpdateANNP(t *testing.T) {
	_, npc := newController(nil, nil)
	annp := getANNP()
	newANNP := annp.DeepCopy()
	// Make a change to the ANNP.
	newANNP.Annotations = map[string]string{"foo": "bar"}
	npc.updateANNP(annp, newANNP)
	require.Equal(t, 1, npc.internalNetworkPolicyQueue.Len())
	key, done := npc.internalNetworkPolicyQueue.Get()
	expectedKey := getANNPReference(annp)
	assert.Equal(t, *expectedKey, key)
	assert.False(t, done)
}

func TestDeleteANNP(t *testing.T) {
	_, npc := newController(nil, nil)
	annp := getANNP()
	npc.deleteANNP(annp)
	require.Equal(t, 1, npc.internalNetworkPolicyQueue.Len())
	key, done := npc.internalNetworkPolicyQueue.Get()
	expectedKey := getANNPReference(annp)
	assert.Equal(t, *expectedKey, key)
	assert.False(t, done)
}

// util functions for testing.
func getANNP() *crdv1beta1.NetworkPolicy {
	p10 := float64(10)
	allowAction := crdv1beta1.RuleActionAllow
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	ingressRules := []crdv1beta1.Rule{
		{
			From: []crdv1beta1.NetworkPolicyPeer{
				{
					NamespaceSelector: &selectorB,
				},
			},
			Action: &allowAction,
		},
	}
	egressRules := []crdv1beta1.Rule{
		{
			To: []crdv1beta1.NetworkPolicyPeer{
				{
					ExternalEntitySelector: &selectorC,
				},
			},
			Action: &allowAction,
		},
	}
	npObj := &crdv1beta1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test-ns", Name: "test-annp"},
		Spec: crdv1beta1.NetworkPolicySpec{
			AppliedTo: []crdv1beta1.AppliedTo{
				{PodSelector: &selectorA},
			},
			Priority: p10,
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
	return npObj
}
