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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	antreatypes "antrea.io/antrea/pkg/controller/types"
)

var (
	selectorA = metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB = metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC = metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorD = metav1.LabelSelector{MatchLabels: map[string]string{"foo4": "bar4"}}
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
	allowAction := crdv1alpha1.RuleActionAllow
	protocolTCP := controlplane.ProtocolTCP
	tests := []struct {
		name                    string
		inputPolicy             *crdv1alpha1.NetworkPolicy
		expectedPolicy          *antreatypes.NetworkPolicy
		expectedAppliedToGroups int
		expectedAddressGroups   int
	}{
		{
			name: "rules-with-same-selectors",
			inputPolicy: &crdv1alpha1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "npA", UID: "uidA"},
				Spec: crdv1alpha1.NetworkPolicySpec{
					AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []crdv1alpha1.Rule{
						{
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Port: &int80,
								},
							},
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
							Action: &allowAction,
						},
					},
					Egress: []crdv1alpha1.Rule{
						{
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Port: &int81,
								},
							},
							To: []crdv1alpha1.NetworkPolicyPeer{
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
				TierPriority: &DefaultTierPriority,
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
			inputPolicy: &crdv1alpha1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns2", Name: "npB", UID: "uidB"},
				Spec: crdv1alpha1.NetworkPolicySpec{
					AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []crdv1alpha1.Rule{
						{
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Port: &int80,
								},
							},
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
							Action: &allowAction,
						},
						{
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Port: &int81,
								},
							},
							From: []crdv1alpha1.NetworkPolicyPeer{
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
				TierPriority: &DefaultTierPriority,
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
			inputPolicy: &crdv1alpha1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns3", Name: "npC", UID: "uidC"},
				Spec: crdv1alpha1.NetworkPolicySpec{
					AppliedTo: nil,
					Priority:  p10,
					Ingress: []crdv1alpha1.Rule{
						{
							AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &selectorA,
								},
							},
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Port: &int80,
								},
							},
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
							Action: &allowAction,
						},
						{
							AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Port: &int81,
								},
							},
							From: []crdv1alpha1.NetworkPolicyPeer{
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
				TierPriority: &DefaultTierPriority,
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
			inputPolicy: &crdv1alpha1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns4", Name: "npD", UID: "uidD"},
				Spec: crdv1alpha1.NetworkPolicySpec{
					AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []crdv1alpha1.Rule{
						{
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Protocol: &k8sProtocolTCP,
									Port:     &int1000,
									EndPort:  &int32For1999,
								},
							},
							From: []crdv1alpha1.NetworkPolicyPeer{
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
				TierPriority: &DefaultTierPriority,
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
			inputPolicy: &crdv1alpha1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns5", Name: "npE", UID: "uidE"},
				Spec: crdv1alpha1.NetworkPolicySpec{
					AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Egress: []crdv1alpha1.Rule{
						{
							ToServices: []crdv1alpha1.NamespacedName{
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
				TierPriority: &DefaultTierPriority,
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
			name: "rules-with-nodeSelector",
			inputPolicy: &crdv1alpha1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns6", Name: "npF", UID: "uidF"},
				Spec: crdv1alpha1.NetworkPolicySpec{
					AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Egress: []crdv1alpha1.Rule{
						{
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Port: &int81,
								},
							},
							To: []crdv1alpha1.NetworkPolicyPeer{
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
				TierPriority: &DefaultTierPriority,
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController()
			c.serviceStore.Add(&svcA)
			assert.Equal(t, tt.expectedPolicy, c.processAntreaNetworkPolicy(tt.inputPolicy))
			assert.Equal(t, tt.expectedAddressGroups, len(c.addressGroupStore.List()))
			assert.Equal(t, tt.expectedAppliedToGroups, len(c.appliedToGroupStore.List()))
		})
	}
}

func TestAddANP(t *testing.T) {
	p10 := float64(10)
	allowAction := crdv1alpha1.RuleActionAllow
	protocolTCP := controlplane.ProtocolTCP
	int80 := intstr.FromInt(80)
	selectorAll := metav1.LabelSelector{}
	matchAllPeerEgress := matchAllPeer
	matchAllPeerEgress.AddressGroups = []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorAll, nil, nil).NormalizedName)}
	tests := []struct {
		name               string
		inputPolicy        *crdv1alpha1.NetworkPolicy
		expPolicy          *antreatypes.NetworkPolicy
		expAppliedToGroups int
		expAddressGroups   int
	}{
		{
			name: "application-tier-policy",
			inputPolicy: &crdv1alpha1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "anpA", UID: "uidA"},
				Spec: crdv1alpha1.NetworkPolicySpec{
					AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Tier:     "Application",
					Ingress: []crdv1alpha1.Rule{
						{
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Port: &int80,
								},
							},
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									PodSelector:            &selectorB,
									NamespaceSelector:      &selectorC,
									ExternalEntitySelector: &selectorD,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.AntreaNetworkPolicy,
					Namespace: "nsA",
					Name:      "anpA",
					UID:       "uidA",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, &selectorC, &selectorD, nil).NormalizedName)},
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
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "with-port-range",
			inputPolicy: &crdv1alpha1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsB", Name: "npB", UID: "uidB"},
				Spec: crdv1alpha1.NetworkPolicySpec{
					AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []crdv1alpha1.Rule{
						{
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Protocol: &k8sProtocolTCP,
									Port:     &int1000,
									EndPort:  &int32For1999,
								},
							},
							From: []crdv1alpha1.NetworkPolicyPeer{
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
				UID:  "uidB",
				Name: "uidB",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.AntreaNetworkPolicy,
					Namespace: "nsB",
					Name:      "npB",
					UID:       "uidB",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsB", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			npc.addANP(tt.inputPolicy)
			key := internalNetworkPolicyKeyFunc(tt.inputPolicy)
			actualPolicyObj, _, _ := npc.internalNetworkPolicyStore.Get(key)
			actualPolicy := actualPolicyObj.(*antreatypes.NetworkPolicy)

			assert.Equal(t, tt.expPolicy, actualPolicy)
			assert.Equal(t, tt.expAddressGroups, len(npc.addressGroupStore.List()))
			assert.Equal(t, tt.expAppliedToGroups, len(npc.appliedToGroupStore.List()))
		})
	}
}

func TestDeleteANP(t *testing.T) {
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	anpObj := getANP()
	apgID := getNormalizedUID(antreatypes.NewGroupSelector("test-ns", &selectorA, nil, nil, nil).NormalizedName)
	_, npc := newController()
	npc.addANP(anpObj)
	npc.deleteANP(anpObj)
	_, found, _ := npc.appliedToGroupStore.Get(apgID)
	assert.False(t, found, "expected AppliedToGroup to be deleted")
	adgs := npc.addressGroupStore.List()
	assert.Len(t, adgs, 0, "expected empty AddressGroup list")
	key := internalNetworkPolicyKeyFunc(anpObj)
	_, found, _ = npc.internalNetworkPolicyStore.Get(key)
	assert.False(t, found, "expected internal NetworkPolicy to be deleted")
}

// util functions for testing.
func getANP() *crdv1alpha1.NetworkPolicy {
	p10 := float64(10)
	allowAction := crdv1alpha1.RuleActionAllow
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	ingressRules := []crdv1alpha1.Rule{
		{
			From: []crdv1alpha1.NetworkPolicyPeer{
				{
					NamespaceSelector: &selectorB,
				},
			},
			Action: &allowAction,
		},
	}
	egressRules := []crdv1alpha1.Rule{
		{
			To: []crdv1alpha1.NetworkPolicyPeer{
				{
					ExternalEntitySelector: &selectorC,
				},
			},
			Action: &allowAction,
		},
	}
	npObj := &crdv1alpha1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test-ns", Name: "test-anp"},
		Spec: crdv1alpha1.NetworkPolicySpec{
			AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
				{PodSelector: &selectorA},
			},
			Priority: p10,
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
	return npObj
}
