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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	corev1a2 "github.com/vmware-tanzu/antrea/pkg/apis/core/v1alpha2"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

func TestProcessClusterNetworkPolicy(t *testing.T) {
	p10 := float64(10)
	t10 := int32(10)
	tierA := secv1alpha1.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "tier-A", UID: "uidA"},
		Spec: secv1alpha1.TierSpec{
			Priority:    t10,
			Description: "tier-A",
		},
	}

	allowAction := secv1alpha1.RuleActionAllow
	protocolTCP := controlplane.ProtocolTCP
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	cgA := corev1a2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec: corev1a2.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
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
									Port: &int80,
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
									Port: &int81,
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
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpA",
					UID:  "uidA",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC, nil).NormalizedName)},
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
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "rules-with-different-selectors",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "", Name: "cnpB", UID: "uidB"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &int80,
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
									Port: &int81,
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
				UID:  "uidB",
				Name: "uidB",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpB",
					UID:  "uidB",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, nil, nil).NormalizedName)},
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
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", nil, &selectorC, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   2,
		},
		{
			name: "with-tier-A",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "", Name: "cnpC", UID: "uidC"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Tier:     "tier-A",
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &int80,
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
									Port: &int81,
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
				UID:  "uidC",
				Name: "uidC",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpC",
					UID:  "uidC",
				},
				Priority:     &p10,
				TierPriority: &t10,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, nil, nil).NormalizedName)},
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
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", nil, &selectorC, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   2,
		},
		{
			name: "with-port-range",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "", Name: "cnpD", UID: "uidD"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Protocol: &k8sProtocolTCP,
									Port:     &int1000,
									EndPort:  &int32For1999,
								},
							},
							From: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
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
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpD",
					UID:  "uidD",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, nil, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "appliedTo-per-rule",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpH", UID: "uidH"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: nil,
					Priority:  p10,
					Ingress: []secv1alpha1.Rule{
						{
							AppliedTo: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &selectorA,
								},
							},
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &int80,
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
							AppliedTo: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &int81,
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
				UID:  "uidH",
				Name: "uidH",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpH",
					UID:  "uidH",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction:       controlplane.DirectionIn,
						AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil, nil).NormalizedName)},
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, nil, nil).NormalizedName)},
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
						AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC, nil).NormalizedName)},
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", nil, &selectorC, nil).NormalizedName)},
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
					getNormalizedUID(toGroupSelector("", &selectorA, nil, nil).NormalizedName),
					getNormalizedUID(toGroupSelector("", &selectorB, &selectorC, nil).NormalizedName),
				},
				AppliedToPerRule: true,
			},
			expectedAppliedToGroups: 2,
			expectedAddressGroups:   2,
		},
		{
			name: "with-cluster-group-ingress-egress",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpI", UID: "uidI"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &int80,
								},
							},
							From: []secv1alpha1.NetworkPolicyPeer{
								{
									Group: cgA.Name,
								},
							},
							Action: &allowAction,
						},
					},
					Egress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &int81,
								},
							},
							To: []secv1alpha1.NetworkPolicyPeer{
								{
									Group: cgA.Name,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidI",
				Name: "uidI",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpI",
					UID:  "uidI",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{cgA.Name},
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
							AddressGroups: []string{cgA.Name},
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
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "with-applied-to-cluster-group-ingress-egress",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpI", UID: "uidI"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					Priority: p10,
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &int80,
								},
							},
							From: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
							AppliedTo: []secv1alpha1.NetworkPolicyPeer{
								{
									Group: cgA.Name,
								},
							},
							Action: &allowAction,
						},
					},
					Egress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &int81,
								},
							},
							To: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
							AppliedTo: []secv1alpha1.NetworkPolicyPeer{
								{
									Group: cgA.Name,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidI",
				Name: "uidI",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpI",
					UID:  "uidI",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction:       controlplane.DirectionIn,
						AppliedToGroups: []string{cgA.Name},
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, nil, nil).NormalizedName)},
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
						Direction:       controlplane.DirectionOut,
						AppliedToGroups: []string{cgA.Name},
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, nil, nil).NormalizedName)},
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
				AppliedToGroups:  []string{cgA.Name},
				AppliedToPerRule: true,
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController()
			c.addClusterGroup(&cgA)
			c.cgStore.Add(&cgA)
			if tt.inputPolicy.Spec.Tier != "" {
				c.tierStore.Add(&tierA)
			}
			assert.Equal(t, tt.expectedPolicy, c.processClusterNetworkPolicy(tt.inputPolicy))
			assert.Equal(t, tt.expectedAddressGroups, len(c.addressGroupStore.List()))
			assert.Equal(t, tt.expectedAppliedToGroups, len(c.appliedToGroupStore.List()))
		})
	}
}

func TestAddCNP(t *testing.T) {
	p10 := float64(10)
	emergencyTierPriority := int32(1)
	emergencyTier := secv1alpha1.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "emergency", UID: "tE"},
		Spec: secv1alpha1.TierSpec{
			Priority: emergencyTierPriority,
		},
	}
	appTier := secv1alpha1.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "application", UID: "tA"},
		Spec: secv1alpha1.TierSpec{
			Priority: DefaultTierPriority,
		},
	}
	allowAction := secv1alpha1.RuleActionAllow
	protocolTCP := controlplane.ProtocolTCP
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorAll := metav1.LabelSelector{}
	matchAllPeerEgress := matchAllPeer
	matchAllPeerEgress.AddressGroups = []string{getNormalizedUID(toGroupSelector("", nil, &selectorAll, nil).NormalizedName)}
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
					Tier:     "application",
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &int80,
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
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpA",
					UID:  "uidA",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "empty-tier-policy",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpB", UID: "uidB"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &int80,
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
				UID:  "uidB",
				Name: "uidB",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpB",
					UID:  "uidB",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil, nil).NormalizedName)},
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
					Tier:     "emergency",
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &int80,
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
				UID:  "uidD",
				Name: "uidD",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpD",
					UID:  "uidD",
				},
				Priority:     &p10,
				TierPriority: &emergencyTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "static-tier-policy",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpE", UID: "uidE"},
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
									Port: &int80,
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
				UID:  "uidE",
				Name: "uidE",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpE",
					UID:  "uidE",
				},
				Priority:     &p10,
				TierPriority: &emergencyTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "rules-with-same-selectors",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpF", UID: "uidF"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &int80,
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
									Port: &int81,
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
				UID:  "uidF",
				Name: "uidF",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpF",
					UID:  "uidF",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC, nil).NormalizedName)},
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
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "rules-with-different-selectors",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpG", UID: "uidG"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Port: &int80,
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
									Port: &int81,
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
				UID:  "uidG",
				Name: "uidG",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpG",
					UID:  "uidG",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, nil, nil).NormalizedName)},
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
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", nil, &selectorC, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   2,
		},
		{
			name: "with-port-range",
			inputPolicy: &secv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "", Name: "cnpH", UID: "uidH"},
				Spec: secv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []secv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []secv1alpha1.Rule{
						{
							Ports: []secv1alpha1.NetworkPolicyPort{
								{
									Protocol: &k8sProtocolTCP,
									Port:     &int1000,
									EndPort:  &int32For1999,
								},
							},
							From: []secv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidH",
				Name: "uidH",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpH",
					UID:  "uidH",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, nil, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("", &selectorA, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			npc.tierStore.Add(&appTier)
			npc.tierStore.Add(&emergencyTier)
			npc.addCNP(tt.inputPolicy)
			key := internalNetworkPolicyKeyFunc(tt.inputPolicy)
			actualPolicyObj, _, _ := npc.internalNetworkPolicyStore.Get(key)
			actualPolicy := actualPolicyObj.(*antreatypes.NetworkPolicy)
			assert.Equal(t, tt.expPolicy, actualPolicy)
			assert.Equal(t, tt.expAddressGroups, len(npc.addressGroupStore.List()))
			assert.Equal(t, tt.expAppliedToGroups, len(npc.appliedToGroupStore.List()))
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
	apgID := getNormalizedUID(toGroupSelector("", &selectorA, nil, nil).NormalizedName)
	_, npc := newController()
	npc.addCNP(cnpObj)
	npc.deleteCNP(cnpObj)
	_, found, _ := npc.appliedToGroupStore.Get(apgID)
	assert.False(t, found, "expected AppliedToGroup to be deleted")
	adgs := npc.addressGroupStore.List()
	assert.Len(t, adgs, 0, "expected empty AddressGroup list")
	key := internalNetworkPolicyKeyFunc(cnpObj)
	_, found, _ = npc.internalNetworkPolicyStore.Get(key)
	assert.False(t, found, "expected internal NetworkPolicy to be deleted")
}

func TestGetTierPriority(t *testing.T) {
	p10 := int32(10)
	tests := []struct {
		name      string
		inputTier *secv1alpha1.Tier
		expPrio   int32
	}{
		{
			name:      "empty-tier-name",
			inputTier: nil,
			expPrio:   DefaultTierPriority,
		},
		{
			name: "tier10",
			inputTier: &secv1alpha1.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: "tA", UID: "uidA"},
				Spec: secv1alpha1.TierSpec{
					Priority:    p10,
					Description: "tier10",
				},
			},
			expPrio: p10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			name := ""
			if tt.inputTier != nil {
				npc.tierStore.Add(tt.inputTier)
				name = tt.inputTier.Name
			}
			actualPrio := npc.getTierPriority(name)
			assert.Equal(t, tt.expPrio, actualPrio, "tier priorities do not match")
		})
	}
}

func TestProcessRefCG(t *testing.T) {
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	cidr := "10.0.0.0/24"
	cidrIPNet, _ := cidrStrToIPNet(cidr)
	// cgA with selector present in cache
	cgA := corev1a2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec: corev1a2.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	// cgB with IPBlock present in cache
	cgB := corev1a2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "uidB"},
		Spec: corev1a2.GroupSpec{
			IPBlock: &secv1alpha1.IPBlock{
				CIDR: cidr,
			},
		},
	}
	// cgC not found in cache
	cgC := corev1a2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgC", UID: "uidC"},
		Spec: corev1a2.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	_, npc := newController()
	npc.addClusterGroup(&cgA)
	npc.addClusterGroup(&cgB)
	npc.cgStore.Add(&cgA)
	npc.cgStore.Add(&cgB)
	tests := []struct {
		name        string
		inputCG     string
		expectedAG  string
		expectedIPB *controlplane.IPBlock
	}{
		{
			name:        "empty-cg-no-result",
			inputCG:     "",
			expectedAG:  "",
			expectedIPB: nil,
		},
		{
			name:        "cg-with-selector",
			inputCG:     cgA.Name,
			expectedAG:  cgA.Name,
			expectedIPB: nil,
		},
		{
			name:        "cg-with-selector-not-found",
			inputCG:     cgC.Name,
			expectedAG:  "",
			expectedIPB: nil,
		},
		{
			name:       "cg-with-ipblock",
			inputCG:    cgB.Name,
			expectedAG: "",
			expectedIPB: &controlplane.IPBlock{
				CIDR:   *cidrIPNet,
				Except: []controlplane.IPNet{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualAG, actualIPB := npc.processRefCG(tt.inputCG)
			assert.Equal(t, tt.expectedIPB, actualIPB, "IPBlock does not match")
			assert.Equal(t, tt.expectedAG, actualAG, "addressGroup does not match")
		})
	}
}

func TestProcessAppliedToGroupsForCGs(t *testing.T) {
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	cidr := "10.0.0.0/24"
	// cgA with selector present in cache
	cgA := corev1a2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec: corev1a2.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	// cgB with IPBlock present in cache
	cgB := corev1a2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "uidB"},
		Spec: corev1a2.GroupSpec{
			IPBlock: &secv1alpha1.IPBlock{
				CIDR: cidr,
			},
		},
	}
	// cgC not found in cache
	cgC := corev1a2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgC", UID: "uidC"},
		Spec: corev1a2.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	_, npc := newController()
	npc.addClusterGroup(&cgA)
	npc.addClusterGroup(&cgB)
	npc.cgStore.Add(&cgA)
	npc.cgStore.Add(&cgB)
	tests := []struct {
		name       string
		inputCG    string
		expectedAG string
	}{
		{
			name:       "empty-cgs-no-result",
			inputCG:    "",
			expectedAG: "",
		},
		{
			name:       "ipblock-cgs-no-result",
			inputCG:    cgB.Name,
			expectedAG: "",
		},
		{
			name:       "selector-cgs-missing-no-result",
			inputCG:    cgC.Name,
			expectedAG: "",
		},
		{
			name:       "selector-cgs",
			inputCG:    cgA.Name,
			expectedAG: cgA.Name,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualAG := npc.processAppliedToGroupForCG(tt.inputCG)
			assert.Equal(t, tt.expectedAG, actualAG, "appliedToGroup list does not match")
		})
	}
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
