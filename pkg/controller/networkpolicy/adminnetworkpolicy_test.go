// Copyright 2023 Antrea Authors
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
	"k8s.io/apimachinery/pkg/util/intstr"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"antrea.io/antrea/pkg/apis/controlplane"
	antreatypes "antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/features"
)

func TestProcessAdminNetworkPolicy(t *testing.T) {
	p10 := float64(10)
	portName := "secured"
	intstrPortName := intstr.FromString(portName)
	tests := []struct {
		name                    string
		inputPolicy             *v1alpha1.AdminNetworkPolicy
		expectedPolicy          *antreatypes.NetworkPolicy
		expectedAppliedToGroups int
		expectedAddressGroups   int
	}{
		{
			name: "rules-with-same-selectors",
			inputPolicy: &v1alpha1.AdminNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "anpA", UID: "uidA"},
				Spec: v1alpha1.AdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &selectorA,
					},
					Priority: 10,
					Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
							From: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Pods: &v1alpha1.NamespacedPodPeer{
										Namespaces: v1alpha1.NamespacedPeer{
											NamespaceSelector: &selectorC,
										},
										PodSelector: selectorB,
									},
								},
							},
							Ports: &[]v1alpha1.AdminNetworkPolicyPort{
								{
									PortNumber: &v1alpha1.Port{
										Port:     80,
										Protocol: k8sProtocolTCP,
									},
								},
							},
						},
					},
					Egress: []v1alpha1.AdminNetworkPolicyEgressRule{
						{
							Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
							To: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Pods: &v1alpha1.NamespacedPodPeer{
										Namespaces: v1alpha1.NamespacedPeer{
											NamespaceSelector: &selectorC,
										},
										PodSelector: selectorB,
									},
								},
							},
							Ports: &[]v1alpha1.AdminNetworkPolicyPort{
								{
									PortNumber: &v1alpha1.Port{
										Port:     81,
										Protocol: k8sProtocolTCP,
									},
								},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AdminNetworkPolicy,
					Name: "anpA",
					UID:  "uidA",
				},
				Priority:     &p10,
				TierPriority: &adminNetworkPolicyTierPriority,
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorA, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "rules-with-different-selectors",
			inputPolicy: &v1alpha1.AdminNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "anpB", UID: "uidB"},
				Spec: v1alpha1.AdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &selectorA,
					},
					Priority: 10,
					Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
							From: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Pods: &v1alpha1.NamespacedPodPeer{
										Namespaces: v1alpha1.NamespacedPeer{
											NamespaceSelector: &selectorC,
										},
										PodSelector: selectorB,
									},
								},
							},
							Ports: &[]v1alpha1.AdminNetworkPolicyPort{
								{
									PortNumber: &v1alpha1.Port{
										Port:     80,
										Protocol: k8sProtocolTCP,
									},
								},
							},
						},
					},
					Egress: []v1alpha1.AdminNetworkPolicyEgressRule{
						{
							Action: v1alpha1.AdminNetworkPolicyRuleActionDeny,
							To: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Pods: &v1alpha1.NamespacedPodPeer{
										Namespaces: v1alpha1.NamespacedPeer{
											NamespaceSelector: &selectorB,
										},
										PodSelector: selectorC,
									},
								},
							},
							Ports: &[]v1alpha1.AdminNetworkPolicyPort{
								{
									PortNumber: &v1alpha1.Port{
										Port:     81,
										Protocol: k8sProtocolTCP,
									},
								},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidB",
				Name: "uidB",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AdminNetworkPolicy,
					Name: "anpB",
					UID:  "uidB",
				},
				Priority:     &p10,
				TierPriority: &adminNetworkPolicyTierPriority,
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
						Action:   &dropAction,
					},
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorC, &selectorB, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
						Priority: 0,
						Action:   &dropAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorA, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   2,
		},
		{
			name: "with-port-range",
			inputPolicy: &v1alpha1.AdminNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "anpC", UID: "uidC"},
				Spec: v1alpha1.AdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &selectorA,
					},
					Priority: 10,
					Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.AdminNetworkPolicyRuleActionPass,
							From: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Pods: &v1alpha1.NamespacedPodPeer{
										Namespaces: v1alpha1.NamespacedPeer{
											NamespaceSelector: &selectorC,
										},
										PodSelector: selectorB,
									},
								},
							},
							Ports: &[]v1alpha1.AdminNetworkPolicyPort{
								{
									PortRange: &v1alpha1.PortRange{
										Protocol: k8sProtocolTCP,
										Start:    1000,
										End:      1999,
									},
								},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidC",
				Name: "uidC",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AdminNetworkPolicy,
					Name: "anpC",
					UID:  "uidC",
				},
				Priority:     &p10,
				TierPriority: &adminNetworkPolicyTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, &selectorC, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int1000,
								EndPort:  &int32For1999,
							},
						},
						Priority: 0,
						Action:   &passAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorA, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "with-named-ports",
			inputPolicy: &v1alpha1.AdminNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "anpD", UID: "uidD"},
				Spec: v1alpha1.AdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Pods: &v1alpha1.NamespacedPodSubject{
							NamespaceSelector: selectorA,
							PodSelector:       selectorB,
						},
					},
					Priority: 10,
					Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
							From: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Namespaces: &v1alpha1.NamespacedPeer{
										NamespaceSelector: &selectorC,
									},
								},
							},
							Ports: &[]v1alpha1.AdminNetworkPolicyPort{
								{
									NamedPort: &portName,
								},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidD",
				Name: "uidD",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AdminNetworkPolicy,
					Name: "anpD",
					UID:  "uidD",
				},
				Priority:     &p10,
				TierPriority: &adminNetworkPolicyTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorC, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Port: &intstrPortName,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, &selectorA, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			// TODO: when sameLabels and notSameLabels is supported, this test need to be modified
			name: "with-same-label-namespaces-selection",
			inputPolicy: &v1alpha1.AdminNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "anpE", UID: "uidE"},
				Spec: v1alpha1.AdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &selectorA,
					},
					Priority: 10,
					Ingress: []v1alpha1.AdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.AdminNetworkPolicyRuleActionAllow,
							From: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Namespaces: &v1alpha1.NamespacedPeer{
										SameLabels: []string{"purpose"},
									},
								},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidE",
				Name: "uidE",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AdminNetworkPolicy,
					Name: "anpE",
					UID:  "uidE",
				},
				Priority:         &p10,
				TierPriority:     &adminNetworkPolicyTierPriority,
				Rules:            []controlplane.NetworkPolicyRule{},
				AppliedToGroups:  []string{},
				AppliedToPerRule: true,
			},
			expectedAppliedToGroups: 0,
			expectedAddressGroups:   0,
		},
	}
	defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.AdminNetworkPolicy, true)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController(nil, nil)
			actualPolicy, actualAppliedToGroups, actualAddressGroups := c.processAdminNetworkPolicy(tt.inputPolicy)
			assert.Equal(t, tt.expectedPolicy.UID, actualPolicy.UID)
			assert.Equal(t, tt.expectedPolicy.Name, actualPolicy.Name)
			assert.Equal(t, tt.expectedPolicy.SourceRef, actualPolicy.SourceRef)
			assert.Equal(t, tt.expectedPolicy.Priority, actualPolicy.Priority)
			assert.Equal(t, tt.expectedPolicy.TierPriority, actualPolicy.TierPriority)
			assert.Equal(t, tt.expectedPolicy.AppliedToPerRule, actualPolicy.AppliedToPerRule)
			assert.ElementsMatch(t, tt.expectedPolicy.Rules, actualPolicy.Rules)
			assert.ElementsMatch(t, tt.expectedPolicy.AppliedToGroups, actualPolicy.AppliedToGroups)
			assert.Equal(t, tt.expectedAppliedToGroups, len(actualAppliedToGroups))
			assert.Equal(t, tt.expectedAddressGroups, len(actualAddressGroups))
		})
	}
}

func TestProcessBaselineAdminNetworkPolicy(t *testing.T) {
	tests := []struct {
		name                    string
		inputPolicy             *v1alpha1.BaselineAdminNetworkPolicy
		expectedPolicy          *antreatypes.NetworkPolicy
		expectedAppliedToGroups int
		expectedAddressGroups   int
	}{
		{
			name: "rules-with-same-selectors",
			inputPolicy: &v1alpha1.BaselineAdminNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "banpA", UID: "uidA"},
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &selectorA,
					},
					Ingress: []v1alpha1.BaselineAdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
							From: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Pods: &v1alpha1.NamespacedPodPeer{
										Namespaces: v1alpha1.NamespacedPeer{
											NamespaceSelector: &selectorC,
										},
										PodSelector: selectorB,
									},
								},
							},
							Ports: &[]v1alpha1.AdminNetworkPolicyPort{
								{
									PortNumber: &v1alpha1.Port{
										Port:     80,
										Protocol: k8sProtocolTCP,
									},
								},
							},
						},
					},
					Egress: []v1alpha1.BaselineAdminNetworkPolicyEgressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
							To: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Pods: &v1alpha1.NamespacedPodPeer{
										Namespaces: v1alpha1.NamespacedPeer{
											NamespaceSelector: &selectorC,
										},
										PodSelector: selectorB,
									},
								},
							},
							Ports: &[]v1alpha1.AdminNetworkPolicyPort{
								{
									PortNumber: &v1alpha1.Port{
										Port:     81,
										Protocol: k8sProtocolTCP,
									},
								},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.BaselineAdminNetworkPolicy,
					Name: "banpA",
					UID:  "uidA",
				},
				Priority:     &banpPriority,
				TierPriority: &banpTierPriority,
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
						Action:   &dropAction,
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
						Action:   &dropAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorA, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "rules-with-different-selectors",
			inputPolicy: &v1alpha1.BaselineAdminNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "banpB", UID: "uidB"},
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &selectorA,
					},
					Ingress: []v1alpha1.BaselineAdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
							From: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Pods: &v1alpha1.NamespacedPodPeer{
										Namespaces: v1alpha1.NamespacedPeer{
											NamespaceSelector: &selectorC,
										},
										PodSelector: selectorB,
									},
								},
							},
							Ports: &[]v1alpha1.AdminNetworkPolicyPort{
								{
									PortNumber: &v1alpha1.Port{
										Port:     80,
										Protocol: k8sProtocolTCP,
									},
								},
							},
						},
					},
					Egress: []v1alpha1.BaselineAdminNetworkPolicyEgressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
							To: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Pods: &v1alpha1.NamespacedPodPeer{
										Namespaces: v1alpha1.NamespacedPeer{
											NamespaceSelector: &selectorB,
										},
										PodSelector: selectorC,
									},
								},
							},
							Ports: &[]v1alpha1.AdminNetworkPolicyPort{
								{
									PortNumber: &v1alpha1.Port{
										Port:     81,
										Protocol: k8sProtocolTCP,
									},
								},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidB",
				Name: "uidB",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.BaselineAdminNetworkPolicy,
					Name: "banpB",
					UID:  "uidB",
				},
				Priority:     &banpPriority,
				TierPriority: &banpTierPriority,
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
						Action:   &dropAction,
					},
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorC, &selectorB, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
						Priority: 0,
						Action:   &dropAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorA, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   2,
		},
		{
			name: "with-port-range",
			inputPolicy: &v1alpha1.BaselineAdminNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "banpC", UID: "uidC"},
				Spec: v1alpha1.BaselineAdminNetworkPolicySpec{
					Subject: v1alpha1.AdminNetworkPolicySubject{
						Namespaces: &selectorA,
					},
					Ingress: []v1alpha1.BaselineAdminNetworkPolicyIngressRule{
						{
							Action: v1alpha1.BaselineAdminNetworkPolicyRuleActionAllow,
							From: []v1alpha1.AdminNetworkPolicyPeer{
								{
									Pods: &v1alpha1.NamespacedPodPeer{
										Namespaces: v1alpha1.NamespacedPeer{
											NamespaceSelector: &selectorC,
										},
										PodSelector: selectorB,
									},
								},
							},
							Ports: &[]v1alpha1.AdminNetworkPolicyPort{
								{
									PortRange: &v1alpha1.PortRange{
										Protocol: k8sProtocolTCP,
										Start:    1000,
										End:      1999,
									},
								},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidC",
				Name: "uidC",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.BaselineAdminNetworkPolicy,
					Name: "banpC",
					UID:  "uidC",
				},
				Priority:     &banpPriority,
				TierPriority: &banpTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, &selectorC, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int1000,
								EndPort:  &int32For1999,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorA, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
	}
	defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.AdminNetworkPolicy, true)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController(nil, nil)
			actualPolicy, actualAppliedToGroups, actualAddressGroups := c.processBaselineAdminNetworkPolicy(tt.inputPolicy)
			assert.Equal(t, tt.expectedPolicy.UID, actualPolicy.UID)
			assert.Equal(t, tt.expectedPolicy.Name, actualPolicy.Name)
			assert.Equal(t, tt.expectedPolicy.SourceRef, actualPolicy.SourceRef)
			assert.Equal(t, tt.expectedPolicy.Priority, actualPolicy.Priority)
			assert.Equal(t, tt.expectedPolicy.TierPriority, actualPolicy.TierPriority)
			assert.Equal(t, tt.expectedPolicy.AppliedToPerRule, actualPolicy.AppliedToPerRule)
			assert.ElementsMatch(t, tt.expectedPolicy.Rules, actualPolicy.Rules)
			assert.ElementsMatch(t, tt.expectedPolicy.AppliedToGroups, actualPolicy.AppliedToGroups)
			assert.Equal(t, tt.expectedAppliedToGroups, len(actualAppliedToGroups))
			assert.Equal(t, tt.expectedAddressGroups, len(actualAddressGroups))
		})
	}
}
