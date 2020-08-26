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
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/vmware-tanzu/antrea/pkg/apis/networking"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

func TestProcessAntreaNetworkPolicy(t *testing.T) {
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
		inputPolicy             *secv1alpha1.NetworkPolicy
		expectedPolicy          *antreatypes.NetworkPolicy
		expectedAppliedToGroups int
		expectedAddressGroups   int
	}{
		{
			name: "rules-with-same-selectors",
			inputPolicy: &secv1alpha1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "npA", UID: "uidA"},
				Spec: secv1alpha1.NetworkPolicySpec{
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
				Name:         "npA",
				Namespace:    "ns1",
				Priority:     &p10,
				TierPriority: &appTier,
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC, nil).NormalizedName)},
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
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", &selectorB, &selectorC, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("ns1", &selectorA, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "rules-with-different-selectors",
			inputPolicy: &secv1alpha1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns2", Name: "npB", UID: "uidB"},
				Spec: secv1alpha1.NetworkPolicySpec{
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
				UID:          "uidB",
				Name:         "npB",
				Namespace:    "ns2",
				Priority:     &p10,
				TierPriority: &appTier,
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("ns2", &selectorB, nil, nil).NormalizedName)},
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
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", nil, &selectorC, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("ns2", &selectorA, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController()

			if actualPolicy := c.processAntreaNetworkPolicy(tt.inputPolicy); !reflect.DeepEqual(actualPolicy, tt.expectedPolicy) {
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
