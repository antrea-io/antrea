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
	"k8s.io/apimachinery/pkg/labels"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha3 "antrea.io/antrea/pkg/apis/crd/v1alpha3"
	antreatypes "antrea.io/antrea/pkg/controller/types"
)

func TestProcessClusterNetworkPolicy(t *testing.T) {
	p10 := float64(10)
	t10 := int32(10)
	tierA := crdv1alpha1.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "tier-A", UID: "uidA"},
		Spec: crdv1alpha1.TierSpec{
			Priority:    t10,
			Description: "tier-A",
		},
	}
	nsA := v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nsA",
			Labels: map[string]string{"foo1": "bar1"},
		},
	}
	nsB := v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nsB",
			Labels: map[string]string{"foo2": "bar2"},
		},
	}

	svcA := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svcA",
			Namespace: "nsA",
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

	saA := v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "saA",
			Namespace: nsA.Name,
		},
	}

	allowAction := crdv1alpha1.RuleActionAllow
	dropAction := crdv1alpha1.RuleActionDrop
	protocolTCP := controlplane.ProtocolTCP
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorD := metav1.LabelSelector{MatchLabels: map[string]string{"internal.antrea.io/service-account": saA.Name}}

	labelSelectorA, _ := metav1.LabelSelectorAsSelector(&selectorA)
	labelSelectorB, _ := metav1.LabelSelectorAsSelector(&selectorB)
	cgA := crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec: crdv1alpha3.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	tests := []struct {
		name                    string
		inputPolicy             *crdv1alpha1.ClusterNetworkPolicy
		expectedPolicy          *antreatypes.NetworkPolicy
		expectedAppliedToGroups int
		expectedAddressGroups   int
	}{
		{
			name: "rules-with-same-selectors",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpA", UID: "uidA"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "rules-with-different-selectors",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "", Name: "cnpB", UID: "uidB"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
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
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, nil, nil, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   2,
		},
		{
			name: "with-tier-A",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "", Name: "cnpC", UID: "uidC"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Tier:     "tier-A",
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
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, nil, nil, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   2,
		},
		{
			name: "with-port-range",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "", Name: "cnpD", UID: "uidD"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
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
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, nil, nil, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "appliedTo-per-rule",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpH", UID: "uidH"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
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
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
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
						AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, nil, nil, nil).NormalizedName)},
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
						AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, &selectorC, nil, nil).NormalizedName)},
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
					getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName),
					getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, &selectorC, nil, nil).NormalizedName),
				},
				AppliedToPerRule: true,
			},
			expectedAppliedToGroups: 2,
			expectedAddressGroups:   2,
		},
		{
			name: "with-cluster-group-ingress-egress",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpI", UID: "uidI"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
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
									Group: cgA.Name,
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "with-applied-to-cluster-group-ingress-egress",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpI", UID: "uidI"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
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
							AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
								{
									Group: cgA.Name,
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
									PodSelector: &selectorB,
								},
							},
							AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
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
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, nil, nil, nil).NormalizedName)},
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
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, nil, nil, nil).NormalizedName)},
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
		{
			name: "with-per-namespace-rule",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpI", UID: "uidI"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{},
						},
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
									Namespaces: &crdv1alpha1.PeerNamespaces{
										Match: crdv1alpha1.NamespaceMatchSelf,
									},
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
									NamespaceSelector: &selectorA,
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
						AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", nil, nil, nil, nil).NormalizedName)},
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", nil, nil, nil, nil).NormalizedName)},
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
						AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsB", nil, nil, nil, nil).NormalizedName)},
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsB", nil, nil, nil, nil).NormalizedName)},
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
						AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &metav1.LabelSelector{}, nil, nil).NormalizedName)},
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorA, nil, nil).NormalizedName)},
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
					getNormalizedUID(antreatypes.NewGroupSelector("nsA", nil, nil, nil, nil).NormalizedName),
					getNormalizedUID(antreatypes.NewGroupSelector("nsB", nil, nil, nil, nil).NormalizedName),
					getNormalizedUID(antreatypes.NewGroupSelector("", nil, &metav1.LabelSelector{}, nil, nil).NormalizedName),
				},
				AppliedToPerRule:      true,
				PerNamespaceSelectors: []labels.Selector{labels.Everything()},
			},
			expectedAppliedToGroups: 3,
			expectedAddressGroups:   3,
		},
		{
			name: "with-per-namespace-rule-applied-to-per-rule",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpJ", UID: "uidJ"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					Priority: p10,
					Ingress: []crdv1alpha1.Rule{
						{
							AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
								{
									NamespaceSelector: &selectorA,
									PodSelector:       &selectorA,
								},
							},
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Port: &int80,
								},
							},
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									Namespaces: &crdv1alpha1.PeerNamespaces{
										Match: crdv1alpha1.NamespaceMatchSelf,
									},
									PodSelector: &selectorA,
								},
							},
							Action: &dropAction,
						},
						{
							AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
								{
									NamespaceSelector: &selectorB,
								},
							},
							Ports: []crdv1alpha1.NetworkPolicyPort{
								{
									Port: &int81,
								},
							},
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									Namespaces: &crdv1alpha1.PeerNamespaces{
										Match: crdv1alpha1.NamespaceMatchSelf,
									},
								},
							},
							Action: &dropAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidJ",
				Name: "uidJ",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpJ",
					UID:  "uidJ",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction:       controlplane.DirectionIn,
						AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorA, nil, nil, nil).NormalizedName)},
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorA, nil, nil, nil).NormalizedName)},
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
						Direction:       controlplane.DirectionIn,
						AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsB", nil, nil, nil, nil).NormalizedName)},
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsB", nil, nil, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
						Priority: 1,
						Action:   &dropAction,
					},
				},
				AppliedToGroups: []string{
					getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorA, nil, nil, nil).NormalizedName),
					getNormalizedUID(antreatypes.NewGroupSelector("nsB", nil, nil, nil, nil).NormalizedName),
				},
				AppliedToPerRule:      true,
				PerNamespaceSelectors: []labels.Selector{labelSelectorA, labelSelectorB},
			},
			expectedAppliedToGroups: 2,
			expectedAddressGroups:   2,
		},
		{
			name: "rule-with-to-service",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpK", UID: "uidK"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Egress: []crdv1alpha1.Rule{
						{
							ToServices: []crdv1alpha1.NamespacedName{
								{
									Namespace: "nsA",
									Name:      "svcA",
								},
							},
							Action: &dropAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidK",
				Name: "uidK",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpK",
					UID:  "uidK",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							ToServices: []controlplane.ServiceReference{
								{
									Namespace: "nsA",
									Name:      "svcA",
								},
							},
						},
						Priority: 0,
						Action:   &dropAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   0,
		},
		{
			name: "applied-to-with-service-account-namespaced-name",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpL", UID: "uidL"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
						{
							ServiceAccount: &crdv1alpha1.NamespacedName{
								Name:      saA.Name,
								Namespace: saA.Namespace,
							},
						},
					},
					Priority: p10,
					Egress: []crdv1alpha1.Rule{
						{
							ToServices: []crdv1alpha1.NamespacedName{
								{
									Namespace: "nsA",
									Name:      "svcA",
								},
							},
							Action: &dropAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidL",
				Name: "uidL",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpL",
					UID:  "uidL",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							ToServices: []controlplane.ServiceReference{
								{
									Namespace: "nsA",
									Name:      "svcA",
								},
							},
						},
						Priority: 0,
						Action:   &dropAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorD, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   0,
		},
		{
			name: "rule-with-service-account-namespaced-name",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpP", UID: "uidP"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
						{
							PodSelector: &selectorA,
						},
					},
					Priority: p10,
					Egress: []crdv1alpha1.Rule{
						{
							To: []crdv1alpha1.NetworkPolicyPeer{
								{
									ServiceAccount: &crdv1alpha1.NamespacedName{
										Name:      saA.Name,
										Namespace: saA.Namespace,
									},
								},
							},
							Action: &dropAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidP",
				Name: "uidP",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpP",
					UID:  "uidP",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorD, nil, nil, nil).NormalizedName)},
						},
						Priority: 0,
						Action:   &dropAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "rule-applied-to-with-service-account-namespaced-name",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpQ", UID: "uidQ"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					Priority: p10,
					Egress: []crdv1alpha1.Rule{
						{
							To: []crdv1alpha1.NetworkPolicyPeer{
								{
									PodSelector: &selectorA,
								},
							},
							Action: &dropAction,
							AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
								{
									ServiceAccount: &crdv1alpha1.NamespacedName{
										Name:      saA.Name,
										Namespace: saA.Namespace,
									},
								},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidQ",
				Name: "uidQ",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpQ",
					UID:  "uidQ",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
						},
						Priority:        0,
						Action:          &dropAction,
						AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorD, nil, nil, nil).NormalizedName)},
					},
				},
				AppliedToGroups:  []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorD, nil, nil, nil).NormalizedName)},
				AppliedToPerRule: true,
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "service-account-per-namespace-rule",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpR", UID: "uidR"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
						{
							ServiceAccount: &crdv1alpha1.NamespacedName{
								Name:      saA.Name,
								Namespace: saA.Namespace,
							},
						},
					},
					Priority: p10,
					Egress: []crdv1alpha1.Rule{
						{
							To: []crdv1alpha1.NetworkPolicyPeer{
								{
									Namespaces: &crdv1alpha1.PeerNamespaces{
										Match: crdv1alpha1.NamespaceMatchSelf,
									},
								},
							},
							Action: &dropAction,
						},
						{
							To: []crdv1alpha1.NetworkPolicyPeer{
								{
									NamespaceSelector: &selectorB,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidR",
				Name: "uidR",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpR",
					UID:  "uidR",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", nil, nil, nil, nil).NormalizedName)},
						},
						Priority:        0,
						Action:          &dropAction,
						AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorD, nil, nil, nil).NormalizedName)},
					},
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorB, nil, nil).NormalizedName)},
						},
						Priority:        1,
						Action:          &allowAction,
						AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorD, nil, nil, nil).NormalizedName)},
					},
				},
				AppliedToGroups: []string{
					getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorD, nil, nil, nil).NormalizedName),
				},
				AppliedToPerRule:      true,
				PerNamespaceSelectors: []labels.Selector{},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   2,
		},
		{
			name: "rule-with-node-selector",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpL", UID: "uidL"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
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
							Action: &dropAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidL",
				Name: "uidL",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpL",
					UID:  "uidL",
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
						Action:   &dropAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
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
			c.namespaceStore.Add(&nsA)
			c.namespaceStore.Add(&nsB)
			c.serviceStore.Add(&svcA)
			if tt.inputPolicy.Spec.Tier != "" {
				c.tierStore.Add(&tierA)
			}
			actualPolicy := c.processClusterNetworkPolicy(tt.inputPolicy)
			assert.Equal(t, tt.expectedPolicy.UID, actualPolicy.UID)
			assert.Equal(t, tt.expectedPolicy.Name, actualPolicy.Name)
			assert.Equal(t, tt.expectedPolicy.SourceRef, actualPolicy.SourceRef)
			assert.Equal(t, tt.expectedPolicy.Priority, actualPolicy.Priority)
			assert.Equal(t, tt.expectedPolicy.TierPriority, actualPolicy.TierPriority)
			assert.Equal(t, tt.expectedPolicy.AppliedToPerRule, actualPolicy.AppliedToPerRule)
			assert.ElementsMatch(t, tt.expectedPolicy.Rules, actualPolicy.Rules)
			assert.ElementsMatch(t, tt.expectedPolicy.PerNamespaceSelectors, actualPolicy.PerNamespaceSelectors)
			assert.ElementsMatch(t, tt.expectedPolicy.AppliedToGroups, actualPolicy.AppliedToGroups)
			assert.Equal(t, tt.expectedAppliedToGroups, len(c.appliedToGroupStore.List()))
			assert.Equal(t, tt.expectedAddressGroups, len(c.addressGroupStore.List()))
		})
	}
}

func TestAddCNP(t *testing.T) {
	p10 := float64(10)
	emergencyTierPriority := int32(1)
	emergencyTier := crdv1alpha1.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "emergency", UID: "tE"},
		Spec: crdv1alpha1.TierSpec{
			Priority: emergencyTierPriority,
		},
	}
	appTier := crdv1alpha1.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "application", UID: "tA"},
		Spec: crdv1alpha1.TierSpec{
			Priority: DefaultTierPriority,
		},
	}
	allowAction := crdv1alpha1.RuleActionAllow
	protocolTCP := controlplane.ProtocolTCP
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorAll := metav1.LabelSelector{}
	matchAllPeerEgress := matchAllPeer
	matchAllPeerEgress.AddressGroups = []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorAll, nil, nil).NormalizedName)}
	tests := []struct {
		name               string
		inputPolicy        *crdv1alpha1.ClusterNetworkPolicy
		expPolicy          *antreatypes.NetworkPolicy
		expAppliedToGroups int
		expAddressGroups   int
	}{
		{
			name: "application-tier-policy",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpA", UID: "uidA"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Tier:     "application",
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
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "empty-tier-policy",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpB", UID: "uidB"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
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
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "emergency-tier-policy",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpD", UID: "uidD"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Tier:     "emergency",
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
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "static-tier-policy",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpE", UID: "uidE"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Tier:     "Emergency",
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
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "rules-with-same-selectors",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpF", UID: "uidF"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "rules-with-different-selectors",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpG", UID: "uidG"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
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
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, nil, nil, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   2,
		},
		{
			name: "with-port-range",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "", Name: "cnpH", UID: "uidH"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
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
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, nil, nil, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "rules-with-node-selector",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpI", UID: "uidI"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
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
									NodeSelector: &selectorB,
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
									NodeSelector: &selectorA,
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expPolicy: &antreatypes.NetworkPolicy{
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
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, nil, nil, &selectorB).NormalizedName)},
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
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, nil, nil, &selectorA).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   2,
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
	assert.Equal(t, 8, npc.GetNetworkPolicyNum(), "number of NetworkPolicies do not match")
	assert.Equal(t, 5, npc.GetAddressGroupNum(), "number of AddressGroups do not match")
	assert.Equal(t, 1, npc.GetAppliedToGroupNum(), "number of AppliedToGroups do not match")
}

func TestDeleteCNP(t *testing.T) {
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	cnpObj := getCNP()
	apgID := getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)
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
		inputTier *crdv1alpha1.Tier
		expPrio   int32
	}{
		{
			name:      "empty-tier-name",
			inputTier: nil,
			expPrio:   DefaultTierPriority,
		},
		{
			name: "tier10",
			inputTier: &crdv1alpha1.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: "tA", UID: "uidA"},
				Spec: crdv1alpha1.TierSpec{
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
	cgA := crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec: crdv1alpha3.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	// cgB with IPBlock present in cache
	cgB := crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "uidB"},
		Spec: crdv1alpha3.GroupSpec{
			IPBlocks: []crdv1alpha1.IPBlock{
				{
					CIDR: cidr,
				},
			},
		},
	}
	// cgC not found in cache
	cgC := crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgC", UID: "uidC"},
		Spec: crdv1alpha3.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	cgNested1 := crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgD", UID: "uidD"},
		Spec: crdv1alpha3.GroupSpec{
			ChildGroups: []crdv1alpha3.ClusterGroupReference{"cgB"},
		},
	}
	cgNested2 := crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgE", UID: "uidE"},
		Spec: crdv1alpha3.GroupSpec{
			ChildGroups: []crdv1alpha3.ClusterGroupReference{"cgA", "cgB"},
		},
	}
	_, npc := newController()
	npc.addClusterGroup(&cgA)
	npc.addClusterGroup(&cgB)
	npc.addClusterGroup(&cgNested1)
	npc.addClusterGroup(&cgNested2)
	npc.cgStore.Add(&cgA)
	npc.cgStore.Add(&cgB)
	npc.cgStore.Add(&cgNested1)
	npc.cgStore.Add(&cgNested2)
	tests := []struct {
		name        string
		inputCG     string
		expectedAG  string
		expectedIPB []controlplane.IPBlock
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
			expectedIPB: []controlplane.IPBlock{
				{
					CIDR:   *cidrIPNet,
					Except: []controlplane.IPNet{},
				},
			},
		},
		{
			name:       "nested-cg-with-ipblock",
			inputCG:    cgNested1.Name,
			expectedAG: "",
			expectedIPB: []controlplane.IPBlock{
				{
					CIDR:   *cidrIPNet,
					Except: []controlplane.IPNet{},
				},
			},
		},
		{
			name:       "nested-cg-with-ipblock-and-selector",
			inputCG:    cgNested2.Name,
			expectedAG: cgNested2.Name,
			expectedIPB: []controlplane.IPBlock{
				{
					CIDR:   *cidrIPNet,
					Except: []controlplane.IPNet{},
				},
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
	cgA := crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec: crdv1alpha3.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	// cgB with IPBlock present in cache
	cgB := crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "uidB"},
		Spec: crdv1alpha3.GroupSpec{
			IPBlocks: []crdv1alpha1.IPBlock{
				{
					CIDR: cidr,
				},
			},
		},
	}
	// cgC not found in cache
	cgC := crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgC", UID: "uidC"},
		Spec: crdv1alpha3.GroupSpec{
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

func getCNP() *crdv1alpha1.ClusterNetworkPolicy {
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
					PodSelector: &selectorC,
				},
			},
			Action: &allowAction,
		},
	}
	npObj := &crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cnp"},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
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
