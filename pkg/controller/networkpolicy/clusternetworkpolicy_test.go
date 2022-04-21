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
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha3 "antrea.io/antrea/pkg/apis/crd/v1alpha3"
	antreatypes "antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/util/k8s"
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

	ipA := "1.1.1.1"

	allowAction := crdv1alpha1.RuleActionAllow
	dropAction := crdv1alpha1.RuleActionDrop
	protocolTCP := controlplane.ProtocolTCP
	query := crdv1alpha1.IGMPQuery
	report := crdv1alpha1.IGMPReportV1
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorD := metav1.LabelSelector{MatchLabels: map[string]string{"internal.antrea.io/service-account": saA.Name}}
	queryAddr := "224.0.0.1"
	reportAddr := "225.1.2.3"
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
					AppliedTo: []crdv1alpha1.AppliedTo{
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
					AppliedTo: []crdv1alpha1.AppliedTo{
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
					AppliedTo: []crdv1alpha1.AppliedTo{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Tier:     tierA.Name,
					Ingress: []crdv1alpha1.Rule{
						{
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
				UID:  "uidC",
				Name: "uidC",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpC",
					UID:  "uidC",
				},
				Priority:     &p10,
				TierPriority: &tierA.Spec.Priority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, nil, nil, nil).NormalizedName)},
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
			name: "with-port-range",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "", Name: "cnpD", UID: "uidD"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
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
							AppliedTo: []crdv1alpha1.AppliedTo{
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
							AppliedTo: []crdv1alpha1.AppliedTo{
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
					AppliedTo: []crdv1alpha1.AppliedTo{
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
							AppliedTo: []crdv1alpha1.AppliedTo{
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
							AppliedTo: []crdv1alpha1.AppliedTo{
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
					AppliedTo: []crdv1alpha1.AppliedTo{
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
				AppliedToPerRule: true,
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
							AppliedTo: []crdv1alpha1.AppliedTo{
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
							AppliedTo: []crdv1alpha1.AppliedTo{
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
				AppliedToPerRule: true,
			},
			expectedAppliedToGroups: 2,
			expectedAddressGroups:   2,
		},
		{
			name: "rule-with-to-service",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpK", UID: "uidK"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
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
					AppliedTo: []crdv1alpha1.AppliedTo{
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
					AppliedTo: []crdv1alpha1.AppliedTo{
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
							AppliedTo: []crdv1alpha1.AppliedTo{
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
					AppliedTo: []crdv1alpha1.AppliedTo{
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
				AppliedToPerRule: true,
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   2,
		},
		{
			name: "rule-with-node-selector",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpL", UID: "uidL"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
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
									NodeSelector: &selectorA,
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
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, nil, nil, &selectorA).NormalizedName)},
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
			expectedAddressGroups:   2,
		},
		{
			name: "rules-with-icmp-protocol",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnp-icmp", UID: "uid-icmp"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []crdv1alpha1.Rule{
						{
							Protocols: []crdv1alpha1.NetworkPolicyProtocol{
								{
									ICMP: &crdv1alpha1.ICMPProtocol{
										ICMPType: &icmpType8,
										ICMPCode: &icmpCode0,
									},
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
							Protocols: []crdv1alpha1.NetworkPolicyProtocol{
								{
									ICMP: &crdv1alpha1.ICMPProtocol{},
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
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uid-icmp",
				Name: "uid-icmp",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnp-icmp",
					UID:  "uid-icmp",
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
								Protocol: &protocolICMP,
								ICMPType: &icmpType8,
								ICMPCode: &icmpCode0,
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
								Protocol: &protocolICMP,
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   2,
		},
		{
			name: "rule-with-igmp-query",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpL", UID: "uidL"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Ingress: []crdv1alpha1.Rule{
						{
							Action: &dropAction,
							Protocols: []crdv1alpha1.NetworkPolicyProtocol{
								{
									IGMP: &crdv1alpha1.IGMPProtocol{
										IGMPType:     &query,
										GroupAddress: queryAddr,
									},
								},
							},
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
						Direction: controlplane.DirectionIn,
						Services: []controlplane.Service{
							{
								Protocol:     &protocolIGMP,
								IGMPType:     &query,
								GroupAddress: queryAddr,
							},
						},
						Priority: 0,
						Action:   &dropAction,
						From: controlplane.NetworkPolicyPeer{
							IPBlocks: []controlplane.IPBlock{
								{CIDR: controlplane.IPNet{IP: controlplane.IPAddress(net.IPv4zero), PrefixLength: 0}},
								{CIDR: controlplane.IPNet{IP: controlplane.IPAddress(net.IPv6zero), PrefixLength: 0}},
							},
						},
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   0,
		},
		{
			name: "rule-with-igmp-report",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpL", UID: "uidL"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{PodSelector: &selectorA},
					},
					Priority: p10,
					Egress: []crdv1alpha1.Rule{
						{
							Action: &dropAction,
							Protocols: []crdv1alpha1.NetworkPolicyProtocol{
								{
									IGMP: &crdv1alpha1.IGMPProtocol{
										IGMPType:     &report,
										GroupAddress: reportAddr,
									},
								},
							},
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
						Services: []controlplane.Service{
							{
								Protocol:     &protocolIGMP,
								IGMPType:     &report,
								GroupAddress: reportAddr,
							},
						},
						Priority: 0,
						Action:   &dropAction,
						To: controlplane.NetworkPolicyPeer{
							IPBlocks: []controlplane.IPBlock{
								{CIDR: controlplane.IPNet{IP: controlplane.IPAddress(net.IPv4zero), PrefixLength: 0}},
								{CIDR: controlplane.IPNet{IP: controlplane.IPAddress(net.IPv6zero), PrefixLength: 0}},
							},
						},
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   0,
		},
		{
			name: "appliedTo-service",
			inputPolicy: &crdv1alpha1.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpM", UID: "uidM"},
				Spec: crdv1alpha1.ClusterNetworkPolicySpec{
					AppliedTo: nil,
					Priority:  p10,
					Ingress: []crdv1alpha1.Rule{
						{
							AppliedTo: []crdv1alpha1.AppliedTo{
								{
									Service: &crdv1alpha1.NamespacedName{
										Name:      svcA.Name,
										Namespace: svcA.Namespace,
									},
								},
							},
							From: []crdv1alpha1.NetworkPolicyPeer{
								{
									IPBlock: &crdv1alpha1.IPBlock{
										CIDR: ipA + "/32",
									},
								},
							},
							Action: &allowAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidM",
				Name: "uidM",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.AntreaClusterNetworkPolicy,
					Name: "cnpM",
					UID:  "uidM",
				},
				Priority:     &p10,
				TierPriority: &DefaultTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction:       controlplane.DirectionIn,
						AppliedToGroups: []string{getNormalizedUID(k8s.NamespacedName(svcA.Namespace, svcA.Name))},
						From: controlplane.NetworkPolicyPeer{
							IPBlocks: []controlplane.IPBlock{
								{
									CIDR: controlplane.IPNet{
										IP:           controlplane.IPAddress(net.ParseIP(ipA)),
										PrefixLength: 32,
									},
									Except: []controlplane.IPNet{},
								},
							},
						},
						Priority: 0,
						Action:   &allowAction,
					},
				},
				AppliedToGroups: []string{
					getNormalizedUID(k8s.NamespacedName(svcA.Namespace, svcA.Name)),
				},
				AppliedToPerRule: true,
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   0,
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
			c.tierStore.Add(&tierA)
			actualPolicy, actualAppliedToGroups, actualAddressGroups := c.processClusterNetworkPolicy(tt.inputPolicy)
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

func TestAddCNP(t *testing.T) {
	_, npc := newController()
	cnp := getCNP()
	npc.addCNP(cnp)
	require.Equal(t, 1, npc.internalNetworkPolicyQueue.Len())
	key, done := npc.internalNetworkPolicyQueue.Get()
	expectedKey := getACNPReference(cnp)
	assert.Equal(t, *expectedKey, key)
	assert.False(t, done)
}

func TestUpdateCNP(t *testing.T) {
	_, npc := newController()
	cnp := getCNP()
	newCNP := cnp.DeepCopy()
	// Make a change to the CNP.
	newCNP.Annotations = map[string]string{"foo": "bar"}
	npc.updateCNP(cnp, newCNP)
	require.Equal(t, 1, npc.internalNetworkPolicyQueue.Len())
	key, done := npc.internalNetworkPolicyQueue.Get()
	expectedKey := getACNPReference(cnp)
	assert.Equal(t, *expectedKey, key)
	assert.False(t, done)
}

func TestDeleteCNP(t *testing.T) {
	_, npc := newController()
	cnp := getCNP()
	npc.deleteCNP(cnp)
	require.Equal(t, 1, npc.internalNetworkPolicyQueue.Len())
	key, done := npc.internalNetworkPolicyQueue.Get()
	expectedKey := getACNPReference(cnp)
	assert.Equal(t, *expectedKey, key)
	assert.False(t, done)
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

func TestProcessRefGroupOrClusterGroup(t *testing.T) {
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
	// gA with selector present in cache
	gA := crdv1alpha3.Group{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gA", UID: "uidGA"},
		Spec: crdv1alpha3.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	// gB with IPBlock present in cache
	gB := crdv1alpha3.Group{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nsB", Name: "gB", UID: "uidGB"},
		Spec: crdv1alpha3.GroupSpec{
			IPBlocks: []crdv1alpha1.IPBlock{
				{
					CIDR: cidr,
				},
			},
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
	npc.addGroup(&gA)
	npc.addGroup(&gB)
	npc.gStore.Add(&gA)
	npc.gStore.Add(&gB)
	tests := []struct {
		name           string
		inputNamespace string
		inputGroupName string
		expectedAG     *antreatypes.AddressGroup
		expectedIPB    []controlplane.IPBlock
	}{
		{
			name:           "empty-cg-no-result",
			inputGroupName: "",
			expectedAG:     nil,
			expectedIPB:    nil,
		},
		{
			name:           "cg-with-selector",
			inputGroupName: cgA.Name,
			expectedAG:     &antreatypes.AddressGroup{UID: cgA.UID, Name: cgA.Name},
			expectedIPB:    nil,
		},
		{
			name:           "cg-with-selector-not-found",
			inputGroupName: cgC.Name,
			expectedAG:     nil,
			expectedIPB:    nil,
		},
		{
			name:           "cg-with-ipblock",
			inputGroupName: cgB.Name,
			expectedAG:     nil,
			expectedIPB: []controlplane.IPBlock{
				{
					CIDR:   *cidrIPNet,
					Except: []controlplane.IPNet{},
				},
			},
		},
		{
			name:           "nested-cg-with-ipblock",
			inputGroupName: cgNested1.Name,
			expectedAG:     nil,
			expectedIPB: []controlplane.IPBlock{
				{
					CIDR:   *cidrIPNet,
					Except: []controlplane.IPNet{},
				},
			},
		},
		{
			name:           "nested-cg-with-ipblock-and-selector",
			inputGroupName: cgNested2.Name,
			expectedAG:     &antreatypes.AddressGroup{UID: cgNested2.UID, Name: cgNested2.Name},
			expectedIPB: []controlplane.IPBlock{
				{
					CIDR:   *cidrIPNet,
					Except: []controlplane.IPNet{},
				},
			},
		},
		{
			name:           "empty-g-no-result",
			inputNamespace: "",
			inputGroupName: "",
			expectedAG:     nil,
			expectedIPB:    nil,
		},
		{
			name:           "g-with-selector",
			inputNamespace: gA.Namespace,
			inputGroupName: gA.Name,
			expectedAG:     &antreatypes.AddressGroup{UID: gA.UID, Name: fmt.Sprintf("%s/%s", gA.Namespace, gA.Name)},
			expectedIPB:    nil,
		},
		{
			name:           "non-existing-group",
			inputNamespace: "non-existing-namespace",
			inputGroupName: "non-existing-group",
			expectedAG:     nil,
			expectedIPB:    nil,
		},
		{
			name:           "g-with-ipblock",
			inputNamespace: gB.Namespace,
			inputGroupName: gB.Name,
			expectedAG:     nil,
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
			actualAG, actualIPB := npc.processRefGroupOrClusterGroup(tt.inputGroupName, tt.inputNamespace)
			assert.Equal(t, tt.expectedIPB, actualIPB, "IPBlock does not match")
			assert.Equal(t, tt.expectedAG, actualAG, "addressGroup does not match")
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
			AppliedTo: []crdv1alpha1.AppliedTo{
				{PodSelector: &selectorA},
			},
			Priority: p10,
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
	return npObj
}

func TestFilterPerNamespaceRuleACNPsByNSLabels(t *testing.T) {
	group := &crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group1"},
		Spec:       crdv1alpha3.GroupSpec{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}},
	}
	cnpWithSpecAppliedTo := &crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cnp-with-spec-appliedTo"},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			AppliedTo: []crdv1alpha1.AppliedTo{
				{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}},
			},
			Ingress: []crdv1alpha1.Rule{
				{
					From: []crdv1alpha1.NetworkPolicyPeer{
						{Namespaces: &crdv1alpha1.PeerNamespaces{Match: crdv1alpha1.NamespaceMatchSelf}},
					},
				},
			},
		},
	}
	cnpWithRuleAppliedTo := &crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cnp-with-rule-appliedTo"},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			Ingress: []crdv1alpha1.Rule{
				{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{Group: group.Name},
					},
					From: []crdv1alpha1.NetworkPolicyPeer{
						{Namespaces: &crdv1alpha1.PeerNamespaces{Match: crdv1alpha1.NamespaceMatchSelf}},
					},
				},
				{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}},
					},
					From: []crdv1alpha1.NetworkPolicyPeer{
						{IPBlock: &crdv1alpha1.IPBlock{CIDR: "10.0.0.0/8"}},
					},
				},
			},
			Egress: []crdv1alpha1.Rule{
				{
					AppliedTo: []crdv1alpha1.AppliedTo{
						{Group: "non-existing-group"},
						{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"foo4": "bar4"}}},
					},
					To: []crdv1alpha1.NetworkPolicyPeer{
						{Namespaces: &crdv1alpha1.PeerNamespaces{Match: crdv1alpha1.NamespaceMatchSelf}},
					},
				},
			},
		},
	}
	cnpMatchAllNamespaces := &crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cnp3-match-all-namespaces"},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			AppliedTo: []crdv1alpha1.AppliedTo{
				{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"foo": "bar"}}},
			},
			Ingress: []crdv1alpha1.Rule{
				{
					From: []crdv1alpha1.NetworkPolicyPeer{
						{Namespaces: &crdv1alpha1.PeerNamespaces{Match: crdv1alpha1.NamespaceMatchSelf}},
					},
				},
			},
		},
	}
	tests := []struct {
		name     string
		nsLabels labels.Set
		want     sets.String
	}{
		{
			name: "match spec AppliedTo",
			nsLabels: map[string]string{
				"foo1": "bar1",
			},
			want: sets.NewString(cnpWithSpecAppliedTo.Name, cnpMatchAllNamespaces.Name),
		},
		{
			name: "match per-namespace ingress rule AppliedTo",
			nsLabels: map[string]string{
				"foo2": "bar2",
			},
			want: sets.NewString(cnpWithRuleAppliedTo.Name, cnpMatchAllNamespaces.Name),
		},
		{
			name: "match non-per-namespace ingress rule AppliedTo",
			nsLabels: map[string]string{
				"foo3": "bar3",
			},
			want: sets.NewString(cnpMatchAllNamespaces.Name),
		},
		{
			name: "match per-namespace egress rule AppliedTo",
			nsLabels: map[string]string{
				"foo4": "bar4",
			},
			want: sets.NewString(cnpWithRuleAppliedTo.Name, cnpMatchAllNamespaces.Name),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController()
			c.cnpStore.Add(cnpWithSpecAppliedTo)
			c.cnpStore.Add(cnpWithRuleAppliedTo)
			c.cnpStore.Add(cnpMatchAllNamespaces)
			c.cgStore.Add(group)
			assert.Equal(t, tt.want, c.filterPerNamespaceRuleACNPsByNSLabels(tt.nsLabels))
		})
	}
}
