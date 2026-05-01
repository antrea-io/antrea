// Copyright 2026 Antrea Authors
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
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	v1alpha2 "sigs.k8s.io/network-policy-api/apis/v1alpha2"

	"antrea.io/antrea/v2/pkg/apis/controlplane"
	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	antreatypes "antrea.io/antrea/v2/pkg/controller/types"
)

func TestProcessClusterNetworkPolicy(t *testing.T) {
	p100 := float64(100)
	p50 := float64(50)
	allow := crdv1beta1.RuleActionAllow
	drop := crdv1beta1.RuleActionDrop
	pass := crdv1beta1.RuleActionPass
	protoTCP := controlplane.ProtocolTCP
	protoUDP := controlplane.ProtocolUDP

	selApp := metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}
	selEnv := metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}
	selClient := metav1.LabelSelector{MatchLabels: map[string]string{"client": "yes"}}
	selDstPod := metav1.LabelSelector{MatchLabels: map[string]string{"tier": "db"}}
	selDstNs := metav1.LabelSelector{MatchLabels: map[string]string{"zone": "east"}}
	selGateway := metav1.LabelSelector{MatchLabels: map[string]string{"role": "gateway"}}
	emptyNSSel := metav1.LabelSelector{}
	selTeam := metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}}

	port80 := intstr.FromInt32(80)
	port443 := intstr.FromInt32(443)
	port53 := intstr.FromInt32(53)

	cidr203, _ := cidrStrToIPNet("203.0.113.0/24")

	tests := []struct {
		name                    string
		inputPolicy             *v1alpha2.ClusterNetworkPolicy
		expectedPolicy          *antreatypes.NetworkPolicy
		expectedAppliedToGroups int
		expectedAddressGroups   int
	}{
		{
			name: "admin-tier-ingress-from-namespaces-with-tcp",
			inputPolicy: &v1alpha2.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnp-ingress-ns", UID: "uid-1"},
				Spec: v1alpha2.ClusterNetworkPolicySpec{
					Tier:     v1alpha2.AdminTier,
					Priority: 100,
					Subject: v1alpha2.ClusterNetworkPolicySubject{
						Pods: &v1alpha2.NamespacedPod{
							NamespaceSelector: selEnv,
							PodSelector:       selApp,
						},
					},
					Ingress: []v1alpha2.ClusterNetworkPolicyIngressRule{
						{
							Name:   "r1",
							Action: v1alpha2.ClusterNetworkPolicyRuleActionAccept,
							From: []v1alpha2.ClusterNetworkPolicyIngressPeer{
								{Namespaces: &selClient},
							},
							Protocols: []v1alpha2.ClusterNetworkPolicyProtocol{
								{TCP: &v1alpha2.ClusterNetworkPolicyProtocolTCP{
									DestinationPort: &v1alpha2.Port{Number: 80},
								}},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uid-1",
				Name: "uid-1",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.ClusterNetworkPolicy,
					Name: "cnp-ingress-ns",
					UID:  "uid-1",
				},
				Priority:         &p100,
				TierPriority:     ptr.To(adminTierPriority),
				AppliedToPerRule: false,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selClient, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{{Protocol: &protoTCP, Port: &port80}},
						Name:     "r1",
						Action:   &allow,
						Priority: 0,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selApp, &selEnv, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "baseline-tier-egress-to-namespaces-deny-udp",
			inputPolicy: &v1alpha2.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnp-egress-ns", UID: "uid-2"},
				Spec: v1alpha2.ClusterNetworkPolicySpec{
					Tier:     v1alpha2.BaselineTier,
					Priority: 50,
					Subject: v1alpha2.ClusterNetworkPolicySubject{
						Pods: &v1alpha2.NamespacedPod{
							NamespaceSelector: emptyNSSel,
							PodSelector:       selGateway,
						},
					},
					Egress: []v1alpha2.ClusterNetworkPolicyEgressRule{
						{
							Name:   "e1",
							Action: v1alpha2.ClusterNetworkPolicyRuleActionDeny,
							To: []v1alpha2.ClusterNetworkPolicyEgressPeer{
								{Namespaces: &selDstNs},
							},
							Protocols: []v1alpha2.ClusterNetworkPolicyProtocol{
								{UDP: &v1alpha2.ClusterNetworkPolicyProtocolUDP{
									DestinationPort: &v1alpha2.Port{Number: 53},
								}},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uid-2",
				Name: "uid-2",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.ClusterNetworkPolicy,
					Name: "cnp-egress-ns",
					UID:  "uid-2",
				},
				Priority:         &p50,
				TierPriority:     ptr.To(baselineTierPriority),
				AppliedToPerRule: false,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selDstNs, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{{Protocol: &protoUDP, Port: &port53}},
						Name:     "e1",
						Action:   &drop,
						Priority: 0,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selGateway, &emptyNSSel, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "ingress-from-pods-peer-and-pass-action",
			inputPolicy: &v1alpha2.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnp-ingress-pods", UID: "uid-3"},
				Spec: v1alpha2.ClusterNetworkPolicySpec{
					Tier:     v1alpha2.AdminTier,
					Priority: 10,
					Subject: v1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &selTeam,
					},
					Ingress: []v1alpha2.ClusterNetworkPolicyIngressRule{
						{
							Name:   "from-app",
							Action: v1alpha2.ClusterNetworkPolicyRuleActionPass,
							From: []v1alpha2.ClusterNetworkPolicyIngressPeer{
								{
									Pods: &v1alpha2.NamespacedPod{
										NamespaceSelector: selDstNs,
										PodSelector:       selDstPod,
									},
								},
							},
							Protocols: []v1alpha2.ClusterNetworkPolicyProtocol{
								{TCP: &v1alpha2.ClusterNetworkPolicyProtocolTCP{
									DestinationPort: &v1alpha2.Port{Number: 443},
								}},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uid-3",
				Name: "uid-3",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.ClusterNetworkPolicy,
					Name: "cnp-ingress-pods",
					UID:  "uid-3",
				},
				Priority:         ptr.To(float64(10)),
				TierPriority:     ptr.To(adminTierPriority),
				AppliedToPerRule: false,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selDstPod, &selDstNs, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{{Protocol: &protoTCP, Port: &port443}},
						Name:     "from-app",
						Action:   &pass,
						Priority: 0,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selTeam, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "egress-to-networks-cidr",
			inputPolicy: &v1alpha2.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnp-egress-net", UID: "uid-4"},
				Spec: v1alpha2.ClusterNetworkPolicySpec{
					Tier:     v1alpha2.AdminTier,
					Priority: 200,
					Subject: v1alpha2.ClusterNetworkPolicySubject{
						Pods: &v1alpha2.NamespacedPod{
							NamespaceSelector: selEnv,
							PodSelector:       selApp,
						},
					},
					Egress: []v1alpha2.ClusterNetworkPolicyEgressRule{
						{
							Name:   "to-external",
							Action: v1alpha2.ClusterNetworkPolicyRuleActionAccept,
							To: []v1alpha2.ClusterNetworkPolicyEgressPeer{
								{Networks: []v1alpha2.CIDR{v1alpha2.CIDR("203.0.113.0/24")}},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uid-4",
				Name: "uid-4",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.ClusterNetworkPolicy,
					Name: "cnp-egress-net",
					UID:  "uid-4",
				},
				Priority:         ptr.To(float64(200)),
				TierPriority:     ptr.To(adminTierPriority),
				AppliedToPerRule: false,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							IPBlocks: []controlplane.IPBlock{{CIDR: *cidr203}},
						},
						Name:     "to-external",
						Action:   &allow,
						Priority: 0,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selApp, &selEnv, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   0,
		},
		{
			name: "two-ingress-rules-distinct-peers",
			inputPolicy: &v1alpha2.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnp-multi-in", UID: "uid-5"},
				Spec: v1alpha2.ClusterNetworkPolicySpec{
					Tier:     v1alpha2.AdminTier,
					Priority: 30,
					Subject: v1alpha2.ClusterNetworkPolicySubject{
						Pods: &v1alpha2.NamespacedPod{
							NamespaceSelector: selEnv,
							PodSelector:       selApp,
						},
					},
					Ingress: []v1alpha2.ClusterNetworkPolicyIngressRule{
						{
							Name:   "first",
							Action: v1alpha2.ClusterNetworkPolicyRuleActionAccept,
							From: []v1alpha2.ClusterNetworkPolicyIngressPeer{
								{Namespaces: &selClient},
							},
						},
						{
							Name:   "second",
							Action: v1alpha2.ClusterNetworkPolicyRuleActionAccept,
							From: []v1alpha2.ClusterNetworkPolicyIngressPeer{
								{Namespaces: &selDstNs},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uid-5",
				Name: "uid-5",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.ClusterNetworkPolicy,
					Name: "cnp-multi-in",
					UID:  "uid-5",
				},
				Priority:         ptr.To(float64(30)),
				TierPriority:     ptr.To(adminTierPriority),
				AppliedToPerRule: false,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selClient, nil, nil).NormalizedName)},
						},
						Name:     "first",
						Action:   &allow,
						Priority: 0,
					},
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selDstNs, nil, nil).NormalizedName)},
						},
						Name:     "second",
						Action:   &allow,
						Priority: 1,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selApp, &selEnv, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController(nil, nil)
			c.namespaceStore.Add(&v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "nsA"}})
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

func cnpForInformerTests() *v1alpha2.ClusterNetworkPolicy {
	return &v1alpha2.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cnp-informer", UID: "uid-inf"},
		Spec: v1alpha2.ClusterNetworkPolicySpec{
			Tier:     v1alpha2.AdminTier,
			Priority: 1,
			Subject: v1alpha2.ClusterNetworkPolicySubject{
				Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "blue"}},
			},
			Ingress: []v1alpha2.ClusterNetworkPolicyIngressRule{
				{
					Action: v1alpha2.ClusterNetworkPolicyRuleActionAccept,
					From: []v1alpha2.ClusterNetworkPolicyIngressPeer{
						{Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"client": "x"}}},
					},
				},
			},
		},
	}
}

func TestAddCNP(t *testing.T) {
	_, npc := newController(nil, nil)
	cnp := cnpForInformerTests()
	npc.addCNP(cnp)
	require.Equal(t, 1, npc.internalNetworkPolicyQueue.Len())
	key, done := npc.internalNetworkPolicyQueue.Get()
	expectedKey := getCNPReference(cnp)
	assert.Equal(t, *expectedKey, key)
	assert.False(t, done)
}

func TestUpdateCNP(t *testing.T) {
	_, npc := newController(nil, nil)
	cnp := cnpForInformerTests()
	newCNP := cnp.DeepCopy()
	newCNP.Annotations = map[string]string{"k": "v"}
	npc.updateCNP(cnp, newCNP)
	require.Equal(t, 1, npc.internalNetworkPolicyQueue.Len())
	key, done := npc.internalNetworkPolicyQueue.Get()
	assert.Equal(t, *getCNPReference(cnp), key)
	assert.False(t, done)
}

func TestDeleteCNP(t *testing.T) {
	_, npc := newController(nil, nil)
	cnp := cnpForInformerTests()
	npc.deleteCNP(cnp)
	require.Equal(t, 1, npc.internalNetworkPolicyQueue.Len())
	key, done := npc.internalNetworkPolicyQueue.Get()
	assert.Equal(t, *getCNPReference(cnp), key)
	assert.False(t, done)
}
