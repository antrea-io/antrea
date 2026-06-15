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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/cache"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	policyv1alpha2 "sigs.k8s.io/network-policy-api/apis/v1alpha2"

	"antrea.io/antrea/v2/pkg/apis/controlplane"
	antreatypes "antrea.io/antrea/v2/pkg/controller/types"
	"antrea.io/antrea/v2/pkg/features"
)

func TestProcessK8sClusterNetworkPolicy(t *testing.T) {
	p10 := float64(10)
	p5 := float64(5)
	portName := "secured"
	intstrPortName := intstr.FromString(portName)
	cidr := "10.0.0.0/8"
	cidrIPNet, _ := cidrStrToIPNet(cidr)
	tests := []struct {
		name                    string
		inputPolicy             *policyv1alpha2.ClusterNetworkPolicy
		expectedPolicy          *antreatypes.NetworkPolicy
		expectedAppliedToGroups int
		expectedAddressGroups   int
	}{
		{
			name: "admin-tier-with-pods-peer-and-ports",
			inputPolicy: &policyv1alpha2.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpA", UID: "uidA"},
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Tier:     policyv1alpha2.AdminTier,
					Priority: 10,
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &selectorA,
					},
					Ingress: []policyv1alpha2.ClusterNetworkPolicyIngressRule{
						{
							Action: policyv1alpha2.ClusterNetworkPolicyRuleActionAccept,
							From: []policyv1alpha2.ClusterNetworkPolicyIngressPeer{
								{
									Pods: &policyv1alpha2.NamespacedPod{
										NamespaceSelector: selectorC,
										PodSelector:       selectorB,
									},
								},
							},
							Protocols: []policyv1alpha2.ClusterNetworkPolicyProtocol{
								{TCP: &policyv1alpha2.ClusterNetworkPolicyProtocolTCP{DestinationPort: &policyv1alpha2.Port{Number: 80}}},
								{DestinationNamedPort: portName},
							},
						},
					},
					Egress: []policyv1alpha2.ClusterNetworkPolicyEgressRule{
						{
							Action: policyv1alpha2.ClusterNetworkPolicyRuleActionDeny,
							To: []policyv1alpha2.ClusterNetworkPolicyEgressPeer{
								{
									Pods: &policyv1alpha2.NamespacedPod{
										NamespaceSelector: selectorC,
										PodSelector:       selectorB,
									},
								},
							},
							Protocols: []policyv1alpha2.ClusterNetworkPolicyProtocol{
								{TCP: &policyv1alpha2.ClusterNetworkPolicyProtocolTCP{DestinationPort: &policyv1alpha2.Port{Number: 81}}},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.K8sClusterNetworkPolicy,
					Name: "cnpA",
					UID:  "uidA",
				},
				Priority:     &p10,
				TierPriority: &adminTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, &selectorC, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{Protocol: &protocolTCP, Port: &int80},
							{Port: &intstrPortName},
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
							{Protocol: &protocolTCP, Port: &int81},
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
			name: "admin-tier-with-networks-peer",
			inputPolicy: &policyv1alpha2.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpB", UID: "uidB"},
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Tier:     policyv1alpha2.AdminTier,
					Priority: 10,
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &selectorA,
					},
					Egress: []policyv1alpha2.ClusterNetworkPolicyEgressRule{
						{
							Action: policyv1alpha2.ClusterNetworkPolicyRuleActionDeny,
							To: []policyv1alpha2.ClusterNetworkPolicyEgressPeer{
								{Networks: []policyv1alpha2.CIDR{policyv1alpha2.CIDR(cidr)}},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidB",
				Name: "uidB",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.K8sClusterNetworkPolicy,
					Name: "cnpB",
					UID:  "uidB",
				},
				Priority:     &p10,
				TierPriority: &adminTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							IPBlocks: []controlplane.IPBlock{{CIDR: *cidrIPNet}},
						},
						Priority: 0,
						Action:   &dropAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorA, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   0,
		},
		{
			name: "baseline-tier",
			inputPolicy: &policyv1alpha2.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "cnpC", UID: "uidC"},
				Spec: policyv1alpha2.ClusterNetworkPolicySpec{
					Tier:     policyv1alpha2.BaselineTier,
					Priority: 5,
					Subject: policyv1alpha2.ClusterNetworkPolicySubject{
						Namespaces: &selectorA,
					},
					Ingress: []policyv1alpha2.ClusterNetworkPolicyIngressRule{
						{
							Action: policyv1alpha2.ClusterNetworkPolicyRuleActionDeny,
							From: []policyv1alpha2.ClusterNetworkPolicyIngressPeer{
								{Namespaces: &selectorB},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidC",
				Name: "uidC",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type: controlplane.K8sClusterNetworkPolicy,
					Name: "cnpC",
					UID:  "uidC",
				},
				Priority:     &p5,
				TierPriority: &baselineTierPriority,
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorB, nil, nil).NormalizedName)},
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
	}
	featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.K8sClusterNetworkPolicy, true)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController(nil, nil)
			actualPolicy, actualAppliedToGroups, actualAddressGroups := c.processK8sClusterNetworkPolicy(tt.inputPolicy)
			assert.Equal(t, tt.expectedPolicy.UID, actualPolicy.UID)
			assert.Equal(t, tt.expectedPolicy.Name, actualPolicy.Name)
			assert.Equal(t, tt.expectedPolicy.SourceRef, actualPolicy.SourceRef)
			assert.Equal(t, tt.expectedPolicy.Priority, actualPolicy.Priority)
			assert.Equal(t, tt.expectedPolicy.TierPriority, actualPolicy.TierPriority)
			assert.ElementsMatch(t, tt.expectedPolicy.Rules, actualPolicy.Rules)
			assert.ElementsMatch(t, tt.expectedPolicy.AppliedToGroups, actualPolicy.AppliedToGroups)
			assert.Equal(t, tt.expectedAppliedToGroups, len(actualAppliedToGroups))
			assert.Equal(t, tt.expectedAddressGroups, len(actualAddressGroups))
		})
	}
}

func TestToAntreaServicesForK8sCNP(t *testing.T) {
	port53 := intstr.FromInt(53)
	port132 := intstr.FromInt(132)
	port8080 := intstr.FromInt(8080)
	portRangeStart := intstr.FromInt(8000)
	endPort := int32(9000)
	namedPort := intstr.FromString("http")
	protoTCP := controlplane.ProtocolTCP
	protoUDP := controlplane.ProtocolUDP
	protoSCTP := controlplane.ProtocolSCTP
	protocols := []policyv1alpha2.ClusterNetworkPolicyProtocol{
		{TCP: &policyv1alpha2.ClusterNetworkPolicyProtocolTCP{DestinationPort: &policyv1alpha2.Port{Number: 8080}}},
		{UDP: &policyv1alpha2.ClusterNetworkPolicyProtocolUDP{DestinationPort: &policyv1alpha2.Port{Number: 53}}},
		{SCTP: &policyv1alpha2.ClusterNetworkPolicyProtocolSCTP{DestinationPort: &policyv1alpha2.Port{Number: 132}}},
		{TCP: &policyv1alpha2.ClusterNetworkPolicyProtocolTCP{DestinationPort: &policyv1alpha2.Port{Range: &policyv1alpha2.PortRange{Start: 8000, End: 9000}}}},
		{DestinationNamedPort: "http"},
	}
	expected := []controlplane.Service{
		{Protocol: &protoTCP, Port: &port8080},
		{Protocol: &protoUDP, Port: &port53},
		{Protocol: &protoSCTP, Port: &port132},
		{Protocol: &protoTCP, Port: &portRangeStart, EndPort: &endPort},
		{Port: &namedPort},
	}
	assert.Equal(t, expected, toAntreaServicesForK8sCNP(protocols))
}

func TestToAntreaServiceForK8sCNPPort(t *testing.T) {
	port80 := intstr.FromInt(80)
	portRangeStart := intstr.FromInt(8000)
	endPort := int32(9000)
	protoUDP := controlplane.ProtocolUDP
	protoTCP := controlplane.ProtocolTCP
	tests := []struct {
		name     string
		protocol v1.Protocol
		port     *policyv1alpha2.Port
		expected controlplane.Service
	}{
		{
			name:     "nil-port-matches-all",
			protocol: v1.ProtocolUDP,
			port:     nil,
			expected: controlplane.Service{Protocol: &protoUDP},
		},
		{
			name:     "single-port-number",
			protocol: v1.ProtocolTCP,
			port:     &policyv1alpha2.Port{Number: 80},
			expected: controlplane.Service{Protocol: &protoTCP, Port: &port80},
		},
		{
			name:     "port-range",
			protocol: v1.ProtocolTCP,
			port:     &policyv1alpha2.Port{Range: &policyv1alpha2.PortRange{Start: 8000, End: 9000}},
			expected: controlplane.Service{Protocol: &protoTCP, Port: &portRangeStart, EndPort: &endPort},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, toAntreaServiceForK8sCNPPort(tt.protocol, tt.port))
		})
	}
}

func TestK8sCNPNetworkToAntreaIPBlock(t *testing.T) {
	ipBlock, err := k8sCNPNetworkToAntreaIPBlock("10.0.0.0/8")
	assert.NoError(t, err)
	assert.NotNil(t, ipBlock)
	assert.EqualValues(t, 8, ipBlock.CIDR.PrefixLength)

	_, err = k8sCNPNetworkToAntreaIPBlock("not-a-valid-cidr")
	assert.Error(t, err)
}

func TestK8sCNPEventHandlers(t *testing.T) {
	cnp := &policyv1alpha2.ClusterNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "cnpA", UID: "uidA"}}
	_, c := newController(nil, nil)
	drain := func() {
		key, _ := c.internalNetworkPolicyQueue.Get()
		c.internalNetworkPolicyQueue.Done(key)
	}
	c.addK8sCNP(cnp)
	assert.Equal(t, 1, c.internalNetworkPolicyQueue.Len(), "addK8sCNP should enqueue the policy")
	drain()
	c.updateK8sCNP(cnp, cnp)
	assert.Equal(t, 1, c.internalNetworkPolicyQueue.Len(), "updateK8sCNP should enqueue the policy")
	drain()
	c.deleteK8sCNP(cnp)
	assert.Equal(t, 1, c.internalNetworkPolicyQueue.Len(), "deleteK8sCNP should enqueue the policy")
	drain()
	// deleteK8sCNP must also handle the DeletedFinalStateUnknown tombstone.
	c.deleteK8sCNP(cache.DeletedFinalStateUnknown{Key: "cnpA", Obj: cnp})
	assert.Equal(t, 1, c.internalNetworkPolicyQueue.Len(), "deleteK8sCNP should handle a tombstone")
}

func TestToAntreaPeerForK8sCNPEgressInvalidCIDR(t *testing.T) {
	_, c := newController(nil, nil)
	peer, ags := c.toAntreaPeerForK8sCNPEgress([]policyv1alpha2.ClusterNetworkPolicyEgressPeer{
		{Networks: []policyv1alpha2.CIDR{"not-a-valid-cidr"}},
	}, "cnpX")
	assert.Empty(t, peer.IPBlocks, "invalid CIDR should be skipped")
	assert.Empty(t, ags)
}
