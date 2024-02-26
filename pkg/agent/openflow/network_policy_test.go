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

package openflow

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	opstest "antrea.io/antrea/pkg/agent/openflow/operations/testing"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	mocks "antrea.io/antrea/pkg/ovs/openflow/testing"
	ovsctltest "antrea.io/antrea/pkg/ovs/ovsctl/testing"
)

var (
	c                               *client
	mockAntreaPolicyEgressRuleTable *mocks.MockTable
	mockEgressRuleTable             *mocks.MockTable
	mockEgressDefaultTable          *mocks.MockTable
	mockL3ForwardingTable           *mocks.MockTable
	mockEgressMetricTable           *mocks.MockTable

	ruleFlowBuilder   *mocks.MockFlowBuilder
	ruleFlow          *mocks.MockFlow
	dropFlowBuilder   *mocks.MockFlowBuilder
	dropFlow          *mocks.MockFlow
	metricFlowBuilder *mocks.MockFlowBuilder
	metricFlow        *mocks.MockFlow

	ruleAction   *mocks.MockAction
	metricAction *mocks.MockAction

	_, podIPv4CIDR, _ = net.ParseCIDR("100.100.100.0/24")
	_, podIPv6CIDR, _ = net.ParseCIDR("fd12:ab35:34:a001::/64")

	actionAllow  = crdv1beta1.RuleActionAllow
	actionDrop   = crdv1beta1.RuleActionDrop
	port8080     = intstr.FromInt(8080)
	port32800    = int32(32800)
	protocolICMP = v1beta2.ProtocolICMP
	priority100  = uint16(100)
	priority200  = uint16(200)
	priority201  = uint16(201)
	icmpType8    = int32(8)
	icmpCode0    = int32(0)

	mockFeaturePodConnectivity = featurePodConnectivity{}
	mockFeatureNetworkPolicy   = featureNetworkPolicy{enableAntreaPolicy: true}
	activeFeatures             = []feature{&mockFeaturePodConnectivity, &mockFeatureNetworkPolicy}
	pipelineMap                = map[binding.PipelineID]binding.Pipeline{}
)

type expectConjunctionTimes struct {
	count    int
	conjID   uint32
	clauseID uint8
	nClause  uint8
}

func TestPolicyRuleConjunction(t *testing.T) {
	ctrl := gomock.NewController(t)
	preparePipelines()
	defer resetPipelines()
	c = prepareClient(ctrl, false)

	ruleID1 := uint32(1001)
	conj1 := &policyRuleConjunction{
		id: ruleID1,
	}
	clauseID := uint8(1)
	nClause := uint8(3)
	clause1 := conj1.newClause(clauseID, nClause, mockEgressRuleTable, mockEgressDefaultTable)

	mockEgressDefaultTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockDropFlowBuilder(ctrl, mockEgressDefaultTable)).AnyTimes()
	mockEgressRuleTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockRuleFlowBuilder(ctrl, mockEgressRuleTable)).AnyTimes()
	mockEgressMetricTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockMetricFlowBuilder(ctrl, mockEgressMetricTable)).AnyTimes()

	var addedAddrs = parseAddresses([]string{"192.168.1.3", "192.168.1.30", "192.168.2.0/24", "103", "104"})
	expectConjunctionsCount([]*expectConjunctionTimes{{5, ruleID1, clauseID, nClause}})
	flowChanges1 := clause1.addAddrFlows(c.featureNetworkPolicy, types.SrcAddress, addedAddrs, nil, false, false)
	err := c.featureNetworkPolicy.applyConjunctiveMatchFlows(flowChanges1)
	require.Nil(t, err, "Failed to invoke addAddrFlows")
	checkFlowCount(t, len(addedAddrs))
	for _, addr := range addedAddrs {
		checkConjMatchFlowActions(t, c, clause1, addr, types.SrcAddress, 1, 0)
	}
	var currentFlowCount = len(c.featureNetworkPolicy.globalConjMatchFlowCache)

	var deletedAddrs = parseAddresses([]string{"192.168.1.3", "103"})
	flowChanges2 := clause1.deleteAddrFlows(types.SrcAddress, deletedAddrs, nil)
	err = c.featureNetworkPolicy.applyConjunctiveMatchFlows(flowChanges2)
	require.Nil(t, err, "Failed to invoke deleteAddrFlows")
	checkFlowCount(t, currentFlowCount-len(deletedAddrs))
	currentFlowCount = len(c.featureNetworkPolicy.globalConjMatchFlowCache)

	ruleID2 := uint32(1002)
	conj2 := &policyRuleConjunction{
		id: ruleID2,
	}
	clauseID2 := uint8(2)
	clause2 := conj2.newClause(clauseID2, nClause, mockEgressRuleTable, mockEgressDefaultTable)
	var addedAddrs2 = parseAddresses([]string{"192.168.1.30", "192.168.1.50"})
	expectConjunctionsCount([]*expectConjunctionTimes{{2, ruleID2, clauseID2, nClause}})
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID1, clauseID, nClause}})
	flowChanges3 := clause2.addAddrFlows(c.featureNetworkPolicy, types.SrcAddress, addedAddrs2, nil, false, false)
	err = c.featureNetworkPolicy.applyConjunctiveMatchFlows(flowChanges3)
	require.Nil(t, err, "Failed to invoke addAddrFlows")
	testAddr := NewIPAddress(net.ParseIP("192.168.1.30"))
	checkConjMatchFlowActions(t, c, clause2, testAddr, types.SrcAddress, 2, 0)
	checkFlowCount(t, currentFlowCount+1)
	currentFlowCount = len(c.featureNetworkPolicy.globalConjMatchFlowCache)

	ruleID3 := uint32(1003)
	conj3 := &policyRuleConjunction{
		id: ruleID3,
	}
	clauseID3 := uint8(1)
	nClause3 := uint8(1)
	clause3 := conj3.newClause(clauseID3, nClause3, mockEgressRuleTable, mockEgressDefaultTable)
	var addedAddrs3 = parseAddresses([]string{"192.168.1.30"})
	flowChanges4 := clause3.addAddrFlows(c.featureNetworkPolicy, types.SrcAddress, addedAddrs3, nil, false, false)
	err = c.featureNetworkPolicy.applyConjunctiveMatchFlows(flowChanges4)
	require.Nil(t, err, "Failed to invoke addAddrFlows")
	checkConjMatchFlowActions(t, c, clause3, testAddr, types.SrcAddress, 2, 1)
	checkFlowCount(t, currentFlowCount)
	flowChanges5 := clause3.deleteAddrFlows(types.SrcAddress, addedAddrs3, nil)
	err = c.featureNetworkPolicy.applyConjunctiveMatchFlows(flowChanges5)
	require.Nil(t, err, "Failed to invoke deleteAddrFlows")
	checkConjMatchFlowActions(t, c, clause3, testAddr, types.SrcAddress, 2, 0)
	checkFlowCount(t, currentFlowCount)
}

func TestInstallPolicyRuleFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	preparePipelines()
	defer resetPipelines()
	c = prepareClient(ctrl, false)
	c.nodeConfig = &config.NodeConfig{PodIPv4CIDR: podIPv4CIDR, PodIPv6CIDR: nil}
	c.networkConfig = &config.NetworkConfig{}
	c.pipelines = pipelineMap
	defaultAction := crdv1beta1.RuleActionAllow
	// Create a policyRuleConjunction for the dns response interception flows
	// to ensure nil NetworkPolicyReference is handled correctly by GetNetworkPolicyFlowKeys.
	dnsID := uint32(1)
	require.NoError(t, c.NewDNSPacketInConjunction(dnsID))

	ruleID1 := uint32(101)
	rule1 := &types.PolicyRule{
		Direction: v1beta2.DirectionOut,
		From:      parseAddresses([]string{"192.168.1.30", "192.168.1.50"}),
		Action:    &defaultAction,
		Priority:  nil,
		FlowID:    ruleID1,
		TableID:   EgressRuleTable.ofTable.GetID(),
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "id1",
		},
	}

	mockEgressDefaultTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockDropFlowBuilder(ctrl, mockEgressDefaultTable)).AnyTimes()
	mockEgressRuleTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockRuleFlowBuilder(ctrl, mockEgressRuleTable)).AnyTimes()
	mockEgressMetricTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockMetricFlowBuilder(ctrl, mockEgressMetricTable)).AnyTimes()

	conj := &policyRuleConjunction{id: ruleID1}
	conj.calculateClauses(rule1)
	require.Nil(t, conj.toClause)
	require.Nil(t, conj.serviceClause)
	ctxChanges := conj.calculateChangesForRuleCreation(c.featureNetworkPolicy, rule1)
	assert.Equal(t, len(rule1.From), len(ctxChanges))
	matchFlows, dropFlows := getChangedFlows(ctxChanges)
	assert.Equal(t, len(rule1.From), getChangedFlowCount(dropFlows))
	assert.Equal(t, 0, getChangedFlowCount(matchFlows))
	assert.Equal(t, 2, getDenyAllRuleOPCount(matchFlows, insertion))
	err := c.featureNetworkPolicy.applyConjunctiveMatchFlows(ctxChanges)
	require.Nil(t, err)

	ruleID2 := uint32(102)
	rule2 := &types.PolicyRule{
		Direction: v1beta2.DirectionOut,
		From:      parseAddresses([]string{"192.168.1.40", "192.168.1.50"}),
		Action:    &defaultAction,
		To:        parseAddresses([]string{"0.0.0.0/0"}),
		FlowID:    ruleID2,
		TableID:   EgressRuleTable.ofTable.GetID(),
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "id1",
		},
	}
	conj2 := &policyRuleConjunction{id: ruleID2}
	conj2.calculateClauses(rule2)
	require.NotNil(t, conj2.toClause)
	require.Nil(t, conj2.serviceClause)
	ruleFlowBuilder.EXPECT().MatchConjID(ruleID2).MaxTimes(1)
	ruleFlowBuilder.EXPECT().MatchPriority(priorityLow).MaxTimes(1)
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID2, 2, 2}})
	expectConjunctionsCount([]*expectConjunctionTimes{{2, ruleID2, 1, 2}})
	ctxChanges2 := conj2.calculateChangesForRuleCreation(c.featureNetworkPolicy, rule2)
	matchFlows2, dropFlows2 := getChangedFlows(ctxChanges2)
	assert.Equal(t, 1, getChangedFlowCount(dropFlows2))
	assert.Equal(t, 3, getChangedFlowCount(matchFlows2))
	assert.Equal(t, 3, getChangedFlowOPCount(matchFlows2, insertion))
	err = c.featureNetworkPolicy.applyConjunctiveMatchFlows(ctxChanges2)
	require.Nil(t, err)

	assert.Equal(t, 0, len(c.GetNetworkPolicyFlowKeys("np1", "ns1")))
	err = c.InstallPolicyRuleFlows(rule2)
	require.Nil(t, err)
	checkConjunctionConfig(t, ruleID2, 1, 2, 1, 0)
	assert.Equal(t, 6, len(c.GetNetworkPolicyFlowKeys("np1", "ns1")))

	ruleID3 := uint32(103)
	port1 := intstr.FromInt(8080)
	port2 := intstr.FromInt(1000)
	port3 := int32(1007)
	npService1 := v1beta2.Service{Protocol: &protocolTCP, Port: &port1}
	npService2 := v1beta2.Service{Protocol: &protocolTCP, Port: &port2, EndPort: &port3}
	npService3 := v1beta2.Service{Protocol: &protocolICMP, ICMPType: &icmpType8, ICMPCode: &icmpCode0}
	rule3 := &types.PolicyRule{
		Direction: v1beta2.DirectionOut,
		From:      parseAddresses([]string{"192.168.1.40", "192.168.1.60"}),
		To:        parseAddresses([]string{"192.168.2.0/24"}),
		Action:    &defaultAction,
		Service:   []v1beta2.Service{npService1, npService2, npService3},
		FlowID:    ruleID3,
		TableID:   EgressRuleTable.ofTable.GetID(),
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "id1",
		},
	}
	conj3 := &policyRuleConjunction{id: ruleID3}
	conj3.calculateClauses(rule3)
	ruleFlowBuilder.EXPECT().MatchConjID(ruleID3).MaxTimes(3)
	ruleFlowBuilder.EXPECT().MatchPriority(priorityLow).MaxTimes(3)
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID2, 1, 2}})
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID3, 2, 3}})
	expectConjunctionsCount([]*expectConjunctionTimes{{2, ruleID3, 1, 3}})
	expectConjunctionsCount([]*expectConjunctionTimes{{2, ruleID3, 3, 3}})
	ctxChanges3 := conj3.calculateChangesForRuleCreation(c.featureNetworkPolicy, rule3)
	matchFlows3, dropFlows3 := getChangedFlows(ctxChanges3)
	assert.Equal(t, 1, getChangedFlowOPCount(dropFlows3, insertion))
	assert.Equal(t, 6, getChangedFlowCount(matchFlows3))
	assert.Equal(t, 5, getChangedFlowOPCount(matchFlows3, insertion))
	assert.Equal(t, 1, getChangedFlowOPCount(matchFlows3, modification))
	err = c.featureNetworkPolicy.applyConjunctiveMatchFlows(ctxChanges3)
	require.Nil(t, err)

	err = c.InstallPolicyRuleFlows(rule3)
	require.Nil(t, err, "Failed to invoke InstallPolicyRuleFlows")
	checkConjunctionConfig(t, ruleID3, 1, 2, 1, 3)
	assert.Equal(t, 15, len(c.GetNetworkPolicyFlowKeys("np1", "ns1")))

	ctxChanges4 := conj.calculateChangesForRuleDeletion()
	matchFlows4, dropFlows4 := getChangedFlows(ctxChanges4)
	assert.Equal(t, 1, getChangedFlowOPCount(dropFlows4, deletion))
	assert.Equal(t, 2, getDenyAllRuleOPCount(matchFlows4, deletion))
	err = c.featureNetworkPolicy.applyConjunctiveMatchFlows(ctxChanges4)
	require.Nil(t, err)

	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID3, 1, 3}})
	ctxChanges5 := conj2.calculateChangesForRuleDeletion()
	matchFlows5, dropFlows5 := getChangedFlows(ctxChanges5)
	assert.Equal(t, 1, getChangedFlowOPCount(dropFlows5, deletion))
	assert.Equal(t, 3, getChangedFlowCount(matchFlows5))
	assert.Equal(t, 2, getChangedFlowOPCount(matchFlows5, deletion))
	assert.Equal(t, 1, getChangedFlowOPCount(matchFlows5, modification))
	err = c.featureNetworkPolicy.applyConjunctiveMatchFlows(ctxChanges5)
	assert.Equal(t, 12, len(c.GetNetworkPolicyFlowKeys("np1", "ns1")))
	require.Nil(t, err)
}

func TestBatchInstallPolicyRuleFlows(t *testing.T) {
	for _, tt := range []struct {
		name          string
		rules         []*types.PolicyRule
		expectedFlows []string
	}{
		{
			name: "multiple K8s NetworkPolicy rules",
			rules: []*types.PolicyRule{
				{
					Direction: v1beta2.DirectionOut,
					From:      parseAddresses([]string{"192.168.1.40", "192.168.1.50"}),
					To:        parseAddresses([]string{"0.0.0.0/0"}),
					FlowID:    uint32(10),
					PolicyRef: &v1beta2.NetworkPolicyReference{
						Type:      v1beta2.K8sNetworkPolicy,
						Namespace: "ns1",
						Name:      "np1",
						UID:       "id1",
					},
				},
				{
					Direction: v1beta2.DirectionOut,
					// conjunctive match flow for nw_src=192.168.1.40 should tie to conjunction 10 and 11.
					// conjunctive match flow for nw_src=192.168.1.51 should tie to conjunction 11 only.
					From:    parseAddresses([]string{"192.168.1.40", "192.168.1.51"}),
					To:      parseAddresses([]string{"0.0.0.0/0"}),
					Service: []v1beta2.Service{{Protocol: &protocolTCP, Port: &port8080}},
					FlowID:  uint32(11),
					PolicyRef: &v1beta2.NetworkPolicyReference{
						Type:      v1beta2.K8sNetworkPolicy,
						Namespace: "ns1",
						Name:      "np2",
						UID:       "id2",
					},
				},
			},
			expectedFlows: []string{
				"cookie=0x1020000000000, table=EgressRule, priority=190,conj_id=10,ip actions=set_field:0xa->reg5,ct(commit,table=EgressMetric,zone=65520,exec(set_field:0xa00000000/0xffffffff00000000->ct_label))",
				"cookie=0x1020000000000, table=EgressRule, priority=190,conj_id=11,ip actions=set_field:0xb->reg5,ct(commit,table=EgressMetric,zone=65520,exec(set_field:0xb00000000/0xffffffff00000000->ct_label))",
				"cookie=0x1020000000000, table=EgressRule, priority=200,ip,nw_src=192.168.1.40 actions=conjunction(10,1/2),conjunction(11,1/3)",
				"cookie=0x1020000000000, table=EgressRule, priority=200,ip,nw_src=192.168.1.50 actions=conjunction(10,1/2)",
				"cookie=0x1020000000000, table=EgressRule, priority=200,ip,nw_src=192.168.1.51 actions=conjunction(11,1/3)",
				"cookie=0x1020000000000, table=EgressRule, priority=200,ip,nw_dst=0.0.0.0/0 actions=conjunction(10,2/2),conjunction(11,2/3)",
				"cookie=0x1020000000000, table=EgressRule, priority=200,tcp,tp_dst=8080 actions=conjunction(11,3/3)",
				"cookie=0x1020000000000, table=EgressDefaultRule, priority=200,ip,nw_src=192.168.1.40 actions=drop",
				"cookie=0x1020000000000, table=EgressDefaultRule, priority=200,ip,nw_src=192.168.1.50 actions=drop",
				"cookie=0x1020000000000, table=EgressDefaultRule, priority=200,ip,nw_src=192.168.1.51 actions=drop",
				"cookie=0x1020000000000, table=EgressMetric, priority=200,ct_state=+new,ct_label=0xa00000000/0xffffffff00000000,ip actions=goto_table:L3Forwarding",
				"cookie=0x1020000000000, table=EgressMetric, priority=200,ct_state=-new,ct_label=0xa00000000/0xffffffff00000000,ip actions=goto_table:L3Forwarding",
				"cookie=0x1020000000000, table=EgressMetric, priority=200,ct_state=+new,ct_label=0xb00000000/0xffffffff00000000,ip actions=goto_table:L3Forwarding",
				"cookie=0x1020000000000, table=EgressMetric, priority=200,ct_state=-new,ct_label=0xb00000000/0xffffffff00000000,ip actions=goto_table:L3Forwarding",
			},
		},
		{
			name: "multiple Antrea NetworkPolicy rules",
			rules: []*types.PolicyRule{
				{
					Direction: v1beta2.DirectionIn,
					From:      parseAddresses([]string{"192.168.1.40", "192.168.1.50"}),
					Action:    &actionAllow,
					Priority:  &priority100,
					To:        []types.Address{NewOFPortAddress(1), NewOFPortAddress(2)},
					FlowID:    uint32(10),
					PolicyRef: &v1beta2.NetworkPolicyReference{
						Type:      v1beta2.AntreaNetworkPolicy,
						Namespace: "ns1",
						Name:      "np1",
						UID:       "id1",
					},
				},
				{
					Direction: v1beta2.DirectionIn,
					// conjunctive match flow with priority 100 for nw_src=192.168.1.40 should tie to conjunction 10 and 11 but not 12.
					From:     parseAddresses([]string{"192.168.1.40", "192.168.1.51"}),
					Action:   &actionDrop,
					Priority: &priority100,
					To:       []types.Address{NewOFPortAddress(1), NewOFPortAddress(3)},
					Service:  []v1beta2.Service{{Protocol: &protocolTCP, Port: &port8080}},
					FlowID:   uint32(11),
					PolicyRef: &v1beta2.NetworkPolicyReference{
						Type:      v1beta2.AntreaNetworkPolicy,
						Namespace: "ns1",
						Name:      "np2",
						UID:       "id2",
					},
				},
				{
					Direction: v1beta2.DirectionIn,
					// conjunctive match flow with priority 200 for nw_src=192.168.1.40 should tie to conjunction 12 only.
					From:     parseAddresses([]string{"192.168.1.40"}),
					Action:   &actionDrop,
					Priority: &priority200,
					To:       []types.Address{NewOFPortAddress(1)},
					Service:  []v1beta2.Service{{Protocol: &protocolTCP, Port: &port8080}, {Protocol: &protocolICMP, ICMPType: &icmpType8, ICMPCode: &icmpCode0}},
					FlowID:   uint32(12),
					PolicyRef: &v1beta2.NetworkPolicyReference{
						Type:      v1beta2.AntreaNetworkPolicy,
						Namespace: "ns1",
						Name:      "np3",
						UID:       "id3",
					},
				},
				{
					Direction: v1beta2.DirectionIn,
					From:      parseLabelIdentityAddresses([]uint32{1, 2}),
					Action:    &actionDrop,
					Priority:  &priority201,
					To:        []types.Address{NewOFPortAddress(1), NewOFPortAddress(2)},
					Service:   []v1beta2.Service{},
					FlowID:    uint32(13),
					PolicyRef: &v1beta2.NetworkPolicyReference{
						Type:      v1beta2.AntreaNetworkPolicy,
						Namespace: "ns1",
						Name:      "np4",
						UID:       "id4",
					},
				},
				{
					Direction: v1beta2.DirectionIn,
					From:      parseAddresses([]string{"192.168.1.51"}),
					Action:    &actionDrop,
					Priority:  &priority100,
					To:        []types.Address{NewOFPortAddress(2)},
					Service:   []v1beta2.Service{{Protocol: &protocolTCP, SrcPort: &port32800}},
					FlowID:    uint32(14),
					PolicyRef: &v1beta2.NetworkPolicyReference{
						Type:      v1beta2.AntreaNetworkPolicy,
						Namespace: "ns1",
						Name:      "np5",
						UID:       "id5",
					},
				},
			},
			expectedFlows: []string{
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=100,conj_id=10,ip actions=set_field:0xa->reg6,ct(commit,table=IngressMetric,zone=65520,exec(set_field:0xa/0xffffffff->ct_label))",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=100,conj_id=11 actions=set_field:0xb->reg3,set_field:0x400/0x400->reg0,goto_table:IngressMetric",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=200,conj_id=12 actions=set_field:0xc->reg3,set_field:0x400/0x400->reg0,goto_table:IngressMetric",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=201,conj_id=13 actions=set_field:0xd->reg3,set_field:0x400/0x400->reg0,goto_table:IngressMetric",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=100,conj_id=14 actions=set_field:0xe->reg3,set_field:0x400/0x400->reg0,goto_table:IngressMetric",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=100,ip,nw_src=192.168.1.40 actions=conjunction(10,1/2),conjunction(11,1/3)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=100,ip,nw_src=192.168.1.50 actions=conjunction(10,1/2)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=100,ip,nw_src=192.168.1.51 actions=conjunction(11,1/3),conjunction(14,1/3)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=201,tun_id=1 actions=conjunction(13,1/3)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=201,tun_id=2 actions=conjunction(13,1/3)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=201,reg1=0x1 actions=conjunction(13,2/3)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=100,reg1=0x1 actions=conjunction(11,2/3),conjunction(10,2/2)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=100,tcp,tp_dst=8080 actions=conjunction(11,3/3)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=200,reg1=0x1 actions=conjunction(12,2/3)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=100,reg1=0x2 actions=conjunction(10,2/2),conjunction(14,2/3)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=200,tcp,tp_dst=8080 actions=conjunction(12,3/3)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=200,icmp,icmp_type=8,icmp_code=0 actions=conjunction(12,3/3)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=201,reg1=0x2 actions=conjunction(13,2/3)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=100,reg1=0x3 actions=conjunction(11,2/3)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=200,ip,nw_src=192.168.1.40 actions=conjunction(12,1/3)",

				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=100,tcp,tp_src=32800 actions=conjunction(14,3/3)",
				"cookie=0x1020000000000, table=IngressDefaultRule, priority=200,reg1=0x1,tun_id=16777215 actions=drop",
				"cookie=0x1020000000000, table=IngressDefaultRule, priority=200,reg1=0x2,tun_id=16777215 actions=drop",
				"cookie=0x1020000000000, table=IngressMetric, priority=200,ct_state=+new,ct_label=0xa/0xffffffff,ip actions=goto_table:ConntrackCommit",
				"cookie=0x1020000000000, table=IngressMetric, priority=200,ct_state=-new,ct_label=0xa/0xffffffff,ip actions=goto_table:ConntrackCommit",
				"cookie=0x1020000000000, table=IngressMetric, priority=200,reg0=0x400/0x400,reg3=0xb actions=drop",
				"cookie=0x1020000000000, table=IngressMetric, priority=200,reg0=0x400/0x400,reg3=0xc actions=drop",
				"cookie=0x1020000000000, table=IngressMetric, priority=200,reg0=0x400/0x400,reg3=0xd actions=drop",
				"cookie=0x1020000000000, table=IngressMetric, priority=200,reg0=0x400/0x400,reg3=0xe actions=drop",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockOperations := opstest.NewMockOFEntryOperations(ctrl)

			c := newFakeClient(mockOperations, true, false, config.K8sNode, config.TrafficEncapModeEncap)
			defer resetPipelines()
			c.featureNetworkPolicy.egressTables = map[uint8]struct{}{EgressRuleTable.GetID(): {}, EgressDefaultTable.GetID(): {}, AntreaPolicyEgressRuleTable.GetID(): {}}

			for _, r := range tt.rules {
				if r.Direction == v1beta2.DirectionOut {
					if r.IsAntreaNetworkPolicyRule() {
						r.TableID = AntreaPolicyEgressRuleTable.GetID()
					} else {
						r.TableID = EgressRuleTable.GetID()
					}
				} else {
					if r.IsAntreaNetworkPolicyRule() {
						r.TableID = AntreaPolicyIngressRuleTable.GetID()
					} else {
						r.TableID = IngressRuleTable.GetID()
					}
				}
			}
			c.featureNetworkPolicy.globalConjMatchFlowCache = make(map[string]*conjMatchFlowContext)
			c.featureNetworkPolicy.policyCache = cache.NewIndexer(policyConjKeyFunc, cache.Indexers{priorityIndex: priorityIndexFunc})
			expectedFlowStr := strings.Join(tt.expectedFlows, "; ")
			// For better readability when debugging failure.
			eq := gomock.GotFormatterAdapter(
				gomock.GotFormatterFunc(
					func(i interface{}) string {
						return dumpFlows(i.([]*openflow15.FlowMod))
					}),
				gomock.WantFormatter(
					gomock.StringerFunc(func() string { return expectedFlowStr }),
					newFlowModIgnoreTxIDMatcher(tt.expectedFlows),
				),
			)
			mockOperations.EXPECT().AddAll(eq).Return(nil).Times(1)
			err := c.BatchInstallPolicyRuleFlows(tt.rules)
			require.Nil(t, err)
		})
	}
}

type flowModIgnoreTxIDMatcher struct {
	flowMods []string
}

func newFlowModIgnoreTxIDMatcher(flowModMessages []string) gomock.Matcher {
	return flowModIgnoreTxIDMatcher{flowMods: flowModMessages}
}

func (m flowModIgnoreTxIDMatcher) Matches(x interface{}) bool {
	messages, ok := x.([]*openflow15.FlowMod)
	if !ok {
		return false
	}
	wanted := getFlowStrings(messages)
	if len(wanted) != len(m.flowMods) {
		return false
	}
	sortFlows := func(flows []string) sets.Set[string] {
		sort.Strings(flows)
		flowSet := sets.New[string]()
		getConjunctionID := func(conj string) int {
			newStr := strings.ReplaceAll(conj, "conjunction(", "")
			id, _ := strconv.Atoi(strings.Split(newStr, ",")[0])
			return id
		}
		for _, f := range flows {
			if !strings.Contains(f, "actions=conjunction") {
				flowSet.Insert(f)
				continue
			}
			strParts := strings.Split(f, "actions=")
			prefix := strParts[0]
			actionStr := strings.ReplaceAll(strParts[1], "),", ")_")
			conjunctions := strings.Split(actionStr, "_")
			sort.Slice(conjunctions, func(i, j int) bool {
				c1 := getConjunctionID(conjunctions[i])
				c2 := getConjunctionID(conjunctions[j])
				return c1 < c2
			})
			newActions := strings.Join(conjunctions, ",")
			flowSet.Insert(strings.Join([]string{prefix, newActions}, "actions="))
		}
		return flowSet
	}
	wantedSets := sortFlows(wanted)
	givenSets := sortFlows(m.flowMods)
	return wantedSets.Equal(givenSets)
}

func (m flowModIgnoreTxIDMatcher) String() string {
	return fmt.Sprintf("has the same elements as %v", strings.Join(m.flowMods, "; "))
}

func dumpFlows(flows []*openflow15.FlowMod) string {
	flowStrings := getFlowStrings(flows)
	return strings.Join(flowStrings, "; ")
}

func BenchmarkBatchInstallPolicyRuleFlows(b *testing.B) {
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()

	preparePipelines()
	defer resetPipelines()
	c = prepareClient(ctrl, false)
	// Make it return error so no change gets committed to cache.
	mockOperations := opstest.NewMockOFEntryOperations(ctrl)
	mockOperations.EXPECT().AddAll(gomock.Any()).Return(errors.New("fake error")).AnyTimes()
	c.ofEntryOperations = mockOperations

	var commonIPs []types.Address
	for i := 0; i < 250; i++ {
		commonIPs = append(commonIPs, NewIPAddress(net.ParseIP(fmt.Sprintf("192.168.0.%d", i))))
	}
	var rules []*types.PolicyRule
	for i := 0; i < 100; i++ {
		var uniqueIPs []types.Address
		for j := 0; j < 250; j++ {
			uniqueIPs = append(uniqueIPs, NewIPAddress(net.ParseIP(fmt.Sprintf("192.169.%d.%d", i, j))))
		}
		rules = append(rules, &types.PolicyRule{
			Direction: v1beta2.DirectionIn,
			From:      append(uniqueIPs, commonIPs...),
			Action:    &actionAllow,
			Priority:  &priority100,
			To:        []types.Address{NewOFPortAddress(1), NewOFPortAddress(int32(i))},
			FlowID:    uint32(i),
			TableID:   AntreaPolicyIngressRuleTable.GetID(),
			PolicyRef: &v1beta2.NetworkPolicyReference{
				Type:      v1beta2.AntreaNetworkPolicy,
				Namespace: "ns1",
				Name:      fmt.Sprintf("np%d", i),
				UID:       k8stypes.UID(fmt.Sprintf("id%d", i)),
			},
		})
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.BatchInstallPolicyRuleFlows(rules)
	}
}

func TestConjMatchFlowContextKeyConflict(t *testing.T) {
	ctrl := gomock.NewController(t)
	preparePipelines()
	defer resetPipelines()
	c = prepareClient(ctrl, false)
	mockEgressDefaultTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockDropFlowBuilder(ctrl, mockEgressDefaultTable)).AnyTimes()
	mockEgressRuleTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockRuleFlowBuilder(ctrl, mockEgressRuleTable)).AnyTimes()
	ruleAction.EXPECT().Conjunction(gomock.Any(), gomock.Any(), gomock.Any()).Return(ruleFlowBuilder).MaxTimes(3)

	ip, ipNet, _ := net.ParseCIDR("192.168.2.30/32")
	singleMatchPair := matchPair{
		matchKey:   MatchDstIPNet,
		matchValue: ipNet,
	}

	ruleID1 := uint32(11)
	conj1 := &policyRuleConjunction{
		id: ruleID1,
	}
	clause1 := conj1.newClause(1, 3, mockEgressRuleTable, mockEgressDefaultTable)
	flowChange1 := clause1.addAddrFlows(c.featureNetworkPolicy, types.DstAddress, parseAddresses([]string{ip.String()}), nil, false, false)
	err := c.featureNetworkPolicy.applyConjunctiveMatchFlows(flowChange1)
	require.Nil(t, err, "no error expect in applyConjunctiveMatchFlows")

	ruleID2 := uint32(12)
	conj2 := &policyRuleConjunction{
		id: ruleID2,
	}
	clause2 := conj2.newClause(1, 3, mockEgressRuleTable, mockEgressDefaultTable)
	flowChange2 := clause2.addAddrFlows(c.featureNetworkPolicy, types.DstAddress, parseAddresses([]string{ipNet.String()}), nil, false, false)
	err = c.featureNetworkPolicy.applyConjunctiveMatchFlows(flowChange2)
	require.Nil(t, err, "no error expect in applyConjunctiveMatchFlows")
	expectedMatchKey := fmt.Sprintf("table:%d,priority:%s,matchPair:%s", EgressRuleTable.GetID(), strconv.Itoa(int(priorityNormal)), singleMatchPair.KeyString())
	ctx, found := c.featureNetworkPolicy.globalConjMatchFlowCache[expectedMatchKey]
	assert.True(t, found)
	assert.Equal(t, 2, len(ctx.actions))
	act1, found := ctx.actions[ruleID1]
	assert.True(t, found)
	assert.Equal(t, clause1.action, act1)
	act2, found := ctx.actions[ruleID2]
	assert.True(t, found)
	assert.Equal(t, clause2.action, act2)
}

func TestInstallPolicyRuleFlowsInDualStackCluster(t *testing.T) {
	ctrl := gomock.NewController(t)
	preparePipelines()
	defer resetPipelines()
	c = prepareClient(ctrl, true)
	c.nodeConfig = &config.NodeConfig{PodIPv4CIDR: podIPv4CIDR, PodIPv6CIDR: podIPv6CIDR}
	c.networkConfig = &config.NetworkConfig{IPv4Enabled: true, IPv6Enabled: true}
	c.ipProtocols = []binding.Protocol{binding.ProtocolIP, binding.ProtocolIPv6}
	defaultAction := crdv1beta1.RuleActionAllow
	ruleID1 := uint32(101)
	rule1 := &types.PolicyRule{
		Direction: v1beta2.DirectionOut,
		From:      parseAddresses([]string{"192.168.1.30", "192.168.1.50", "fd12:ab:34:a001::4"}),
		Action:    &defaultAction,
		Priority:  nil,
		FlowID:    ruleID1,
		TableID:   EgressRuleTable.ofTable.GetID(),
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "id1",
		},
	}

	mockEgressDefaultTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockDropFlowBuilder(ctrl, mockEgressDefaultTable)).AnyTimes()
	mockEgressRuleTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockRuleFlowBuilder(ctrl, mockEgressRuleTable)).AnyTimes()
	mockEgressMetricTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockMetricFlowBuilder(ctrl, mockEgressMetricTable)).AnyTimes()

	conj := &policyRuleConjunction{id: ruleID1}
	conj.calculateClauses(rule1)
	require.Nil(t, conj.toClause)
	require.Nil(t, conj.serviceClause)
	ctxChanges := conj.calculateChangesForRuleCreation(c.featureNetworkPolicy, rule1)
	assert.Equal(t, len(rule1.From), len(ctxChanges))
	matchFlows, dropFlows := getChangedFlows(ctxChanges)
	assert.Equal(t, len(rule1.From), getChangedFlowCount(dropFlows))
	assert.Equal(t, 0, getChangedFlowCount(matchFlows))
	assert.Equal(t, len(rule1.From), getDenyAllRuleOPCount(matchFlows, insertion))
	err := c.featureNetworkPolicy.applyConjunctiveMatchFlows(ctxChanges)
	require.Nil(t, err)

	ruleID2 := uint32(102)
	rule2 := &types.PolicyRule{
		Direction: v1beta2.DirectionOut,
		From:      parseAddresses([]string{"192.168.1.40", "192.168.1.50", "fd12:ab:34:a001::5"}),
		Action:    &defaultAction,
		To:        parseAddresses([]string{"0.0.0.0/0"}),
		FlowID:    ruleID2,
		TableID:   EgressRuleTable.ofTable.GetID(),
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "id1",
		},
	}
	conj2 := &policyRuleConjunction{id: ruleID2}
	conj2.calculateClauses(rule2)
	require.NotNil(t, conj2.toClause)
	require.Nil(t, conj2.serviceClause)
	ruleFlowBuilder.EXPECT().MatchConjID(ruleID2).MaxTimes(1)
	ruleFlowBuilder.EXPECT().MatchPriority(priorityLow).MaxTimes(1)
	expectConjunctionsCount([]*expectConjunctionTimes{{len(rule2.To), ruleID2, 2, 2}})
	expectConjunctionsCount([]*expectConjunctionTimes{{len(rule2.From), ruleID2, 1, 2}})
	ctxChanges2 := conj2.calculateChangesForRuleCreation(c.featureNetworkPolicy, rule2)
	matchFlows2, dropFlows2 := getChangedFlows(ctxChanges2)
	assert.Equal(t, 2, getChangedFlowCount(dropFlows2))
	assert.Equal(t, 4, getChangedFlowCount(matchFlows2))
	assert.Equal(t, 4, getChangedFlowOPCount(matchFlows2, insertion))
	err = c.featureNetworkPolicy.applyConjunctiveMatchFlows(ctxChanges2)
	require.Nil(t, err)

	assert.Equal(t, 0, len(c.GetNetworkPolicyFlowKeys("np1", "ns1")))
	err = c.InstallPolicyRuleFlows(rule2)
	require.Nil(t, err)
	checkConjunctionConfig(t, ruleID2, 2, 3, 1, 0)
	assert.Equal(t, 9, len(c.GetNetworkPolicyFlowKeys("np1", "ns1")))

	ruleID3 := uint32(103)
	port1 := intstr.FromInt(8080)
	port2 := intstr.FromInt(8081)
	tcpProtocol := v1beta2.ProtocolTCP
	npPort1 := v1beta2.Service{Protocol: &tcpProtocol, Port: &port1}
	npPort2 := v1beta2.Service{Protocol: &tcpProtocol, Port: &port2}
	rule3 := &types.PolicyRule{
		Direction: v1beta2.DirectionOut,
		From:      parseAddresses([]string{"192.168.1.40", "192.168.1.60"}),
		To:        parseAddresses([]string{"192.168.2.0/24"}),
		Action:    &defaultAction,
		Service:   []v1beta2.Service{npPort1, npPort2},
		FlowID:    ruleID3,
		TableID:   EgressRuleTable.ofTable.GetID(),
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "id1",
		},
	}
	conj3 := &policyRuleConjunction{id: ruleID3}
	conj3.calculateClauses(rule3)
	ruleFlowBuilder.EXPECT().MatchConjID(ruleID3).MaxTimes(3)
	ruleFlowBuilder.EXPECT().MatchPriority(priorityLow).MaxTimes(3)
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID2, 1, 2}})
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID3, 2, 3}})
	expectConjunctionsCount([]*expectConjunctionTimes{{2, ruleID3, 1, 3}})
	expectConjunctionsCount([]*expectConjunctionTimes{{4, ruleID3, 3, 3}})
	ctxChanges3 := conj3.calculateChangesForRuleCreation(c.featureNetworkPolicy, rule3)
	matchFlows3, dropFlows3 := getChangedFlows(ctxChanges3)
	assert.Equal(t, 1, getChangedFlowOPCount(dropFlows3, insertion))
	assert.Equal(t, 7, getChangedFlowCount(matchFlows3))
	assert.Equal(t, 6, getChangedFlowOPCount(matchFlows3, insertion))
	assert.Equal(t, 1, getChangedFlowOPCount(matchFlows3, modification))
	err = c.featureNetworkPolicy.applyConjunctiveMatchFlows(ctxChanges3)
	require.Nil(t, err)

	err = c.InstallPolicyRuleFlows(rule3)
	require.Nil(t, err, "Failed to invoke InstallPolicyRuleFlows")
	checkConjunctionConfig(t, ruleID3, 2, 2, 1, 4)
	assert.Equal(t, 20, len(c.GetNetworkPolicyFlowKeys("np1", "ns1")))

	ctxChanges4 := conj.calculateChangesForRuleDeletion()
	matchFlows4, dropFlows4 := getChangedFlows(ctxChanges4)
	assert.Equal(t, 2, getChangedFlowOPCount(dropFlows4, deletion))
	assert.Equal(t, 3, getDenyAllRuleOPCount(matchFlows4, deletion))
	err = c.featureNetworkPolicy.applyConjunctiveMatchFlows(ctxChanges4)
	require.Nil(t, err)

	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID3, 1, 3}})
	ctxChanges5 := conj2.calculateChangesForRuleDeletion()
	matchFlows5, dropFlows5 := getChangedFlows(ctxChanges5)
	assert.Equal(t, 2, getChangedFlowOPCount(dropFlows5, deletion))
	assert.Equal(t, 4, getChangedFlowCount(matchFlows5))
	assert.Equal(t, 3, getChangedFlowOPCount(matchFlows5, deletion))
	assert.Equal(t, 1, getChangedFlowOPCount(matchFlows5, modification))
	err = c.featureNetworkPolicy.applyConjunctiveMatchFlows(ctxChanges5)
	assert.Equal(t, 15, len(c.GetNetworkPolicyFlowKeys("np1", "ns1")))
	require.Nil(t, err)
}

func getChangedFlowCount(flows []*flowChange) int {
	var count int
	for _, changedFlow := range flows {
		if changedFlow.flow != nil {
			count++
		}
	}
	return count
}

func getChangedFlowOPCount(flows []*flowChange, flowOperType changeType) int {
	var count int
	for _, changedFlow := range flows {
		if changedFlow.flow != nil && changedFlow.changeType == flowOperType {
			count++
		}
	}
	return count
}

func getChangedFlows(changes []*conjMatchFlowContextChange) ([]*flowChange, []*flowChange) {
	var matchFlows, dropFlows []*flowChange
	for _, change := range changes {
		if change.matchFlow != nil {
			matchFlows = append(matchFlows, change.matchFlow)
		}
		if change.dropFlow != nil {
			dropFlows = append(dropFlows, change.dropFlow)
		}
	}
	return matchFlows, dropFlows
}

func getDenyAllRuleOPCount(flows []*flowChange, operType changeType) int {
	var count int
	for _, changedFlow := range flows {
		if changedFlow.flow == nil && changedFlow.changeType == operType {
			count++
		}
	}
	return count
}

func checkConjunctionConfig(t *testing.T, ruleID uint32, actionFlowCount, fromMatchCount, toMatchCount, serviceMatchCount int) {
	conj := c.featureNetworkPolicy.getPolicyRuleConjunction(ruleID)
	require.NotNil(t, conj, "Failed to add policyRuleConjunction into client cache")
	assert.Equal(t, actionFlowCount, len(conj.actionFlows), fmt.Sprintf("Incorrect number of conjunction action flows, expect: %d, actual: %d", actionFlowCount, len(conj.actionFlows)))
	if fromMatchCount > 0 {
		assert.Equal(t, fromMatchCount, len(conj.fromClause.matches), fmt.Sprintf("Incorrect number of conjunctive match flows for fromClause, expect: %d, actual: %d", fromMatchCount, len(conj.fromClause.matches)))
	}
	if toMatchCount > 0 {
		assert.Equal(t, toMatchCount, len(conj.toClause.matches), fmt.Sprintf("Incorrect number of conjunctive match flows for toClause, expect: %d, actual: %d", fromMatchCount, len(conj.toClause.matches)))
	}
	if serviceMatchCount > 0 {
		assert.Equal(t, serviceMatchCount, len(conj.serviceClause.matches), fmt.Sprintf("Incorrect number of conjunctive match flows for serviceClause, expect: %d, actual: %d", fromMatchCount, len(conj.serviceClause.matches)))
	}
}

func checkFlowCount(t *testing.T, expectCount int) {
	actualCount := len(c.featureNetworkPolicy.globalConjMatchFlowCache)
	assert.Equal(t, expectCount, actualCount, fmt.Sprintf("Incorrect count of conjunctive match flow context into global cache, expect: %d, actual: %d", expectCount, actualCount))
}

func checkConjMatchFlowActions(t *testing.T, client *client, c *clause, address types.Address, addressType types.AddressType, actionCount int, anyDropRuleCount int) {
	addrMatch := generateAddressConjMatch(c.ruleTable.GetID(), address, addressType, nil)
	context, found := client.featureNetworkPolicy.globalConjMatchFlowCache[addrMatch.generateGlobalMapKey()]
	require.True(t, found, "Failed to add conjunctive match flow to global cache")
	assert.Equal(t, actionCount, len(context.actions), fmt.Sprintf("Incorrect policyRuleConjunction action number, expect: %d, actual: %d", actionCount, len(context.actions)))
	assert.Equal(t, anyDropRuleCount, len(context.denyAllRules), fmt.Sprintf("Incorrect policyRuleConjunction anyDropRule number, expect: %d, actual: %d", anyDropRuleCount, len(context.denyAllRules)))
}

func expectConjunctionsCount(conjs []*expectConjunctionTimes) {
	for _, c := range conjs {
		ruleAction.EXPECT().Conjunction(c.conjID, c.clauseID, c.nClause).Return(ruleFlowBuilder).MaxTimes(c.count)
	}
}

func newMockDropFlowBuilder(ctrl *gomock.Controller, flowTable *mocks.MockTable) *mocks.MockFlowBuilder {
	dropFlowBuilder = mocks.NewMockFlowBuilder(ctrl)
	dropFlowBuilder.EXPECT().Cookie(gomock.Any()).Return(dropFlowBuilder).AnyTimes()
	dropFlowBuilder.EXPECT().MatchProtocol(gomock.Any()).Return(dropFlowBuilder).AnyTimes()
	dropFlowBuilder.EXPECT().MatchDstIPNet(gomock.Any()).Return(dropFlowBuilder).AnyTimes()
	dropFlowBuilder.EXPECT().MatchSrcIPNet(gomock.Any()).Return(dropFlowBuilder).AnyTimes()
	dropFlowBuilder.EXPECT().MatchDstIP(gomock.Any()).Return(dropFlowBuilder).AnyTimes()
	dropFlowBuilder.EXPECT().MatchSrcIP(gomock.Any()).Return(dropFlowBuilder).AnyTimes()
	dropFlowBuilder.EXPECT().MatchInPort(gomock.Any()).Return(dropFlowBuilder).AnyTimes()
	dropFlowBuilder.EXPECT().MatchConjID(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	dropFlowBuilder.EXPECT().MatchPriority(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	action := mocks.NewMockAction(ctrl)
	action.EXPECT().Drop().Return(dropFlowBuilder).AnyTimes()
	dropFlowBuilder.EXPECT().Action().Return(action).AnyTimes()
	dropFlow = mocks.NewMockFlow(ctrl)
	dropFlowBuilder.EXPECT().Done().Return(dropFlow).AnyTimes()
	flowModMessages := []ofctrl.OpenFlowModMessage{
		&ofctrl.FlowBundleMessage{},
	}
	dropFlow.EXPECT().GetBundleMessages(binding.AddMessage).Return(flowModMessages, nil).AnyTimes()
	dropFlow.EXPECT().MatchString().Return("").AnyTimes()
	return dropFlowBuilder
}

func newMockRuleFlowBuilder(ctrl *gomock.Controller, flowTable *mocks.MockTable) *mocks.MockFlowBuilder {
	ruleFlowBuilder = mocks.NewMockFlowBuilder(ctrl)
	ruleFlowBuilder.EXPECT().Cookie(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchProtocol(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchDstIPNet(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchSrcIPNet(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchDstIP(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchSrcIP(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchInPort(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchDstPort(gomock.Any(), gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchConjID(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchPriority(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleAction = mocks.NewMockAction(ctrl)
	ruleCtAction := mocks.NewMockCTAction(ctrl)
	ruleCtAction.EXPECT().LoadToLabelField(gomock.Any(), gomock.Any()).Return(ruleCtAction).AnyTimes()
	ruleCtAction.EXPECT().CTDone().Return(ruleFlowBuilder).AnyTimes()
	ruleAction.EXPECT().CT(true, gomock.Any(), gomock.Any(), nil).Return(ruleCtAction).AnyTimes()
	ruleAction.EXPECT().GotoTable(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleAction.EXPECT().LoadToRegField(gomock.Any(), gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().Action().Return(ruleAction).AnyTimes()
	ruleFlow = mocks.NewMockFlow(ctrl)
	ruleFlowBuilder.EXPECT().Done().Return(ruleFlow).AnyTimes()
	flowModMessages := []ofctrl.OpenFlowModMessage{
		&ofctrl.FlowBundleMessage{},
	}
	ruleFlow.EXPECT().GetBundleMessages(binding.AddMessage).Return(flowModMessages, nil).AnyTimes()
	ruleFlow.EXPECT().MatchString().Return("").AnyTimes()
	return ruleFlowBuilder
}

func newMockMetricFlowBuilder(ctrl *gomock.Controller, flowTable *mocks.MockTable) *mocks.MockFlowBuilder {
	metricFlowBuilder = mocks.NewMockFlowBuilder(ctrl)
	metricFlowBuilder.EXPECT().Cookie(gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricFlowBuilder.EXPECT().MatchProtocol(gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricFlowBuilder.EXPECT().MatchPriority(gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricFlowBuilder.EXPECT().MatchCTStateNew(gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricFlowBuilder.EXPECT().MatchCTLabelField(gomock.Any(), gomock.Any(), gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricAction = mocks.NewMockAction(ctrl)
	metricAction.EXPECT().NextTable().Return(metricFlowBuilder).AnyTimes()
	metricAction.EXPECT().LoadToRegField(gomock.Any(), gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricAction.EXPECT().Drop().Return(metricFlowBuilder).AnyTimes()
	metricFlowBuilder.EXPECT().Action().Return(metricAction).AnyTimes()
	metricFlow = mocks.NewMockFlow(ctrl)
	metricFlowBuilder.EXPECT().Done().Return(metricFlow).AnyTimes()
	flowModMessages := []ofctrl.OpenFlowModMessage{
		&ofctrl.FlowBundleMessage{},
	}
	metricFlow.EXPECT().GetBundleMessages(binding.AddMessage).Return(flowModMessages, nil).AnyTimes()
	metricFlow.EXPECT().MatchString().Return("").AnyTimes()
	return metricFlowBuilder
}

func parseAddresses(addrs []string) []types.Address {
	var addresses = make([]types.Address, 0)
	for _, addr := range addrs {
		if !strings.Contains(addr, ".") && !strings.Contains(addr, ":") {
			ofPort, _ := strconv.ParseInt(addr, 10, 32)
			addresses = append(addresses, NewOFPortAddress(int32(ofPort)))
		} else if strings.Contains(addr, "/") {
			_, ipnet, _ := net.ParseCIDR(addr)
			addresses = append(addresses, NewIPNetAddress(*ipnet))
		} else {
			ip := net.ParseIP(addr)
			addresses = append(addresses, NewIPAddress(ip))
		}
	}
	return addresses
}

func parseLabelIdentityAddresses(labelIdentities []uint32) []types.Address {
	var addresses = make([]types.Address, 0)
	for _, labelIdentity := range labelIdentities {
		addresses = append(addresses, NewLabelIDAddress(labelIdentity))
	}
	return addresses
}

func preparePipelines() {
	pipelineID := pipelineIP
	requiredTablesMap := make(map[*Table]struct{})
	for _, f := range activeFeatures {
		for _, t := range f.getRequiredTables() {
			requiredTablesMap[t] = struct{}{}
		}
	}

	var requiredTables []*Table
	for _, table := range tableOrderCache[pipelineID] {
		if _, ok := requiredTablesMap[table]; ok {
			requiredTables = append(requiredTables, table)
		}
	}
	pipelineMap[pipelineID] = generatePipeline(pipelineID, requiredTables)
	// Set ofctrl.Table with a valid TableID to ensure the OpenFlow Modification messages can be generated successfully
	// in tests.
	for _, obj := range tableCache.List() {
		t := obj.(*Table)
		t.ofTable.SetTable()
	}

	mockFeatureNetworkPolicy.egressTables = map[uint8]struct{}{EgressRuleTable.GetID(): {}, EgressDefaultTable.GetID(): {}}
	if mockFeatureNetworkPolicy.enableAntreaPolicy {
		mockFeatureNetworkPolicy.egressTables[AntreaPolicyEgressRuleTable.GetID()] = struct{}{}
	}
	mockFeatureNetworkPolicy.category = cookie.NetworkPolicy
	mockFeaturePodConnectivity.category = cookie.PodConnectivity
}

func prepareClient(ctrl *gomock.Controller, dualStack bool) *client {
	bridge := mocks.NewMockBridge(ctrl)
	bridge.EXPECT().AddFlowsInBundle(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	ipProtocols := []binding.Protocol{binding.ProtocolIP}
	if dualStack {
		ipProtocols = append(ipProtocols, binding.ProtocolIPv6)
	}
	c = &client{
		bridge:      bridge,
		ipProtocols: ipProtocols,
	}
	c.cookieAllocator = cookie.NewAllocator(0)
	m := opstest.NewMockOFEntryOperations(ctrl)
	m.EXPECT().AddAll(gomock.Any()).Return(nil).AnyTimes()
	m.EXPECT().DeleteAll(gomock.Any()).Return(nil).AnyTimes()
	c.ofEntryOperations = m
	mockFeaturePodConnectivity.cookieAllocator = c.cookieAllocator
	mockFeaturePodConnectivity.ipProtocols = c.ipProtocols
	mockFeatureNetworkPolicy.cookieAllocator = c.cookieAllocator
	mockFeatureNetworkPolicy.ipProtocols = c.ipProtocols
	mockFeatureNetworkPolicy.bridge = c.bridge
	c.featurePodConnectivity = &mockFeaturePodConnectivity
	c.featureNetworkPolicy = &mockFeatureNetworkPolicy
	c.featureNetworkPolicy.deterministic = true
	c.featureNetworkPolicy.policyCache = cache.NewIndexer(policyConjKeyFunc, cache.Indexers{priorityIndex: priorityIndexFunc})
	c.featureNetworkPolicy.globalConjMatchFlowCache = map[string]*conjMatchFlowContext{}
	c.pipelines = pipelineMap

	setMockOFTables(ctrl,
		map[*Table]**mocks.MockTable{
			AntreaPolicyEgressRuleTable: &mockAntreaPolicyEgressRuleTable,
			EgressRuleTable:             &mockEgressRuleTable,
			EgressDefaultTable:          &mockEgressDefaultTable,
			EgressMetricTable:           &mockEgressMetricTable,
			L3ForwardingTable:           &mockL3ForwardingTable,
		},
	)
	return c
}

func TestParseMetricFlow(t *testing.T) {
	for name, tc := range map[string]struct {
		flow   string
		rule   uint32
		metric types.RuleMetric
	}{
		"Drop flow": {
			flow: "table=101, n_packets=9, n_bytes=666, priority=200,reg0=0x100000/0x100000,reg3=0x5 actions=drop",
			rule: 5,
			metric: types.RuleMetric{
				Bytes:    666,
				Packets:  9,
				Sessions: 9,
			},
		},
		"New allow flow": {
			flow: "table=101, n_packets=123, n_bytes=456, priority=200,ct_state=+new,ct_label=0x112345678/0xffffffff00000000,ip actions=goto_table:105",
			rule: 1,
			metric: types.RuleMetric{
				Bytes:    456,
				Packets:  123,
				Sessions: 123,
			},
		},
		"Following allow flow": {
			flow: "table=101, n_packets=123, n_bytes=456, priority=200,ct_state=-new,ct_label=0x1/0xffffffff,ip actions=goto_table:105",
			rule: 1,
			metric: types.RuleMetric{
				Bytes:    456,
				Packets:  123,
				Sessions: 0,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			rule, metric := parseMetricFlow(parseFlowToMap(tc.flow))
			require.Equal(t, tc.rule, rule)
			require.Equal(t, tc.metric.Bytes, metric.Bytes)
			require.Equal(t, tc.metric.Sessions, metric.Sessions)
			require.Equal(t, tc.metric.Packets, metric.Packets)
		})
	}
}

func TestNetworkPolicyMetrics(t *testing.T) {
	tests := []struct {
		name         string
		egressFlows  []string
		ingressFlows []string
		want         map[uint32]*types.RuleMetric
	}{
		{
			name: "Normal flows",
			egressFlows: []string{
				"table=61, n_packets=1, n_bytes=74, priority=200,ct_state=+new,ct_label=0x200000000/0xffffffff00000000,ip actions=goto_table:70",
				"table=61, n_packets=11, n_bytes=1661, priority=200,ct_state=-new,ct_label=0x200000000/0xffffffff00000000,ip actions=goto_table:70",
				"table=61, n_packets=0, n_bytes=0, priority=200,ct_state=+new,ct_label=0x600000000/0xffffffff00000000,ip actions=goto_table:70",
				"table=61, n_packets=0, n_bytes=0, priority=200,ct_state=-new,ct_label=0x600000000/0xffffffff00000000,ip actions=goto_table:70",
				"table=61, n_packets=4, n_bytes=336, priority=200,reg0=0x100000/0x100000,reg3=0x4 actions=drop",
				"table=61, n_packets=0, n_bytes=0, priority=200,reg0=0x100000/0x100000,reg3=0x8 actions=drop",
				"table=61, n_packets=1502362, n_bytes=601635949, priority=0 actions=goto_table:70",
			},
			ingressFlows: []string{
				"table=101, n_packets=1, n_bytes=74, priority=200,ct_state=+new,ct_label=0x1/0xffffffff,ip actions=resubmit(,105)",
				"table=101, n_packets=11, n_bytes=1661, priority=200,ct_state=-new,ct_label=0x1/0xffffffff,ip actions=resubmit(,105)",
				"table=101, n_packets=2, n_bytes=148, priority=200,ct_state=+new,ct_label=0x5/0xffffffff,ip actions=resubmit(,105)",
				"table=101, n_packets=12, n_bytes=943, priority=200,ct_state=-new,ct_label=0x5/0xffffffff,ip actions=resubmit(,105)",
				"table=101, n_packets=0, n_bytes=0, priority=200,reg0=0x100000/0x100000,reg3=0x3 actions=drop",
				"table=101, n_packets=4, n_bytes=338, priority=200,reg0=0x100000/0x100000,reg3=0xb actions=drop",
				"table=101, n_packets=1407190, n_bytes=509746586, priority=0 actions=resubmit(,105)",
			},
			want: map[uint32]*types.RuleMetric{
				2:  {Bytes: 1735, Sessions: 1, Packets: 12},
				6:  {Bytes: 0, Sessions: 0, Packets: 0},
				4:  {Bytes: 336, Sessions: 4, Packets: 4},
				8:  {Bytes: 0, Sessions: 0, Packets: 0},
				1:  {Bytes: 1735, Sessions: 1, Packets: 12},
				5:  {Bytes: 1091, Sessions: 2, Packets: 14},
				3:  {Bytes: 0, Sessions: 0, Packets: 0},
				11: {Bytes: 338, Sessions: 4, Packets: 4},
			},
		},
		{
			name: "Flows with traceflow flows",
			egressFlows: []string{
				"table=61, n_packets=0, n_bytes=0, hard_timeout=300, priority=202,ip,reg0=0x100000/0x100000,reg3=0x4,nw_tos=28 actions=controller(max_len=65535,id=15768)",
				"table=61, n_packets=0, n_bytes=0, hard_timeout=300, priority=202,ip,reg0=0x100000/0x100000,reg3=0x8,nw_tos=28 actions=controller(max_len=65535,id=15768)",
				"table=61, n_packets=1, n_bytes=74, priority=200,ct_state=+new,ct_label=0x200000000/0xffffffff00000000,ip actions=goto_table:70",
				"table=61, n_packets=11, n_bytes=1661, priority=200,ct_state=-new,ct_label=0x200000000/0xffffffff00000000,ip actions=goto_table:70",
				"table=61, n_packets=0, n_bytes=0, priority=200,ct_state=+new,ct_label=0x600000000/0xffffffff00000000,ip actions=goto_table:70",
				"table=61, n_packets=0, n_bytes=0, priority=200,ct_state=-new,ct_label=0x600000000/0xffffffff00000000,ip actions=goto_table:70",
				"table=61, n_packets=4, n_bytes=336, priority=200,reg0=0x100000/0x100000,reg3=0x4 actions=drop",
				"table=61, n_packets=0, n_bytes=0, priority=200,reg0=0x100000/0x100000,reg3=0x8 actions=drop",
				"table=61, n_packets=1502362, n_bytes=601635949, priority=0 actions=goto_table:70",
			},
			ingressFlows: []string{
				"table=101, n_packets=0, n_bytes=0, hard_timeout=300, priority=202,ip,reg0=0x100000/0x100000,reg3=0x3,nw_tos=28 actions=controller(max_len=65535,id=15768)",
				"table=101, n_packets=0, n_bytes=0, hard_timeout=300, priority=202,ip,reg0=0x100000/0x100000,reg3=0xb,nw_tos=28 actions=controller(max_len=65535,id=15768)",
				"table=101, n_packets=1, n_bytes=74, priority=200,ct_state=+new,ct_label=0x1/0xffffffff,ip actions=resubmit(,105)",
				"table=101, n_packets=11, n_bytes=1661, priority=200,ct_state=-new,ct_label=0x1/0xffffffff,ip actions=resubmit(,105)",
				"table=101, n_packets=2, n_bytes=148, priority=200,ct_state=+new,ct_label=0x5/0xffffffff,ip actions=resubmit(,105)",
				"table=101, n_packets=12, n_bytes=943, priority=200,ct_state=-new,ct_label=0x5/0xffffffff,ip actions=resubmit(,105)",
				"table=101, n_packets=0, n_bytes=0, priority=200,reg0=0x100000/0x100000,reg3=0x3 actions=drop",
				"table=101, n_packets=4, n_bytes=338, priority=200,reg0=0x100000/0x100000,reg3=0xb actions=drop",
				"table=101, n_packets=1407190, n_bytes=509746586, priority=0 actions=resubmit(,105)",
			},
			want: map[uint32]*types.RuleMetric{
				2:  {Bytes: 1735, Sessions: 1, Packets: 12},
				6:  {Bytes: 0, Sessions: 0, Packets: 0},
				4:  {Bytes: 336, Sessions: 4, Packets: 4},
				8:  {Bytes: 0, Sessions: 0, Packets: 0},
				1:  {Bytes: 1735, Sessions: 1, Packets: 12},
				5:  {Bytes: 1091, Sessions: 2, Packets: 14},
				3:  {Bytes: 0, Sessions: 0, Packets: 0},
				11: {Bytes: 338, Sessions: 4, Packets: 4},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			preparePipelines()
			defer resetPipelines()
			c = prepareClient(ctrl, false)
			mockOVSClient := ovsctltest.NewMockOVSCtlClient(ctrl)
			c.ovsctlClient = mockOVSClient
			gomock.InOrder(
				mockOVSClient.EXPECT().DumpTableFlows(EgressMetricTable.ofTable.GetID()).Return(tt.egressFlows, nil),
				mockOVSClient.EXPECT().DumpTableFlows(IngressMetricTable.ofTable.GetID()).Return(tt.ingressFlows, nil),
			)
			got := c.NetworkPolicyMetrics()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetMatchFlowUpdates(t *testing.T) {
	ctrl := gomock.NewController(t)
	preparePipelines()
	defer resetPipelines()
	c = prepareClient(ctrl, false)
	c.nodeConfig = &config.NodeConfig{PodIPv4CIDR: podIPv4CIDR, PodIPv6CIDR: nil}
	c.networkConfig = &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap, IPv4Enabled: true}
	c.ipProtocols = []binding.Protocol{binding.ProtocolIP}
	mockEgressDefaultTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockDropFlowBuilder(ctrl, mockEgressDefaultTable)).AnyTimes()
	mockAntreaPolicyEgressRuleTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockRuleFlowBuilder(ctrl, mockAntreaPolicyEgressRuleTable)).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchRegFieldWithValue(gomock.Any(), gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleAction.EXPECT().LoadRegMark(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleAction.EXPECT().Conjunction(gomock.Any(), gomock.Any(), gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleAction.EXPECT().ResubmitToTables(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	mockEgressMetricTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockMetricFlowBuilder(ctrl, mockEgressMetricTable)).AnyTimes()
	metricFlowBuilder.EXPECT().MatchRegMark(gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricFlowBuilder.EXPECT().MatchRegFieldWithValue(gomock.Any(), gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	rules := []*types.PolicyRule{
		{
			Direction: v1beta2.DirectionOut,
			From:      parseAddresses([]string{"192.168.1.40", "192.168.1.50"}),
			Action:    &actionAllow,
			Priority:  &priority100,
			To:        []types.Address{NewOFPortAddress(1), NewOFPortAddress(2)},
			FlowID:    uint32(10),
			TableID:   AntreaPolicyEgressRuleTable.ofTable.GetID(),
			PolicyRef: &v1beta2.NetworkPolicyReference{
				Type:      v1beta2.AntreaNetworkPolicy,
				Namespace: "ns1",
				Name:      "np1",
				UID:       "id1",
			},
		},
		{
			Direction: v1beta2.DirectionOut,
			// conjunctive match flow with priority 100 for nw_src=192.168.1.40 should tie to conjunction 10 and 11 but not 12.
			From:     parseAddresses([]string{"192.168.1.40", "192.168.1.51"}),
			Action:   &actionDrop,
			Priority: &priority100,
			To:       []types.Address{NewOFPortAddress(1), NewOFPortAddress(3)},
			Service:  []v1beta2.Service{{Protocol: &protocolTCP, Port: &port8080}},
			FlowID:   uint32(11),
			TableID:  AntreaPolicyEgressRuleTable.ofTable.GetID(),
			PolicyRef: &v1beta2.NetworkPolicyReference{
				Type:      v1beta2.AntreaNetworkPolicy,
				Namespace: "ns1",
				Name:      "np2",
				UID:       "id2",
			},
		},
		{
			Direction: v1beta2.DirectionOut,
			// conjunctive match flow with priority 200 for nw_src=192.168.1.40 should tie to conjunction 12 only.
			From:     parseAddresses([]string{"192.168.1.40"}),
			Action:   &actionDrop,
			Priority: &priority200,
			To:       []types.Address{NewOFPortAddress(1)},
			Service:  []v1beta2.Service{{Protocol: &protocolTCP, Port: &port8080}},
			FlowID:   uint32(12),
			TableID:  AntreaPolicyEgressRuleTable.ofTable.GetID(),
			PolicyRef: &v1beta2.NetworkPolicyReference{
				Type:      v1beta2.AntreaNetworkPolicy,
				Namespace: "ns1",
				Name:      "np3",
				UID:       "id3",
			},
		},
	}
	err := c.BatchInstallPolicyRuleFlows(rules)
	assert.Nil(t, err)
	updatedPriorities := map[uint16]uint16{
		priority100: 101,
		priority200: 202,
	}
	err = c.ReassignFlowPriorities(updatedPriorities, AntreaPolicyEgressRuleTable.ofTable.GetID())
	assert.Nil(t, err)
}

// setMockOFTables is used to generate mock OF tables.
func setMockOFTables(ctrl *gomock.Controller, tableMap map[*Table]**mocks.MockTable) {
	for table, mockTable := range tableMap {
		t := mocks.NewMockTable(ctrl)
		t.EXPECT().GetID().Return(table.GetID()).AnyTimes()
		t.EXPECT().GetNext().Return(table.GetNext()).AnyTimes()
		t.EXPECT().GetMissAction().Return(table.GetMissAction()).AnyTimes()
		t.EXPECT().GetName().Return("table").AnyTimes()
		tableCache.Update(table)
		*mockTable = t // Update the value with generated mock table.
	}
}

func TestClient_GetPolicyInfoFromConjunction(t *testing.T) {
	ctrl := gomock.NewController(t)
	preparePipelines()
	defer resetPipelines()
	c = prepareClient(ctrl, false)

	ruleID1 := uint32(101)
	ruleID2 := uint32(102)
	npRef := &v1beta2.NetworkPolicyReference{
		Type:      v1beta2.K8sNetworkPolicy,
		Namespace: "ns1",
		Name:      "np1",
		UID:       "id1",
	}
	conj1 := &policyRuleConjunction{
		id:       ruleID1,
		npRef:    npRef,
		ruleName: fmt.Sprint(ruleID1),
	}
	flow := EgressRuleTable.ofTable.BuildFlow(priority100).MatchCTSrcIP(net.ParseIP("1.1.1.10")).Action().Drop().Done()
	msg := getFlowModMessage(flow, binding.AddMessage)
	conj2 := &policyRuleConjunction{
		id:           ruleID2,
		actionFlows:  []*openflow15.FlowMod{msg},
		npRef:        npRef,
		ruleName:     fmt.Sprint(ruleID2),
		ruleLogLabel: "test-log-label",
	}
	c.featureNetworkPolicy.policyCache.Add(conj1)
	c.featureNetworkPolicy.policyCache.Add(conj2)

	tests := []struct {
		name             string
		ruleID           uint32
		valid            bool
		wantNpRef        string
		wantPriority     string
		wantRuleName     string
		wantRuleLogLabel string
	}{
		{
			name:   "conjunction not found",
			ruleID: uint32(100),
			valid:  false,
		},
		{
			name:   "conjunction empty priorities",
			ruleID: ruleID1,
			valid:  false,
		},
		{
			name:             "conjunction no error",
			ruleID:           ruleID2,
			valid:            true,
			wantNpRef:        "K8sNetworkPolicy:ns1/np1",
			wantPriority:     "100",
			wantRuleName:     fmt.Sprint(ruleID2),
			wantRuleLogLabel: "test-log-label",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, gotNpRef, gotPriority, gotRuleName, gotRuleLogLabel := c.GetPolicyInfoFromConjunction(tc.ruleID)
			require.Equal(t, tc.valid, ok)
			if tc.valid {
				assert.Equal(t, tc.wantNpRef, gotNpRef.ToString())
				assert.Equal(t, tc.wantPriority, gotPriority)
				assert.Equal(t, tc.wantRuleName, gotRuleName)
				assert.Equal(t, tc.wantRuleLogLabel, gotRuleLogLabel)
			}
		})
	}
}

func networkPolicyInitFlows(ovsMeterSupported, externalNodeEnabled, l7NetworkPolicyEnabled bool) []string {
	loggingFlows := []string{
		"cookie=0x1020000000000, table=Output, priority=200,reg0=0x2400000/0xfe600000 actions=controller(id=32776,reason=no_match,userdata=01.01,max_len=65535)",
		"cookie=0x1020000000000, table=Output, priority=200,reg0=0x4400000/0xfe600000 actions=controller(id=32776,reason=no_match,userdata=01.02,max_len=65535)",
		"cookie=0x1020000000000, table=Output, priority=200,reg0=0x6400000/0xfe600000 actions=controller(id=32776,reason=no_match,userdata=01.03,max_len=65535)",
		"cookie=0x1020000000000, table=Output, priority=200,reg0=0x8400000/0xfe600000 actions=controller(id=32776,reason=no_match,userdata=01.04,max_len=65535)",
		"cookie=0x1020000000000, table=Output, priority=200,reg0=0xa400000/0xfe600000 actions=controller(id=32776,reason=no_match,userdata=01.05,max_len=65535)",
		"cookie=0x1020000000000, table=Output, priority=200,reg0=0xc400000/0xfe600000 actions=controller(id=32776,reason=no_match,userdata=01.06,max_len=65535)",
		"cookie=0x1020000000000, table=Output, priority=200,reg0=0xe400000/0xfe600000 actions=controller(id=32776,reason=no_match,userdata=01.07,max_len=65535)",
	}
	if ovsMeterSupported {
		loggingFlows = []string{
			"cookie=0x1020000000000, table=Output, priority=200,reg0=0x2400000/0xfe600000 actions=meter:256,controller(id=32776,reason=no_match,userdata=01.01,max_len=65535)",
			"cookie=0x1020000000000, table=Output, priority=200,reg0=0x4400000/0xfe600000 actions=meter:256,controller(id=32776,reason=no_match,userdata=01.02,max_len=65535)",
			"cookie=0x1020000000000, table=Output, priority=200,reg0=0x6400000/0xfe600000 actions=meter:256,controller(id=32776,reason=no_match,userdata=01.03,max_len=65535)",
			"cookie=0x1020000000000, table=Output, priority=200,reg0=0x8400000/0xfe600000 actions=meter:256,controller(id=32776,reason=no_match,userdata=01.04,max_len=65535)",
			"cookie=0x1020000000000, table=Output, priority=200,reg0=0xa400000/0xfe600000 actions=meter:256,controller(id=32776,reason=no_match,userdata=01.05,max_len=65535)",
			"cookie=0x1020000000000, table=Output, priority=200,reg0=0xc400000/0xfe600000 actions=meter:256,controller(id=32776,reason=no_match,userdata=01.06,max_len=65535)",
			"cookie=0x1020000000000, table=Output, priority=200,reg0=0xe400000/0xfe600000 actions=meter:256,controller(id=32776,reason=no_match,userdata=01.07,max_len=65535)",
		}
	}
	if externalNodeEnabled {
		return append(loggingFlows,
			"cookie=0x1020000000000, table=AntreaPolicyEgressRule, priority=64990,ct_state=-new+est,ip actions=goto_table:EgressMetric",
			"cookie=0x1020000000000, table=AntreaPolicyEgressRule, priority=64990,ct_state=-new+rel,ip actions=goto_table:EgressMetric",
			"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64990,ct_state=-new+est,ip actions=goto_table:IngressMetric",
			"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64990,ct_state=-new+rel,ip actions=goto_table:IngressMetric",
		)
	}
	initFlows := append(loggingFlows,
		"cookie=0x1020000000000, table=IngressSecurityClassifier, priority=200,reg0=0x20/0xf0 actions=goto_table:IngressMetric",
		"cookie=0x1020000000000, table=IngressSecurityClassifier, priority=200,reg0=0x10/0xf0 actions=goto_table:IngressMetric",
		"cookie=0x1020000000000, table=IngressSecurityClassifier, priority=200,reg0=0x40/0xf0 actions=goto_table:IngressMetric",
		"cookie=0x1020000000000, table=IngressSecurityClassifier, priority=200,ct_mark=0x40/0x40 actions=goto_table:ConntrackCommit",
		"cookie=0x1020000000000, table=AntreaPolicyEgressRule, priority=64990,ct_state=-new+est,ip actions=goto_table:EgressMetric",
		"cookie=0x1020000000000, table=AntreaPolicyEgressRule, priority=64990,ct_state=-new+rel,ip actions=goto_table:EgressMetric",
		"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64990,ct_state=-new+est,ip actions=goto_table:IngressMetric",
		"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64990,ct_state=-new+rel,ip actions=goto_table:IngressMetric",
	)
	if l7NetworkPolicyEnabled {
		initFlows = append(initFlows,
			"cookie=0x1020000000000, table=Classifier, priority=200,in_port=11,vlan_tci=0x1000/0x1000 actions=pop_vlan,set_field:0x6/0xf->reg0,goto_table:L3Forwarding",
			"cookie=0x1020000000000, table=TrafficControl, priority=210,reg0=0x200006/0x60000f actions=goto_table:Output",
			"cookie=0x1020000000000, table=Output, priority=212,ct_mark=0x80/0x80,reg0=0x200000/0x600000 actions=push_vlan:0x8100,move:NXM_NX_CT_LABEL[64..75]->OXM_OF_VLAN_VID[0..11],output:10",
		)
	}
	return initFlows
}

func Test_featureNetworkPolicy_initFlows(t *testing.T) {
	runTests := func(t *testing.T, ovsMetersSupported bool) {
		testCases := []struct {
			name          string
			nodeType      config.NodeType
			clientOptions []clientOptionsFn
			expectedFlows []string
		}{
			{
				name:          "K8s Node with Multicast and L7NetworkPolicy",
				nodeType:      config.K8sNode,
				clientOptions: []clientOptionsFn{enableMulticast, enableL7NetworkPolicy},
				expectedFlows: networkPolicyInitFlows(ovsMetersSupported, false, true),
			},
			{
				name:          "K8s Node with Multicast",
				nodeType:      config.K8sNode,
				clientOptions: []clientOptionsFn{enableMulticast},
				expectedFlows: networkPolicyInitFlows(ovsMetersSupported, false, false),
			},
			{
				name:          "External Node",
				nodeType:      config.ExternalNode,
				expectedFlows: networkPolicyInitFlows(ovsMetersSupported, true, false),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				options := append(tc.clientOptions, setEnableOVSMeters(ovsMetersSupported))
				fc := newFakeClient(nil, true, false, tc.nodeType, config.TrafficEncapModeEncap, options...)
				defer resetPipelines()

				assert.ElementsMatch(t, tc.expectedFlows, getFlowStrings(fc.featureNetworkPolicy.initFlows()))
			})
		}
	}

	t.Run("With OVS meters", func(t *testing.T) { runTests(t, true) })
	t.Run("Without OVS meters", func(t *testing.T) { runTests(t, false) })
}

func Test_NewDNSPacketInConjunction(t *testing.T) {
	ipv4ExpFlows := func(ovsMetersSupported bool) []string {
		if ovsMetersSupported {
			return []string{
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,conj_id=1 actions=meter:258,controller(id=32776,reason=no_match,userdata=02,max_len=65535),goto_table:IngressMetric",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,ct_state=+rpl+trk,udp,tp_src=53 actions=conjunction(1,1/2)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,ct_state=+rpl+trk,tcp,tp_src=53 actions=conjunction(1,1/2)",
			}
		} else {
			return []string{
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,conj_id=1 actions=controller(id=32776,reason=no_match,userdata=02,max_len=65535),goto_table:IngressMetric",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,ct_state=+rpl+trk,udp,tp_src=53 actions=conjunction(1,1/2)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,ct_state=+rpl+trk,tcp,tp_src=53 actions=conjunction(1,1/2)",
			}
		}
	}

	ipv6ExpFlows := func(ovsMetersSupported bool) []string {
		if ovsMetersSupported {
			return []string{
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,conj_id=1 actions=meter:258,controller(id=32776,reason=no_match,userdata=02,max_len=65535),goto_table:IngressMetric",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,ct_state=+rpl+trk,udp6,tp_src=53 actions=conjunction(1,1/2)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,ct_state=+rpl+trk,tcp6,tp_src=53 actions=conjunction(1,1/2)",
			}
		} else {
			return []string{
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,conj_id=1 actions=controller(id=32776,reason=no_match,userdata=02,max_len=65535),goto_table:IngressMetric",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,ct_state=+rpl+trk,udp6,tp_src=53 actions=conjunction(1,1/2)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,ct_state=+rpl+trk,tcp6,tp_src=53 actions=conjunction(1,1/2)",
			}
		}
	}

	dsExpFlows := func(ovsMetersSupported bool) []string {
		if ovsMetersSupported {
			return []string{
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,conj_id=1 actions=meter:258,controller(id=32776,reason=no_match,userdata=02,max_len=65535),goto_table:IngressMetric",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,ct_state=+rpl+trk,udp,tp_src=53 actions=conjunction(1,1/2)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,ct_state=+rpl+trk,tcp,tp_src=53 actions=conjunction(1,1/2)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,ct_state=+rpl+trk,udp6,tp_src=53 actions=conjunction(1,1/2)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,ct_state=+rpl+trk,tcp6,tp_src=53 actions=conjunction(1,1/2)",
			}
		} else {
			return []string{
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,conj_id=1 actions=controller(id=32776,reason=no_match,userdata=02,max_len=65535),goto_table:IngressMetric",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,ct_state=+rpl+trk,udp,tp_src=53 actions=conjunction(1,1/2)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,ct_state=+rpl+trk,tcp,tp_src=53 actions=conjunction(1,1/2)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,ct_state=+rpl+trk,udp6,tp_src=53 actions=conjunction(1,1/2)",
				"cookie=0x1020000000000, table=AntreaPolicyIngressRule, priority=64991,ct_state=+rpl+trk,tcp6,tp_src=53 actions=conjunction(1,1/2)",
			}
		}
	}

	runTests := func(t *testing.T, ovsMetersSupported bool) {
		for _, tc := range []struct {
			name          string
			enableIPv4    bool
			enableIPv6    bool
			conjID        uint32
			expectedFlows []string
		}{
			{
				name:          "IPv4 only",
				enableIPv4:    true,
				enableIPv6:    false,
				conjID:        1,
				expectedFlows: ipv4ExpFlows(ovsMetersSupported),
			},
			{
				name:          "IPv6 only",
				enableIPv4:    false,
				enableIPv6:    true,
				conjID:        1,
				expectedFlows: ipv6ExpFlows(ovsMetersSupported),
			},
			{
				name:          "dual stack",
				enableIPv4:    true,
				enableIPv6:    true,
				conjID:        1,
				expectedFlows: dsExpFlows(ovsMetersSupported),
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ctrl := gomock.NewController(t)
				m := opstest.NewMockOFEntryOperations(ctrl)
				bridge := mocks.NewMockBridge(ctrl)
				fc := newFakeClient(m, tc.enableIPv4, tc.enableIPv6, config.K8sNode, config.TrafficEncapModeEncap, setEnableOVSMeters(ovsMetersSupported))
				defer resetPipelines()
				fc.featureNetworkPolicy.bridge = bridge
				actualFlows := make([]string, 0)
				m.EXPECT().AddAll(gomock.Any()).Do(func(flowMessages []*openflow15.FlowMod) {
					flowStrings := getFlowStrings(flowMessages)
					actualFlows = append(actualFlows, flowStrings...)
				}).Return(nil).AnyTimes()
				bridge.EXPECT().AddFlowsInBundle(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(addflows, modFlows, delFlows []*openflow15.FlowMod) {
					flowStrings := getFlowStrings(addflows)
					actualFlows = append(actualFlows, flowStrings...)
				}).Return(nil).Times(1)
				err := fc.NewDNSPacketInConjunction(tc.conjID)
				assert.NoError(t, err)
				assert.ElementsMatch(t, tc.expectedFlows, actualFlows)
			})
		}
	}

	t.Run("With OVS meters", func(t *testing.T) { runTests(t, true) })
	t.Run("Without OVS meters", func(t *testing.T) { runTests(t, false) })
}
