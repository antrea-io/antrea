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
	"strconv"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	oftest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	mocks "antrea.io/antrea/pkg/ovs/openflow/testing"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsctltest "antrea.io/antrea/pkg/ovs/ovsctl/testing"
	"antrea.io/antrea/pkg/util/ip"
)

var (
	c             *client
	cnpOutTable   *mocks.MockTable
	outTable      *mocks.MockTable
	outDropTable  *mocks.MockTable
	outAllowTable *mocks.MockTable
	metricTable   *mocks.MockTable

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

	actionAllow = crdv1alpha1.RuleActionAllow
	actionDrop  = crdv1alpha1.RuleActionDrop
	port8080    = intstr.FromInt(8080)
	protocolTCP = v1beta2.ProtocolTCP
	priority100 = uint16(100)
	priority200 = uint16(200)
)

type expectConjunctionTimes struct {
	count    int
	conjID   uint32
	clauseID uint8
	nClause  uint8
}

func TestPolicyRuleConjunction(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c = prepareClient(ctrl)
	ruleID1 := uint32(1001)
	conj1 := &policyRuleConjunction{
		id: ruleID1,
	}
	clauseID := uint8(1)
	nClause := uint8(3)
	clause1 := conj1.newClause(clauseID, nClause, outTable, outDropTable)

	outDropTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockDropFlowBuilder(ctrl)).AnyTimes()
	outTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockRuleFlowBuilder(ctrl)).AnyTimes()
	metricTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockMetricFlowBuilder(ctrl)).AnyTimes()

	var addedAddrs = parseAddresses([]string{"192.168.1.3", "192.168.1.30", "192.168.2.0/24", "103", "104"})
	expectConjunctionsCount([]*expectConjunctionTimes{{5, ruleID1, clauseID, nClause}})
	flowChanges1 := clause1.addAddrFlows(c, types.SrcAddress, addedAddrs, nil)
	err := c.applyConjunctiveMatchFlows(flowChanges1)
	require.Nil(t, err, "Failed to invoke addAddrFlows")
	checkFlowCount(t, len(addedAddrs))
	for _, addr := range addedAddrs {
		checkConjMatchFlowActions(t, c, clause1, addr, types.SrcAddress, 1, 0)
	}
	var currentFlowCount = len(c.globalConjMatchFlowCache)

	var deletedAddrs = parseAddresses([]string{"192.168.1.3", "103"})
	flowChanges2 := clause1.deleteAddrFlows(types.SrcAddress, deletedAddrs, nil)
	err = c.applyConjunctiveMatchFlows(flowChanges2)
	require.Nil(t, err, "Failed to invoke deleteAddrFlows")
	checkFlowCount(t, currentFlowCount-len(deletedAddrs))
	currentFlowCount = len(c.globalConjMatchFlowCache)

	ruleID2 := uint32(1002)
	conj2 := &policyRuleConjunction{
		id: ruleID2,
	}
	clauseID2 := uint8(2)
	clause2 := conj2.newClause(clauseID2, nClause, outTable, outDropTable)
	var addedAddrs2 = parseAddresses([]string{"192.168.1.30", "192.168.1.50"})
	expectConjunctionsCount([]*expectConjunctionTimes{{2, ruleID2, clauseID2, nClause}})
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID1, clauseID, nClause}})
	flowChanges3 := clause2.addAddrFlows(c, types.SrcAddress, addedAddrs2, nil)
	err = c.applyConjunctiveMatchFlows(flowChanges3)
	require.Nil(t, err, "Failed to invoke addAddrFlows")
	testAddr := NewIPAddress(net.ParseIP("192.168.1.30"))
	checkConjMatchFlowActions(t, c, clause2, testAddr, types.SrcAddress, 2, 0)
	checkFlowCount(t, currentFlowCount+1)
	currentFlowCount = len(c.globalConjMatchFlowCache)

	ruleID3 := uint32(1003)
	conj3 := &policyRuleConjunction{
		id: ruleID3,
	}
	clauseID3 := uint8(1)
	nClause3 := uint8(1)
	clause3 := conj3.newClause(clauseID3, nClause3, outTable, outDropTable)
	var addedAddrs3 = parseAddresses([]string{"192.168.1.30"})
	flowChanges4 := clause3.addAddrFlows(c, types.SrcAddress, addedAddrs3, nil)
	err = c.applyConjunctiveMatchFlows(flowChanges4)
	require.Nil(t, err, "Failed to invoke addAddrFlows")
	checkConjMatchFlowActions(t, c, clause3, testAddr, types.SrcAddress, 2, 1)
	checkFlowCount(t, currentFlowCount)
	flowChanges5 := clause3.deleteAddrFlows(types.SrcAddress, addedAddrs3, nil)
	err = c.applyConjunctiveMatchFlows(flowChanges5)
	require.Nil(t, err, "Failed to invoke deleteAddrFlows")
	checkConjMatchFlowActions(t, c, clause3, testAddr, types.SrcAddress, 2, 0)
	checkFlowCount(t, currentFlowCount)
}

func TestInstallPolicyRuleFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c = prepareClient(ctrl)
	c.nodeConfig = &config.NodeConfig{PodIPv4CIDR: podIPv4CIDR, PodIPv6CIDR: nil}
	c.ipProtocols = []binding.Protocol{binding.ProtocolIP}
	defaultAction := crdv1alpha1.RuleActionAllow
	ruleID1 := uint32(101)
	rule1 := &types.PolicyRule{
		Direction: v1beta2.DirectionOut,
		From:      parseAddresses([]string{"192.168.1.30", "192.168.1.50"}),
		Action:    &defaultAction,
		Priority:  nil,
		FlowID:    ruleID1,
		TableID:   EgressRuleTable,
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "id1",
		},
	}

	outDropTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockDropFlowBuilder(ctrl)).AnyTimes()
	outTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockRuleFlowBuilder(ctrl)).AnyTimes()
	metricTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockMetricFlowBuilder(ctrl)).AnyTimes()

	conj := &policyRuleConjunction{id: ruleID1}
	conj.calculateClauses(rule1, c)
	require.Nil(t, conj.toClause)
	require.Nil(t, conj.serviceClause)
	ctxChanges := conj.calculateChangesForRuleCreation(c, rule1)
	assert.Equal(t, len(rule1.From), len(ctxChanges))
	matchFlows, dropFlows := getChangedFlows(ctxChanges)
	assert.Equal(t, len(rule1.From), getChangedFlowCount(dropFlows))
	assert.Equal(t, 0, getChangedFlowCount(matchFlows))
	assert.Equal(t, 2, getDenyAllRuleOPCount(matchFlows, insertion))
	err := c.applyConjunctiveMatchFlows(ctxChanges)
	require.Nil(t, err)

	ruleID2 := uint32(102)
	rule2 := &types.PolicyRule{
		Direction: v1beta2.DirectionOut,
		From:      parseAddresses([]string{"192.168.1.40", "192.168.1.50"}),
		Action:    &defaultAction,
		To:        parseAddresses([]string{"0.0.0.0/0"}),
		FlowID:    ruleID2,
		TableID:   EgressRuleTable,
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "id1",
		},
	}
	conj2 := &policyRuleConjunction{id: ruleID2}
	conj2.calculateClauses(rule2, c)
	require.NotNil(t, conj2.toClause)
	require.Nil(t, conj2.serviceClause)
	ruleFlowBuilder.EXPECT().MatchConjID(ruleID2).MaxTimes(1)
	ruleFlowBuilder.EXPECT().MatchPriority(priorityLow).MaxTimes(1)
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID2, 2, 2}})
	expectConjunctionsCount([]*expectConjunctionTimes{{2, ruleID2, 1, 2}})
	ctxChanges2 := conj2.calculateChangesForRuleCreation(c, rule2)
	matchFlows2, dropFlows2 := getChangedFlows(ctxChanges2)
	assert.Equal(t, 1, getChangedFlowCount(dropFlows2))
	assert.Equal(t, 3, getChangedFlowCount(matchFlows2))
	assert.Equal(t, 3, getChangedFlowOPCount(matchFlows2, insertion))
	err = c.applyConjunctiveMatchFlows(ctxChanges2)
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
	tcpProtocol := v1beta2.ProtocolTCP
	npPort1 := v1beta2.Service{Protocol: &tcpProtocol, Port: &port1}
	npPort2 := v1beta2.Service{Protocol: &tcpProtocol, Port: &port2, EndPort: &port3}
	rule3 := &types.PolicyRule{
		Direction: v1beta2.DirectionOut,
		From:      parseAddresses([]string{"192.168.1.40", "192.168.1.60"}),
		To:        parseAddresses([]string{"192.168.2.0/24"}),
		Action:    &defaultAction,
		Service:   []v1beta2.Service{npPort1, npPort2},
		FlowID:    ruleID3,
		TableID:   EgressRuleTable,
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "id1",
		},
	}
	conj3 := &policyRuleConjunction{id: ruleID3}
	conj3.calculateClauses(rule3, c)
	ruleFlowBuilder.EXPECT().MatchConjID(ruleID3).MaxTimes(3)
	ruleFlowBuilder.EXPECT().MatchPriority(priorityLow).MaxTimes(3)
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID2, 1, 2}})
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID3, 2, 3}})
	expectConjunctionsCount([]*expectConjunctionTimes{{2, ruleID3, 1, 3}})
	expectConjunctionsCount([]*expectConjunctionTimes{{2, ruleID3, 3, 3}})
	ctxChanges3 := conj3.calculateChangesForRuleCreation(c, rule3)
	matchFlows3, dropFlows3 := getChangedFlows(ctxChanges3)
	assert.Equal(t, 1, getChangedFlowOPCount(dropFlows3, insertion))
	assert.Equal(t, 5, getChangedFlowCount(matchFlows3))
	assert.Equal(t, 4, getChangedFlowOPCount(matchFlows3, insertion))
	assert.Equal(t, 1, getChangedFlowOPCount(matchFlows3, modification))
	err = c.applyConjunctiveMatchFlows(ctxChanges3)
	require.Nil(t, err)

	err = c.InstallPolicyRuleFlows(rule3)
	require.Nil(t, err, "Failed to invoke InstallPolicyRuleFlows")
	checkConjunctionConfig(t, ruleID3, 1, 2, 1, 2)
	assert.Equal(t, 14, len(c.GetNetworkPolicyFlowKeys("np1", "ns1")))

	ctxChanges4 := conj.calculateChangesForRuleDeletion()
	matchFlows4, dropFlows4 := getChangedFlows(ctxChanges4)
	assert.Equal(t, 1, getChangedFlowOPCount(dropFlows4, deletion))
	assert.Equal(t, 2, getDenyAllRuleOPCount(matchFlows4, deletion))
	err = c.applyConjunctiveMatchFlows(ctxChanges4)
	require.Nil(t, err)

	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID3, 1, 3}})
	ctxChanges5 := conj2.calculateChangesForRuleDeletion()
	matchFlows5, dropFlows5 := getChangedFlows(ctxChanges5)
	assert.Equal(t, 1, getChangedFlowOPCount(dropFlows5, deletion))
	assert.Equal(t, 3, getChangedFlowCount(matchFlows5))
	assert.Equal(t, 2, getChangedFlowOPCount(matchFlows5, deletion))
	assert.Equal(t, 1, getChangedFlowOPCount(matchFlows5, modification))
	err = c.applyConjunctiveMatchFlows(ctxChanges5)
	assert.Equal(t, 11, len(c.GetNetworkPolicyFlowKeys("np1", "ns1")))
	require.Nil(t, err)
}

func TestBatchInstallPolicyRuleFlows(t *testing.T) {
	tests := []struct {
		name            string
		rules           []*types.PolicyRule
		expectedFlowsFn func(c *client) []binding.Flow
	}{
		{
			name: "multiple K8s NetworkPolicy rules",
			rules: []*types.PolicyRule{
				{
					Direction: v1beta2.DirectionOut,
					From:      parseAddresses([]string{"192.168.1.40", "192.168.1.50"}),
					To:        parseAddresses([]string{"0.0.0.0/0"}),
					FlowID:    uint32(10),
					TableID:   EgressRuleTable,
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
					TableID: EgressRuleTable,
					PolicyRef: &v1beta2.NetworkPolicyReference{
						Type:      v1beta2.K8sNetworkPolicy,
						Namespace: "ns1",
						Name:      "np2",
						UID:       "id2",
					},
				},
			},
			expectedFlowsFn: func(c *client) []binding.Flow {
				cookiePolicy := c.cookieAllocator.Request(cookie.Policy).Raw()
				cookieDefault := c.cookieAllocator.Request(cookie.Default).Raw()
				return []binding.Flow{
					c.pipeline[EgressRuleTable].BuildFlow(priorityLow).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchConjID(10).
						Action().LoadToRegField(TFEgressConjIDField, 10).
						Action().CT(true, EgressMetricTable, CtZone).LoadToLabelField(10, EgressRuleCTLabel).CTDone().Done(),
					c.pipeline[EgressRuleTable].BuildFlow(priorityLow).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchConjID(11).
						Action().LoadToRegField(TFEgressConjIDField, 11).
						Action().CT(true, EgressMetricTable, CtZone).LoadToLabelField(11, EgressRuleCTLabel).CTDone().Done(),
					c.pipeline[EgressRuleTable].BuildFlow(priorityNormal).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchSrcIP(net.ParseIP("192.168.1.40")).
						Action().Conjunction(10, 1, 2).
						Action().Conjunction(11, 1, 3).Done(),
					c.pipeline[EgressRuleTable].BuildFlow(priorityNormal).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchSrcIP(net.ParseIP("192.168.1.50")).
						Action().Conjunction(10, 1, 2).Done(),
					c.pipeline[EgressRuleTable].BuildFlow(priorityNormal).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchSrcIP(net.ParseIP("192.168.1.51")).
						Action().Conjunction(11, 1, 3).Done(),
					c.pipeline[EgressRuleTable].BuildFlow(priorityNormal).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchDstIPNet(*ip.MustParseCIDR("0.0.0.0/0")).
						Action().Conjunction(10, 2, 2).
						Action().Conjunction(11, 2, 3).Done(),
					c.pipeline[EgressRuleTable].BuildFlow(priorityNormal).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolTCP).MatchDstPort(8080, nil).
						Action().Conjunction(11, 3, 3).Done(),
					c.pipeline[EgressDefaultTable].BuildFlow(priorityNormal).Cookie(cookieDefault).
						MatchProtocol(binding.ProtocolIP).MatchSrcIP(net.ParseIP("192.168.1.40")).
						Action().Drop().Done(),
					c.pipeline[EgressDefaultTable].BuildFlow(priorityNormal).Cookie(cookieDefault).
						MatchProtocol(binding.ProtocolIP).MatchSrcIP(net.ParseIP("192.168.1.50")).
						Action().Drop().Done(),
					c.pipeline[EgressDefaultTable].BuildFlow(priorityNormal).Cookie(cookieDefault).
						MatchProtocol(binding.ProtocolIP).MatchSrcIP(net.ParseIP("192.168.1.51")).
						Action().Drop().Done(),
					c.pipeline[EgressMetricTable].BuildFlow(priorityNormal).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchCTStateNew(true).MatchCTLabelField(0, uint64(10)<<32, EgressRuleCTLabel).
						Action().GotoTable(l3ForwardingTable).Done(),
					c.pipeline[EgressMetricTable].BuildFlow(priorityNormal).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchCTStateNew(false).MatchCTLabelField(0, uint64(10)<<32, EgressRuleCTLabel).
						Action().GotoTable(l3ForwardingTable).Done(),
					c.pipeline[EgressMetricTable].BuildFlow(priorityNormal).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchCTStateNew(true).MatchCTLabelField(0, uint64(11)<<32, EgressRuleCTLabel).
						Action().GotoTable(l3ForwardingTable).Done(),
					c.pipeline[EgressMetricTable].BuildFlow(priorityNormal).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchCTStateNew(false).MatchCTLabelField(0, uint64(11)<<32, EgressRuleCTLabel).
						Action().GotoTable(l3ForwardingTable).Done(),
				}
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
					TableID:   AntreaPolicyIngressRuleTable,
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
					TableID:  AntreaPolicyIngressRuleTable,
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
					Service:  []v1beta2.Service{{Protocol: &protocolTCP, Port: &port8080}},
					FlowID:   uint32(12),
					TableID:  AntreaPolicyIngressRuleTable,
					PolicyRef: &v1beta2.NetworkPolicyReference{
						Type:      v1beta2.AntreaNetworkPolicy,
						Namespace: "ns1",
						Name:      "np3",
						UID:       "id3",
					},
				},
			},
			expectedFlowsFn: func(c *client) []binding.Flow {
				cookiePolicy := c.cookieAllocator.Request(cookie.Policy).Raw()
				return []binding.Flow{
					c.pipeline[AntreaPolicyIngressRuleTable].BuildFlow(priority100).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchConjID(10).
						Action().LoadToRegField(TFIngressConjIDField, 10).
						Action().CT(true, IngressMetricTable, CtZone).LoadToLabelField(10, IngressRuleCTLabel).CTDone().Done(),
					c.pipeline[AntreaPolicyIngressRuleTable].BuildFlow(priority100).Cookie(cookiePolicy).
						MatchConjID(11).
						Action().LoadToRegField(CNPDenyConjIDField, 11).
						Action().LoadRegMark(CnpDenyRegMark).
						Action().GotoTable(IngressMetricTable).Done(),
					c.pipeline[AntreaPolicyIngressRuleTable].BuildFlow(priority200).Cookie(cookiePolicy).
						MatchConjID(12).
						Action().LoadToRegField(CNPDenyConjIDField, 12).
						Action().LoadRegMark(CnpDenyRegMark).
						Action().GotoTable(IngressMetricTable).Done(),
					c.pipeline[AntreaPolicyIngressRuleTable].BuildFlow(priority100).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchSrcIP(net.ParseIP("192.168.1.40")).
						Action().Conjunction(10, 1, 2).
						Action().Conjunction(11, 1, 3).Done(),
					c.pipeline[AntreaPolicyIngressRuleTable].BuildFlow(priority200).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchSrcIP(net.ParseIP("192.168.1.40")).
						Action().Conjunction(12, 1, 3).Done(),
					c.pipeline[AntreaPolicyIngressRuleTable].BuildFlow(priority100).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchSrcIP(net.ParseIP("192.168.1.50")).
						Action().Conjunction(10, 1, 2).Done(),
					c.pipeline[AntreaPolicyIngressRuleTable].BuildFlow(priority100).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchSrcIP(net.ParseIP("192.168.1.51")).
						Action().Conjunction(11, 1, 3).Done(),
					c.pipeline[AntreaPolicyIngressRuleTable].BuildFlow(priority100).Cookie(cookiePolicy).
						MatchRegFieldWithValue(TargetOFPortField, uint32(1)).
						Action().Conjunction(10, 2, 2).
						Action().Conjunction(11, 2, 3).Done(),
					c.pipeline[AntreaPolicyIngressRuleTable].BuildFlow(priority200).Cookie(cookiePolicy).
						MatchRegFieldWithValue(TargetOFPortField, uint32(1)).
						Action().Conjunction(12, 2, 3).Done(),
					c.pipeline[AntreaPolicyIngressRuleTable].BuildFlow(priority100).Cookie(cookiePolicy).
						MatchRegFieldWithValue(TargetOFPortField, uint32(2)).
						Action().Conjunction(10, 2, 2).Done(),
					c.pipeline[AntreaPolicyIngressRuleTable].BuildFlow(priority100).Cookie(cookiePolicy).
						MatchRegFieldWithValue(TargetOFPortField, uint32(3)).
						Action().Conjunction(11, 2, 3).Done(),
					c.pipeline[AntreaPolicyIngressRuleTable].BuildFlow(priority100).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolTCP).MatchDstPort(8080, nil).
						Action().Conjunction(11, 3, 3).Done(),
					c.pipeline[AntreaPolicyIngressRuleTable].BuildFlow(priority200).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolTCP).MatchDstPort(8080, nil).
						Action().Conjunction(12, 3, 3).Done(),
					c.pipeline[IngressMetricTable].BuildFlow(priorityNormal).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchCTStateNew(true).MatchCTLabelField(0, 10, IngressRuleCTLabel).
						Action().GotoTable(conntrackCommitTable).Done(),
					c.pipeline[IngressMetricTable].BuildFlow(priorityNormal).Cookie(cookiePolicy).
						MatchProtocol(binding.ProtocolIP).MatchCTStateNew(false).MatchCTLabelField(0, 10, IngressRuleCTLabel).
						Action().GotoTable(conntrackCommitTable).Done(),
					c.pipeline[IngressMetricTable].BuildFlow(priorityNormal).Cookie(cookiePolicy).
						MatchRegMark(CnpDenyRegMark).MatchRegFieldWithValue(CNPDenyConjIDField, 11).
						Action().Drop().Done(),
					c.pipeline[IngressMetricTable].BuildFlow(priorityNormal).Cookie(cookiePolicy).
						MatchRegMark(CnpDenyRegMark).MatchRegFieldWithValue(CNPDenyConjIDField, 12).
						Action().Drop().Done(),
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockOperations := oftest.NewMockOFEntryOperations(ctrl)
			ofClient := NewClient(bridgeName, bridgeMgmtAddr, ovsconfig.OVSDatapathSystem, false, true, false, false)
			c = ofClient.(*client)
			c.cookieAllocator = cookie.NewAllocator(0)
			c.ofEntryOperations = mockOperations
			c.nodeConfig = &config.NodeConfig{PodIPv4CIDR: podIPv4CIDR, PodIPv6CIDR: nil}
			c.ipProtocols = []binding.Protocol{binding.ProtocolIP}
			c.deterministic = true

			expectedFlows := tt.expectedFlowsFn(c)
			// For better readability when debugging failure.
			eq := gomock.GotFormatterAdapter(
				gomock.GotFormatterFunc(
					func(i interface{}) string {
						return dumpFlows(i.([]binding.Flow))
					}),
				gomock.WantFormatter(
					gomock.StringerFunc(func() string { return dumpFlows(expectedFlows) }),
					gomock.InAnyOrder(expectedFlows),
				),
			)
			mockOperations.EXPECT().AddAll(eq).Return(nil).Times(1)
			err := c.BatchInstallPolicyRuleFlows(tt.rules)
			require.Nil(t, err)
		})
	}
}

func dumpFlows(flows []binding.Flow) string {
	lines := []string{}
	lines = append(lines, "[")
	for _, flow := range flows {
		lines = append(lines, fmt.Sprintf("%s", flow))
	}
	lines = append(lines, "]")
	return strings.Join(lines, "\n")
}

func BenchmarkBatchInstallPolicyRuleFlows(b *testing.B) {
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
			TableID:   AntreaPolicyIngressRuleTable,
			PolicyRef: &v1beta2.NetworkPolicyReference{
				Type:      v1beta2.AntreaNetworkPolicy,
				Namespace: "ns1",
				Name:      fmt.Sprintf("np%d", i),
				UID:       k8stypes.UID(fmt.Sprintf("id%d", i)),
			},
		})
	}
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()
	mockOperations := oftest.NewMockOFEntryOperations(ctrl)
	ofClient := NewClient(bridgeName, bridgeMgmtAddr, ovsconfig.OVSDatapathSystem, false, true, false, false)
	c = ofClient.(*client)
	c.cookieAllocator = cookie.NewAllocator(0)
	c.ofEntryOperations = mockOperations
	c.nodeConfig = &config.NodeConfig{PodIPv4CIDR: podIPv4CIDR, PodIPv6CIDR: nil}
	c.ipProtocols = []binding.Protocol{binding.ProtocolIP}
	// Make it return error so no change gets committed to cache.
	mockOperations.EXPECT().AddAll(gomock.Any()).Return(errors.New("fake error")).AnyTimes()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.BatchInstallPolicyRuleFlows(rules)
	}
}

func TestConjMatchFlowContextKeyConflict(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c = prepareClient(ctrl)
	outDropTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockDropFlowBuilder(ctrl)).AnyTimes()
	outTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockRuleFlowBuilder(ctrl)).AnyTimes()
	ruleAction.EXPECT().Conjunction(gomock.Any(), gomock.Any(), gomock.Any()).Return(ruleFlowBuilder).MaxTimes(3)

	ip, ipNet, _ := net.ParseCIDR("192.168.2.30/32")

	ruleID1 := uint32(11)
	conj1 := &policyRuleConjunction{
		id: ruleID1,
	}
	clause1 := conj1.newClause(1, 3, outTable, outDropTable)
	flowChange1 := clause1.addAddrFlows(c, types.DstAddress, parseAddresses([]string{ip.String()}), nil)
	err := c.applyConjunctiveMatchFlows(flowChange1)
	require.Nil(t, err, "no error expect in applyConjunctiveMatchFlows")

	ruleID2 := uint32(12)
	conj2 := &policyRuleConjunction{
		id: ruleID2,
	}
	clause2 := conj2.newClause(1, 3, outTable, outDropTable)
	flowChange2 := clause2.addAddrFlows(c, types.DstAddress, parseAddresses([]string{ipNet.String()}), nil)
	err = c.applyConjunctiveMatchFlows(flowChange2)
	require.Nil(t, err, "no error expect in applyConjunctiveMatchFlows")

	expectedMatchKey := fmt.Sprintf("table:%d,priority:%s,type:%v,value:%s", EgressRuleTable, strconv.Itoa(int(priorityNormal)), MatchDstIPNet, ipNet.String())
	ctx, found := c.globalConjMatchFlowCache[expectedMatchKey]
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
	defer ctrl.Finish()

	c = prepareClient(ctrl)
	c.nodeConfig = &config.NodeConfig{PodIPv4CIDR: podIPv4CIDR, PodIPv6CIDR: podIPv6CIDR}
	c.ipProtocols = []binding.Protocol{binding.ProtocolIP, binding.ProtocolIPv6}
	defaultAction := crdv1alpha1.RuleActionAllow
	ruleID1 := uint32(101)
	rule1 := &types.PolicyRule{
		Direction: v1beta2.DirectionOut,
		From:      parseAddresses([]string{"192.168.1.30", "192.168.1.50", "fd12:ab:34:a001::4"}),
		Action:    &defaultAction,
		Priority:  nil,
		FlowID:    ruleID1,
		TableID:   EgressRuleTable,
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "id1",
		},
	}

	outDropTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockDropFlowBuilder(ctrl)).AnyTimes()
	outTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockRuleFlowBuilder(ctrl)).AnyTimes()
	metricTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockMetricFlowBuilder(ctrl)).AnyTimes()

	conj := &policyRuleConjunction{id: ruleID1}
	conj.calculateClauses(rule1, c)
	require.Nil(t, conj.toClause)
	require.Nil(t, conj.serviceClause)
	ctxChanges := conj.calculateChangesForRuleCreation(c, rule1)
	assert.Equal(t, len(rule1.From), len(ctxChanges))
	matchFlows, dropFlows := getChangedFlows(ctxChanges)
	assert.Equal(t, len(rule1.From), getChangedFlowCount(dropFlows))
	assert.Equal(t, 0, getChangedFlowCount(matchFlows))
	assert.Equal(t, len(rule1.From), getDenyAllRuleOPCount(matchFlows, insertion))
	err := c.applyConjunctiveMatchFlows(ctxChanges)
	require.Nil(t, err)

	ruleID2 := uint32(102)
	rule2 := &types.PolicyRule{
		Direction: v1beta2.DirectionOut,
		From:      parseAddresses([]string{"192.168.1.40", "192.168.1.50", "fd12:ab:34:a001::5"}),
		Action:    &defaultAction,
		To:        parseAddresses([]string{"0.0.0.0/0"}),
		FlowID:    ruleID2,
		TableID:   EgressRuleTable,
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "id1",
		},
	}
	conj2 := &policyRuleConjunction{id: ruleID2}
	conj2.calculateClauses(rule2, c)
	require.NotNil(t, conj2.toClause)
	require.Nil(t, conj2.serviceClause)
	ruleFlowBuilder.EXPECT().MatchConjID(ruleID2).MaxTimes(1)
	ruleFlowBuilder.EXPECT().MatchPriority(priorityLow).MaxTimes(1)
	expectConjunctionsCount([]*expectConjunctionTimes{{len(rule2.To), ruleID2, 2, 2}})
	expectConjunctionsCount([]*expectConjunctionTimes{{len(rule2.From), ruleID2, 1, 2}})
	ctxChanges2 := conj2.calculateChangesForRuleCreation(c, rule2)
	matchFlows2, dropFlows2 := getChangedFlows(ctxChanges2)
	assert.Equal(t, 2, getChangedFlowCount(dropFlows2))
	assert.Equal(t, 4, getChangedFlowCount(matchFlows2))
	assert.Equal(t, 4, getChangedFlowOPCount(matchFlows2, insertion))
	err = c.applyConjunctiveMatchFlows(ctxChanges2)
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
		TableID:   EgressRuleTable,
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "id1",
		},
	}
	conj3 := &policyRuleConjunction{id: ruleID3}
	conj3.calculateClauses(rule3, c)
	ruleFlowBuilder.EXPECT().MatchConjID(ruleID3).MaxTimes(3)
	ruleFlowBuilder.EXPECT().MatchPriority(priorityLow).MaxTimes(3)
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID2, 1, 2}})
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID3, 2, 3}})
	expectConjunctionsCount([]*expectConjunctionTimes{{2, ruleID3, 1, 3}})
	expectConjunctionsCount([]*expectConjunctionTimes{{4, ruleID3, 3, 3}})
	ctxChanges3 := conj3.calculateChangesForRuleCreation(c, rule3)
	matchFlows3, dropFlows3 := getChangedFlows(ctxChanges3)
	assert.Equal(t, 1, getChangedFlowOPCount(dropFlows3, insertion))
	assert.Equal(t, 7, getChangedFlowCount(matchFlows3))
	assert.Equal(t, 6, getChangedFlowOPCount(matchFlows3, insertion))
	assert.Equal(t, 1, getChangedFlowOPCount(matchFlows3, modification))
	err = c.applyConjunctiveMatchFlows(ctxChanges3)
	require.Nil(t, err)

	err = c.InstallPolicyRuleFlows(rule3)
	require.Nil(t, err, "Failed to invoke InstallPolicyRuleFlows")
	checkConjunctionConfig(t, ruleID3, 2, 2, 1, 4)
	assert.Equal(t, 20, len(c.GetNetworkPolicyFlowKeys("np1", "ns1")))

	ctxChanges4 := conj.calculateChangesForRuleDeletion()
	matchFlows4, dropFlows4 := getChangedFlows(ctxChanges4)
	assert.Equal(t, 2, getChangedFlowOPCount(dropFlows4, deletion))
	assert.Equal(t, 3, getDenyAllRuleOPCount(matchFlows4, deletion))
	err = c.applyConjunctiveMatchFlows(ctxChanges4)
	require.Nil(t, err)

	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID3, 1, 3}})
	ctxChanges5 := conj2.calculateChangesForRuleDeletion()
	matchFlows5, dropFlows5 := getChangedFlows(ctxChanges5)
	assert.Equal(t, 2, getChangedFlowOPCount(dropFlows5, deletion))
	assert.Equal(t, 4, getChangedFlowCount(matchFlows5))
	assert.Equal(t, 3, getChangedFlowOPCount(matchFlows5, deletion))
	assert.Equal(t, 1, getChangedFlowOPCount(matchFlows5, modification))
	err = c.applyConjunctiveMatchFlows(ctxChanges5)
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
	conj := c.getPolicyRuleConjunction(ruleID)
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
	actualCount := len(c.globalConjMatchFlowCache)
	assert.Equal(t, expectCount, actualCount, fmt.Sprintf("Incorrect count of conjunctive match flow context into global cache, expect: %d, actual: %d", expectCount, actualCount))
}

func checkConjMatchFlowActions(t *testing.T, client *client, c *clause, address types.Address, addressType types.AddressType, actionCount int, anyDropRuleCount int) {
	addrMatch := generateAddressConjMatch(c.ruleTable.GetID(), address, addressType, nil)
	context, found := client.globalConjMatchFlowCache[addrMatch.generateGlobalMapKey()]
	require.True(t, found, "Failed to add conjunctive match flow to global cache")
	assert.Equal(t, actionCount, len(context.actions), fmt.Sprintf("Incorrect policyRuleConjunction action number, expect: %d, actual: %d", actionCount, len(context.actions)))
	assert.Equal(t, anyDropRuleCount, len(context.denyAllRules), fmt.Sprintf("Incorrect policyRuleConjunction anyDropRule number, expect: %d, actual: %d", anyDropRuleCount, len(context.denyAllRules)))
}

func expectConjunctionsCount(conjs []*expectConjunctionTimes) {
	for _, c := range conjs {
		ruleAction.EXPECT().Conjunction(c.conjID, c.clauseID, c.nClause).Return(ruleFlowBuilder).MaxTimes(c.count)
	}
}

func newMockDropFlowBuilder(ctrl *gomock.Controller) *mocks.MockFlowBuilder {
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
	dropFlow.EXPECT().MatchString().Return("").AnyTimes()
	return dropFlowBuilder
}

func newMockRuleFlowBuilder(ctrl *gomock.Controller) *mocks.MockFlowBuilder {
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
	ruleAction.EXPECT().CT(true, gomock.Any(), gomock.Any()).Return(ruleCtAction).AnyTimes()
	ruleAction.EXPECT().GotoTable(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleAction.EXPECT().LoadToRegField(gomock.Any(), gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().Action().Return(ruleAction).AnyTimes()
	ruleFlow = mocks.NewMockFlow(ctrl)
	ruleFlowBuilder.EXPECT().Done().Return(ruleFlow).AnyTimes()
	ruleFlow.EXPECT().CopyToBuilder(gomock.Any(), gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlow.EXPECT().FlowPriority().Return(uint16(priorityNormal)).AnyTimes()
	ruleFlow.EXPECT().MatchString().Return("").AnyTimes()
	return ruleFlowBuilder
}

func newMockMetricFlowBuilder(ctrl *gomock.Controller) *mocks.MockFlowBuilder {
	metricFlowBuilder = mocks.NewMockFlowBuilder(ctrl)
	metricFlowBuilder.EXPECT().Cookie(gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricFlowBuilder.EXPECT().MatchProtocol(gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricFlowBuilder.EXPECT().MatchPriority(gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricFlowBuilder.EXPECT().MatchCTStateNew(gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricFlowBuilder.EXPECT().MatchCTLabelField(gomock.Any(), gomock.Any(), gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricAction = mocks.NewMockAction(ctrl)
	metricAction.EXPECT().GotoTable(gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricAction.EXPECT().LoadToRegField(gomock.Any(), gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricAction.EXPECT().Drop().Return(metricFlowBuilder).AnyTimes()
	metricFlowBuilder.EXPECT().Action().Return(metricAction).AnyTimes()
	metricFlow = mocks.NewMockFlow(ctrl)
	metricFlowBuilder.EXPECT().Done().Return(metricFlow).AnyTimes()
	metricFlow.EXPECT().CopyToBuilder(gomock.Any(), gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricFlow.EXPECT().FlowPriority().Return(uint16(priorityNormal)).AnyTimes()
	metricFlow.EXPECT().MatchString().Return("").AnyTimes()
	return metricFlowBuilder
}

func parseAddresses(addrs []string) []types.Address {
	var addresses = make([]types.Address, 0)
	for _, addr := range addrs {
		if !strings.Contains(addr, ".") && !strings.Contains(addr, ":") {
			// #nosec G109: parseAddresses is only called on constant test inputs, no potential integer overflow
			ofPort, _ := strconv.Atoi(addr)
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

func createMockTable(ctrl *gomock.Controller, tableID binding.TableIDType, nextTable binding.TableIDType, missAction binding.MissActionType) *mocks.MockTable {
	table := mocks.NewMockTable(ctrl)
	table.EXPECT().GetID().Return(tableID).AnyTimes()
	table.EXPECT().GetNext().Return(nextTable).AnyTimes()
	table.EXPECT().GetMissAction().Return(missAction).AnyTimes()
	return table
}

func prepareClient(ctrl *gomock.Controller) *client {
	policyCache := cache.NewIndexer(
		policyConjKeyFunc,
		cache.Indexers{priorityIndex: priorityIndexFunc},
	)
	bridge := mocks.NewMockBridge(ctrl)
	bridge.EXPECT().AddFlowsInBundle(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	cnpOutTable = createMockTable(ctrl, AntreaPolicyEgressRuleTable, EgressRuleTable, binding.TableMissActionNext)
	outTable = createMockTable(ctrl, EgressRuleTable, EgressDefaultTable, binding.TableMissActionNext)
	outDropTable = createMockTable(ctrl, EgressDefaultTable, EgressMetricTable, binding.TableMissActionNext)
	metricTable = createMockTable(ctrl, EgressMetricTable, l3ForwardingTable, binding.TableMissActionNext)
	outAllowTable = createMockTable(ctrl, l3ForwardingTable, l2ForwardingCalcTable, binding.TableMissActionNext)
	c = &client{
		pipeline: map[binding.TableIDType]binding.Table{
			AntreaPolicyEgressRuleTable: cnpOutTable,
			EgressRuleTable:             outTable,
			EgressDefaultTable:          outDropTable,
			EgressMetricTable:           metricTable,
			l3ForwardingTable:           outAllowTable,
		},
		policyCache:              policyCache,
		globalConjMatchFlowCache: map[string]*conjMatchFlowContext{},
		bridge:                   bridge,
		ovsDatapathType:          ovsconfig.OVSDatapathNetdev,
	}
	c.cookieAllocator = cookie.NewAllocator(0)
	m := oftest.NewMockOFEntryOperations(ctrl)
	m.EXPECT().AddAll(gomock.Any()).Return(nil).AnyTimes()
	m.EXPECT().DeleteAll(gomock.Any()).Return(nil).AnyTimes()
	c.ofEntryOperations = m
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
			rule, metric := parseMetricFlow(tc.flow)
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
				"table=61, n_packets=0, n_bytes=0, hard_timeout=300, priority=202,ip,reg0=0x100000/0x100000,reg3=0x4,nw_tos=28 actions=controller(max_len=128,id=15768)",
				"table=61, n_packets=0, n_bytes=0, hard_timeout=300, priority=202,ip,reg0=0x100000/0x100000,reg3=0x8,nw_tos=28 actions=controller(max_len=128,id=15768)",
				"table=61, n_packets=1, n_bytes=74, priority=200,ct_state=+new,ct_label=0x200000000/0xffffffff00000000,ip actions=goto_table:70",
				"table=61, n_packets=11, n_bytes=1661, priority=200,ct_state=-new,ct_label=0x200000000/0xffffffff00000000,ip actions=goto_table:70",
				"table=61, n_packets=0, n_bytes=0, priority=200,ct_state=+new,ct_label=0x600000000/0xffffffff00000000,ip actions=goto_table:70",
				"table=61, n_packets=0, n_bytes=0, priority=200,ct_state=-new,ct_label=0x600000000/0xffffffff00000000,ip actions=goto_table:70",
				"table=61, n_packets=4, n_bytes=336, priority=200,reg0=0x100000/0x100000,reg3=0x4 actions=drop",
				"table=61, n_packets=0, n_bytes=0, priority=200,reg0=0x100000/0x100000,reg3=0x8 actions=drop",
				"table=61, n_packets=1502362, n_bytes=601635949, priority=0 actions=goto_table:70",
			},
			ingressFlows: []string{
				"table=101, n_packets=0, n_bytes=0, hard_timeout=300, priority=202,ip,reg0=0x100000/0x100000,reg3=0x3,nw_tos=28 actions=controller(max_len=128,id=15768)",
				"table=101, n_packets=0, n_bytes=0, hard_timeout=300, priority=202,ip,reg0=0x100000/0x100000,reg3=0xb,nw_tos=28 actions=controller(max_len=128,id=15768)",
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
			defer ctrl.Finish()

			c = prepareClient(ctrl)
			mockOVSClient := ovsctltest.NewMockOVSCtlClient(ctrl)
			c.ovsctlClient = mockOVSClient
			gomock.InOrder(
				mockOVSClient.EXPECT().DumpTableFlows(uint8(EgressMetricTable)).Return(tt.egressFlows, nil),
				mockOVSClient.EXPECT().DumpTableFlows(uint8(IngressMetricTable)).Return(tt.ingressFlows, nil),
			)
			got := c.NetworkPolicyMetrics()
			assert.Equal(t, tt.want, got)
		})
	}
}
