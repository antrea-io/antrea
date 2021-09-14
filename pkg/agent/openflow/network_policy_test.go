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
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/cache"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow/cookie"
	oftest "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	mocks "github.com/vmware-tanzu/antrea/pkg/ovs/openflow/testing"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	ovsctltest "github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl/testing"
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
	defaultAction := secv1alpha1.RuleActionAllow
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
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c = prepareClient(ctrl)
	c.nodeConfig = &config.NodeConfig{PodIPv4CIDR: podIPv4CIDR, PodIPv6CIDR: nil}
	c.ipProtocols = []binding.Protocol{binding.ProtocolIP}
	defaultAction := secv1alpha1.RuleActionAllow
	priorityRule2 := uint16(10000)

	ruleID1 := uint32(10)
	rule1 := &types.PolicyRule{
		Direction: v1beta2.DirectionOut,
		From:      parseAddresses([]string{"192.168.1.40", "192.168.1.50"}),
		Action:    &defaultAction,
		To:        parseAddresses([]string{"0.0.0.0/0"}),
		FlowID:    ruleID1,
		TableID:   EgressRuleTable,
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "id1",
		},
	}
	ruleID2 := uint32(20)
	rule2 := &types.PolicyRule{
		Direction: v1beta2.DirectionOut,
		From:      parseAddresses([]string{"192.168.1.60"}),
		Action:    &defaultAction,
		Priority:  &priorityRule2,
		To:        parseAddresses([]string{"192.168.1.70"}),
		FlowID:    ruleID2,
		TableID:   AntreaPolicyEgressRuleTable,
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.AntreaNetworkPolicy,
			Namespace: "ns1",
			Name:      "np2",
			UID:       "id2",
		},
	}

	outDropTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockDropFlowBuilder(ctrl)).AnyTimes()
	ruleFlowBuilder := newMockRuleFlowBuilder(ctrl)
	outTable.EXPECT().BuildFlow(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	cnpOutTable.EXPECT().BuildFlow(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	metricTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockMetricFlowBuilder(ctrl)).AnyTimes()

	conj := &policyRuleConjunction{id: ruleID1}
	conj.calculateClauses(rule1, c)
	require.NotNil(t, conj.toClause)
	require.Nil(t, conj.serviceClause)
	ruleFlowBuilder.EXPECT().MatchConjID(ruleID1).MaxTimes(1)
	ruleFlowBuilder.EXPECT().MatchPriority(priorityLow).MaxTimes(1)
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID1, 2, 2}})
	expectConjunctionsCount([]*expectConjunctionTimes{{2, ruleID1, 1, 2}})
	ctxChanges1 := conj.calculateChangesForRuleCreation(c, rule1)
	matchFlows1, dropFlows1 := getChangedFlows(ctxChanges1)
	assert.Equal(t, 2, getChangedFlowCount(dropFlows1))
	assert.Equal(t, 3, getChangedFlowCount(matchFlows1))
	assert.Equal(t, 3, getChangedFlowOPCount(matchFlows1, insertion))

	conj2 := &policyRuleConjunction{id: ruleID2}
	conj2.calculateClauses(rule2, c)
	require.NotNil(t, conj2.toClause)
	require.Nil(t, conj2.serviceClause)
	ruleFlowBuilder.EXPECT().MatchConjID(ruleID2).MaxTimes(1)
	ruleFlowBuilder.EXPECT().MatchPriority(priorityRule2).MaxTimes(1)
	ruleAction.EXPECT().Conjunction(ruleID2, gomock.Any(), gomock.Any()).Return(ruleFlowBuilder).MaxTimes(1)
	ruleAction.EXPECT().Conjunction(ruleID2, gomock.Any(), gomock.Any()).Return(ruleFlowBuilder).MaxTimes(1)
	ctxChanges2 := conj2.calculateChangesForRuleCreation(c, rule2)
	matchFlows2, dropFlows2 := getChangedFlows(ctxChanges2)
	assert.Equal(t, 0, getChangedFlowCount(dropFlows2))
	assert.Equal(t, 2, getChangedFlowCount(matchFlows2))
	assert.Equal(t, 2, getChangedFlowOPCount(matchFlows2, insertion))

	err := c.applyConjunctiveMatchFlows(append(ctxChanges1, ctxChanges2...))
	require.Nil(t, err)

	err = c.BatchInstallPolicyRuleFlows([]*types.PolicyRule{rule1, rule2})
	require.Nil(t, err)
	checkConjunctionConfig(t, ruleID1, 1, 2, 1, 0)
	checkActionFlowPriority(t, ruleID1, priorityNormal)
	checkConjunctionConfig(t, ruleID2, 1, 1, 1, 0)
	assert.Equal(t, 6, len(c.GetNetworkPolicyFlowKeys("np1", "ns1")))
	assert.Equal(t, 3, len(c.GetNetworkPolicyFlowKeys("np2", "ns1")))
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
	defaultAction := secv1alpha1.RuleActionAllow
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

func checkActionFlowPriority(t *testing.T, ruleID uint32, priority uint16) {
	conj := c.getPolicyRuleConjunction(ruleID)
	require.NotNil(t, conj, "Failed to add policyRuleConjunction into client cache")
	actionFlowPriorities := conj.ActionFlowPriorities()
	for _, p := range actionFlowPriorities {
		assert.Equal(t, strconv.Itoa(int(priority)), p, fmt.Sprintf("Action flow for rule %d installed at wrong priority, expect: %s, actual: %s", ruleID, strconv.Itoa(int(priority)), p))
	}
}

func checkFlowCount(t *testing.T, expectCount int) {
	actualCount := len(c.globalConjMatchFlowCache)
	assert.Equal(t, expectCount, actualCount, fmt.Sprintf("Incorrect count of conjunctive match flow context into global cache, expect: %d, actual: %d", expectCount, actualCount))
}

func checkConjMatchFlowActions(t *testing.T, client *client, c *clause, address types.Address, addressType types.AddressType, actionCount int, anyDropRuleCount int) {
	addrMatch := c.generateAddressConjMatch(address, addressType, nil)
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
	dropFlowBuilder.EXPECT().MatchRegRange(gomock.Any(), gomock.Any(), gomock.Any()).Return(dropFlowBuilder).AnyTimes()
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
	ruleFlowBuilder.EXPECT().MatchRegRange(gomock.Any(), gomock.Any(), gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchDstPort(gomock.Any(), gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchConjID(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchPriority(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleAction = mocks.NewMockAction(ctrl)
	ruleCtAction := mocks.NewMockCTAction(ctrl)
	ruleCtAction.EXPECT().LoadToLabelRange(gomock.Any(), gomock.Any()).Return(ruleCtAction).AnyTimes()
	ruleCtAction.EXPECT().CTDone().Return(ruleFlowBuilder).AnyTimes()
	ruleAction.EXPECT().CT(true, gomock.Any(), gomock.Any()).Return(ruleCtAction).AnyTimes()
	ruleAction.EXPECT().GotoTable(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleAction.EXPECT().LoadRegRange(gomock.Any(), gomock.Any(), gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
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
	metricFlowBuilder.EXPECT().MatchRegRange(gomock.Any(), gomock.Any(), gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricFlowBuilder.EXPECT().MatchPriority(gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricFlowBuilder.EXPECT().MatchCTStateNew(gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricFlowBuilder.EXPECT().MatchCTLabelRange(gomock.Any(), gomock.Any(), gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricAction = mocks.NewMockAction(ctrl)
	metricAction.EXPECT().GotoTable(gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	metricAction.EXPECT().LoadRegRange(gomock.Any(), gomock.Any(), gomock.Any()).Return(metricFlowBuilder).AnyTimes()
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

func TestGetMatchFlowUpdates(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c = prepareClient(ctrl)
	c.nodeConfig = &config.NodeConfig{PodIPv4CIDR: podIPv4CIDR, PodIPv6CIDR: nil}
	c.encapMode = config.TrafficEncapModeEncap
	c.ipProtocols = []binding.Protocol{binding.ProtocolIP}
	outDropTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockDropFlowBuilder(ctrl)).AnyTimes()
	cnpOutTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockRuleFlowBuilder(ctrl)).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchReg(gomock.Any(), gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleAction.EXPECT().Conjunction(gomock.Any(), gomock.Any(), gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	metricTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockMetricFlowBuilder(ctrl)).AnyTimes()
	metricFlowBuilder.EXPECT().MatchReg(gomock.Any(), gomock.Any()).Return(metricFlowBuilder).AnyTimes()
	actionAllow := secv1alpha1.RuleActionAllow
	actionDrop := secv1alpha1.RuleActionDrop
	priority100 := uint16(100)
	priority200 := uint16(200)
	ProtocolTCP := v1beta2.ProtocolTCP
	port8080 := intstr.FromInt(8080)
	rules := []*types.PolicyRule{
		{
			Direction: v1beta2.DirectionOut,
			From:      parseAddresses([]string{"192.168.1.40", "192.168.1.50"}),
			Action:    &actionAllow,
			Priority:  &priority100,
			To:        []types.Address{NewOFPortAddress(1), NewOFPortAddress(2)},
			FlowID:    uint32(10),
			TableID:   AntreaPolicyEgressRuleTable,
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
			Service:  []v1beta2.Service{{Protocol: &ProtocolTCP, Port: &port8080}},
			FlowID:   uint32(11),
			TableID:  AntreaPolicyEgressRuleTable,
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
			Service:  []v1beta2.Service{{Protocol: &ProtocolTCP, Port: &port8080}},
			FlowID:   uint32(12),
			TableID:  AntreaPolicyEgressRuleTable,
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
	err = c.ReassignFlowPriorities(updatedPriorities, AntreaPolicyEgressRuleTable)
	assert.Nil(t, err)
}
