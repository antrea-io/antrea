package openflow

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow/cookie"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	coreV1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	mocks "github.com/vmware-tanzu/antrea/pkg/ovs/openflow/testing"
)

var (
	c             *client
	outTable      *mocks.MockTable
	outDropTable  *mocks.MockTable
	outAllowTable *mocks.MockTable

	ruleFlowBuilder *mocks.MockFlowBuilder
	ruleFlow        *mocks.MockFlow
	dropFlowBuilder *mocks.MockFlowBuilder
	dropFlow        *mocks.MockFlow

	ruleAction *mocks.MockAction
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

	var addedAddrs = parseAddresses([]string{"192.168.1.3", "192.168.1.30", "192.168.2.0/24", "103", "104"})
	expectFlowInvokeTimes(dropFlow, 5, 0, 0)
	expectFlowInvokeTimes(ruleFlow, 5, 0, 0)
	expectConjunctionsCount([]*expectConjunctionTimes{{5, ruleID1, clauseID, nClause}})
	err := clause1.addAddrFlows(c, types.SrcAddress, addedAddrs)
	require.Nil(t, err, "Failed to invoke addAddrFlows")
	checkFlowCount(t, len(addedAddrs))
	for _, addr := range addedAddrs {
		checkConjMatchFlowActions(t, c, clause1, addr, types.SrcAddress, 1, 0)
	}
	var currentFlowCount = len(c.globalConjMatchFlowCache)

	var deletedAddrs = parseAddresses([]string{"192.168.1.3", "103"})
	expectFlowInvokeTimes(dropFlow, 0, 0, 2)
	expectFlowInvokeTimes(ruleFlow, 0, 0, 2)
	err = clause1.deleteAddrFlows(types.SrcAddress, deletedAddrs)
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

	expectFlowInvokeTimes(dropFlow, 1, 0, 0)
	expectFlowInvokeTimes(ruleFlow, 1, 1, 0)
	expectConjunctionsCount([]*expectConjunctionTimes{{2, ruleID2, clauseID2, nClause}})
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID1, clauseID, nClause}})
	err = clause2.addAddrFlows(c, types.SrcAddress, addedAddrs2)
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
	err = clause3.addAddrFlows(c, types.SrcAddress, addedAddrs3)
	require.Nil(t, err, "Failed to invoke addAddrFlows")
	checkConjMatchFlowActions(t, c, clause3, testAddr, types.SrcAddress, 2, 1)
	checkFlowCount(t, currentFlowCount)
	err = clause3.deleteAddrFlows(types.SrcAddress, addedAddrs3)
	require.Nil(t, err, "Failed to invoke deleteAddrFlows")
	checkConjMatchFlowActions(t, c, clause3, testAddr, types.SrcAddress, 2, 0)
	checkFlowCount(t, currentFlowCount)
}

func TestInstallPolicyRuleFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c = prepareClient(ctrl)
	ruleID1 := uint32(101)
	rule1 := &types.PolicyRule{
		ID:        ruleID1,
		Direction: v1.PolicyTypeEgress,
		From:      parseAddresses([]string{"192.168.1.30", "192.168.1.50"}),
	}

	outDropTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockDropFlowBuilder(ctrl)).AnyTimes()
	outTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockRuleFlowBuilder(ctrl)).AnyTimes()

	expectFlowInvokeTimes(dropFlow, 2, 0, 0)
	err := c.InstallPolicyRuleFlows(rule1)
	if err != nil {
		t.Fatalf("Failed to invoke InstallPolicyRuleFlows: %v", err)
	}
	checkConjunctionConfig(t, ruleID1, 0, 0, 0, 0)

	ruleID2 := uint32(102)
	rule2 := &types.PolicyRule{
		ID:        ruleID2,
		Direction: v1.PolicyTypeEgress,
		From:      parseAddresses([]string{"192.168.1.40", "192.168.1.50"}),
		To:        parseAddresses([]string{"0.0.0.0/0"}),
	}
	expectFlowInvokeTimes(dropFlow, 1, 0, 0)
	expectFlowInvokeTimes(ruleFlow, 4, 0, 0)
	ruleFlowBuilder.EXPECT().MatchConjID(ruleID2).MaxTimes(1)
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID2, 2, 2}})
	expectConjunctionsCount([]*expectConjunctionTimes{{2, ruleID2, 1, 2}})
	err = c.InstallPolicyRuleFlows(rule2)
	if err != nil {
		t.Fatalf("Failed to invoke InstallPolicyRuleFlows: %v", err)
	}
	checkConjunctionConfig(t, ruleID2, 1, 2, 1, 0)

	ruleID3 := uint32(103)
	port1 := intstr.FromInt(8080)
	port2 := intstr.FromInt(8081)
	tcpProtocol := coreV1.ProtocolTCP
	npPort1 := &v1.NetworkPolicyPort{Protocol: &tcpProtocol, Port: &port1}
	npPort2 := &v1.NetworkPolicyPort{Protocol: &tcpProtocol, Port: &port2}
	rule3 := &types.PolicyRule{
		ID:        ruleID3,
		Direction: v1.PolicyTypeEgress,
		From:      parseAddresses([]string{"192.168.1.40", "192.168.1.60"}),
		To:        parseAddresses([]string{"192.168.2.0/24"}),
		ExceptTo:  parseAddresses([]string{"192.168.2.100", "192.168.2.150"}),
		Service:   []*v1.NetworkPolicyPort{npPort1, npPort2},
	}
	expectFlowInvokeTimes(dropFlow, 1, 0, 0)
	expectFlowInvokeTimes(ruleFlow, 7, 1, 0)
	ruleFlowBuilder.EXPECT().MatchConjID(ruleID3).MaxTimes(3)
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID2, 1, 2}})
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID3, 2, 3}})
	expectConjunctionsCount([]*expectConjunctionTimes{{2, ruleID3, 1, 3}})
	expectConjunctionsCount([]*expectConjunctionTimes{{2, ruleID3, 3, 3}})

	err = c.InstallPolicyRuleFlows(rule3)
	require.Nil(t, err, "Failed to invoke InstallPolicyRuleFlows")
	checkConjunctionConfig(t, ruleID3, 3, 2, 1, 2)

	expectFlowInvokeTimes(dropFlow, 0, 0, 1)
	expectFlowInvokeTimes(ruleFlow, 0, 1, 3)
	expectConjunctionsCount([]*expectConjunctionTimes{{1, ruleID3, 1, 3}})
	err = c.UninstallPolicyRuleFlows(ruleID2)
	require.Nil(t, err, "Failed to invoke UninstallPolicyRuleFlows")
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
	assert.Equal(t, expectCount, len(c.globalConjMatchFlowCache), fmt.Sprintf("Incorrect count of conjunctive match flow context into global cache, expect: %d, actual: %d", expectCount, actualCount))
}

func checkConjMatchFlowActions(t *testing.T, client *client, c *clause, address types.Address, addressType types.AddressType, actionCount int, anyDropRuleCount int) {
	addrMatch := c.generateAddressConjMatch(address, addressType)
	context, found := client.globalConjMatchFlowCache[addrMatch.generateGlobalMapKey()]
	require.True(t, found, "Failed to add conjunctive match flow to global cache")
	assert.Equal(t, actionCount, len(context.actions), fmt.Sprintf("Incorrect policyRuleConjunction action number, expect: %d, actual: %d", actionCount, len(context.actions)))
	assert.Equal(t, anyDropRuleCount, len(context.denyAllRules), fmt.Sprintf("Incorrect policyRuleConjunction anyDropRule number, expect: %d, actual: %d", anyDropRuleCount, len(context.denyAllRules)))
}

func expectFlowInvokeTimes(flow *mocks.MockFlow, addCount, modifyCount, deleteCount int) {
	if addCount > 0 {
		flow.EXPECT().Add().MaxTimes(addCount)
	}
	if modifyCount > 0 {
		flow.EXPECT().Modify().MaxTimes(modifyCount)
	}
	if deleteCount > 0 {
		flow.EXPECT().Delete().MaxTimes(deleteCount)
	}
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
	dropFlowBuilder.EXPECT().MatchRegRange(gomock.Any(), gomock.Any(), gomock.Any()).Return(dropFlowBuilder).AnyTimes()
	action := mocks.NewMockAction(ctrl)
	action.EXPECT().Drop().Return(dropFlowBuilder).AnyTimes()
	dropFlowBuilder.EXPECT().Action().Return(action).AnyTimes()
	dropFlow = mocks.NewMockFlow(ctrl)
	dropFlowBuilder.EXPECT().Done().Return(dropFlow).AnyTimes()
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
	ruleFlowBuilder.EXPECT().MatchTCPDstPort(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchUDPDstPort(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchSCTPDstPort(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().MatchConjID(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleAction = mocks.NewMockAction(ctrl)
	ruleAction.EXPECT().ResubmitToTable(gomock.Any()).Return(ruleFlowBuilder).AnyTimes()
	ruleFlowBuilder.EXPECT().Action().Return(ruleAction).AnyTimes()
	ruleFlow = mocks.NewMockFlow(ctrl)
	ruleFlowBuilder.EXPECT().Done().Return(ruleFlow).AnyTimes()
	ruleFlow.EXPECT().CopyToBuilder().Return(ruleFlowBuilder).AnyTimes()
	return ruleFlowBuilder
}

func parseAddresses(addrs []string) []types.Address {
	var addresses = make([]types.Address, 0)
	for _, addr := range addrs {
		if !strings.Contains(addr, ".") {
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
	outTable = createMockTable(ctrl, egressRuleTable, egressDefaultTable, binding.TableMissActionNext)
	outDropTable = createMockTable(ctrl, egressDefaultTable, l3ForwardingTable, binding.TableMissActionNext)
	outAllowTable = createMockTable(ctrl, l3ForwardingTable, l2ForwardingCalcTable, binding.TableMissActionNext)
	c = &client{
		pipeline: map[binding.TableIDType]binding.Table{
			egressRuleTable:    outTable,
			egressDefaultTable: outDropTable,
			l3ForwardingTable:  outAllowTable,
		},
		policyCache:              sync.Map{},
		globalConjMatchFlowCache: map[string]*conjMatchFlowContext{},
	}
	c.cookieAllocator = cookie.NewAllocator(0)
	return c
}
