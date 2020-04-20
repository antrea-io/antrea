package openflow

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow/cookie"
	oftest "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
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
	expectConjunctionsCount([]*expectConjunctionTimes{{5, ruleID1, clauseID, nClause}})
	flowChanges1 := clause1.addAddrFlows(c, types.SrcAddress, addedAddrs)
	err := c.applyConjunctiveMatchFlows(flowChanges1)
	require.Nil(t, err, "Failed to invoke addAddrFlows")
	checkFlowCount(t, len(addedAddrs))
	for _, addr := range addedAddrs {
		checkConjMatchFlowActions(t, c, clause1, addr, types.SrcAddress, 1, 0)
	}
	var currentFlowCount = len(c.globalConjMatchFlowCache)

	var deletedAddrs = parseAddresses([]string{"192.168.1.3", "103"})
	flowChanges2 := clause1.deleteAddrFlows(types.SrcAddress, deletedAddrs)
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
	flowChanges3 := clause2.addAddrFlows(c, types.SrcAddress, addedAddrs2)
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
	flowChanges4 := clause3.addAddrFlows(c, types.SrcAddress, addedAddrs3)
	err = c.applyConjunctiveMatchFlows(flowChanges4)
	require.Nil(t, err, "Failed to invoke addAddrFlows")
	checkConjMatchFlowActions(t, c, clause3, testAddr, types.SrcAddress, 2, 1)
	checkFlowCount(t, currentFlowCount)
	flowChanges5 := clause3.deleteAddrFlows(types.SrcAddress, addedAddrs3)
	err = c.applyConjunctiveMatchFlows(flowChanges5)
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
		Direction: v1beta1.DirectionOut,
		From:      parseAddresses([]string{"192.168.1.30", "192.168.1.50"}),
	}

	outDropTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockDropFlowBuilder(ctrl)).AnyTimes()
	outTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockRuleFlowBuilder(ctrl)).AnyTimes()

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
		Direction: v1beta1.DirectionOut,
		From:      parseAddresses([]string{"192.168.1.40", "192.168.1.50"}),
		To:        parseAddresses([]string{"0.0.0.0/0"}),
	}
	conj2 := &policyRuleConjunction{id: ruleID2}
	conj2.calculateClauses(rule2, c)
	require.NotNil(t, conj2.toClause)
	require.Nil(t, conj2.serviceClause)
	ruleFlowBuilder.EXPECT().MatchConjID(ruleID2).MaxTimes(1)
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
	err = c.InstallPolicyRuleFlows(ruleID2, rule2, "np1", "ns1")
	require.Nil(t, err)
	checkConjunctionConfig(t, ruleID2, 1, 2, 1, 0)
	assert.Equal(t, 6, len(c.GetNetworkPolicyFlowKeys("np1", "ns1")))

	ruleID3 := uint32(103)
	port1 := intstr.FromInt(8080)
	port2 := intstr.FromInt(8081)
	tcpProtocol := v1beta1.ProtocolTCP
	npPort1 := v1beta1.Service{Protocol: &tcpProtocol, Port: &port1}
	npPort2 := v1beta1.Service{Protocol: &tcpProtocol, Port: &port2}
	rule3 := &types.PolicyRule{
		Direction: v1beta1.DirectionOut,
		From:      parseAddresses([]string{"192.168.1.40", "192.168.1.60"}),
		To:        parseAddresses([]string{"192.168.2.0/24"}),
		Service:   []v1beta1.Service{npPort1, npPort2},
	}
	conj3 := &policyRuleConjunction{id: ruleID3}
	conj3.calculateClauses(rule3, c)
	ruleFlowBuilder.EXPECT().MatchConjID(ruleID3).MaxTimes(3)
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

	err = c.InstallPolicyRuleFlows(ruleID3, rule3, "np1", "ns1")
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
	flowChange1 := clause1.addAddrFlows(c, types.DstAddress, parseAddresses([]string{ip.String()}))
	err := c.applyConjunctiveMatchFlows(flowChange1)
	require.Nil(t, err, "no error expect in applyConjunctiveMatchFlows")

	ruleID2 := uint32(12)
	conj2 := &policyRuleConjunction{
		id: ruleID2,
	}
	clause2 := conj2.newClause(1, 3, outTable, outDropTable)
	flowChange2 := clause2.addAddrFlows(c, types.DstAddress, parseAddresses([]string{ipNet.String()}))
	err = c.applyConjunctiveMatchFlows(flowChange2)
	require.Nil(t, err, "no error expect in applyConjunctiveMatchFlows")

	expectedMatchKey := fmt.Sprintf("table:%d,type:%d,value:%s", egressRuleTable, MatchDstIPNet, ipNet.String())
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
	addrMatch := c.generateAddressConjMatch(address, addressType)
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
	ruleFlow.EXPECT().MatchString().Return("").AnyTimes()
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
	bridge := mocks.NewMockBridge(ctrl)
	bridge.EXPECT().AddFlowsInBundle(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
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
		bridge:                   bridge,
	}
	c.cookieAllocator = cookie.NewAllocator(0)
	m := oftest.NewMockOFEntryOperations(ctrl)
	m.EXPECT().AddAll(gomock.Any()).Return(nil).AnyTimes()
	m.EXPECT().DeleteAll(gomock.Any()).Return(nil).AnyTimes()
	c.ofEntryOperations = m
	return c
}
