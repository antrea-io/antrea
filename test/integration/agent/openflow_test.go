// Copyright 2019 Antrea Authors
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

package agent

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/intstr"

	config1 "github.com/vmware-tanzu/antrea/pkg/agent/config"
	ofClient "github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
	ofconfig "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	ofTestUtils "github.com/vmware-tanzu/antrea/test/integration/ovs"
)

var (
	br             = "br01"
	c              ofClient.Client
	roundInfo      = types.RoundInfo{0, nil}
	bridgeMgmtAddr = ofconfig.GetMgmtAddress(ovsconfig.DefaultOVSRunDir, br)
)

const (
	ingressRuleTable    = uint8(90)
	ingressDefaultTable = uint8(100)
	contrackCommitTable = uint8(105)
	priorityNormal      = 200
)

type expectTableFlows struct {
	tableID uint8
	flows   []*ofTestUtils.ExpectFlow
}

type testPortConfig struct {
	ip     net.IP
	mac    net.HardwareAddr
	ofPort uint32
}

type testLocalPodConfig struct {
	name string
	*testPortConfig
}

type testPeerConfig struct {
	name        string
	nodeAddress net.IP
	subnet      net.IPNet
	gateway     net.IP
}

type testConfig struct {
	bridge       string
	localGateway *testPortConfig
	localPods    []*testLocalPodConfig
	peers        []*testPeerConfig
	tunnelOFPort uint32
	serviceCIDR  *net.IPNet
	globalMAC    net.HardwareAddr
}

func TestConnectivityFlows(t *testing.T) {
	c = ofClient.NewClient(br, bridgeMgmtAddr)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))
	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
	}()

	config := prepareConfiguration()
	for _, f := range []func(t *testing.T, config *testConfig){
		testInitialize,
		testInstallGatewayFlows,
		testInstallServiceFlows,
		testInstallTunnelFlows,
		testInstallNodeFlows,
		testInstallPodFlows,
		testUninstallPodFlows,
		testUninstallNodeFlows,
	} {
		f(t, config)
	}
}

func TestReplayFlowsConnectivityFlows(t *testing.T) {
	c = ofClient.NewClient(br, bridgeMgmtAddr)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))

	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
	}()

	config := prepareConfiguration()
	for _, f := range []func(t *testing.T, config *testConfig){
		testInitialize,
		testInstallGatewayFlows,
		testInstallServiceFlows,
		testInstallTunnelFlows,
		testInstallNodeFlows,
		testInstallPodFlows,
	} {
		f(t, config)
	}

	testReplayFlows(t)
}

func TestReplayFlowsNetworkPolicyFlows(t *testing.T) {
	c = ofClient.NewClient(br, bridgeMgmtAddr)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))

	_, err = c.Initialize(roundInfo, &config1.NodeConfig{}, config1.TrafficEncapModeEncap, config1.HostGatewayOFPort)
	require.Nil(t, err, "Failed to initialize OFClient")

	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
	}()

	ruleID := uint32(100)
	fromList := []string{"192.168.1.3", "192.168.1.25", "192.168.2.4"}
	exceptFromList := []string{"192.168.2.3"}
	toList := []string{"192.168.3.4", "192.168.3.5"}

	port2 := intstr.FromInt(8080)
	tcpProtocol := v1beta1.ProtocolTCP
	npPort1 := v1beta1.Service{Protocol: &tcpProtocol, Port: &port2}
	toIPList := prepareIPAddresses(toList)
	rule := &types.PolicyRule{
		Direction:  v1beta1.DirectionIn,
		From:       prepareIPAddresses(fromList),
		ExceptFrom: prepareIPAddresses(exceptFromList),
		To:         toIPList,
		Service:    []v1beta1.Service{npPort1},
	}

	err = c.InstallPolicyRuleFlows(ruleID, rule)
	require.Nil(t, err, "Failed to InstallPolicyRuleFlows")

	err = c.AddPolicyRuleAddress(ruleID, types.SrcAddress, prepareIPNetAddresses([]string{"192.168.5.0/24", "192.169.1.0/24"}))
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")
	ofport := int32(100)
	err = c.AddPolicyRuleAddress(ruleID, types.DstAddress, []types.Address{ofClient.NewOFPortAddress(ofport)})
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")

	testReplayFlows(t)
}

func testReplayFlows(t *testing.T) {
	var err error

	countFlows := func() int {
		flowList, err := ofTestUtils.OfctlDumpFlows(br)
		require.Nil(t, err, "Error when dumping flows from OVS bridge")
		return len(flowList)
	}

	count1 := countFlows()
	t.Logf("Counted %d flows before deletion & reconciliation", count1)
	err = ofTestUtils.OfctlDeleteFlows(br)
	require.Nil(t, err, "Error when deleting flows from OVS bridge")
	count2 := countFlows()
	assert.Zero(t, count2, "Expected no flows after deletion")
	c.ReplayFlows()
	count3 := countFlows()
	t.Logf("Counted %d flows after reconciliation", count3)
	assert.Equal(t, count1, count3, "Expected same number of flows after reconciliation")
}

func testInitialize(t *testing.T, config *testConfig) {
	if _, err := c.Initialize(roundInfo, &config1.NodeConfig{}, config1.TrafficEncapModeEncap, config1.HostGatewayOFPort); err != nil {
		t.Errorf("Failed to initialize openflow client: %v", err)
	}
	for _, tableFlow := range prepareDefaultFlows() {
		ofTestUtils.CheckFlowExists(t, config.bridge, tableFlow.tableID, true, tableFlow.flows)
	}
}

func testInstallTunnelFlows(t *testing.T, config *testConfig) {
	err := c.InstallDefaultTunnelFlows(config.tunnelOFPort)
	if err != nil {
		t.Fatalf("Failed to install Openflow entries for tunnel port: %v", err)
	}
	for _, tableFlow := range prepareTunnelFlows(config.tunnelOFPort, config.globalMAC) {
		ofTestUtils.CheckFlowExists(t, config.bridge, tableFlow.tableID, true, tableFlow.flows)
	}
}

func testInstallServiceFlows(t *testing.T, config *testConfig) {
	err := c.InstallClusterServiceCIDRFlows(config.serviceCIDR, config.localGateway.mac, config.localGateway.ofPort)
	if err != nil {
		t.Fatalf("Failed to install Openflow entries to skip service CIDR from egress table")
	}
	for _, tableFlow := range prepareServiceHelperFlows(*config.serviceCIDR, config.localGateway.mac, config.localGateway.ofPort) {
		ofTestUtils.CheckFlowExists(t, config.bridge, tableFlow.tableID, true, tableFlow.flows)
	}
}

func testInstallNodeFlows(t *testing.T, config *testConfig) {
	for _, node := range config.peers {
		err := c.InstallNodeFlows(node.name, config.localGateway.mac, node.subnet, node.gateway, node.nodeAddress, config.tunnelOFPort, 0)
		if err != nil {
			t.Fatalf("Failed to install Openflow entries for node connectivity: %v", err)
		}
		for _, tableFlow := range prepareNodeFlows(config.tunnelOFPort, node.subnet, node.gateway, node.nodeAddress, config.globalMAC, config.localGateway.mac) {
			ofTestUtils.CheckFlowExists(t, config.bridge, tableFlow.tableID, true, tableFlow.flows)
		}
	}
}

func testUninstallNodeFlows(t *testing.T, config *testConfig) {
	for _, node := range config.peers {
		err := c.UninstallNodeFlows(node.name)
		if err != nil {
			t.Fatalf("Failed to uninstall Openflow entries for node connectivity: %v", err)
		}
		for _, tableFlow := range prepareNodeFlows(config.tunnelOFPort, node.subnet, node.gateway, node.nodeAddress, config.globalMAC, config.localGateway.mac) {
			ofTestUtils.CheckFlowExists(t, config.bridge, tableFlow.tableID, false, tableFlow.flows)
		}
	}
}

func testInstallPodFlows(t *testing.T, config *testConfig) {
	for _, pod := range config.localPods {
		err := c.InstallPodFlows(pod.name, pod.ip, pod.mac, config.localGateway.mac, pod.ofPort)
		if err != nil {
			t.Fatalf("Failed to install Openflow entries for pod: %v", err)
		}
		for _, tableFlow := range preparePodFlows(pod.ip, pod.mac, pod.ofPort, config.localGateway.mac, config.globalMAC) {
			ofTestUtils.CheckFlowExists(t, config.bridge, tableFlow.tableID, true, tableFlow.flows)
		}
	}
}

func testUninstallPodFlows(t *testing.T, config *testConfig) {
	for _, pod := range config.localPods {
		err := c.UninstallPodFlows(pod.name)
		if err != nil {
			t.Fatalf("Failed to uninstall Openflow entries for pod: %v", err)
		}
		for _, tableFlow := range preparePodFlows(pod.ip, pod.mac, pod.ofPort, config.localGateway.mac, config.globalMAC) {
			ofTestUtils.CheckFlowExists(t, config.bridge, tableFlow.tableID, false, tableFlow.flows)
		}
	}
}

func TestNetworkPolicyFlows(t *testing.T) {
	c = ofClient.NewClient(br, bridgeMgmtAddr)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge %s", br))

	_, err = c.Initialize(roundInfo, &config1.NodeConfig{}, config1.TrafficEncapModeEncap, config1.HostGatewayOFPort)
	require.Nil(t, err, "Failed to initialize OFClient")

	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
	}()

	ruleID := uint32(100)
	fromList := []string{"192.168.1.3", "192.168.1.25", "192.168.2.4"}
	exceptFromList := []string{"192.168.2.3"}
	toList := []string{"192.168.3.4", "192.168.3.5"}

	port2 := intstr.FromInt(8080)
	tcpProtocol := v1beta1.ProtocolTCP
	npPort1 := v1beta1.Service{Protocol: &tcpProtocol, Port: &port2}
	toIPList := prepareIPAddresses(toList)
	rule := &types.PolicyRule{
		Direction:  v1beta1.DirectionIn,
		From:       prepareIPAddresses(fromList),
		ExceptFrom: prepareIPAddresses(exceptFromList),
		To:         toIPList,
		Service:    []v1beta1.Service{npPort1},
	}

	err = c.InstallPolicyRuleFlows(ruleID, rule)
	require.Nil(t, err, "Failed to InstallPolicyRuleFlows")
	checkConjunctionFlows(t, ingressRuleTable, ingressDefaultTable, contrackCommitTable, priorityNormal, ruleID, rule, assert.True)
	checkDefaultDropFlows(t, ingressDefaultTable, priorityNormal, types.DstAddress, toIPList, true)

	addedFrom := prepareIPNetAddresses([]string{"192.168.5.0/24", "192.169.1.0/24"})
	checkAddAddress(t, ingressRuleTable, priorityNormal, ruleID, addedFrom, types.SrcAddress)
	checkDeleteAddress(t, ingressRuleTable, priorityNormal, ruleID, addedFrom, types.SrcAddress)

	ofport := int32(100)
	err = c.AddPolicyRuleAddress(ruleID, types.DstAddress, []types.Address{ofClient.NewOFPortAddress(ofport)})
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")

	// Dump flows.
	flowList, err := ofTestUtils.OfctlDumpTableFlows(br, ingressRuleTable)
	require.Nil(t, err, "Failed to dump flows")
	conjMatch := fmt.Sprintf("priority=%d,ip,reg1=0x%x", priorityNormal, ofport)
	flow := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: fmt.Sprintf("conjunction(%d,2/3)", ruleID)}
	assert.True(t, ofTestUtils.OfctlFlowMatch(flowList, ingressRuleTable, flow), "Failed to install conjunctive match flow")

	// Verify multiple conjunctions share the same match conditions.
	ruleID2 := uint32(101)
	toList2 := []string{"192.168.3.4"}
	toIPList2 := prepareIPAddresses(toList2)
	port3 := intstr.FromInt(206)
	udpProtocol := v1beta1.ProtocolUDP
	npPort2 := v1beta1.Service{Protocol: &udpProtocol, Port: &port3}
	rule2 := &types.PolicyRule{
		Direction: v1beta1.DirectionIn,
		To:        toIPList2,
		Service:   []v1beta1.Service{npPort2},
	}
	err = c.InstallPolicyRuleFlows(ruleID2, rule2)
	require.Nil(t, err, "Failed to InstallPolicyRuleFlows")

	// Dump flows
	flowList, err = ofTestUtils.OfctlDumpTableFlows(br, ingressRuleTable)
	require.Nil(t, err, "Failed to dump flows")
	conjMatch = fmt.Sprintf("priority=%d,ip,nw_dst=192.168.3.4", priorityNormal)
	flow1 := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: fmt.Sprintf("conjunction(%d,2/3),conjunction(%d,1/2)", ruleID, ruleID2)}
	flow2 := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: fmt.Sprintf("conjunction(%d,1/2),conjunction(%d,2/3)", ruleID2, ruleID)}
	if !ofTestUtils.OfctlFlowMatch(flowList, ingressRuleTable, flow1) && !ofTestUtils.OfctlFlowMatch(flowList, ingressRuleTable, flow2) {
		t.Errorf("Failed to install conjunctive match flow")
	}
	err = c.UninstallPolicyRuleFlows(ruleID2)
	require.Nil(t, err, "Failed to InstallPolicyRuleFlows")
	checkDefaultDropFlows(t, ingressDefaultTable, priorityNormal, types.DstAddress, toIPList2, true)

	err = c.UninstallPolicyRuleFlows(ruleID)
	require.Nil(t, err, "Failed to DeletePolicyRuleService")
	checkConjunctionFlows(t, ingressRuleTable, ingressDefaultTable, contrackCommitTable, priorityNormal, ruleID, rule, assert.False)
	checkDefaultDropFlows(t, ingressDefaultTable, priorityNormal, types.DstAddress, toIPList, false)
}

func checkDefaultDropFlows(t *testing.T, table uint8, priority int, addrType types.AddressType, addresses []types.Address, add bool) {
	// dump flows
	flowList, err := ofTestUtils.OfctlDumpTableFlows(br, table)
	assert.Nil(t, err, fmt.Sprintf("Failed to dump flows: %v", err))
	for _, addr := range addresses {
		conjMatch := fmt.Sprintf("priority=%d,ip,%s=%s", priority, getCmdMatchKey(addr.GetMatchKey(addrType)), addr.GetMatchValue())
		flow := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: "drop"}
		if add {
			assert.True(t, ofTestUtils.OfctlFlowMatch(flowList, table, flow), "Failed to install conjunctive match flow")
		} else {
			assert.False(t, ofTestUtils.OfctlFlowMatch(flowList, table, flow), "Failed to uninstall conjunctive match flow")
		}
	}
}

func getCmdMatchKey(matchType int) string {
	switch matchType {
	case ofClient.MatchSrcIP:
		fallthrough
	case ofClient.MatchSrcIPNet:
		return "nw_src"
	case ofClient.MatchDstIP:
		fallthrough
	case ofClient.MatchDstIPNet:
		return "nw_dst"
	case ofClient.MatchSrcOFPort:
		return "in_port"
	case ofClient.MatchDstOFPort:
		return "reg1[0..31]"
	default:
		return ""
	}
}

func checkAddAddress(t *testing.T, ruleTable uint8, priority int, ruleID uint32, addedAddress []types.Address, addrType types.AddressType) {
	err := c.AddPolicyRuleAddress(ruleID, addrType, addedAddress)
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")

	// dump flows
	flowList, err := ofTestUtils.OfctlDumpTableFlows(br, ruleTable)
	require.Nil(t, err, "Failed to dump flows")

	action := fmt.Sprintf("conjunction(%d,1/3)", ruleID)
	if addrType == types.DstAddress {
		action = fmt.Sprintf("conjunction(%d,2/3)", ruleID)
	}

	for _, addr := range addedAddress {
		conjMatch := fmt.Sprintf("priority=%d,ip,%s=%s", priority, getCmdMatchKey(addr.GetMatchKey(addrType)), addr.GetMatchValue())
		flow := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: action}
		assert.True(t, ofTestUtils.OfctlFlowMatch(flowList, ruleTable, flow), "Failed to install conjunctive match flow")
	}

	tableStatus := c.GetFlowTableStatus()
	for _, tableStatus := range tableStatus {
		if tableStatus.ID == uint(ruleTable) {
			assert.Equal(t, tableStatus.FlowCount, uint(len(flowList)),
				fmt.Sprintf("Cached table status in %d is incorrect, expect: %d, actual %d", tableStatus.ID, tableStatus.FlowCount, len(flowList)))
		}
	}
}

func checkDeleteAddress(t *testing.T, ruleTable uint8, priority int, ruleID uint32, addedAddress []types.Address, addrType types.AddressType) {
	err := c.DeletePolicyRuleAddress(ruleID, addrType, addedAddress)
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")
	flowList, err := ofTestUtils.OfctlDumpTableFlows(br, ruleTable)
	require.Nil(t, err, "Failed to dump flows")

	action := fmt.Sprintf("conjunction(%d,1/3)", ruleID)
	if addrType == types.DstAddress {
		action = fmt.Sprintf("conjunction(%d,2/3)", ruleID)
	}

	for _, addr := range addedAddress {
		conjMatch := fmt.Sprintf("priority=%d,ip,%s=%s", priority, getCmdMatchKey(addr.GetMatchKey(addrType)), addr.GetMatchValue())
		flow := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: action}
		assert.False(t, ofTestUtils.OfctlFlowMatch(flowList, ruleTable, flow), "Failed to install conjunctive match flow")
	}

	tableStatus := c.GetFlowTableStatus()
	for _, tableStatus := range tableStatus {
		if tableStatus.ID == uint(ruleTable) {
			assert.Equal(t, tableStatus.FlowCount, uint(len(flowList)),
				fmt.Sprintf("Cached table status in %d is incorrect, expect: %d, actual %d", tableStatus.ID, tableStatus.FlowCount, len(flowList)))
		}
	}
}

func checkConjunctionFlows(t *testing.T, ruleTable uint8, dropTable uint8, allowTable uint8, priority int, ruleID uint32, rule *types.PolicyRule, testFunc func(t assert.TestingT, value bool, msgAndArgs ...interface{}) bool) {
	flowList, err := ofTestUtils.OfctlDumpTableFlows(br, ruleTable)
	require.Nil(t, err, "Failed to dump flows")

	conjunctionActionMatch := fmt.Sprintf("priority=%d,conj_id=%d,ip", priority-10, ruleID)
	flow := &ofTestUtils.ExpectFlow{MatchStr: conjunctionActionMatch, ActStr: fmt.Sprintf("resubmit(,%d)", allowTable)}
	testFunc(t, ofTestUtils.OfctlFlowMatch(flowList, ruleTable, flow), "Failed to update conjunction action flow")

	if rule.ExceptFrom != nil {
		for _, addr := range rule.ExceptFrom {
			exceptsMatch := fmt.Sprintf("priority=%d,conj_id=%d,ip,%s=%s", priority, ruleID, getCmdMatchKey(addr.GetMatchKey(types.SrcAddress)), addr.GetMatchValue())
			flow := &ofTestUtils.ExpectFlow{MatchStr: exceptsMatch, ActStr: fmt.Sprintf("resubmit(,%d)", dropTable)}
			testFunc(t, ofTestUtils.OfctlFlowMatch(flowList, ruleTable, flow), "Failed to install conjunction excepts flow")
		}
	}

	if rule.ExceptTo != nil {
		for _, addr := range rule.ExceptTo {
			exceptsMatch := fmt.Sprintf("priority=%d,conj_id=%d,ip,%s=%s", priority, ruleID, getCmdMatchKey(addr.GetMatchKey(types.DstAddress)), addr.GetMatchValue())
			flow := &ofTestUtils.ExpectFlow{MatchStr: exceptsMatch, ActStr: fmt.Sprintf("resubmit(,%d)", dropTable)}
			testFunc(t, ofTestUtils.OfctlFlowMatch(flowList, ruleTable, flow),
				"Failed to install conjunction excepts flow")
		}
	}

	for _, addr := range rule.From {
		conjMatch := fmt.Sprintf("priority=%d,ip,%s=%s", priority, getCmdMatchKey(addr.GetMatchKey(types.SrcAddress)), addr.GetMatchValue())
		flow := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: fmt.Sprintf("conjunction(%d,1/3)", ruleID)}
		testFunc(t, ofTestUtils.OfctlFlowMatch(flowList, ruleTable, flow), "Failed to install conjunctive match flow for clause1")
	}

	for _, addr := range rule.To {
		conjMatch := fmt.Sprintf("priority=%d,ip,%s=%s", priority, getCmdMatchKey(addr.GetMatchKey(types.DstAddress)), addr.GetMatchValue())
		flow := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: fmt.Sprintf("conjunction(%d,2/3)", ruleID)}
		testFunc(t, ofTestUtils.OfctlFlowMatch(flowList, ruleTable, flow), "Failed to install conjunctive match flow for clause2")
	}

	for _, service := range rule.Service {
		conjMatch1 := fmt.Sprintf("priority=%d,%s,tp_dst=%d", priority, strings.ToLower(string(*service.Protocol)), service.Port.IntVal)
		flow := &ofTestUtils.ExpectFlow{MatchStr: conjMatch1, ActStr: fmt.Sprintf("conjunction(%d,3/3)", ruleID)}
		testFunc(t, ofTestUtils.OfctlFlowMatch(flowList, ruleTable, flow), "Failed to install conjunctive match flow for clause3")
	}

	tablesStatus := c.GetFlowTableStatus()
	for _, tableStatus := range tablesStatus {
		if tableStatus.ID == uint(ruleTable) {
			assert.Equal(t, tableStatus.FlowCount, uint(len(flowList)),
				fmt.Sprintf("Cached table status in %d is incorrect, expect: %d, actual %d", tableStatus.ID, tableStatus.FlowCount, len(flowList)))
		}
	}
}

func testInstallGatewayFlows(t *testing.T, config *testConfig) {
	err := c.InstallGatewayFlows(config.localGateway.ip, config.localGateway.mac, config.localGateway.ofPort)
	if err != nil {
		t.Fatalf("Failed to install Openflow entries for gateway: %v", err)
	}
	for _, tableFlow := range prepareGatewayFlows(config.localGateway.ip, config.localGateway.mac, config.localGateway.ofPort, config.globalMAC) {
		ofTestUtils.CheckFlowExists(t, config.bridge, tableFlow.tableID, true, tableFlow.flows)
	}
}

func prepareConfiguration() *testConfig {
	podMAC, _ := net.ParseMAC("aa:aa:aa:aa:aa:13")
	gwMAC, _ := net.ParseMAC("aa:aa:aa:aa:aa:11")
	podCfg := &testLocalPodConfig{
		name: "container-1",
		testPortConfig: &testPortConfig{
			ip:     net.ParseIP("192.168.1.3"),
			mac:    podMAC,
			ofPort: uint32(3),
		},
	}
	gwCfg := &testPortConfig{
		ip:     net.ParseIP("192.168.1.1"),
		mac:    gwMAC,
		ofPort: uint32(1),
	}
	_, serviceCIDR, _ := net.ParseCIDR("172.16.0.0/16")
	_, peerSubnet, _ := net.ParseCIDR("192.168.2.0/24")
	peerNode := &testPeerConfig{
		name:        "n2",
		nodeAddress: net.ParseIP("10.1.1.2"),
		subnet:      *peerSubnet,
		gateway:     net.ParseIP("192.168.2.1"),
	}
	vMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	return &testConfig{
		bridge:       br,
		localGateway: gwCfg,
		localPods:    []*testLocalPodConfig{podCfg},
		peers:        []*testPeerConfig{peerNode},
		tunnelOFPort: uint32(2),
		serviceCIDR:  serviceCIDR,
		globalMAC:    vMAC,
	}
}

func preparePodFlows(podIP net.IP, podMAC net.HardwareAddr, podOFPort uint32, gwMAC, vMAC net.HardwareAddr) []expectTableFlows {
	return []expectTableFlows{
		{
			uint8(0),
			[]*ofTestUtils.ExpectFlow{
				{fmt.Sprintf("priority=190,in_port=%d", podOFPort), "load:0x2->NXM_NX_REG0[0..15],resubmit(,10)"},
			},
		},
		{
			uint8(10),
			[]*ofTestUtils.ExpectFlow{
				{fmt.Sprintf("priority=200,ip,in_port=%d,dl_src=%s,nw_src=%s", podOFPort, podMAC.String(), podIP.String()),
					"resubmit(,30)"},
				{
					fmt.Sprintf("priority=200,arp,in_port=%d,arp_spa=%s,arp_sha=%s", podOFPort, podIP.String(), podMAC.String()),
					"resubmit(,20)"},
			},
		},
		{
			uint8(70),
			[]*ofTestUtils.ExpectFlow{
				{
					fmt.Sprintf("priority=200,ip,dl_dst=%s,nw_dst=%s", vMAC.String(), podIP.String()),
					fmt.Sprintf("set_field:%s->eth_src,set_field:%s->eth_dst,dec_ttl,resubmit(,80)", gwMAC.String(), podMAC.String())},
			},
		},
		{
			uint8(80),
			[]*ofTestUtils.ExpectFlow{
				{
					fmt.Sprintf("priority=200,dl_dst=%s", podMAC.String()),
					fmt.Sprintf("load:0x%x->NXM_NX_REG1[],load:0x1->NXM_NX_REG0[16],resubmit(,90)", podOFPort)},
			},
		},
	}
}

func prepareGatewayFlows(gwIP net.IP, gwMAC net.HardwareAddr, gwOFPort uint32, vMAC net.HardwareAddr) []expectTableFlows {
	return []expectTableFlows{
		{
			uint8(0),
			[]*ofTestUtils.ExpectFlow{
				{fmt.Sprintf("priority=200,in_port=%d", gwOFPort),
					"load:0x1->NXM_NX_REG0[0..15],resubmit(,10)"},
			},
		},
		{
			uint8(31),
			[]*ofTestUtils.ExpectFlow{
				{"priority=200,ct_state=-new+trk,ct_mark=0x20,ip",
					fmt.Sprintf("load:0x%s->NXM_OF_ETH_DST[],resubmit(,40)", strings.Replace(gwMAC.String(), ":", "", -1))},
			},
		},
		{
			uint8(10),
			[]*ofTestUtils.ExpectFlow{
				{fmt.Sprintf("priority=200,arp,in_port=%d,arp_spa=%s,arp_sha=%s", gwOFPort, gwIP, gwMAC), "resubmit(,20)"},
				{fmt.Sprintf("priority=200,ip,in_port=%d", gwOFPort), "resubmit(,30)"},
			},
		},
		{
			uint8(70),
			[]*ofTestUtils.ExpectFlow{
				{
					fmt.Sprintf("priority=200,ip,dl_dst=%s,nw_dst=%s", vMAC.String(), gwIP.String()),
					fmt.Sprintf("set_field:%s->eth_dst,resubmit(,80)", gwMAC.String())},
			},
		},
		{
			uint8(80),
			[]*ofTestUtils.ExpectFlow{
				{
					fmt.Sprintf("priority=200,dl_dst=%s", gwMAC.String()),
					fmt.Sprintf("load:0x%x->NXM_NX_REG1[],load:0x1->NXM_NX_REG0[16],resubmit(,90)", gwOFPort)},
			},
		},
		{
			uint8(90),
			[]*ofTestUtils.ExpectFlow{
				{
					fmt.Sprintf("priority=210,ip,nw_src=%s", gwIP.String()),
					"resubmit(,105)"},
			},
		},
	}
}

func prepareTunnelFlows(tunnelPort uint32, vMAC net.HardwareAddr) []expectTableFlows {
	return []expectTableFlows{
		{
			uint8(0),
			[]*ofTestUtils.ExpectFlow{
				{fmt.Sprintf("priority=200,in_port=%d", tunnelPort), "load:0->NXM_NX_REG0[0..15],resubmit(,30)"},
			},
		},
	}
}

func prepareNodeFlows(tunnelPort uint32, peerSubnet net.IPNet, peerGwIP, peerNodeIP net.IP, vMAC, localGwMAC net.HardwareAddr) []expectTableFlows {
	return []expectTableFlows{
		{
			uint8(20),
			[]*ofTestUtils.ExpectFlow{
				{fmt.Sprintf("priority=200,arp,arp_tpa=%s,arp_op=1", peerGwIP.String()),
					fmt.Sprintf("move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:%s->eth_src,load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],set_field:%s->arp_sha,move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:%s->arp_spa,IN_PORT", vMAC.String(), vMAC.String(), peerGwIP.String())},
			},
		},
		{
			uint8(70),
			[]*ofTestUtils.ExpectFlow{
				{
					fmt.Sprintf("priority=200,ip,nw_dst=%s", peerSubnet.String()),
					fmt.Sprintf("dec_ttl,set_field:%s->eth_src,set_field:%s->eth_dst,load:0x%x->NXM_NX_REG1[],load:0x1->NXM_NX_REG0[16],set_field:%s->tun_dst,resubmit(,105)", localGwMAC.String(), vMAC.String(), tunnelPort, peerNodeIP.String())},
			},
		},
	}
}

func prepareServiceHelperFlows(serviceCIDR net.IPNet, gwMAC net.HardwareAddr, gwOFPort uint32) []expectTableFlows {
	return []expectTableFlows{
		{
			uint8(40),
			[]*ofTestUtils.ExpectFlow{
				{fmt.Sprintf("priority=200,ip,nw_dst=%s", serviceCIDR.String()),
					fmt.Sprintf("set_field:%s->eth_dst,load:0x%x->NXM_NX_REG1[],load:0x1->NXM_NX_REG0[16],resubmit(,105)", gwMAC, gwOFPort),
				},
			},
		},
	}
}

func prepareDefaultFlows() []expectTableFlows {
	return []expectTableFlows{
		{
			uint8(0),
			[]*ofTestUtils.ExpectFlow{{"priority=0", "drop"}},
		},
		{
			uint8(10),
			[]*ofTestUtils.ExpectFlow{{"priority=0", "drop"}},
		},
		{
			uint8(20),
			[]*ofTestUtils.ExpectFlow{
				{"priority=190,arp", "NORMAL"},
				{"priority=0", "drop"},
			},
		},
		{
			uint8(30),
			[]*ofTestUtils.ExpectFlow{
				{"priority=200,ip", "ct(table=31,zone=65520)"},
			},
		},
		{
			uint8(31),
			[]*ofTestUtils.ExpectFlow{
				{"priority=210,ct_state=-new+trk,ct_mark=0x20,ip,reg0=0x1/0xffff", "resubmit(,40)"},
				{"priority=200,ct_state=+inv+trk,ip", "drop"},
				{"priority=0", "resubmit(,40)"},
			},
		},
		{
			uint8(40),
			[]*ofTestUtils.ExpectFlow{{"priority=0", "resubmit(,50)"}},
		},
		{
			uint8(50),
			[]*ofTestUtils.ExpectFlow{{"priority=0", "resubmit(,60)"}},
		},
		{
			uint8(60),
			[]*ofTestUtils.ExpectFlow{{"priority=0", "resubmit(,70)"}},
		},
		{
			uint8(70),
			[]*ofTestUtils.ExpectFlow{{"priority=0", "resubmit(,80)"}},
		},
		{
			uint8(80),
			[]*ofTestUtils.ExpectFlow{{"priority=0", "resubmit(,90)"}},
		},
		{
			uint8(90),
			[]*ofTestUtils.ExpectFlow{{"priority=0", "resubmit(,100)"}},
		},
		{
			uint8(100),
			[]*ofTestUtils.ExpectFlow{{"priority=0", "resubmit(,105)"}},
		},
		{
			uint8(105),
			[]*ofTestUtils.ExpectFlow{
				{"priority=200,ct_state=+new+trk,ip,reg0=0x1/0xffff", "ct(commit,table=110,zone=65520,exec(load:0x20->NXM_NX_CT_MARK[])"},
				{"priority=190,ct_state=+new+trk,ip", "ct(commit,table=110,zone=65520)"},
				{"priority=0", "resubmit(,110)"}},
		},
		{
			uint8(110),
			[]*ofTestUtils.ExpectFlow{
				{"priority=200,ip,reg0=0x10000/0x10000", "output:NXM_NX_REG1[]"},
			},
		},
	}
}

func prepareIPAddresses(addresses []string) []types.Address {
	var ipAddresses = make([]types.Address, 0)
	for _, addr := range addresses {
		ip := net.ParseIP(addr)
		ipAddresses = append(ipAddresses, ofClient.NewIPAddress(ip))
	}
	return ipAddresses
}

func prepareIPNetAddresses(addresses []string) []types.Address {
	var ipAddresses = make([]types.Address, 0)
	for _, addr := range addresses {
		_, ipNet, _ := net.ParseCIDR(addr)
		ipAddresses = append(ipAddresses, ofClient.NewIPNetAddress(*ipNet))
	}
	return ipAddresses
}
