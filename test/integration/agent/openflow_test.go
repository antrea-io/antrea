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
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/component-base/metrics/testutil"

	config1 "github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/metrics"
	ofClient "github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta1"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	ofconfig "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
	ofTestUtils "github.com/vmware-tanzu/antrea/test/integration/ovs"
)

var (
	br             = "br01"
	c              ofClient.Client
	roundInfo      = types.RoundInfo{RoundNum: 0, PrevRoundNum: nil}
	ovsCtlClient   = ovsctl.NewClient(br)
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
	// Initialize ovs metrics (Prometheus) to test them
	metrics.InitializeOVSMetrics()

	c = ofClient.NewClient(br, bridgeMgmtAddr, true, false)
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
		testExternalFlows,
	} {
		f(t, config)
	}
}

func TestReplayFlowsConnectivityFlows(t *testing.T) {
	c = ofClient.NewClient(br, bridgeMgmtAddr, true, false)
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
	c = ofClient.NewClient(br, bridgeMgmtAddr, true, false)
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
	toList := []string{"192.168.3.4", "192.168.3.5"}

	port2 := intstr.FromInt(8080)
	tcpProtocol := v1beta1.ProtocolTCP
	defaultAction := secv1alpha1.RuleActionAllow
	npPort1 := v1beta1.Service{Protocol: &tcpProtocol, Port: &port2}
	toIPList := prepareIPAddresses(toList)
	rule := &types.PolicyRule{
		Direction: v1beta1.DirectionIn,
		From:      prepareIPAddresses(fromList),
		To:        toIPList,
		Service:   []v1beta1.Service{npPort1},
		Action:    &defaultAction,
		FlowID:    ruleID,
		TableID:   ofClient.IngressRuleTable,
		PolicyRef: &v1beta1.NetworkPolicyReference{
			Type:      v1beta1.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "uid1",
		},
	}

	err = c.InstallPolicyRuleFlows(rule)
	require.Nil(t, err, "Failed to InstallPolicyRuleFlows")

	err = c.AddPolicyRuleAddress(ruleID, types.SrcAddress, prepareIPNetAddresses([]string{"192.168.5.0/24", "192.169.1.0/24"}), nil)
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")
	ofport := int32(100)
	err = c.AddPolicyRuleAddress(ruleID, types.DstAddress, []types.Address{ofClient.NewOFPortAddress(ofport)}, nil)
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")

	testReplayFlows(t)
}

func testExternalFlows(t *testing.T, config *testConfig) {
	nodeIP := net.ParseIP("10.10.10.1")
	_, localSubnet, _ := net.ParseCIDR("172.16.1.0/24")
	if err := c.InstallExternalFlows(nodeIP, *localSubnet); err != nil {
		t.Errorf("Failed to install OpenFlow entries to allow Pod to communicate to the external addresses: %v", err)
	}
	for _, tableFlow := range prepareExternalFlows(nodeIP, localSubnet) {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
	}
}

func testReplayFlows(t *testing.T) {
	var err error

	countFlows := func() int {
		flowList, err := ofTestUtils.OfctlDumpFlows(ovsCtlClient)
		require.Nil(t, err, "Error when dumping flows from OVS bridge")
		return len(flowList)
	}

	count1 := countFlows()
	t.Logf("Counted %d flows before deletion & reconciliation", count1)
	err = ofTestUtils.OfctlDeleteFlows(ovsCtlClient)
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
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
	}
	checkOVSFlowMetrics(t, c)
}

func testInstallTunnelFlows(t *testing.T, config *testConfig) {
	err := c.InitialTLVMap()
	if err != nil {
		t.Fatalf("Failed to install TLV Map: %v", err)
	}
	err = c.InstallDefaultTunnelFlows(config.tunnelOFPort)
	if err != nil {
		t.Fatalf("Failed to install Openflow entries for tunnel port: %v", err)
	}
	for _, tableFlow := range prepareTunnelFlows(config.tunnelOFPort, config.globalMAC) {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
	}
}

func testInstallServiceFlows(t *testing.T, config *testConfig) {
	err := c.InstallClusterServiceFlows()
	if err != nil {
		t.Fatalf("Failed to install Openflow entries to skip service CIDR from egress table: %v", err)
	}
	for _, tableFlow := range prepareServiceHelperFlows() {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
	}
}

func testInstallNodeFlows(t *testing.T, config *testConfig) {
	for _, node := range config.peers {
		err := c.InstallNodeFlows(node.name, config.localGateway.mac, node.subnet, node.gateway, node.nodeAddress, config.tunnelOFPort, 0)
		if err != nil {
			t.Fatalf("Failed to install Openflow entries for node connectivity: %v", err)
		}
		for _, tableFlow := range prepareNodeFlows(config.tunnelOFPort, node.subnet, node.gateway, node.nodeAddress, config.globalMAC, config.localGateway.mac) {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
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
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, false, tableFlow.flows)
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
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
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
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, false, tableFlow.flows)
		}
	}
}

func TestNetworkPolicyFlows(t *testing.T) {
	// Initialize ovs metrics (Prometheus) to test them
	metrics.InitializeOVSMetrics()

	c = ofClient.NewClient(br, bridgeMgmtAddr, true, false)
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
	toList := []string{"192.168.3.4", "192.168.3.5"}

	port2 := intstr.FromInt(8080)
	tcpProtocol := v1beta1.ProtocolTCP
	defaultAction := secv1alpha1.RuleActionAllow
	npPort1 := v1beta1.Service{Protocol: &tcpProtocol, Port: &port2}
	toIPList := prepareIPAddresses(toList)
	rule := &types.PolicyRule{
		Direction: v1beta1.DirectionIn,
		From:      prepareIPAddresses(fromList),
		To:        toIPList,
		Service:   []v1beta1.Service{npPort1},
		Action:    &defaultAction,
		FlowID:    ruleID,
		TableID:   ofClient.IngressRuleTable,
		PolicyRef: &v1beta1.NetworkPolicyReference{
			Type:      v1beta1.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "uid1",
		},
	}
	err = c.InstallPolicyRuleFlows(rule)
	require.Nil(t, err, "Failed to InstallPolicyRuleFlows")
	checkConjunctionFlows(t, ingressRuleTable, ingressDefaultTable, contrackCommitTable, priorityNormal, ruleID, rule, assert.True)
	checkDefaultDropFlows(t, ingressDefaultTable, priorityNormal, types.DstAddress, toIPList, true)

	addedFrom := prepareIPNetAddresses([]string{"192.168.5.0/24", "192.169.1.0/24"})
	checkAddAddress(t, ingressRuleTable, priorityNormal, ruleID, addedFrom, types.SrcAddress)
	checkDeleteAddress(t, ingressRuleTable, priorityNormal, ruleID, addedFrom, types.SrcAddress)

	ofport := int32(100)
	err = c.AddPolicyRuleAddress(ruleID, types.DstAddress, []types.Address{ofClient.NewOFPortAddress(ofport)}, nil)
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")

	// Dump flows.
	flowList, err := ofTestUtils.OfctlDumpTableFlows(ovsCtlClient, ingressRuleTable)
	require.Nil(t, err, "Failed to dump flows")
	conjMatch := fmt.Sprintf("priority=%d,ip,reg1=0x%x", priorityNormal, ofport)
	flow := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: fmt.Sprintf("conjunction(%d,2/3)", ruleID)}
	assert.True(t, ofTestUtils.OfctlFlowMatch(flowList, ingressRuleTable, flow), "Failed to install conjunctive match flow")
	serviceConjMatch := fmt.Sprintf("priority=%d,tcp,tp_dst=8080", priorityNormal)
	flow = &ofTestUtils.ExpectFlow{MatchStr: serviceConjMatch, ActStr: fmt.Sprintf("conjunction(%d,3/3)", ruleID)}
	assert.True(t, ofTestUtils.OfctlFlowMatch(flowList, ingressRuleTable, flow), "Failed to install service flow")

	// Verify multiple conjunctions share the same match conditions.
	ruleID2 := uint32(101)
	toList2 := []string{"192.168.3.4"}
	toIPList2 := prepareIPAddresses(toList2)
	udpProtocol := v1beta1.ProtocolUDP
	npPort2 := v1beta1.Service{Protocol: &udpProtocol}
	rule2 := &types.PolicyRule{
		Direction: v1beta1.DirectionIn,
		To:        toIPList2,
		Service:   []v1beta1.Service{npPort2},
		Action:    &defaultAction,
		FlowID:    ruleID2,
		TableID:   ofClient.IngressRuleTable,
		PolicyRef: &v1beta1.NetworkPolicyReference{
			Type:      v1beta1.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "uid1",
		},
	}
	err = c.InstallPolicyRuleFlows(rule2)
	require.Nil(t, err, "Failed to InstallPolicyRuleFlows")

	// Dump flows
	flowList, err = ofTestUtils.OfctlDumpTableFlows(ovsCtlClient, ingressRuleTable)
	require.Nil(t, err, "Failed to dump flows")
	conjMatch = fmt.Sprintf("priority=%d,ip,nw_dst=192.168.3.4", priorityNormal)
	flow1 := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: fmt.Sprintf("conjunction(%d,2/3),conjunction(%d,1/2)", ruleID, ruleID2)}
	flow2 := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: fmt.Sprintf("conjunction(%d,1/2),conjunction(%d,2/3)", ruleID2, ruleID)}
	serviceConjMatch = fmt.Sprintf("priority=%d,udp", priorityNormal)
	flow3 := &ofTestUtils.ExpectFlow{MatchStr: serviceConjMatch, ActStr: fmt.Sprintf("conjunction(%d,2/2)", ruleID2)}
	if !ofTestUtils.OfctlFlowMatch(flowList, ingressRuleTable, flow1) && !ofTestUtils.OfctlFlowMatch(flowList, ingressRuleTable, flow2) {
		t.Errorf("Failed to install conjunctive match flow")
	}
	require.True(t, ofTestUtils.OfctlFlowMatch(flowList, ingressRuleTable, flow3), "Failed to install service flow")
	checkOVSFlowMetrics(t, c)

	_, err = c.UninstallPolicyRuleFlows(ruleID2)
	require.Nil(t, err, "Failed to InstallPolicyRuleFlows")
	checkDefaultDropFlows(t, ingressDefaultTable, priorityNormal, types.DstAddress, toIPList2, true)

	_, err = c.UninstallPolicyRuleFlows(ruleID)
	require.Nil(t, err, "Failed to DeletePolicyRuleService")
	checkConjunctionFlows(t, ingressRuleTable, ingressDefaultTable, contrackCommitTable, priorityNormal, ruleID, rule, assert.False)
	checkDefaultDropFlows(t, ingressDefaultTable, priorityNormal, types.DstAddress, toIPList, false)
	checkOVSFlowMetrics(t, c)
}

func checkDefaultDropFlows(t *testing.T, table uint8, priority int, addrType types.AddressType, addresses []types.Address, add bool) {
	// dump flows
	flowList, err := ofTestUtils.OfctlDumpTableFlows(ovsCtlClient, table)
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
	err := c.AddPolicyRuleAddress(ruleID, addrType, addedAddress, nil)
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")

	// dump flows
	flowList, err := ofTestUtils.OfctlDumpTableFlows(ovsCtlClient, ruleTable)
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
	err := c.DeletePolicyRuleAddress(ruleID, addrType, addedAddress, nil)
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")
	flowList, err := ofTestUtils.OfctlDumpTableFlows(ovsCtlClient, ruleTable)
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
	flowList, err := ofTestUtils.OfctlDumpTableFlows(ovsCtlClient, ruleTable)
	require.Nil(t, err, "Failed to dump flows")

	conjunctionActionMatch := fmt.Sprintf("priority=%d,conj_id=%d,ip", priority-10, ruleID)
	conjReg := 6
	nextTable := ofClient.IngressMetricTable
	if ruleTable == uint8(ofClient.EgressRuleTable) {
		nextTable = ofClient.EgressMetricTable
	}

	flow := &ofTestUtils.ExpectFlow{MatchStr: conjunctionActionMatch, ActStr: fmt.Sprintf("load:0x%x->NXM_NX_REG%d[],ct(commit,table=%d,zone=65520,exec(load:0x%x->NXM_NX_CT_LABEL[0..31])", ruleID, conjReg, nextTable, ruleID)}
	testFunc(t, ofTestUtils.OfctlFlowMatch(flowList, ruleTable, flow), "Failed to update conjunction action flow")

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

func checkOVSFlowMetrics(t *testing.T, client ofClient.Client) {
	expectedFlowCount := `
	# HELP antrea_agent_ovs_flow_count [STABLE] Flow count for each OVS flow table. The TableID is used as a label.
	# TYPE antrea_agent_ovs_flow_count gauge
	`
	tableStatus := client.GetFlowTableStatus()
	totalFlowCount := 0
	for _, table := range tableStatus {
		expectedFlowCount = expectedFlowCount + fmt.Sprintf("antrea_agent_ovs_flow_count{table_id=\"%d\"} %d\n", table.ID, table.FlowCount)
		totalFlowCount = totalFlowCount + int(table.FlowCount)
	}
	expectedTotalFlowCount := `
	# HELP antrea_agent_ovs_total_flow_count [STABLE] Total flow count of all OVS flow tables.
	# TYPE antrea_agent_ovs_total_flow_count gauge
	`
	expectedTotalFlowCount = expectedTotalFlowCount + fmt.Sprintf("antrea_agent_ovs_total_flow_count %d\n", totalFlowCount)

	assert.Equal(t, nil, testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedTotalFlowCount), "antrea_agent_ovs_total_flow_count"))
	assert.Equal(t, nil, testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedFlowCount), "antrea_agent_ovs_flow_count"))

}

func testInstallGatewayFlows(t *testing.T, config *testConfig) {
	err := c.InstallGatewayFlows(config.localGateway.ip, config.localGateway.mac, config.localGateway.ofPort)
	if err != nil {
		t.Fatalf("Failed to install Openflow entries for gateway: %v", err)
	}
	for _, tableFlow := range prepareGatewayFlows(config.localGateway.ip, config.localGateway.mac, config.localGateway.ofPort, config.globalMAC) {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
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
				{
					MatchStr: fmt.Sprintf("priority=190,in_port=%d", podOFPort),
					ActStr:   "load:0x2->NXM_NX_REG0[0..15],goto_table:10",
				},
			},
		},
		{
			uint8(10),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,ip,in_port=%d,dl_src=%s,nw_src=%s", podOFPort, podMAC.String(), podIP.String()),
					ActStr:   "goto_table:29",
				},
				{
					MatchStr: fmt.Sprintf("priority=200,arp,in_port=%d,arp_spa=%s,arp_sha=%s", podOFPort, podIP.String(), podMAC.String()),
					ActStr:   "goto_table:20",
				},
			},
		},
		{
			uint8(70),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,ip,reg0=0x80000/0x80000,nw_dst=%s", podIP.String()),
					ActStr:   fmt.Sprintf("set_field:%s->eth_src,set_field:%s->eth_dst,dec_ttl,goto_table:80", gwMAC.String(), podMAC.String()),
				},
			},
		},
		{
			uint8(80),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,dl_dst=%s", podMAC.String()),
					ActStr:   fmt.Sprintf("load:0x%x->NXM_NX_REG1[],load:0x1->NXM_NX_REG0[16],goto_table:90", podOFPort),
				},
			},
		},
	}
}

func prepareGatewayFlows(gwIP net.IP, gwMAC net.HardwareAddr, gwOFPort uint32, vMAC net.HardwareAddr) []expectTableFlows {
	return []expectTableFlows{
		{
			uint8(0),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,in_port=%d", gwOFPort),
					ActStr:   "load:0x1->NXM_NX_REG0[0..15],goto_table:10",
				},
			},
		},
		{
			uint8(31),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: "priority=200,ct_state=-new+trk,ct_mark=0x20,ip",
					ActStr:   fmt.Sprintf("load:0x%s->NXM_OF_ETH_DST[],goto_table:42", strings.Replace(gwMAC.String(), ":", "", -1)),
				},
			},
		},
		{
			uint8(10),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,arp,in_port=%d,arp_spa=%s,arp_sha=%s", gwOFPort, gwIP, gwMAC),
					ActStr:   "goto_table:20",
				},
				{
					MatchStr: fmt.Sprintf("priority=200,ip,in_port=%d", gwOFPort),
					ActStr:   "goto_table:29",
				},
			},
		},
		{
			uint8(70),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,ip,dl_dst=%s,nw_dst=%s", vMAC.String(), gwIP.String()),
					ActStr:   fmt.Sprintf("set_field:%s->eth_dst,goto_table:80", gwMAC.String()),
				},
			},
		},
		{
			uint8(80),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,dl_dst=%s", gwMAC.String()),
					ActStr:   fmt.Sprintf("load:0x%x->NXM_NX_REG1[],load:0x1->NXM_NX_REG0[16],goto_table:90", gwOFPort),
				},
			},
		},
		{
			uint8(90),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=210,ip,nw_src=%s", gwIP.String()),
					ActStr:   "goto_table:105",
				},
			},
		},
	}
}

func prepareTunnelFlows(tunnelPort uint32, vMAC net.HardwareAddr) []expectTableFlows {
	return []expectTableFlows{
		{
			uint8(0),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,in_port=%d", tunnelPort),
					ActStr:   "load:0->NXM_NX_REG0[0..15],load:0x1->NXM_NX_REG0[19],goto_table:30",
				},
			},
		},
	}
}

func prepareNodeFlows(tunnelPort uint32, peerSubnet net.IPNet, peerGwIP, peerNodeIP net.IP, vMAC, localGwMAC net.HardwareAddr) []expectTableFlows {
	return []expectTableFlows{
		{
			uint8(20),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,arp,arp_tpa=%s,arp_op=1", peerGwIP.String()),
					ActStr:   fmt.Sprintf("move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:%s->eth_src,load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],set_field:%s->arp_sha,move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:%s->arp_spa,IN_PORT", vMAC.String(), vMAC.String(), peerGwIP.String()),
				},
			},
		},
		{
			uint8(70),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,ip,nw_dst=%s", peerSubnet.String()),
					ActStr:   fmt.Sprintf("dec_ttl,set_field:%s->eth_src,set_field:%s->eth_dst,load:0x%x->NXM_NX_REG1[],load:0x1->NXM_NX_REG0[16],set_field:%s->tun_dst,goto_table:105", localGwMAC.String(), vMAC.String(), tunnelPort, peerNodeIP.String()),
				},
			},
		},
	}
}

func prepareServiceHelperFlows() []expectTableFlows {
	return []expectTableFlows{
		{
			uint8(40),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprint("priority=0"),
					ActStr:   fmt.Sprint("load:0x1->NXM_NX_REG4[16..18]"),
				},
			},
		},
	}
}

func prepareDefaultFlows() []expectTableFlows {
	return []expectTableFlows{
		{
			uint8(0),
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "drop"}},
		},
		{
			uint8(10),
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "drop"}},
		},
		{
			uint8(20),
			[]*ofTestUtils.ExpectFlow{
				{MatchStr: "priority=190,arp", ActStr: "NORMAL"},
				{MatchStr: "priority=0", ActStr: "drop"},
			},
		},
		{
			uint8(30),
			[]*ofTestUtils.ExpectFlow{
				{MatchStr: "priority=200,ip", ActStr: "ct(table=31,zone=65520,nat)"},
			},
		},
		{
			uint8(31),
			[]*ofTestUtils.ExpectFlow{
				{MatchStr: "priority=210,ct_state=-new+trk,ct_mark=0x20,ip,reg0=0x1/0xffff", ActStr: "goto_table:42"},
				{MatchStr: "priority=190,ct_state=+inv+trk,ip", ActStr: "drop"},
				{MatchStr: "priority=0", ActStr: "resubmit(,40),resubmit(,41)"},
			},
		},
		{
			uint8(42),
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:50"}},
		},
		{
			uint8(50),
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:60"}},
		},
		{
			uint8(60),
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:61"}},
		},
		{
			uint8(61),
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:70"}},
		},
		{
			uint8(70),
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:80"}},
		},
		{
			uint8(80),
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:90"}},
		},
		{
			uint8(90),
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:100"}},
		},
		{
			uint8(100),
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:101"}},
		},
		{
			uint8(101),
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:105"}},
		},
		{
			uint8(105),
			[]*ofTestUtils.ExpectFlow{
				{MatchStr: "priority=200,ct_state=+new+trk,ip,reg0=0x1/0xffff", ActStr: "ct(commit,table=106,zone=65520,exec(load:0x20->NXM_NX_CT_MARK[])"},
				{MatchStr: "priority=190,ct_state=+new+trk,ip", ActStr: "ct(commit,table=106,zone=65520)"},
				{MatchStr: "priority=0", ActStr: "goto_table:106"}},
		},
		{
			uint8(110),
			[]*ofTestUtils.ExpectFlow{
				{MatchStr: "priority=200,ip,reg0=0x10000/0x10000", ActStr: "output:NXM_NX_REG1[]"},
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

func prepareExternalFlows(nodeIP net.IP, localSubnet *net.IPNet) []expectTableFlows {
	return []expectTableFlows{
		{
			uint8(0),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=210,ip,in_port=LOCAL,nw_dst=%s", localSubnet.String()),
					ActStr:   "load:0x1->NXM_NX_REG0[19],goto_table:30",
				},
			},
		},
		{
			uint8(5),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,ip"),
					ActStr:   "load:0x4->NXM_NX_REG0[0..15],goto_table:30",
				},
			},
		},
		{
			uint8(30),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: "priority=200,ip", ActStr: "ct(table=31,zone=65520,nat)",
				},
			},
		},
		{
			uint8(31),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: "priority=210,ct_state=-new+trk,ct_mark=0x40,ip,reg0=0x4/0xffff",
					ActStr:   "load:0xaabbccddeeff->NXM_OF_ETH_DST[],load:0x1->NXM_NX_REG0[19],goto_table:42",
				},
				{
					MatchStr: "priority=200,ct_state=-new+trk,ct_mark=0x40,ip",
					ActStr:   "goto_table:42",
				},
				{
					MatchStr: fmt.Sprintf("priority=200,ip,in_port=%d", config1.UplinkOFPort),
					ActStr:   "LOCAL",
				},
			},
		},
		{
			uint8(70),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: "priority=200,ct_mark=0x20,ip,reg0=0x2/0xffff", ActStr: "goto_table:80",
				},
				{
					MatchStr: fmt.Sprintf("priority=190,ip,reg0=0x2/0xffff,nw_dst=%s", nodeIP.String()),
					ActStr:   "goto_table:80",
				},
				{
					MatchStr: "priority=180,ip,reg0=0x2/0xffff",
					ActStr:   "load:0x1->NXM_NX_REG0[17],goto_table:90",
				},
			},
		},
		{
			uint8(105),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: "priority=200,ct_state=+new+trk,ip,reg0=0x20000/0x20000",
					ActStr:   fmt.Sprintf("ct(commit,table=110,zone=65520,nat(src=%s),exec(load:0x40->NXM_NX_CT_MARK[]))", nodeIP.String()),
				},
			},
		},
		{
			uint8(110),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: "priority=200,ip,reg0=0x20000/0x20000",
					ActStr:   fmt.Sprintf("output:%d", config1.HostGatewayOFPort),
				},
			},
		},
	}
}
