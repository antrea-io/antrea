//go:build linux
// +build linux

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
	"encoding/hex"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/component-base/metrics/legacyregistry"

	agentconfig "antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/metrics"
	nodeiptest "antrea.io/antrea/pkg/agent/nodeip/testing"
	ofClient "antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	k8stypes "antrea.io/antrea/pkg/agent/proxy/types"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	ofconfig "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	utilip "antrea.io/antrea/pkg/util/ip"
	antrearuntime "antrea.io/antrea/pkg/util/runtime"
	ofTestUtils "antrea.io/antrea/test/integration/ovs"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

var (
	br                  = "br01"
	c                   ofClient.Client
	roundInfo           = types.RoundInfo{RoundNum: 0, PrevRoundNum: nil}
	ovsCtlClient        = ovsctl.NewClient(br)
	bridgeMgmtAddr      = ofconfig.GetMgmtAddress(ovsconfig.DefaultOVSRunDir, br)
	groupIDAllocator    = ofClient.NewGroupAllocator()
	defaultPacketInRate = 500
)

const (
	ingressRuleTable    = "IngressRule"
	ingressDefaultTable = "IngressDefaultRule"
	priorityNormal      = 200
)

type expectTableFlows struct {
	tableName string
	flows     []*ofTestUtils.ExpectFlow
}

type testPortConfig struct {
	ips    []net.IP
	mac    net.HardwareAddr
	ofPort uint32
	vlanID uint16
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
	nodeMAC     net.HardwareAddr
}

type testConfig struct {
	bridge                       string
	nodeConfig                   *agentconfig.NodeConfig
	localPods                    []*testLocalPodConfig
	peers                        []*testPeerConfig
	globalMAC                    net.HardwareAddr
	enableIPv6                   bool
	enableIPv4                   bool
	connectUplinkToBridge        bool
	enableStretchedNetworkPolicy bool
}

var (
	_, podIPv4CIDR, _ = net.ParseCIDR("192.168.1.0/24")
	_, podIPv6CIDR, _ = net.ParseCIDR("fd74:ca9b:172:19::/64")
)

func TestConnectivityFlows(t *testing.T) {
	// Reset OVS metrics (Prometheus) and reinitialize them to test.
	legacyregistry.Reset()
	metrics.InitializeOVSMetrics()

	// Hack the OS type if we run the test not on Windows Node.
	// Because we test some Windows only functions.
	if !antrearuntime.IsWindowsPlatform() {
		antrearuntime.WindowsOS = runtime.GOOS
	}

	c = ofClient.NewClient(br, bridgeMgmtAddr, nodeiptest.NewFakeNodeIPChecker(), true, false, false, true, true, false, false, false, false, false, false, false, false, groupIDAllocator, false, defaultPacketInRate)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))
	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
		ofClient.CleanOFTableCache()
		ofClient.ResetOFTable()
	}()

	config := prepareConfiguration(true, false, false)

	t.Run("testInitialize", func(t *testing.T) {
		testInitialize(t, config)
	})
	t.Run("testInstallGatewayFlows", func(t *testing.T) {
		testInstallGatewayFlows(t, config)
	})
	t.Run("testInstallServiceFlows", func(t *testing.T) {
		testInstallServiceFlows(t, config)
	})
	t.Run("testInstallTunnelFlows", func(t *testing.T) {
		testInstallTunnelFlows(t, config)
	})
	t.Run("testInstallNodeFlows", func(t *testing.T) {
		testInstallNodeFlows(t, config)
	})
	t.Run("testInstallPodFlows", func(t *testing.T) {
		testInstallPodFlows(t, config)
	})
	t.Run("testUninstallPodFlows", func(t *testing.T) {
		testUninstallPodFlows(t, config)
	})
	t.Run("testUninstallNodeFlows", func(t *testing.T) {
		testUninstallNodeFlows(t, config)
	})
	t.Run("testExternalFlows", func(t *testing.T) {
		testExternalFlows(t, config)
	})

	stretchedNetworkPolicyConfig := prepareConfiguration(true, false, true)
	t.Run("testInstallPodFlows", func(t *testing.T) {
		testInstallPodFlows(t, stretchedNetworkPolicyConfig)
	})
	t.Run("testUninstallPodFlows", func(t *testing.T) {
		testUninstallPodFlows(t, stretchedNetworkPolicyConfig)
	})
}

func TestAntreaFlexibleIPAMConnectivityFlows(t *testing.T) {
	// Reset OVS metrics (Prometheus) and reinitialize them to test.
	legacyregistry.Reset()
	metrics.InitializeOVSMetrics()

	c = ofClient.NewClient(br, bridgeMgmtAddr, nodeiptest.NewFakeNodeIPChecker(), true, false, false, true, true, false, false, false, true, false, false, false, false, groupIDAllocator, false, defaultPacketInRate)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))
	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
		ofClient.CleanOFTableCache()
		ofClient.ResetOFTable()
	}()

	config := prepareConfiguration(true, false, false)
	config.connectUplinkToBridge = true
	config.localPods[0].ips = []net.IP{net.ParseIP("192.168.255.3")}
	vlanID := uint16(100)
	podMAC, _ := net.ParseMAC("aa:aa:aa:aa:aa:14")
	config.localPods = append(config.localPods, &testLocalPodConfig{
		name: "container-2",
		testPortConfig: &testPortConfig{
			ips:    []net.IP{net.ParseIP("192.168.255.3")},
			mac:    podMAC,
			ofPort: uint32(12),
			vlanID: vlanID,
		},
	})
	uplinkMAC, _ := net.ParseMAC("aa:aa:aa:aa:aa:00")
	config.nodeConfig.UplinkNetConfig = &agentconfig.AdapterNetConfig{
		Name:  "fake-uplink",
		Index: 0,
		MAC:   uplinkMAC,
		IPs: []*net.IPNet{
			{
				IP:   nil,
				Mask: nil,
			},
		},
		Gateway:    "",
		DNSServers: "",
		Routes:     nil,
		OFPort:     uint32(agentconfig.UplinkOFPort),
	}
	config.nodeConfig.HostInterfaceOFPort = agentconfig.BridgeOFPort
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
	// Reset OVS metrics (Prometheus) and reinitialize them to test.
	legacyregistry.Reset()
	metrics.InitializeOVSMetrics()

	c = ofClient.NewClient(br, bridgeMgmtAddr, nodeiptest.NewFakeNodeIPChecker(), true, false, false, true, true, false, false, false, false, false, false, false, false, groupIDAllocator, false, defaultPacketInRate)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))

	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
		ofClient.CleanOFTableCache()
		ofClient.ResetOFTable()
	}()

	config := prepareConfiguration(true, false, false)
	t.Run("testInitialize", func(t *testing.T) {
		testInitialize(t, config)
	})
	t.Run("testInstallGatewayFlows", func(t *testing.T) {
		testInstallGatewayFlows(t, config)
	})
	t.Run("testInstallServiceFlows", func(t *testing.T) {
		testInstallServiceFlows(t, config)
	})
	t.Run("testInstallTunnelFlows", func(t *testing.T) {
		testInstallTunnelFlows(t, config)
	})
	t.Run("testInstallNodeFlows", func(t *testing.T) {
		testInstallNodeFlows(t, config)
	})
	t.Run("testInstallPodFlows", func(t *testing.T) {
		testInstallPodFlows(t, config)
	})
	t.Run("testReplayFlows", func(t *testing.T) {
		testReplayFlows(t)
	})
}

func TestReplayFlowsNetworkPolicyFlows(t *testing.T) {
	// Reset OVS metrics (Prometheus) and reinitialize them to test.
	legacyregistry.Reset()
	metrics.InitializeOVSMetrics()

	c = ofClient.NewClient(br, bridgeMgmtAddr, nodeiptest.NewFakeNodeIPChecker(), true, false, false, false, false, false, false, false, false, false, false, false, false, groupIDAllocator, false, defaultPacketInRate)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))

	config := prepareConfiguration(true, false, false)
	_, err = c.Initialize(roundInfo, config.nodeConfig, &agentconfig.NetworkConfig{TrafficEncapMode: agentconfig.TrafficEncapModeEncap, IPv4Enabled: true}, &agentconfig.EgressConfig{}, &agentconfig.ServiceConfig{}, &agentconfig.L7NetworkPolicyConfig{})
	require.Nil(t, err, "Failed to initialize OFClient")

	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
		ofClient.CleanOFTableCache()
		ofClient.ResetOFTable()
	}()

	ruleID := uint32(100)
	fromList := []string{"192.168.1.3", "192.168.1.25", "192.168.2.4"}
	toList := []string{"192.168.3.4", "192.168.3.5"}

	port2 := intstr.FromInt(8080)
	tcpProtocol := v1beta2.ProtocolTCP
	defaultAction := crdv1beta1.RuleActionAllow
	npPort1 := v1beta2.Service{Protocol: &tcpProtocol, Port: &port2}
	toIPList := prepareIPAddresses(toList)
	rule := &types.PolicyRule{
		Direction: v1beta2.DirectionIn,
		From:      prepareIPAddresses(fromList),
		To:        toIPList,
		Service:   []v1beta2.Service{npPort1},
		Action:    &defaultAction,
		FlowID:    ruleID,
		TableID:   ofClient.IngressRuleTable.GetID(),
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "uid1",
		},
	}

	err = c.InstallPolicyRuleFlows(rule)
	require.Nil(t, err, "Failed to InstallPolicyRuleFlows")

	err = c.AddPolicyRuleAddress(ruleID, types.SrcAddress, prepareIPNetAddresses([]string{"192.168.5.0/24", "192.169.1.0/24"}), nil, false, false)
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")
	ofport := int32(100)
	err = c.AddPolicyRuleAddress(ruleID, types.DstAddress, []types.Address{ofClient.NewOFPortAddress(ofport)}, nil, false, false)
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")

	testReplayFlows(t)
}

func testExternalFlows(t *testing.T, config *testConfig) {
	gwMACStr := config.nodeConfig.GatewayConfig.MAC.String()
	if config.enableIPv4 {
		for _, tableFlow := range expectedExternalFlows("ip", gwMACStr) {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, true, tableFlow.flows)
		}
	}
	if config.enableIPv6 {
		for _, tableFlow := range expectedExternalFlows("ipv6", gwMACStr) {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, true, tableFlow.flows)
		}
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
	err = ofTestUtils.OfctlDeleteGroups(ovsCtlClient)
	require.Nil(t, err, "Error when deleting groups from OVS bridge")
	count2 := countFlows()
	assert.Zero(t, count2, "Expected no flows after deletion")
	c.ReplayFlows()
	count3 := countFlows()
	t.Logf("Counted %d flows after reconciliation", count3)
	assert.Equal(t, count1, count3, "Expected same number of flows after reconciliation")
}

func testInitialize(t *testing.T, config *testConfig) {
	if _, err := c.Initialize(roundInfo, config.nodeConfig, &agentconfig.NetworkConfig{TrafficEncapMode: agentconfig.TrafficEncapModeEncap, IPv4Enabled: config.enableIPv4, IPv6Enabled: config.enableIPv6}, &agentconfig.EgressConfig{}, &agentconfig.ServiceConfig{}, &agentconfig.L7NetworkPolicyConfig{}); err != nil {
		t.Errorf("Failed to initialize openflow client: %v", err)
	}
	for _, tableFlow := range prepareDefaultFlows(config) {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, true, tableFlow.flows)
	}
	checkOVSFlowMetrics(t, c)
}

func testInstallTunnelFlows(t *testing.T, config *testConfig) {
	for _, tableFlow := range prepareTunnelFlows(agentconfig.DefaultTunOFPort, config.globalMAC) {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, true, tableFlow.flows)
	}
}

func testInstallServiceFlows(t *testing.T, config *testConfig) {
	for _, tableFlow := range prepareServiceHelperFlows() {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, true, tableFlow.flows)
	}
}

func testInstallNodeFlows(t *testing.T, config *testConfig) {
	gatewayConfig := config.nodeConfig.GatewayConfig
	for _, node := range config.peers {
		peerConfigs := map[*net.IPNet]net.IP{
			&node.subnet: node.gateway,
		}
		dsIPs := new(utilip.DualStackIPs)
		if node.gateway.To4() == nil {
			dsIPs.IPv6 = node.nodeAddress
		} else {
			dsIPs.IPv4 = node.nodeAddress
		}
		err := c.InstallNodeFlows(node.name, peerConfigs, dsIPs, 0, node.nodeMAC)
		if err != nil {
			t.Fatalf("Failed to install Openflow entries for node connectivity: %v", err)
		}
		for _, tableFlow := range prepareNodeFlows(node.subnet, node.gateway, node.nodeAddress, config.globalMAC, gatewayConfig.MAC, node.nodeMAC, config.connectUplinkToBridge) {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, true, tableFlow.flows)
		}
	}
}

func testUninstallNodeFlows(t *testing.T, config *testConfig) {
	gatewayConfig := config.nodeConfig.GatewayConfig
	for _, node := range config.peers {
		err := c.UninstallNodeFlows(node.name)
		if err != nil {
			t.Fatalf("Failed to uninstall Openflow entries for node connectivity: %v", err)
		}
		for _, tableFlow := range prepareNodeFlows(node.subnet, node.gateway, node.nodeAddress, config.globalMAC, gatewayConfig.MAC, node.nodeMAC, config.connectUplinkToBridge) {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, false, tableFlow.flows)
		}
	}
}

func testInstallPodFlows(t *testing.T, config *testConfig) {
	gatewayConfig := config.nodeConfig.GatewayConfig
	for _, pod := range config.localPods {
		var err error
		if config.enableStretchedNetworkPolicy {
			labelIdentity := ofClient.UnknownLabelIdentity
			err = c.InstallPodFlows(pod.name, pod.ips, pod.mac, pod.ofPort, pod.vlanID, &labelIdentity)
		} else {
			err = c.InstallPodFlows(pod.name, pod.ips, pod.mac, pod.ofPort, pod.vlanID, nil)
		}
		if err != nil {
			t.Fatalf("Failed to install Openflow entries for pod: %v", err)
		}
		for _, tableFlow := range preparePodFlows(pod.ips, pod.mac, pod.ofPort, gatewayConfig.MAC, config.globalMAC, config.nodeConfig, config.connectUplinkToBridge, pod.vlanID, config.enableStretchedNetworkPolicy) {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, true, tableFlow.flows)
		}
	}
}

func testUninstallPodFlows(t *testing.T, config *testConfig) {
	gatewayConfig := config.nodeConfig.GatewayConfig
	for _, pod := range config.localPods {
		err := c.UninstallPodFlows(pod.name)
		if err != nil {
			t.Fatalf("Failed to uninstall Openflow entries for pod: %v", err)
		}
		for _, tableFlow := range preparePodFlows(pod.ips, pod.mac, pod.ofPort, gatewayConfig.MAC, config.globalMAC, config.nodeConfig, config.connectUplinkToBridge, pod.vlanID, config.enableStretchedNetworkPolicy) {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, false, tableFlow.flows)
		}
	}
}

func TestNetworkPolicyFlows(t *testing.T) {
	// Reset OVS metrics (Prometheus) and reinitialize them to test.
	legacyregistry.Reset()
	metrics.InitializeOVSMetrics()

	c = ofClient.NewClient(br, bridgeMgmtAddr, nodeiptest.NewFakeNodeIPChecker(), true, false, false, false, false, false, false, false, false, false, false, false, false, groupIDAllocator, false, defaultPacketInRate)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge %s", br))

	config := prepareConfiguration(true, true, false)
	_, err = c.Initialize(roundInfo, config.nodeConfig, &agentconfig.NetworkConfig{TrafficEncapMode: agentconfig.TrafficEncapModeEncap, IPv4Enabled: true, IPv6Enabled: true}, &agentconfig.EgressConfig{}, &agentconfig.ServiceConfig{}, &agentconfig.L7NetworkPolicyConfig{})
	require.Nil(t, err, "Failed to initialize OFClient")

	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
		ofClient.CleanOFTableCache()
		ofClient.ResetOFTable()
	}()

	ruleID := uint32(100)
	fromList := []string{"192.168.1.3", "192.168.1.25", "192.168.2.4", "fd12:ab:34:a001::3"}
	toList := []string{"192.168.3.4", "192.168.3.5", "fd12:ab:34:a002::4"}

	port2 := intstr.FromInt(8080)
	tcpProtocol := v1beta2.ProtocolTCP
	defaultAction := crdv1beta1.RuleActionAllow
	npPort1 := v1beta2.Service{Protocol: &tcpProtocol, Port: &port2}
	toIPList := prepareIPAddresses(toList)
	rule := &types.PolicyRule{
		Direction: v1beta2.DirectionIn,
		From:      prepareIPAddresses(fromList),
		To:        toIPList,
		Service:   []v1beta2.Service{npPort1},
		Action:    &defaultAction,
		FlowID:    ruleID,
		TableID:   ofClient.IngressRuleTable.GetID(),
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "np1",
			UID:       "uid1",
		},
	}
	err = c.InstallPolicyRuleFlows(rule)
	require.Nil(t, err, "Failed to InstallPolicyRuleFlows")
	checkConjunctionFlows(t, ingressRuleTable, priorityNormal, ruleID, rule, assert.True)
	checkDefaultDropFlows(t, ingressDefaultTable, priorityNormal, types.DstAddress, toIPList, true)

	addedFrom := prepareIPNetAddresses([]string{"192.168.5.0/24", "192.169.1.0/24", "fd12:ab:34:a003::/64"})
	checkAddAddress(t, ingressRuleTable, priorityNormal, ruleID, addedFrom, types.SrcAddress)
	checkDeleteAddress(t, ingressRuleTable, priorityNormal, ruleID, addedFrom, types.SrcAddress)

	ofport := int32(100)
	err = c.AddPolicyRuleAddress(ruleID, types.DstAddress, []types.Address{ofClient.NewOFPortAddress(ofport)}, nil, false, false)
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")

	// Dump flows.
	flowList, err := ofTestUtils.OfctlDumpTableFlows(ovsCtlClient, ingressRuleTable)
	require.Nil(t, err, "Failed to dump flows")
	conjMatch := fmt.Sprintf("priority=%d,reg1=0x%x", priorityNormal, ofport)
	flow := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: fmt.Sprintf("conjunction(%d,2/3)", ruleID)}
	assert.True(t, ofTestUtils.OfctlFlowMatch(flowList, ingressRuleTable, flow), "Failed to install conjunctive match flow")

	// Verify multiple conjunctions share the same match conditions.
	ruleID2 := uint32(101)
	toList2 := []string{"192.168.3.4", "fd12:ab:34:a002::4"}
	toIPList2 := prepareIPAddresses(toList2)
	udpProtocol := v1beta2.ProtocolUDP
	npPort2 := v1beta2.Service{Protocol: &udpProtocol}
	rule2 := &types.PolicyRule{
		Direction: v1beta2.DirectionIn,
		To:        toIPList2,
		Service:   []v1beta2.Service{npPort2},
		Action:    &defaultAction,
		FlowID:    ruleID2,
		TableID:   ofClient.IngressRuleTable.GetID(),
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
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
	for _, addr := range toIPList2 {
		_, ipProto := getIPProtoStr(addr)
		conjMatch = fmt.Sprintf("priority=%d,%s,%s=%s", priorityNormal, ipProto, addr.GetMatchKey(types.DstAddress).GetKeyString(), addr.GetMatchValue())
		flow1 := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: fmt.Sprintf("conjunction(%d,2/3),conjunction(%d,1/2)", ruleID, ruleID2)}
		flow2 := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: fmt.Sprintf("conjunction(%d,1/2),conjunction(%d,2/3)", ruleID2, ruleID)}
		if !ofTestUtils.OfctlFlowMatch(flowList, ingressRuleTable, flow1) && !ofTestUtils.OfctlFlowMatch(flowList, ingressRuleTable, flow2) {
			t.Errorf("Failed to install conjunctive match flow")
		}
	}
	checkOVSFlowMetrics(t, c)

	_, err = c.UninstallPolicyRuleFlows(ruleID2)
	require.Nil(t, err, "Failed to InstallPolicyRuleFlows")
	checkDefaultDropFlows(t, ingressDefaultTable, priorityNormal, types.DstAddress, toIPList2, true)

	_, err = c.UninstallPolicyRuleFlows(ruleID)
	require.Nil(t, err, "Failed to DeletePolicyRuleService")
	checkConjunctionFlows(t, ingressRuleTable, priorityNormal, ruleID, rule, assert.False)
	checkDefaultDropFlows(t, ingressDefaultTable, priorityNormal, types.DstAddress, toIPList, false)
	checkOVSFlowMetrics(t, c)
}

func TestIPv6ConnectivityFlows(t *testing.T) {
	// Reset OVS metrics (Prometheus) and reinitialize them to test.
	legacyregistry.Reset()
	metrics.InitializeOVSMetrics()

	c = ofClient.NewClient(br, bridgeMgmtAddr, nodeiptest.NewFakeNodeIPChecker(), true, false, false, true, true, false, false, false, false, false, false, false, false, groupIDAllocator, false, defaultPacketInRate)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))

	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
		ofClient.CleanOFTableCache()
		ofClient.ResetOFTable()
	}()
	config := prepareConfiguration(false, true, false)
	t.Run("testInitialize", func(t *testing.T) {
		testInitialize(t, config)
	})
	t.Run("testInstallNodeFlows", func(t *testing.T) {
		testInstallNodeFlows(t, config)
	})
	t.Run("testInstallPodFlows", func(t *testing.T) {
		testInstallPodFlows(t, config)
	})
	t.Run("testInstallGatewayFlows", func(t *testing.T) {
		testInstallGatewayFlows(t, config)
	})
	t.Run("testUninstallPodFlows", func(t *testing.T) {
		testUninstallPodFlows(t, config)
	})
	t.Run("testUninstallNodeFlows", func(t *testing.T) {
		testUninstallNodeFlows(t, config)
	})
	t.Run("testExternalFlows", func(t *testing.T) {
		testExternalFlows(t, config)
	})
}

func TestProxyServiceFlowsAntreaPolicyDisabled(t *testing.T) {
	// Reset OVS metrics (Prometheus) and reinitialize them to test.
	legacyregistry.Reset()
	metrics.InitializeOVSMetrics()

	c = ofClient.NewClient(br, bridgeMgmtAddr, nodeiptest.NewFakeNodeIPChecker(), true, false, false, false, false, false, false, false, false, false, false, false, false, groupIDAllocator, false, defaultPacketInRate)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge %s", br))

	config := prepareConfiguration(true, false, false)
	_, err = c.Initialize(roundInfo, config.nodeConfig, &agentconfig.NetworkConfig{TrafficEncapMode: agentconfig.TrafficEncapModeEncap, IPv4Enabled: true}, &agentconfig.EgressConfig{}, &agentconfig.ServiceConfig{}, &agentconfig.L7NetworkPolicyConfig{})
	require.Nil(t, err, "Failed to initialize OFClient")

	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
		ofClient.CleanOFTableCache()
		ofClient.ResetOFTable()
	}()

	endpoints := []k8sproxy.Endpoint{
		k8stypes.NewEndpointInfo(&k8sproxy.BaseEndpointInfo{
			Endpoint: net.JoinHostPort("192.168.1.2", "8081"),
			IsLocal:  true,
		}),
		k8stypes.NewEndpointInfo(&k8sproxy.BaseEndpointInfo{
			Endpoint: net.JoinHostPort("10.20.1.11", "8081"),
			IsLocal:  false,
			NodeName: "node1",
		}),
	}

	stickyMaxAgeSeconds := uint16(30)

	tcs := []struct {
		svc       *types.ServiceConfig
		endpoints []k8sproxy.Endpoint
		stickyAge uint16
	}{
		{
			svc: &types.ServiceConfig{
				Protocol:        ofconfig.ProtocolTCP,
				ServiceIP:       net.ParseIP("10.20.30.41"),
				ServicePort:     uint16(8000),
				ClusterGroupID:  2,
				AffinityTimeout: stickyMaxAgeSeconds,
			},
			endpoints: endpoints,
		},
		{
			svc: &types.ServiceConfig{
				Protocol:        ofconfig.ProtocolUDP,
				ServiceIP:       net.ParseIP("10.20.30.42"),
				ServicePort:     uint16(8000),
				ClusterGroupID:  3,
				AffinityTimeout: stickyMaxAgeSeconds,
			},
			endpoints: endpoints,
		},
		{
			svc: &types.ServiceConfig{
				Protocol:        ofconfig.ProtocolSCTP,
				ServiceIP:       net.ParseIP("10.20.30.43"),
				ServicePort:     uint16(8000),
				ClusterGroupID:  4,
				AffinityTimeout: stickyMaxAgeSeconds,
			},
			endpoints: endpoints,
		},
	}

	for _, tc := range tcs {
		groupID := tc.svc.ClusterGroupID
		expTableFlows, expGroupBuckets := expectedProxyServiceGroupAndFlows(tc.svc, tc.endpoints, false)
		installServiceFlows(t, tc.svc, tc.endpoints)
		for _, tableFlow := range expTableFlows {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, true, tableFlow.flows)
		}
		ofTestUtils.CheckGroupExists(t, ovsCtlClient, groupID, "select", expGroupBuckets, true)

		uninstallServiceFlowsFunc(t, tc.svc, tc.endpoints)
		for _, tableFlow := range expTableFlows {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, false, tableFlow.flows)
		}
		ofTestUtils.CheckGroupExists(t, ovsCtlClient, groupID, "select", expGroupBuckets, false)
	}
}

func TestProxyServiceFlowsAntreaPoilcyEnabled(t *testing.T) {
	// Reset OVS metrics (Prometheus) and reinitialize them to test.
	legacyregistry.Reset()
	metrics.InitializeOVSMetrics()

	c = ofClient.NewClient(br, bridgeMgmtAddr, nodeiptest.NewFakeNodeIPChecker(), true, true, false, false, false, false, false, false, false, false, false, false, false, groupIDAllocator, false, defaultPacketInRate)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge %s", br))

	config := prepareConfiguration(true, false, false)
	_, err = c.Initialize(roundInfo, config.nodeConfig, &agentconfig.NetworkConfig{TrafficEncapMode: agentconfig.TrafficEncapModeEncap, IPv4Enabled: true}, &agentconfig.EgressConfig{}, &agentconfig.ServiceConfig{}, &agentconfig.L7NetworkPolicyConfig{})
	require.Nil(t, err, "Failed to initialize OFClient")

	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
		ofClient.CleanOFTableCache()
		ofClient.ResetOFTable()
	}()

	endpoints := []k8sproxy.Endpoint{
		k8stypes.NewEndpointInfo(&k8sproxy.BaseEndpointInfo{
			Endpoint: net.JoinHostPort("192.168.1.2", "8081"),
			IsLocal:  true,
		}),
		k8stypes.NewEndpointInfo(&k8sproxy.BaseEndpointInfo{
			Endpoint: net.JoinHostPort("10.20.1.11", "8081"),
			IsLocal:  false,
			NodeName: "node1",
		}),
	}

	stickyMaxAgeSeconds := uint16(30)

	tcs := []struct {
		svc       *types.ServiceConfig
		endpoints []k8sproxy.Endpoint
		stickyAge uint16
	}{
		{
			svc: &types.ServiceConfig{
				Protocol:        ofconfig.ProtocolTCP,
				ServiceIP:       net.ParseIP("10.20.30.41"),
				ServicePort:     uint16(8000),
				ClusterGroupID:  2,
				AffinityTimeout: stickyMaxAgeSeconds,
			},
			endpoints: endpoints,
		},
	}

	for _, tc := range tcs {
		groupID := ofconfig.GroupIDType(tc.svc.ClusterGroupID)
		expTableFlows, expGroupBuckets := expectedProxyServiceGroupAndFlows(tc.svc, tc.endpoints, true)
		installServiceFlows(t, tc.svc, tc.endpoints)
		for _, tableFlow := range expTableFlows {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, true, tableFlow.flows)
		}
		ofTestUtils.CheckGroupExists(t, ovsCtlClient, groupID, "select", expGroupBuckets, true)

		uninstallServiceFlowsFunc(t, tc.svc, tc.endpoints)
		for _, tableFlow := range expTableFlows {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, false, tableFlow.flows)
		}
		ofTestUtils.CheckGroupExists(t, ovsCtlClient, groupID, "select", expGroupBuckets, false)
	}
}

func installServiceFlows(t *testing.T, svc *types.ServiceConfig, endpointList []k8sproxy.Endpoint) {
	err := c.InstallEndpointFlows(svc.Protocol, endpointList)
	assert.NoError(t, err, "no error should return when installing flows for Endpoints")
	err = c.InstallServiceGroup(svc.ClusterGroupID, svc.AffinityTimeout != 0, endpointList)
	assert.NoError(t, err, "no error should return when installing groups for Service")
	err = c.InstallServiceFlows(svc)
	assert.NoError(t, err, "no error should return when installing flows for Service")
}

func uninstallServiceFlowsFunc(t *testing.T, svc *types.ServiceConfig, endpointList []k8sproxy.Endpoint) {
	err := c.UninstallServiceFlows(svc.ServiceIP, svc.ServicePort, svc.Protocol)
	assert.Nil(t, err)
	err = c.UninstallServiceGroup(svc.ClusterGroupID)
	assert.Nil(t, err)
	assert.NoError(t, c.UninstallEndpointFlows(svc.Protocol, endpointList))
}

func expectedProxyServiceGroupAndFlows(svc *types.ServiceConfig, endpointList []k8sproxy.Endpoint, antreaPolicyEnabled bool) (tableFlows []expectTableFlows, groupBuckets []string) {
	nw_proto := 6
	learnProtoField := "NXM_OF_TCP_DST[]"
	if svc.Protocol == ofconfig.ProtocolUDP {
		nw_proto = 17
		learnProtoField = "NXM_OF_UDP_DST[]"
	} else if svc.Protocol == ofconfig.ProtocolSCTP {
		nw_proto = 132
		learnProtoField = "OXM_OF_SCTP_DST[]"
	}

	serviceLearnReg := 2
	if svc.AffinityTimeout != 0 {
		serviceLearnReg = 3
	}
	cookieAllocator := cookie.NewAllocator(roundInfo.RoundNum)

	loadGourpID := ""
	ctTable := "EgressRule"
	if antreaPolicyEnabled {
		loadGourpID = fmt.Sprintf("set_field:0x%x->reg7,", svc.ClusterGroupID)
		ctTable = "AntreaPolicyEgressRule"
	}
	svcFlows := expectTableFlows{tableName: "ServiceLB", flows: []*ofTestUtils.ExpectFlow{
		{
			MatchStr: fmt.Sprintf("priority=200,%s,reg4=0x10000/0x70000,nw_dst=%s,tp_dst=%d", string(svc.Protocol), svc.ServiceIP.String(), svc.ServicePort),
			ActStr:   fmt.Sprintf("set_field:0x200/0x200->reg0,set_field:0x%x/0x70000->reg4,%sgroup:%d", serviceLearnReg<<16, loadGourpID, svc.ClusterGroupID),
		},
		{
			MatchStr: fmt.Sprintf("priority=190,%s,reg4=0x30000/0x70000,nw_dst=%s,tp_dst=%d", string(svc.Protocol), svc.ServiceIP.String(), svc.ServicePort),
			ActStr:   fmt.Sprintf("learn(table=SessionAffinity,hard_timeout=%d,priority=200,delete_learned,cookie=0x%x,eth_type=0x800,nw_proto=%d,%s,NXM_OF_IP_DST[],NXM_OF_IP_SRC[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:NXM_NX_REG4[26]->NXM_NX_REG4[26],load:NXM_NX_REG3[]->NXM_NX_REG3[],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG0[9]),set_field:0x20000/0x70000->reg4,goto_table:EndpointDNAT", svc.AffinityTimeout, cookieAllocator.RequestWithObjectID(cookie.Service, uint32(svc.ClusterGroupID)).Raw(), nw_proto, learnProtoField),
		},
	}}
	epDNATFlows := expectTableFlows{tableName: "EndpointDNAT", flows: []*ofTestUtils.ExpectFlow{}}
	hairpinFlows := expectTableFlows{tableName: "SNATMark", flows: []*ofTestUtils.ExpectFlow{}}
	groupBuckets = make([]string, 0)
	for _, ep := range endpointList {
		epIP := ipToHexString(net.ParseIP(ep.IP()))
		epPort, _ := ep.Port()
		var bucket string
		if ep.GetIsLocal() {
			bucket = fmt.Sprintf("weight:100,actions=set_field:%s->reg3,set_field:0x%x/0xffff->reg4,resubmit(,%d)", epIP, epPort, ofClient.ServiceLBTable.GetID())
		} else {
			bucket = fmt.Sprintf("weight:100,actions=set_field:0x4000000/0x4000000->reg4,set_field:%s->reg3,set_field:0x%x/0xffff->reg4,resubmit(,%d)", epIP, epPort, ofClient.ServiceLBTable.GetID())
		}
		groupBuckets = append(groupBuckets, bucket)

		unionVal := (0b010 << 16) + uint32(epPort)
		epDNATFlows.flows = append(epDNATFlows.flows, &ofTestUtils.ExpectFlow{
			MatchStr: fmt.Sprintf("priority=200,%s,reg3=%s,reg4=0x%x/0x7ffff", string(svc.Protocol), epIP, unionVal),
			ActStr:   fmt.Sprintf("ct(commit,table=%s,zone=65520,nat(dst=%s:%d),exec(set_field:0x10/0x10->ct_mark,move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3])", ctTable, ep.IP(), epPort),
		})

		if ep.GetIsLocal() {
			hairpinFlows.flows = append(hairpinFlows.flows, &ofTestUtils.ExpectFlow{
				MatchStr: fmt.Sprintf("priority=190,ct_state=+new+trk,ip,nw_src=%s,nw_dst=%s", ep.IP(), ep.IP()),
				ActStr:   "ct(commit,table=SNAT,zone=65520,exec(set_field:0x20/0x20->ct_mark,set_field:0x40/0x40->ct_mark))",
			})
		}
	}

	tableFlows = []expectTableFlows{svcFlows, epDNATFlows, hairpinFlows}
	return
}

func ipToHexString(ip net.IP) string {
	ipBytes := ip
	if ip.To4() != nil {
		ipBytes = []byte(ip)[12:16]
	}
	ipStr := hex.EncodeToString(ipBytes)
	// Trim "0" at the beginning of the string to be compatible with OVS printed values.
	ipStr = "0x" + strings.TrimLeft(ipStr, "0")
	return ipStr
}

func checkDefaultDropFlows(t *testing.T, table string, priority int, addrType types.AddressType, addresses []types.Address, add bool) {
	// dump flows
	flowList, err := ofTestUtils.OfctlDumpTableFlows(ovsCtlClient, table)
	assert.Nil(t, err, fmt.Sprintf("Failed to dump flows: %v", err))
	for _, addr := range addresses {
		_, ipProto := getIPProtoStr(addr)
		conjMatch := fmt.Sprintf("priority=%d,%s,%s=%s", priority, ipProto, addr.GetMatchKey(addrType).GetKeyString(), addr.GetMatchValue())
		flow := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: "drop"}
		if add {
			assert.True(t, ofTestUtils.OfctlFlowMatch(flowList, table, flow), "Failed to install conjunctive match flow")
		} else {
			assert.False(t, ofTestUtils.OfctlFlowMatch(flowList, table, flow), "Failed to uninstall conjunctive match flow")
		}
	}
}

func checkAddAddress(t *testing.T, ruleTable string, priority int, ruleID uint32, addedAddress []types.Address, addrType types.AddressType) {
	err := c.AddPolicyRuleAddress(ruleID, addrType, addedAddress, nil, false, false)
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")

	// dump flows
	flowList, err := ofTestUtils.OfctlDumpTableFlows(ovsCtlClient, ruleTable)
	require.Nil(t, err, "Failed to dump flows")

	action := fmt.Sprintf("conjunction(%d,1/3)", ruleID)
	if addrType == types.DstAddress {
		action = fmt.Sprintf("conjunction(%d,2/3)", ruleID)
	}

	for _, addr := range addedAddress {
		_, ipProto := getIPProtoStr(addr)
		conjMatch := fmt.Sprintf("priority=%d,%s,%s=%s", priority, ipProto, addr.GetMatchKey(addrType).GetKeyString(), addr.GetMatchValue())
		flow := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: action}
		assert.True(t, ofTestUtils.OfctlFlowMatch(flowList, ruleTable, flow), "Failed to install conjunctive match flow")
	}

	tableStatus := c.GetFlowTableStatus()
	for _, tableStatus := range tableStatus {
		if tableStatus.Name == ruleTable {
			assert.Equal(t, tableStatus.FlowCount, uint(len(flowList)),
				fmt.Sprintf("Cached table status in %d is incorrect, expect: %d, actual %d", tableStatus.ID, tableStatus.FlowCount, len(flowList)))
		}
	}
}

func checkDeleteAddress(t *testing.T, ruleTable string, priority int, ruleID uint32, addedAddress []types.Address, addrType types.AddressType) {
	err := c.DeletePolicyRuleAddress(ruleID, addrType, addedAddress, nil)
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")
	flowList, err := ofTestUtils.OfctlDumpTableFlows(ovsCtlClient, ruleTable)
	require.Nil(t, err, "Failed to dump flows")

	action := fmt.Sprintf("conjunction(%d,1/3)", ruleID)
	if addrType == types.DstAddress {
		action = fmt.Sprintf("conjunction(%d,2/3)", ruleID)
	}

	for _, addr := range addedAddress {
		_, ipProto := getIPProtoStr(addr)
		conjMatch := fmt.Sprintf("priority=%d,%s,%s=%s", priority, ipProto, addr.GetMatchKey(addrType).GetKeyString(), addr.GetMatchValue())
		flow := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: action}
		assert.False(t, ofTestUtils.OfctlFlowMatch(flowList, ruleTable, flow), "Failed to install conjunctive match flow")
	}

	tableStatus := c.GetFlowTableStatus()
	for _, tableStatus := range tableStatus {
		if tableStatus.Name == ruleTable {
			assert.Equal(t, tableStatus.FlowCount, uint(len(flowList)),
				fmt.Sprintf("Cached table status in %d is incorrect, expect: %d, actual %d", tableStatus.ID, tableStatus.FlowCount, len(flowList)))
		}
	}
}

func checkConjunctionFlows(t *testing.T, ruleTable string, priority int, ruleID uint32, rule *types.PolicyRule, testFunc func(t assert.TestingT, value bool, msgAndArgs ...interface{}) bool) {
	flowList, err := ofTestUtils.OfctlDumpTableFlows(ovsCtlClient, ruleTable)
	require.Nil(t, err, "Failed to dump flows")

	conjunctionActionMatch := fmt.Sprintf("priority=%d,conj_id=%d,ip", priority-10, ruleID)
	conjReg := 6
	nextTable := ofClient.IngressMetricTable.GetName()
	if ruleTable == ofClient.EgressRuleTable.GetName() {
		nextTable = ofClient.EgressMetricTable.GetName()
	}

	flow := &ofTestUtils.ExpectFlow{MatchStr: conjunctionActionMatch, ActStr: fmt.Sprintf("set_field:0x%x->reg%d,ct(commit,table=%s,zone=65520,exec(set_field:0x%x/0xffffffff->ct_label)", ruleID, conjReg, nextTable, ruleID)}
	testFunc(t, ofTestUtils.OfctlFlowMatch(flowList, ruleTable, flow), "Failed to update conjunction action flow")
	useIPv4 := false
	useIPv6 := false

	for _, addr := range rule.From {
		isIPv6, ipProto := getIPProtoStr(addr)
		if isIPv6 && !useIPv6 {
			useIPv6 = true
		} else if !isIPv6 && !useIPv4 {
			useIPv4 = true
		}
		conjMatch := fmt.Sprintf("priority=%d,%s,%s=%s", priority, ipProto, addr.GetMatchKey(types.SrcAddress).GetKeyString(), addr.GetMatchValue())
		flow := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: fmt.Sprintf("conjunction(%d,1/3)", ruleID)}
		testFunc(t, ofTestUtils.OfctlFlowMatch(flowList, ruleTable, flow), "Failed to install conjunctive match flow for clause1")
	}

	for _, addr := range rule.To {
		isIPv6, ipProto := getIPProtoStr(addr)
		if isIPv6 && !useIPv6 {
			useIPv6 = true
		} else if !isIPv6 && !useIPv4 {
			useIPv4 = true
		}
		conjMatch := fmt.Sprintf("priority=%d,%s,%s=%s", priority, ipProto, addr.GetMatchKey(types.DstAddress).GetKeyString(), addr.GetMatchValue())
		flow := &ofTestUtils.ExpectFlow{MatchStr: conjMatch, ActStr: fmt.Sprintf("conjunction(%d,2/3)", ruleID)}
		testFunc(t, ofTestUtils.OfctlFlowMatch(flowList, ruleTable, flow), "Failed to install conjunctive match flow for clause2")
	}

	for _, service := range rule.Service {
		if useIPv4 {
			conjMatch1 := fmt.Sprintf("priority=%d,%s,tp_dst=%d", priority, strings.ToLower(string(*service.Protocol)), service.Port.IntVal)
			flow := &ofTestUtils.ExpectFlow{MatchStr: conjMatch1, ActStr: fmt.Sprintf("conjunction(%d,3/3)", ruleID)}
			testFunc(t, ofTestUtils.OfctlFlowMatch(flowList, ruleTable, flow), "Failed to install conjunctive match flow for clause3")
		}
		if useIPv6 {
			conjMatch1 := fmt.Sprintf("priority=%d,%s6,tp_dst=%d", priority, strings.ToLower(string(*service.Protocol)), service.Port.IntVal)
			flow := &ofTestUtils.ExpectFlow{MatchStr: conjMatch1, ActStr: fmt.Sprintf("conjunction(%d,3/3)", ruleID)}
			testFunc(t, ofTestUtils.OfctlFlowMatch(flowList, ruleTable, flow), "Failed to install conjunctive match flow for clause3")
		}
	}

	tablesStatus := c.GetFlowTableStatus()
	for _, tableStatus := range tablesStatus {
		if tableStatus.Name == ruleTable {
			assert.Equal(t, tableStatus.FlowCount, uint(len(flowList)),
				fmt.Sprintf("Cached table status in %d is incorrect, expect: %d, actual %d", tableStatus.ID, tableStatus.FlowCount, len(flowList)))
		}
	}
}

func getIPProtoStr(addr types.Address) (bool, string) {
	var addrIP net.IP
	switch v := addr.GetValue().(type) {
	case net.IP:
		addrIP = v
	case net.IPNet:
		addrIP = v.IP
	}
	if addrIP.To4() != nil {
		return false, "ip"
	}
	return true, "ipv6"
}

func checkOVSFlowMetrics(t *testing.T, client ofClient.Client) {
	expectedFlowCount := `
	# HELP antrea_agent_ovs_flow_count [STABLE] Flow count for each OVS flow table. The TableID and TableName are used as labels.
	# TYPE antrea_agent_ovs_flow_count gauge
	`
	tableStatus := client.GetFlowTableStatus()
	totalFlowCount := 0
	for _, table := range tableStatus {
		expectedFlowCount = expectedFlowCount + fmt.Sprintf("antrea_agent_ovs_flow_count{table_id=\"%d\", table_name=\"%s\"} %d\n", table.ID, table.Name, table.FlowCount)
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
	gatewayConfig := config.nodeConfig.GatewayConfig
	var ips []net.IP
	if config.enableIPv4 {
		ips = append(ips, gatewayConfig.IPv4)
	}
	if config.enableIPv6 {
		ips = append(ips, gatewayConfig.IPv6)
	}
	for _, tableFlow := range prepareGatewayFlows(ips, gatewayConfig.MAC, config.globalMAC, config.nodeConfig, config.connectUplinkToBridge) {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, true, tableFlow.flows)
	}
}

func prepareConfiguration(enableIPv4, enableIPv6, enableStretchedNetworkPolicy bool) *testConfig {
	podMAC, _ := net.ParseMAC("aa:aa:aa:aa:aa:13")
	gwMAC, _ := net.ParseMAC("aa:aa:aa:aa:aa:11")
	uplinkMAC, _ := net.ParseMAC("aa:aa:aa:aa:aa:12")
	peerNodeMAC, _ := net.ParseMAC("aa:aa:aa:aa:ab:00")

	nodeIPv4, nodeIPv4Subnet, _ := net.ParseCIDR("10.10.10.1/24")
	nodeIPv4Subnet.IP = nodeIPv4
	nodeIPv6, nodeIPv6Subnet, _ := net.ParseCIDR("a963:ca9b:172:10::11/64")
	nodeIPv6Subnet.IP = nodeIPv6
	_, peerIPv4Subnet, _ := net.ParseCIDR("192.168.2.0/24")
	_, peerIPv6Subnet, _ := net.ParseCIDR("fd74:ca9b:172:20::/64")

	gatewayConfig := &agentconfig.GatewayConfig{MAC: gwMAC, OFPort: uint32(agentconfig.HostGatewayOFPort)}
	uplinkConfig := &agentconfig.AdapterNetConfig{MAC: uplinkMAC}
	nodeConfig := &agentconfig.NodeConfig{GatewayConfig: gatewayConfig, UplinkNetConfig: uplinkConfig, TunnelOFPort: uint32(agentconfig.DefaultTunOFPort), Type: agentconfig.K8sNode}
	podCfg := &testLocalPodConfig{
		name: "container-1",
		testPortConfig: &testPortConfig{
			mac:    podMAC,
			ofPort: uint32(11),
		},
	}
	peerNode := &testPeerConfig{
		name:        "n2",
		nodeAddress: net.ParseIP("10.1.1.2"),
		nodeMAC:     peerNodeMAC,
	}

	if enableIPv4 {
		gatewayConfig.IPv4 = net.ParseIP("192.168.1.1")
		nodeConfig.NodeIPv4Addr = nodeIPv4Subnet
		nodeConfig.PodIPv4CIDR = podIPv4CIDR
		podCfg.ips = append(podCfg.ips, net.ParseIP("192.168.1.3"))
		peerNode.gateway = net.ParseIP("192.168.2.1")
		peerNode.subnet = *peerIPv4Subnet
	}
	if enableIPv6 {
		gatewayConfig.IPv6 = net.ParseIP("fd74:ca9b:172:19::1")
		nodeConfig.NodeIPv6Addr = nodeIPv6Subnet
		nodeConfig.PodIPv6CIDR = podIPv6CIDR
		podCfg.ips = append(podCfg.ips, net.ParseIP("fd74:ca9b:172:19::3"))
		peerNode.gateway = net.ParseIP("fd74:ca9b:172:20::1")
		peerNode.subnet = *peerIPv6Subnet
	}

	vMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	return &testConfig{
		bridge:                       br,
		nodeConfig:                   nodeConfig,
		localPods:                    []*testLocalPodConfig{podCfg},
		peers:                        []*testPeerConfig{peerNode},
		globalMAC:                    vMAC,
		enableIPv4:                   enableIPv4,
		enableIPv6:                   enableIPv6,
		enableStretchedNetworkPolicy: enableStretchedNetworkPolicy,
	}
}

func preparePodFlows(podIPs []net.IP, podMAC net.HardwareAddr, podOFPort uint32, gwMAC, vMAC net.HardwareAddr, nodeConfig *agentconfig.NodeConfig, connectUplinkToBridge bool, vlanID uint16, enableStretchedNetworkPolicy bool) []expectTableFlows {
	podIPv4 := util.GetIPv4Addr(podIPs)
	isAntreaFlexibleIPAM := connectUplinkToBridge && podIPv4 != nil && !nodeConfig.PodIPv4CIDR.Contains(podIPv4)
	actionNotAntreaFlexibleIPAMString := ""
	actionNotMulticlusterString := ""
	matchRewriteMACMarkString := ",reg0=0x200/0x200"
	if isAntreaFlexibleIPAM {
		actionNotAntreaFlexibleIPAMString = ",set_field:0x100000/0x100000->reg4,set_field:0x200/0x200->reg0"
		matchRewriteMACMarkString = ""
	}
	if enableStretchedNetworkPolicy {
		actionNotMulticlusterString = ",set_field:0xffffff->tun_id"
	}
	flows := []expectTableFlows{
		{
			"Classifier",
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=190,in_port=%d", podOFPort),
					ActStr:   fmt.Sprintf("set_field:0x3/0xf->reg0%s%s,goto_table:SpoofGuard", actionNotAntreaFlexibleIPAMString, actionNotMulticlusterString),
				},
			},
		},
		{
			"L2ForwardingCalc",
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,dl_dst=%s", podMAC.String()),
					ActStr:   fmt.Sprintf("set_field:0x%x->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier", podOFPort),
				},
			},
		},
	}

	matchVlanVIDString := ""
	matchVlanRegString := ""
	vlanVIDString := "0"
	if connectUplinkToBridge {
		matchVlanVIDString = ",vlan_tci=0x0000/0x1fff"
		matchVlanRegString = ",reg8=0/0xfff"
		if vlanID > 0 {
			matchVlanVIDString = fmt.Sprintf(",dl_vlan=%d", vlanID)
			matchVlanRegString = fmt.Sprintf(",reg8=0x%x/0xfff", vlanID)
			vlanVIDString = fmt.Sprintf("0x%x", vlanID)
		}
	}

	if isAntreaFlexibleIPAM {
		flows = append(flows, []expectTableFlows{{
			"Classifier",
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=210,ip,in_port=%d%s,dl_dst=%s", 3, matchVlanVIDString, podMAC.String()),
					ActStr:   fmt.Sprintf("set_field:0x1000/0xf000->reg8,set_field:0x4/0xf->reg0,set_field:%s/0xfff->reg8,goto_table:UnSNAT", vlanVIDString),
				},
			},
		}}...)
		if vlanID == 0 {
			flows = append(flows, []expectTableFlows{{
				"Classifier",
				[]*ofTestUtils.ExpectFlow{
					{
						MatchStr: fmt.Sprintf("priority=210,ip,in_port=LOCAL,vlan_tci=0x0000/0x1fff,dl_dst=%s", podMAC.String()),
						ActStr:   "set_field:0x1000/0xf000->reg8,set_field:0x5/0xf->reg0,goto_table:UnSNAT",
					},
				},
			}}...)
		} else {
			flows = append(flows, []expectTableFlows{{
				"VLAN",
				[]*ofTestUtils.ExpectFlow{
					{
						MatchStr: fmt.Sprintf("priority=190,reg1=0x%x,in_port=%d", 3, podOFPort),
						ActStr:   fmt.Sprintf("push_vlan:0x8100,set_field:%d->vlan_vid,goto_table:Output", vlanID+4096),
					},
				},
			}}...)
		}
	}

	for _, podIP := range podIPs {
		var ipProto, nwSrcField, nwDstField string
		var nextTableForSpoofguard string
		actionNotAntreaFlexibleIPAMString = ""
		actionSetCtZoneField := ""
		if !isAntreaFlexibleIPAM {
			actionNotAntreaFlexibleIPAMString = fmt.Sprintf("set_field:%s->eth_src,", gwMAC)
		}
		vlanType := uint16(1)
		if podIP.To4() != nil {
			ipProto = "ip"
			nwSrcField = "nw_src"
			nwDstField = "nw_dst"
			flows = append(flows,
				expectTableFlows{
					"ARPSpoofGuard",
					[]*ofTestUtils.ExpectFlow{
						{
							MatchStr: fmt.Sprintf("priority=200,arp,in_port=%d,arp_spa=%s,arp_sha=%s", podOFPort, podIP.String(), podMAC.String()),
							ActStr:   "goto_table:ARPResponder",
						},
					},
				})
			nextTableForSpoofguard = "UnSNAT"
		} else {
			ipProto = "ipv6"
			nwSrcField = "ipv6_src"
			nwDstField = "ipv6_dst"
			nextTableForSpoofguard = "IPv6"
			vlanType = 3
		}
		if isAntreaFlexibleIPAM {
			actionSetCtZoneField = fmt.Sprintf("set_field:0x%x/0xf000->reg8,set_field:%s/0xfff->reg8,", vlanType<<12, vlanVIDString)
		}
		flows = append(flows,
			expectTableFlows{
				"SpoofGuard",
				[]*ofTestUtils.ExpectFlow{
					{
						MatchStr: fmt.Sprintf("priority=200,%s,in_port=%d,dl_src=%s,%s=%s", ipProto, podOFPort, podMAC.String(), nwSrcField, podIP.String()),
						ActStr:   fmt.Sprintf("%sgoto_table:%s", actionSetCtZoneField, nextTableForSpoofguard),
					},
				},
			},
			expectTableFlows{
				"L3Forwarding",
				[]*ofTestUtils.ExpectFlow{
					{
						MatchStr: fmt.Sprintf("priority=200,%s%s%s,%s=%s", ipProto, matchVlanRegString, matchRewriteMACMarkString, nwDstField, podIP.String()),
						ActStr:   fmt.Sprintf("%sset_field:%s->eth_dst,goto_table:L3DecTTL", actionNotAntreaFlexibleIPAMString, podMAC.String()),
					},
				},
			},
		)
	}

	return flows
}

func prepareGatewayFlows(gwIPs []net.IP, gwMAC net.HardwareAddr, vMAC net.HardwareAddr, nodeConfig *agentconfig.NodeConfig, connectUplinkToBridge bool) []expectTableFlows {
	flows := []expectTableFlows{
		{
			"Classifier",
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,in_port=%d", agentconfig.HostGatewayOFPort),
					ActStr:   "set_field:0x2/0xf->reg0,set_field:0x8000000/0x8000000->reg4,goto_table:SpoofGuard",
				},
			},
		},
		{
			"L2ForwardingCalc",
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,dl_dst=%s", gwMAC.String()),
					ActStr:   fmt.Sprintf("set_field:0x%x->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier", agentconfig.HostGatewayOFPort),
				},
			},
		},
	}

	for _, gwIP := range gwIPs {
		var ipProtoStr, nwSrcStr, nwDstStr string
		actionSetCtZoneField := ""
		vlanType := uint16(1)
		if connectUplinkToBridge {
			actionSetCtZoneField = fmt.Sprintf("set_field:0x%x/0xf000->reg8,", vlanType<<12)
		}
		if gwIP.To4() != nil {
			ipProtoStr = "ip"
			nwSrcStr = "nw_src"
			nwDstStr = "nw_dst"
			flows = append(flows,
				expectTableFlows{
					"SpoofGuard",
					[]*ofTestUtils.ExpectFlow{
						{
							MatchStr: fmt.Sprintf("priority=200,ip,in_port=%d", agentconfig.HostGatewayOFPort),
							ActStr:   fmt.Sprintf("%sgoto_table:UnSNAT", actionSetCtZoneField),
						},
					},
				},
				expectTableFlows{
					"ARPSpoofGuard",
					[]*ofTestUtils.ExpectFlow{
						{
							MatchStr: fmt.Sprintf("priority=200,arp,in_port=%d,arp_spa=%s,arp_sha=%s", agentconfig.HostGatewayOFPort, gwIP, gwMAC),
							ActStr:   "goto_table:ARPResponder",
						},
					},
				},
			)
		} else {
			ipProtoStr = "ipv6"
			nwSrcStr = "ipv6_src"
			nwDstStr = "ipv6_dst"
		}
		flows = append(flows,
			expectTableFlows{
				"Classifier",
				[]*ofTestUtils.ExpectFlow{
					{
						MatchStr: fmt.Sprintf("priority=210,%s,in_port=%d,%s=%s", ipProtoStr, agentconfig.HostGatewayOFPort, nwSrcStr, gwIP),
						ActStr:   "set_field:0x2/0xf->reg0,goto_table:SpoofGuard",
					},
				},
			},
			expectTableFlows{
				tableName: "IngressSecurityClassifier",
				flows: []*ofTestUtils.ExpectFlow{
					{
						MatchStr: fmt.Sprintf("priority=210,ct_state=-rpl+trk,%s,%s=%s", ipProtoStr, nwSrcStr, gwIP.String()),
						ActStr:   "goto_table:ConntrackCommit",
					},
				},
			},
			expectTableFlows{
				"L3Forwarding",
				[]*ofTestUtils.ExpectFlow{
					{
						MatchStr: fmt.Sprintf("priority=210,ct_state=+rpl+trk,ct_mark=0x2/0xf,%s", ipProtoStr),
						ActStr:   fmt.Sprintf("set_field:%s->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL", gwMAC.String()),
					},
					{
						MatchStr: fmt.Sprintf("priority=210,%s,%s=%s", ipProtoStr, nwDstStr, gwIP.String()),
						ActStr:   fmt.Sprintf("set_field:%s->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL", gwMAC.String()),
					},
				},
			},
		)
	}

	return flows
}

func prepareTunnelFlows(tunnelPort uint32, vMAC net.HardwareAddr) []expectTableFlows {
	return []expectTableFlows{
		{
			"Classifier",
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,in_port=%d", tunnelPort),
					ActStr:   "set_field:0x1/0xf->reg0,set_field:0x200/0x200->reg0,goto_table:UnSNAT",
				},
			},
		},
		{
			"L2ForwardingCalc",
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,dl_dst=%s", vMAC.String()),
					ActStr:   fmt.Sprintf("set_field:0x%x->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier", agentconfig.DefaultTunOFPort),
				},
			},
		},
	}
}

func prepareNodeFlows(peerSubnet net.IPNet, peerGwIP, peerNodeIP net.IP, vMAC, localGwMAC, peerNodeMAC net.HardwareAddr, connectUplinkToBridge bool) []expectTableFlows {
	var expFlows []expectTableFlows
	var ipProtoStr, nwDstFieldName string
	if peerGwIP.To4() != nil {
		ipProtoStr = "ip"
		nwDstFieldName = "nw_dst"
		expFlows = append(expFlows, expectTableFlows{
			"ARPResponder",
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,arp,arp_tpa=%s,arp_op=1", peerGwIP.String()),
					ActStr:   fmt.Sprintf("move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:%s->eth_src,set_field:2->arp_op,move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],set_field:%s->arp_sha,move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:%s->arp_spa,IN_PORT", vMAC.String(), vMAC.String(), peerGwIP.String()),
				},
			},
		})
	} else {
		ipProtoStr = "ipv6"
		nwDstFieldName = "ipv6_dst"
	}
	expFlows = append(expFlows, expectTableFlows{
		"L3Forwarding",
		[]*ofTestUtils.ExpectFlow{
			{
				MatchStr: fmt.Sprintf("priority=200,%s,%s=%s", ipProtoStr, nwDstFieldName, peerSubnet.String()),
				ActStr:   fmt.Sprintf("set_field:%s->eth_src,set_field:%s->eth_dst,set_field:%s->tun_dst,set_field:0x10/0xf0->reg0,goto_table:L3DecTTL", localGwMAC.String(), vMAC.String(), peerNodeIP.String()),
			},
		},
	})
	if connectUplinkToBridge {
		expFlows = append(expFlows, expectTableFlows{
			"L3Forwarding",
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,%s,reg4=0x100000/0x100000,reg8=0/0xfff,%s=%s", ipProtoStr, nwDstFieldName, peerSubnet.String()),
					ActStr:   fmt.Sprintf("set_field:%s->eth_dst,set_field:0x40/0xf0->reg0,goto_table:L3DecTTL", peerNodeMAC.String()),
				},
			},
		})
	}

	return expFlows
}

func prepareServiceHelperFlows() []expectTableFlows {
	return []expectTableFlows{
		{
			"SessionAffinity",
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: "priority=0",
					ActStr:   "set_field:0x10000/0x70000->reg4",
				},
			},
		},
	}
}

func prepareDefaultFlows(config *testConfig) []expectTableFlows {
	outputStageTable := "Output"
	ctZone := "65520"
	ctZoneV6 := "65510"
	matchVLANString := ""
	tableVLANFlows := expectTableFlows{}
	if config.connectUplinkToBridge {
		outputStageTable = "VLAN"
		ctZone = "NXM_NX_REG8[0..15]"
		ctZoneV6 = "NXM_NX_REG8[0..15]"
		tableVLANFlows.tableName = "VLAN"
		tableVLANFlows.flows = append(tableVLANFlows.flows, &ofTestUtils.ExpectFlow{MatchStr: "priority=0", ActStr: "goto_table:Output"})
		matchVLANString = ",reg8=0/0xfff"
	}
	tableARPResponderFlows := expectTableFlows{
		tableName: "ARPResponder",
	}
	tableConntrackStateFlows := expectTableFlows{
		tableName: "ConntrackState",
		flows:     []*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:PreRoutingClassifier"}},
	}
	tableConntrackCommitFlows := expectTableFlows{
		tableName: "ConntrackCommit",
		flows:     []*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: fmt.Sprintf("goto_table:%s", outputStageTable)}},
	}
	tableSNATFlows := expectTableFlows{
		tableName: "SNAT",
	}
	tableL3ForwardingFlows := expectTableFlows{
		"L3Forwarding",
		[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc"}},
	}
	tableL3DecTTLFlows := expectTableFlows{
		tableName: "L3DecTTL",
		flows:     []*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:SNATMark"}},
	}
	tableUnSNATFlows := expectTableFlows{
		tableName: "UnSNAT",
		flows:     []*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:ConntrackZone"}},
	}
	tableConntrackZoneFlows := expectTableFlows{
		tableName: "ConntrackZone",
		flows:     []*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:ConntrackState"}},
	}
	tableSNATMarkFlows := expectTableFlows{
		tableName: "SNATMark",
		flows:     []*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:SNAT"}},
	}
	if config.enableIPv4 {
		tableARPResponderFlows.flows = append(tableARPResponderFlows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=190,arp", ActStr: "NORMAL"},
			&ofTestUtils.ExpectFlow{MatchStr: "priority=0", ActStr: "drop"},
		)
		tableUnSNATFlows.flows = append(tableUnSNATFlows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: fmt.Sprintf("priority=200,ip,nw_dst=%s", config.nodeConfig.GatewayConfig.IPv4), ActStr: "ct(table=ConntrackZone,zone=65521,nat)"},
			&ofTestUtils.ExpectFlow{MatchStr: fmt.Sprintf("priority=200,ip,nw_dst=%s", agentconfig.VirtualServiceIPv4), ActStr: "ct(table=ConntrackZone,zone=65521,nat)"},
		)
		tableConntrackZoneFlows.flows = append(tableConntrackZoneFlows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ip", ActStr: fmt.Sprintf("ct(table=ConntrackState,zone=%s,nat)", ctZone)},
		)
		tableConntrackStateFlows.flows = append(tableConntrackStateFlows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ct_state=+inv+trk,ip", ActStr: "drop"},
		)
		tableConntrackCommitFlows.flows = append(tableConntrackCommitFlows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ct_state=+new+trk-snat,ct_mark=0/0x10,ip", ActStr: fmt.Sprintf("ct(commit,table=%s,zone=%s,exec(move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))", outputStageTable, ctZone)},
		)
		tableSNATFlows.flows = append(tableSNATFlows.flows,
			&ofTestUtils.ExpectFlow{
				MatchStr: "priority=200,ct_state=+new+trk,ct_mark=0x40/0x40,ip,reg0=0x2/0xf",
				ActStr:   fmt.Sprintf("ct(commit,table=L2ForwardingCalc,zone=65521,nat(src=%s),exec(set_field:0x10/0x10->ct_mark,set_field:0x40/0x40->ct_mark))", agentconfig.VirtualServiceIPv4),
			},
			&ofTestUtils.ExpectFlow{
				MatchStr: "priority=200,ct_state=+new+trk,ct_mark=0x40/0x40,ip,reg0=0x3/0xf",
				ActStr:   fmt.Sprintf("ct(commit,table=L2ForwardingCalc,zone=65521,nat(src=%s),exec(set_field:0x10/0x10->ct_mark,set_field:0x40/0x40->ct_mark))", config.nodeConfig.GatewayConfig.IPv4),
			},
			&ofTestUtils.ExpectFlow{
				MatchStr: "priority=190,ct_state=+new+trk,ct_mark=0x20/0x20,ip,reg0=0x2/0xf",
				ActStr:   fmt.Sprintf("ct(commit,table=L2ForwardingCalc,zone=65521,nat(src=%s),exec(set_field:0x10/0x10->ct_mark))", config.nodeConfig.GatewayConfig.IPv4),
			},
			&ofTestUtils.ExpectFlow{
				MatchStr: "priority=200,ct_state=-new-rpl+trk,ct_mark=0x20/0x20,ip",
				ActStr:   "ct(table=L2ForwardingCalc,zone=65521,nat)",
			},
		)
		podCIDR := config.nodeConfig.PodIPv4CIDR.String()
		tableL3ForwardingFlows.flows = append(tableL3ForwardingFlows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: fmt.Sprintf("priority=200,ip,reg0=0/0x200%s,nw_dst=%s", matchVLANString, podCIDR), ActStr: "goto_table:L2ForwardingCalc"},
		)
		tableSNATMarkFlows.flows = append(tableSNATMarkFlows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ct_state=+new+trk,ip,reg0=0x22/0xff", ActStr: fmt.Sprintf("ct(commit,table=SNAT,zone=%s,exec(set_field:0x20/0x20->ct_mark,set_field:0x40/0x40->ct_mark))", ctZone)},
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ct_state=+new+trk,ip,reg0=0x12/0xff,reg4=0x200000/0x2200000", ActStr: fmt.Sprintf("ct(commit,table=SNAT,zone=%s,exec(set_field:0x20/0x20->ct_mark))", ctZone)},
		)
		tableL3DecTTLFlows.flows = append(tableL3DecTTLFlows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=210,ip,reg0=0x2/0xf", ActStr: "goto_table:SNATMark"},
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ip", ActStr: "dec_ttl,goto_table:SNATMark"},
		)
	}
	if config.enableIPv6 {
		tableUnSNATFlows.flows = append(tableUnSNATFlows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: fmt.Sprintf("priority=200,ipv6,ipv6_dst=%s", config.nodeConfig.GatewayConfig.IPv6), ActStr: "ct(table=ConntrackZone,zone=65511,nat)"},
			&ofTestUtils.ExpectFlow{MatchStr: fmt.Sprintf("priority=200,ipv6,ipv6_dst=%s", agentconfig.VirtualServiceIPv6), ActStr: "ct(table=ConntrackZone,zone=65511,nat)"},
		)
		tableConntrackZoneFlows.flows = append(tableConntrackZoneFlows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ipv6", ActStr: fmt.Sprintf("ct(table=ConntrackState,zone=%s,nat)", ctZoneV6)},
		)
		tableConntrackStateFlows.flows = append(tableConntrackStateFlows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ct_state=+inv+trk,ipv6", ActStr: "drop"},
		)
		tableConntrackCommitFlows.flows = append(tableConntrackCommitFlows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ct_state=+new+trk-snat,ct_mark=0/0x10,ipv6", ActStr: fmt.Sprintf("ct(commit,table=Output,zone=%s,exec(move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))", ctZoneV6)},
		)
		tableSNATFlows.flows = append(tableSNATFlows.flows,
			&ofTestUtils.ExpectFlow{
				MatchStr: "priority=200,ct_state=+new+trk,ct_mark=0x40/0x40,ipv6,reg0=0x2/0xf",
				ActStr:   fmt.Sprintf("ct(commit,table=L2ForwardingCalc,zone=65511,nat(src=%s),exec(set_field:0x10/0x10->ct_mark,set_field:0x40/0x40->ct_mark))", agentconfig.VirtualServiceIPv6),
			},
			&ofTestUtils.ExpectFlow{
				MatchStr: "priority=200,ct_state=+new+trk,ct_mark=0x40/0x40,ipv6,reg0=0x3/0xf",
				ActStr:   fmt.Sprintf("ct(commit,table=L2ForwardingCalc,zone=65511,nat(src=%s),exec(set_field:0x10/0x10->ct_mark,set_field:0x40/0x40->ct_mark))", config.nodeConfig.GatewayConfig.IPv6),
			},
			&ofTestUtils.ExpectFlow{
				MatchStr: "priority=190,ct_state=+new+trk,ct_mark=0x20/0x20,ipv6,reg0=0x2/0xf",
				ActStr:   fmt.Sprintf("ct(commit,table=L2ForwardingCalc,zone=65511,nat(src=%s),exec(set_field:0x10/0x10->ct_mark))", config.nodeConfig.GatewayConfig.IPv6),
			},
			&ofTestUtils.ExpectFlow{
				MatchStr: "priority=200,ct_state=-new-rpl+trk,ct_mark=0x20/0x20,ipv6",
				ActStr:   "ct(table=L2ForwardingCalc,zone=65511,nat)",
			},
		)
		podCIDR := config.nodeConfig.PodIPv6CIDR.String()
		tableL3ForwardingFlows.flows = append(tableL3ForwardingFlows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: fmt.Sprintf("priority=200,ipv6,reg0=0/0x200,ipv6_dst=%s", podCIDR), ActStr: "goto_table:L2ForwardingCalc"},
		)
		tableSNATMarkFlows.flows = append(tableSNATMarkFlows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ct_state=+new+trk,ipv6,reg0=0x22/0xff", ActStr: "ct(commit,table=SNAT,zone=65510,exec(set_field:0x20/0x20->ct_mark,set_field:0x40/0x40->ct_mark))"},
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ct_state=+new+trk,ipv6,reg0=0x12/0xff,reg4=0x200000/0x2200000", ActStr: "ct(commit,table=SNAT,zone=65510,exec(set_field:0x20/0x20->ct_mark))"},
		)
		tableL3DecTTLFlows.flows = append(tableL3DecTTLFlows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=210,ipv6,reg0=0x2/0xf", ActStr: "goto_table:SNATMark"},
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ipv6", ActStr: "dec_ttl,goto_table:SNATMark"},
		)
	}
	if config.enableIPv4 && config.connectUplinkToBridge {
		tableARPResponderFlows.flows = append(tableARPResponderFlows.flows,
			&ofTestUtils.ExpectFlow{
				MatchStr: fmt.Sprintf("priority=200,arp,arp_tpa=%s,arp_op=1", config.nodeConfig.GatewayConfig.IPv4.String()),
				ActStr:   fmt.Sprintf("move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:%s->eth_src,set_field:2->arp_op,move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],set_field:%s->arp_sha,move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:%s->arp_spa,IN_PORT", config.nodeConfig.GatewayConfig.MAC.String(), config.nodeConfig.GatewayConfig.MAC.String(), config.nodeConfig.GatewayConfig.IPv4.String()),
			},
		)
	}

	tableFlows := []expectTableFlows{
		tableConntrackZoneFlows,
		tableConntrackStateFlows,
		tableConntrackCommitFlows,
		tableSNATFlows,
		tableL3ForwardingFlows,
		tableL3DecTTLFlows,
		tableUnSNATFlows,
		tableSNATMarkFlows,
		tableVLANFlows,
		{
			"Classifier",
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "drop"}},
		},
		{
			"SpoofGuard",
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "drop"}},
		},
		{
			"EndpointDNAT",
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:EgressRule"}},
		},
		{
			"EgressRule",
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:EgressDefaultRule"}},
		},
		{
			"EgressDefaultRule",
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:EgressMetric"}},
		},
		{
			"EgressMetric",
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:L3Forwarding"}},
		},
		{
			"L2ForwardingCalc",
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:IngressSecurityClassifier"}},
		},
		{
			"IngressSecurityClassifier",
			[]*ofTestUtils.ExpectFlow{
				{MatchStr: "priority=0", ActStr: "goto_table:IngressRule"},
				{MatchStr: "priority=200,reg0=0x20/0xf0", ActStr: "goto_table:IngressMetric"},
				{MatchStr: "priority=200,reg0=0x10/0xf0", ActStr: "goto_table:IngressMetric"},
			},
		},
		{
			"IngressRule",
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:IngressDefaultRule"}},
		},
		{
			"IngressDefaultRule",
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:IngressMetric"}},
		},
		{
			"IngressMetric",
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:ConntrackCommit"}},
		},
		{
			"Output",
			[]*ofTestUtils.ExpectFlow{
				{MatchStr: "priority=200,reg0=0x200000/0x600000", ActStr: "output:NXM_NX_REG1[]"},
			},
		},
	}
	if config.enableIPv4 {
		tableFlows = append(tableFlows, tableARPResponderFlows)
	}
	return tableFlows
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

func expectedExternalFlows(ipProtoStr, gwMACStr string) []expectTableFlows {
	return []expectTableFlows{
		{
			"L3Forwarding",
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=190,ct_state=-rpl+trk,%s,reg0=0x3/0xf,reg4=0/0x100000", ipProtoStr),
					ActStr:   "goto_table:EgressMark",
				},
				{
					MatchStr: fmt.Sprintf("priority=190,ct_state=-rpl+trk,%s,reg0=0x1/0xf", ipProtoStr),
					ActStr:   fmt.Sprintf("set_field:%s->eth_dst,goto_table:EgressMark", gwMACStr),
				},
			},
		},
		{
			"EgressMark",
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=190,ct_state=+new+trk,%s,reg0=0x1/0xf", ipProtoStr),
					ActStr:   "drop",
				},
				{
					MatchStr: "priority=0",
					ActStr:   "set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
				},
			},
		},
	}
}

func prepareEgressMarkFlows(snatIP net.IP, mark, podOFPort, podOFPortRemote uint32, vMAC, localGwMAC net.HardwareAddr, trafficShaping bool) []expectTableFlows {
	var ipProtoStr, tunDstFieldName, nextTableName string
	if snatIP.To4() != nil {
		tunDstFieldName = "tun_dst"
		ipProtoStr = "ip"
	} else {
		tunDstFieldName = "tun_ipv6_dst"
		ipProtoStr = "ipv6"
	}
	if trafficShaping {
		nextTableName = "EgressQoS"
	} else {
		nextTableName = "L2ForwardingCalc"
	}
	return []expectTableFlows{
		{
			"EgressMark",
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,ct_state=+trk,%s,%s=%s", ipProtoStr, tunDstFieldName, snatIP),
					ActStr:   fmt.Sprintf("set_field:0x%x/0xff->pkt_mark,set_field:0x20/0xf0->reg0,goto_table:%s", mark, nextTableName),
				},
				{
					MatchStr: fmt.Sprintf("priority=200,ct_state=+trk,%s,in_port=%d", ipProtoStr, podOFPort),
					ActStr:   fmt.Sprintf("set_field:0x%x/0xff->pkt_mark,set_field:0x20/0xf0->reg0,goto_table:%s", mark, nextTableName),
				},
				{
					MatchStr: fmt.Sprintf("priority=200,%s,in_port=%d", ipProtoStr, podOFPortRemote),
					ActStr:   fmt.Sprintf("set_field:%s->eth_src,set_field:%s->eth_dst,set_field:%s->%s,set_field:0x10/0xf0->reg0,set_field:0x80000/0x80000->reg0,goto_table:L2ForwardingCalc", localGwMAC.String(), vMAC.String(), snatIP, tunDstFieldName),
				},
			},
		},
	}
}

func prepareTrafficControlFlows(sourceOFPorts []uint32, targetOFPort, returnOFPort uint32) []expectTableFlows {
	expectedFlows := []expectTableFlows{
		{
			"Classifier",
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,in_port=%d", returnOFPort),
					ActStr:   "set_field:0x6/0xf->reg0,goto_table:L3Forwarding",
				},
			},
		},
		{
			"Output",
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: "priority=211,reg0=0x200000/0x600000,reg4=0x400000/0xc00000",
					ActStr:   "output:NXM_NX_REG1[],output:NXM_NX_REG9[]",
				},
				{
					MatchStr: "priority=211,reg0=0x200000/0x600000,reg4=0x800000/0xc00000",
					ActStr:   "output:NXM_NX_REG9[]",
				},
			},
		},
	}
	trafficControlTableFlows := expectTableFlows{
		"TrafficControl",
		[]*ofTestUtils.ExpectFlow{
			{
				MatchStr: "priority=210,reg0=0x200006/0x60000f",
				ActStr:   "goto_table:Output",
			},
		},
	}
	for _, port := range sourceOFPorts {
		trafficControlTableFlows.flows = append(trafficControlTableFlows.flows,
			&ofTestUtils.ExpectFlow{
				MatchStr: fmt.Sprintf("priority=200,reg1=0x%x", port),
				ActStr:   fmt.Sprintf("set_field:0x%x->reg9,set_field:0x800000/0xc00000->reg4,goto_table:IngressSecurityClassifier", targetOFPort),
			},
			&ofTestUtils.ExpectFlow{
				MatchStr: fmt.Sprintf("priority=200,in_port=%d", port),
				ActStr:   fmt.Sprintf("set_field:0x%x->reg9,set_field:0x800000/0xc00000->reg4,goto_table:IngressSecurityClassifier", targetOFPort),
			},
		)
	}
	expectedFlows = append(expectedFlows, trafficControlTableFlows)
	return expectedFlows
}

func TestEgressMarkFlows(t *testing.T) {
	testEgressMarkFlows(t, true)
	testEgressMarkFlows(t, false)
}

func testEgressMarkFlows(t *testing.T, trafficShaping bool) {
	// Reset OVS metrics (Prometheus) and reinitialize them to test.
	legacyregistry.Reset()
	metrics.InitializeOVSMetrics()

	c = ofClient.NewClient(br, bridgeMgmtAddr, nodeiptest.NewFakeNodeIPChecker(), false, false, false, true, trafficShaping, false, false, false, false, false, false, false, false, groupIDAllocator, false, defaultPacketInRate)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge %s", br))

	config := prepareConfiguration(true, true, false)
	_, err = c.Initialize(roundInfo, config.nodeConfig, &agentconfig.NetworkConfig{TrafficEncapMode: agentconfig.TrafficEncapModeEncap}, &agentconfig.EgressConfig{}, &agentconfig.ServiceConfig{}, &agentconfig.L7NetworkPolicyConfig{})
	require.Nil(t, err, "Failed to initialize OFClient")

	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
		ofClient.CleanOFTableCache()
		ofClient.ResetOFTable()
	}()

	snatIP := net.ParseIP("10.10.10.14")
	snatIPV6 := net.ParseIP("a963:ca9b:172:10::16")
	snatMark := uint32(14)
	snatMarkV6 := uint32(16)
	podOFPort := uint32(104)
	podOFPortRemote := uint32(204)
	podOFPortV6 := uint32(106)
	podOFPortRemoteV6 := uint32(206)

	vMAC := config.globalMAC
	gwMAC := config.nodeConfig.GatewayConfig.MAC
	expectedFlows := append(prepareEgressMarkFlows(snatIP, snatMark, podOFPort, podOFPortRemote, vMAC, gwMAC, trafficShaping),
		prepareEgressMarkFlows(snatIPV6, snatMarkV6, podOFPortV6, podOFPortRemoteV6, vMAC, gwMAC, trafficShaping)...)

	c.InstallSNATMarkFlows(snatIP, snatMark)
	c.InstallSNATMarkFlows(snatIPV6, snatMarkV6)
	c.InstallPodSNATFlows(podOFPort, snatIP, snatMark)
	c.InstallPodSNATFlows(podOFPortRemote, snatIP, 0)
	c.InstallPodSNATFlows(podOFPortV6, snatIPV6, snatMarkV6)
	c.InstallPodSNATFlows(podOFPortRemoteV6, snatIPV6, 0)
	for _, tableFlow := range expectedFlows {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, true, tableFlow.flows)
	}

	c.UninstallPodSNATFlows(podOFPort)
	c.UninstallPodSNATFlows(podOFPortRemote)
	c.UninstallPodSNATFlows(podOFPortV6)
	c.UninstallPodSNATFlows(podOFPortRemoteV6)
	c.UninstallSNATMarkFlows(snatMark)
	c.UninstallSNATMarkFlows(snatMarkV6)
	for _, tableFlow := range expectedFlows {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, false, tableFlow.flows)
	}
}

func TestTrafficControlFlows(t *testing.T) {
	// Reset OVS metrics (Prometheus) and reinitialize them to test.
	legacyregistry.Reset()
	metrics.InitializeOVSMetrics()

	c = ofClient.NewClient(br, bridgeMgmtAddr, nodeiptest.NewFakeNodeIPChecker(), false, false, false, false, false, false, false, false, false, false, true, false, false, groupIDAllocator, false, defaultPacketInRate)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge %s", br))

	config := prepareConfiguration(true, false, false)
	_, err = c.Initialize(roundInfo, config.nodeConfig, &agentconfig.NetworkConfig{TrafficEncapMode: agentconfig.TrafficEncapModeEncap, IPv4Enabled: config.enableIPv4}, &agentconfig.EgressConfig{}, &agentconfig.ServiceConfig{}, &agentconfig.L7NetworkPolicyConfig{})
	require.Nil(t, err, "Failed to initialize OFClient")

	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
		ofClient.CleanOFTableCache()
		ofClient.ResetOFTable()
	}()

	sourceOFPorts := []uint32{100, 101, 102}
	targetOFPort := uint32(200)
	returnOFPort := uint32(201)
	expectedFlows := prepareTrafficControlFlows(sourceOFPorts, targetOFPort, returnOFPort)
	c.InstallTrafficControlReturnPortFlow(returnOFPort)
	c.InstallTrafficControlMarkFlows("tc", sourceOFPorts, targetOFPort, v1alpha2.DirectionBoth, v1alpha2.ActionRedirect, types.TrafficControlFlowPriorityMedium)
	for _, tableFlow := range expectedFlows {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableName, 0, true, tableFlow.flows)
	}
}
