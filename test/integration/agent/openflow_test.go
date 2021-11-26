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
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/component-base/metrics/legacyregistry"

	config1 "antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/metrics"
	ofClient "antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	k8stypes "antrea.io/antrea/pkg/agent/proxy/types"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	ofconfig "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	utilip "antrea.io/antrea/pkg/util/ip"
	antrearuntime "antrea.io/antrea/pkg/util/runtime"
	ofTestUtils "antrea.io/antrea/test/integration/ovs"
	k8sproxy "antrea.io/antrea/third_party/proxy"
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
	ips    []net.IP
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
	nodeMAC     net.HardwareAddr
}

type testConfig struct {
	bridge                string
	nodeConfig            *config1.NodeConfig
	localPods             []*testLocalPodConfig
	peers                 []*testPeerConfig
	serviceCIDR           *net.IPNet
	globalMAC             net.HardwareAddr
	enableIPv6            bool
	enableIPv4            bool
	connectUplinkToBridge bool
}

var (
	_, podIPv4CIDR, _ = net.ParseCIDR("192.168.1.0/24")
	_, podIPv6CIDR, _ = net.ParseCIDR("fd74:ca9b:172:19::/64")
)

func TestConnectivityFlows(t *testing.T) {
	// Initialize ovs metrics (Prometheus) to test them
	metrics.InitializeOVSMetrics()

	// Hack the OS type if we run the test not on Windows Node.
	// Because we test some Windows only functions.
	if !antrearuntime.IsWindowsPlatform() {
		antrearuntime.WindowsOS = runtime.GOOS
	}

	c = ofClient.NewClient(br, bridgeMgmtAddr, ovsconfig.OVSDatapathNetdev, true, false, true, false, false, false)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))
	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
	}()

	config := prepareConfiguration()
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
}

func TestAntreaFlexibleIPAMConnectivityFlows(t *testing.T) {
	// Initialize ovs metrics (Prometheus) to test them
	metrics.InitializeOVSMetrics()

	c = ofClient.NewClient(br, bridgeMgmtAddr, ovsconfig.OVSDatapathNetdev, true, false, true, false, false, true)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))
	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
	}()

	config := prepareConfiguration()
	config.connectUplinkToBridge = true
	config.localPods[0].ips = []net.IP{net.ParseIP("192.168.255.3")}
	uplinkMAC, _ := net.ParseMAC("aa:aa:aa:aa:aa:00")
	config.nodeConfig.UplinkNetConfig = &config1.AdapterNetConfig{
		Name:  "fake-uplink",
		Index: 0,
		MAC:   uplinkMAC,
		IP: &net.IPNet{
			IP:   nil,
			Mask: nil,
		},
		Gateway:    "",
		DNSServers: "",
		Routes:     nil,
	}
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
	c = ofClient.NewClient(br, bridgeMgmtAddr, ovsconfig.OVSDatapathNetdev, true, false, false, false, false, false)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))

	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
	}()

	config := prepareConfiguration()
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
	t.Run("testInstallPodFlows", func(t *testing.T) {
		testReplayFlows(t)
	})
}

func TestReplayFlowsNetworkPolicyFlows(t *testing.T) {
	c = ofClient.NewClient(br, bridgeMgmtAddr, ovsconfig.OVSDatapathNetdev, true, false, false, false, false, false)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))

	_, err = c.Initialize(roundInfo, &config1.NodeConfig{}, &config1.NetworkConfig{TrafficEncapMode: config1.TrafficEncapModeEncap})
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
	tcpProtocol := v1beta2.ProtocolTCP
	defaultAction := crdv1alpha1.RuleActionAllow
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

	err = c.AddPolicyRuleAddress(ruleID, types.SrcAddress, prepareIPNetAddresses([]string{"192.168.5.0/24", "192.169.1.0/24"}), nil)
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")
	ofport := int32(100)
	err = c.AddPolicyRuleAddress(ruleID, types.DstAddress, []types.Address{ofClient.NewOFPortAddress(ofport)}, nil)
	require.Nil(t, err, "Failed to AddPolicyRuleAddress")

	testReplayFlows(t)
}

func testExternalFlows(t *testing.T, config *testConfig) {
	exceptCIDRs := []net.IPNet{}
	if err := c.InstallExternalFlows(exceptCIDRs); err != nil {
		t.Errorf("Failed to install OpenFlow entries to allow Pod to communicate to the external addresses: %v", err)
	}

	gwMAC := config.nodeConfig.GatewayConfig.MAC
	if config.nodeConfig.NodeIPv4Addr != nil && config.nodeConfig.PodIPv4CIDR != nil {
		for _, tableFlow := range expectedExternalFlows(config.nodeConfig.NodeIPv4Addr.IP, config.nodeConfig.PodIPv4CIDR, gwMAC) {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
		}
	}
	if config.nodeConfig.NodeIPv6Addr != nil && config.nodeConfig.PodIPv6CIDR != nil {
		for _, tableFlow := range expectedExternalFlows(config.nodeConfig.NodeIPv6Addr.IP, config.nodeConfig.PodIPv6CIDR, gwMAC) {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
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
	count2 := countFlows()
	assert.Zero(t, count2, "Expected no flows after deletion")
	c.ReplayFlows()
	count3 := countFlows()
	t.Logf("Counted %d flows after reconciliation", count3)
	assert.Equal(t, count1, count3, "Expected same number of flows after reconciliation")
}

func testInitialize(t *testing.T, config *testConfig) {
	if _, err := c.Initialize(roundInfo, config.nodeConfig, &config1.NetworkConfig{TrafficEncapMode: config1.TrafficEncapModeEncap}); err != nil {
		t.Errorf("Failed to initialize openflow client: %v", err)
	}
	for _, tableFlow := range prepareDefaultFlows(config) {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
	}
	checkOVSFlowMetrics(t, c)
}

func testInstallTunnelFlows(t *testing.T, config *testConfig) {
	err := c.InstallDefaultTunnelFlows()
	if err != nil {
		t.Fatalf("Failed to install Openflow entries for tunnel port: %v", err)
	}
	for _, tableFlow := range prepareTunnelFlows(config1.DefaultTunOFPort, config.globalMAC) {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
	}
}

func testInstallServiceFlows(t *testing.T, config *testConfig) {
	err := c.InstallDefaultServiceFlows(nil, nil)
	if err != nil {
		t.Fatalf("Failed to install Openflow entries to skip service CIDR from egress table: %v", err)
	}
	for _, tableFlow := range prepareServiceHelperFlows() {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
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
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
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
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, false, tableFlow.flows)
		}
	}
}

func testInstallPodFlows(t *testing.T, config *testConfig) {
	gatewayConfig := config.nodeConfig.GatewayConfig
	for _, pod := range config.localPods {
		err := c.InstallPodFlows(pod.name, pod.ips, pod.mac, pod.ofPort)
		if err != nil {
			t.Fatalf("Failed to install Openflow entries for pod: %v", err)
		}
		for _, tableFlow := range preparePodFlows(pod.ips, pod.mac, pod.ofPort, gatewayConfig.MAC, config.globalMAC, config.nodeConfig, config.connectUplinkToBridge) {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
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
		for _, tableFlow := range preparePodFlows(pod.ips, pod.mac, pod.ofPort, gatewayConfig.MAC, config.globalMAC, config.nodeConfig, config.connectUplinkToBridge) {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, false, tableFlow.flows)
		}
	}
}

func TestNetworkPolicyFlows(t *testing.T) {
	// Initialize ovs metrics (Prometheus) to test them
	metrics.InitializeOVSMetrics()

	c = ofClient.NewClient(br, bridgeMgmtAddr, ovsconfig.OVSDatapathNetdev, true, false, false, false, false, false)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge %s", br))

	_, err = c.Initialize(roundInfo, &config1.NodeConfig{PodIPv4CIDR: podIPv4CIDR, PodIPv6CIDR: podIPv6CIDR, GatewayConfig: gwConfig}, &config1.NetworkConfig{TrafficEncapMode: config1.TrafficEncapModeEncap})
	require.Nil(t, err, "Failed to initialize OFClient")

	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
	}()

	ruleID := uint32(100)
	fromList := []string{"192.168.1.3", "192.168.1.25", "192.168.2.4", "fd12:ab:34:a001::3"}
	toList := []string{"192.168.3.4", "192.168.3.5", "fd12:ab:34:a002::4"}

	port2 := intstr.FromInt(8080)
	tcpProtocol := v1beta2.ProtocolTCP
	defaultAction := crdv1alpha1.RuleActionAllow
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
	checkConjunctionFlows(t, ingressRuleTable, ingressDefaultTable, contrackCommitTable, priorityNormal, ruleID, rule, assert.True)
	checkDefaultDropFlows(t, ingressDefaultTable, priorityNormal, types.DstAddress, toIPList, true)

	addedFrom := prepareIPNetAddresses([]string{"192.168.5.0/24", "192.169.1.0/24", "fd12:ab:34:a003::/64"})
	checkAddAddress(t, ingressRuleTable, priorityNormal, ruleID, addedFrom, types.SrcAddress)
	checkDeleteAddress(t, ingressRuleTable, priorityNormal, ruleID, addedFrom, types.SrcAddress)

	ofport := int32(100)
	err = c.AddPolicyRuleAddress(ruleID, types.DstAddress, []types.Address{ofClient.NewOFPortAddress(ofport)}, nil)
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
	checkConjunctionFlows(t, ingressRuleTable, ingressDefaultTable, contrackCommitTable, priorityNormal, ruleID, rule, assert.False)
	checkDefaultDropFlows(t, ingressDefaultTable, priorityNormal, types.DstAddress, toIPList, false)
	checkOVSFlowMetrics(t, c)
}

func TestIPv6ConnectivityFlows(t *testing.T) {
	// Initialize ovs metrics (Prometheus) to test them
	metrics.InitializeOVSMetrics()

	c = ofClient.NewClient(br, bridgeMgmtAddr, ovsconfig.OVSDatapathNetdev, true, false, true, false, false, false)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))

	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
	}()
	config := prepareIPv6Configuration()
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

type svcConfig struct {
	ip                  net.IP
	port                uint16
	protocol            ofconfig.Protocol
	withSessionAffinity bool
}

func TestProxyServiceFlows(t *testing.T) {
	c = ofClient.NewClient(br, bridgeMgmtAddr, ovsconfig.OVSDatapathNetdev, true, false, false, false, false, false)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge %s", br))

	_, err = c.Initialize(roundInfo, &config1.NodeConfig{PodIPv4CIDR: podIPv4CIDR, PodIPv6CIDR: podIPv6CIDR, GatewayConfig: gwConfig}, &config1.NetworkConfig{TrafficEncapMode: config1.TrafficEncapModeEncap})
	require.Nil(t, err, "Failed to initialize OFClient")

	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
	}()

	endpoints := []k8sproxy.Endpoint{
		k8stypes.NewEndpointInfo(&k8sproxy.BaseEndpointInfo{
			Endpoint: net.JoinHostPort("192.168.1.2", "8081"),
			IsLocal:  true,
		}),
		k8stypes.NewEndpointInfo(&k8sproxy.BaseEndpointInfo{
			Endpoint: net.JoinHostPort("10.20.1.11", "8081"),
			IsLocal:  false,
		}),
	}

	stickyMaxAgeSeconds := uint16(30)

	tcs := []struct {
		svc       svcConfig
		gid       uint32
		endpoints []k8sproxy.Endpoint
		stickyAge uint16
	}{
		{
			svc: svcConfig{
				protocol: ofconfig.ProtocolTCP,
				ip:       net.ParseIP("10.20.30.41"),
				port:     uint16(8000),
			},
			gid:       2,
			endpoints: endpoints,
			stickyAge: stickyMaxAgeSeconds,
		},
		{
			svc: svcConfig{
				protocol: ofconfig.ProtocolUDP,
				ip:       net.ParseIP("10.20.30.42"),
				port:     uint16(8000),
			},
			gid:       3,
			endpoints: endpoints,
			stickyAge: stickyMaxAgeSeconds,
		},
		{
			svc: svcConfig{
				protocol: ofconfig.ProtocolSCTP,
				ip:       net.ParseIP("10.20.30.43"),
				port:     uint16(8000),
			},
			gid:       4,
			endpoints: endpoints,
			stickyAge: stickyMaxAgeSeconds,
		},
	}

	for _, tc := range tcs {
		groupID := ofconfig.GroupIDType(tc.gid)
		expTableFlows, expGroupBuckets := expectedProxyServiceGroupAndFlows(tc.gid, tc.svc, tc.endpoints, tc.stickyAge)
		installServiceFlows(t, tc.gid, tc.svc, tc.endpoints, tc.stickyAge)
		for _, tableFlow := range expTableFlows {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
		}
		ofTestUtils.CheckGroupExists(t, ovsCtlClient, groupID, "select", expGroupBuckets, true)

		uninstallServiceFlowsFunc(t, tc.gid, tc.svc, tc.endpoints)
		for _, tableFlow := range expTableFlows {
			ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, false, tableFlow.flows)
		}
		ofTestUtils.CheckGroupExists(t, ovsCtlClient, groupID, "select", expGroupBuckets, false)
	}
}

func installServiceFlows(t *testing.T, gid uint32, svc svcConfig, endpointList []k8sproxy.Endpoint, stickyMaxAgeSeconds uint16) {
	groupID := ofconfig.GroupIDType(gid)
	err := c.InstallEndpointFlows(svc.protocol, endpointList)
	assert.NoError(t, err, "no error should return when installing flows for Endpoints")
	err = c.InstallServiceGroup(groupID, svc.withSessionAffinity, endpointList)
	assert.NoError(t, err, "no error should return when installing groups for Service")
	err = c.InstallServiceFlows(groupID, svc.ip, svc.port, svc.protocol, stickyMaxAgeSeconds, false, v1.ServiceTypeClusterIP)
	assert.NoError(t, err, "no error should return when installing flows for Service")
}

func uninstallServiceFlowsFunc(t *testing.T, gid uint32, svc svcConfig, endpointList []k8sproxy.Endpoint) {
	groupID := ofconfig.GroupIDType(gid)
	err := c.UninstallServiceFlows(svc.ip, svc.port, svc.protocol)
	assert.Nil(t, err)
	err = c.UninstallServiceGroup(groupID)
	assert.Nil(t, err)
	for _, ep := range endpointList {
		err := c.UninstallEndpointFlows(svc.protocol, ep)
		assert.Nil(t, err)
	}
}

func expectedProxyServiceGroupAndFlows(gid uint32, svc svcConfig, endpointList []k8sproxy.Endpoint, stickyAge uint16) (tableFlows []expectTableFlows, groupBuckets []string) {
	nw_proto := 6
	learnProtoField := "NXM_OF_TCP_DST[]"
	if svc.protocol == ofconfig.ProtocolUDP {
		nw_proto = 17
		learnProtoField = "NXM_OF_UDP_DST[]"
	} else if svc.protocol == ofconfig.ProtocolSCTP {
		nw_proto = 132
		learnProtoField = "OXM_OF_SCTP_DST[]"
	}

	serviceLearnReg := 2
	if stickyAge != 0 {
		serviceLearnReg = 3
	}
	cookieAllocator := cookie.NewAllocator(roundInfo.RoundNum)
	svcFlows := expectTableFlows{tableID: 41, flows: []*ofTestUtils.ExpectFlow{
		{
			MatchStr: fmt.Sprintf("priority=200,%s,reg4=0x10000/0x70000,nw_dst=%s,tp_dst=%d", string(svc.protocol), svc.ip.String(), svc.port),
			ActStr:   fmt.Sprintf("load:0x%x->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG0[19],load:0x%x->NXM_NX_REG7[],group:%d", serviceLearnReg, gid, gid),
		},
		{
			MatchStr: fmt.Sprintf("priority=190,%s,reg4=0x30000/0x70000,nw_dst=%s,tp_dst=%d", string(svc.protocol), svc.ip.String(), svc.port),
			ActStr:   fmt.Sprintf("learn(table=40,hard_timeout=%d,priority=200,delete_learned,cookie=0x%x,eth_type=0x800,nw_proto=%d,%s,NXM_OF_IP_DST[],NXM_OF_IP_SRC[],load:NXM_NX_REG3[]->NXM_NX_REG3[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG0[19]),load:0x2->NXM_NX_REG4[16..18],goto_table:42", stickyAge, cookieAllocator.RequestWithObjectID(4, gid).Raw(), nw_proto, learnProtoField),
		},
	}}
	epDNATFlows := expectTableFlows{tableID: 42, flows: []*ofTestUtils.ExpectFlow{}}
	hairpinFlows := expectTableFlows{tableID: 108, flows: []*ofTestUtils.ExpectFlow{}}
	groupBuckets = make([]string, 0)
	for _, ep := range endpointList {
		epIP := ipToHexString(net.ParseIP(ep.IP()))
		epPort, _ := ep.Port()
		bucket := fmt.Sprintf("weight:100,actions=load:%s->NXM_NX_REG3[],load:0x%x->NXM_NX_REG4[0..15],resubmit(,42)", epIP, epPort)
		groupBuckets = append(groupBuckets, bucket)

		unionVal := (0b010 << 16) + uint32(epPort)
		epDNATFlows.flows = append(epDNATFlows.flows, &ofTestUtils.ExpectFlow{
			MatchStr: fmt.Sprintf("priority=200,%s,reg3=%s,reg4=0x%x/0x7ffff", string(svc.protocol), epIP, unionVal),
			ActStr:   fmt.Sprintf("ct(commit,table=50,zone=65520,nat(dst=%s:%d),exec(load:0x1->NXM_NX_CT_MARK[2])", ep.IP(), epPort),
		})

		if ep.GetIsLocal() {
			hairpinFlows.flows = append(hairpinFlows.flows, &ofTestUtils.ExpectFlow{
				MatchStr: fmt.Sprintf("priority=200,ip,nw_src=%s,nw_dst=%s", ep.IP(), ep.IP()),
				ActStr:   "set_field:169.254.169.252->ip_src,load:0x1->NXM_NX_REG0[18],goto_table:110",
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

func checkDefaultDropFlows(t *testing.T, table uint8, priority int, addrType types.AddressType, addresses []types.Address, add bool) {
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
		_, ipProto := getIPProtoStr(addr)
		conjMatch := fmt.Sprintf("priority=%d,%s,%s=%s", priority, ipProto, addr.GetMatchKey(addrType).GetKeyString(), addr.GetMatchValue())
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
		_, ipProto := getIPProtoStr(addr)
		conjMatch := fmt.Sprintf("priority=%d,%s,%s=%s", priority, ipProto, addr.GetMatchKey(addrType).GetKeyString(), addr.GetMatchValue())
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
	nextTable := ofClient.IngressMetricTable.GetID()
	if ruleTable == ofClient.EgressRuleTable.GetID() {
		nextTable = ofClient.EgressMetricTable.GetID()
	}

	flow := &ofTestUtils.ExpectFlow{MatchStr: conjunctionActionMatch, ActStr: fmt.Sprintf("load:0x%x->NXM_NX_REG%d[],ct(commit,table=%d,zone=65520,exec(load:0x%x->NXM_NX_CT_LABEL[0..31])", ruleID, conjReg, nextTable, ruleID)}
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
		if tableStatus.ID == uint(ruleTable) {
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
	gatewayConfig := config.nodeConfig.GatewayConfig
	err := c.InstallGatewayFlows()
	if err != nil {
		t.Fatalf("Failed to install Openflow entries for gateway: %v", err)
	}
	var ips []net.IP
	if config.enableIPv4 {
		ips = append(ips, gatewayConfig.IPv4)
	}
	if config.enableIPv6 {
		ips = append(ips, gatewayConfig.IPv6)
	}
	for _, tableFlow := range prepareGatewayFlows(ips, gatewayConfig.MAC, config.globalMAC, config.nodeConfig, config.connectUplinkToBridge) {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
	}
}

func prepareConfiguration() *testConfig {
	podMAC, _ := net.ParseMAC("aa:aa:aa:aa:aa:13")
	gwMAC, _ := net.ParseMAC("aa:aa:aa:aa:aa:11")
	peerNodeMAC, _ := net.ParseMAC("aa:aa:aa:aa:ab:00")
	nodeIP, nodeSubnet, _ := net.ParseCIDR("10.10.10.1/24")
	nodeSubnet.IP = nodeIP

	gatewayConfig := &config1.GatewayConfig{
		IPv4: net.ParseIP("192.168.1.1"),
		MAC:  gwMAC,
	}
	nodeConfig := &config1.NodeConfig{
		NodeIPv4Addr:  nodeSubnet,
		GatewayConfig: gatewayConfig,
		PodIPv4CIDR:   podIPv4CIDR,
	}

	podCfg := &testLocalPodConfig{
		name: "container-1",
		testPortConfig: &testPortConfig{
			ips:    []net.IP{net.ParseIP("192.168.1.3")},
			mac:    podMAC,
			ofPort: uint32(11),
		},
	}
	_, serviceCIDR, _ := net.ParseCIDR("172.16.0.0/16")
	_, peerSubnet, _ := net.ParseCIDR("192.168.2.0/24")
	peerNode := &testPeerConfig{
		name:        "n2",
		nodeAddress: net.ParseIP("10.1.1.2"),
		subnet:      *peerSubnet,
		gateway:     net.ParseIP("192.168.2.1"),
		nodeMAC:     peerNodeMAC,
	}
	vMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	return &testConfig{
		bridge:      br,
		nodeConfig:  nodeConfig,
		localPods:   []*testLocalPodConfig{podCfg},
		peers:       []*testPeerConfig{peerNode},
		serviceCIDR: serviceCIDR,
		globalMAC:   vMAC,
		enableIPv4:  true,
		enableIPv6:  false,
	}
}

func prepareIPv6Configuration() *testConfig {
	podMAC, _ := net.ParseMAC("aa:aa:aa:aa:aa:13")
	nodeIP, nodeSubnet, _ := net.ParseCIDR("a963:ca9b:172:10::11/64")
	nodeSubnet.IP = nodeIP
	gwMAC, _ := net.ParseMAC("aa:aa:aa:aa:aa:11")

	gatewayConfig := &config1.GatewayConfig{
		IPv6: net.ParseIP("fd74:ca9b:172:19::1"),
		MAC:  gwMAC,
	}
	nodeConfig := &config1.NodeConfig{
		NodeIPv4Addr:  nodeSubnet,
		GatewayConfig: gatewayConfig,
		PodIPv6CIDR:   podIPv6CIDR,
	}

	podCfg := &testLocalPodConfig{
		name: "container-1",
		testPortConfig: &testPortConfig{
			ips:    []net.IP{net.ParseIP("fd74:ca9b:172:19::3")},
			mac:    podMAC,
			ofPort: uint32(11),
		},
	}
	_, serviceCIDR, _ := net.ParseCIDR("ee74:ca9b:2345:a33::/64")
	_, peerSubnet, _ := net.ParseCIDR("fd74:ca9b:172:20::/64")
	peerNode := &testPeerConfig{
		name:        "n2",
		nodeAddress: net.ParseIP("10.1.1.2"),
		subnet:      *peerSubnet,
		gateway:     net.ParseIP("fd74:ca9b:172:20::1"),
	}
	vMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	return &testConfig{
		bridge:      br,
		nodeConfig:  nodeConfig,
		localPods:   []*testLocalPodConfig{podCfg},
		peers:       []*testPeerConfig{peerNode},
		serviceCIDR: serviceCIDR,
		globalMAC:   vMAC,
		enableIPv4:  false,
		enableIPv6:  true,
	}
}

func preparePodFlows(podIPs []net.IP, podMAC net.HardwareAddr, podOFPort uint32, gwMAC, vMAC net.HardwareAddr, nodeConfig *config1.NodeConfig, connectUplinkToBridge bool) []expectTableFlows {
	podIPv4 := util.GetIPv4Addr(podIPs)
	isAntreaFlexibleIPAM := connectUplinkToBridge && podIPv4 != nil && !nodeConfig.PodIPv4CIDR.Contains(podIPv4)
	actionAntreaFlexibleIPAMMarkString := ""
	matchRewriteMACMarkString := ",reg0=0x80000/0x80000"
	if isAntreaFlexibleIPAM {
		actionAntreaFlexibleIPAMMarkString = ",load:0x1->NXM_NX_REG4[21]"
		matchRewriteMACMarkString = ""
	}
	flows := []expectTableFlows{
		{
			uint8(0),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=190,in_port=%d", podOFPort),
					ActStr:   fmt.Sprintf("load:0x2->NXM_NX_REG0[0..3]%s,goto_table:10", actionAntreaFlexibleIPAMMarkString),
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

	if isAntreaFlexibleIPAM {
		flows = append(flows, []expectTableFlows{{
			uint8(0),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=210,in_port=%d,dl_dst=%s", 3, podMAC.String()),
					ActStr:   fmt.Sprintf("load:0x4->NXM_NX_REG0[0..3],goto_table:23"),
				},
			},
		},
			{
				uint8(0),
				[]*ofTestUtils.ExpectFlow{
					{
						MatchStr: fmt.Sprintf("priority=210,in_port=LOCAL,dl_dst=%s", podMAC.String()),
						ActStr:   fmt.Sprintf("load:0x5->NXM_NX_REG0[0..3],goto_table:23"),
					},
				},
			}}...)
	}

	for _, podIP := range podIPs {
		var ipProto, nwSrcField, nwDstField string
		var nextTableForSpoofguard uint8
		if podIP.To4() != nil {
			ipProto = "ip"
			nwSrcField = "nw_src"
			nwDstField = "nw_dst"
			flows = append(flows,
				expectTableFlows{
					uint8(10),
					[]*ofTestUtils.ExpectFlow{
						{
							MatchStr: fmt.Sprintf("priority=200,arp,in_port=%d,arp_spa=%s,arp_sha=%s", podOFPort, podIP.String(), podMAC.String()),
							ActStr:   "goto_table:20",
						},
					},
				})
			nextTableForSpoofguard = 23
		} else {
			ipProto = "ipv6"
			nwSrcField = "ipv6_src"
			nwDstField = "ipv6_dst"
			nextTableForSpoofguard = 21
		}
		flows = append(flows,
			expectTableFlows{
				uint8(10),
				[]*ofTestUtils.ExpectFlow{
					{
						MatchStr: fmt.Sprintf("priority=200,%s,in_port=%d,dl_src=%s,%s=%s", ipProto, podOFPort, podMAC.String(), nwSrcField, podIP.String()),
						ActStr:   fmt.Sprintf("goto_table:%d", nextTableForSpoofguard),
					},
				},
			},
			expectTableFlows{
				uint8(70),
				[]*ofTestUtils.ExpectFlow{
					{
						MatchStr: fmt.Sprintf("priority=200,%s%s,%s=%s", ipProto, matchRewriteMACMarkString, nwDstField, podIP.String()),
						ActStr:   fmt.Sprintf("set_field:%s->eth_src,set_field:%s->eth_dst,goto_table:72", gwMAC.String(), podMAC.String()),
					},
				},
			},
		)
	}

	return flows
}

func prepareGatewayFlows(gwIPs []net.IP, gwMAC net.HardwareAddr, vMAC net.HardwareAddr, nodeConfig *config1.NodeConfig, connectUplinkToBridge bool) []expectTableFlows {
	flows := []expectTableFlows{
		{
			uint8(0),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,in_port=%d", config1.HostGatewayOFPort),
					ActStr:   "load:0x1->NXM_NX_REG0[0..3],goto_table:10",
				},
			},
		},
		{
			uint8(80),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,dl_dst=%s", gwMAC.String()),
					ActStr:   fmt.Sprintf("load:0x%x->NXM_NX_REG1[],load:0x1->NXM_NX_REG0[16],goto_table:101", config1.HostGatewayOFPort),
				},
			},
		},
	}

	for _, gwIP := range gwIPs {
		var ipProtoStr, nwSrcStr, nwDstStr string
		if gwIP.To4() != nil {
			ipProtoStr = "ip"
			nwSrcStr = "nw_src"
			nwDstStr = "nw_dst"
			flows = append(flows,
				expectTableFlows{
					uint8(10),
					[]*ofTestUtils.ExpectFlow{
						{
							MatchStr: fmt.Sprintf("priority=200,arp,in_port=%d,arp_spa=%s,arp_sha=%s", config1.HostGatewayOFPort, gwIP, gwMAC),
							ActStr:   "goto_table:20",
						},
						{
							MatchStr: fmt.Sprintf("priority=200,ip,in_port=%d", config1.HostGatewayOFPort),
							ActStr:   "goto_table:23",
						},
					},
				})
			if connectUplinkToBridge {
				flows[len(flows)-1].flows = append(flows[len(flows)-1].flows, &ofTestUtils.ExpectFlow{
					MatchStr: fmt.Sprintf("priority=200,arp,in_port=%d,arp_spa=%s,arp_sha=%s", config1.HostGatewayOFPort, nodeConfig.NodeIPv4Addr.IP.String(), gwMAC),
					ActStr:   "goto_table:20",
				})
			}
		} else {
			ipProtoStr = "ipv6"
			nwSrcStr = "ipv6_src"
			nwDstStr = "ipv6_dst"
		}
		flows = append(flows,
			expectTableFlows{
				uint8(70),
				[]*ofTestUtils.ExpectFlow{
					{
						MatchStr: fmt.Sprintf("priority=200,%s,reg0=0x80000/0x80000,%s=%s", ipProtoStr, nwDstStr, gwIP.String()),
						ActStr:   fmt.Sprintf("set_field:%s->eth_dst,goto_table:80", gwMAC.String()),
					},
				},
			},
			expectTableFlows{
				tableID: uint8(90),
				flows: []*ofTestUtils.ExpectFlow{
					{
						MatchStr: fmt.Sprintf("priority=210,%s,%s=%s", ipProtoStr, nwSrcStr, gwIP.String()),
						ActStr:   "goto_table:105",
					},
				},
			},
			expectTableFlows{
				uint8(70),
				[]*ofTestUtils.ExpectFlow{
					{
						MatchStr: fmt.Sprintf("priority=210,ct_state=+rpl+trk,ct_mark=0x2/0x2,%s,reg0=0x2/0xf", ipProtoStr),
						ActStr:   fmt.Sprintf("set_field:%s->eth_dst,goto_table:80", gwMAC.String()),
					},
					{
						MatchStr: fmt.Sprintf("priority=210,ct_state=+rpl+trk,ct_mark=0x2/0x2,%s,reg0=0/0xf", ipProtoStr),
						ActStr:   fmt.Sprintf("set_field:%s->eth_dst,goto_table:80", gwMAC.String()),
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
			uint8(0),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,in_port=%d", tunnelPort),
					ActStr:   "load:0->NXM_NX_REG0[0..3],load:0x1->NXM_NX_REG0[19],goto_table:30",
				},
			},
		},
		{
			uint8(80),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,dl_dst=%s", vMAC.String()),
					ActStr:   fmt.Sprintf("load:0x%x->NXM_NX_REG1[],load:0x1->NXM_NX_REG0[16],goto_table:101", config1.DefaultTunOFPort),
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
			uint8(20),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,arp,arp_tpa=%s,arp_op=1", peerGwIP.String()),
					ActStr:   fmt.Sprintf("move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:%s->eth_src,load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],set_field:%s->arp_sha,move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:%s->arp_spa,IN_PORT", vMAC.String(), vMAC.String(), peerGwIP.String()),
				},
			},
		})
	} else {
		ipProtoStr = "ipv6"
		nwDstFieldName = "ipv6_dst"
	}
	expFlows = append(expFlows, expectTableFlows{
		uint8(70),
		[]*ofTestUtils.ExpectFlow{
			{
				MatchStr: fmt.Sprintf("priority=200,%s,%s=%s", ipProtoStr, nwDstFieldName, peerSubnet.String()),
				ActStr:   fmt.Sprintf("set_field:%s->eth_src,set_field:%s->eth_dst,set_field:%s->tun_dst,goto_table:72", localGwMAC.String(), vMAC.String(), peerNodeIP.String()),
			},
		},
	})
	if connectUplinkToBridge {
		expFlows = append(expFlows, expectTableFlows{
			uint8(70),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=210,%s,reg4=0x200000/0x200000,%s=%s", ipProtoStr, nwDstFieldName, peerSubnet.String()),
					ActStr:   fmt.Sprintf("set_field:%s->eth_dst,goto_table:80", peerNodeMAC.String()),
				},
			},
		})
	}

	return expFlows
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

func prepareDefaultFlows(config *testConfig) []expectTableFlows {
	table20Flows := expectTableFlows{
		tableID: 20,
		flows:   []*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "drop"}},
	}
	table31Flows := expectTableFlows{
		tableID: 31,
		flows:   []*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "resubmit(,40),resubmit(,41)"}},
	}
	table105Flows := expectTableFlows{
		tableID: 105,
		flows:   []*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:108"}},
	}
	table72Flows := expectTableFlows{
		tableID: 72,
		flows:   []*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:80"}},
	}
	table30Flows := expectTableFlows{
		tableID: 30,
	}
	if config.enableIPv4 {
		table30Flows.flows = append(table30Flows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ip", ActStr: "ct(table=31,zone=65520,nat)"},
		)
		table31Flows.flows = append(table31Flows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=190,ct_state=+inv+trk,ip", ActStr: "drop"},
		)
		table105Flows.flows = append(table105Flows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ct_state=+new+trk,ip,reg0=0x1/0xf", ActStr: "ct(commit,table=108,zone=65520,exec(load:0x1->NXM_NX_CT_MARK[1])"},
			&ofTestUtils.ExpectFlow{MatchStr: "priority=190,ct_state=+new+trk,ip", ActStr: "ct(commit,table=108,zone=65520)"},
		)
		table72Flows.flows = append(table72Flows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=210,ip,reg0=0x1/0xf", ActStr: "goto_table:80"},
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ip", ActStr: "dec_ttl,goto_table:80"},
		)
	}
	if config.enableIPv6 {
		table30Flows.flows = append(table30Flows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ipv6", ActStr: "ct(table=31,zone=65510,nat)"},
		)
		table31Flows.flows = append(table31Flows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=190,ct_state=+inv+trk,ipv6", ActStr: "drop"},
		)
		table105Flows.flows = append(table105Flows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ct_state=+new+trk,ipv6,reg0=0x1/0xf", ActStr: "ct(commit,table=108,zone=65510,exec(load:0x1->NXM_NX_CT_MARK[1])"},
			&ofTestUtils.ExpectFlow{MatchStr: "priority=190,ct_state=+new+trk,ipv6", ActStr: "ct(commit,table=108,zone=65510)"},
		)
		table72Flows.flows = append(table72Flows.flows,
			&ofTestUtils.ExpectFlow{MatchStr: "priority=210,ipv6,reg0=0x1/0xf", ActStr: "goto_table:80"},
			&ofTestUtils.ExpectFlow{MatchStr: "priority=200,ipv6", ActStr: "dec_ttl,goto_table:80"},
		)
	}
	if config.connectUplinkToBridge {
		table20Flows.flows = append(table20Flows.flows,
			&ofTestUtils.ExpectFlow{
				MatchStr: fmt.Sprintf("priority=200,arp,arp_tpa=%s,arp_op=1", config.nodeConfig.GatewayConfig.IPv4.String()),
				ActStr:   fmt.Sprintf("move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:%s->eth_src,load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],set_field:%s->arp_sha,move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:%s->arp_spa,IN_PORT", config.nodeConfig.GatewayConfig.MAC.String(), config.nodeConfig.GatewayConfig.MAC.String(), config.nodeConfig.GatewayConfig.IPv4.String()),
			},
		)
	}
	return []expectTableFlows{
		table20Flows, table30Flows, table31Flows, table105Flows, table72Flows,
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
			[]*ofTestUtils.ExpectFlow{{MatchStr: "priority=0", ActStr: "goto_table:101"}},
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

func expectedExternalFlows(nodeIP net.IP, localSubnet *net.IPNet, gwMAC net.HardwareAddr) []expectTableFlows {
	var ipProtoStr, nwDstFieldName string
	if localSubnet.IP.To4() != nil {
		ipProtoStr = "ip"
		nwDstFieldName = "nw_dst"
	} else {
		ipProtoStr = "ipv6"
		nwDstFieldName = "ipv6_dst"
	}
	return []expectTableFlows{
		{
			// snatCommonFlows()
			uint8(70),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,%s,reg0=0/0x80000,%s=%s", ipProtoStr, nwDstFieldName, localSubnet.String()),
					ActStr:   "goto_table:80",
				},
				{
					MatchStr: fmt.Sprintf("priority=200,%s,reg0=0x2/0xf,%s=%s", ipProtoStr, nwDstFieldName, nodeIP.String()),
					ActStr:   "goto_table:80",
				},
				{
					MatchStr: fmt.Sprintf("priority=190,%s,reg0=0x2/0xf", ipProtoStr),
					ActStr:   "goto_table:71",
				},
				{
					MatchStr: fmt.Sprintf("priority=190,%s,reg0=0/0xf", ipProtoStr),
					ActStr:   fmt.Sprintf("set_field:%s->eth_dst,goto_table:71", gwMAC.String()),
				},
			},
		},
		{
			uint8(71),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=190,ct_state=+new+trk,%s,reg0=0/0xf", ipProtoStr),
					ActStr:   "drop",
				},
				{
					MatchStr: "priority=0",
					ActStr:   "goto_table:80",
				},
			},
		},
	}
}

func prepareSNATFlows(snatIP net.IP, mark, podOFPort, podOFPortRemote uint32, vMAC, localGwMAC net.HardwareAddr) []expectTableFlows {
	var ipProtoStr, tunDstFieldName string
	if snatIP.To4() != nil {
		tunDstFieldName = "tun_dst"
		ipProtoStr = "ip"
	} else {
		tunDstFieldName = "tun_ipv6_dst"
		ipProtoStr = "ipv6"
	}
	return []expectTableFlows{
		{
			uint8(71),
			[]*ofTestUtils.ExpectFlow{
				{
					MatchStr: fmt.Sprintf("priority=200,ct_state=+new+trk,%s,%s=%s", ipProtoStr, tunDstFieldName, snatIP),
					ActStr:   fmt.Sprintf("load:0x%x->NXM_NX_PKT_MARK[0..7],goto_table:72", mark),
				},
				{
					MatchStr: fmt.Sprintf("priority=200,ct_state=+new+trk,%s,in_port=%d", ipProtoStr, podOFPort),
					ActStr:   fmt.Sprintf("load:0x%x->NXM_NX_PKT_MARK[0..7],goto_table:80", mark),
				},
				{
					MatchStr: fmt.Sprintf("priority=200,%s,in_port=%d", ipProtoStr, podOFPortRemote),
					ActStr:   fmt.Sprintf("set_field:%s->eth_src,set_field:%s->eth_dst,set_field:%s->%s,goto_table:72", localGwMAC.String(), vMAC.String(), snatIP, tunDstFieldName),
				},
			},
		},
	}
}

func TestSNATFlows(t *testing.T) {
	c = ofClient.NewClient(br, bridgeMgmtAddr, ovsconfig.OVSDatapathNetdev, false, false, true, false, false, false)
	err := ofTestUtils.PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge %s", br))

	config := prepareConfiguration()
	_, err = c.Initialize(roundInfo, config.nodeConfig, &config1.NetworkConfig{TrafficEncapMode: config1.TrafficEncapModeEncap})
	require.Nil(t, err, "Failed to initialize OFClient")

	defer func() {
		err = c.Disconnect()
		assert.Nil(t, err, fmt.Sprintf("Error while disconnecting from OVS bridge: %v", err))
		err = ofTestUtils.DeleteOVSBridge(br)
		assert.Nil(t, err, fmt.Sprintf("Error while deleting OVS bridge: %v", err))
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
	expectedFlows := append(prepareSNATFlows(snatIP, snatMark, podOFPort, podOFPortRemote, vMAC, gwMAC),
		prepareSNATFlows(snatIPV6, snatMarkV6, podOFPortV6, podOFPortRemoteV6, vMAC, gwMAC)...)

	c.InstallSNATMarkFlows(snatIP, snatMark)
	c.InstallSNATMarkFlows(snatIPV6, snatMarkV6)
	c.InstallPodSNATFlows(podOFPort, snatIP, snatMark)
	c.InstallPodSNATFlows(podOFPortRemote, snatIP, 0)
	c.InstallPodSNATFlows(podOFPortV6, snatIPV6, snatMarkV6)
	c.InstallPodSNATFlows(podOFPortRemoteV6, snatIPV6, 0)
	for _, tableFlow := range expectedFlows {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, true, tableFlow.flows)
	}

	c.UninstallPodSNATFlows(podOFPort)
	c.UninstallPodSNATFlows(podOFPortRemote)
	c.UninstallPodSNATFlows(podOFPortV6)
	c.UninstallPodSNATFlows(podOFPortRemoteV6)
	c.UninstallSNATMarkFlows(snatMark)
	c.UninstallSNATMarkFlows(snatMarkV6)
	for _, tableFlow := range expectedFlows {
		ofTestUtils.CheckFlowExists(t, ovsCtlClient, tableFlow.tableID, false, tableFlow.flows)
	}
}
