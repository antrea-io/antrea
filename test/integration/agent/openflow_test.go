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
	"testing"

	ofClient "github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	ofTestUtils "github.com/vmware-tanzu/antrea/pkg/ovs/openflow/testing"
)

var (
	bridgeName = "br123"
	c          = ofClient.NewClient(bridgeName)
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
	err := ofTestUtils.PrepareOVSBridge(bridgeName)
	if err != nil {
		t.Errorf("failed to prepare OVS bridge: %v", bridgeName)
	}
	defer func() {
		err = ofTestUtils.DeleteOVSBridge(bridgeName)
		if err != nil {
			t.Errorf("error while deleting OVS bridge: %v", err)
		}
	}()

	defer c.Disconnect()

	config := prepareConfiguration()
	for _, f := range []func(t *testing.T, config *testConfig){
		testInitialize,
		testInstallGatewayFlows,
		testInstallServiceFlows,
		testInstallTunnelFlows,
		testInstallNodeFlows,
		testInstallPodFlows,
		testInstallPodFlows,
		testUninstallPodFlows,
		testUninstallNodeFlows,
	} {
		f(t, config)
	}
}

func testInitialize(t *testing.T, config *testConfig) {
	if err := c.Initialize(); err != nil {
		t.Errorf("failed to initialize openflow client: %v", err)
	}
	for _, tableFlow := range prepareDefaultFlows() {
		ofTestUtils.CheckFlowExists(t, config.bridge, tableFlow.tableID, true, tableFlow.flows)
	}
}

func testInstallTunnelFlows(t *testing.T, config *testConfig) {
	err := c.InstallTunnelFlows(config.tunnelOFPort)
	if err != nil {
		t.Fatalf("Failed to install Openflow entries for tunnel port: %v", err)
	}
	for _, tableFlow := range prepareTunnelFlows(config.tunnelOFPort, config.globalMAC) {
		ofTestUtils.CheckFlowExists(t, config.bridge, tableFlow.tableID, true, tableFlow.flows)
	}
}

func testInstallServiceFlows(t *testing.T, config *testConfig) {
	err := c.InstallServiceFlows("serviceAssistant", config.serviceCIDR, config.localGateway.ofPort)
	if err != nil {
		t.Fatalf("Failed to install Openflow entries to skip service CIDR from egress table")
	}
	for _, tableFlow := range prepareServiceHelperFlows(*config.serviceCIDR) {
		ofTestUtils.CheckFlowExists(t, config.bridge, tableFlow.tableID, true, tableFlow.flows)
	}
}

func testInstallNodeFlows(t *testing.T, config *testConfig) {
	for _, node := range config.peers {
		err := c.InstallNodeFlows("peer", config.localGateway.mac, node.gateway, node.subnet, node.nodeAddress)
		if err != nil {
			t.Fatalf("Failed to install Openflow entries for node connectivity: %v", err)
		}
		for _, tableFlow := range prepareNodeFlows(node.subnet, node.gateway, node.nodeAddress, config.globalMAC, config.localGateway.mac) {
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
		for _, tableFlow := range prepareNodeFlows(node.subnet, node.gateway, node.nodeAddress, config.globalMAC, config.localGateway.mac) {
			ofTestUtils.CheckFlowExists(t, config.bridge, tableFlow.tableID, true, tableFlow.flows)
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

func testInstallGatewayFlows(t *testing.T, config *testConfig) {
	err := c.InstallGatewayFlows(config.localGateway.ip, config.localGateway.mac, config.localGateway.ofPort)
	if err != nil {
		t.Fatalf("Failed to install Openflow entries for gateway: %v", err)
	}
	for _, tableFlow := range prepareGatewayFlows(config.localGateway.ip, config.localGateway.mac, config.localGateway.ofPort) {
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
		bridge:       bridgeName,
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

func prepareGatewayFlows(gwIP net.IP, gwMAC net.HardwareAddr, gwOFPort uint32) []expectTableFlows {
	return []expectTableFlows{
		{
			uint8(0),
			[]*ofTestUtils.ExpectFlow{
				{fmt.Sprintf("priority=200,in_port=%d", gwOFPort),
					"load:0x1->NXM_NX_REG0[0..15],resubmit(,10)"},
			},
		},
		{
			uint8(10),
			[]*ofTestUtils.ExpectFlow{
				{fmt.Sprintf("priority=200,arp,in_port=%d", gwOFPort), "resubmit(,20)"},
				{fmt.Sprintf("priority=200,ip,in_port=%d", gwOFPort), "resubmit(,30)"},
			},
		},
		{
			uint8(70),
			[]*ofTestUtils.ExpectFlow{
				{
					fmt.Sprintf("priority=200,ip,nw_dst=%s", gwIP.String()),
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
		{
			uint8(80),
			[]*ofTestUtils.ExpectFlow{
				{
					fmt.Sprintf("priority=200,dl_dst=%s", vMAC.String()),
					fmt.Sprintf("load:0x%x->NXM_NX_REG1[],load:0x1->NXM_NX_REG0[16],resubmit(,90)", tunnelPort)},
			},
		},
	}
}

func prepareNodeFlows(peerSubnet net.IPNet, peerGwIP, peerNodeIP net.IP, vMAC, localGwMAC net.HardwareAddr) []expectTableFlows {
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
					fmt.Sprintf("dec_ttl,set_field:%s->eth_src,set_field:%s->eth_dst,set_field:%s->tun_dst,resubmit(,80)", localGwMAC.String(), vMAC.String(), peerNodeIP.String())},
			},
		},
	}
}

func prepareServiceHelperFlows(serviceCIDR net.IPNet) []expectTableFlows {
	return []expectTableFlows{
		{
			uint8(40),
			[]*ofTestUtils.ExpectFlow{
				{fmt.Sprintf("priority=200,ip,nw_dst=%s", serviceCIDR.String()), "output:1"},
			},
		},
	}
}

func prepareDefaultFlows() []expectTableFlows {
	return []expectTableFlows{
		{
			uint8(0),
			[]*ofTestUtils.ExpectFlow{{"priority=80,ip", "resubmit(,10)"}},
		},
		{
			uint8(10),
			[]*ofTestUtils.ExpectFlow{{"priority=80,ip", "drop"}},
		},
		{
			uint8(20),
			[]*ofTestUtils.ExpectFlow{
				{"priority=190,arp", "NORMAL"},
				{"priority=80,ip", "drop"},
			},
		},
		{
			uint8(30),
			[]*ofTestUtils.ExpectFlow{
				{"priority=200,ip", "ct(table=31,zone=65520)"},
				{"priority=80,ip", "resubmit(,31)"},
			},
		},
		{
			uint8(31),
			[]*ofTestUtils.ExpectFlow{
				{"priority=210,ct_state=-new+trk,ct_mark=0x20,ip,reg0=0x1/0xffff", "resubmit(,40)"},
				{"priority=200,ct_state=+new+trk,ip,reg0=0x1/0xffff", "ct(commit,table=40,zone=65520,exec(load:0x20->NXM_NX_CT_MARK[],move:NXM_OF_ETH_SRC[]->NXM_NX_CT_LABEL[0..47]))"},
				{"priority=200,ct_state=-new+trk,ct_mark=0x20,ip", "move:NXM_NX_CT_LABEL[0..47]->NXM_OF_ETH_DST[],resubmit(,40)"},
				{"priority=200,ct_state=+new+inv,ip", "drop"},
				{"priority=190,ct_state=+new+trk,ip", "ct(commit,table=40,zone=65520)"},
				{"priority=80,ip", "resubmit(,40)"},
			},
		},
		{
			uint8(40),
			[]*ofTestUtils.ExpectFlow{{"priority=80,ip", "resubmit(,50)"}},
		},
		{
			uint8(50),
			[]*ofTestUtils.ExpectFlow{{"priority=80,ip", "resubmit(,60)"}},
		},
		{
			uint8(60),
			[]*ofTestUtils.ExpectFlow{{"priority=80,ip", "resubmit(,70)"}},
		},
		{
			uint8(70),
			[]*ofTestUtils.ExpectFlow{{"priority=80,ip", "resubmit(,80)"}},
		},
		{
			uint8(80),
			[]*ofTestUtils.ExpectFlow{{"priority=80,ip", "resubmit(,90)"}},
		},
		{
			uint8(90),
			[]*ofTestUtils.ExpectFlow{{"priority=80,ip", "resubmit(,100)"}},
		},
		{
			uint8(100),
			[]*ofTestUtils.ExpectFlow{{"priority=80,ip", "resubmit(,110)"}},
		},
		{
			uint8(110),
			[]*ofTestUtils.ExpectFlow{
				{"priority=200,ip,reg0=0x10000/0x10000", "output:NXM_NX_REG1[]"},
			},
		},
	}
}
