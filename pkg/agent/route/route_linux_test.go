// Copyright 2022 Antrea Authors
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

package route

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/config"
	servicecidrtest "antrea.io/antrea/pkg/agent/servicecidr/testing"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util/ipset"
	ipsettest "antrea.io/antrea/pkg/agent/util/ipset/testing"
	"antrea.io/antrea/pkg/agent/util/iptables"
	iptablestest "antrea.io/antrea/pkg/agent/util/iptables/testing"
	netlinktest "antrea.io/antrea/pkg/agent/util/netlink/testing"
	"antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/ip"
)

var (
	nodeConfig = &config.NodeConfig{GatewayConfig: &config.GatewayConfig{LinkIndex: 10}}

	externalIPv4Addr1 = "1.1.1.1"
	externalIPv4Addr2 = "1.1.1.2"
	externalIPv6Addr1 = "fd00:1234:5678:dead:beaf::1"
	externalIPv6Addr2 = "fd00:1234:5678:dead:beaf::a"

	ipv4Route1 = generateRoute(net.ParseIP(externalIPv4Addr1), 32, config.VirtualServiceIPv4, 10, netlink.SCOPE_UNIVERSE)
	ipv4Route2 = generateRoute(net.ParseIP(externalIPv4Addr2), 32, config.VirtualServiceIPv4, 10, netlink.SCOPE_UNIVERSE)
	ipv6Route1 = generateRoute(net.ParseIP(externalIPv6Addr1), 128, config.VirtualServiceIPv6, 10, netlink.SCOPE_UNIVERSE)
	ipv6Route2 = generateRoute(net.ParseIP(externalIPv6Addr2), 128, config.VirtualServiceIPv6, 10, netlink.SCOPE_UNIVERSE)
)

func TestSyncRoutes(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockNetlink := netlinktest.NewMockInterface(ctrl)

	nodeRoute1 := &netlink.Route{Dst: ip.MustParseCIDR("192.168.1.0/24"), Gw: net.ParseIP("1.1.1.1")}
	nodeRoute2 := &netlink.Route{Dst: ip.MustParseCIDR("192.168.2.0/24"), Gw: net.ParseIP("1.1.1.2")}
	serviceRoute1 := &netlink.Route{Dst: ip.MustParseCIDR("169.254.0.253/32"), LinkIndex: 10}
	serviceRoute2 := &netlink.Route{Dst: ip.MustParseCIDR("169.254.0.252/32"), Gw: net.ParseIP("169.254.0.253")}
	egressRoute1 := &netlink.Route{Scope: netlink.SCOPE_LINK, Dst: ip.MustParseCIDR("10.10.10.0/24"), LinkIndex: 10, Table: 101}
	egressRoute2 := &netlink.Route{Gw: net.ParseIP("10.10.10.1"), LinkIndex: 10, Table: 101}
	mockNetlink.EXPECT().RouteList(nil, netlink.FAMILY_ALL).Return([]netlink.Route{*nodeRoute1, *serviceRoute1, *egressRoute1}, nil)
	mockNetlink.EXPECT().RouteReplace(nodeRoute2)
	mockNetlink.EXPECT().RouteReplace(serviceRoute2)
	mockNetlink.EXPECT().RouteReplace(egressRoute2)
	mockNetlink.EXPECT().RouteReplace(&netlink.Route{
		LinkIndex: 10,
		Dst:       ip.MustParseCIDR("192.168.0.0/24"),
		Src:       net.ParseIP("192.168.0.1"),
		Scope:     netlink.SCOPE_LINK,
	})
	mockNetlink.EXPECT().RouteReplace(&netlink.Route{
		LinkIndex: 10,
		Dst:       ip.MustParseCIDR("aabb:ccdd::/64"),
		Src:       net.ParseIP("aabb:ccdd::1"),
		Scope:     netlink.SCOPE_LINK,
	})
	mockNetlink.EXPECT().RouteReplace(&netlink.Route{
		LinkIndex: 10,
		Dst:       ip.MustParseCIDR("fe80::/64"),
		Scope:     netlink.SCOPE_LINK,
	})

	c := &Client{
		netlink:       mockNetlink,
		proxyAll:      true,
		nodeRoutes:    sync.Map{},
		serviceRoutes: sync.Map{},
		nodeConfig: &config.NodeConfig{
			GatewayConfig: &config.GatewayConfig{LinkIndex: 10, IPv4: net.ParseIP("192.168.0.1"), IPv6: net.ParseIP("aabb:ccdd::1")},
			PodIPv4CIDR:   ip.MustParseCIDR("192.168.0.0/24"),
			PodIPv6CIDR:   ip.MustParseCIDR("aabb:ccdd::/64"),
		},
	}
	c.nodeRoutes.Store("192.168.1.0/24", []*netlink.Route{nodeRoute1})
	c.nodeRoutes.Store("192.168.2.0/24", []*netlink.Route{nodeRoute2})
	c.serviceRoutes.Store("169.254.0.253/32", serviceRoute1)
	c.serviceRoutes.Store("169.254.0.252/32", serviceRoute2)
	c.egressRoutes.Store(101, []*netlink.Route{egressRoute1, egressRoute2})

	assert.NoError(t, c.syncRoute())
}

func TestRestoreEgressRoutesAndRules(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockNetlink := netlinktest.NewMockInterface(ctrl)

	// route1 and route2 should be removed
	route1 := &netlink.Route{Scope: netlink.SCOPE_LINK, Dst: ip.MustParseCIDR("10.10.10.0/24"), LinkIndex: 10, Table: 101}
	route2 := &netlink.Route{Gw: net.ParseIP("10.10.10.1"), LinkIndex: 10, Table: 101}
	route3 := &netlink.Route{Dst: ip.MustParseCIDR("192.168.1.0/24"), Gw: net.ParseIP("1.1.1.1")}
	route4 := &netlink.Route{Gw: net.ParseIP("192.168.1.1"), LinkIndex: 8}
	// rule1 should be removed
	rule1 := netlink.NewRule()
	rule1.Table = 101
	rule1.Mark = 1
	rule1.Mask = int(types.SNATIPMarkMask)
	rule2 := netlink.NewRule()
	rule2.Table = 50
	rule2.Mark = 10
	rule2.Mask = int(types.SNATIPMarkMask)

	mockNetlink.EXPECT().RouteList(nil, netlink.FAMILY_ALL).Return([]netlink.Route{*route1, *route2, *route3, *route4}, nil)
	mockNetlink.EXPECT().RuleList(netlink.FAMILY_ALL).Return([]netlink.Rule{*rule1, *rule2}, nil)
	mockNetlink.EXPECT().RouteDel(route1)
	mockNetlink.EXPECT().RouteDel(route2)
	mockNetlink.EXPECT().RuleDel(rule1)
	c := &Client{
		netlink:       mockNetlink,
		proxyAll:      true,
		nodeRoutes:    sync.Map{},
		serviceRoutes: sync.Map{},
		nodeConfig: &config.NodeConfig{
			GatewayConfig: &config.GatewayConfig{LinkIndex: 10, IPv4: net.ParseIP("192.168.0.1"), IPv6: net.ParseIP("aabb:ccdd::1")},
			PodIPv4CIDR:   ip.MustParseCIDR("192.168.0.0/24"),
			PodIPv6CIDR:   ip.MustParseCIDR("aabb:ccdd::/64"),
		},
	}
	assert.NoError(t, c.RestoreEgressRoutesAndRules(101, 120))
}

func TestSyncIPSet(t *testing.T) {
	podCIDRStr := "172.16.10.0/24"
	_, podCIDR, _ := net.ParseCIDR(podCIDRStr)
	podCIDRv6Str := "2001:ab03:cd04:55ef::/64"
	_, podCIDRv6, _ := net.ParseCIDR(podCIDRv6Str)
	tests := []struct {
		name                        string
		proxyAll                    bool
		multicastEnabled            bool
		connectUplinkToBridge       bool
		nodeNetworkPolicyEnabled    bool
		networkConfig               *config.NetworkConfig
		nodeConfig                  *config.NodeConfig
		nodePortsIPv4               []string
		nodePortsIPv6               []string
		clusterNodeIPs              map[string]string
		clusterNodeIP6s             map[string]string
		nodeNetworkPolicyIPSetsIPv4 map[string]sets.Set[string]
		nodeNetworkPolicyIPSetsIPv6 map[string]sets.Set[string]
		expectedCalls               func(ipset *ipsettest.MockInterfaceMockRecorder)
	}{
		{
			name: "networkPolicyOnly",
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeNetworkPolicyOnly,
			},
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {},
		},
		{
			name: "noencap",
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeNoEncap,
				IPv4Enabled:      true,
				IPv6Enabled:      true,
			},
			nodeConfig: &config.NodeConfig{
				PodIPv4CIDR: podCIDR,
				PodIPv6CIDR: podCIDRv6,
			},
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.CreateIPSet(antreaPodIPSet, ipset.HashNet, false)
				mockIPSet.CreateIPSet(antreaPodIP6Set, ipset.HashNet, true)
				mockIPSet.AddEntry(antreaPodIPSet, podCIDRStr)
				mockIPSet.AddEntry(antreaPodIP6Set, podCIDRv6Str)
			},
		},
		{
			name:                     "encap, proxyAll=true, multicastEnabled=true, nodeNetworkPolicy=true",
			proxyAll:                 true,
			multicastEnabled:         true,
			nodeNetworkPolicyEnabled: true,
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeEncap,
				IPv4Enabled:      true,
				IPv6Enabled:      true,
			},
			nodeConfig: &config.NodeConfig{
				PodIPv4CIDR: podCIDR,
				PodIPv6CIDR: podCIDRv6,
			},
			nodePortsIPv4:               []string{"192.168.0.2,tcp:10000", "127.0.0.1,tcp:10000"},
			nodePortsIPv6:               []string{"fe80::e643:4bff:fe44:ee,tcp:10000", "::1,tcp:10000"},
			clusterNodeIPs:              map[string]string{"172.16.3.0/24": "192.168.0.3", "172.16.4.0/24": "192.168.0.4"},
			clusterNodeIP6s:             map[string]string{"2001:ab03:cd04:5503::/64": "fe80::e643:4bff:fe03", "2001:ab03:cd04:5504::/64": "fe80::e643:4bff:fe04"},
			nodeNetworkPolicyIPSetsIPv4: map[string]sets.Set[string]{"ANTREA-POL-RULE1-4": sets.New[string]("1.1.1.1/32", "2.2.2.2/32")},
			nodeNetworkPolicyIPSetsIPv6: map[string]sets.Set[string]{"ANTREA-POL-RULE1-6": sets.New[string]("fec0::1111/128", "fec0::2222/128")},
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.CreateIPSet(antreaPodIPSet, ipset.HashNet, false)
				mockIPSet.CreateIPSet(antreaPodIP6Set, ipset.HashNet, true)
				mockIPSet.AddEntry(antreaPodIPSet, podCIDRStr)
				mockIPSet.AddEntry(antreaPodIP6Set, podCIDRv6Str)
				mockIPSet.CreateIPSet(antreaNodePortIPSet, ipset.HashIPPort, false)
				mockIPSet.CreateIPSet(antreaNodePortIP6Set, ipset.HashIPPort, true)
				mockIPSet.AddEntry(antreaNodePortIPSet, "192.168.0.2,tcp:10000")
				mockIPSet.AddEntry(antreaNodePortIPSet, "127.0.0.1,tcp:10000")
				mockIPSet.AddEntry(antreaNodePortIP6Set, "fe80::e643:4bff:fe44:ee,tcp:10000")
				mockIPSet.AddEntry(antreaNodePortIP6Set, "::1,tcp:10000")
				mockIPSet.CreateIPSet(clusterNodeIPSet, ipset.HashIP, false)
				mockIPSet.CreateIPSet(clusterNodeIP6Set, ipset.HashIP, true)
				mockIPSet.AddEntry(clusterNodeIPSet, "192.168.0.3")
				mockIPSet.AddEntry(clusterNodeIPSet, "192.168.0.4")
				mockIPSet.AddEntry(clusterNodeIP6Set, "fe80::e643:4bff:fe03")
				mockIPSet.AddEntry(clusterNodeIP6Set, "fe80::e643:4bff:fe04")
				mockIPSet.CreateIPSet("ANTREA-POL-RULE1-4", ipset.HashNet, false)
				mockIPSet.CreateIPSet("ANTREA-POL-RULE1-6", ipset.HashNet, true)
				mockIPSet.AddEntry("ANTREA-POL-RULE1-4", "1.1.1.1/32")
				mockIPSet.AddEntry("ANTREA-POL-RULE1-4", "2.2.2.2/32")
				mockIPSet.AddEntry("ANTREA-POL-RULE1-6", "fec0::1111/128")
				mockIPSet.AddEntry("ANTREA-POL-RULE1-6", "fec0::2222/128")
			},
		},
		{
			name:                  "noencap, connectUplinkToBridge=true",
			connectUplinkToBridge: true,
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeNoEncap,
				IPv4Enabled:      true,
				IPv6Enabled:      true,
			},
			nodeConfig: &config.NodeConfig{
				PodIPv4CIDR: podCIDR,
				PodIPv6CIDR: podCIDRv6,
			},
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.CreateIPSet(antreaPodIPSet, ipset.HashNet, false)
				mockIPSet.CreateIPSet(antreaPodIP6Set, ipset.HashNet, true)
				mockIPSet.AddEntry(antreaPodIPSet, podCIDRStr)
				mockIPSet.AddEntry(antreaPodIP6Set, podCIDRv6Str)
				mockIPSet.CreateIPSet(localAntreaFlexibleIPAMPodIPSet, ipset.HashIP, false)
				mockIPSet.CreateIPSet(localAntreaFlexibleIPAMPodIP6Set, ipset.HashIP, true)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			ipset := ipsettest.NewMockInterface(ctrl)
			c := &Client{ipset: ipset,
				networkConfig:            tt.networkConfig,
				nodeConfig:               tt.nodeConfig,
				proxyAll:                 tt.proxyAll,
				multicastEnabled:         tt.multicastEnabled,
				connectUplinkToBridge:    tt.connectUplinkToBridge,
				nodeNetworkPolicyEnabled: tt.nodeNetworkPolicyEnabled,
				nodePortsIPv4:            sync.Map{},
				nodePortsIPv6:            sync.Map{},
				clusterNodeIPs:           sync.Map{},
				clusterNodeIP6s:          sync.Map{},
			}
			for _, nodePortIPv4 := range tt.nodePortsIPv4 {
				c.nodePortsIPv4.Store(nodePortIPv4, struct{}{})
			}
			for _, nodePortIPv6 := range tt.nodePortsIPv6 {
				c.nodePortsIPv6.Store(nodePortIPv6, struct{}{})
			}
			for cidr, nodeIP := range tt.clusterNodeIPs {
				c.clusterNodeIPs.Store(cidr, nodeIP)
			}
			for cidr, nodeIP := range tt.clusterNodeIP6s {
				c.clusterNodeIP6s.Store(cidr, nodeIP)
			}
			for set, ips := range tt.nodeNetworkPolicyIPSetsIPv4 {
				c.nodeNetworkPolicyIPSetsIPv4.Store(set, ips)
			}
			for set, ips := range tt.nodeNetworkPolicyIPSetsIPv6 {
				c.nodeNetworkPolicyIPSetsIPv6.Store(set, ips)
			}
			tt.expectedCalls(ipset.EXPECT())
			assert.NoError(t, c.syncIPSet())
		})
	}
}

func TestSyncIPTables(t *testing.T) {
	tests := []struct {
		name                     string
		isCloudEKS               bool
		proxyAll                 bool
		multicastEnabled         bool
		connectUplinkToBridge    bool
		nodeNetworkPolicyEnabled bool
		networkConfig            *config.NetworkConfig
		nodeConfig               *config.NodeConfig
		nodePortsIPv4            []string
		nodePortsIPv6            []string
		markToSNATIP             map[uint32]string
		expectedCalls            func(iptables *iptablestest.MockInterfaceMockRecorder)
	}{
		{
			name:                     "encap,egress=true,multicastEnabled=true,proxyAll=true,nodeNetworkPolicy=true",
			proxyAll:                 true,
			multicastEnabled:         true,
			nodeNetworkPolicyEnabled: true,
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeEncap,
				TunnelType:       ovsconfig.GeneveTunnel,
				IPv4Enabled:      true,
				IPv6Enabled:      true,
			},
			nodeConfig: &config.NodeConfig{
				PodIPv4CIDR: ip.MustParseCIDR("172.16.10.0/24"),
				PodIPv6CIDR: ip.MustParseCIDR("2001:ab03:cd04:55ef::/64"),
				GatewayConfig: &config.GatewayConfig{
					Name: "antrea-gw0",
				},
			},
			markToSNATIP: map[uint32]string{
				1: "1.1.1.1",
				2: "fe80::e643:4bff:fe02",
			},
			expectedCalls: func(mockIPTables *iptablestest.MockInterfaceMockRecorder) {
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.RawTable, antreaPreRoutingChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.RawTable, iptables.PreRoutingChain, []string{"-j", antreaPreRoutingChain, "-m", "comment", "--comment", "Antrea: jump to Antrea prerouting rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.RawTable, antreaOutputChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.RawTable, iptables.OutputChain, []string{"-j", antreaOutputChain, "-m", "comment", "--comment", "Antrea: jump to Antrea output rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.FilterTable, antreaForwardChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.FilterTable, iptables.ForwardChain, []string{"-j", antreaForwardChain, "-m", "comment", "--comment", "Antrea: jump to Antrea forwarding rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.NATTable, antreaPostRoutingChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.NATTable, iptables.PostRoutingChain, []string{"-j", antreaPostRoutingChain, "-m", "comment", "--comment", "Antrea: jump to Antrea postrouting rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.MangleTable, antreaMangleChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.MangleTable, iptables.PreRoutingChain, []string{"-j", antreaMangleChain, "-m", "comment", "--comment", "Antrea: jump to Antrea mangle rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.MangleTable, antreaOutputChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.MangleTable, iptables.OutputChain, []string{"-j", antreaOutputChain, "-m", "comment", "--comment", "Antrea: jump to Antrea output rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.NATTable, antreaPreRoutingChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.NATTable, iptables.PreRoutingChain, []string{"-j", antreaPreRoutingChain, "-m", "comment", "--comment", "Antrea: jump to Antrea prerouting rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.NATTable, antreaOutputChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.NATTable, iptables.OutputChain, []string{"-j", antreaOutputChain, "-m", "comment", "--comment", "Antrea: jump to Antrea output rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.FilterTable, antreaInputChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.FilterTable, iptables.InputChain, []string{"-j", antreaInputChain, "-m", "comment", "--comment", "Antrea: jump to Antrea input rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.FilterTable, antreaOutputChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.FilterTable, iptables.OutputChain, []string{"-j", antreaOutputChain, "-m", "comment", "--comment", "Antrea: jump to Antrea output rules"})
				mockIPTables.Restore(`*raw
:ANTREA-PREROUTING - [0:0]
:ANTREA-OUTPUT - [0:0]
-A ANTREA-PREROUTING -m comment --comment "Antrea: do not track incoming encapsulation packets" -m udp -p udp --dport 6081 -m addrtype --dst-type LOCAL -j NOTRACK
-A ANTREA-OUTPUT -m comment --comment "Antrea: do not track outgoing encapsulation packets" -m udp -p udp --dport 6081 -m addrtype --src-type LOCAL -j NOTRACK
-A ANTREA-PREROUTING -m comment --comment "Antrea: drop Pod multicast traffic forwarded via underlay network" -m set --match-set CLUSTER-NODE-IP src -d 224.0.0.0/4 -j DROP
COMMIT
*mangle
:ANTREA-MANGLE - [0:0]
:ANTREA-OUTPUT - [0:0]
-A ANTREA-OUTPUT -m comment --comment "Antrea: mark LOCAL output packets" -m addrtype --src-type LOCAL -o antrea-gw0 -j MARK --or-mark 0x80000000
COMMIT
*filter
:ANTREA-FORWARD - [0:0]
:ANTREA-INPUT - [0:0]
:ANTREA-OUTPUT - [0:0]
:ANTREA-POL-EGRESS-RULES - [0:0]
:ANTREA-POL-INGRESS-RULES - [0:0]
:ANTREA-POL-PRE-EGRESS-RULES - [0:0]
:ANTREA-POL-PRE-INGRESS-RULES - [0:0]
-A ANTREA-FORWARD -m comment --comment "Antrea: accept packets from local Pods" -i antrea-gw0 -j ACCEPT
-A ANTREA-FORWARD -m comment --comment "Antrea: accept packets to local Pods" -o antrea-gw0 -j ACCEPT
-A ANTREA-INPUT -m comment --comment "Antrea: jump to static ingress NodeNetworkPolicy rules" -j ANTREA-POL-PRE-INGRESS-RULES
-A ANTREA-INPUT -m comment --comment "Antrea: jump to ingress NodeNetworkPolicy rules" -j ANTREA-POL-INGRESS-RULES
-A ANTREA-OUTPUT -m comment --comment "Antrea: jump to static egress NodeNetworkPolicy rules" -j ANTREA-POL-PRE-EGRESS-RULES
-A ANTREA-OUTPUT -m comment --comment "Antrea: jump to egress NodeNetworkPolicy rules" -j ANTREA-POL-EGRESS-RULES
-A ANTREA-POL-INGRESS-RULES -j ACCEPT -m comment --comment "mock rule"
-A ANTREA-POL-PRE-EGRESS-RULES -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "Antrea: allow egress established or related packets" -j ACCEPT
-A ANTREA-POL-PRE-EGRESS-RULES -o lo -m comment --comment "Antrea: allow egress packets to loopback" -j ACCEPT
-A ANTREA-POL-PRE-INGRESS-RULES -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "Antrea: allow ingress established or related packets" -j ACCEPT
-A ANTREA-POL-PRE-INGRESS-RULES -i lo -m comment --comment "Antrea: allow ingress packets from loopback" -j ACCEPT
COMMIT
*nat
:ANTREA-PREROUTING - [0:0]
-A ANTREA-PREROUTING -m comment --comment "Antrea: DNAT external to NodePort packets" -m set --match-set ANTREA-NODEPORT-IP dst,dst -j DNAT --to-destination 169.254.0.252
:ANTREA-OUTPUT - [0:0]
-A ANTREA-OUTPUT -m comment --comment "Antrea: DNAT local to NodePort packets" -m set --match-set ANTREA-NODEPORT-IP dst,dst -j DNAT --to-destination 169.254.0.252
:ANTREA-POSTROUTING - [0:0]
-A ANTREA-POSTROUTING -m comment --comment "Antrea: SNAT Pod to external packets" ! -o antrea-gw0 -m mark --mark 0x00000001/0x000000ff -j SNAT --to 1.1.1.1
-A ANTREA-POSTROUTING -m comment --comment "Antrea: masquerade Pod to external packets" -s 172.16.10.0/24 -m set ! --match-set ANTREA-POD-IP dst ! -o antrea-gw0 -j MASQUERADE
-A ANTREA-POSTROUTING -m comment --comment "Antrea: masquerade LOCAL traffic" -o antrea-gw0 -m addrtype ! --src-type LOCAL --limit-iface-out -m addrtype --src-type LOCAL -j MASQUERADE --random-fully
-A ANTREA-POSTROUTING -m comment --comment "Antrea: masquerade OVS virtual source IP" -s 169.254.0.253 -j MASQUERADE
COMMIT
`, false, false)
				mockIPTables.Restore(`*raw
:ANTREA-PREROUTING - [0:0]
:ANTREA-OUTPUT - [0:0]
-A ANTREA-PREROUTING -m comment --comment "Antrea: do not track incoming encapsulation packets" -m udp -p udp --dport 6081 -m addrtype --dst-type LOCAL -j NOTRACK
-A ANTREA-OUTPUT -m comment --comment "Antrea: do not track outgoing encapsulation packets" -m udp -p udp --dport 6081 -m addrtype --src-type LOCAL -j NOTRACK
COMMIT
*mangle
:ANTREA-MANGLE - [0:0]
:ANTREA-OUTPUT - [0:0]
-A ANTREA-OUTPUT -m comment --comment "Antrea: mark LOCAL output packets" -m addrtype --src-type LOCAL -o antrea-gw0 -j MARK --or-mark 0x80000000
COMMIT
*filter
:ANTREA-FORWARD - [0:0]
:ANTREA-INPUT - [0:0]
:ANTREA-OUTPUT - [0:0]
:ANTREA-POL-EGRESS-RULES - [0:0]
:ANTREA-POL-INGRESS-RULES - [0:0]
:ANTREA-POL-PRE-EGRESS-RULES - [0:0]
:ANTREA-POL-PRE-INGRESS-RULES - [0:0]
-A ANTREA-FORWARD -m comment --comment "Antrea: accept packets from local Pods" -i antrea-gw0 -j ACCEPT
-A ANTREA-FORWARD -m comment --comment "Antrea: accept packets to local Pods" -o antrea-gw0 -j ACCEPT
-A ANTREA-INPUT -m comment --comment "Antrea: jump to static ingress NodeNetworkPolicy rules" -j ANTREA-POL-PRE-INGRESS-RULES
-A ANTREA-INPUT -m comment --comment "Antrea: jump to ingress NodeNetworkPolicy rules" -j ANTREA-POL-INGRESS-RULES
-A ANTREA-OUTPUT -m comment --comment "Antrea: jump to static egress NodeNetworkPolicy rules" -j ANTREA-POL-PRE-EGRESS-RULES
-A ANTREA-OUTPUT -m comment --comment "Antrea: jump to egress NodeNetworkPolicy rules" -j ANTREA-POL-EGRESS-RULES
-A ANTREA-POL-INGRESS-RULES -j ACCEPT -m comment --comment "mock rule"
-A ANTREA-POL-PRE-EGRESS-RULES -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "Antrea: allow egress established or related packets" -j ACCEPT
-A ANTREA-POL-PRE-EGRESS-RULES -o lo -m comment --comment "Antrea: allow egress packets to loopback" -j ACCEPT
-A ANTREA-POL-PRE-INGRESS-RULES -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "Antrea: allow ingress established or related packets" -j ACCEPT
-A ANTREA-POL-PRE-INGRESS-RULES -i lo -m comment --comment "Antrea: allow ingress packets from loopback" -j ACCEPT
COMMIT
*nat
:ANTREA-PREROUTING - [0:0]
-A ANTREA-PREROUTING -m comment --comment "Antrea: DNAT external to NodePort packets" -m set --match-set ANTREA-NODEPORT-IP6 dst,dst -j DNAT --to-destination fc01::aabb:ccdd:eefe
:ANTREA-OUTPUT - [0:0]
-A ANTREA-OUTPUT -m comment --comment "Antrea: DNAT local to NodePort packets" -m set --match-set ANTREA-NODEPORT-IP6 dst,dst -j DNAT --to-destination fc01::aabb:ccdd:eefe
:ANTREA-POSTROUTING - [0:0]
-A ANTREA-POSTROUTING -m comment --comment "Antrea: SNAT Pod to external packets" ! -o antrea-gw0 -m mark --mark 0x00000002/0x000000ff -j SNAT --to fe80::e643:4bff:fe02
-A ANTREA-POSTROUTING -m comment --comment "Antrea: masquerade Pod to external packets" -s 2001:ab03:cd04:55ef::/64 -m set ! --match-set ANTREA-POD-IP6 dst ! -o antrea-gw0 -j MASQUERADE
-A ANTREA-POSTROUTING -m comment --comment "Antrea: masquerade LOCAL traffic" -o antrea-gw0 -m addrtype ! --src-type LOCAL --limit-iface-out -m addrtype --src-type LOCAL -j MASQUERADE --random-fully
-A ANTREA-POSTROUTING -m comment --comment "Antrea: masquerade OVS virtual source IP" -s fc01::aabb:ccdd:eeff -j MASQUERADE
COMMIT
`, false, true)
			},
		},
		{
			name:       "encap,eks",
			isCloudEKS: true,
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeEncap,
				TunnelType:       ovsconfig.GeneveTunnel,
				IPv4Enabled:      true,
				IPv6Enabled:      true,
			},
			nodeConfig: &config.NodeConfig{
				PodIPv4CIDR: ip.MustParseCIDR("172.16.10.0/24"),
				PodIPv6CIDR: ip.MustParseCIDR("2001:ab03:cd04:55ef::/64"),
				GatewayConfig: &config.GatewayConfig{
					Name: "antrea-gw0",
				},
			},
			expectedCalls: func(mockIPTables *iptablestest.MockInterfaceMockRecorder) {
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.RawTable, antreaPreRoutingChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.RawTable, iptables.PreRoutingChain, []string{"-j", antreaPreRoutingChain, "-m", "comment", "--comment", "Antrea: jump to Antrea prerouting rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.RawTable, antreaOutputChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.RawTable, iptables.OutputChain, []string{"-j", antreaOutputChain, "-m", "comment", "--comment", "Antrea: jump to Antrea output rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.FilterTable, antreaForwardChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.FilterTable, iptables.ForwardChain, []string{"-j", antreaForwardChain, "-m", "comment", "--comment", "Antrea: jump to Antrea forwarding rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.NATTable, antreaPostRoutingChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.NATTable, iptables.PostRoutingChain, []string{"-j", antreaPostRoutingChain, "-m", "comment", "--comment", "Antrea: jump to Antrea postrouting rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.MangleTable, antreaMangleChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.MangleTable, iptables.PreRoutingChain, []string{"-j", antreaMangleChain, "-m", "comment", "--comment", "Antrea: jump to Antrea mangle rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.MangleTable, antreaOutputChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.MangleTable, iptables.OutputChain, []string{"-j", antreaOutputChain, "-m", "comment", "--comment", "Antrea: jump to Antrea output rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.NATTable, antreaPreRoutingChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.NATTable, iptables.PreRoutingChain, []string{"-j", antreaPreRoutingChain, "-m", "comment", "--comment", "Antrea: jump to Antrea prerouting rules"})
				mockIPTables.Restore(`*raw
:ANTREA-PREROUTING - [0:0]
:ANTREA-OUTPUT - [0:0]
-A ANTREA-PREROUTING -m comment --comment "Antrea: do not track incoming encapsulation packets" -m udp -p udp --dport 6081 -m addrtype --dst-type LOCAL -j NOTRACK
-A ANTREA-OUTPUT -m comment --comment "Antrea: do not track outgoing encapsulation packets" -m udp -p udp --dport 6081 -m addrtype --src-type LOCAL -j NOTRACK
COMMIT
*mangle
:ANTREA-MANGLE - [0:0]
:ANTREA-OUTPUT - [0:0]
-A ANTREA-MANGLE -m comment --comment "Antrea: AWS, primary ENI" -i antrea-gw0 -j CONNMARK --restore-mark --nfmask 0x80 --ctmask 0x80
-A ANTREA-OUTPUT -m comment --comment "Antrea: mark LOCAL output packets" -m addrtype --src-type LOCAL -o antrea-gw0 -j MARK --or-mark 0x80000000
COMMIT
*filter
:ANTREA-FORWARD - [0:0]
-A ANTREA-FORWARD -m comment --comment "Antrea: accept packets from local Pods" -i antrea-gw0 -j ACCEPT
-A ANTREA-FORWARD -m comment --comment "Antrea: accept packets to local Pods" -o antrea-gw0 -j ACCEPT
COMMIT
*nat
:ANTREA-PREROUTING - [0:0]
:ANTREA-POSTROUTING - [0:0]
-A ANTREA-POSTROUTING -m comment --comment "Antrea: masquerade Pod to external packets" -s 172.16.10.0/24 -m set ! --match-set ANTREA-POD-IP dst ! -o antrea-gw0 -j MASQUERADE
-A ANTREA-POSTROUTING -m comment --comment "Antrea: masquerade LOCAL traffic" -o antrea-gw0 -m addrtype ! --src-type LOCAL --limit-iface-out -m addrtype --src-type LOCAL -j MASQUERADE --random-fully
-A ANTREA-PREROUTING -i antrea-gw0 -m comment --comment "Antrea: AWS, outbound connections" -j AWS-CONNMARK-CHAIN-0
-A ANTREA-PREROUTING -m comment --comment "Antrea: AWS, CONNMARK (first packet)" -j CONNMARK --restore-mark --nfmask 0x80 --ctmask 0x80
COMMIT
`, false, false)
				mockIPTables.Restore(`*raw
:ANTREA-PREROUTING - [0:0]
:ANTREA-OUTPUT - [0:0]
-A ANTREA-PREROUTING -m comment --comment "Antrea: do not track incoming encapsulation packets" -m udp -p udp --dport 6081 -m addrtype --dst-type LOCAL -j NOTRACK
-A ANTREA-OUTPUT -m comment --comment "Antrea: do not track outgoing encapsulation packets" -m udp -p udp --dport 6081 -m addrtype --src-type LOCAL -j NOTRACK
COMMIT
*mangle
:ANTREA-MANGLE - [0:0]
:ANTREA-OUTPUT - [0:0]
-A ANTREA-OUTPUT -m comment --comment "Antrea: mark LOCAL output packets" -m addrtype --src-type LOCAL -o antrea-gw0 -j MARK --or-mark 0x80000000
COMMIT
*filter
:ANTREA-FORWARD - [0:0]
-A ANTREA-FORWARD -m comment --comment "Antrea: accept packets from local Pods" -i antrea-gw0 -j ACCEPT
-A ANTREA-FORWARD -m comment --comment "Antrea: accept packets to local Pods" -o antrea-gw0 -j ACCEPT
COMMIT
*nat
:ANTREA-PREROUTING - [0:0]
:ANTREA-POSTROUTING - [0:0]
-A ANTREA-POSTROUTING -m comment --comment "Antrea: masquerade Pod to external packets" -s 2001:ab03:cd04:55ef::/64 -m set ! --match-set ANTREA-POD-IP6 dst ! -o antrea-gw0 -j MASQUERADE
-A ANTREA-POSTROUTING -m comment --comment "Antrea: masquerade LOCAL traffic" -o antrea-gw0 -m addrtype ! --src-type LOCAL --limit-iface-out -m addrtype --src-type LOCAL -j MASQUERADE --random-fully
COMMIT
`, false, true)
			},
		},
		{
			name:                  "noencap,connectUplinkToBridge=true",
			connectUplinkToBridge: true,
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeNoEncap,
				IPv4Enabled:      true,
			},
			nodeConfig: &config.NodeConfig{
				PodIPv4CIDR: ip.MustParseCIDR("172.16.10.0/24"),
				GatewayConfig: &config.GatewayConfig{
					Name: "antrea-gw0",
				},
			},
			expectedCalls: func(mockIPTables *iptablestest.MockInterfaceMockRecorder) {
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.RawTable, antreaPreRoutingChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.RawTable, iptables.PreRoutingChain, []string{"-j", antreaPreRoutingChain, "-m", "comment", "--comment", "Antrea: jump to Antrea prerouting rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.RawTable, antreaOutputChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.RawTable, iptables.OutputChain, []string{"-j", antreaOutputChain, "-m", "comment", "--comment", "Antrea: jump to Antrea output rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.FilterTable, antreaForwardChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.FilterTable, iptables.ForwardChain, []string{"-j", antreaForwardChain, "-m", "comment", "--comment", "Antrea: jump to Antrea forwarding rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.NATTable, antreaPostRoutingChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.NATTable, iptables.PostRoutingChain, []string{"-j", antreaPostRoutingChain, "-m", "comment", "--comment", "Antrea: jump to Antrea postrouting rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.MangleTable, antreaMangleChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.MangleTable, iptables.PreRoutingChain, []string{"-j", antreaMangleChain, "-m", "comment", "--comment", "Antrea: jump to Antrea mangle rules"})
				mockIPTables.EnsureChain(iptables.ProtocolDual, iptables.MangleTable, antreaOutputChain)
				mockIPTables.AppendRule(iptables.ProtocolDual, iptables.MangleTable, iptables.OutputChain, []string{"-j", antreaOutputChain, "-m", "comment", "--comment", "Antrea: jump to Antrea output rules"})
				mockIPTables.Restore(`*raw
:ANTREA-PREROUTING - [0:0]
:ANTREA-OUTPUT - [0:0]
COMMIT
*mangle
:ANTREA-MANGLE - [0:0]
:ANTREA-OUTPUT - [0:0]
-A ANTREA-OUTPUT -m comment --comment "Antrea: mark LOCAL output packets" -m addrtype --src-type LOCAL -o antrea-gw0 -j MARK --or-mark 0x80000000
-A ANTREA-OUTPUT -m comment --comment "Antrea: mark LOCAL output packets" -m addrtype --src-type LOCAL -o  -j MARK --or-mark 0x80000000
COMMIT
*filter
:ANTREA-FORWARD - [0:0]
-A ANTREA-FORWARD -m comment --comment "Antrea: accept packets from local Pods" -i antrea-gw0 -j ACCEPT
-A ANTREA-FORWARD -m comment --comment "Antrea: accept packets to local Pods" -o antrea-gw0 -j ACCEPT
-A ANTREA-FORWARD -m comment --comment "Antrea: accept packets from local AntreaFlexibleIPAM Pods" -m set --match-set LOCAL-FLEXIBLE-IPAM-POD-IP src -j ACCEPT
-A ANTREA-FORWARD -m comment --comment "Antrea: accept packets to local AntreaFlexibleIPAM Pods" -m set --match-set LOCAL-FLEXIBLE-IPAM-POD-IP dst -j ACCEPT
COMMIT
*nat
:ANTREA-POSTROUTING - [0:0]
-A ANTREA-POSTROUTING -m comment --comment "Antrea: masquerade Pod to external packets" -s 172.16.10.0/24 -m set ! --match-set ANTREA-POD-IP dst ! -o antrea-gw0 -j MASQUERADE
-A ANTREA-POSTROUTING -m comment --comment "Antrea: masquerade LOCAL traffic" -o antrea-gw0 -m addrtype ! --src-type LOCAL --limit-iface-out -m addrtype --src-type LOCAL -j MASQUERADE --random-fully
-A ANTREA-POSTROUTING -m comment --comment "Antrea: masquerade traffic to local AntreaIPAM hostPort Pod" ! -s 172.16.10.0/24 -m set --match-set LOCAL-FLEXIBLE-IPAM-POD-IP dst -j MASQUERADE
COMMIT
`, false, false)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPTables := iptablestest.NewMockInterface(ctrl)
			c := &Client{iptables: mockIPTables,
				networkConfig:            tt.networkConfig,
				nodeConfig:               tt.nodeConfig,
				proxyAll:                 tt.proxyAll,
				isCloudEKS:               tt.isCloudEKS,
				multicastEnabled:         tt.multicastEnabled,
				connectUplinkToBridge:    tt.connectUplinkToBridge,
				nodeNetworkPolicyEnabled: tt.nodeNetworkPolicyEnabled,
				deterministic:            true,
			}
			for mark, snatIP := range tt.markToSNATIP {
				c.markToSNATIP.Store(mark, net.ParseIP(snatIP))
			}
			if tt.nodeNetworkPolicyEnabled {
				c.initNodeNetworkPolicy()
				c.nodeNetworkPolicyIPTablesIPv4.Store(config.NodeNetworkPolicyIngressRulesChain, []string{
					`-A ANTREA-POL-INGRESS-RULES -j ACCEPT -m comment --comment "mock rule"`})
				c.nodeNetworkPolicyIPTablesIPv6.Store(config.NodeNetworkPolicyIngressRulesChain, []string{
					`-A ANTREA-POL-INGRESS-RULES -j ACCEPT -m comment --comment "mock rule"`})
			}
			tt.expectedCalls(mockIPTables.EXPECT())
			assert.NoError(t, c.syncIPTables())
		})
	}
}

func TestInitIPRoutes(t *testing.T) {
	ipv4, nodeTransPortIPv4Addr, _ := net.ParseCIDR("172.16.10.2/24")
	nodeTransPortIPv4Addr.IP = ipv4
	ipv6, nodeTransPortIPv6Addr, _ := net.ParseCIDR("fe80::e643:4bff:fe44:ee/64")
	nodeTransPortIPv6Addr.IP = ipv6

	tests := []struct {
		name          string
		networkConfig *config.NetworkConfig
		nodeConfig    *config.NodeConfig
		expectedCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
	}{
		{
			name:          "networkPolicyOnly",
			networkConfig: &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeNetworkPolicyOnly},
			nodeConfig: &config.NodeConfig{
				GatewayConfig:         &config.GatewayConfig{Name: "antrea-gw0"},
				NodeTransportIPv4Addr: nodeTransPortIPv4Addr,
				NodeTransportIPv6Addr: nodeTransPortIPv6Addr,
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("antrea-gw0")
				_, ipv4, _ := net.ParseCIDR("172.16.10.2/32")
				mockNetlink.AddrReplace(gomock.Any(), &netlink.Addr{IPNet: ipv4})
				_, ipv6, _ := net.ParseCIDR("fe80::e643:4bff:fe44:ee/128")
				mockNetlink.AddrReplace(gomock.Any(), &netlink.Addr{IPNet: ipv6})
			},
		},
		{
			name:          "encap",
			networkConfig: &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap},
			nodeConfig: &config.NodeConfig{
				GatewayConfig:         &config.GatewayConfig{Name: "antrea-gw0"},
				NodeTransportIPv4Addr: nodeTransPortIPv4Addr,
				NodeTransportIPv6Addr: nodeTransPortIPv6Addr,
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockNetlink := netlinktest.NewMockInterface(ctrl)
			c := &Client{netlink: mockNetlink,
				networkConfig: tt.networkConfig,
				nodeConfig:    tt.nodeConfig,
			}
			tt.expectedCalls(mockNetlink.EXPECT())
			assert.NoError(t, c.initIPRoutes())
		})
	}
}

func TestInitServiceIPRoutes(t *testing.T) {
	tests := []struct {
		name          string
		networkConfig *config.NetworkConfig
		nodeConfig    *config.NodeConfig
		expectedCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
	}{
		{
			name: "encap",
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeEncap,
				IPv4Enabled:      true,
				IPv6Enabled:      true,
			},
			nodeConfig: &config.NodeConfig{
				GatewayConfig: &config.GatewayConfig{Name: "antrea-gw0", LinkIndex: 10},
			},
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.NeighSet(&netlink.Neigh{
					LinkIndex:    10,
					Family:       netlink.FAMILY_V4,
					State:        netlink.NUD_PERMANENT,
					IP:           config.VirtualServiceIPv4,
					HardwareAddr: globalVMAC,
				})
				mockNetlink.RouteReplace(&netlink.Route{
					Dst: &net.IPNet{
						IP:   config.VirtualServiceIPv4,
						Mask: net.CIDRMask(32, 32),
					},
					Scope:     netlink.SCOPE_LINK,
					LinkIndex: 10,
				})
				mockNetlink.RouteReplace(&netlink.Route{
					Dst: &net.IPNet{
						IP:   config.VirtualNodePortDNATIPv4,
						Mask: net.CIDRMask(32, 32),
					},
					Gw:        config.VirtualServiceIPv4,
					Scope:     netlink.SCOPE_UNIVERSE,
					LinkIndex: 10,
				})
				mockNetlink.NeighSet(&netlink.Neigh{
					LinkIndex:    10,
					Family:       netlink.FAMILY_V6,
					State:        netlink.NUD_PERMANENT,
					IP:           config.VirtualServiceIPv6,
					HardwareAddr: globalVMAC,
				})
				mockNetlink.RouteReplace(&netlink.Route{
					Dst: &net.IPNet{
						IP:   config.VirtualServiceIPv6,
						Mask: net.CIDRMask(128, 128),
					},
					Scope:     netlink.SCOPE_LINK,
					LinkIndex: 10,
				})
				mockNetlink.RouteReplace(&netlink.Route{
					Dst: &net.IPNet{
						IP:   config.VirtualNodePortDNATIPv6,
						Mask: net.CIDRMask(128, 128),
					},
					Gw:        config.VirtualServiceIPv6,
					Scope:     netlink.SCOPE_UNIVERSE,
					LinkIndex: 10,
				})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockNetlink := netlinktest.NewMockInterface(ctrl)
			mockServiceCIDRProvider := servicecidrtest.NewMockInterface(ctrl)
			c := &Client{netlink: mockNetlink,
				networkConfig:       tt.networkConfig,
				nodeConfig:          tt.nodeConfig,
				serviceCIDRProvider: mockServiceCIDRProvider,
			}
			tt.expectedCalls(mockNetlink.EXPECT())
			mockServiceCIDRProvider.EXPECT().AddEventHandler(gomock.Any())
			assert.NoError(t, c.initServiceIPRoutes())
		})
	}
}

func TestReconcile(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockNetlink := netlinktest.NewMockInterface(ctrl)
	mockIPSet := ipsettest.NewMockInterface(ctrl)
	c := &Client{netlink: mockNetlink,
		ipset:         mockIPSet,
		proxyAll:      true,
		networkConfig: &config.NetworkConfig{},
		nodeConfig: &config.NodeConfig{
			PodIPv4CIDR:   ip.MustParseCIDR("192.168.10.0/24"),
			PodIPv6CIDR:   ip.MustParseCIDR("2001:ab03:cd04:55ee:100a::/80"),
			GatewayConfig: &config.GatewayConfig{LinkIndex: 10},
		},
	}
	podCIDRs := []string{"192.168.0.0/24", "192.168.1.0/24", "2001:ab03:cd04:55ee:1001::/80", "2001:ab03:cd04:55ee:1002::/80"}

	mockIPSet.EXPECT().ListEntries(antreaPodIPSet).Return([]string{
		"192.168.0.0/24", // existing podCIDR, should not be deleted.
		"192.168.2.0/24", // non-existing podCIDR, should be deleted.
	}, nil)
	mockIPSet.EXPECT().ListEntries(antreaPodIP6Set).Return([]string{
		"2001:ab03:cd04:55ee:1001::/80", // existing podCIDR, should not be deleted.
		"2001:ab03:cd04:55ee:1003::/80", // non-existing podCIDR, should be deleted.
	}, nil)
	mockIPSet.EXPECT().DelEntry(antreaPodIPSet, "192.168.2.0/24")
	mockIPSet.EXPECT().DelEntry(antreaPodIP6Set, "2001:ab03:cd04:55ee:1003::/80")
	mockNetlink.EXPECT().RouteDel(&netlink.Route{Dst: ip.MustParseCIDR("192.168.2.0/24")})
	mockNetlink.EXPECT().RouteDel(&netlink.Route{Dst: ip.MustParseCIDR("2001:ab03:cd04:55ee:1003::/80")})

	mockNetlink.EXPECT().RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{LinkIndex: 10}, netlink.RT_FILTER_OIF).Return([]netlink.Route{
		{Dst: ip.MustParseCIDR("192.168.10.0/24")},  // local podCIDR, should not be deleted.
		{Dst: ip.MustParseCIDR("192.168.1.0/24")},   // existing podCIDR, should not be deleted.
		{Dst: ip.MustParseCIDR("169.254.0.253/32")}, // service route, should not be deleted.
		{Dst: ip.MustParseCIDR("192.168.11.0/24")},  // non-existing podCIDR, should be deleted.
	}, nil)
	mockNetlink.EXPECT().RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{LinkIndex: 10}, netlink.RT_FILTER_OIF).Return([]netlink.Route{
		{Dst: ip.MustParseCIDR("2001:ab03:cd04:55ee:100a::/80")},   // local podCIDR, should not be deleted.
		{Dst: ip.MustParseCIDR("2001:ab03:cd04:55ee:1001::1/128")}, // existing podCIDR, should not be deleted.
		{Dst: ip.MustParseCIDR("fc01::aabb:ccdd:eeff/128")},        // service route, should not be deleted.
		{Dst: ip.MustParseCIDR("2001:ab03:cd04:55ee:100b::/80")},   // non-existing podCIDR, should be deleted.
		{Dst: ip.MustParseCIDR("fe80::/80")},                       // link-local route, should not be deleted.
	}, nil)
	mockNetlink.EXPECT().RouteDel(&netlink.Route{Dst: ip.MustParseCIDR("192.168.11.0/24")})
	mockNetlink.EXPECT().RouteDel(&netlink.Route{Dst: ip.MustParseCIDR("2001:ab03:cd04:55ee:100b::/80")})

	mockNetlink.EXPECT().NeighList(10, netlink.FAMILY_V6).Return([]netlink.Neigh{
		{IP: net.ParseIP("2001:ab03:cd04:55ee:1001::1")}, // existing podCIDR, should not be deleted.
		{IP: net.ParseIP("fc01::aabb:ccdd:eeff")},        // virtual service IP, should not be deleted.
		{IP: net.ParseIP("2001:ab03:cd04:55ee:100b::1")}, // non-existing podCIDR, should be deleted.
	}, nil)
	mockNetlink.EXPECT().NeighDel(&netlink.Neigh{IP: net.ParseIP("2001:ab03:cd04:55ee:100b::1")})
	assert.NoError(t, c.Reconcile(podCIDRs))
}

func TestAddRoutes(t *testing.T) {
	ipv4, nodeTransPortIPv4Addr, _ := net.ParseCIDR("172.16.10.2/24")
	nodeTransPortIPv4Addr.IP = ipv4
	ipv6, nodeTransPortIPv6Addr, _ := net.ParseCIDR("fe80::e643:4bff:fe44:ee/64")
	nodeTransPortIPv6Addr.IP = ipv6

	tests := []struct {
		name                 string
		networkConfig        *config.NetworkConfig
		nodeConfig           *config.NodeConfig
		podCIDR              *net.IPNet
		nodeName             string
		nodeIP               net.IP
		nodeGwIP             net.IP
		expectedIPSetCalls   func(mockNetlink *ipsettest.MockInterfaceMockRecorder)
		expectedNetlinkCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
	}{
		{
			name: "wireGuard IPv4",
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode:      config.TrafficEncapModeEncap,
				TrafficEncryptionMode: config.TrafficEncryptionModeWireGuard,
				IPv4Enabled:           true,
			},
			nodeConfig: &config.NodeConfig{
				GatewayConfig: &config.GatewayConfig{
					Name:      "antrea-gw0",
					IPv4:      net.ParseIP("1.1.1.1"),
					LinkIndex: 10,
				},
				WireGuardConfig:       &config.WireGuardConfig{LinkIndex: 11},
				NodeTransportIPv4Addr: nodeTransPortIPv4Addr,
			},
			podCIDR:  ip.MustParseCIDR("192.168.10.0/24"),
			nodeName: "node0",
			nodeIP:   net.ParseIP("1.1.1.10"),
			nodeGwIP: net.ParseIP("192.168.10.1"),
			expectedIPSetCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.AddEntry(antreaPodIPSet, "192.168.10.0/24")
			},
			expectedNetlinkCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteReplace(&netlink.Route{
					Src:       net.ParseIP("1.1.1.1"),
					Dst:       ip.MustParseCIDR("192.168.10.0/24"),
					Scope:     netlink.SCOPE_LINK,
					LinkIndex: 11,
				})
			},
		},
		{
			name: "wireGuard IPv6",
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode:      config.TrafficEncapModeEncap,
				TrafficEncryptionMode: config.TrafficEncryptionModeWireGuard,
				IPv6Enabled:           true,
			},
			nodeConfig: &config.NodeConfig{
				GatewayConfig: &config.GatewayConfig{
					Name:      "antrea-gw0",
					IPv6:      net.ParseIP("fe80::e643:4bff:fe44:1"),
					LinkIndex: 10,
				},
				WireGuardConfig:       &config.WireGuardConfig{LinkIndex: 11},
				NodeTransportIPv6Addr: nodeTransPortIPv6Addr,
			},
			podCIDR:  ip.MustParseCIDR("2001:ab03:cd04:55ee:1001::/80"),
			nodeName: "node0",
			nodeIP:   net.ParseIP("fe80::e643:4bff:fe44:2"),
			nodeGwIP: net.ParseIP("2001:ab03:cd04:55ee:1001::1"),
			expectedIPSetCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.AddEntry(antreaPodIP6Set, "2001:ab03:cd04:55ee:1001::/80")
			},
			expectedNetlinkCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteReplace(&netlink.Route{
					Src:       net.ParseIP("fe80::e643:4bff:fe44:1"),
					Dst:       ip.MustParseCIDR("2001:ab03:cd04:55ee:1001::/80"),
					Scope:     netlink.SCOPE_LINK,
					LinkIndex: 11,
				})
				mockNetlink.RouteDel(&netlink.Route{
					Dst: &net.IPNet{IP: net.ParseIP("2001:ab03:cd04:55ee:1001::1"), Mask: net.CIDRMask(128, 128)},
				})
				mockNetlink.NeighDel(&netlink.Neigh{
					LinkIndex: 10,
					Family:    netlink.FAMILY_V6,
					IP:        net.ParseIP("2001:ab03:cd04:55ee:1001::1"),
				})
			},
		},
		{
			name: "encap IPv4",
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeEncap,
				IPv4Enabled:      true,
			},
			nodeConfig: &config.NodeConfig{
				GatewayConfig: &config.GatewayConfig{
					Name:      "antrea-gw0",
					IPv4:      net.ParseIP("1.1.1.1"),
					LinkIndex: 10,
				},
				NodeTransportIPv4Addr: nodeTransPortIPv4Addr,
			},
			podCIDR:  ip.MustParseCIDR("192.168.10.0/24"),
			nodeName: "node0",
			nodeIP:   net.ParseIP("1.1.1.10"),
			nodeGwIP: net.ParseIP("192.168.10.1"),
			expectedIPSetCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.AddEntry(antreaPodIPSet, "192.168.10.0/24")
			},
			expectedNetlinkCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteReplace(&netlink.Route{
					Gw:        net.ParseIP("192.168.10.1"),
					Dst:       ip.MustParseCIDR("192.168.10.0/24"),
					Flags:     int(netlink.FLAG_ONLINK),
					LinkIndex: 10,
				})
			},
		},
		{
			name: "encap IPv6",
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeEncap,
				IPv6Enabled:      true,
			},
			nodeConfig: &config.NodeConfig{
				GatewayConfig: &config.GatewayConfig{
					Name:      "antrea-gw0",
					IPv6:      net.ParseIP("fe80::e643:4bff:fe44:1"),
					LinkIndex: 10,
				},
				NodeTransportIPv6Addr: nodeTransPortIPv6Addr,
			},
			podCIDR:  ip.MustParseCIDR("2001:ab03:cd04:55ee:1001::/80"),
			nodeName: "node0",
			nodeIP:   net.ParseIP("fe80::e643:4bff:fe44:2"),
			nodeGwIP: net.ParseIP("2001:ab03:cd04:55ee:1001::1"),
			expectedIPSetCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.AddEntry(antreaPodIP6Set, "2001:ab03:cd04:55ee:1001::/80")
			},
			expectedNetlinkCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteReplace(&netlink.Route{
					Dst:       ip.MustParseCIDR("2001:ab03:cd04:55ee:1001::1/128"),
					LinkIndex: 10,
				})
				mockNetlink.RouteReplace(&netlink.Route{
					Gw:        net.ParseIP("2001:ab03:cd04:55ee:1001::1"),
					Dst:       ip.MustParseCIDR("2001:ab03:cd04:55ee:1001::/80"),
					LinkIndex: 10,
				})
				mockNetlink.NeighSet(&netlink.Neigh{
					LinkIndex:    10,
					Family:       netlink.FAMILY_V6,
					State:        netlink.NUD_PERMANENT,
					IP:           net.ParseIP("2001:ab03:cd04:55ee:1001::1"),
					HardwareAddr: globalVMAC,
				})
			},
		},
		{
			name: "noencap IPv4, direct routing",
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeNoEncap,
				IPv4Enabled:      true,
			},
			nodeConfig: &config.NodeConfig{
				GatewayConfig: &config.GatewayConfig{
					Name:      "antrea-gw0",
					IPv4:      net.ParseIP("192.168.1.1"),
					LinkIndex: 10,
				},
				NodeTransportIPv4Addr: nodeTransPortIPv4Addr,
			},
			podCIDR:  ip.MustParseCIDR("192.168.10.0/24"),
			nodeName: "node0",
			nodeIP:   net.ParseIP("172.16.10.3"), // In the same subnet as local Node IP.
			nodeGwIP: net.ParseIP("192.168.10.1"),
			expectedIPSetCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.AddEntry(antreaPodIPSet, "192.168.10.0/24")
			},
			expectedNetlinkCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteReplace(&netlink.Route{
					Gw:  net.ParseIP("172.16.10.3"),
					Dst: ip.MustParseCIDR("192.168.10.0/24"),
				})
			},
		},
		{
			name: "noencap IPv4, no direct routing",
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeNoEncap,
				IPv4Enabled:      true,
			},
			nodeConfig: &config.NodeConfig{
				GatewayConfig: &config.GatewayConfig{
					Name:      "antrea-gw0",
					IPv4:      net.ParseIP("192.168.1.1"),
					LinkIndex: 10,
				},
				NodeTransportIPv4Addr: nodeTransPortIPv4Addr,
			},
			podCIDR:  ip.MustParseCIDR("192.168.10.0/24"),
			nodeName: "node0",
			nodeIP:   net.ParseIP("172.16.11.3"), // In different subnet from local Node IP.
			nodeGwIP: net.ParseIP("192.168.10.1"),
			expectedIPSetCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.AddEntry(antreaPodIPSet, "192.168.10.0/24")
			},
			expectedNetlinkCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockNetlink := netlinktest.NewMockInterface(ctrl)
			mockIPSet := ipsettest.NewMockInterface(ctrl)
			c := &Client{netlink: mockNetlink,
				ipset:         mockIPSet,
				networkConfig: tt.networkConfig,
				nodeConfig:    tt.nodeConfig,
			}
			tt.expectedIPSetCalls(mockIPSet.EXPECT())
			tt.expectedNetlinkCalls(mockNetlink.EXPECT())
			assert.NoError(t, c.AddRoutes(tt.podCIDR, tt.nodeName, tt.nodeIP, tt.nodeGwIP))
		})
	}
}

func TestDeleteRoutes(t *testing.T) {
	tests := []struct {
		name                  string
		networkConfig         *config.NetworkConfig
		nodeConfig            *config.NodeConfig
		podCIDR               *net.IPNet
		existingNodeRoutes    map[string][]*netlink.Route
		existingNodeNeighbors map[string]*netlink.Neigh
		nodeName              string
		expectedIPSetCalls    func(mockNetlink *ipsettest.MockInterfaceMockRecorder)
		expectedNetlinkCalls  func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
	}{
		{
			name:    "IPv4",
			podCIDR: ip.MustParseCIDR("192.168.10.0/24"),
			existingNodeRoutes: map[string][]*netlink.Route{
				"192.168.10.0/24": {{Gw: net.ParseIP("172.16.10.3"), Dst: ip.MustParseCIDR("192.168.10.0/24")}},
				"192.168.11.0/24": {{Gw: net.ParseIP("172.16.10.4"), Dst: ip.MustParseCIDR("192.168.11.0/24")}},
			},
			expectedIPSetCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.DelEntry(antreaPodIPSet, "192.168.10.0/24")
			},
			expectedNetlinkCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteDel(&netlink.Route{Gw: net.ParseIP("172.16.10.3"), Dst: ip.MustParseCIDR("192.168.10.0/24")})
			},
		},
		{
			name:    "IPv6",
			podCIDR: ip.MustParseCIDR("2001:ab03:cd04:55ee:1001::/80"),
			existingNodeRoutes: map[string][]*netlink.Route{
				"2001:ab03:cd04:55ee:1001::/80": {{Gw: net.ParseIP("fe80::e643:4bff:fe44:1"), Dst: ip.MustParseCIDR("2001:ab03:cd04:55ee:1001::/80")}},
				"2001:ab03:cd04:55ee:1002::/80": {{Gw: net.ParseIP("fe80::e643:4bff:fe44:2"), Dst: ip.MustParseCIDR("2001:ab03:cd04:55ee:1002::/80")}},
			},
			existingNodeNeighbors: map[string]*netlink.Neigh{},
			expectedIPSetCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.DelEntry(antreaPodIP6Set, "2001:ab03:cd04:55ee:1001::/80")
			},
			expectedNetlinkCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteDel(&netlink.Route{Gw: net.ParseIP("fe80::e643:4bff:fe44:1"), Dst: ip.MustParseCIDR("2001:ab03:cd04:55ee:1001::/80")})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockNetlink := netlinktest.NewMockInterface(ctrl)
			mockIPSet := ipsettest.NewMockInterface(ctrl)
			c := &Client{netlink: mockNetlink,
				ipset:         mockIPSet,
				networkConfig: tt.networkConfig,
				nodeConfig:    tt.nodeConfig,
				nodeRoutes:    sync.Map{},
				nodeNeighbors: sync.Map{},
			}
			for podCIDR, nodeRoute := range tt.existingNodeRoutes {
				c.nodeRoutes.Store(podCIDR, nodeRoute)
			}
			for podCIDR, nodeNeighbor := range tt.existingNodeNeighbors {
				c.nodeNeighbors.Store(podCIDR, nodeNeighbor)
			}
			tt.expectedIPSetCalls(mockIPSet.EXPECT())
			tt.expectedNetlinkCalls(mockNetlink.EXPECT())
			assert.NoError(t, c.DeleteRoutes(tt.podCIDR))
		})
	}
}

func TestMigrateRoutesToGw(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockNetlink := netlinktest.NewMockInterface(ctrl)
	mockIPSet := ipsettest.NewMockInterface(ctrl)

	gwLinkName := "antrea-gw0"
	gwLink := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 11}}
	linkName := "eth0"
	link := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 10}}
	linkAddr1, _ := netlink.ParseAddr("192.168.10.1/32")
	linkAddr2, _ := netlink.ParseAddr("169.254.0.2/32") // LinkLocalUnicast address should not be migrated.
	linkAddr3, _ := netlink.ParseAddr("2001:ab03:cd04:55ee:1001::1/80")
	linkAddr4, _ := netlink.ParseAddr("fe80:ab03:cd04:55ee:1001::1/80") // LinkLocalUnicast address should not be migrated.

	mockNetlink.EXPECT().LinkByName(gwLinkName).Return(gwLink, nil)
	mockNetlink.EXPECT().LinkByName(linkName).Return(link, nil)
	mockNetlink.EXPECT().RouteList(link, netlink.FAMILY_V4).Return([]netlink.Route{
		{Gw: net.ParseIP("172.16.1.10"), Dst: ip.MustParseCIDR("192.168.10.0/24"), LinkIndex: 10},
	}, nil)
	mockNetlink.EXPECT().RouteList(link, netlink.FAMILY_V6).Return([]netlink.Route{
		{Gw: net.ParseIP("fe80::e643:4bff:fe44:1"), Dst: ip.MustParseCIDR("2001:ab03:cd04:55ee:1001::/80"), LinkIndex: 10},
	}, nil)
	mockNetlink.EXPECT().RouteReplace(&netlink.Route{Gw: net.ParseIP("172.16.1.10"), Dst: ip.MustParseCIDR("192.168.10.0/24"), LinkIndex: 11})
	mockNetlink.EXPECT().RouteReplace(&netlink.Route{Gw: net.ParseIP("fe80::e643:4bff:fe44:1"), Dst: ip.MustParseCIDR("2001:ab03:cd04:55ee:1001::/80"), LinkIndex: 11})
	mockNetlink.EXPECT().AddrList(link, netlink.FAMILY_V4).Return([]netlink.Addr{*linkAddr1, *linkAddr2}, nil)
	mockNetlink.EXPECT().AddrList(link, netlink.FAMILY_V6).Return([]netlink.Addr{*linkAddr3, *linkAddr4}, nil)
	mockNetlink.EXPECT().AddrDel(link, linkAddr1)
	mockNetlink.EXPECT().AddrReplace(gwLink, linkAddr1)
	mockNetlink.EXPECT().AddrDel(link, linkAddr3)
	mockNetlink.EXPECT().AddrReplace(gwLink, linkAddr3)

	c := &Client{
		netlink: mockNetlink,
		ipset:   mockIPSet,
		nodeConfig: &config.NodeConfig{
			GatewayConfig: &config.GatewayConfig{Name: gwLinkName},
		},
	}
	c.MigrateRoutesToGw(linkName)
}

func TestUnMigrateRoutesToGw(t *testing.T) {
	gwLink := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 11}}
	link := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 10}}
	tests := []struct {
		name          string
		nodeConfig    *config.NodeConfig
		route         string
		link          string
		expectedCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
	}{
		{
			name:       "link provided",
			route:      "192.168.10.0/24",
			link:       "eth0",
			nodeConfig: &config.NodeConfig{GatewayConfig: &config.GatewayConfig{Name: "antrea-gw0"}},
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("antrea-gw0").Return(gwLink, nil)
				mockNetlink.LinkByName("eth0").Return(link, nil)
				mockNetlink.RouteList(gwLink, netlink.FAMILY_V4).Return([]netlink.Route{
					{Gw: net.ParseIP("172.16.1.10"), Dst: ip.MustParseCIDR("192.168.10.0/24"), LinkIndex: 11},
				}, nil)
				mockNetlink.RouteReplace(&netlink.Route{Gw: net.ParseIP("172.16.1.10"), Dst: ip.MustParseCIDR("192.168.10.0/24"), LinkIndex: 10})
			},
		},
		{
			name:       "link not provided",
			route:      "192.168.10.0/24",
			link:       "",
			nodeConfig: &config.NodeConfig{GatewayConfig: &config.GatewayConfig{Name: "antrea-gw0"}},
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.LinkByName("antrea-gw0").Return(gwLink, nil)
				mockNetlink.RouteList(gwLink, netlink.FAMILY_V4).Return([]netlink.Route{
					{Gw: net.ParseIP("172.16.1.10"), Dst: ip.MustParseCIDR("192.168.10.0/24"), LinkIndex: 11},
				}, nil)
				mockNetlink.RouteDel(&netlink.Route{Gw: net.ParseIP("172.16.1.10"), Dst: ip.MustParseCIDR("192.168.10.0/24"), LinkIndex: 11})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockNetlink := netlinktest.NewMockInterface(ctrl)
			c := &Client{
				netlink:    mockNetlink,
				nodeConfig: tt.nodeConfig,
			}
			tt.expectedCalls(mockNetlink.EXPECT())
			c.UnMigrateRoutesFromGw(ip.MustParseCIDR(tt.route), tt.link)
		})
	}
}

func TestAddSNATRule(t *testing.T) {
	tests := []struct {
		name          string
		networkConfig *config.NetworkConfig
		nodeConfig    *config.NodeConfig
		snatIP        net.IP
		mark          uint32
		expectedCalls func(mockIPTables *iptablestest.MockInterfaceMockRecorder)
	}{
		{
			name: "IPv4",
			nodeConfig: &config.NodeConfig{
				GatewayConfig: &config.GatewayConfig{
					Name: "antrea-gw0",
				},
			},
			snatIP: net.ParseIP("1.1.1.1"),
			mark:   10,
			expectedCalls: func(mockIPTables *iptablestest.MockInterfaceMockRecorder) {
				mockIPTables.InsertRule(iptables.ProtocolIPv4, iptables.NATTable, antreaPostRoutingChain, []string{
					"-m", "comment", "--comment", "Antrea: SNAT Pod to external packets",
					"!", "-o", "antrea-gw0",
					"-m", "mark", "--mark", fmt.Sprintf("%#08x/%#08x", 10, types.SNATIPMarkMask),
					"-j", iptables.SNATTarget, "--to", "1.1.1.1",
				})
			},
		},
		{
			name: "IPv6",
			nodeConfig: &config.NodeConfig{
				GatewayConfig: &config.GatewayConfig{
					Name: "antrea-gw0",
				},
			},
			snatIP: net.ParseIP("fe80::e643:4bff:fe44:1"),
			mark:   11,
			expectedCalls: func(mockIPTables *iptablestest.MockInterfaceMockRecorder) {
				mockIPTables.InsertRule(iptables.ProtocolIPv6, iptables.NATTable, antreaPostRoutingChain, []string{
					"-m", "comment", "--comment", "Antrea: SNAT Pod to external packets",
					"!", "-o", "antrea-gw0",
					"-m", "mark", "--mark", fmt.Sprintf("%#08x/%#08x", 11, types.SNATIPMarkMask),
					"-j", iptables.SNATTarget, "--to", "fe80::e643:4bff:fe44:1",
				})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPTables := iptablestest.NewMockInterface(ctrl)
			c := &Client{iptables: mockIPTables,
				nodeConfig: tt.nodeConfig,
			}
			tt.expectedCalls(mockIPTables.EXPECT())
			assert.NoError(t, c.AddSNATRule(tt.snatIP, tt.mark))
		})
	}
}

func TestDeleteSNATRule(t *testing.T) {
	tests := []struct {
		name          string
		networkConfig *config.NetworkConfig
		markToSNATIP  map[uint32]net.IP
		nodeConfig    *config.NodeConfig
		mark          uint32
		expectedCalls func(mockIPTables *iptablestest.MockInterfaceMockRecorder)
	}{
		{
			name: "IPv4",
			nodeConfig: &config.NodeConfig{
				GatewayConfig: &config.GatewayConfig{
					Name: "antrea-gw0",
				},
			},
			markToSNATIP: map[uint32]net.IP{
				10: net.ParseIP("1.1.1.1"),
				11: net.ParseIP("1.1.1.2"),
			},
			mark: 10,
			expectedCalls: func(mockIPTables *iptablestest.MockInterfaceMockRecorder) {
				mockIPTables.DeleteRule(iptables.ProtocolIPv4, iptables.NATTable, antreaPostRoutingChain, []string{
					"-m", "comment", "--comment", "Antrea: SNAT Pod to external packets",
					"!", "-o", "antrea-gw0",
					"-m", "mark", "--mark", fmt.Sprintf("%#08x/%#08x", 10, types.SNATIPMarkMask),
					"-j", iptables.SNATTarget, "--to", "1.1.1.1",
				})
			},
		},
		{
			name: "IPv6",
			nodeConfig: &config.NodeConfig{
				GatewayConfig: &config.GatewayConfig{
					Name: "antrea-gw0",
				},
			},
			markToSNATIP: map[uint32]net.IP{
				10: net.ParseIP("fe80::e643:4bff:fe44:1"),
				11: net.ParseIP("fe80::e643:4bff:fe44:2"),
			},
			mark: 11,
			expectedCalls: func(mockIPTables *iptablestest.MockInterfaceMockRecorder) {
				mockIPTables.DeleteRule(iptables.ProtocolIPv6, iptables.NATTable, antreaPostRoutingChain, []string{
					"-m", "comment", "--comment", "Antrea: SNAT Pod to external packets",
					"!", "-o", "antrea-gw0",
					"-m", "mark", "--mark", fmt.Sprintf("%#08x/%#08x", 11, types.SNATIPMarkMask),
					"-j", iptables.SNATTarget, "--to", "fe80::e643:4bff:fe44:2",
				})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPTables := iptablestest.NewMockInterface(ctrl)
			c := &Client{
				iptables:     mockIPTables,
				nodeConfig:   tt.nodeConfig,
				markToSNATIP: sync.Map{},
			}
			for mark, snatIP := range tt.markToSNATIP {
				c.markToSNATIP.Store(mark, snatIP)
			}
			tt.expectedCalls(mockIPTables.EXPECT())
			assert.NoError(t, c.DeleteSNATRule(tt.mark))
		})
	}
}

func TestAddNodePort(t *testing.T) {
	tests := []struct {
		name              string
		nodePortAddresses []net.IP
		port              uint16
		protocol          openflow.Protocol
		expectedCalls     func(ipset *ipsettest.MockInterfaceMockRecorder)
	}{
		{
			name: "ipv4 tcp",
			nodePortAddresses: []net.IP{
				net.ParseIP("1.1.1.1"),
				net.ParseIP("1.1.2.2"),
			},
			port:     30000,
			protocol: openflow.ProtocolTCP,
			expectedCalls: func(ipset *ipsettest.MockInterfaceMockRecorder) {
				ipset.AddEntry(antreaNodePortIPSet, "1.1.1.1,tcp:30000")
				ipset.AddEntry(antreaNodePortIPSet, "1.1.2.2,tcp:30000")
			},
		},
		{
			name: "ipv6 udp",
			nodePortAddresses: []net.IP{
				net.ParseIP("fd00:1234:5678:dead:beaf::1"),
				net.ParseIP("fd00:1234:5678:dead:beaf::2"),
			},
			port:     30001,
			protocol: openflow.ProtocolUDPv6,
			expectedCalls: func(ipset *ipsettest.MockInterfaceMockRecorder) {
				ipset.AddEntry(antreaNodePortIP6Set, "fd00:1234:5678:dead:beaf::1,udp:30001")
				ipset.AddEntry(antreaNodePortIP6Set, "fd00:1234:5678:dead:beaf::2,udp:30001")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			ipset := ipsettest.NewMockInterface(ctrl)
			c := &Client{ipset: ipset}
			tt.expectedCalls(ipset.EXPECT())
			assert.NoError(t, c.AddNodePort(tt.nodePortAddresses, tt.port, tt.protocol))
		})
	}
}

func TestDeleteNodePort(t *testing.T) {
	tests := []struct {
		name              string
		nodePortAddresses []net.IP
		port              uint16
		protocol          openflow.Protocol
		expectedCalls     func(ipset *ipsettest.MockInterfaceMockRecorder)
	}{
		{
			name: "ipv4 tcp",
			nodePortAddresses: []net.IP{
				net.ParseIP("1.1.1.1"),
				net.ParseIP("1.1.2.2"),
			},
			port:     30000,
			protocol: openflow.ProtocolTCP,
			expectedCalls: func(ipset *ipsettest.MockInterfaceMockRecorder) {
				ipset.DelEntry(antreaNodePortIPSet, "1.1.1.1,tcp:30000")
				ipset.DelEntry(antreaNodePortIPSet, "1.1.2.2,tcp:30000")
			},
		},
		{
			name: "ipv6 udp",
			nodePortAddresses: []net.IP{
				net.ParseIP("fd00:1234:5678:dead:beaf::1"),
				net.ParseIP("fd00:1234:5678:dead:beaf::2"),
			},
			port:     30001,
			protocol: openflow.ProtocolUDPv6,
			expectedCalls: func(ipset *ipsettest.MockInterfaceMockRecorder) {
				ipset.DelEntry(antreaNodePortIP6Set, "fd00:1234:5678:dead:beaf::1,udp:30001")
				ipset.DelEntry(antreaNodePortIP6Set, "fd00:1234:5678:dead:beaf::2,udp:30001")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			ipset := ipsettest.NewMockInterface(ctrl)
			c := &Client{ipset: ipset}
			tt.expectedCalls(ipset.EXPECT())
			assert.NoError(t, c.DeleteNodePort(tt.nodePortAddresses, tt.port, tt.protocol))
		})
	}
}

func TestAddServiceCIDRRoute(t *testing.T) {
	_, serviceIPv4CIDR1, _ := net.ParseCIDR("10.96.0.1/32")
	_, serviceIPv4CIDR2, _ := net.ParseCIDR("10.96.0.0/28")
	_, serviceIPv6CIDR1, _ := net.ParseCIDR("fd00:1234:5678:dead:beaf::1/128")
	_, serviceIPv6CIDR2, _ := net.ParseCIDR("fd00:1234:5678:dead:beaf::/124")
	nodeConfig := &config.NodeConfig{GatewayConfig: &config.GatewayConfig{LinkIndex: 10}}
	tests := []struct {
		name               string
		curServiceIPv4CIDR *net.IPNet
		curServiceIPv6CIDR *net.IPNet
		newServiceIPv4CIDR *net.IPNet
		newServiceIPv6CIDR *net.IPNet
		expectedCalls      func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
	}{
		{
			name:               "Add route for Service IPv4 CIDR",
			curServiceIPv4CIDR: nil,
			newServiceIPv4CIDR: serviceIPv4CIDR1,
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteReplace(&netlink.Route{
					Dst:       &net.IPNet{IP: net.ParseIP("10.96.0.1").To4(), Mask: net.CIDRMask(32, 32)},
					Gw:        config.VirtualServiceIPv4,
					Scope:     netlink.SCOPE_UNIVERSE,
					LinkIndex: 10,
				})
				mockNetlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{LinkIndex: 10}, netlink.RT_FILTER_OIF).Return([]netlink.Route{
					{Dst: ip.MustParseCIDR("10.96.0.0/24"), Gw: config.VirtualServiceIPv4},
				}, nil)
				mockNetlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{LinkIndex: 10}, netlink.RT_FILTER_OIF).Return([]netlink.Route{}, nil)
				mockNetlink.RouteDel(&netlink.Route{
					Dst: ip.MustParseCIDR("10.96.0.0/24"), Gw: config.VirtualServiceIPv4,
				})
			},
		},
		{
			name:               "Add route for Service IPv4 CIDR and clean up stale routes",
			curServiceIPv4CIDR: nil,
			newServiceIPv4CIDR: ip.MustParseCIDR("10.96.0.0/28"),
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteReplace(&netlink.Route{
					Dst:       &net.IPNet{IP: net.ParseIP("10.96.0.0").To4(), Mask: net.CIDRMask(28, 32)},
					Gw:        config.VirtualServiceIPv4,
					Scope:     netlink.SCOPE_UNIVERSE,
					LinkIndex: 10,
				})
				mockNetlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{LinkIndex: 10}, netlink.RT_FILTER_OIF).Return([]netlink.Route{
					{Dst: ip.MustParseCIDR("10.96.0.0/24"), Gw: config.VirtualServiceIPv4},
					{Dst: ip.MustParseCIDR("10.96.0.0/30"), Gw: config.VirtualServiceIPv4},
				}, nil)
				mockNetlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{LinkIndex: 10}, netlink.RT_FILTER_OIF).Return([]netlink.Route{}, nil)
				mockNetlink.RouteDel(&netlink.Route{
					Dst: ip.MustParseCIDR("10.96.0.0/24"), Gw: config.VirtualServiceIPv4,
				})
				mockNetlink.RouteDel(&netlink.Route{
					Dst: ip.MustParseCIDR("10.96.0.0/30"), Gw: config.VirtualServiceIPv4,
				})
			},
		},
		{
			name:               "Update route for Service IPv4 CIDR",
			curServiceIPv4CIDR: serviceIPv4CIDR1,
			newServiceIPv4CIDR: serviceIPv4CIDR2,
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteReplace(&netlink.Route{
					Dst:       &net.IPNet{IP: net.ParseIP("10.96.0.0").To4(), Mask: net.CIDRMask(28, 32)},
					Gw:        config.VirtualServiceIPv4,
					Scope:     netlink.SCOPE_UNIVERSE,
					LinkIndex: 10,
				})
				mockNetlink.RouteDel(&netlink.Route{
					Dst:       &net.IPNet{IP: net.ParseIP("10.96.0.1").To4(), Mask: net.CIDRMask(32, 32)},
					Gw:        config.VirtualServiceIPv4,
					Scope:     netlink.SCOPE_UNIVERSE,
					LinkIndex: 10,
				})
			},
		},
		{
			name:               "Add route for Service IPv6 CIDR",
			curServiceIPv6CIDR: nil,
			newServiceIPv6CIDR: serviceIPv6CIDR1,
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteReplace(&netlink.Route{
					Dst:       &net.IPNet{IP: net.ParseIP("fd00:1234:5678:dead:beaf::1"), Mask: net.CIDRMask(128, 128)},
					Gw:        config.VirtualServiceIPv6,
					Scope:     netlink.SCOPE_UNIVERSE,
					LinkIndex: 10,
				})
				mockNetlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{LinkIndex: 10}, netlink.RT_FILTER_OIF).Return([]netlink.Route{}, nil)
				mockNetlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{LinkIndex: 10}, netlink.RT_FILTER_OIF).Return([]netlink.Route{
					{Dst: ip.MustParseCIDR("fd00:1234:5678:dead:beaf::/80"), Gw: config.VirtualServiceIPv6},
				}, nil)
				mockNetlink.RouteDel(&netlink.Route{
					Dst: ip.MustParseCIDR("fd00:1234:5678:dead:beaf::/80"), Gw: config.VirtualServiceIPv6,
				})
			},
		},
		{
			name:               "Update route for Service IPv6 CIDR",
			curServiceIPv6CIDR: serviceIPv6CIDR1,
			newServiceIPv6CIDR: serviceIPv6CIDR2,
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteReplace(&netlink.Route{
					Dst:       &net.IPNet{IP: net.ParseIP("fd00:1234:5678:dead:beaf::"), Mask: net.CIDRMask(124, 128)},
					Gw:        config.VirtualServiceIPv6,
					Scope:     netlink.SCOPE_UNIVERSE,
					LinkIndex: 10,
				})
				mockNetlink.RouteDel(&netlink.Route{
					Dst:       &net.IPNet{IP: net.ParseIP("fd00:1234:5678:dead:beaf::1"), Mask: net.CIDRMask(128, 128)},
					Gw:        config.VirtualServiceIPv6,
					Scope:     netlink.SCOPE_UNIVERSE,
					LinkIndex: 10,
				})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockNetlink := netlinktest.NewMockInterface(ctrl)
			c := &Client{
				netlink:    mockNetlink,
				nodeConfig: nodeConfig,
			}
			tt.expectedCalls(mockNetlink.EXPECT())

			if tt.curServiceIPv4CIDR != nil {
				c.serviceRoutes.Store(serviceIPv4CIDRKey, &netlink.Route{
					Dst:       &net.IPNet{IP: net.ParseIP("10.96.0.1").To4(), Mask: net.CIDRMask(32, 32)},
					Gw:        config.VirtualServiceIPv4,
					Scope:     netlink.SCOPE_UNIVERSE,
					LinkIndex: 10,
				})
			}
			if tt.curServiceIPv6CIDR != nil {
				c.serviceRoutes.Store(serviceIPv6CIDRKey, &netlink.Route{
					Dst:       &net.IPNet{IP: net.ParseIP("fd00:1234:5678:dead:beaf::1"), Mask: net.CIDRMask(128, 128)},
					Gw:        config.VirtualServiceIPv6,
					Scope:     netlink.SCOPE_UNIVERSE,
					LinkIndex: 10,
				})
			}

			if tt.newServiceIPv4CIDR != nil {
				assert.NoError(t, c.addServiceCIDRRoute(tt.newServiceIPv4CIDR))
			}
			if tt.newServiceIPv6CIDR != nil {
				assert.NoError(t, c.addServiceCIDRRoute(tt.newServiceIPv6CIDR))
			}
		})
	}
}

func TestAddExternalIPRoute(t *testing.T) {
	tests := []struct {
		name          string
		externalIPs   []string
		serviceRoutes map[string]*netlink.Route
		expectedCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
	}{
		{
			name: "IPv4",
			serviceRoutes: map[string]*netlink.Route{
				externalIPv4Addr1: ipv4Route1,
				externalIPv4Addr2: ipv4Route2,
			},
			externalIPs: []string{externalIPv4Addr1, externalIPv4Addr2},
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteReplace(ipv4Route1)
				mockNetlink.RouteReplace(ipv4Route2)
			},
		},
		{
			name: "IPv6",
			serviceRoutes: map[string]*netlink.Route{
				externalIPv6Addr1: ipv6Route1,
				externalIPv6Addr2: ipv6Route2,
			},
			externalIPs: []string{externalIPv6Addr1, externalIPv6Addr2},
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteReplace(ipv6Route1)
				mockNetlink.RouteReplace(ipv6Route2)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockNetlink := netlinktest.NewMockInterface(ctrl)
			c := &Client{
				netlink:    mockNetlink,
				nodeConfig: nodeConfig,
			}
			tt.expectedCalls(mockNetlink.EXPECT())

			for _, externalIP := range tt.externalIPs {
				assert.NoError(t, c.AddExternalIPRoute(net.ParseIP(externalIP)))
			}
		})
	}
}

func TestDeleteExternalIPRoute(t *testing.T) {
	tests := []struct {
		name          string
		serviceRoutes map[string]*netlink.Route
		externalIPs   []string
		expectedCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
	}{
		{
			name: "IPv4",
			serviceRoutes: map[string]*netlink.Route{
				externalIPv4Addr1: ipv4Route1,
				externalIPv4Addr2: ipv4Route2,
			},
			externalIPs: []string{externalIPv4Addr1, externalIPv4Addr2},
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteDel(ipv4Route1)
				mockNetlink.RouteDel(ipv4Route2)
			},
		},
		{
			name: "IPv6",
			serviceRoutes: map[string]*netlink.Route{
				externalIPv6Addr1: ipv6Route1,
				externalIPv6Addr2: ipv6Route2,
			},
			externalIPs: []string{externalIPv6Addr1, externalIPv6Addr2},
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteDel(ipv6Route1)
				mockNetlink.RouteDel(ipv6Route2)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockNetlink := netlinktest.NewMockInterface(ctrl)
			c := &Client{
				netlink:       mockNetlink,
				nodeConfig:    nodeConfig,
				serviceRoutes: sync.Map{},
			}
			for ipStr, route := range tt.serviceRoutes {
				c.serviceRoutes.Store(ipStr, route)
			}
			tt.expectedCalls(mockNetlink.EXPECT())

			for _, externalIP := range tt.externalIPs {
				assert.NoError(t, c.DeleteExternalIPRoute(net.ParseIP(externalIP)))
			}
		})
	}
}

func TestAddLocalAntreaFlexibleIPAMPodRule(t *testing.T) {
	tests := []struct {
		name                  string
		nodeConfig            *config.NodeConfig
		connectUplinkToBridge bool
		podAddresses          []net.IP
		expectedCalls         func(mockIPSet *ipsettest.MockInterfaceMockRecorder)
	}{
		{
			name: "connectUplinkToBridge=false",
			nodeConfig: &config.NodeConfig{
				PodIPv4CIDR: ip.MustParseCIDR("1.1.1.0/24"),
				PodIPv6CIDR: ip.MustParseCIDR("aabb::/64"),
			},
			connectUplinkToBridge: false,
			podAddresses:          []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("aabb::1")},
			expectedCalls:         func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {},
		},
		{
			name: "connectUplinkToBridge=true,nodeIPAMPod",
			nodeConfig: &config.NodeConfig{
				PodIPv4CIDR: ip.MustParseCIDR("1.1.1.0/24"),
				PodIPv6CIDR: ip.MustParseCIDR("aabb::/64"),
			},
			connectUplinkToBridge: false,
			podAddresses:          []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("aabb::1")},
			expectedCalls:         func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {},
		},
		{
			name: "connectUplinkToBridge=true,antreaIPAMPod",
			nodeConfig: &config.NodeConfig{
				PodIPv4CIDR: ip.MustParseCIDR("1.1.1.0/24"),
				PodIPv6CIDR: ip.MustParseCIDR("aabb::/64"),
			},
			connectUplinkToBridge: true,
			podAddresses:          []net.IP{net.ParseIP("1.1.2.1"), net.ParseIP("aabc::1")},
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.AddEntry(localAntreaFlexibleIPAMPodIPSet, "1.1.2.1")
				mockIPSet.AddEntry(localAntreaFlexibleIPAMPodIP6Set, "aabc::1")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPSet := ipsettest.NewMockInterface(ctrl)
			c := &Client{
				ipset:                 mockIPSet,
				nodeConfig:            tt.nodeConfig,
				connectUplinkToBridge: tt.connectUplinkToBridge,
			}
			tt.expectedCalls(mockIPSet.EXPECT())

			assert.NoError(t, c.AddLocalAntreaFlexibleIPAMPodRule(tt.podAddresses))
		})
	}
}

func TestDeleteLocalAntreaFlexibleIPAMPodRule(t *testing.T) {
	nodeConfig := &config.NodeConfig{GatewayConfig: &config.GatewayConfig{LinkIndex: 10}}
	tests := []struct {
		name                  string
		connectUplinkToBridge bool
		podAddresses          []net.IP
		expectedCalls         func(mockIPSet *ipsettest.MockInterfaceMockRecorder)
	}{
		{
			name:                  "connectUplinkToBridge=false",
			connectUplinkToBridge: false,
			podAddresses:          []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("aabb::1")},
			expectedCalls:         func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {},
		},
		{
			name:                  "connectUplinkToBridge=true",
			connectUplinkToBridge: true,
			podAddresses:          []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("aabb::1")},
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.DelEntry(localAntreaFlexibleIPAMPodIPSet, "1.1.1.1")
				mockIPSet.DelEntry(localAntreaFlexibleIPAMPodIP6Set, "aabb::1")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPSet := ipsettest.NewMockInterface(ctrl)
			c := &Client{
				ipset:                 mockIPSet,
				nodeConfig:            nodeConfig,
				connectUplinkToBridge: tt.connectUplinkToBridge,
			}
			tt.expectedCalls(mockIPSet.EXPECT())

			assert.NoError(t, c.DeleteLocalAntreaFlexibleIPAMPodRule(tt.podAddresses))
		})
	}
}

func TestAddAndDeleteNodeIP(t *testing.T) {
	tests := []struct {
		name             string
		multicastEnabled bool
		networkConfig    *config.NetworkConfig
		podCIDR          *net.IPNet
		nodeIP           net.IP
		expectedCalls    func(mockIPSet *ipsettest.MockInterfaceMockRecorder)
	}{
		{
			name:             "IPv4",
			multicastEnabled: true,
			networkConfig:    &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap},
			podCIDR:          ip.MustParseCIDR("192.168.0.0/24"),
			nodeIP:           net.ParseIP("1.1.1.1"),
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.AddEntry(clusterNodeIPSet, "1.1.1.1")
				mockIPSet.DelEntry(clusterNodeIPSet, "1.1.1.1")
			},
		},
		{
			name:             "IPv6",
			multicastEnabled: true,
			networkConfig:    &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap},
			podCIDR:          ip.MustParseCIDR("1122:3344::/80"),
			nodeIP:           net.ParseIP("aabb:ccdd::1"),
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.AddEntry(clusterNodeIP6Set, "aabb:ccdd::1")
				mockIPSet.DelEntry(clusterNodeIP6Set, "aabb:ccdd::1")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPSet := ipsettest.NewMockInterface(ctrl)
			c := &Client{
				ipset:            mockIPSet,
				networkConfig:    tt.networkConfig,
				multicastEnabled: tt.multicastEnabled,
			}
			tt.expectedCalls(mockIPSet.EXPECT())

			ipv6 := tt.nodeIP.To4() == nil
			assert.NoError(t, c.addNodeIP(tt.podCIDR, tt.nodeIP))
			var exists bool
			if ipv6 {
				_, exists = c.clusterNodeIP6s.Load(tt.podCIDR.String())
			} else {
				_, exists = c.clusterNodeIPs.Load(tt.podCIDR.String())
			}
			assert.True(t, exists)

			assert.NoError(t, c.deleteNodeIP(tt.podCIDR))
			if ipv6 {
				_, exists = c.clusterNodeIP6s.Load(tt.podCIDR.String())
			} else {
				_, exists = c.clusterNodeIPs.Load(tt.podCIDR.String())
			}
			assert.False(t, exists)
		})
	}
}

func TestEgressRoutes(t *testing.T) {
	tests := []struct {
		name          string
		tableID       uint32
		dev           int
		gateway       net.IP
		prefixLength  int
		expectedCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
	}{
		{
			name:         "IPv4",
			tableID:      101,
			dev:          10,
			gateway:      net.ParseIP("1.1.1.1"),
			prefixLength: 24,
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteReplace(&netlink.Route{Dst: ip.MustParseCIDR("1.1.1.0/24"), Scope: netlink.SCOPE_LINK, LinkIndex: 10, Table: 101})
				mockNetlink.RouteReplace(&netlink.Route{Gw: net.ParseIP("1.1.1.1"), LinkIndex: 10, Table: 101})

				mockNetlink.RouteDel(&netlink.Route{Dst: ip.MustParseCIDR("1.1.1.0/24"), Scope: netlink.SCOPE_LINK, LinkIndex: 10, Table: 101})
				mockNetlink.RouteDel(&netlink.Route{Gw: net.ParseIP("1.1.1.1"), LinkIndex: 10, Table: 101})
			},
		},
		{
			name:         "IPv6",
			tableID:      102,
			dev:          11,
			gateway:      net.ParseIP("1122:3344::5566"),
			prefixLength: 80,
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				mockNetlink.RouteReplace(&netlink.Route{Dst: ip.MustParseCIDR("1122:3344::/80"), Scope: netlink.SCOPE_LINK, LinkIndex: 11, Table: 102})
				mockNetlink.RouteReplace(&netlink.Route{Gw: net.ParseIP("1122:3344::5566"), LinkIndex: 11, Table: 102})

				mockNetlink.RouteDel(&netlink.Route{Dst: ip.MustParseCIDR("1122:3344::/80"), Scope: netlink.SCOPE_LINK, LinkIndex: 11, Table: 102})
				mockNetlink.RouteDel(&netlink.Route{Gw: net.ParseIP("1122:3344::5566"), LinkIndex: 11, Table: 102})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockNetlink := netlinktest.NewMockInterface(ctrl)
			c := &Client{
				netlink:    mockNetlink,
				nodeConfig: nodeConfig,
			}
			tt.expectedCalls(mockNetlink.EXPECT())

			assert.NoError(t, c.AddEgressRoutes(tt.tableID, tt.dev, tt.gateway, tt.prefixLength))
			assert.NoError(t, c.DeleteEgressRoutes(tt.tableID))
			c.egressRoutes.Range(func(key, value any) bool {
				t.Errorf("The egressRoutes should be empty but contains %v:%v", key, value)
				return true
			})
		})
	}
}

func TestEgressRule(t *testing.T) {
	tests := []struct {
		name          string
		tableID       uint32
		mark          uint32
		expectedCalls func(mockNetlink *netlinktest.MockInterfaceMockRecorder)
	}{
		{
			name:    "normal",
			tableID: 101,
			mark:    1,
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				rule := netlink.NewRule()
				rule.Table = 101
				rule.Mark = 1
				rule.Mask = int(types.SNATIPMarkMask)
				mockNetlink.RuleAdd(rule)
				mockNetlink.RuleDel(rule)
			},
		},
		{
			name:    "not found",
			tableID: 101,
			mark:    1,
			expectedCalls: func(mockNetlink *netlinktest.MockInterfaceMockRecorder) {
				rule := netlink.NewRule()
				rule.Table = 101
				rule.Mark = 1
				rule.Mask = int(types.SNATIPMarkMask)
				mockNetlink.RuleAdd(rule)
				mockNetlink.RuleDel(rule).Return(fmt.Errorf("no such process"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockNetlink := netlinktest.NewMockInterface(ctrl)
			c := &Client{
				netlink:    mockNetlink,
				nodeConfig: nodeConfig,
			}
			tt.expectedCalls(mockNetlink.EXPECT())

			assert.NoError(t, c.AddEgressRule(tt.tableID, tt.mark))
			assert.NoError(t, c.DeleteEgressRule(tt.tableID, tt.mark))
		})
	}
}

func TestAddAndDeleteNodeNetworkPolicyIPSet(t *testing.T) {
	ipv4SetName := "TEST-IPSET-4"
	ipv4Net1 := "1.1.1.1/32"
	ipv4Net2 := "2.2.2.2/32"
	ipv4Net3 := "3.3.3.3/32"
	ipv6SetName := "TEST-IPSET-6"
	ipv6Net1 := "fec0::1111/128"
	ipv6Net2 := "fec0::2222/128"
	ipv6Net3 := "fec0::3333/128"

	tests := []struct {
		name             string
		ipsetName        string
		prevIPSetEntries sets.Set[string]
		curIPSetEntries  sets.Set[string]
		isIPv6           bool
		expectedCalls    func(mockIPSet *ipsettest.MockInterfaceMockRecorder)
	}{
		{
			name:            "IPv4, add an ipset and delete it",
			ipsetName:       ipv4SetName,
			curIPSetEntries: sets.New[string](ipv4Net1, ipv4Net3),
			isIPv6:          false,
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.CreateIPSet(ipv4SetName, ipset.HashNet, false).Times(1)
				mockIPSet.AddEntry(ipv4SetName, ipv4Net1).Times(1)
				mockIPSet.AddEntry(ipv4SetName, ipv4Net3).Times(1)
				mockIPSet.DestroyIPSet(ipv4SetName).Times(1)
			},
		},
		{
			name:             "IPv4, update an ipset and delete it",
			ipsetName:        ipv4SetName,
			prevIPSetEntries: sets.New[string](ipv4Net1, ipv4Net2),
			curIPSetEntries:  sets.New[string](ipv4Net1, ipv4Net3),
			isIPv6:           false,
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.CreateIPSet(ipv4SetName, ipset.HashNet, false).Times(1)
				mockIPSet.AddEntry(ipv4SetName, ipv4Net3).Times(1)
				mockIPSet.DelEntry(ipv4SetName, ipv4Net2).Times(1)
				mockIPSet.DestroyIPSet(ipv4SetName).Times(1)
			},
		},
		{
			name:            "IPv6, add an ipset and delete it",
			ipsetName:       ipv6SetName,
			curIPSetEntries: sets.New[string](ipv6Net1, ipv6Net3),
			isIPv6:          true,
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.CreateIPSet(ipv6SetName, ipset.HashNet, true).Times(1)
				mockIPSet.AddEntry(ipv6SetName, ipv6Net1).Times(1)
				mockIPSet.AddEntry(ipv6SetName, ipv6Net3).Times(1)
				mockIPSet.DestroyIPSet(ipv6SetName).Times(1)
			},
		},
		{
			name:             "IPv6, update an ipset and delete it",
			ipsetName:        ipv6SetName,
			prevIPSetEntries: sets.New[string](ipv6Net1, ipv6Net2),
			curIPSetEntries:  sets.New[string](ipv6Net1, ipv6Net3),
			isIPv6:           true,
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.CreateIPSet(ipv6SetName, ipset.HashNet, true).Times(1)
				mockIPSet.AddEntry(ipv6SetName, ipv6Net3).Times(1)
				mockIPSet.DelEntry(ipv6SetName, ipv6Net2).Times(1)
				mockIPSet.DestroyIPSet(ipv6SetName).Times(1)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPSet := ipsettest.NewMockInterface(ctrl)
			c := &Client{ipset: mockIPSet}
			tt.expectedCalls(mockIPSet.EXPECT())

			if tt.prevIPSetEntries != nil {
				if tt.isIPv6 {
					c.nodeNetworkPolicyIPSetsIPv6.Store(tt.ipsetName, tt.prevIPSetEntries)
				} else {
					c.nodeNetworkPolicyIPSetsIPv4.Store(tt.ipsetName, tt.prevIPSetEntries)
				}
			}

			assert.NoError(t, c.AddOrUpdateNodeNetworkPolicyIPSet(tt.ipsetName, tt.curIPSetEntries, tt.isIPv6))
			var exists bool
			if tt.isIPv6 {
				_, exists = c.nodeNetworkPolicyIPSetsIPv6.Load(tt.ipsetName)
			} else {
				_, exists = c.nodeNetworkPolicyIPSetsIPv4.Load(tt.ipsetName)
			}
			assert.True(t, exists)

			assert.NoError(t, c.DeleteNodeNetworkPolicyIPSet(tt.ipsetName, tt.isIPv6))
			if tt.isIPv6 {
				_, exists = c.nodeNetworkPolicyIPSetsIPv6.Load(tt.ipsetName)
			} else {
				_, exists = c.nodeNetworkPolicyIPSetsIPv4.Load(tt.ipsetName)
			}
			assert.False(t, exists)
		})
	}
}

func TestAddAndDeleteNodeNetworkPolicyIPTables(t *testing.T) {
	ingressChain := config.NodeNetworkPolicyIngressRulesChain
	ingressRules := []string{
		"-A ANTREA-POL-INGRESS-RULES -p tcp --dport 80 -j ACCEPT",
	}
	svcChain := "ANTREA-POL-12619C0214FB0845"
	svcRules := []string{
		"-A ANTREA-POL-12619C0214FB0845 -p tcp --dport 80 -j ACCEPT",
		"-A ANTREA-POL-12619C0214FB0845 -p tcp --dport 443 -j ACCEPT",
	}

	tests := []struct {
		name          string
		isIPv6        bool
		expectedCalls func(mockIPTables *iptablestest.MockInterfaceMockRecorder)
		expectedRules map[string][]string
	}{
		{
			name:   "IPv4",
			isIPv6: false,
			expectedCalls: func(mockIPTables *iptablestest.MockInterfaceMockRecorder) {
				mockIPTables.Restore(`*filter
:ANTREA-POL-INGRESS-RULES - [0:0]
-A ANTREA-POL-INGRESS-RULES -p tcp --dport 80 -j ACCEPT
COMMIT
`, false, false)
				mockIPTables.Restore(`*filter
:ANTREA-POL-12619C0214FB0845 - [0:0]
-A ANTREA-POL-12619C0214FB0845 -p tcp --dport 80 -j ACCEPT
-A ANTREA-POL-12619C0214FB0845 -p tcp --dport 443 -j ACCEPT
COMMIT
`, false, false)
				mockIPTables.DeleteChain(iptables.ProtocolIPv4, iptables.FilterTable, svcChain).Times(1)
				mockIPTables.Restore(`*filter
:ANTREA-POL-INGRESS-RULES - [0:0]
COMMIT
`, false, false)
			},
		},

		{
			name:   "IPv6",
			isIPv6: true,
			expectedCalls: func(mockIPTables *iptablestest.MockInterfaceMockRecorder) {
				mockIPTables.Restore(`*filter
:ANTREA-POL-INGRESS-RULES - [0:0]
-A ANTREA-POL-INGRESS-RULES -p tcp --dport 80 -j ACCEPT
COMMIT
`, false, true)
				mockIPTables.Restore(`*filter
:ANTREA-POL-12619C0214FB0845 - [0:0]
-A ANTREA-POL-12619C0214FB0845 -p tcp --dport 80 -j ACCEPT
-A ANTREA-POL-12619C0214FB0845 -p tcp --dport 443 -j ACCEPT
COMMIT
`, false, true)
				mockIPTables.DeleteChain(iptables.ProtocolIPv6, iptables.FilterTable, svcChain).Times(1)
				mockIPTables.Restore(`*filter
:ANTREA-POL-INGRESS-RULES - [0:0]
COMMIT
`, false, true)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPTables := iptablestest.NewMockInterface(ctrl)
			c := &Client{iptables: mockIPTables,
				networkConfig: &config.NetworkConfig{
					IPv4Enabled: true,
					IPv6Enabled: true,
				},
			}
			c.initNodeNetworkPolicy()

			tt.expectedCalls(mockIPTables.EXPECT())

			assert.NoError(t, c.AddOrUpdateNodeNetworkPolicyIPTables([]string{ingressChain}, [][]string{ingressRules}, tt.isIPv6))
			var gotRules any
			var exists bool
			if tt.isIPv6 {
				gotRules, exists = c.nodeNetworkPolicyIPTablesIPv6.Load(ingressChain)
			} else {
				gotRules, exists = c.nodeNetworkPolicyIPTablesIPv4.Load(ingressChain)
			}
			assert.True(t, exists)
			assert.EqualValues(t, ingressRules, gotRules)

			assert.NoError(t, c.AddOrUpdateNodeNetworkPolicyIPTables([]string{svcChain}, [][]string{svcRules}, tt.isIPv6))
			if tt.isIPv6 {
				gotRules, exists = c.nodeNetworkPolicyIPTablesIPv6.Load(svcChain)
			} else {
				gotRules, exists = c.nodeNetworkPolicyIPTablesIPv4.Load(svcChain)
			}
			assert.True(t, exists)
			assert.EqualValues(t, svcRules, gotRules)

			assert.NoError(t, c.DeleteNodeNetworkPolicyIPTables([]string{svcChain}, tt.isIPv6))
			if tt.isIPv6 {
				_, exists = c.nodeNetworkPolicyIPTablesIPv6.Load(svcChain)
			} else {
				_, exists = c.nodeNetworkPolicyIPTablesIPv4.Load(svcChain)
			}
			assert.False(t, exists)

			assert.NoError(t, c.AddOrUpdateNodeNetworkPolicyIPTables([]string{ingressChain}, [][]string{nil}, tt.isIPv6))
			if tt.isIPv6 {
				gotRules, exists = c.nodeNetworkPolicyIPTablesIPv6.Load(ingressChain)
			} else {
				gotRules, exists = c.nodeNetworkPolicyIPTablesIPv4.Load(ingressChain)
			}
			assert.True(t, exists)
			assert.EqualValues(t, []string(nil), gotRules)
		})
	}
}
