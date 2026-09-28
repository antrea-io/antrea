// Copyright 2026 Antrea Authors
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
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"go.uber.org/mock/gomock"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/agent/util/ipset"
	ipsettest "antrea.io/antrea/v2/pkg/agent/util/ipset/testing"
	netlinktest "antrea.io/antrea/v2/pkg/agent/util/netlink/testing"
	"antrea.io/antrea/v2/pkg/util/ip"
)

const l2DispatchTestLinkIndex = 7

func newL2DispatchTestClient(mockNetlink *netlinktest.MockInterface, enabled bool) *Client {
	c := &Client{
		netlink: mockNetlink,
		networkConfig: &config.NetworkConfig{
			TrafficEncapMode: config.TrafficEncapModeNoEncap,
			IPv4Enabled:      true,
			IPv6Enabled:      true,
			EnableL2Dispatch: enabled,
		},
		nodeConfig: &config.NodeConfig{NodeTransportInterfaceName: "eth0"},
	}
	c.l2DispatchEnabled = c.networkConfig.SupportsL2Dispatch()
	c.l2DispatchLinkIndex = l2DispatchTestLinkIndex
	return c
}

func l2DispatchTestRule(family, priority int, mark, mask uint32, table int) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Family = family
	rule.Priority = priority
	rule.Mark = mark
	rule.Mask = ptr.To(mask)
	rule.Table = table
	return rule
}

func l2DispatchTestRoute(gw string, table int) *netlink.Route {
	return &netlink.Route{LinkIndex: l2DispatchTestLinkIndex, Gw: net.ParseIP(gw), Table: table, Flags: int(netlink.FLAG_ONLINK)}
}

func TestL2DispatchSharedRules(t *testing.T) {
	c := newL2DispatchTestClient(nil, true)
	rules := c.l2DispatchSharedRules()
	require.Len(t, rules, 6, "a guard, a no-op and a drop rule for each IP family")
	for _, rule := range rules[:3] {
		assert.Equal(t, netlink.FAMILY_V4, rule.Family)
		assert.Equal(t, uint32(0x20000000), rule.Mark)
		assert.Equal(t, uint32(0x20000000), *rule.Mask)
	}
	guard, anchor, drop := rules[0], rules[1], rules[2]
	assert.Equal(t, 32000, guard.Priority)
	assert.Equal(t, 40000, guard.Goto, "the guard rule jumps over the main table to the peer rules")
	assert.Equal(t, 40000, anchor.Priority)
	assert.Equal(t, uint8(unix.FR_ACT_NOP), anchor.Type)
	assert.Equal(t, 40001, drop.Priority)
	assert.Equal(t, uint8(unix.FR_ACT_BLACKHOLE), drop.Type)
	assert.Equal(t, netlink.FAMILY_V6, rules[3].Family)
}

func TestInitL2Dispatch(t *testing.T) {
	c := newL2DispatchTestClient(nil, true)
	shared := c.l2DispatchSharedRules()
	peerRule := l2DispatchTestRule(netlink.FAMILY_V4, 40000, 0x20030000, 0x2fff0000, 1004)
	egressRule := l2DispatchTestRule(netlink.FAMILY_V4, 32765, 1, 0xff, 101)
	foreignRule := l2DispatchTestRule(netlink.FAMILY_V4, 40000, 0x20000000, 0xffffffff, 200)
	peerRoute := l2DispatchTestRoute("192.168.77.103", 1004)
	gatewayRoute := &netlink.Route{LinkIndex: l2DispatchTestLinkIndex, Gw: net.ParseIP("192.168.77.200"), Table: 1500}
	foreignRoute := l2DispatchTestRoute("192.168.77.201", 200)

	t.Run("enabled installs the missing shared rules and keeps the peer routing", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockNetlink := netlinktest.NewMockInterface(ctrl)
		c := newL2DispatchTestClient(mockNetlink, true)
		c.l2DispatchLinkIndex = 0
		mockNetlink.EXPECT().RuleList(netlink.FAMILY_ALL).Return([]netlink.Rule{*shared[0], *peerRule, *egressRule}, nil)
		mockNetlink.EXPECT().LinkByName("eth0").Return(&netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: l2DispatchTestLinkIndex}}, nil)
		for _, rule := range shared[1:] {
			mockNetlink.EXPECT().RuleAdd(rule)
		}
		require.NoError(t, c.initL2Dispatch())
		assert.Equal(t, l2DispatchTestLinkIndex, c.l2DispatchLinkIndex)
	})

	t.Run("disabled removes only the rules and routes of the l2 dispatch", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockNetlink := netlinktest.NewMockInterface(ctrl)
		c := newL2DispatchTestClient(mockNetlink, false)
		mockNetlink.EXPECT().RuleList(netlink.FAMILY_ALL).Return([]netlink.Rule{*shared[0], *shared[1], *shared[2], *peerRule, *egressRule, *foreignRule}, nil)
		for _, rule := range []*netlink.Rule{shared[0], shared[1], shared[2], peerRule} {
			mockNetlink.EXPECT().RuleDel(rule)
		}
		mockNetlink.EXPECT().LinkByName("eth0").Return(&netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: l2DispatchTestLinkIndex}}, nil)
		mockNetlink.EXPECT().RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{LinkIndex: l2DispatchTestLinkIndex}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF).
			Return([]netlink.Route{*peerRoute, *gatewayRoute, *foreignRoute}, nil)
		mockNetlink.EXPECT().RouteDel(peerRoute).Return(unix.ESRCH)
		require.NoError(t, c.initL2Dispatch())
	})

	t.Run("disabled does nothing more when no rule of the l2 dispatch exists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockNetlink := netlinktest.NewMockInterface(ctrl)
		c := newL2DispatchTestClient(mockNetlink, false)
		mockNetlink.EXPECT().RuleList(netlink.FAMILY_ALL).Return([]netlink.Rule{*egressRule, *foreignRule}, nil)
		require.NoError(t, c.initL2Dispatch())
	})
}

func TestAddL2DispatchPeerRoutes(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockNetlink := netlinktest.NewMockInterface(ctrl)
	c := newL2DispatchTestClient(mockNetlink, true)

	routeV4 := l2DispatchTestRoute("192.168.77.103", 1004)
	routeV6 := l2DispatchTestRoute("fd00:77::103", 1004)
	ruleV4 := l2DispatchTestRule(netlink.FAMILY_V4, 40000, 0x20030000, 0x2fff0000, 1004)
	ruleV6 := l2DispatchTestRule(netlink.FAMILY_V6, 40000, 0x20030000, 0x2fff0000, 1004)
	gomock.InOrder(
		mockNetlink.EXPECT().RouteReplace(routeV4),
		mockNetlink.EXPECT().RouteReplace(routeV6),
		mockNetlink.EXPECT().RuleAdd(ruleV4),
		mockNetlink.EXPECT().RuleAdd(ruleV6),
	)
	require.NoError(t, c.AddL2DispatchPeerRoutes(3, &ip.DualStackIPs{IPv4: net.ParseIP("192.168.77.103"), IPv6: net.ParseIP("fd00:77::103")}))

	// The peer Node loses its IPv6 address and changes its IPv4 address: the IPv6 routing goes, the IPv4 route is
	// replaced, and the IPv4 rule, which does not depend on the address, already exists.
	newRouteV4 := l2DispatchTestRoute("192.168.77.104", 1004)
	gomock.InOrder(
		mockNetlink.EXPECT().RuleDel(ruleV6),
		mockNetlink.EXPECT().RouteDel(routeV6),
		mockNetlink.EXPECT().RouteReplace(newRouteV4),
		mockNetlink.EXPECT().RuleAdd(ruleV4).Return(unix.EEXIST),
	)
	require.NoError(t, c.AddL2DispatchPeerRoutes(3, &ip.DualStackIPs{IPv4: net.ParseIP("192.168.77.104")}))
	value, ok := c.l2DispatchPeers.Load(uint32(3))
	require.True(t, ok)
	assert.Equal(t, &l2DispatchPeerRouting{routes: []*netlink.Route{newRouteV4}, rules: []*netlink.Rule{ruleV4}}, value)

	assert.ErrorContains(t, c.AddL2DispatchPeerRoutes(0, &ip.DualStackIPs{IPv4: net.ParseIP("192.168.77.103")}), "out of the range [1, 4095]")
	assert.ErrorContains(t, c.AddL2DispatchPeerRoutes(4096, &ip.DualStackIPs{IPv4: net.ParseIP("192.168.77.103")}), "out of the range [1, 4095]")
	assert.ErrorContains(t, c.AddL2DispatchPeerRoutes(5, &ip.DualStackIPs{}), "no transport IP of an enabled IP family")
	disabled := newL2DispatchTestClient(mockNetlink, false)
	assert.ErrorContains(t, disabled.AddL2DispatchPeerRoutes(5, &ip.DualStackIPs{IPv4: net.ParseIP("192.168.77.105")}), "not enabled")
}

func TestDeleteL2DispatchPeerRoutes(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockNetlink := netlinktest.NewMockInterface(ctrl)
	c := newL2DispatchTestClient(mockNetlink, true)
	c.l2DispatchPeers.Store(uint32(3), &l2DispatchPeerRouting{})

	route := l2DispatchTestRoute("192.168.77.103", 1004)
	mockNetlink.EXPECT().RuleDel(l2DispatchTestRule(netlink.FAMILY_V4, 40000, 0x20030000, 0x2fff0000, 1004))
	mockNetlink.EXPECT().RuleDel(l2DispatchTestRule(netlink.FAMILY_V6, 40000, 0x20030000, 0x2fff0000, 1004)).Return(unix.ENOENT)
	mockNetlink.EXPECT().RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: 1004}, netlink.RT_FILTER_TABLE).Return([]netlink.Route{*route}, nil)
	mockNetlink.EXPECT().RouteDel(route)
	require.NoError(t, c.DeleteL2DispatchPeerRoutes(3))
	_, cached := c.l2DispatchPeers.Load(uint32(3))
	assert.False(t, cached)

	mockNetlink.EXPECT().RuleDel(gomock.Any()).Return(unix.EPERM)
	assert.ErrorContains(t, c.DeleteL2DispatchPeerRoutes(3), "failed to delete ip rule")
}

func TestListL2DispatchPeers(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockNetlink := netlinktest.NewMockInterface(ctrl)
	c := newL2DispatchTestClient(mockNetlink, true)

	_, defaultDst, _ := net.ParseCIDR("0.0.0.0/0")
	_, subnetDst, _ := net.ParseCIDR("192.168.77.0/24")
	defaultRouteWithDst := l2DispatchTestRoute("192.168.77.105", 1006)
	defaultRouteWithDst.Dst = defaultDst
	subnetRoute := l2DispatchTestRoute("192.168.77.107", 1008)
	subnetRoute.Dst = subnetDst
	notOnlink := l2DispatchTestRoute("192.168.77.108", 1009)
	notOnlink.Flags = 0
	otherLink := l2DispatchTestRoute("192.168.77.110", 1011)
	otherLink.LinkIndex = 8
	mockNetlink.EXPECT().RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{LinkIndex: l2DispatchTestLinkIndex}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF).Return([]netlink.Route{
		*l2DispatchTestRoute("192.168.77.103", 1004),
		*l2DispatchTestRoute("fd00:77::103", 1004),
		*defaultRouteWithDst,
		*subnetRoute,
		*notOnlink,
		*otherLink,
		*l2DispatchTestRoute("192.168.77.1", 1001),
		*l2DispatchTestRoute("192.168.77.1", 5097),
		*l2DispatchTestRoute("192.168.77.1", 254),
	}, nil)
	mockNetlink.EXPECT().RuleList(netlink.FAMILY_ALL).Return([]netlink.Rule{
		*l2DispatchTestRule(netlink.FAMILY_V4, 40000, 0x20030000, 0x2fff0000, 1004),
		*l2DispatchTestRule(netlink.FAMILY_V4, 40000, 0x20090000, 0x2fff0000, 1010),
		*l2DispatchTestRule(netlink.FAMILY_V4, 40000, 0x200a0000, 0x2fff0000, 1004),
		*l2DispatchTestRule(netlink.FAMILY_V4, 40000, 0x200b0000, 0xffffffff, 1012),
		*l2DispatchTestRule(netlink.FAMILY_V4, 40000, 0x20000000, 0x20000000, 0),
	}, nil)

	peers, err := c.ListL2DispatchPeers()
	require.NoError(t, err)
	assert.Equal(t, map[uint32]*ip.DualStackIPs{
		3: {IPv4: net.ParseIP("192.168.77.103"), IPv6: net.ParseIP("fd00:77::103")},
		5: {IPv4: net.ParseIP("192.168.77.105")},
		// A rule without a route is reported, so that it is kept or removed with its index.
		9: {},
	}, peers)
}

func TestSyncL2DispatchRules(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockNetlink := netlinktest.NewMockInterface(ctrl)
	c := newL2DispatchTestClient(mockNetlink, true)
	c.networkConfig.IPv6Enabled = false
	shared := c.l2DispatchSharedRules()
	peerRule := l2DispatchTestRule(netlink.FAMILY_V4, 40000, 0x20030000, 0x2fff0000, 1004)
	c.l2DispatchPeers.Store(uint32(3), &l2DispatchPeerRouting{rules: []*netlink.Rule{peerRule}})

	// The kernel does not report the action of a rule, so the listed rules carry no type.
	listedAnchor := *shared[1]
	listedAnchor.Type = 0
	mockNetlink.EXPECT().RuleList(netlink.FAMILY_ALL).Return([]netlink.Rule{*shared[0], listedAnchor}, nil)
	mockNetlink.EXPECT().RuleAdd(shared[2])
	mockNetlink.EXPECT().RuleAdd(peerRule)
	require.NoError(t, c.syncIPRule())
}

func TestIsL2DispatchRule(t *testing.T) {
	guard := l2DispatchTestRule(netlink.FAMILY_V4, 32000, 0x20000000, 0x20000000, 0)
	guard.Goto = 40000
	tests := []struct {
		name     string
		rule     *netlink.Rule
		expected bool
	}{
		{name: "guard rule", rule: guard, expected: true},
		{name: "no-op rule", rule: l2DispatchTestRule(netlink.FAMILY_V4, 40000, 0x20000000, 0x20000000, 0), expected: true},
		{name: "drop rule", rule: l2DispatchTestRule(netlink.FAMILY_V6, 40001, 0x20000000, 0x20000000, 0), expected: true},
		{name: "peer rule", rule: l2DispatchTestRule(netlink.FAMILY_V4, 40000, 0x20030000, 0x2fff0000, 1004), expected: true},
		{name: "peer rule with the table of another index", rule: l2DispatchTestRule(netlink.FAMILY_V4, 40000, 0x20030000, 0x2fff0000, 1005), expected: false},
		{name: "peer rule with index 0", rule: l2DispatchTestRule(netlink.FAMILY_V4, 40000, 0x20000000, 0x2fff0000, 1001), expected: false},
		{name: "rule with the mark and a full mask", rule: l2DispatchTestRule(netlink.FAMILY_V4, 40000, 0x20000000, 0xffffffff, 200), expected: false},
		{name: "guard priority without goto", rule: l2DispatchTestRule(netlink.FAMILY_V4, 32000, 0x20000000, 0x20000000, 0), expected: false},
		{name: "Egress rule", rule: l2DispatchTestRule(netlink.FAMILY_V4, 32765, 1, types.SNATIPMarkMask, 101), expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isL2DispatchRule(tt.rule))
		})
	}
}

func TestNeedsLooseRPFilterOnGateway(t *testing.T) {
	dsr := func(mode config.TrafficEncapModeType, l2 bool) *config.NetworkConfig {
		return &config.NetworkConfig{TrafficEncapMode: mode, EnableDSR: true, EnableDSRL2Dispatch: l2, EnableL2Dispatch: l2}
	}
	tests := []struct {
		name          string
		networkConfig *config.NetworkConfig
		egressEnabled bool
		expected      bool
	}{
		{name: "DSR, l2 dispatch, noEncap", networkConfig: dsr(config.TrafficEncapModeNoEncap, true), expected: true},
		{name: "DSR, l2 dispatch, hybrid", networkConfig: dsr(config.TrafficEncapModeHybrid, true), expected: true},
		{name: "DSR without the l2 dispatch", networkConfig: dsr(config.TrafficEncapModeNoEncap, false), expected: false},
		{name: "DSR in encap mode", networkConfig: dsr(config.TrafficEncapModeEncap, true), expected: false},
		{
			name:          "Egress in noEncap mode",
			networkConfig: &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeNoEncap},
			egressEnabled: true,
			expected:      true,
		},
		{
			name:          "Egress in encap mode",
			networkConfig: &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap},
			egressEnabled: true,
			expected:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{networkConfig: tt.networkConfig, egressEnabled: tt.egressEnabled}
			assert.Equal(t, tt.expected, c.needsLooseRPFilterOnGateway())
		})
	}
}

func newDSRL2DispatchTestClient(ipsetClient ipset.Interface, dsrL2Dispatch bool) *Client {
	return &Client{
		ipset: ipsetClient,
		networkConfig: &config.NetworkConfig{
			TrafficEncapMode:    config.TrafficEncapModeNoEncap,
			IPv4Enabled:         true,
			EnableDSR:           true,
			EnableDSRL2Dispatch: dsrL2Dispatch,
			EnableL2Dispatch:    dsrL2Dispatch,
		},
		nodeConfig: &config.NodeConfig{
			NodeTransportInterfaceName: "eth0",
			PodIPv4CIDR:                ip.MustParseCIDR("172.16.10.0/24"),
			PodIPv6CIDR:                ip.MustParseCIDR("2001:ab03:cd04:55ef::/64"),
			GatewayConfig:              &config.GatewayConfig{Name: "antrea-gw0"},
		},
		proxyAll:               true,
		iptablesHasRandomFully: true,
	}
}

func TestDSRL2DispatchMangleRule(t *testing.T) {
	rule := `-A ANTREA-PREROUTING -m comment --comment "Antrea: mark DSR packets dispatched by peer Nodes" -i eth0 ` +
		`-m set --match-set ANTREA-DSR-PEER-NODE-MAC src -m set --match-set ANTREA-EXTERNAL-IP dst ` +
		`-j MARK --set-xmark 0x10000000/0x10000000`
	tests := []struct {
		name          string
		dsrL2Dispatch bool
		isIPv6        bool
		expectedRule  bool
	}{
		{name: "DSR l2 dispatch", dsrL2Dispatch: true, expectedRule: true},
		{name: "DSR l2 dispatch, IPv6, which DSR does not support", dsrL2Dispatch: true, isIPv6: true},
		{name: "no DSR l2 dispatch", dsrL2Dispatch: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newDSRL2DispatchTestClient(nil, tt.dsrL2Dispatch)
			podCIDR, externalIPSet := c.nodeConfig.PodIPv4CIDR, antreaExternalIPIPSet
			if tt.isIPv6 {
				podCIDR, externalIPSet = c.nodeConfig.PodIPv6CIDR, antreaExternalIPIP6Set
			}
			data := c.restoreIptablesData(podCIDR, antreaPodIPSet, localAntreaFlexibleIPAMPodIPSet, antreaNodePortIPSet,
				externalIPSet, clusterNodeIPSet, config.VirtualNodePortDNATIPv4, config.VirtualServiceIPv4,
				map[uint32]net.IP{}, map[string][]string{}, tt.isIPv6).String()
			// The rule belongs to the mangle table.
			mangle := data[strings.Index(data, "*mangle"):strings.Index(data, "*filter")]
			if tt.expectedRule {
				assert.Contains(t, mangle, rule+"\n")
			} else {
				assert.NotContains(t, data, "ANTREA-DSR-PEER-NODE-MAC")
			}
		})
	}
}

func TestSyncDSRPeerNodeMACIPSet(t *testing.T) {
	tests := []struct {
		name          string
		dsrL2Dispatch bool
		cachedMACs    []string
		expectedCalls func(mockIPSet *ipsettest.MockInterfaceMockRecorder)
	}{
		{
			name:          "DSR l2 dispatch",
			dsrL2Dispatch: true,
			cachedMACs:    []string{"0a:00:00:00:00:02"},
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.CreateIPSet(antreaDSRPeerNodeMACIPSet, ipset.HashMAC, false)
				mockIPSet.AddEntry(antreaDSRPeerNodeMACIPSet, "0a:00:00:00:00:02")
			},
		},
		{
			name:          "no DSR l2 dispatch",
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPSet := ipsettest.NewMockInterface(ctrl)
			c := newDSRL2DispatchTestClient(mockIPSet, tt.dsrL2Dispatch)
			for _, mac := range tt.cachedMACs {
				c.dsrPeerNodeMACs.Store(mac, struct{}{})
			}
			// The ipsets of the Pod CIDRs are not the subject of this test.
			mockIPSet.EXPECT().CreateIPSet(antreaPodIPSet, ipset.HashNet, false)
			mockIPSet.EXPECT().CreateIPSet(antreaPodIP6Set, ipset.HashNet, true)
			mockIPSet.EXPECT().AddEntry(antreaPodIPSet, "172.16.10.0/24")
			mockIPSet.EXPECT().AddEntry(antreaPodIP6Set, "2001:ab03:cd04:55ef::/64")
			tt.expectedCalls(mockIPSet.EXPECT())
			assert.NoError(t, c.syncIPSet())
		})
	}
}

func TestDSRPeerNodeMACs(t *testing.T) {
	mac1, _ := net.ParseMAC("0a:00:00:00:00:02")
	mac2, _ := net.ParseMAC("0a:00:00:00:00:03")

	t.Run("add and delete", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockIPSet := ipsettest.NewMockInterface(ctrl)
		c := newDSRL2DispatchTestClient(mockIPSet, true)
		mockIPSet.EXPECT().AddEntry(antreaDSRPeerNodeMACIPSet, "0a:00:00:00:00:02")
		require.NoError(t, c.AddDSRPeerNodeMAC(mac1))
		_, cached := c.dsrPeerNodeMACs.Load("0a:00:00:00:00:02")
		assert.True(t, cached, "the periodic sync restores the MAC address")
		mockIPSet.EXPECT().DelEntry(antreaDSRPeerNodeMACIPSet, "0a:00:00:00:00:02")
		require.NoError(t, c.DeleteDSRPeerNodeMAC(mac1))
		_, cached = c.dsrPeerNodeMACs.Load("0a:00:00:00:00:02")
		assert.False(t, cached)
	})

	t.Run("add without the DSR l2 dispatch", func(t *testing.T) {
		c := newDSRL2DispatchTestClient(nil, false)
		assert.Error(t, c.AddDSRPeerNodeMAC(mac1))
		assert.NoError(t, c.DeleteDSRPeerNodeMAC(mac1))
	})

	t.Run("reconcile deletes the MAC addresses of Nodes which are gone", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockIPSet := ipsettest.NewMockInterface(ctrl)
		c := newDSRL2DispatchTestClient(mockIPSet, true)
		// ipset lists the MAC addresses in uppercase.
		mockIPSet.EXPECT().ListEntries(antreaDSRPeerNodeMACIPSet).
			Return([]string{"0A:00:00:00:00:02", "0A:00:00:00:00:04"}, nil)
		mockIPSet.EXPECT().DelEntry(antreaDSRPeerNodeMACIPSet, "0A:00:00:00:00:04")
		require.NoError(t, c.ReconcileDSRPeerNodeMACs(sets.New[string](mac1.String(), mac2.String())))
	})
}

func TestDeleteStaleDSRPeerNodeMACIPSet(t *testing.T) {
	tests := []struct {
		name            string
		dsrL2Dispatch   bool
		expectedDestroy bool
	}{
		{name: "the DSR l2 dispatch is disabled", expectedDestroy: true},
		{name: "the DSR l2 dispatch is enabled", dsrL2Dispatch: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPSet := ipsettest.NewMockInterface(ctrl)
			c := newDSRL2DispatchTestClient(mockIPSet, tt.dsrL2Dispatch)
			if tt.expectedDestroy {
				mockIPSet.EXPECT().DestroyIPSet(antreaDSRPeerNodeMACIPSet)
			}
			assert.NoError(t, c.deleteStaleDSRPeerNodeMACIPSet())
		})
	}
}
