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
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/util/ipset"
	ipsettest "antrea.io/antrea/v2/pkg/agent/util/ipset/testing"
	"antrea.io/antrea/v2/pkg/agent/util/iptables"
	iptablestest "antrea.io/antrea/v2/pkg/agent/util/iptables/testing"
	"antrea.io/antrea/v2/pkg/util/ip"
)

var egressL2DispatchNodeConfig = &config.NodeConfig{
	GatewayConfig:              &config.GatewayConfig{Name: "antrea-gw0"},
	NodeTransportInterfaceName: "eth0",
	PodIPv4CIDR:                ip.MustParseCIDR("10.10.0.0/24"),
	PodIPv6CIDR:                ip.MustParseCIDR("fd00:10:10::/64"),
}

const (
	// snatMark10 and snatMark11 are the iptables marks of the SNAT IPs with the IDs 10 and 11.
	snatMark10 = "0x0000000a/0x000000ff"
	snatMark11 = "0x0000000b/0x000000ff"
)

// egressL2DispatchMocks are the recorders of the mocks which the Egress rules use.
type egressL2DispatchMocks struct {
	iptables *iptablestest.MockInterfaceMockRecorder
	ipset    *ipsettest.MockInterfaceMockRecorder
}

func mangleRuleSpec(ipsetName, podIPSet, mark string) []string {
	return []string{
		"-m", "comment", "--comment", "Antrea: mark Egress packets from remote Pods",
		"-i", "eth0",
		"-m", "set", "--match-set", ipsetName, "src",
		"-m", "set", "!", "--match-set", podIPSet, "dst",
		"-m", "addrtype", "!", "--dst-type", "LOCAL",
		"-j", "MARK", "--set-xmark", mark,
	}
}

func natSNATRuleSpec(snatIP, mark string) []string {
	return []string{
		"-m", "comment", "--comment", "Antrea: SNAT Pod to external packets",
		"!", "-o", "antrea-gw0",
		"-m", "mark", "--mark", mark,
		"-j", iptables.SNATTarget, "--to", snatIP,
	}
}

func TestAddSNATRuleWithEgressL2Dispatch(t *testing.T) {
	tests := []struct {
		name             string
		snatIP           string
		mark             uint32
		egressL2Dispatch bool
		expectedCalls    func(m egressL2DispatchMocks)
	}{
		{
			name:             "IPv4",
			snatIP:           "1.1.1.1",
			mark:             10,
			egressL2Dispatch: true,
			expectedCalls: func(m egressL2DispatchMocks) {
				m.iptables.InsertRule(iptables.ProtocolIPv4, iptables.NATTable, antreaPostRoutingChain,
					natSNATRuleSpec("1.1.1.1", snatMark10))
				m.ipset.CreateIPSet("ANTREA-EGRESS-POD-IP-10", ipset.HashIP, false)
				m.ipset.ListEntries("ANTREA-EGRESS-POD-IP-10")
				m.iptables.InsertRule(iptables.ProtocolIPv4, iptables.MangleTable, antreaPreRoutingChain,
					mangleRuleSpec("ANTREA-EGRESS-POD-IP-10", "ANTREA-POD-IP", snatMark10))
			},
		},
		{
			name:             "IPv6",
			snatIP:           "fd00::1",
			mark:             11,
			egressL2Dispatch: true,
			expectedCalls: func(m egressL2DispatchMocks) {
				m.iptables.InsertRule(iptables.ProtocolIPv6, iptables.NATTable, antreaPostRoutingChain,
					natSNATRuleSpec("fd00::1", snatMark11))
				m.ipset.CreateIPSet("ANTREA-EGRESS-POD-IP6-11", ipset.HashIP, true)
				m.ipset.ListEntries("ANTREA-EGRESS-POD-IP6-11")
				m.iptables.InsertRule(iptables.ProtocolIPv6, iptables.MangleTable, antreaPreRoutingChain,
					mangleRuleSpec("ANTREA-EGRESS-POD-IP6-11", "ANTREA-POD-IP6", snatMark11))
			},
		},
		{
			// The ipset of the mark may remain from a previous agent, with the Pods of another Egress IP.
			name:             "stale entries",
			snatIP:           "1.1.1.1",
			mark:             10,
			egressL2Dispatch: true,
			expectedCalls: func(m egressL2DispatchMocks) {
				m.iptables.InsertRule(iptables.ProtocolIPv4, iptables.NATTable, antreaPostRoutingChain,
					natSNATRuleSpec("1.1.1.1", snatMark10))
				m.ipset.CreateIPSet("ANTREA-EGRESS-POD-IP-10", ipset.HashIP, false)
				m.ipset.ListEntries("ANTREA-EGRESS-POD-IP-10").Return([]string{"10.10.1.5", "10.10.2.5"}, nil)
				m.ipset.DelEntry("ANTREA-EGRESS-POD-IP-10", "10.10.1.5")
				m.ipset.DelEntry("ANTREA-EGRESS-POD-IP-10", "10.10.2.5")
				m.iptables.InsertRule(iptables.ProtocolIPv4, iptables.MangleTable, antreaPreRoutingChain,
					mangleRuleSpec("ANTREA-EGRESS-POD-IP-10", "ANTREA-POD-IP", snatMark10))
			},
		},
		{
			name:   "tunnel dispatch",
			snatIP: "1.1.1.1",
			mark:   10,
			expectedCalls: func(m egressL2DispatchMocks) {
				m.iptables.InsertRule(iptables.ProtocolIPv4, iptables.NATTable, antreaPostRoutingChain,
					natSNATRuleSpec("1.1.1.1", snatMark10))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPTables := iptablestest.NewMockInterface(ctrl)
			mockIPSet := ipsettest.NewMockInterface(ctrl)
			c := &Client{
				iptables:         mockIPTables,
				ipset:            mockIPSet,
				nodeConfig:       egressL2DispatchNodeConfig,
				egressL2Dispatch: tt.egressL2Dispatch,
			}
			tt.expectedCalls(egressL2DispatchMocks{iptables: mockIPTables.EXPECT(), ipset: mockIPSet.EXPECT()})
			require.NoError(t, c.AddSNATRule(net.ParseIP(tt.snatIP), tt.mark))
			// The SNAT rule can be added again, for example when the Egress IP is realized again after an error.
			mockIPTables.EXPECT().InsertRule(gomock.Any(), iptables.NATTable, antreaPostRoutingChain, gomock.Any())
			require.NoError(t, c.AddSNATRule(net.ParseIP(tt.snatIP), tt.mark))
			if tt.egressL2Dispatch {
				expectedIPSet := &egressRemotePodIPSet{isIPv6: net.ParseIP(tt.snatIP).To4() == nil, podIPs: sets.New[string]()}
				assert.Equal(t, map[uint32]*egressRemotePodIPSet{tt.mark: expectedIPSet}, c.egressRemotePodIPSets)
			} else {
				assert.Empty(t, c.egressRemotePodIPSets)
			}
		})
	}
}

func TestDeleteSNATRuleWithEgressL2Dispatch(t *testing.T) {
	tests := []struct {
		name          string
		destroyErr    error
		expectedStale sets.Set[string]
	}{
		{
			name: "ipset destroyed",
		},
		{
			// For example, an iptables sync added the mangle rule again. The periodic sync destroys the ipset later.
			name:          "ipset in use",
			destroyErr:    fmt.Errorf("set cannot be destroyed: it is in use by a kernel component"),
			expectedStale: sets.New("ANTREA-EGRESS-POD-IP-10"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPTables := iptablestest.NewMockInterface(ctrl)
			mockIPSet := ipsettest.NewMockInterface(ctrl)
			c := &Client{
				iptables:         mockIPTables,
				ipset:            mockIPSet,
				nodeConfig:       egressL2DispatchNodeConfig,
				egressL2Dispatch: true,
				egressRemotePodIPSets: map[uint32]*egressRemotePodIPSet{
					10: {podIPs: sets.New("10.10.1.5")},
					11: {podIPs: sets.New("10.10.1.6")},
				},
			}
			c.markToSNATIP.Store(uint32(10), net.ParseIP("1.1.1.1"))
			c.markToSNATIP.Store(uint32(11), net.ParseIP("1.1.1.2"))
			// The mangle rule is deleted before the ipset, which cannot be destroyed while a rule uses it.
			gomock.InOrder(
				mockIPTables.EXPECT().DeleteRule(iptables.ProtocolIPv4, iptables.MangleTable, antreaPreRoutingChain,
					mangleRuleSpec("ANTREA-EGRESS-POD-IP-10", "ANTREA-POD-IP", snatMark10)),
				mockIPSet.EXPECT().DestroyIPSet("ANTREA-EGRESS-POD-IP-10").Return(tt.destroyErr),
			)
			mockIPTables.EXPECT().DeleteRule(iptables.ProtocolIPv4, iptables.NATTable, antreaPostRoutingChain,
				natSNATRuleSpec("1.1.1.1", snatMark10))
			require.NoError(t, c.DeleteSNATRule(10))
			assert.Equal(t, map[uint32]*egressRemotePodIPSet{11: {podIPs: sets.New("10.10.1.6")}}, c.egressRemotePodIPSets)
			assert.Equal(t, tt.expectedStale, c.staleEgressRemotePodIPSets)
			_, exists := c.markToSNATIP.Load(uint32(10))
			assert.False(t, exists)
		})
	}
}

func TestSetEgressRemotePodIPs(t *testing.T) {
	tests := []struct {
		name           string
		existingIPs    sets.Set[string]
		podIPs         sets.Set[string]
		mark           uint32
		expectedCalls  func(mockIPSet *ipsettest.MockInterfaceMockRecorder)
		expectedErr    string
		expectedPodIPs sets.Set[string]
	}{
		{
			name:        "add and remove IPs",
			existingIPs: sets.New("10.10.1.5", "10.10.1.6"),
			podIPs:      sets.New("10.10.1.6", "10.10.2.7"),
			mark:        10,
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.AddEntry("ANTREA-EGRESS-POD-IP-10", "10.10.2.7")
				mockIPSet.DelEntry("ANTREA-EGRESS-POD-IP-10", "10.10.1.5")
			},
			expectedPodIPs: sets.New("10.10.1.6", "10.10.2.7"),
		},
		{
			name:           "no change",
			existingIPs:    sets.New("10.10.1.5"),
			podIPs:         sets.New("10.10.1.5"),
			mark:           10,
			expectedCalls:  func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {},
			expectedPodIPs: sets.New("10.10.1.5"),
		},
		{
			name:        "failure to add an IP",
			existingIPs: sets.New[string](),
			podIPs:      sets.New("10.10.1.5"),
			mark:        10,
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.AddEntry("ANTREA-EGRESS-POD-IP-10", "10.10.1.5").Return(fmt.Errorf("ipset error"))
			},
			expectedErr:    "ipset error",
			expectedPodIPs: sets.New[string](),
		},
		{
			name:          "no ipset for the mark",
			existingIPs:   sets.New[string](),
			podIPs:        sets.New("10.10.1.5"),
			mark:          11,
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {},
			expectedErr:   "the Egress IP with mark 0xb has no ipset for remote Pods",
			// The ipset of mark 10 is unchanged.
			expectedPodIPs: sets.New[string](),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPSet := ipsettest.NewMockInterface(ctrl)
			c := &Client{
				ipset:                 mockIPSet,
				egressL2Dispatch:      true,
				egressRemotePodIPSets: map[uint32]*egressRemotePodIPSet{10: {podIPs: tt.existingIPs}},
			}
			tt.expectedCalls(mockIPSet.EXPECT())
			err := c.SetEgressRemotePodIPs(tt.mark, tt.podIPs)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedPodIPs, c.egressRemotePodIPSets[10].podIPs)
		})
	}
}

func TestSyncIPSetWithEgressL2Dispatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockIPSet := ipsettest.NewMockInterface(ctrl)
	c := &Client{
		ipset:            mockIPSet,
		networkConfig:    &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeNoEncap, IPv4Enabled: true},
		nodeConfig:       egressL2DispatchNodeConfig,
		egressL2Dispatch: true,
		egressRemotePodIPSets: map[uint32]*egressRemotePodIPSet{
			10: {podIPs: sets.New("10.10.1.5")},
			11: {isIPv6: true, podIPs: sets.New("fd00:10:11::5")},
		},
	}
	mockIPSet.EXPECT().CreateIPSet(antreaPodIPSet, ipset.HashNet, false)
	mockIPSet.EXPECT().CreateIPSet(antreaPodIP6Set, ipset.HashNet, true)
	mockIPSet.EXPECT().AddEntry(antreaPodIPSet, "10.10.0.0/24")
	mockIPSet.EXPECT().AddEntry(antreaPodIP6Set, "fd00:10:10::/64")
	// The ipsets of the Egress IPs and their entries are restored.
	mockIPSet.EXPECT().CreateIPSet("ANTREA-EGRESS-POD-IP-10", ipset.HashIP, false)
	mockIPSet.EXPECT().AddEntry("ANTREA-EGRESS-POD-IP-10", "10.10.1.5")
	mockIPSet.EXPECT().CreateIPSet("ANTREA-EGRESS-POD-IP6-11", ipset.HashIP, true)
	mockIPSet.EXPECT().AddEntry("ANTREA-EGRESS-POD-IP6-11", "fd00:10:11::5")
	assert.NoError(t, c.syncIPSet())
}

func TestStaleEgressRemotePodIPSets(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockIPSet := ipsettest.NewMockInterface(ctrl)
	c := &Client{
		ipset:                 mockIPSet,
		egressRemotePodIPSets: map[uint32]*egressRemotePodIPSet{3: {podIPs: sets.New[string]()}},
	}
	mockIPSet.EXPECT().Save().Return([]byte(strings.Join([]string{
		"create ANTREA-POD-IP hash:net family inet hashsize 1024 maxelem 65536",
		"add ANTREA-POD-IP 10.10.0.0/24",
		"create ANTREA-EGRESS-POD-IP-3 hash:ip family inet hashsize 1024 maxelem 65536",
		"create ANTREA-EGRESS-POD-IP-4 hash:ip family inet hashsize 1024 maxelem 65536",
		"add ANTREA-EGRESS-POD-IP-4 10.10.1.5",
		"create ANTREA-EGRESS-POD-IP6-5 hash:ip family inet6 hashsize 1024 maxelem 65536",
		"",
	}, "\n")), nil)
	require.NoError(t, c.findStaleEgressRemotePodIPSets())
	// The ipset of mark 3 is in use, and ANTREA-POD-IP is not an ipset of an Egress IP.
	assert.Equal(t, sets.New("ANTREA-EGRESS-POD-IP-4", "ANTREA-EGRESS-POD-IP6-5"), c.staleEgressRemotePodIPSets)

	mockIPSet.EXPECT().DestroyIPSet("ANTREA-EGRESS-POD-IP-4")
	mockIPSet.EXPECT().DestroyIPSet("ANTREA-EGRESS-POD-IP6-5").Return(fmt.Errorf("set is in use"))
	c.destroyStaleEgressRemotePodIPSets()
	assert.Equal(t, sets.New("ANTREA-EGRESS-POD-IP6-5"), c.staleEgressRemotePodIPSets)

	// An ipset which is used again is no longer stale.
	mockIPSet.EXPECT().CreateIPSet("ANTREA-EGRESS-POD-IP6-5", ipset.HashIP, true)
	mockIPSet.EXPECT().ListEntries("ANTREA-EGRESS-POD-IP6-5")
	mockIPTables := iptablestest.NewMockInterface(ctrl)
	c.iptables = mockIPTables
	c.nodeConfig = egressL2DispatchNodeConfig
	mockIPTables.EXPECT().InsertRule(iptables.ProtocolIPv6, iptables.MangleTable, antreaPreRoutingChain, gomock.Any())
	require.NoError(t, c.addEgressRemotePodIPSet(5, true))
	assert.Empty(t, c.staleEgressRemotePodIPSets)
	c.destroyStaleEgressRemotePodIPSets()
}

// iptablesTableLines returns the lines of each table in iptables-restore data.
func iptablesTableLines(data string) map[string][]string {
	lines := map[string][]string{}
	var table string
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "*") {
			table = strings.TrimPrefix(line, "*")
			continue
		}
		lines[table] = append(lines[table], line)
	}
	return lines
}

func TestRestoreIptablesDataWithEgressL2Dispatch(t *testing.T) {
	ipv4Rules := map[string][]string{
		iptables.MangleTable: {
			`-A ANTREA-PREROUTING -m comment --comment "Antrea: mark Egress packets from remote Pods" -i eth0 ` +
				`-m set --match-set ANTREA-EGRESS-POD-IP-1 src -m set ! --match-set ANTREA-POD-IP dst ` +
				`-m addrtype ! --dst-type LOCAL -j MARK --set-xmark 0x00000001/0x000000ff`,
			`-A ANTREA-PREROUTING -m comment --comment "Antrea: mark Egress packets from remote Pods" -i eth0 ` +
				`-m set --match-set ANTREA-EGRESS-POD-IP-3 src -m set ! --match-set ANTREA-POD-IP dst ` +
				`-m addrtype ! --dst-type LOCAL -j MARK --set-xmark 0x00000003/0x000000ff`,
		},
		iptables.FilterTable: {
			`-A ANTREA-FORWARD -m comment --comment "Antrea: accept Egress packets from remote Pods" -i eth0 ` +
				`-m mark ! --mark 0x00000000/0x000000ff -j ACCEPT`,
			`-A ANTREA-FORWARD -m comment --comment "Antrea: accept reply packets of Egress connections from remote Pods" ` +
				`-o eth0 -m conntrack --ctstate SNAT -m conntrack --ctdir REPLY -j ACCEPT`,
		},
		iptables.NATTable: {
			`-A ANTREA-POSTROUTING ` +
				`-m comment --comment "Antrea: masquerade Egress packets from remote Pods without an Egress IP" ` +
				`-m set --match-set ANTREA-POD-IP src -m set ! --match-set ANTREA-POD-IP dst ! -o antrea-gw0 -j MASQUERADE`,
		},
	}
	ipv6Rules := map[string][]string{
		iptables.MangleTable: {
			`-A ANTREA-PREROUTING -m comment --comment "Antrea: mark Egress packets from remote Pods" -i eth0 ` +
				`-m set --match-set ANTREA-EGRESS-POD-IP6-2 src -m set ! --match-set ANTREA-POD-IP6 dst ` +
				`-m addrtype ! --dst-type LOCAL -j MARK --set-xmark 0x00000002/0x000000ff`,
		},
		iptables.FilterTable: ipv4Rules[iptables.FilterTable],
		iptables.NATTable: {
			`-A ANTREA-POSTROUTING ` +
				`-m comment --comment "Antrea: masquerade Egress packets from remote Pods without an Egress IP" ` +
				`-m set --match-set ANTREA-POD-IP6 src -m set ! --match-set ANTREA-POD-IP6 dst ! -o antrea-gw0 -j MASQUERADE`,
		},
	}
	tests := []struct {
		name             string
		egressL2Dispatch bool
		noSNAT           bool
		isIPv6           bool
		expectedRules    map[string][]string
		unexpectedRules  map[string][]string
	}{
		{
			name:             "IPv4",
			egressL2Dispatch: true,
			expectedRules:    ipv4Rules,
		},
		{
			name:             "IPv6",
			egressL2Dispatch: true,
			isIPv6:           true,
			expectedRules:    ipv6Rules,
		},
		{
			name:             "noSNAT",
			egressL2Dispatch: true,
			noSNAT:           true,
			expectedRules: map[string][]string{
				iptables.MangleTable: ipv4Rules[iptables.MangleTable],
				iptables.FilterTable: ipv4Rules[iptables.FilterTable],
			},
			unexpectedRules: map[string][]string{iptables.NATTable: ipv4Rules[iptables.NATTable]},
		},
		{
			name:            "tunnel dispatch",
			unexpectedRules: ipv4Rules,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			networkConfig := &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeNoEncap,
				IPv4Enabled:      true,
				IPv6Enabled:      true,
				EnableEgress:     true,
			}
			if tt.egressL2Dispatch {
				networkConfig.EgressDispatch = config.EgressDispatchL2
				networkConfig.EnableL2Dispatch = true
			}
			c := &Client{
				networkConfig:     networkConfig,
				nodeConfig:        egressL2DispatchNodeConfig,
				noSNAT:            tt.noSNAT,
				egressEnabled:     true,
				l2DispatchEnabled: networkConfig.SupportsL2Dispatch(),
				egressL2Dispatch:  networkConfig.UsesEgressL2Dispatch(),
				egressRemotePodIPSets: map[uint32]*egressRemotePodIPSet{
					3: {podIPs: sets.New[string]()},
					1: {podIPs: sets.New[string]()},
					2: {isIPv6: true, podIPs: sets.New[string]()},
				},
			}
			podCIDR, podIPSet := egressL2DispatchNodeConfig.PodIPv4CIDR, antreaPodIPSet
			snatMarkToIP := map[uint32]net.IP{1: net.ParseIP("1.1.1.1"), 3: net.ParseIP("1.1.1.3")}
			if tt.isIPv6 {
				podCIDR, podIPSet = egressL2DispatchNodeConfig.PodIPv6CIDR, antreaPodIP6Set
				snatMarkToIP = map[uint32]net.IP{2: net.ParseIP("fd00::2")}
			}
			data := c.restoreIptablesData(podCIDR, podIPSet, localAntreaFlexibleIPAMPodIPSet, antreaNodePortIPSet,
				antreaExternalIPIPSet, clusterNodeIPSet, config.VirtualNodePortDNATIPv4, config.VirtualServiceIPv4, snatMarkToIP,
				map[string][]string{}, tt.isIPv6).String()
			lines := iptablesTableLines(data)
			for table, rules := range tt.expectedRules {
				for _, rule := range rules {
					assert.Contains(t, lines[table], rule, "Table %s", table)
				}
			}
			for table, rules := range tt.unexpectedRules {
				for _, rule := range rules {
					assert.NotContains(t, lines[table], rule, "Table %s", table)
				}
			}
			if tt.egressL2Dispatch && !tt.noSNAT {
				// The Egress SNAT rules and the default masquerade rule of the local Pods come first.
				natRules := lines[iptables.NATTable]
				fallback := slices.Index(natRules, tt.expectedRules[iptables.NATTable][0])
				for i, rule := range natRules {
					if strings.Contains(rule, "Antrea: SNAT Pod to external packets") ||
						strings.Contains(rule, "Antrea: masquerade Pod to external packets") {
						assert.Less(t, i, fallback, "Rule %s must come before the fallback masquerade rule", rule)
					}
				}
			}
		})
	}
}
