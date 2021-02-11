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
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/nettest"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/route"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/agent/util/ipset"
	"github.com/vmware-tanzu/antrea/pkg/agent/util/iptables"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
)

func ExecOutputTrim(cmd string) (string, error) {
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return "", err
	}
	return strings.Join(strings.Fields(string(out)), ""), nil
}

var (
	_, podCIDR, _       = net.ParseCIDR("10.10.10.0/24")
	nodeIP, nodeIntf, _ = util.GetIPNetDeviceFromIP(func() net.IP {
		conn, _ := net.Dial("udp", "8.8.8.8:80")
		defer conn.Close()
		return conn.LocalAddr().(*net.UDPAddr).IP
	}())
	nodeLink, _       = netlink.LinkByName(nodeIntf.Name)
	localPeerIP       = ip.NextIP(nodeIP.IP)
	remotePeerIP      = net.ParseIP("50.50.50.1")
	_, serviceCIDR, _ = net.ParseCIDR("200.200.0.0/16")
	gwIP              = net.ParseIP("10.10.10.1")
	gwMAC, _          = net.ParseMAC("12:34:56:78:bb:cc")
	gwName            = "antrea-gw0"
	gwConfig          = &config.GatewayConfig{IPv4: gwIP, MAC: gwMAC, Name: gwName}
	nodeConfig        = &config.NodeConfig{
		Name:          "test",
		PodIPv4CIDR:   podCIDR,
		NodeIPAddr:    nodeIP,
		GatewayConfig: gwConfig,
	}
)

func createDummyGW(t *testing.T) netlink.Link {
	// create dummy gw interface
	gwLink := &netlink.Dummy{}
	gwLink.Name = gwName
	assert.NoError(t, netlink.LinkAdd(gwLink))
	link, _ := netlink.LinkByName(gwLink.Name)
	assert.NoError(t, netlink.LinkSetUp(link))
	nodeConfig.GatewayConfig.LinkIndex = link.Attrs().Index
	nodeConfig.GatewayConfig.Name = gwLink.Attrs().Name
	return link
}

func skipIfNotInContainer(t *testing.T) {
	if _, incontainer := os.LookupEnv("INCONTAINER"); !incontainer {
		// test changes file system, routing table. Run in contain only
		t.Skipf("Skipping test which is run only in container")
	}
}

func TestInitialize(t *testing.T) {
	skipIfNotInContainer(t)

	link := createDummyGW(t)
	defer netlink.LinkDel(link)

	tcs := []struct {
		// variations
		networkConfig        *config.NetworkConfig
		noSNAT               bool
		xtablesHoldDuration  time.Duration
		expectNoTrackRules   bool
		expectUDPPortInRules int
	}{
		{
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeNoEncap,
			},
			expectNoTrackRules: false,
		},
		{
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeHybrid,
				TunnelType:       ovsconfig.GeneveTunnel,
			},
			noSNAT:               true,
			expectNoTrackRules:   true,
			expectUDPPortInRules: 6081,
		},
		{
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeEncap,
				TunnelType:       ovsconfig.VXLANTunnel,
			},
			expectNoTrackRules:   true,
			expectUDPPortInRules: 4789,
		},
		{
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeNoEncap,
			},
			xtablesHoldDuration: 5 * time.Second,
			expectNoTrackRules:  false,
		},
	}

	for _, tc := range tcs {
		t.Logf("Running Initialize test with mode %s node config %s", tc.networkConfig.TrafficEncapMode, nodeConfig)
		routeClient, err := route.NewClient(serviceCIDR, tc.networkConfig, tc.noSNAT)
		assert.NoError(t, err)

		var xtablesReleasedTime, initializedTime time.Time
		if tc.xtablesHoldDuration > 0 {
			closeFn, err := iptables.Lock(iptables.XtablesLockFilePath, 1*time.Second)
			require.NoError(t, err)
			go func() {
				time.Sleep(tc.xtablesHoldDuration)
				xtablesReleasedTime = time.Now()
				closeFn()
			}()
		}
		inited1 := make(chan struct{})
		err = routeClient.Initialize(nodeConfig, func() {
			initializedTime = time.Now()
			close(inited1)
		})
		assert.NoError(t, err)

		select {
		case <-time.After(tc.xtablesHoldDuration + 3*time.Second):
			t.Errorf("Initialize didn't finish in time when the xtables was held by others for %v", tc.xtablesHoldDuration)
		case <-inited1:
		}

		if tc.xtablesHoldDuration > 0 {
			assert.True(t, initializedTime.After(xtablesReleasedTime), "Initialize shouldn't finish before xtables lock was released")
		}
		inited2 := make(chan struct{})
		t.Log("Calling Initialize twice and verify no duplicates")
		err = routeClient.Initialize(nodeConfig, func() {
			close(inited2)
		})
		assert.NoError(t, err)

		select {
		case <-time.After(3 * time.Second):
			t.Errorf("Initialize didn't finish in time when the xtables was not held by others")
		case <-inited2:
		}

		// verify ipset
		err = exec.Command("ipset", "list", "ANTREA-POD-IP").Run()
		assert.NoError(t, err, "ipset not exist")
		entries, err := ipset.ListEntries("ANTREA-POD-IP")
		assert.NoError(t, err, "list ipset entries failed")
		assert.Contains(t, entries, podCIDR.String(), "entry should be in ipset")

		// verify iptables
		expectedIPTables := map[string]string{
			"raw": `:ANTREA-OUTPUT - [0:0]
:ANTREA-PREROUTING - [0:0]
-A PREROUTING -m comment --comment "Antrea: jump to Antrea prerouting rules" -j ANTREA-PREROUTING
-A OUTPUT -m comment --comment "Antrea: jump to Antrea output rules" -j ANTREA-OUTPUT
`,
			"filter": `:ANTREA-FORWARD - [0:0]
-A FORWARD -m comment --comment "Antrea: jump to Antrea forwarding rules" -j ANTREA-FORWARD
-A ANTREA-FORWARD -i antrea-gw0 -m comment --comment "Antrea: accept packets from local pods" -j ACCEPT
-A ANTREA-FORWARD -o antrea-gw0 -m comment --comment "Antrea: accept packets to local pods" -j ACCEPT
`,
			"mangle": `:ANTREA-MANGLE - [0:0]
:ANTREA-OUTPUT - [0:0]
-A PREROUTING -m comment --comment "Antrea: jump to Antrea mangle rules" -j ANTREA-MANGLE
-A OUTPUT -m comment --comment "Antrea: jump to Antrea output rules" -j ANTREA-OUTPUT
-A ANTREA-OUTPUT -o antrea-gw0 -m comment --comment "Antrea: mark local output packets" -m addrtype --src-type LOCAL -j MARK --set-xmark 0x1/0x1
`,
			"nat": `:ANTREA-POSTROUTING - [0:0]
-A POSTROUTING -m comment --comment "Antrea: jump to Antrea postrouting rules" -j ANTREA-POSTROUTING
-A ANTREA-POSTROUTING -s 10.10.10.0/24 -m comment --comment "Antrea: masquerade pod to external packets" -m set ! --match-set ANTREA-POD-IP dst -j MASQUERADE
`}

		if tc.noSNAT {
			expectedIPTables["nat"] = `:ANTREA-POSTROUTING - [0:0]
-A POSTROUTING -m comment --comment "Antrea: jump to Antrea postrouting rules" -j ANTREA-POSTROUTING
`
		}

		if tc.expectNoTrackRules {
			expectedIPTables["raw"] = fmt.Sprintf(`:ANTREA-OUTPUT - [0:0]
:ANTREA-PREROUTING - [0:0]
-A PREROUTING -m comment --comment "Antrea: jump to Antrea prerouting rules" -j ANTREA-PREROUTING
-A OUTPUT -m comment --comment "Antrea: jump to Antrea output rules" -j ANTREA-OUTPUT
-A ANTREA-OUTPUT -p udp -m comment --comment "Antrea: do not track outgoing encapsulation packets" -m udp --dport %d -m addrtype --src-type LOCAL -j NOTRACK
-A ANTREA-PREROUTING -p udp -m comment --comment "Antrea: do not track incoming encapsulation packets" -m udp --dport %d -m addrtype --dst-type LOCAL -j NOTRACK
`, tc.expectUDPPortInRules, tc.expectUDPPortInRules)
		}

		for table, expectedData := range expectedIPTables {
			// #nosec G204: ignore in test code
			actualData, err := exec.Command(
				"bash", "-c", fmt.Sprintf("iptables-save -t %s | grep -i antrea", table),
			).Output()
			assert.NoError(t, err, "error executing iptables-save")
			assert.Equal(t, expectedData, string(actualData), "mismatch iptables data in table %s", table)
		}
	}
}

func TestIpTablesSync(t *testing.T) {
	skipIfNotInContainer(t)
	gwLink := createDummyGW(t)
	defer netlink.LinkDel(gwLink)

	routeClient, err := route.NewClient(serviceCIDR, &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap}, false)
	assert.Nil(t, err)

	inited := make(chan struct{})
	err = routeClient.Initialize(nodeConfig, func() {
		close(inited)
	})
	assert.NoError(t, err)
	select {
	case <-inited: // Node network initialized
	}
	tcs := []struct {
		RuleSpec, Cmd, Table, Chain string
	}{
		{Table: "raw", Cmd: "-A", Chain: "OUTPUT", RuleSpec: "-m comment --comment \"Antrea: jump to Antrea output rules\" -j ANTREA-OUTPUT"},
		{Table: "filter", Cmd: "-A", Chain: "ANTREA-FORWARD", RuleSpec: "-i antrea-gw0 -m comment --comment \"Antrea: accept packets from local pods\" -j ACCEPT"},
	}
	// we delete some rules, start the sync goroutine, wait for sync operation to restore them.
	for _, tc := range tcs {
		delCmd := fmt.Sprintf("iptables -t %s -D %s  %s", tc.Table, tc.Chain, tc.RuleSpec)
		// #nosec G204: ignore in test code
		actualData, err := exec.Command("bash", "-c", delCmd).Output()
		assert.NoError(t, err, "error executing iptables cmd: %s", delCmd)
		assert.Equal(t, "", string(actualData), "failed to remove iptables rule for %v", tc)
	}
	stopCh := make(chan struct{})
	route.IPTablesSyncInterval = 2 * time.Second
	go routeClient.Run(stopCh)
	time.Sleep(route.IPTablesSyncInterval) // wait for one iteration of sync operation.
	for _, tc := range tcs {
		saveCmd := fmt.Sprintf("iptables-save -t %s | grep -e '%s %s'", tc.Table, tc.Cmd, tc.Chain)
		// #nosec G204: ignore in test code
		actualData, err := exec.Command("bash", "-c", saveCmd).Output()
		assert.NoError(t, err, "error executing iptables-save cmd")
		contains := fmt.Sprintf("%s %s %s", tc.Cmd, tc.Chain, tc.RuleSpec)
		assert.Contains(t, string(actualData), contains, "%s command's output did not contain rule: %s", saveCmd, contains)
	}
	close(stopCh)
}

func TestAddAndDeleteRoutes(t *testing.T) {
	skipIfNotInContainer(t)

	gwLink := createDummyGW(t)
	defer netlink.LinkDel(gwLink)

	tcs := []struct {
		// variations
		mode     config.TrafficEncapModeType
		peerCIDR string
		peerIP   net.IP
		// expectations
		uplink netlink.Link // indicates outbound of the route.
	}{
		{mode: config.TrafficEncapModeEncap, peerCIDR: "10.10.20.0/24", peerIP: localPeerIP, uplink: gwLink},
		{mode: config.TrafficEncapModeNoEncap, peerCIDR: "10.10.30.0/24", peerIP: localPeerIP, uplink: nodeLink},
		{mode: config.TrafficEncapModeNoEncap, peerCIDR: "10.10.40.0/24", peerIP: remotePeerIP, uplink: nil},
		{mode: config.TrafficEncapModeHybrid, peerCIDR: "10.10.50.0/24", peerIP: localPeerIP, uplink: nodeLink},
		{mode: config.TrafficEncapModeHybrid, peerCIDR: "10.10.60.0/24", peerIP: remotePeerIP, uplink: gwLink},
	}

	for _, tc := range tcs {
		t.Logf("Running test with mode %s peer cidr %s peer ip %s node config %s", tc.mode, tc.peerCIDR, tc.peerIP, nodeConfig)
		routeClient, err := route.NewClient(serviceCIDR, &config.NetworkConfig{TrafficEncapMode: tc.mode}, false)
		assert.NoError(t, err)
		err = routeClient.Initialize(nodeConfig, func() {})
		assert.NoError(t, err)

		_, peerCIDR, _ := net.ParseCIDR(tc.peerCIDR)
		nhCIDRIP := ip.NextIP(peerCIDR.IP)
		assert.NoError(t, routeClient.AddRoutes(peerCIDR, tc.peerIP, nhCIDRIP), "adding routes failed")

		expRouteStr := ""
		if tc.uplink != nil {
			nhIP := nhCIDRIP
			onlink := "onlink"
			if tc.uplink.Attrs().Name != gwName {
				nhIP = tc.peerIP
				onlink = ""
			}
			expRouteStr = fmt.Sprintf("%s via %s dev %s %s", peerCIDR, nhIP, tc.uplink.Attrs().Name, onlink)
			expRouteStr = strings.Join(strings.Fields(expRouteStr), "")
		}
		ipRoute, _ := ExecOutputTrim(fmt.Sprintf("ip route show | grep %s", tc.peerCIDR))
		if len(ipRoute) > len(expRouteStr) {
			ipRoute = ipRoute[:len(expRouteStr)]
		}
		assert.Equal(t, expRouteStr, ipRoute, "route mismatch")

		entries, err := ipset.ListEntries("ANTREA-POD-IP")
		assert.NoError(t, err, "list ipset entries failed")
		assert.Contains(t, entries, tc.peerCIDR, "entry should be in ipset")

		assert.NoError(t, routeClient.DeleteRoutes(peerCIDR), "deleting routes failed")
		output, err := ExecOutputTrim(fmt.Sprintf("ip route show table 0 exact %s", peerCIDR))
		assert.NoError(t, err)
		assert.Equal(t, "", output, "expected no routes to %s", peerCIDR)

		entries, err = ipset.ListEntries("ANTREA-POD-IP")
		assert.NoError(t, err, "list ipset entries failed")
		assert.NotContains(t, entries, tc.peerCIDR, "entry should not be in ipset")
	}
}

func TestReconcile(t *testing.T) {
	skipIfNotInContainer(t)

	gwLink := createDummyGW(t)
	defer netlink.LinkDel(gwLink)

	type peer struct {
		peerCIDR string
		peerIP   net.IP
	}
	tcs := []struct {
		// variations
		mode             config.TrafficEncapModeType
		addedRoutes      []peer
		desiredPeerCIDRs []string
		desiredNodeIPs   []string
		// expectations
		expRoutes map[string]netlink.Link
	}{
		{
			mode: config.TrafficEncapModeEncap,
			addedRoutes: []peer{
				{peerCIDR: "10.10.20.0/24", peerIP: remotePeerIP},
				{peerCIDR: "10.10.30.0/24", peerIP: ip.NextIP((remotePeerIP))},
			},
			desiredPeerCIDRs: []string{"10.10.20.0/24"},
			desiredNodeIPs:   []string{remotePeerIP.String()},
			expRoutes:        map[string]netlink.Link{"10.10.20.0/24": gwLink, "10.10.30.0/24": nil},
		},
		{
			mode: config.TrafficEncapModeNoEncap,
			addedRoutes: []peer{
				{peerCIDR: "10.10.20.0/24", peerIP: localPeerIP},
				{peerCIDR: "10.10.30.0/24", peerIP: ip.NextIP((localPeerIP))},
			},
			desiredPeerCIDRs: []string{"10.10.20.0/24"},
			desiredNodeIPs:   []string{localPeerIP.String()},
			expRoutes:        map[string]netlink.Link{"10.10.20.0/24": nodeLink, "10.10.30.0/24": nil},
		},
		{
			mode: config.TrafficEncapModeHybrid,
			addedRoutes: []peer{
				{peerCIDR: "10.10.20.0/24", peerIP: localPeerIP},
				{peerCIDR: "10.10.30.0/24", peerIP: ip.NextIP((localPeerIP))},
				{peerCIDR: "10.10.40.0/24", peerIP: remotePeerIP},
				{peerCIDR: "10.10.50.0/24", peerIP: ip.NextIP((remotePeerIP))},
			},
			desiredPeerCIDRs: []string{"10.10.20.0/24", "10.10.40.0/24"},
			desiredNodeIPs:   []string{localPeerIP.String(), remotePeerIP.String()},
			expRoutes:        map[string]netlink.Link{"10.10.20.0/24": nodeLink, "10.10.30.0/24": nil, "10.10.40.0/24": gwLink, "10.10.50.0/24": nil},
		},
	}

	for _, tc := range tcs {
		t.Logf("Running test with mode %s added routes %v desired routes %v", tc.mode, tc.addedRoutes, tc.desiredPeerCIDRs)
		routeClient, err := route.NewClient(serviceCIDR, &config.NetworkConfig{TrafficEncapMode: tc.mode}, false)
		assert.NoError(t, err)
		err = routeClient.Initialize(nodeConfig, func() {})
		assert.NoError(t, err)

		for _, route := range tc.addedRoutes {
			_, peerNet, _ := net.ParseCIDR(route.peerCIDR)
			peerGwIP := ip.NextIP(peerNet.IP)
			assert.NoError(t, routeClient.AddRoutes(peerNet, route.peerIP, peerGwIP), "adding routes failed")
		}

		assert.NoError(t, routeClient.Reconcile(tc.desiredPeerCIDRs), "reconcile failed")

		for dst, uplink := range tc.expRoutes {
			expNum := 0
			if uplink != nil {
				output, err := ExecOutputTrim(fmt.Sprintf("ip route show table 0 exact %s", dst))
				assert.NoError(t, err)
				assert.Contains(t, output, fmt.Sprintf("dev%s", uplink.Attrs().Name))
				expNum = 1
			}
			output, err := ExecOutputTrim(fmt.Sprintf("ip route show table 0 exact %s | wc -l", dst))
			assert.NoError(t, err)
			assert.Equal(t, fmt.Sprint(expNum), output, "mismatch number of routes to %s", dst)
		}

		entries, err := ipset.ListEntries("ANTREA-POD-IP")
		assert.NoError(t, err, "list ipset entries failed")
		assert.ElementsMatch(t, entries, tc.desiredPeerCIDRs, "mismatch ipset entries")
	}
}

func TestRouteTablePolicyOnly(t *testing.T) {
	skipIfNotInContainer(t)

	gwLink := createDummyGW(t)
	defer netlink.LinkDel(gwLink)

	routeClient, err := route.NewClient(serviceCIDR, &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeNetworkPolicyOnly}, false)
	assert.NoError(t, err)
	err = routeClient.Initialize(nodeConfig, func() {})
	assert.NoError(t, err)
	// Verify gw IP
	gwName := nodeConfig.GatewayConfig.Name
	gwIPOut, err := ExecOutputTrim(fmt.Sprintf("ip addr show %s", gwName))
	assert.NoError(t, err)
	gwIP := net.IPNet{
		IP:   nodeConfig.NodeIPAddr.IP,
		Mask: net.CIDRMask(32, 32),
	}
	assert.Contains(t, gwIPOut, gwIP.String())

	cLink := &netlink.Dummy{}
	cLink.Name = "containerLink"
	assert.NoError(t, netlink.LinkAdd(cLink), "creating linked failed")
	assert.NoError(t, netlink.LinkSetUp(cLink), "setting-up link failed")

	_, ipAddr, _ := net.ParseCIDR("10.10.1.1/32")
	_, hostRt, _ := net.ParseCIDR("10.10.1.2/32")
	assert.NoError(t, netlink.AddrAdd(cLink, &netlink.Addr{IPNet: ipAddr}), "configuring IP on link failed")
	rt := &netlink.Route{
		LinkIndex: cLink.Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       hostRt,
	}
	if assert.NoError(t, netlink.RouteAdd(rt)) {
		t.Logf("route added: %v - output interface index: %d - input interface index: %d", rt, rt.LinkIndex, rt.ILinkIndex)
	}

	// verify route is migrated.
	assert.NoError(t, routeClient.MigrateRoutesToGw(cLink.Name))
	expRoute := strings.Join(strings.Fields(
		fmt.Sprintf("%s dev %s scope link", hostRt.IP, gwName)), "")
	output, _ := ExecOutputTrim(fmt.Sprintf("ip route show"))
	assert.Containsf(t, output, expRoute, output)
	output, _ = ExecOutputTrim(fmt.Sprintf("ip add show %s", gwName))
	assert.Containsf(t, output, ipAddr.String(), output)

	// verify route being removed after unmigrate
	assert.NoError(t, routeClient.UnMigrateRoutesFromGw(hostRt, ""))
	output, _ = ExecOutputTrim(fmt.Sprintf("ip route show"))
	assert.NotContainsf(t, output, expRoute, output)
	// note unmigrate does not remove ip addresses given to antrea-gw0
	output, _ = ExecOutputTrim(fmt.Sprintf("ip add show %s", gwName))
	assert.Containsf(t, output, ipAddr.String(), output)
	_ = netlink.LinkDel(gwLink)
}

func TestIPv6RoutesAndNeighbors(t *testing.T) {
	skipIfNotInContainer(t)
	if !nettest.SupportsIPv6() {
		t.Skipf("Skipping test as IPv6 is not supported")
	}

	gwLink := createDummyGW(t)
	defer netlink.LinkDel(gwLink)

	routeClient, err := route.NewClient(serviceCIDR, &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap}, false)
	assert.Nil(t, err)
	_, ipv6Subnet, _ := net.ParseCIDR("fd74:ca9b:172:19::/64")
	gwIPv6 := net.ParseIP("fd74:ca9b:172:19::1")
	dualGWConfig := &config.GatewayConfig{IPv4: gwIP, IPv6: gwIPv6, MAC: gwMAC, Name: gwName, LinkIndex: gwLink.Attrs().Index}
	dualNodeConfig := &config.NodeConfig{
		Name:          "test",
		PodIPv4CIDR:   podCIDR,
		PodIPv6CIDR:   ipv6Subnet,
		NodeIPAddr:    nodeIP,
		GatewayConfig: dualGWConfig,
	}
	err = routeClient.Initialize(dualNodeConfig, func() {})
	assert.Nil(t, err)

	tcs := []struct {
		// variations
		peerCIDR string
		// expectations
		uplink netlink.Link
	}{
		{peerCIDR: "10.10.20.0/24", uplink: gwLink},
		{peerCIDR: "fd74:ca9b:172:18::/64", uplink: gwLink},
	}

	for _, tc := range tcs {
		_, peerCIDR, _ := net.ParseCIDR(tc.peerCIDR)
		nhCIDRIP := ip.NextIP(peerCIDR.IP)
		assert.NoError(t, routeClient.AddRoutes(peerCIDR, localPeerIP, nhCIDRIP), "adding routes failed")

		link := tc.uplink
		nhIP := nhCIDRIP
		var expRouteStr, ipRoute, expNeighStr, ipNeigh string
		if nhIP.To4() != nil {
			onlink := "onlink"
			expRouteStr = fmt.Sprintf("%s via %s dev %s %s", peerCIDR, nhIP, link.Attrs().Name, onlink)
			ipRoute, _ = ExecOutputTrim(fmt.Sprintf("ip route show | grep %s", tc.peerCIDR))
		} else {
			expRouteStr = fmt.Sprintf("%s via %s dev %s", peerCIDR, nhIP, link.Attrs().Name)
			ipRoute, _ = ExecOutputTrim(fmt.Sprintf("ip -6 route show | grep %s", tc.peerCIDR))
			expNeighStr = fmt.Sprintf("%s dev %s lladdr aa:bb:cc:dd:ee:ff PERMANENT", nhIP, link.Attrs().Name)
			ipNeigh, _ = ExecOutputTrim(fmt.Sprintf("ip -6 neighbor show | grep %s", nhIP))
		}
		expRouteStr = strings.Join(strings.Fields(expRouteStr), "")
		if len(ipRoute) > len(expRouteStr) {
			ipRoute = ipRoute[:len(expRouteStr)]
		}
		assert.Equal(t, expRouteStr, ipRoute, "route mismatch")
		if expNeighStr != "" {
			expNeighStr = strings.Join(strings.Fields(expNeighStr), "")
			if len(ipNeigh) > len(expNeighStr) {
				ipNeigh = ipNeigh[:len(expNeighStr)]
			}
			assert.Equal(t, expNeighStr, ipNeigh, "IPv6 Neighbor mismatch")
		}
		assert.NoError(t, routeClient.DeleteRoutes(peerCIDR), "deleting routes failed")
		output, err := ExecOutputTrim(fmt.Sprintf("ip route show table 0 exact %s", peerCIDR))
		assert.NoError(t, err)
		assert.Equal(t, "", output, "expected no routes to %s", peerCIDR)
	}
}
