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

// +build linux

package agent

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/route"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/agent/util/ipset"
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
	nodeIP, nodeLink, _ = util.GetIPNetDeviceFromIP(func() net.IP {
		conn, _ := net.Dial("udp", "8.8.8.8:80")
		defer conn.Close()
		return conn.LocalAddr().(*net.UDPAddr).IP
	}())
	localPeerIP       = ip.NextIP(nodeIP.IP)
	remotePeerIP      = net.ParseIP("50.50.50.1")
	_, serviceCIDR, _ = net.ParseCIDR("200.200.0.0/16")
	gwIP              = net.ParseIP("10.10.10.1")
	gwMAC, _          = net.ParseMAC("12:34:56:78:bb:cc")
	gwName            = "gw0"
	svcTblIdx         = route.AntreaServiceTableIdx
	svcTblName        = route.AntreaServiceTable
	mainTblIdx        = 254
	gwConfig          = &config.GatewayConfig{IP: gwIP, MAC: gwMAC, Name: gwName}
	nodeConfig        = &config.NodeConfig{
		Name:          "test",
		PodCIDR:       podCIDR,
		NodeIPAddr:    nodeIP,
		GatewayConfig: gwConfig,
	}
)

func createDummyGW(t *testing.T) netlink.Link {
	// create dummy gw interface
	gwLink := &netlink.Dummy{}
	gwLink.Name = gwName
	if err := netlink.LinkAdd(gwLink); err != nil {
		t.Error(err)
	}
	link, _ := netlink.LinkByName(gwLink.Name)
	if err := netlink.LinkSetUp(link); err != nil {
		t.Error(err)
	}
	nodeConfig.GatewayConfig.LinkIndex = link.Attrs().Index
	nodeConfig.GatewayConfig.Name = gwLink.Attrs().Name
	return link
}

func TestInitialize(t *testing.T) {
	if _, incontainer := os.LookupEnv("INCONTAINER"); !incontainer {
		// test changes file system, routing table. Run in contain only
		t.Skipf("Skip test runs only in container")
	}

	link := createDummyGW(t)
	defer netlink.LinkDel(link)

	refRouteTablesStr, _ := ExecOutputTrim("cat /etc/iproute2/rt_tables")

	tcs := []struct {
		// variations
		mode config.TrafficEncapModeType
		// expectations
		expSvcTbl bool
		expIPRule bool
	}{
		{mode: config.TrafficEncapModeNoEncap, expSvcTbl: true, expIPRule: true},
		{mode: config.TrafficEncapModeHybrid, expSvcTbl: true, expIPRule: true},
		{mode: config.TrafficEncapModeEncap, expSvcTbl: false, expIPRule: false},
	}

	for _, tc := range tcs {
		t.Logf("Running Initialize test with mode %s node config %s", tc.mode, nodeConfig)
		routeClient, err := route.NewClient(gwName, serviceCIDR, tc.mode)
		if err != nil {
			t.Error(err)
		}
		if err := routeClient.Initialize(nodeConfig); err != nil {
			t.Error(err)
		}

		// Call initialize twice and verify no duplicates
		if err := routeClient.Initialize(nodeConfig); err != nil {
			t.Error(err)
		}

		// verify route tables
		expRouteTablesStr := refRouteTablesStr
		if tc.expSvcTbl {
			expRouteTablesStr = fmt.Sprintf("%s%d%s", refRouteTablesStr, svcTblIdx, svcTblName)
		}
		routeTables, err := ExecOutputTrim("cat /etc/iproute2/rt_tables")
		if err != nil {
			t.Error(err)
		}
		if !assert.Equal(t, expRouteTablesStr, routeTables) {
			t.Errorf("mismatch route tables")
		}

		if tc.expSvcTbl {
			expRouteStr := fmt.Sprintf("%s dev %s scope link", podCIDR, gwName)
			expRouteStr = strings.Join(strings.Fields(expRouteStr), "")
			ipRoute, _ := ExecOutputTrim(fmt.Sprintf("ip route show table %d | grep %s", svcTblIdx, podCIDR))
			if len(ipRoute) > len(expRouteStr) {
				ipRoute = ipRoute[:len(expRouteStr)]
			}
			assert.Equal(t, expRouteStr, ipRoute, "mismatch link route")
		}

		// verify ip rules
		expIPRulesStr := ""
		if tc.expIPRule {
			expIPRulesStr = fmt.Sprintf("%d: from all fwmark %#x/%#x iif %s lookup %s", route.AntreaIPRulePriority, route.RtTblSelectorValue, route.RtTblSelectorValue,
				gwName, svcTblName)
			expIPRulesStr = strings.Join(strings.Fields(expIPRulesStr), "")
		}
		ipRule, _ := ExecOutputTrim(fmt.Sprintf("ip rule | grep %x", route.RtTblSelectorValue))
		if !assert.Equal(t, expIPRulesStr, ipRule) {
			t.Errorf("mismatch ip rules")
		}

		// verify ipset
		err = exec.Command("ipset", "list", "ANTREA-POD-IP").Run()
		assert.NoError(t, err, "ipset not exist")
		entries, err := ipset.ListEntries("ANTREA-POD-IP")
		assert.NoError(t, err, "list ipset entries failed")
		assert.Contains(t, entries, podCIDR.String(), "entry should be in ipset")

		// verify iptables
		expectedIPTables := map[string]string{
			"filter": `:ANTREA-FORWARD - [0:0]
-A FORWARD -m comment --comment "Antrea: jump to Antrea forwarding rules" -j ANTREA-FORWARD
-A ANTREA-FORWARD -i gw0 -m comment --comment "Antrea: accept packets from local pods" -j ACCEPT
-A ANTREA-FORWARD -o gw0 -m comment --comment "Antrea: accept packets to local pods" -j ACCEPT
`,
			"raw": `:ANTREA-RAW - [0:0]
-A PREROUTING -m comment --comment "Antrea: jump to Antrea raw rules" -j ANTREA-RAW
`,
			"mangle": `:ANTREA-MANGLE - [0:0]
-A PREROUTING -m comment --comment "Antrea: jump to Antrea mangle rules" -j ANTREA-MANGLE
`,
			"nat": `:ANTREA-POSTROUTING - [0:0]
-A POSTROUTING -m comment --comment "Antrea: jump to Antrea postrouting rules" -j ANTREA-POSTROUTING
-A ANTREA-POSTROUTING -s 10.10.10.0/24 -m set ! --match-set ANTREA-POD-IP dst -m comment --comment "Antrea: masquerade pod to external packets" -j MASQUERADE
`,
		}
		if tc.mode.SupportsNoEncap() {
			expectedIPTables["mangle"] = `:ANTREA-MANGLE - [0:0]
-A PREROUTING -m comment --comment "Antrea: jump to Antrea mangle rules" -j ANTREA-MANGLE
-A ANTREA-MANGLE -d 200.200.0.0/16 -i gw0 -m comment --comment "Antrea: mark pod to service packets" -j MARK --set-xmark 0x800/0x800
-A ANTREA-MANGLE ! -d 200.200.0.0/16 -i gw0 -m comment --comment "Antrea: unmark post LB service packets" -j MARK --set-xmark 0x0/0xffffffff
`
			expectedIPTables["raw"] = `:ANTREA-RAW - [0:0]
-A PREROUTING -m comment --comment "Antrea: jump to Antrea raw rules" -j ANTREA-RAW
-A ANTREA-RAW -i gw0 -m mac --mac-source DE:AD:BE:EF:DE:AD -m comment --comment "Antrea: reentry pod traffic skip conntrack" -j CT --notrack
`
		}

		for table, expectedData := range expectedIPTables {
			actualData, err := exec.Command(
				"bash", "-c", fmt.Sprintf("iptables-save -t %s | grep -i antrea", table),
			).Output()
			assert.NoError(t, err, "error executing iptables-save")
			assert.Equal(t, expectedData, string(actualData), "mismatch iptables data in table %s", table)
		}
	}
}

func TestAddAndDeleteRoutes(t *testing.T) {
	if _, incontainer := os.LookupEnv("INCONTAINER"); !incontainer {
		// test changes file system, routing table. Run in contain only
		t.Skipf("Skip test runs only in container")
	}

	gwLink := createDummyGW(t)
	defer netlink.LinkDel(gwLink)

	tcs := []struct {
		// variations
		mode     config.TrafficEncapModeType
		peerCIDR string
		peerIP   net.IP
		// expectations
		expRoutes map[int]netlink.Link // keyed on rt id, and val indicates outbound dev
	}{
		{mode: config.TrafficEncapModeEncap, peerCIDR: "10.10.20.0/24", peerIP: localPeerIP,
			expRoutes: map[int]netlink.Link{mainTblIdx: gwLink}},
		{mode: config.TrafficEncapModeNoEncap, peerCIDR: "10.10.30.0/24", peerIP: localPeerIP,
			expRoutes: map[int]netlink.Link{svcTblIdx: gwLink, mainTblIdx: nodeLink}},
		{mode: config.TrafficEncapModeNoEncap, peerCIDR: "10.10.40.0/24", peerIP: remotePeerIP,
			expRoutes: map[int]netlink.Link{svcTblIdx: gwLink}},
		{mode: config.TrafficEncapModeHybrid, peerCIDR: "10.10.50.0/24", peerIP: localPeerIP,
			expRoutes: map[int]netlink.Link{svcTblIdx: gwLink, mainTblIdx: nodeLink}},
		{mode: config.TrafficEncapModeHybrid, peerCIDR: "10.10.60.0/24", peerIP: remotePeerIP,
			expRoutes: map[int]netlink.Link{svcTblIdx: gwLink, mainTblIdx: gwLink}},
	}

	for _, tc := range tcs {
		t.Logf("Running test with mode %s peer cidr %s peer ip %s node config %s", tc.mode, tc.peerCIDR, tc.peerIP, nodeConfig)
		routeClient, err := route.NewClient(gwName, serviceCIDR, tc.mode)
		if err != nil {
			t.Error(err)
		}
		if err := routeClient.Initialize(nodeConfig); err != nil {
			t.Error(err)
		}

		_, peerCIDR, _ := net.ParseCIDR(tc.peerCIDR)
		nhCIDRIP := ip.NextIP(peerCIDR.IP)
		if err := routeClient.AddRoutes(peerCIDR, tc.peerIP, nhCIDRIP); err != nil {
			t.Errorf("route add failed with err %v", err)
		}

		for tblIdx, link := range tc.expRoutes {
			nhIP := nhCIDRIP
			onlink := "onlink"
			if link.Attrs().Name != gwName {
				nhIP = tc.peerIP
				onlink = ""
			}
			expRouteStr := fmt.Sprintf("%s via %s dev %s %s", peerCIDR, nhIP, link.Attrs().Name, onlink)
			expRouteStr = strings.Join(strings.Fields(expRouteStr), "")
			ipRoute, _ := ExecOutputTrim(fmt.Sprintf("ip route show table %d | grep %s", tblIdx, tc.peerCIDR))
			if len(ipRoute) > len(expRouteStr) {
				ipRoute = ipRoute[:len(expRouteStr)]
			}
			if !assert.Equal(t, expRouteStr, ipRoute) {
				t.Errorf("mismatch route")
			}
		}

		entries, err := ipset.ListEntries("ANTREA-POD-IP")
		assert.NoError(t, err, "list ipset entries failed")
		assert.Contains(t, entries, tc.peerCIDR, "entry should be in ipset")

		if err := routeClient.DeleteRoutes(peerCIDR); err != nil {
			t.Errorf("route delete failed with err %v", err)
		}
		output, err := ExecOutputTrim(fmt.Sprintf("ip route show table 0 exact %s", peerCIDR))
		assert.NoError(t, err)
		assert.Equal(t, "", output, "expected no routes to %s", peerCIDR)

		entries, err = ipset.ListEntries("ANTREA-POD-IP")
		assert.NoError(t, err, "list ipset entries failed")
		assert.NotContains(t, entries, tc.peerCIDR, "entry should not be in ipset")
	}
}

func TestReconcile(t *testing.T) {
	if _, incontainer := os.LookupEnv("INCONTAINER"); !incontainer {
		// test changes file system, routing table. Run in contain only
		t.Skipf("Skip test runs only in container")
	}

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
		// expectations
		expRouteNum map[string]int
	}{
		{
			mode: config.TrafficEncapModeEncap,
			addedRoutes: []peer{
				{peerCIDR: "10.10.20.0/24", peerIP: remotePeerIP},
				{peerCIDR: "10.10.30.0/24", peerIP: ip.NextIP((remotePeerIP))},
			},
			desiredPeerCIDRs: []string{"10.10.20.0/24"},
			expRouteNum:      map[string]int{"10.10.20.0/24": 1, "10.10.30.0/24": 0},
		},
		{
			mode: config.TrafficEncapModeNoEncap,
			addedRoutes: []peer{
				{peerCIDR: "10.10.20.0/24", peerIP: localPeerIP},
				{peerCIDR: "10.10.30.0/24", peerIP: ip.NextIP((localPeerIP))},
			},
			desiredPeerCIDRs: []string{"10.10.20.0/24"},
			expRouteNum:      map[string]int{"10.10.20.0/24": 2, "10.10.30.0/24": 0},
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
			expRouteNum:      map[string]int{"10.10.20.0/24": 2, "10.10.30.0/24": 0, "10.10.40.0/24": 2, "10.10.50.0/24": 0},
		},
	}

	for _, tc := range tcs {
		routeClient, err := route.NewClient(gwName, serviceCIDR, tc.mode)
		if err != nil {
			t.Error(err)
		}
		if err := routeClient.Initialize(nodeConfig); err != nil {
			t.Error(err)
		}

		for _, route := range tc.addedRoutes {
			_, peerNet, _ := net.ParseCIDR(route.peerCIDR)
			peerGwIP := ip.NextIP(peerNet.IP)
			if err := routeClient.AddRoutes(peerNet, route.peerIP, peerGwIP); err != nil {
				t.Errorf("route add failed with err %v", err)
			}
		}

		if err := routeClient.Reconcile(tc.desiredPeerCIDRs); err != nil {
			t.Errorf("Reconcile failed with err %v", err)
		}

		for dst, expNum := range tc.expRouteNum {
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
	if _, incontainer := os.LookupEnv("INCONTAINER"); !incontainer {
		// test changes file system, routing table. Run in contain only
		t.Skipf("Skip test runs only in container")
	}

	gwLink := createDummyGW(t)
	defer netlink.LinkDel(gwLink)

	routeClient, err := route.NewClient(gwName, serviceCIDR, config.TrafficEncapModeNetworkPolicyOnly)
	if err != nil {
		t.Error(err)
	}
	if err := routeClient.Initialize(nodeConfig); err != nil {
		t.Error(err)
	}
	//verify gw IP
	gwName := nodeConfig.GatewayConfig.Name
	gwIPOut, err := ExecOutputTrim(fmt.Sprintf("ip addr show %s", gwName))
	if err != nil {
		t.Error(err)
	}
	gwIP := net.IPNet{
		IP:   nodeConfig.NodeIPAddr.IP,
		Mask: net.CIDRMask(32, 32),
	}
	assert.Contains(t, gwIPOut, gwIP.String())
	// verify default routes and neigh
	expRoute := strings.Join(strings.Fields(
		"default via 169.254.253.1 dev gw0 onlink"), "")
	routeOut, err := ExecOutputTrim(fmt.Sprintf("ip route show table %d", svcTblIdx))
	assert.Equal(t, expRoute, routeOut)
	expNeigh := strings.Join(strings.Fields(
		"169.254.253.1 dev gw0 lladdr 12:34:56:78:9a:bc PERMANENT"), "")
	neighOut, err := ExecOutputTrim(fmt.Sprintf("ip neigh | grep %s", gwName))
	assert.Equal(t, expNeigh, neighOut)

	cLink := &netlink.Dummy{}
	cLink.Name = "containerLink"
	err = netlink.LinkAdd(cLink)
	if err == nil {
		err = netlink.LinkSetUp(cLink)
	}
	if err != nil {
		t.Error(err)
	}

	_, ipAddr, _ := net.ParseCIDR("10.10.1.1/32")
	_, hostRt, _ := net.ParseCIDR("10.10.1.2/32")
	if err := netlink.AddrAdd(cLink, &netlink.Addr{IPNet: ipAddr}); err != nil {
		t.Error(err)
	}
	rt := &netlink.Route{
		LinkIndex: cLink.Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       hostRt,
	}
	if err := netlink.RouteAdd(rt); err != nil {
		t.Error(err)
	}
	t.Logf("route %v indx %d, iindx %d added", rt, rt.LinkIndex, rt.ILinkIndex)

	// verify route is migrated.
	if err := routeClient.MigrateRoutesToGw(cLink.Name); err != nil {
		t.Error(err)
	}
	expRoute = strings.Join(strings.Fields(
		fmt.Sprintf("%s dev %s scope link", hostRt.IP, gwName)), "")
	output, _ := ExecOutputTrim(fmt.Sprintf("ip route show"))
	assert.Containsf(t, output, expRoute, output)
	output, _ = ExecOutputTrim(fmt.Sprintf("ip add show %s", gwName))
	assert.Containsf(t, output, ipAddr.String(), output)

	// verify route being removed after unmigrate
	if err := routeClient.UnMigrateRoutesFromGw(hostRt, ""); err != nil {
		t.Error(err)
	}
	output, _ = ExecOutputTrim(fmt.Sprintf("ip route show"))
	assert.NotContainsf(t, output, expRoute, output)
	// note unmigrate does not remove ip addresses given to gw0
	output, _ = ExecOutputTrim(fmt.Sprintf("ip add show %s", gwName))
	assert.Containsf(t, output, ipAddr.String(), output)
	_ = netlink.LinkDel(gwLink)
}
