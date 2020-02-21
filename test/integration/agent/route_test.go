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

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/iptables"
	"github.com/vmware-tanzu/antrea/pkg/agent/route"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
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
		defer func() { _ = conn.Close() }()
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
		PodCIDR:       nil,
		NodeIPAddr:    nodeIP,
		GatewayConfig: gwConfig,
	}
)

func TestRouteTable(t *testing.T) {
	if _, incontainer := os.LookupEnv("INCONTAINER"); !incontainer {
		// test changes file system, routing table. Run in contain only
		t.Skipf("Skip test runs only in container")
	}

	// create dummy gw interface
	gwLink := &netlink.Veth{}
	gwLink.Name = gwName
	gwLink.PeerName = gwLink.Name + "-peer"
	if err := netlink.LinkAdd(gwLink); err != nil {
		t.Error(err)
	}

	link, _ := netlink.LinkByName(gwLink.Name)
	if err := netlink.LinkSetUp(link); err != nil {
		t.Error(err)
	}

	nodeConfig.GatewayConfig.LinkIndex = link.Attrs().Index

	refRouteTablesStr, _ := ExecOutputTrim("cat /etc/iproute2/rt_tables")
	tcs := []struct {
		// variations
		mode     config.TrafficEncapModeType
		podCIDR  *net.IPNet
		peerCIDR string
		peerIP   net.IP
		// expectations
		expSvcTbl bool
		expIPRule bool
		expRoutes map[int]netlink.Link // keyed on rt id, and val indicates outbound dev
	}{
		{mode: config.TrafficEncapModeEncap, podCIDR: podCIDR, peerCIDR: "10.10.20.0/24", peerIP: localPeerIP,
			expSvcTbl: false, expIPRule: false, expRoutes: map[int]netlink.Link{mainTblIdx: gwLink}},
		{mode: config.TrafficEncapModeNoEncap, podCIDR: podCIDR, peerCIDR: "10.10.30.0/24", peerIP: localPeerIP,
			expSvcTbl: true, expIPRule: true, expRoutes: map[int]netlink.Link{svcTblIdx: gwLink, mainTblIdx: nodeLink}},
		{mode: config.TrafficEncapModeNoEncap, podCIDR: podCIDR, peerCIDR: "10.10.40.0/24", peerIP: remotePeerIP,
			expSvcTbl: true, expIPRule: true, expRoutes: map[int]netlink.Link{svcTblIdx: gwLink}},
		{mode: config.TrafficEncapModeHybrid, podCIDR: podCIDR, peerCIDR: "10.10.50.0/24", peerIP: localPeerIP,
			expSvcTbl: true, expIPRule: true, expRoutes: map[int]netlink.Link{svcTblIdx: gwLink, mainTblIdx: nodeLink}},
		{mode: config.TrafficEncapModeHybrid, podCIDR: podCIDR, peerCIDR: "10.10.60.0/24", peerIP: remotePeerIP,
			expSvcTbl: true, expIPRule: true, expRoutes: map[int]netlink.Link{svcTblIdx: gwLink, mainTblIdx: gwLink}},
	}

	for _, tc := range tcs {
		nodeConfig.PodCIDR = tc.podCIDR
		t.Logf("Running test with mode %s peer cidr %s peer ip %s node config %s", tc.mode, tc.peerCIDR, tc.peerIP, nodeConfig)
		routeClient := route.NewClient(tc.mode)
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
			expRouteTablesStr = fmt.Sprintf("%s%d%s", refRouteTablesStr, route.ServiceRtTable.Idx, route.ServiceRtTable.Name)
		}
		routeTables, err := ExecOutputTrim("cat /etc/iproute2/rt_tables")
		if err != nil {
			t.Error(err)
		}
		if !assert.Equal(t, expRouteTablesStr, routeTables) {
			t.Errorf("mismatch route tables")
		}

		if tc.expSvcTbl && tc.podCIDR != nil {
			expRouteStr := fmt.Sprintf("%s dev %s scope link", tc.podCIDR, gwName)
			expRouteStr = strings.Join(strings.Fields(expRouteStr), "")
			ipRoute, _ := ExecOutputTrim(fmt.Sprintf("ip route show table %d | grep %s", svcTblIdx, tc.podCIDR))
			if len(ipRoute) > len(expRouteStr) {
				ipRoute = ipRoute[:len(expRouteStr)]
			}
			if !assert.Equal(t, expRouteStr, ipRoute) {
				t.Errorf("mismatch link route")
			}
		}

		// verify ip rules
		expIPRulesStr := ""
		if tc.expIPRule {
			expIPRulesStr = fmt.Sprintf("%d: from all fwmark %#x iif %s lookup %s", route.AntreaIPRulePriority, iptables.RtTblSelectorValue,
				gwName, svcTblName)
			expIPRulesStr = strings.Join(strings.Fields(expIPRulesStr), "")
		}
		ipRule, _ := ExecOutputTrim(fmt.Sprintf("ip rule | grep %x", iptables.RtTblSelectorValue))
		if !assert.Equal(t, expIPRulesStr, ipRule) {
			t.Errorf("mismatch ip rules")
		}

		// verify routes
		var peerCIDR *net.IPNet
		var nhCIDRIP net.IP
		if len(tc.peerCIDR) > 0 {
			_, peerCIDR, _ = net.ParseCIDR(tc.peerCIDR)
			nhCIDRIP = ip.NextIP(peerCIDR.IP)
		}
		routes, err := routeClient.AddPeerCIDRRoute(peerCIDR, gwLink.Index, tc.peerIP, nhCIDRIP)
		if len(routes) != len(tc.expRoutes) {
			t.Errorf("mismatch number of routes, expected %d, actual %d", len(tc.expRoutes), len(routes))
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

		// test list route
		rtMap, err := routeClient.ListPeerCIDRRoute()
		if err != nil {
			t.Error(err)
		}
		t.Logf("list route %s", rtMap)

		// one local, one remote, local can be down
		if !assert.Contains(t, []int{1, 2}, len(rtMap)) {
			t.Errorf("mismatch list route count")
		}

		if !assert.Contains(t, rtMap, tc.peerCIDR) {
			t.Error("mismatch list route content")
		}

		if !assert.Equal(t, len(tc.expRoutes), len(rtMap[tc.peerCIDR])) {
			t.Error("mismatch list route content")
		}

		// test delete route
		if err = routeClient.DeletePeerCIDRRoute(rtMap[tc.peerCIDR]); err != nil {
			t.Errorf("route delete failed with err %v", err)
		}

		if tc.mode != config.TrafficEncapModeEncap {
			if err = routeClient.RemoveServiceRouting(); err != nil {
				t.Errorf("route reset failed with err %v", err)
			}
		}

		// verify route table cleanup works
		routeTables, err = ExecOutputTrim("cat /etc/iproute2/rt_tables")
		if err != nil {
			t.Error(err)
		}
		if !assert.Equal(t, refRouteTablesStr, routeTables) {
			t.Errorf("mismatch route tables after cleanup")
		}
		// verify no ip rule
		output, err := ExecOutputTrim(fmt.Sprintf("ip rule | grep %x", iptables.RtTblSelectorValue))
		if !assert.Error(t, err) {
			t.Errorf("ip rule not cleaned %s", output)
		}
		// verify no routes
		output, err = ExecOutputTrim(fmt.Sprintf("ip route show table %s", route.AntreaServiceTable))
		if !assert.Error(t, err) {
			t.Errorf("route not cleaned %s", output)
		}
	}
}
