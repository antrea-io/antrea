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
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/stretchr/testify/assert"
	"github.com/vmware-tanzu/antrea/pkg/agent/iptables"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/vmware-tanzu/antrea/pkg/agent/route"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/signals"
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
	nodeIP, nodeLink, _ = util.GetDefaultLocalNodeAddr()
	localPeerIP         = ip.NextIP(nodeIP.IP)
	remotePeerIP        = net.ParseIP("50.50.50.1")
	_, serviceCIDR, _   = net.ParseCIDR("200.200.0.0/16")
	gwIP                = net.ParseIP("10.10.10.1")
	gwMAC, _            = net.ParseMAC("12:34:56:78:bb:cc")
	gwName              = "gw0"
	svcTblIdx           = 3000
	svcTblName          = "antrea-service"
	mainTblIdx          = 254
	mainTblName         = "main"
	gwConfig            = &types.GatewayConfig{IP: gwIP, MAC: gwMAC, Name: gwName}
	svcRtTable          = &types.ServiceRtTableConfig{Idx: svcTblIdx, Name: svcTblName}
	mainRtTable         = &types.ServiceRtTableConfig{Idx: mainTblIdx, Name: mainTblName}
	nodeConfig          = &types.NodeConfig{
		Name:           "test",
		PodCIDR:        nil,
		NodeIPAddr:     nodeIP,
		NodeDefaultDev: nodeLink,
		PodEncapMode:   types.PodEncapModeInvald,
		GatewayConfig:  gwConfig,
		ServiceCIDR:    serviceCIDR,
		ServiceRtTable: nil,
	}
)

func TestRouteTable(t *testing.T) {
	if _, incontainer := os.LookupEnv("INCONTAINER"); !incontainer {
		t.Logf("Skip test not run in container")
		return
	}

	// create dummy gw interface
	gwLink := &netlink.Veth{}
	gwLink.Name = nodeConfig.GatewayConfig.Name
	gwLink.PeerName = gwLink.Name + "-peer"
	if err := netlink.LinkAdd(gwLink); err != nil {
		t.Error(err)
	}

	if err := netlink.LinkSetUp(gwLink); err != nil {
		t.Error(err)
	}

	refRouteTablesStr, _ := ExecOutputTrim("cat /etc/iproute2/rt_tables")
	tcs := []struct {
		// variations
		mode     types.PodEncapMode
		podCIDR  *net.IPNet
		rtTable  *types.ServiceRtTableConfig
		peerCIDR string
		peerIP   net.IP
		// expectations
		expSvcTbl bool
		expIPRule bool
		expRoutes map[int]netlink.Link // keyed on rt id, and val indicates outbound dev
	}{
		{mode: types.PodEncapModeEncap, podCIDR: podCIDR, rtTable: mainRtTable, peerCIDR: "10.10.20.0/24", peerIP: localPeerIP,
			expSvcTbl: false, expIPRule: false, expRoutes: map[int]netlink.Link{mainTblIdx: gwLink}},
		{mode: types.PodEncapModeNoEncap, podCIDR: podCIDR, rtTable: svcRtTable, peerCIDR: "10.10.30.0/24", peerIP: localPeerIP,
			expSvcTbl: true, expIPRule: true, expRoutes: map[int]netlink.Link{svcTblIdx: gwLink, mainTblIdx: nodeLink}},
		{mode: types.PodEncapModeHybrid, podCIDR: podCIDR, rtTable: svcRtTable, peerCIDR: "10.10.40.0/24", peerIP: localPeerIP,
			expSvcTbl: true, expIPRule: true, expRoutes: map[int]netlink.Link{svcTblIdx: gwLink, mainTblIdx: nodeLink}},
		{mode: types.PodEncapModeHybrid, podCIDR: podCIDR, rtTable: svcRtTable, peerCIDR: "10.10.50.0/24", peerIP: remotePeerIP,
			expSvcTbl: true, expIPRule: true, expRoutes: map[int]netlink.Link{svcTblIdx: gwLink, mainTblIdx: gwLink}},
		{mode: types.PodEncapModeNoEncapMasq, podCIDR: nil, rtTable: svcRtTable, peerCIDR: "", peerIP: localPeerIP,
			expSvcTbl: true, expIPRule: true, expRoutes: map[int]netlink.Link{}},
	}

	for _, tc := range tcs {
		signals.CleanupFns = nil
		nodeConfig.PodEncapMode = tc.mode
		nodeConfig.PodCIDR = tc.podCIDR
		nodeConfig.ServiceRtTable = tc.rtTable
		t.Logf("Running test with peer cidr %s peer ip %s node config %s", tc.peerCIDR, tc.peerIP, nodeConfig)
		routeClient := route.NewClient()
		if err := routeClient.Initialize(nodeConfig); err != nil {
			t.Error(err)
		}

		// verify route tables
		expRouteTablesStr := refRouteTablesStr
		if tc.expSvcTbl {
			expRouteTablesStr = fmt.Sprintf("%s%d%s", refRouteTablesStr, nodeConfig.ServiceRtTable.Idx, nodeConfig.ServiceRtTable.Name)
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
			expIPRulesStr = fmt.Sprintf("32765: from all fwmark %#x iif %s lookup %s", iptables.RtTblSelectorValue,
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
			if link.Attrs().Name != gwName {
				nhIP = tc.peerIP
			}
			expRouteStr := fmt.Sprintf("%s via %s dev %s onlink", peerCIDR, nhIP, link.Attrs().Name)
			expRouteStr = strings.Join(strings.Fields(expRouteStr), "")
			ipRoute, _ := ExecOutputTrim(fmt.Sprintf("ip route show table %d | grep %s", tblIdx, tc.peerCIDR))
			if len(ipRoute) > len(expRouteStr) {
				ipRoute = ipRoute[:len(expRouteStr)]
			}
			if !assert.Equal(t, expRouteStr, ipRoute) {
				t.Errorf("mismatch route")
			}
		}

		for _, fn := range signals.CleanupFns {
			if err := fn(); err != nil {
				t.Error(err)
			}
		}

		// verfy route table cleanup works
		routeTables, err = ExecOutputTrim("cat /etc/iproute2/rt_tables")
		if err != nil {
			t.Error(err)
		}
		if !assert.Equal(t, refRouteTablesStr, routeTables) {
			t.Errorf("mismatch route tables after cleanup")
		}
	}
}
