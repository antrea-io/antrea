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

package testing

import (
	"net"
	"strings"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
)

func GenerateIPAMResult(cniVersion string, ipConfig []string, routeConfig []string, dnsConfig []string) *current.Result {
	ipamResult := &current.Result{}
	if cniVersion != "" {
		ipamResult.CNIVersion = cniVersion
	} else {
		ipamResult.CNIVersion = "0.3.1"
	}
	ipamResult.IPs = parseIPs(ipConfig)
	ipamResult.Routes = parseRoute(routeConfig)
	ipamResult.DNS = types.DNS{Nameservers: dnsConfig}
	return ipamResult
}

func parseRoute(routeConfig []string) []*types.Route {
	routes := make([]*types.Route, 0)
	for _, rt := range routeConfig {
		route := strings.Split(rt, ",")
		_, dst, _ := net.ParseCIDR(strings.Trim(route[0], " "))
		routeCfg := &types.Route{Dst: *dst}
		if len(route) == 2 {
			gw := net.ParseIP(strings.Trim(route[1], " "))
			routeCfg.GW = gw
		}
		routes = append(routes, routeCfg)
	}
	return routes
}

func parseIPs(ips []string) []*current.IPConfig {
	ipConfigs := make([]*current.IPConfig, 0)
	for _, ipc := range ips {
		configs := strings.Split(ipc, ",")
		addr := strings.Trim(configs[0], " ")
		gw := strings.Trim(configs[1], " ")
		version := strings.Trim(configs[2], " ")
		ipConfigs = append(ipConfigs, parseIPConfig(addr, gw, version))
	}
	return ipConfigs
}

func parseIPConfig(ipAddress string, gw string, version string) *current.IPConfig {
	ip, ipv4Net, _ := net.ParseCIDR(ipAddress)
	ipv4Net.IP = ip
	ipConfig := &current.IPConfig{Version: version, Address: *ipv4Net}
	if gw != "" {
		gateway := net.ParseIP(gw)
		ipConfig.Gateway = gateway
	}
	return ipConfig
}
