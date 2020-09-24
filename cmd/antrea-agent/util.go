// Copyright 2021 Antrea Authors
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

package main

import (
	"net"

	"antrea.io/antrea/pkg/agent/util"
)

func getAvailableNodePortIPs(nodePortIPsFromConfig []string, gateway string) (map[int][]net.IP, map[int][]net.IP, error) {
	// Get all IP addresses of Node
	nodeIPv4Map, nodeIPv6Map, err := util.GetAllNodeIPs()
	if err != nil {
		return nil, nil, err
	}
	// IP address of Antrea gateway should not be NodePort IP as it cannot be accessed from outside the Cluster.
	gatewayIfIndex := util.GetIndexByName(gateway)
	delete(nodeIPv4Map, gatewayIfIndex)
	delete(nodeIPv6Map, gatewayIfIndex)

	// If option `NodePortAddresses` is not set, then all Node IP addresses will be used as NodePort IP address.
	if len(nodePortIPsFromConfig) == 0 {
		return nodeIPv4Map, nodeIPv6Map, nil
	}

	var nodePortIPNets []*net.IPNet
	for _, nodePortIP := range nodePortIPsFromConfig {
		_, ipNet, _ := net.ParseCIDR(nodePortIP)
		nodePortIPNets = append(nodePortIPNets, ipNet)
	}

	nodePortIPv4Map, nodePortIPv6Map := make(map[int][]net.IP), make(map[int][]net.IP)
	for _, nodePortIPNet := range nodePortIPNets {
		for index, ips := range nodeIPv4Map {
			for i := range ips {
				if nodePortIPNet.Contains(ips[i]) {
					nodePortIPv4Map[index] = append(nodePortIPv4Map[index], ips[i])
				}
			}
		}
		for index, ips := range nodeIPv6Map {
			for i := range ips {
				if nodePortIPNet.Contains(ips[i]) {
					nodePortIPv6Map[index] = append(nodePortIPv6Map[index], ips[i])
				}
			}
		}
	}

	return nodePortIPv4Map, nodePortIPv6Map, nil
}
