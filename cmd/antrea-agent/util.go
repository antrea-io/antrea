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
	"fmt"
	"net"
	"strconv"
	"strings"

	"antrea.io/antrea/pkg/agent/util"
)

func getAvailableNodePortAddresses(nodePortAddressesFromConfig []string, excludeDevices []string) ([]net.IP, []net.IP, error) {
	// Get all IP addresses of Node
	nodeAddressesIPv4, nodeAddressesIPv6, err := util.GetAllNodeAddresses(excludeDevices)
	if err != nil {
		return nil, nil, err
	}
	// If option `NodePortAddresses` is not set, then all Node IP addresses will be used as NodePort IP address.
	if len(nodePortAddressesFromConfig) == 0 {
		return nodeAddressesIPv4, nodeAddressesIPv6, nil
	}

	var nodePortIPNets []*net.IPNet
	for _, nodePortIP := range nodePortAddressesFromConfig {
		_, ipNet, _ := net.ParseCIDR(nodePortIP)
		nodePortIPNets = append(nodePortIPNets, ipNet)
	}

	var nodePortAddressesIPv4, nodePortAddressesIPv6 []net.IP
	for _, nodePortIPNet := range nodePortIPNets {
		for i := range nodeAddressesIPv4 {
			if nodePortIPNet.Contains(nodeAddressesIPv4[i]) {
				nodePortAddressesIPv4 = append(nodePortAddressesIPv4, nodeAddressesIPv4[i])
			}
		}
		for i := range nodeAddressesIPv6 {
			if nodePortIPNet.Contains(nodeAddressesIPv6[i]) {
				nodePortAddressesIPv6 = append(nodePortAddressesIPv6, nodeAddressesIPv6[i])
			}
		}
	}

	return nodePortAddressesIPv4, nodePortAddressesIPv6, nil
}

// parsePortRange parses a port range ("<start>-<end>") and checks that it is  valid.
func parsePortRange(portRangeStr string) (start, end int, err error) {
	portsRange := strings.Split(portRangeStr, "-")
	if len(portsRange) != 2 {
		return 0, 0, fmt.Errorf("wrong port range format: %s", portRangeStr)
	}

	if start, err = strconv.Atoi(portsRange[0]); err != nil {
		return 0, 0, err
	}

	if end, err = strconv.Atoi(portsRange[1]); err != nil {
		return 0, 0, err
	}

	if end <= start {
		return 0, 0, fmt.Errorf("start port must be less than end port: %s", portRangeStr)
	}

	return start, end, nil
}
