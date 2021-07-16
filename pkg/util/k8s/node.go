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

package k8s

import (
	"fmt"
	"net"

	v1 "k8s.io/api/core/v1"

	"antrea.io/antrea/pkg/util/ip"
)

// GetNodeAddrs gets the available IP addresses of a Node. GetNodeAddrs will first try to get the NodeInternalIP, then try
// to get the NodeExternalIP.
// If no error is returned, the returned DualStackIPs includes at least one IPv4 or IPv6 address.
func GetNodeAddrs(node *v1.Node) (*ip.DualStackIPs, error) {
	addresses := make(map[v1.NodeAddressType][]string)
	for _, addr := range node.Status.Addresses {
		addresses[addr.Type] = append(addresses[addr.Type], addr.Address)
	}
	var ipAddrStrs []string
	if internalIP, ok := addresses[v1.NodeInternalIP]; ok {
		ipAddrStrs = internalIP
	} else if externalIP, ok := addresses[v1.NodeExternalIP]; ok {
		ipAddrStrs = externalIP
	} else {
		return nil, fmt.Errorf("Node %s has neither external ip nor internal ip", node.Name)
	}
	if len(ipAddrStrs) == 0 {
		return nil, fmt.Errorf("no IP is found for Node '%s'", node.Name)
	}

	nodeAddrs := new(ip.DualStackIPs)
	for i := range ipAddrStrs {
		addr := net.ParseIP(ipAddrStrs[i])
		if addr == nil {
			return nil, fmt.Errorf("'%s' is not a valid IP address", ipAddrStrs[i])
		}
		if addr.To4() == nil {
			nodeAddrs.IPv6 = addr
		} else {
			nodeAddrs.IPv4 = addr
		}
	}
	return nodeAddrs, nil
}
