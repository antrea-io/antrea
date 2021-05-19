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
)

// GetNodeAddr gets the available IP address of a Node. GetNodeAddr will first try to get the NodeInternalIP, then try
// to get the NodeExternalIP.
// Note: Although K8s supports dual-stack, there is only a single Internal address per Node because of issue (
// kubernetes/kubernetes#91940 ). The Node might have multiple addresses after the issue is fixed, and one per address
// family. And we should change the return type at that time.
func GetNodeAddr(node *v1.Node) (net.IP, error) {
	addresses := make(map[v1.NodeAddressType]string)
	for _, addr := range node.Status.Addresses {
		addresses[addr.Type] = addr.Address
	}
	var ipAddrStr string
	if internalIP, ok := addresses[v1.NodeInternalIP]; ok {
		ipAddrStr = internalIP
	} else if externalIP, ok := addresses[v1.NodeExternalIP]; ok {
		ipAddrStr = externalIP
	} else {
		return nil, fmt.Errorf("Node %s has neither external ip nor internal ip", node.Name)
	}
	ipAddr := net.ParseIP(ipAddrStr)
	if ipAddr == nil {
		return nil, fmt.Errorf("<%v> is not a valid ip address", ipAddrStr)
	}
	return ipAddr, nil
}
