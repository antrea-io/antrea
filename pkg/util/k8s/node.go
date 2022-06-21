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
	"strings"

	ip2 "github.com/containernetworking/plugins/pkg/ip"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/types"
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

// GetNodeAddrsFromAnnotations gets available IPs from the Node Annotation. The annotations are set by Antrea.
func GetNodeAddrsFromAnnotations(node *v1.Node, annotationKey string) (*ip.DualStackIPs, error) {
	annotationAddrsStr := node.Annotations[annotationKey]
	if annotationAddrsStr == "" {
		return nil, nil
	}
	var ipAddrs = new(ip.DualStackIPs)
	for _, addr := range strings.Split(annotationAddrsStr, ",") {
		peerNodeAddr := net.ParseIP(addr)
		if peerNodeAddr == nil {
			return nil, fmt.Errorf("invalid annotation for ip-address on Node %s: %s", node.Name, annotationAddrsStr)
		}
		if peerNodeAddr.To4() == nil {
			ipAddrs.IPv6 = peerNodeAddr
		} else {
			ipAddrs.IPv4 = peerNodeAddr
		}
	}
	return ipAddrs, nil
}

// GetNodeGatewayAddrs gets Node Antrea gateway IPs from the Node Spec.
func GetNodeGatewayAddrs(node *v1.Node) (*ip.DualStackIPs, error) {
	nodeAddrs := new(ip.DualStackIPs)
	parseIP := func(podCIDR string) error {
		cidrIP, _, err := net.ParseCIDR(podCIDR)
		if err != nil {
			return err
		}
		if cidrIP.To4() != nil {
			nodeAddrs.IPv4 = ip2.NextIP(cidrIP)
		} else {
			nodeAddrs.IPv6 = ip2.NextIP(cidrIP)
		}
		return nil
	}
	if node.Spec.PodCIDRs != nil {
		for _, podCIDR := range node.Spec.PodCIDRs {
			if err := parseIP(podCIDR); err != nil {
				return nil, err
			}
		}
		return nodeAddrs, nil
	}
	if err := parseIP(node.Spec.PodCIDR); err != nil {
		return nil, err
	}
	return nodeAddrs, nil
}

// GetNodeAllAddrs gets all Node IPs from the Node.
func GetNodeAllAddrs(node *v1.Node) (ips sets.String, err error) {
	var nodeIPs, gwIPs, transportAddrs *ip.DualStackIPs
	ips = sets.String{}
	appendIP := func(dsIPs *ip.DualStackIPs) {
		if dsIPs == nil {
			return
		}
		if dsIPs.IPv4 != nil {
			ips.Insert(dsIPs.IPv4.String())
		}
		if dsIPs.IPv6 != nil {
			ips.Insert(dsIPs.IPv6.String())
		}
	}

	if nodeIPs, err = GetNodeAddrs(node); err != nil {
		return
	}
	appendIP(nodeIPs)

	if gwIPs, err = GetNodeGatewayAddrs(node); err != nil {
		return
	}
	appendIP(gwIPs)

	if transportAddrs, err = GetNodeAddrsFromAnnotations(node, types.NodeTransportAddressAnnotationKey); err != nil {
		return
	}
	appendIP(transportAddrs)

	return
}
