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

	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/util"
	k8sutil "antrea.io/antrea/v2/pkg/util/k8s"
)

var (
	// Declared variables which are meant to be overridden for testing.
	getAllNodeAddresses = util.GetAllNodeAddresses

	getPodCIDRsFromKubeProxy = k8sutil.GetPodCIDRsFromKubeProxy
	getPodCIDRsFromKubeadm   = k8sutil.GetPodCIDRsFromKubeadm
)

func getAvailableNodePortAddresses(nodePortAddressesFromConfig []string, excludeDevices []string, excludeDevicePrefixes []string) ([]net.IP, []net.IP, error) {
	excludeDeviceMatchers := make([]func(string) bool, 0)
	for _, device := range excludeDevices {
		excludeDeviceMatchers = append(excludeDeviceMatchers, func(name string) bool {
			return name == device
		})
	}
	for _, devicePrefix := range excludeDevicePrefixes {
		excludeDeviceMatchers = append(excludeDeviceMatchers, func(name string) bool {
			return strings.HasPrefix(name, devicePrefix)
		})
	}
	// Get all IP addresses of Node
	nodeAddressesIPv4, nodeAddressesIPv6, err := getAllNodeAddresses(excludeDeviceMatchers)
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

// parsePortRange parses a port range ("<start>-<end>") and checks that it is valid.
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
		return 0, 0, fmt.Errorf("start port must be smaller than end port: %s", portRangeStr)
	}

	return start, end, nil
}

// getPodCIDRs gets the cluster-wide Pod CIDRs (IPv4 and IPv6) by attempting the following sources in order:
// 1. Agent configuration if field `podCIDRs` is not empty.
// 2. kube-proxy ConfigMap.
// 3. kubeadm-config ConfigMap.
func getPodCIDRs(o *Options, k8sClient clientset.Interface) ([]*net.IPNet, error) {
	klog.V(2).InfoS("Trying to find Pod CIDRs from antrea-agent configuration")
	podCIDRsStr := strings.TrimSpace(o.config.PodCIDRs)
	if podCIDRsStr != "" {
		return parseCIDRs(podCIDRsStr)
	}
	klog.V(2).InfoS("Field 'PodCIDRs' is not configured in antrea-agent configuration")

	klog.V(2).InfoS("Trying to find Pod CIDRs from ConfigMap kube-proxy")
	podCIDRsStr = getPodCIDRsFromKubeProxy(k8sClient)
	cidrs, err := parseCIDRs(podCIDRsStr)
	if err == nil {
		return cidrs, nil
	}
	klog.V(2).InfoS("Failed to find ConfigMap Pod CIDRs from ConfigMap kube-proxy")

	klog.V(2).InfoS("Trying to find Pod CIDRs from ConfigMap kubeadm-config")
	podCIDRsStr = getPodCIDRsFromKubeadm(k8sClient)
	cidrs, err = parseCIDRs(podCIDRsStr)
	if err == nil {
		return cidrs, nil
	}
	klog.V(2).InfoS("Failed to find ConfigMap Pod CIDRs from ConfigMap kubeadm-config")

	return nil, nil
}

func parseCIDRs(s string) ([]*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty CIDR string")
	}

	var cidrs []*net.IPNet
	for _, cidrStr := range strings.Split(s, ",") {
		cidrStr = strings.TrimSpace(cidrStr)
		if cidrStr == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %s: %w", cidrStr, err)
		}
		cidrs = append(cidrs, cidr)
	}
	return cidrs, nil
}
