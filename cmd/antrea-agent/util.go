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
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/util"
)

var getAllNodeAddresses = util.GetAllNodeAddresses

const (
	configMapKubeProxy = "kube-proxy"
	configMapKubeadm   = "kubeadm-config"
)

func getAvailableNodePortAddresses(nodePortAddressesFromConfig []string, excludeDevices []string) ([]net.IP, []net.IP, error) {
	// Get all IP addresses of Node
	nodeAddressesIPv4, nodeAddressesIPv6, err := getAllNodeAddresses(excludeDevices)
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

func parseCIDRs(s string) []*net.IPNet {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	var cidrs []*net.IPNet
	for _, cidrStr := range strings.Split(s, ",") {
		cidrStr = strings.TrimSpace(cidrStr)
		if cidrStr == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			klog.ErrorS(err, "Failed to parse CIDR", "cidrStr", cidrStr)
			continue
		}
		cidrs = append(cidrs, cidr)
	}
	return cidrs
}

// getPodCIDRs gets the cluster-wide Pod CIDRs (IPv4 and IPv6) by attempting the following sources in order:
// 1. Agent configuration.
// 2. kube-proxy ConfigMap.
// 3. kubeadm-config ConfigMap.
func getPodCIDRStr(o *Options, k8sClient clientset.Interface) string {
	// Get Pod CIDR from agent config
	podCIDRStr := o.config.PodCIDR
	if podCIDRStr != "" {
		return podCIDRStr
	}

	// Try kube-proxy ConfigMap
	klog.V(2).InfoS("Trying to find Pod CIDRs in ConfigMap kube-proxy")
	podCIDRStr = extractPodCIDRFromConfigMap(k8sClient, configMapKubeProxy, "config.conf", "clusterCIDR")
	if podCIDRStr != "" {
		return podCIDRStr
	}

	// Try kubeadm-config ConfigMap
	klog.V(2).InfoS("Trying to find Pod CIDRs in ConfigMap kubeadm-config")
	podCIDRStr = extractPodCIDRFromConfigMap(k8sClient, configMapKubeadm, "ClusterConfiguration", "networking.podSubnet")
	if podCIDRStr != "" {
		return podCIDRStr
	}

	klog.V(2).InfoS("No Pod CIDRs found")
	return ""
}

func extractPodCIDRFromConfigMap(client clientset.Interface, name, key, path string) string {
	cm, err := client.CoreV1().ConfigMaps(metav1.NamespaceSystem).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		klog.ErrorS(err, "Failed to get ConfigMap", "ConfigMap", name)
		return ""
	}
	data, ok := cm.Data[key]
	if !ok {
		klog.InfoS("Key is not found from ConfigMap", "ConfigMap", name, "key", key)
		return ""
	}

	var m map[string]interface{}
	if err := yaml.Unmarshal([]byte(data), &m); err != nil {
		klog.ErrorS(err, "Failed to unmarshal ConfigMap data as YAML", "ConfigMap", name)
		return ""
	}

	podCIDRStr, ok := getNestedValue(m, path)
	if !ok {
		klog.InfoS("Path is not found in ConfigMap", "ConfigMap", name, "path", path)
		return ""
	}

	return podCIDRStr
}

func getNestedValue(m map[string]any, path string) (string, bool) {
	cur := any(m)
	for _, k := range strings.Split(path, ".") {
		next, ok := cur.(map[string]interface{})
		if !ok {
			return "", false
		}
		cur, ok = next[k]
		if !ok {
			return "", false
		}
	}
	s, ok := cur.(string)
	if !ok {
		return "", false
	}
	return s, true
}
