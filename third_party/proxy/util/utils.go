/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/*
Copyright 2020 Antrea Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Derived from Kubernetes pkg/proxy/util/utils.go (v1.34.2); Antrea customizations applied.

package util

import (
	"net"
	"strings"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
)

// IsZeroCIDR checks whether the input CIDR string is either
// the IPv4 or IPv6 zero CIDR.
func IsZeroCIDR(cidr *net.IPNet) bool {
	if cidr == nil {
		return false
	}
	prefixLen, _ := cidr.Mask.Size()
	return prefixLen == 0
}

// ShouldSkipService checks if a given service should skip proxying.
func ShouldSkipService(service *v1.Service, skipServices sets.Set[string], serviceLabelSelector labels.Selector) bool {
	// Skip proxying if the Service label doesn't match the selector.
	if !serviceLabelSelector.Matches(labels.Set(service.Labels)) {
		return true
	}
	// if ClusterIP is "None" or empty, skip proxying.
	if service.Spec.ClusterIP == v1.ClusterIPNone || service.Spec.ClusterIP == "" {
		klog.V(3).InfoS("Skipping service due to cluster IP is none or empty", "service", klog.KObj(service), "clusterIP", service.Spec.ClusterIP)
		return true
	}
	// Even if ClusterIP is set, ServiceTypeExternalName services don't get proxied.
	if service.Spec.Type == v1.ServiceTypeExternalName {
		klog.V(3).InfoS("Skipping service due to Type=ExternalName", "service", klog.KObj(service))
		return true
	}
	if skipServices.Len() == 0 {
		return false
	}
	if skipServices.Has(service.Namespace+"/"+service.Name) || skipServices.Has(service.Spec.ClusterIP) {
		klog.InfoS("Skipping service because it matches skipServices list", "service", klog.KObj(service))
		return true
	}
	return false
}

// GetClusterIPByFamily returns a service cluster IP by family.
func GetClusterIPByFamily(ipFamily v1.IPFamily, service *v1.Service) string {
	// allowing skew
	if len(service.Spec.IPFamilies) == 0 {
		if len(service.Spec.ClusterIP) == 0 || service.Spec.ClusterIP == v1.ClusterIPNone {
			return ""
		}

		isIPv6Family := ipFamily == v1.IPv6Protocol
		if isIPv6Family == netutils.IsIPv6String(service.Spec.ClusterIP) {
			return service.Spec.ClusterIP
		}

		return ""
	}

	for idx, family := range service.Spec.IPFamilies {
		if family == ipFamily {
			if idx < len(service.Spec.ClusterIPs) {
				return service.Spec.ClusterIPs[idx]
			}
		}
	}

	return ""
}

// MapIPsByIPFamily maps a slice of IPs to their respective IP families (v4 or v6).
func MapIPsByIPFamily(ipStrings []string) map[v1.IPFamily][]net.IP {
	ipFamilyMap := map[v1.IPFamily][]net.IP{}
	for _, ipStr := range ipStrings {
		ip := netutils.ParseIPSloppy(ipStr)
		if ip != nil {
			// Since ip is parsed ok, GetIPFamilyFromIP will never return v1.IPFamilyUnknown.
			ipFamily := GetIPFamilyFromIP(ip)
			ipFamilyMap[ipFamily] = append(ipFamilyMap[ipFamily], ip)
		} else {
			// ExternalIPs may not be validated by the API server.
			// Specifically empty strings validation, which yields into a lot of bad error logs.
			if len(strings.TrimSpace(ipStr)) != 0 {
				klog.ErrorS(nil, "Skipping invalid IP", "ip", ipStr)
			}
		}
	}
	return ipFamilyMap
}

// MapCIDRsByIPFamily maps a slice of CIDRs to their respective IP families (v4 or v6).
func MapCIDRsByIPFamily(cidrsStrings []string) map[v1.IPFamily][]*net.IPNet {
	ipFamilyMap := map[v1.IPFamily][]*net.IPNet{}
	for _, cidrStrUntrimmed := range cidrsStrings {
		cidrStr := strings.TrimSpace(cidrStrUntrimmed)
		_, cidr, err := netutils.ParseCIDRSloppy(cidrStr)
		if err != nil {
			// Ignore empty strings. Same as in MapIPsByIPFamily.
			if len(cidrStr) != 0 {
				klog.ErrorS(err, "Invalid CIDR ignored", "CIDR", cidrStr)
			}
			continue
		}
		// since we just successfully parsed the CIDR, IPFamilyOfCIDR will never return "IPFamilyUnknown".
		ipFamily := convertToV1IPFamily(netutils.IPFamilyOfCIDR(cidr))
		ipFamilyMap[ipFamily] = append(ipFamilyMap[ipFamily], cidr)
	}
	return ipFamilyMap
}

// GetIPFamilyFromIP returns the IP family of ipStr, or IPFamilyUnknown if ipStr can't be parsed as an IP.
func GetIPFamilyFromIP(ip net.IP) v1.IPFamily {
	return convertToV1IPFamily(netutils.IPFamilyOf(ip))
}

// Convert netutils.IPFamily to v1.IPFamily.
func convertToV1IPFamily(ipFamily netutils.IPFamily) v1.IPFamily {
	switch ipFamily {
	case netutils.IPv4:
		return v1.IPv4Protocol
	case netutils.IPv6:
		return v1.IPv6Protocol
	}

	return v1.IPFamilyUnknown
}

func IsVIPMode(ing v1.LoadBalancerIngress) bool {
	if ing.IPMode == nil {
		return true
	}
	return *ing.IPMode == v1.LoadBalancerIPModeVIP
}
