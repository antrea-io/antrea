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
// Copyright 2020 Antrea Authors
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

Modifies:
- Remove imports: "errors", "strconv", "k8s.io/apimachinery/pkg/util/rand",
  "k8s.io/apimachinery/pkg/util/sets", "k8s.io/kubernetes/pkg/apis/core/v1/helper"
- Remove consts: "IPv4ZeroCIDR", "IPv6ZeroCIDR"
- Remove vars: "ErrAddressNotAllowed", "ErrNoAddresses"
- Remove functions: "isValidEndpoint", "BuildPortsToEndpointsMap", "IsZeroCIDR",
  "IsProxyableIP", "isProxyableIP", "IsProxyableHostname", "IsLocalIP", "GetNodeAddresses".
*/
package util

import (
	"context"
	"errors"
	"fmt"
	"net"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/record"
	utilnet "k8s.io/utils/net"

	"k8s.io/klog/v2"
)

var (
	// ErrAddressNotAllowed indicates the address is not allowed
	ErrAddressNotAllowed = errors.New("address not allowed")

	// ErrNoAddresses indicates there are no addresses for the hostname
	ErrNoAddresses = errors.New("No addresses for hostname")
)

// Resolver is an interface for net.Resolver
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// ShouldSkipService checks if a given service should skip proxying
func ShouldSkipService(service *v1.Service, skipServices sets.String) bool {
	// if ClusterIP is "None" or empty, skip proxying
	if service.Spec.ClusterIP == v1.ClusterIPNone || service.Spec.ClusterIP == "" {
		klog.V(3).Infof("Skipping service %s in namespace %s due to clusterIP = %q", service.Name, service.Namespace, service.Spec.ClusterIP)
		return true
	}
	// Even if ClusterIP is set, ServiceTypeExternalName services don't get proxied
	if service.Spec.Type == v1.ServiceTypeExternalName {
		klog.V(3).Infof("Skipping service %s in namespace %s due to Type=ExternalName", service.Name, service.Namespace)
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

// LogAndEmitIncorrectIPVersionEvent logs and emits incorrect IP version event.
func LogAndEmitIncorrectIPVersionEvent(recorder record.EventRecorder, fieldName, fieldValue, svcNamespace, svcName string, svcUID types.UID) {
	errMsg := fmt.Sprintf("%s in %s has incorrect IP version", fieldValue, fieldName)
	klog.Errorf("%s (service %s/%s).", errMsg, svcNamespace, svcName)
	if recorder != nil {
		recorder.Eventf(
			&v1.ObjectReference{
				Kind:      "Service",
				Name:      svcName,
				Namespace: svcNamespace,
				UID:       svcUID,
			}, v1.EventTypeWarning, "KubeProxyIncorrectIPVersion", errMsg)
	}
}

// FilterIncorrectIPVersion filters out the incorrect IP version case from a slice of IP strings.
func FilterIncorrectIPVersion(ipStrings []string, isIPv6Mode bool) ([]string, []string) {
	return filterWithCondition(ipStrings, isIPv6Mode, utilnet.IsIPv6String)
}

// FilterIncorrectCIDRVersion filters out the incorrect IP version case from a slice of CIDR strings.
func FilterIncorrectCIDRVersion(ipStrings []string, isIPv6Mode bool) ([]string, []string) {
	return filterWithCondition(ipStrings, isIPv6Mode, utilnet.IsIPv6CIDRString)
}

func filterWithCondition(strs []string, expectedCondition bool, conditionFunc func(string) bool) ([]string, []string) {
	var corrects, incorrects []string
	for _, str := range strs {
		if conditionFunc(str) != expectedCondition {
			incorrects = append(incorrects, str)
		} else {
			corrects = append(corrects, str)
		}
	}
	return corrects, incorrects
}

// GetClusterIPByFamily returns a service clusterip by family
func GetClusterIPByFamily(ipFamily v1.IPFamily, service *v1.Service) string {
	// allowing skew
	if len(service.Spec.IPFamilies) == 0 {
		if len(service.Spec.ClusterIP) == 0 || service.Spec.ClusterIP == v1.ClusterIPNone {
			return ""
		}

		IsIPv6Family := (ipFamily == v1.IPv6Protocol)
		if IsIPv6Family == utilnet.IsIPv6String(service.Spec.ClusterIP) {
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

// MapIPsByIPFamily maps a slice of IPs to their respective IP families (v4 or v6)
func MapIPsByIPFamily(ipStrings []string) map[v1.IPFamily][]string {
	ipFamilyMap := map[v1.IPFamily][]string{}
	for _, ip := range ipStrings {
		// Handle only the valid IPs
		if ipFamily, err := getIPFamilyFromIP(ip); err == nil {
			ipFamilyMap[ipFamily] = append(ipFamilyMap[ipFamily], ip)
		} else {
			klog.Errorf("Skipping invalid IP: %s", ip)
		}
	}
	return ipFamilyMap
}

func getIPFamilyFromIP(ipStr string) (v1.IPFamily, error) {
	netIP := net.ParseIP(ipStr)
	if netIP == nil {
		return "", ErrAddressNotAllowed
	}

	if utilnet.IsIPv6(netIP) {
		return v1.IPv6Protocol, nil
	}
	return v1.IPv4Protocol, nil
}

// OtherIPFamily returns the other ip family
func OtherIPFamily(ipFamily v1.IPFamily) v1.IPFamily {
	if ipFamily == v1.IPv6Protocol {
		return v1.IPv4Protocol
	}

	return v1.IPv6Protocol
}

// MapCIDRsByIPFamily maps a slice of IPs to their respective IP families (v4 or v6)
func MapCIDRsByIPFamily(cidrStrings []string) map[v1.IPFamily][]string {
	ipFamilyMap := map[v1.IPFamily][]string{}
	for _, cidr := range cidrStrings {
		// Handle only the valid CIDRs
		if ipFamily, err := getIPFamilyFromCIDR(cidr); err == nil {
			ipFamilyMap[ipFamily] = append(ipFamilyMap[ipFamily], cidr)
		} else {
			klog.Errorf("Skipping invalid cidr: %s", cidr)
		}
	}
	return ipFamilyMap
}

func getIPFamilyFromCIDR(cidrStr string) (v1.IPFamily, error) {
	_, netCIDR, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return "", ErrAddressNotAllowed
	}
	if utilnet.IsIPv6CIDR(netCIDR) {
		return v1.IPv6Protocol, nil
	}
	return v1.IPv4Protocol, nil
}
