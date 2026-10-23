// Copyright 2026 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/utils/ptr"
)

// SubsetsToEndpoints converts legacy EndpointSubsets to discovery/v1 types.
// It only converts ready Addresses, filters out non-IPv4 addresses, and ensures
// ports have their protocol defaulted to TCP if unspecified.
func SubsetsToEndpoints(subsets []corev1.EndpointSubset) ([]discoveryv1.Endpoint, []discoveryv1.EndpointPort) {
	var endpoints []discoveryv1.Endpoint
	var ports []discoveryv1.EndpointPort
	portSeen := make(map[string]bool)

	for _, subset := range subsets {
		for _, addr := range subset.Addresses {
			ip := net.ParseIP(addr.IP)
			if ip == nil || ip.To4() == nil {
				continue
			}
			endpoints = append(endpoints, discoveryv1.Endpoint{
				Addresses: []string{addr.IP},
				Conditions: discoveryv1.EndpointConditions{
					Ready: ptr.To(true),
				},
			})
		}
		for _, p := range subset.Ports {
			proto := p.Protocol
			if proto == "" {
				proto = corev1.ProtocolTCP
			}
			var name *string
			if p.Name != "" {
				name = ptr.To(p.Name)
			}
			port := p.Port
			key := fmt.Sprintf("%s/%d/%s", p.Name, port, proto)
			if !portSeen[key] {
				portSeen[key] = true
				ports = append(ports, discoveryv1.EndpointPort{
					Name:        name,
					Port:        &port,
					Protocol:    &proto,
					AppProtocol: p.AppProtocol,
				})
			}
		}
	}
	return endpoints, ports
}

// EndpointsToSubsets converts discovery/v1 endpoint data back to EndpointSubsets
// so that member controllers running an older version can still consume it.
func EndpointsToSubsets(endpoints []discoveryv1.Endpoint, ports []discoveryv1.EndpointPort) []corev1.EndpointSubset {
	var addresses []corev1.EndpointAddress
	addrSeen := make(map[string]bool)
	for _, ep := range endpoints {
		// Treat nil Ready as ready per Kubernetes API conventions.
		if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
			continue
		}
		for _, addr := range ep.Addresses {
			if !addrSeen[addr] {
				addrSeen[addr] = true
				addresses = append(addresses, corev1.EndpointAddress{IP: addr})
			}
		}
	}

	var epPorts []corev1.EndpointPort
	for _, p := range ports {
		var name string
		if p.Name != nil {
			name = *p.Name
		}
		var port int32
		if p.Port != nil {
			port = *p.Port
		}
		proto := corev1.ProtocolTCP
		if p.Protocol != nil && *p.Protocol != "" {
			proto = *p.Protocol
		}
		epPorts = append(epPorts, corev1.EndpointPort{
			Name:        name,
			Port:        port,
			Protocol:    proto,
			AppProtocol: p.AppProtocol,
		})
	}

	if len(addresses) == 0 && len(epPorts) == 0 {
		return nil
	}
	return []corev1.EndpointSubset{
		{
			Addresses: addresses,
			Ports:     epPorts,
		},
	}
}

// SanitizeEndpoint strips fields that reference objects in the source cluster
// (NodeName, TargetRef, Hostname, Hints, DeprecatedTopology), retaining only
// Addresses and Conditions.
func SanitizeEndpoint(ep discoveryv1.Endpoint) discoveryv1.Endpoint {
	var addrs []string
	if ep.Addresses != nil {
		addrs = make([]string, len(ep.Addresses))
		copy(addrs, ep.Addresses)
	}
	return discoveryv1.Endpoint{
		Addresses:  addrs,
		Conditions: ep.Conditions,
	}
}

// EndpointAddressType derives the EndpointSlice addressType from the addresses.
// It returns an error if an invalid IP or mixed address families are detected.
func EndpointAddressType(endpoints []discoveryv1.Endpoint) (discoveryv1.AddressType, error) {
	hasIPv4 := false
	hasIPv6 := false
	for _, ep := range endpoints {
		for _, addr := range ep.Addresses {
			ip := net.ParseIP(addr)
			if ip == nil {
				return "", fmt.Errorf("invalid IP address %q", addr)
			}
			if ip.To4() != nil {
				hasIPv4 = true
			} else {
				hasIPv6 = true
			}
		}
	}
	if hasIPv4 && hasIPv6 {
		return "", fmt.Errorf("mixed address families found in endpoints")
	}
	if hasIPv6 {
		return discoveryv1.AddressTypeIPv6, nil
	}
	return discoveryv1.AddressTypeIPv4, nil
}
