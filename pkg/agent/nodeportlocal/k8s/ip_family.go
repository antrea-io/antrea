// Copyright 2025 Antrea Authors
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
	"iter"

	corev1 "k8s.io/api/core/v1"
	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/pkg/agent/nodeportlocal/types"
)

// ipFamilies implements a set of IP families using a bitmask.
// It is an efficient implementation, without any memory allocation.
type ipFamilies int

const (
	ipv4Offset = 4
	ipv6Offset = 6
)

func (ipf ipFamilies) add(ipFamily corev1.IPFamily) ipFamilies {
	if ipFamily == corev1.IPv4Protocol {
		ipf |= (1 << ipv4Offset)
	} else {
		ipf |= (1 << ipv6Offset)
	}
	return ipf
}

func (ipf ipFamilies) union(other ipFamilies) ipFamilies {
	return ipf | other
}

func (ipf ipFamilies) values() iter.Seq[corev1.IPFamily] {
	return func(yield func(ipFamily corev1.IPFamily) bool) {
		if ipf&(1<<ipv4Offset) != 0 && !yield(corev1.IPv4Protocol) {
			return
		}
		if ipf&(1<<ipv6Offset) != 0 && !yield(corev1.IPv6Protocol) {
			return
		}
	}
}

// getServiceIPFamilies returns the IP families required by a Service.
func getServiceIPFamilies(svc *corev1.Service) []corev1.IPFamily {
	return svc.Spec.IPFamilies
}

// getPodIPForFamily returns the Pod IP matching the specified IP family.
// Returns empty string if no matching IP is found.
func getPodIPForFamily(pod *corev1.Pod, ipFamily corev1.IPFamily) string {
	for _, podIP := range pod.Status.PodIPs {
		isIPv6 := utilnet.IsIPv6String(podIP.IP)
		if ipFamily == corev1.IPv6Protocol && isIPv6 {
			return podIP.IP
		}
		if ipFamily == corev1.IPv4Protocol && !isIPv6 {
			return podIP.IP
		}
	}
	return ""
}

// ipFamilyToString converts corev1.IPFamily to a string for annotation.
// ipFamilyForAnnotation converts a corev1.IPFamily to the IPFamilyType used in NPL annotations.
func ipFamilyForAnnotation(ipFamily corev1.IPFamily) types.IPFamilyType {
	if ipFamily == corev1.IPv6Protocol {
		return types.IPFamilyIPv6
	}
	return types.IPFamilyIPv4
}
