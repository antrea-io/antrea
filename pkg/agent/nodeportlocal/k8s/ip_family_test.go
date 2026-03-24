// Copyright 2026 Antrea Authors
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
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"

	"antrea.io/antrea/v2/pkg/agent/nodeportlocal/types"
)

func TestGetServiceIPFamilies(t *testing.T) {
	tests := []struct {
		name           string
		service        *corev1.Service
		expectedResult []corev1.IPFamily
	}{
		{
			name: "Service with IPFamilies set to dual-stack",
			service: &corev1.Service{
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
				},
			},
			expectedResult: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
		},
		{
			name: "Service with IPFamilies set to IPv6 only",
			service: &corev1.Service{
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv6Protocol},
				},
			},
			expectedResult: []corev1.IPFamily{corev1.IPv6Protocol},
		},
		{
			name: "Service with IPFamilies set to IPv4 only",
			service: &corev1.Service{
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
				},
			},
			expectedResult: []corev1.IPFamily{corev1.IPv4Protocol},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedResult, getServiceIPFamilies(tc.service))
		})
	}
}

func TestGetPodIPForFamily(t *testing.T) {
	tests := []struct {
		name           string
		pod            *corev1.Pod
		ipFamily       corev1.IPFamily
		expectedResult string
	}{
		{
			name: "Pod with IPv4 and IPv6, request IPv4",
			pod: &corev1.Pod{
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{
						{IP: "10.0.1.5"},
						{IP: "fd00::5"},
					},
				},
			},
			ipFamily:       corev1.IPv4Protocol,
			expectedResult: "10.0.1.5",
		},
		{
			name: "Pod with IPv4 and IPv6, request IPv6",
			pod: &corev1.Pod{
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{
						{IP: "10.0.1.5"},
						{IP: "fd00::5"},
					},
				},
			},
			ipFamily:       corev1.IPv6Protocol,
			expectedResult: "fd00::5",
		},
		{
			name: "Pod with only IPv4, request IPv4",
			pod: &corev1.Pod{
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{
						{IP: "10.0.1.5"},
					},
				},
			},
			ipFamily:       corev1.IPv4Protocol,
			expectedResult: "10.0.1.5",
		},
		{
			name: "Pod with only IPv4, request IPv6",
			pod: &corev1.Pod{
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{
						{IP: "10.0.1.5"},
					},
				},
			},
			ipFamily:       corev1.IPv6Protocol,
			expectedResult: "",
		},
		{
			name: "Pod with only IPv6, request IPv6",
			pod: &corev1.Pod{
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{
						{IP: "fd00::5"},
					},
				},
			},
			ipFamily:       corev1.IPv6Protocol,
			expectedResult: "fd00::5",
		},
		{
			name: "Pod with only IPv6, request IPv4",
			pod: &corev1.Pod{
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{
						{IP: "fd00::5"},
					},
				},
			},
			ipFamily:       corev1.IPv4Protocol,
			expectedResult: "",
		},
		{
			name: "Pod with no IPs",
			pod: &corev1.Pod{
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{},
				},
			},
			ipFamily:       corev1.IPv4Protocol,
			expectedResult: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedResult, getPodIPForFamily(tc.pod, tc.ipFamily))
		})
	}
}

func TestIPFamilyForAnnotation(t *testing.T) {
	tests := []struct {
		name           string
		ipFamily       corev1.IPFamily
		expectedResult types.IPFamilyType
	}{
		{
			name:           "IPv4 protocol",
			ipFamily:       corev1.IPv4Protocol,
			expectedResult: types.IPFamilyIPv4,
		},
		{
			name:           "IPv6 protocol",
			ipFamily:       corev1.IPv6Protocol,
			expectedResult: types.IPFamilyIPv6,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedResult, ipFamilyForAnnotation(tc.ipFamily))
		})
	}
}

func TestIPFamilies(t *testing.T) {
	tests := []struct {
		name     string
		ops      func() ipFamilies
		expected []corev1.IPFamily
	}{
		{
			name:     "empty",
			ops:      func() ipFamilies { return ipFamilies(0) },
			expected: nil,
		},
		{
			name:     "IPv4 only",
			ops:      func() ipFamilies { return ipFamilies(0).add(corev1.IPv4Protocol) },
			expected: []corev1.IPFamily{corev1.IPv4Protocol},
		},
		{
			name:     "IPv6 only",
			ops:      func() ipFamilies { return ipFamilies(0).add(corev1.IPv6Protocol) },
			expected: []corev1.IPFamily{corev1.IPv6Protocol},
		},
		{
			name: "dual-stack",
			ops: func() ipFamilies {
				return ipFamilies(0).add(corev1.IPv4Protocol).add(corev1.IPv6Protocol)
			},
			expected: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
		},
		{
			name: "union",
			ops: func() ipFamilies {
				ipf1 := ipFamilies(0).add(corev1.IPv4Protocol)
				ipf2 := ipFamilies(0).add(corev1.IPv6Protocol)
				return ipf1.union(ipf2)
			},
			expected: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
		},
		{
			name: "duplicate add",
			ops: func() ipFamilies {
				return ipFamilies(0).add(corev1.IPv4Protocol).add(corev1.IPv4Protocol)
			},
			expected: []corev1.IPFamily{corev1.IPv4Protocol},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ipf := tc.ops()
			assert.Equal(t, tc.expected, slices.Collect(ipf.values()))
		})
	}
}
