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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/utils/ptr"
)

func TestSubsetsToEndpoints(t *testing.T) {
	tests := []struct {
		name          string
		subsets       []corev1.EndpointSubset
		wantEndpoints []discoveryv1.Endpoint
		wantPorts     []discoveryv1.EndpointPort
	}{
		{
			name:          "nil or empty subsets",
			subsets:       nil,
			wantEndpoints: nil,
			wantPorts:     nil,
		},
		{
			name: "single subset with IPv4 and ports",
			subsets: []corev1.EndpointSubset{
				{
					Addresses: []corev1.EndpointAddress{
						{IP: "10.10.1.1"},
						{IP: "10.10.1.2"},
					},
					Ports: []corev1.EndpointPort{
						{
							Name:     "http",
							Port:     80,
							Protocol: corev1.ProtocolTCP,
						},
						{
							Name: "unspecified-proto",
							Port: 8080,
						},
					},
				},
			},
			wantEndpoints: []discoveryv1.Endpoint{
				{
					Addresses:  []string{"10.10.1.1"},
					Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
				},
				{
					Addresses:  []string{"10.10.1.2"},
					Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
				},
			},
			wantPorts: []discoveryv1.EndpointPort{
				{
					Name:     ptr.To("http"),
					Port:     ptr.To(int32(80)),
					Protocol: ptr.To(corev1.ProtocolTCP),
				},
				{
					Name:     ptr.To("unspecified-proto"),
					Port:     ptr.To(int32(8080)),
					Protocol: ptr.To(corev1.ProtocolTCP),
				},
			},
		},
		{
			name: "filters out IPv6 addresses and keeps only IPv4",
			subsets: []corev1.EndpointSubset{
				{
					Addresses: []corev1.EndpointAddress{
						{IP: "2001:db8::1"},
						{IP: "192.168.1.10"},
					},
					Ports: []corev1.EndpointPort{
						{
							Name: "",
							Port: 443,
						},
					},
				},
			},
			wantEndpoints: []discoveryv1.Endpoint{
				{
					Addresses:  []string{"192.168.1.10"},
					Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
				},
			},
			wantPorts: []discoveryv1.EndpointPort{
				{
					Name:     nil,
					Port:     ptr.To(int32(443)),
					Protocol: ptr.To(corev1.ProtocolTCP),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEndpoints, gotPorts := SubsetsToEndpoints(tt.subsets)
			assert.Equal(t, tt.wantEndpoints, gotEndpoints)
			assert.Equal(t, tt.wantPorts, gotPorts)
		})
	}
}

func TestEndpointsToSubsets(t *testing.T) {
	tests := []struct {
		name      string
		endpoints []discoveryv1.Endpoint
		ports     []discoveryv1.EndpointPort
		want      []corev1.EndpointSubset
	}{
		{
			name:      "empty endpoints and ports",
			endpoints: nil,
			ports:     nil,
			want:      nil,
		},
		{
			name: "ready endpoints and ports conversion",
			endpoints: []discoveryv1.Endpoint{
				{
					Addresses:  []string{"10.0.0.1"},
					Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
				},
				{
					Addresses:  []string{"10.0.0.2"},
					Conditions: discoveryv1.EndpointConditions{Ready: nil}, // nil Ready is treated as ready
				},
				{
					Addresses:  []string{"10.0.0.3"},
					Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false)}, // not ready, skip
				},
			},
			ports: []discoveryv1.EndpointPort{
				{
					Name:     ptr.To("http"),
					Port:     ptr.To(int32(80)),
					Protocol: ptr.To(corev1.ProtocolTCP),
				},
				{
					Name: nil,
					Port: ptr.To(int32(8080)),
				},
			},
			want: []corev1.EndpointSubset{
				{
					Addresses: []corev1.EndpointAddress{
						{IP: "10.0.0.1"},
						{IP: "10.0.0.2"},
					},
					Ports: []corev1.EndpointPort{
						{
							Name:     "http",
							Port:     80,
							Protocol: corev1.ProtocolTCP,
						},
						{
							Name:     "",
							Port:     8080,
							Protocol: corev1.ProtocolTCP,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EndpointsToSubsets(tt.endpoints, tt.ports)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRoundTripSubsetsAndEndpoints(t *testing.T) {
	originalSubsets := []corev1.EndpointSubset{
		{
			Addresses: []corev1.EndpointAddress{
				{IP: "192.168.1.1"},
				{IP: "192.168.1.2"},
			},
			Ports: []corev1.EndpointPort{
				{
					Name:     "web",
					Port:     80,
					Protocol: corev1.ProtocolTCP,
				},
			},
		},
	}

	endpoints, ports := SubsetsToEndpoints(originalSubsets)
	require.Len(t, endpoints, 2)
	require.Len(t, ports, 1)

	subsets := EndpointsToSubsets(endpoints, ports)
	assert.Equal(t, originalSubsets, subsets)
}

func TestSanitizeEndpoint(t *testing.T) {
	nodeName := "node-1"
	hostname := "host-1"
	ep := discoveryv1.Endpoint{
		Addresses: []string{"192.168.1.10"},
		Conditions: discoveryv1.EndpointConditions{
			Ready: ptr.To(true),
		},
		Hostname: &hostname,
		NodeName: &nodeName,
		TargetRef: &corev1.ObjectReference{
			Kind: "Pod",
			Name: "my-pod",
		},
		DeprecatedTopology: map[string]string{"kubernetes.io/hostname": "node-1"},
		Hints: &discoveryv1.EndpointHints{
			ForZones: []discoveryv1.ForZone{{Name: "zone-a"}},
		},
	}

	sanitized := SanitizeEndpoint(ep)
	assert.Equal(t, []string{"192.168.1.10"}, sanitized.Addresses)
	assert.Equal(t, ptr.To(true), sanitized.Conditions.Ready)
	assert.Nil(t, sanitized.Hostname)
	assert.Nil(t, sanitized.NodeName)
	assert.Nil(t, sanitized.TargetRef)
	assert.Nil(t, sanitized.DeprecatedTopology)
	assert.Nil(t, sanitized.Hints)

	// Verify deep copy of addresses
	sanitized.Addresses[0] = "1.2.3.4"
	assert.Equal(t, "192.168.1.10", ep.Addresses[0])
}

func TestEndpointAddressType(t *testing.T) {
	tests := []struct {
		name      string
		endpoints []discoveryv1.Endpoint
		wantType  discoveryv1.AddressType
		wantErr   bool
	}{
		{
			name:      "empty endpoints defaults to IPv4",
			endpoints: nil,
			wantType:  discoveryv1.AddressTypeIPv4,
			wantErr:   false,
		},
		{
			name: "IPv4 endpoints",
			endpoints: []discoveryv1.Endpoint{
				{Addresses: []string{"10.0.0.1", "10.0.0.2"}},
			},
			wantType: discoveryv1.AddressTypeIPv4,
			wantErr:  false,
		},
		{
			name: "IPv6 endpoints",
			endpoints: []discoveryv1.Endpoint{
				{Addresses: []string{"2001:db8::1", "fe80::1"}},
			},
			wantType: discoveryv1.AddressTypeIPv6,
			wantErr:  false,
		},
		{
			name: "mixed IPv4 and IPv6 returns error",
			endpoints: []discoveryv1.Endpoint{
				{Addresses: []string{"10.0.0.1", "2001:db8::1"}},
			},
			wantType: "",
			wantErr:  true,
		},
		{
			name: "invalid IP address returns error",
			endpoints: []discoveryv1.Endpoint{
				{Addresses: []string{"invalid-ip"}},
			},
			wantType: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, err := EndpointAddressType(tt.endpoints)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantType, gotType)
			}
		})
	}
}
