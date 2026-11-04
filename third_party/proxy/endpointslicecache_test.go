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

package proxy

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func TestEndpointLocality(t *testing.T) {
	testCases := []struct {
		name          string
		ip            string
		ipFamily      v1.IPFamily
		podCIDR       string
		nodeName      *string
		expectedLocal bool
	}{
		{
			name:          "static IPv4 endpoint inside local PodCIDR",
			ip:            "10.10.0.100",
			ipFamily:      v1.IPv4Protocol,
			podCIDR:       "10.10.0.0/24",
			expectedLocal: true,
		},
		{
			name:          "static IPv6 endpoint inside local PodCIDR",
			ip:            "fec0:10:10::100",
			ipFamily:      v1.IPv6Protocol,
			podCIDR:       "fec0:10:10::/64",
			expectedLocal: true,
		},
		{
			name:          "external IPv4 endpoint",
			ip:            "172.16.0.100",
			ipFamily:      v1.IPv4Protocol,
			podCIDR:       "10.10.0.0/24",
			expectedLocal: false,
		},
		{
			name:          "remote IPv6 endpoint",
			ip:            "fec0:20:20::100",
			ipFamily:      v1.IPv6Protocol,
			podCIDR:       "fec0:10:10::/64",
			expectedLocal: false,
		},
		{
			name:          "missing IPv4 PodCIDR",
			ip:            "10.10.0.100",
			ipFamily:      v1.IPv4Protocol,
			expectedLocal: false,
		},
		{
			name:          "missing IPv6 PodCIDR",
			ip:            "fec0:10:10::100",
			ipFamily:      v1.IPv6Protocol,
			expectedLocal: false,
		},
		{
			name:          "local nodeName without PodCIDR",
			ip:            "10.10.0.100",
			ipFamily:      v1.IPv4Protocol,
			nodeName:      ptr.To("node1"),
			expectedLocal: true,
		},
		{
			name:          "local IPv6 nodeName without PodCIDR",
			ip:            "fec0:10:10::100",
			ipFamily:      v1.IPv6Protocol,
			nodeName:      ptr.To("node1"),
			expectedLocal: true,
		},
		{
			name:          "remote nodeName inside local PodCIDR",
			ip:            "10.10.0.100",
			ipFamily:      v1.IPv4Protocol,
			podCIDR:       "10.10.0.0/24",
			nodeName:      ptr.To("node2"),
			expectedLocal: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var podCIDR *net.IPNet
			if tc.podCIDR != "" {
				var err error
				_, podCIDR, err = net.ParseCIDR(tc.podCIDR)
				require.NoError(t, err)
			}
			tracker := NewEndpointsChangeTracker(tc.ipFamily, "node1", podCIDR, nil, nil)
			addressType := discovery.AddressTypeIPv4
			if tc.ipFamily == v1.IPv6Protocol {
				addressType = discovery.AddressTypeIPv6
			}
			slice := &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc-1",
					Namespace: "ns",
					Labels: map[string]string{
						discovery.LabelServiceName: "svc",
					},
				},
				AddressType: addressType,
				Ports: []discovery.EndpointPort{{
					Name:     ptr.To("http"),
					Port:     ptr.To(int32(80)),
					Protocol: ptr.To(v1.ProtocolTCP),
				}},
				Endpoints: []discovery.Endpoint{{
					Addresses: []string{tc.ip},
					NodeName:  tc.nodeName,
				}},
			}
			require.True(t, tracker.EndpointSliceUpdate(slice, false))
			endpointsMap := EndpointsMap{}
			endpointsMap.Update(tracker)
			svcPortName := ServicePortName{
				NamespacedName: types.NamespacedName{Namespace: "ns", Name: "svc"},
				Port:           "http",
				Protocol:       v1.ProtocolTCP,
			}
			require.Len(t, endpointsMap[svcPortName], 1)
			ep := endpointsMap[svcPortName][net.JoinHostPort(tc.ip, "80")]
			require.NotNil(t, ep)
			assert.Equal(t, tc.expectedLocal, ep.IsLocal())
		})
	}
}
