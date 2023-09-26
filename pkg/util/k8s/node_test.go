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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/util/ip"
)

func TestGetNodeAddrs(t *testing.T) {
	tests := []struct {
		name         string
		node         *corev1.Node
		expectedAddr *ip.DualStackIPs
		expectedErr  error
	}{
		{
			name: "internal address first",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "192.168.10.10",
						},
						{
							Type:    corev1.NodeExternalIP,
							Address: "1.1.1.1",
						},
						{
							Type:    corev1.NodeHostName,
							Address: "foo",
						},
					},
				},
			},
			expectedAddr: &ip.DualStackIPs{IPv4: net.ParseIP("192.168.10.10")},
			expectedErr:  nil,
		},
		{
			name: "external address",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeExternalIP,
							Address: "1.1.1.1",
						},
						{
							Type:    corev1.NodeHostName,
							Address: "foo",
						},
					},
				},
			},
			expectedAddr: &ip.DualStackIPs{IPv4: net.ParseIP("1.1.1.1")},
			expectedErr:  nil,
		},
		{
			name: "no valid address",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeHostName,
							Address: "foo",
						},
					},
				},
			},
			expectedAddr: nil,
			expectedErr:  fmt.Errorf("no IP with type in [InternalIP ExternalIP] was found for Node 'foo'"),
		},
		{
			name: "dual stack Internal IP addresses",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "192.168.10.10",
						},
						{
							Type:    corev1.NodeInternalIP,
							Address: "abcd::1",
						},
					},
				},
			},
			expectedAddr: &ip.DualStackIPs{IPv4: net.ParseIP("192.168.10.10"), IPv6: net.ParseIP("abcd::1")},
			expectedErr:  nil,
		},
		{
			name: "dual stack external IP addresses",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeExternalIP,
							Address: "1.1.1.1",
						},
						{
							Type:    corev1.NodeExternalIP,
							Address: "2023::1",
						},
					},
				},
			},
			expectedAddr: &ip.DualStackIPs{IPv4: net.ParseIP("1.1.1.1"), IPv6: net.ParseIP("2023::1")},
			expectedErr:  nil,
		},
		{
			name: "mixed IP addresses",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "192.168.10.10",
						},
						{
							Type:    corev1.NodeInternalIP,
							Address: "abcd::1",
						},
						{
							Type:    corev1.NodeExternalIP,
							Address: "1.1.1.1",
						},
						{
							Type:    corev1.NodeExternalIP,
							Address: "2023::1",
						},
					},
				},
			},
			expectedAddr: &ip.DualStackIPs{IPv4: net.ParseIP("192.168.10.10"), IPv6: net.ParseIP("abcd::1")},
			expectedErr:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := GetNodeAddrs(tt.node)
			assert.Equal(t, tt.expectedErr, err)
			assert.Equal(t, tt.expectedAddr, addr)
		})
	}
}

func TestGetNodeAddrsWithType(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: "192.168.10.10",
				},
				{
					Type:    corev1.NodeInternalIP,
					Address: "192.168.10.11",
				},
				{
					Type:    corev1.NodeInternalIP,
					Address: "abcd::1",
				},
				{
					Type:    corev1.NodeInternalIP,
					Address: "abcd::2",
				},
				{
					Type:    corev1.NodeExternalIP,
					Address: "1.1.1.1",
				},
				{
					Type:    corev1.NodeExternalIP,
					Address: "2023::1",
				},
			},
		},
	}
	tests := []struct {
		name         string
		types        []corev1.NodeAddressType
		expectedAddr *ip.DualStackIPs
		expectedErr  string
	}{
		{
			name:        "no address type",
			types:       nil,
			expectedErr: "at least one Node address type is required",
		},
		{
			name:        "no matching address",
			types:       []corev1.NodeAddressType{corev1.NodeHostName},
			expectedErr: "no IP with type in [Hostname] was found for Node 'foo'",
		},
		{
			name:         "correct priority",
			types:        []corev1.NodeAddressType{corev1.NodeExternalIP, corev1.NodeInternalIP},
			expectedAddr: &ip.DualStackIPs{IPv4: net.ParseIP("1.1.1.1"), IPv6: net.ParseIP("2023::1")},
		},
		{
			name:         "shoud return the first matching address",
			types:        []corev1.NodeAddressType{corev1.NodeInternalIP, corev1.NodeExternalIP},
			expectedAddr: &ip.DualStackIPs{IPv4: net.ParseIP("192.168.10.10"), IPv6: net.ParseIP("abcd::1")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := GetNodeAddrsWithType(node, tt.types)
			if tt.expectedErr != "" {
				assert.EqualError(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedAddr, addr)
			}
		})
	}
}

func TestGetNodeGatewayAddrs(t *testing.T) {
	tests := []struct {
		name         string
		node         *corev1.Node
		expectedAddr *ip.DualStackIPs
		expectedErr  error
	}{
		{
			name: "Node with PodCIDR",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node0",
				},
				Spec: corev1.NodeSpec{PodCIDR: "192.168.0.0/24"},
			},
			expectedAddr: &ip.DualStackIPs{IPv4: net.ParseIP("192.168.0.1").To4()},
			expectedErr:  nil,
		},
		{
			name: "Node with PodCIDRs",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node1",
				},
				Spec: corev1.NodeSpec{PodCIDRs: []string{"192.168.0.0/24", "2620:124:6020:1006::0/64"}},
			},
			expectedAddr: &ip.DualStackIPs{IPv4: net.ParseIP("192.168.0.1").To4(), IPv6: net.ParseIP("2620:124:6020:1006::1")},
			expectedErr:  nil,
		},
		{
			name: "Node without PodCIDR or PodCIDR",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node2",
				},
			},
			expectedAddr: nil,
			expectedErr:  &net.ParseError{Type: "CIDR address", Text: ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := GetNodeGatewayAddrs(tt.node)
			assert.Equal(t, tt.expectedErr, err)
			assert.Equal(t, tt.expectedAddr, addr)
		})
	}
}

func TestGetNodeAddrsFromAnnotations(t *testing.T) {
	tests := []struct {
		name         string
		node         *corev1.Node
		expectedAddr *ip.DualStackIPs
		expectedErr  error
	}{
		{
			name: "Node with IPv4 Annotation",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "node0",
					Annotations: map[string]string{types.NodeTransportAddressAnnotationKey: "192.168.0.1"},
				},
			},
			expectedAddr: &ip.DualStackIPs{IPv4: net.ParseIP("192.168.0.1")},
			expectedErr:  nil,
		},
		{
			name: "Node with IPv4 and IPv6 Annotation",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "node1",
					Annotations: map[string]string{types.NodeTransportAddressAnnotationKey: "192.168.0.1,2620:124:6020:1006::1"},
				},
			},
			expectedAddr: &ip.DualStackIPs{IPv4: net.ParseIP("192.168.0.1"), IPv6: net.ParseIP("2620:124:6020:1006::1")},
			expectedErr:  nil,
		},
		{
			name: "Node without Annotation",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node2",
				},
			},
			expectedAddr: nil,
			expectedErr:  nil,
		},
		{
			name: "Node with invalid Annotation",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "node3",
					Annotations: map[string]string{types.NodeTransportAddressAnnotationKey: ","},
				},
			},
			expectedAddr: nil,
			expectedErr:  fmt.Errorf("invalid annotation for ip-address on Node node3: ,"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := GetNodeAddrsFromAnnotations(tt.node, types.NodeTransportAddressAnnotationKey)
			assert.Equal(t, tt.expectedErr, err)
			assert.Equal(t, tt.expectedAddr, addr)
		})
	}
}

func TestGetNodeAllAddrs(t *testing.T) {
	tests := []struct {
		name          string
		node          *corev1.Node
		expectedAddrs sets.Set[string]
		expectedErr   error
	}{
		{
			name: "Node with IPs",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "node0",
					Annotations: map[string]string{types.NodeTransportAddressAnnotationKey: "172.16.0.1,1::1"},
				},
				Spec: corev1.NodeSpec{PodCIDRs: []string{"192.168.0.0/24", "2001::/64"}},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "10.176.10.10",
						},
					},
				},
			},
			expectedAddrs: sets.New[string]("172.16.0.1", "192.168.0.1", "10.176.10.10", "1::1", "2001::1"),
			expectedErr:   nil,
		},
		{
			name: "Node with duplicate IPs",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "node1",
					Annotations: map[string]string{types.NodeTransportAddressAnnotationKey: "1.1.1.1"},
				},
				Spec: corev1.NodeSpec{PodCIDR: "192.168.0.0/24"},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "1.1.1.1",
						},
					},
				},
			},
			expectedAddrs: sets.New[string]("192.168.0.1", "1.1.1.1"),
			expectedErr:   nil,
		},
		{
			name: "Node with invalid gateway IP",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node2",
				},
				Spec: corev1.NodeSpec{PodCIDR: "x"},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "1.1.1.1",
						},
					},
				},
			},
			expectedAddrs: sets.New[string]("1.1.1.1"),
			expectedErr:   &net.ParseError{Type: "CIDR address", Text: "x"},
		},
		{
			name: "Node with invalid transport address annotation",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "node3",
					Annotations: map[string]string{types.NodeTransportAddressAnnotationKey: "x"},
				},
				Spec: corev1.NodeSpec{PodCIDR: "192.168.0.0/24"},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "1.1.1.1",
						},
					},
				},
			},
			expectedAddrs: sets.New[string]("1.1.1.1", "192.168.0.1"),
			expectedErr:   fmt.Errorf("invalid annotation for ip-address on Node node3: x"),
		},
		{
			name: "Node with none valid IPs",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node4",
				},
			},
			expectedAddrs: sets.New[string](),
			expectedErr:   fmt.Errorf("no IP with type in [InternalIP ExternalIP] was found for Node 'node4'"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := GetNodeAllAddrs(tt.node)
			assert.Equal(t, tt.expectedErr, err)
			assert.Equal(t, tt.expectedAddrs, addr)
		})
	}
}
