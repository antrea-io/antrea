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
Copyright 2025 Antrea Authors

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

// Derived from Kubernetes pkg/proxy/util/utils.go (v1.34.2); Antrea tests for proxy utility functions.

package util

import (
	"net"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"
)

func TestIsZeroCIDR(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected bool
	}{
		{"IPv4 zero CIDR", "0.0.0.0/0", true},
		{"IPv6 zero CIDR", "::/0", true},
		{"IPv4 non-zero CIDR", "10.0.0.0/8", false},
		{"IPv6 non-zero CIDR", "2001:db8::/32", false},
		{"nil CIDR", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cidr *net.IPNet
			if tt.cidr != "" {
				_, cidr, _ = net.ParseCIDR(tt.cidr)
			}
			if got := IsZeroCIDR(cidr); got != tt.expected {
				t.Errorf("IsZeroCIDR() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestShouldSkipService(t *testing.T) {
	tests := []struct {
		name                 string
		service              *v1.Service
		skipServices         []string
		serviceLabelSelector string
		expected             bool
	}{
		{
			name: "normal service",
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default", Labels: map[string]string{"app": "test"}},
				Spec:       v1.ServiceSpec{ClusterIP: "10.0.0.1", Type: v1.ServiceTypeClusterIP},
			},
			expected: false,
		},
		{
			name: "ClusterIP None",
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "headless", Namespace: "default"},
				Spec:       v1.ServiceSpec{ClusterIP: v1.ClusterIPNone, Type: v1.ServiceTypeClusterIP},
			},
			expected: true,
		},
		{
			name: "ExternalName service",
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "external", Namespace: "default"},
				Spec:       v1.ServiceSpec{ClusterIP: "10.0.0.1", Type: v1.ServiceTypeExternalName},
			},
			expected: true,
		},
		{
			name: "service in skip list by name",
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "skip-me", Namespace: "default"},
				Spec:       v1.ServiceSpec{ClusterIP: "10.0.0.1", Type: v1.ServiceTypeClusterIP},
			},
			skipServices: []string{"default/skip-me"},
			expected:     true,
		},
		{
			name: "service label does not match selector",
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default", Labels: map[string]string{"app": "test"}},
				Spec:       v1.ServiceSpec{ClusterIP: "10.0.0.1", Type: v1.ServiceTypeClusterIP},
			},
			serviceLabelSelector: "env=prod",
			expected:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipSet := sets.New(tt.skipServices...)
			selector := labels.Everything()
			if tt.serviceLabelSelector != "" {
				var err error
				selector, err = labels.Parse(tt.serviceLabelSelector)
				if err != nil {
					t.Fatalf("invalid selector: %v", err)
				}
			}
			if got := ShouldSkipService(tt.service, skipSet, selector); got != tt.expected {
				t.Errorf("ShouldSkipService() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetClusterIPByFamily(t *testing.T) {
	tests := []struct {
		name     string
		ipFamily v1.IPFamily
		service  *v1.Service
		expected string
	}{
		{
			name:     "IPv4 single-stack",
			ipFamily: v1.IPv4Protocol,
			service:  &v1.Service{Spec: v1.ServiceSpec{ClusterIP: "10.0.0.1", IPFamilies: []v1.IPFamily{v1.IPv4Protocol}, ClusterIPs: []string{"10.0.0.1"}}},
			expected: "10.0.0.1",
		},
		{
			name:     "dual-stack get IPv6",
			ipFamily: v1.IPv6Protocol,
			service:  &v1.Service{Spec: v1.ServiceSpec{ClusterIP: "10.0.0.1", IPFamilies: []v1.IPFamily{v1.IPv4Protocol, v1.IPv6Protocol}, ClusterIPs: []string{"10.0.0.1", "2001:db8::1"}}},
			expected: "2001:db8::1",
		},
		{
			name:     "ClusterIP None",
			ipFamily: v1.IPv4Protocol,
			service:  &v1.Service{Spec: v1.ServiceSpec{ClusterIP: v1.ClusterIPNone}},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetClusterIPByFamily(tt.ipFamily, tt.service); got != tt.expected {
				t.Errorf("GetClusterIPByFamily() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMapIPsByIPFamily(t *testing.T) {
	tests := []struct {
		name       string
		ipStrings  []string
		expectedV4 int
		expectedV6 int
	}{
		{"IPv4 only", []string{"10.0.0.1", "192.168.1.1"}, 2, 0},
		{"IPv6 only", []string{"2001:db8::1", "fe80::1"}, 0, 2},
		{"mixed", []string{"10.0.0.1", "2001:db8::1"}, 1, 1},
		{"invalid", []string{"", "invalid", "10.0.0.1"}, 1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MapIPsByIPFamily(tt.ipStrings)
			if len(result[v1.IPv4Protocol]) != tt.expectedV4 {
				t.Errorf("IPv4 count = %d, want %d", len(result[v1.IPv4Protocol]), tt.expectedV4)
			}
			if len(result[v1.IPv6Protocol]) != tt.expectedV6 {
				t.Errorf("IPv6 count = %d, want %d", len(result[v1.IPv6Protocol]), tt.expectedV6)
			}
		})
	}
}

func TestMapCIDRsByIPFamily(t *testing.T) {
	tests := []struct {
		name       string
		cidrs      []string
		expectedV4 int
		expectedV6 int
	}{
		{"IPv4 CIDRs", []string{"10.0.0.0/8", "192.168.0.0/16"}, 2, 0},
		{"IPv6 CIDRs", []string{"2001:db8::/32", "fe80::/10"}, 0, 2},
		{"mixed", []string{"10.0.0.0/8", "2001:db8::/32"}, 1, 1},
		{"with whitespace", []string{" 10.0.0.0/8 ", "  2001:db8::/32  "}, 1, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MapCIDRsByIPFamily(tt.cidrs)
			if len(result[v1.IPv4Protocol]) != tt.expectedV4 {
				t.Errorf("IPv4 CIDR count = %d, want %d", len(result[v1.IPv4Protocol]), tt.expectedV4)
			}
			if len(result[v1.IPv6Protocol]) != tt.expectedV6 {
				t.Errorf("IPv6 CIDR count = %d, want %d", len(result[v1.IPv6Protocol]), tt.expectedV6)
			}
		})
	}
}

func TestIsVIPMode(t *testing.T) {
	tests := []struct {
		name     string
		ingress  v1.LoadBalancerIngress
		expected bool
	}{
		{"VIP mode explicit", v1.LoadBalancerIngress{IP: "10.0.0.1", IPMode: ptr.To(v1.LoadBalancerIPModeVIP)}, true},
		{"Proxy mode", v1.LoadBalancerIngress{IP: "10.0.0.1", IPMode: ptr.To(v1.LoadBalancerIPModeProxy)}, false},
		{"nil IPMode defaults to VIP", v1.LoadBalancerIngress{IP: "10.0.0.1", IPMode: nil}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsVIPMode(tt.ingress); got != tt.expected {
				t.Errorf("IsVIPMode() = %v, want %v", got, tt.expected)
			}
		})
	}
}
