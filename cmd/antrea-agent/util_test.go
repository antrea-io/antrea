// Copyright 2022 Antrea Authors
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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	clientset "k8s.io/client-go/kubernetes"

	"antrea.io/antrea/pkg/agent/util"
	agentconfig "antrea.io/antrea/pkg/config/agent"
)

func TestGetAvailableNodePortAddresses(t *testing.T) {
	testCases := []struct {
		name                        string
		nodePortAddressesFromConfig []string
		expectedIPv4                []net.IP
		expectedIPv6                []net.IP
	}{
		{
			name:                        "empty nodePortAddresses",
			nodePortAddressesFromConfig: []string{},
			expectedIPv4:                []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.225.234"), net.ParseIP("10.104.73.43")},
			expectedIPv6:                []net.IP{net.ParseIP("::1"), net.ParseIP("2409:4071:4d11:f5d2:71:e53f:7d28:668e"), net.ParseIP("2409:4071:4d11:f5d2:75ab:a5b6:ff05:b31e")},
		},
		{
			name:                        "non-empty nodePortAddresses",
			nodePortAddressesFromConfig: []string{"192.168.225.0/24"},
			expectedIPv4:                []net.IP{net.ParseIP("192.168.225.234")},
			expectedIPv6:                nil,
		},
	}
	getAllNodeAddresses = func(excludeDevices []string) ([]net.IP, []net.IP, error) {
		ipv4 := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.225.234"), net.ParseIP("10.104.73.43")}
		ipv6 := []net.IP{net.ParseIP("::1"), net.ParseIP("2409:4071:4d11:f5d2:71:e53f:7d28:668e"), net.ParseIP("2409:4071:4d11:f5d2:75ab:a5b6:ff05:b31e")}
		return ipv4, ipv6, nil
	}
	defer func() {
		getAllNodeAddresses = util.GetAllNodeAddresses
	}()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotIPv4, gotIPv6, err := getAvailableNodePortAddresses(tc.nodePortAddressesFromConfig, []string{"antrea-egress0", "antrea-ingress0", "kube-ipvs0", "antrea-gw0"})
			require.NoError(t, err)
			assert.Equal(t, tc.expectedIPv4, gotIPv4)
			assert.Equal(t, tc.expectedIPv6, gotIPv6)
		})
	}
}

func TestParsePortRange(t *testing.T) {
	testCases := []struct {
		name          string
		portRangeStr  string
		expectedStart int
		expectedEnd   int
		expectedErr   string
	}{
		{
			name:         "wrong port range format",
			portRangeStr: "200 300",
			expectedErr:  "wrong port range format: 200 300",
		},
		{
			name:         "length of port range string not equals to 2",
			portRangeStr: "6110-7000-8000",
			expectedErr:  "wrong port range format: 6110-7000-8000",
		},
		{
			name:         "wrong port range type value for start",
			portRangeStr: "wrong-6200",
			expectedErr:  "strconv.Atoi: parsing \"wrong\": invalid syntax",
		},
		{
			name:         "wrong port range type value for end",
			portRangeStr: "6100-wrong",
			expectedErr:  "strconv.Atoi: parsing \"wrong\": invalid syntax",
		},
		{
			name:          "valid range",
			portRangeStr:  "61000-62000",
			expectedStart: 61000,
			expectedEnd:   62000,
		},
		{
			name:         "port range's end smaller than port range's start",
			portRangeStr: "6000-5000",
			expectedErr:  "start port must be smaller than end port: 6000-5000",
		},
		{
			name:         "port range's start and port range's end with equal values",
			portRangeStr: "6100-6100",
			expectedErr:  "start port must be smaller than end port: 6100-6100",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, err := parsePortRange(tc.portRangeStr)
			if tc.expectedErr != "" {
				assert.EqualError(t, err, tc.expectedErr)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.expectedStart, start)
			assert.Equal(t, tc.expectedEnd, end)

		})
	}
}

func TestGetPodCIDRs(t *testing.T) {
	type mockFns struct {
		fromKubeProxy func(clientset.Interface) string
		fromKubeadm   func(clientset.Interface) string
	}

	tests := []struct {
		name          string
		optionsCIDR   string
		mocks         mockFns
		expectedCIDRs []string
		expectedErr   string
	}{
		{
			name:          "CIDR from options config",
			optionsCIDR:   "10.244.0.0/16,  fd00:10:244::/56",
			expectedCIDRs: []string{"10.244.0.0/16", "fd00:10:244::/56"},
		},
		{
			name:          "invalid CIDR from options config",
			optionsCIDR:   "10.244.0.0/160",
			expectedCIDRs: nil,
			expectedErr:   "invalid CIDR 10.244.0.0/160",
		},
		{
			name: "CIDR from kube-proxy ConfigMap fallback",
			mocks: mockFns{
				fromKubeProxy: func(_ clientset.Interface) string {
					return "10.244.0.0/16"
				},
			},
			expectedCIDRs: []string{"10.244.0.0/16"},
		},
		{
			name: "CIDR from kubeadm-config fallback",
			mocks: mockFns{
				fromKubeProxy: func(_ clientset.Interface) string { return "" },
				fromKubeadm: func(_ clientset.Interface) string {
					return "fd00:10:244::/56"
				},
			},
			expectedCIDRs: []string{"fd00:10:244::/56"},
		},
		{
			name: "No CIDR found",
			mocks: mockFns{
				fromKubeProxy: func(_ clientset.Interface) string { return "" },
				fromKubeadm:   func(_ clientset.Interface) string { return "" },
			},
			expectedCIDRs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originFromKubeProxy := getPodCIDRsFromKubeProxy
			originFromKubeadm := getPodCIDRsFromKubeadm
			t.Cleanup(func() {
				getPodCIDRsFromKubeProxy = originFromKubeProxy
				getPodCIDRsFromKubeadm = originFromKubeadm
			})
			if tt.mocks.fromKubeProxy != nil {
				getPodCIDRsFromKubeProxy = tt.mocks.fromKubeProxy
			}
			if tt.mocks.fromKubeadm != nil {
				getPodCIDRsFromKubeadm = tt.mocks.fromKubeadm
			}

			o := &Options{
				config: &agentconfig.AgentConfig{
					PodCIDRs: tt.optionsCIDR,
				},
			}
			got, err := getPodCIDRs(o, nil)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				var gotCIDRs []string
				for _, cidr := range got {
					gotCIDRs = append(gotCIDRs, cidr.String())
				}
				assert.ElementsMatch(t, tt.expectedCIDRs, gotCIDRs)
			}
		})
	}
}

func TestParseCIDRs(t *testing.T) {
	testCases := []struct {
		name          string
		input         string
		expectedCIDRs []string
		expectedError string
	}{
		{
			name:          "empty string",
			input:         "",
			expectedCIDRs: nil,
			expectedError: "empty CIDR string",
		},
		{
			name:          "only spaces",
			input:         "   ",
			expectedCIDRs: nil,
			expectedError: "empty CIDR string",
		},
		{
			name:          "single valid IPv4 CIDR",
			input:         "10.244.0.0/16",
			expectedCIDRs: []string{"10.244.0.0/16"},
			expectedError: "",
		},
		{
			name:          "multiple valid CIDRs with spaces",
			input:         "10.0.0.0/8, 192.168.0.0/24 ,fd00::/64",
			expectedCIDRs: []string{"10.0.0.0/8", "192.168.0.0/24", "fd00::/64"},
			expectedError: "",
		},
		{
			name:          "contains invalid CIDR",
			input:         "10.1.0.0/16,invalid,fd00::/64",
			expectedCIDRs: nil,
			expectedError: "invalid CIDR",
		},
		{
			name:          "all invalid CIDRs",
			input:         "bad1,bad2",
			expectedCIDRs: []string{},
			expectedError: "invalid CIDR",
		},
		{
			name:          "trailing and leading commas",
			input:         ",10.244.0.0/16,",
			expectedCIDRs: []string{"10.244.0.0/16"},
			expectedError: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCIDRs(tc.input)
			if tc.expectedError != "" {
				assert.ErrorContains(t, err, tc.expectedError)
			} else {
				var gotStrs []string
				for _, cidr := range got {
					gotStrs = append(gotStrs, cidr.String())
				}
				assert.ElementsMatch(t, tc.expectedCIDRs, gotStrs)
			}
		})
	}
}
