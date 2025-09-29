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
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

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

func TestParseCIDRs(t *testing.T) {
	testCases := []struct {
		name          string
		input         string
		expectedCIDRs []string
	}{
		{
			name:          "empty string",
			input:         "",
			expectedCIDRs: nil,
		},
		{
			name:          "only spaces",
			input:         "   ",
			expectedCIDRs: nil,
		},
		{
			name:          "single valid IPv4 CIDR",
			input:         "10.244.0.0/16",
			expectedCIDRs: []string{"10.244.0.0/16"},
		},
		{
			name:          "multiple valid CIDRs with spaces",
			input:         "10.0.0.0/8, 192.168.0.0/24 ,fd00::/64",
			expectedCIDRs: []string{"10.0.0.0/8", "192.168.0.0/24", "fd00::/64"},
		},
		{
			name:          "contains invalid CIDR, should skip it",
			input:         "10.1.0.0/16,invalid,fd00::/64",
			expectedCIDRs: []string{"10.1.0.0/16", "fd00::/64"},
		},
		{
			name:          "all invalid CIDRs, should return empty slice",
			input:         "bad1,bad2",
			expectedCIDRs: []string{},
		},
		{
			name:          "trailing and leading commas",
			input:         ",10.244.0.0/16,",
			expectedCIDRs: []string{"10.244.0.0/16"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCIDRs(tc.input)
			var gotStrs []string
			for _, cidr := range got {
				gotStrs = append(gotStrs, cidr.String())
			}
			assert.ElementsMatch(t, tc.expectedCIDRs, gotStrs)
		})
	}
}

func TestExtractPodCIDRFromConfigMap(t *testing.T) {
	tests := []struct {
		name         string
		cmData       map[string]string
		key          string
		path         string
		expectedCIDR string
	}{
		{
			name: "found Pod CIDR in ConfigMap kube-proxy",
			cmData: map[string]string{
				"config.conf": `
apiVersion: kubeproxy.config.k8s.io/v1alpha1
clusterCIDR : 10.244.0.0/16, fd00:10:244::/56 
mode: iptables
`,
			},
			key:          "config.conf",
			path:         "clusterCIDR",
			expectedCIDR: "10.244.0.0/16, fd00:10:244::/56",
		},
		{
			name: "found Pod CIDR in ConfigMap kubeadm-config",
			cmData: map[string]string{
				"ClusterConfiguration": `
networking:
  dnsDomain: cluster.local
  podSubnet: 10.244.0.0/16,fd00:10:244::/56
  serviceSubnet: 10.96.0.0/16,fd00:10:96::/112
`,
			},
			key:          "ClusterConfiguration",
			path:         "networking.podSubnet",
			expectedCIDR: "10.244.0.0/16,fd00:10:244::/56",
		},
		{
			name: "missing key",
			cmData: map[string]string{
				"wrong.conf": "",
			},
			key:          "config.conf",
			path:         "clusterCIDR",
			expectedCIDR: "",
		},
		{
			name: "no CIDR match",
			cmData: map[string]string{
				"config.conf": `mode: iptables`,
			},
			key:          "config.conf",
			path:         "clusterCIDR",
			expectedCIDR: "",
		},
		{
			name: "wrong path",
			cmData: map[string]string{
				"config.conf": `
apiVersion: kubeproxy.config.k8s.io/v1alpha1
clusterCIDR: 10.244.0.0/16,fd00:10:244::/56
mode: iptables
`,
			},
			key:          "config.conf",
			path:         "clusterCIDRs",
			expectedCIDR: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientset(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapKubeProxy,
					Namespace: metav1.NamespaceSystem,
				},
				Data: tt.cmData,
			})

			cidr := extractPodCIDRFromConfigMap(client, configMapKubeProxy, tt.key, tt.path)
			require.Equal(t, tt.expectedCIDR, cidr)
		})
	}
}

func TestGetPodCIDRs(t *testing.T) {
	tests := []struct {
		name          string
		optionsCIDR   string
		configMaps    []*corev1.ConfigMap
		expectedCIDRs []*net.IPNet
	}{
		{
			name:          "CIDR from options config",
			optionsCIDR:   "10.244.0.0/16,  fd00:10:244::/56",
			expectedCIDRs: []*net.IPNet{mustParseCIDR("10.244.0.0/16"), mustParseCIDR("fd00:10:244::/56")},
		},
		{
			name: "CIDR from kube-proxy ConfigMap fallback",
			configMaps: []*corev1.ConfigMap{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      configMapKubeProxy,
						Namespace: metav1.NamespaceSystem,
					},
					Data: map[string]string{
						"config.conf": `
apiVersion: kubeproxy.config.k8s.io/v1alpha1
clusterCIDR: 10.244.0.0/16
mode: iptables
`,
					},
				},
			},
			expectedCIDRs: []*net.IPNet{mustParseCIDR("10.244.0.0/16")},
		},
		{
			name: "CIDR from kubeadm-config fallback",
			configMaps: []*corev1.ConfigMap{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      configMapKubeadm,
						Namespace: metav1.NamespaceSystem,
					},
					Data: map[string]string{
						"ClusterConfiguration": `
networking:
      dnsDomain: cluster.local
      podSubnet: fd00:10:244::/56
      serviceSubnet: fd00:10:96::/112
`,
					},
				},
			},
			expectedCIDRs: []*net.IPNet{mustParseCIDR("fd00:10:244::/56")},
		},
		{
			name: "No CIDR found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientset()
			for _, cm := range tt.configMaps {
				_, err := client.CoreV1().ConfigMaps(cm.Namespace).Create(context.TODO(), cm, metav1.CreateOptions{})
				require.NoError(t, err)
			}

			o := &Options{
				config: &agentconfig.AgentConfig{
					PodCIDR: tt.optionsCIDR,
				},
			}
			podCIDRStr := getPodCIDRStr(o, client)
			gotCIDRs := parseCIDRs(podCIDRStr)
			require.Equal(t, tt.expectedCIDRs, gotCIDRs)
		})
	}
}

func mustParseCIDR(s string) *net.IPNet {
	_, ipnet, _ := net.ParseCIDR(s)
	return ipnet
}
