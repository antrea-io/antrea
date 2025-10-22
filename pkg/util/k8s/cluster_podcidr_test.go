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
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestExtractPodCIDRFromConfigMap(t *testing.T) {
	tests := []struct {
		name          string
		configMapName string
		cmData        map[string]string
		key           string
		path          []string
		expected      string
	}{
		{
			name:          "found Pod CIDR in ConfigMap kube-proxy",
			configMapName: "kube-proxy",
			cmData: map[string]string{
				"config.conf": `
apiVersion: kubeproxy.config.k8s.io/v1alpha1
clusterCIDR : 10.244.0.0/16, fd00:10:244::/56 
mode: iptables
`,
			},
			key:      "config.conf",
			path:     []string{"clusterCIDR"},
			expected: "10.244.0.0/16, fd00:10:244::/56",
		},
		{
			name:          "found Pod CIDR in ConfigMap kubeadm-config",
			configMapName: "kubeadm-config",
			cmData: map[string]string{
				"ClusterConfiguration": `
networking:
  dnsDomain: cluster.local
  podSubnet: 10.244.0.0/16,fd00:10:244::/56
  serviceSubnet: 10.96.0.0/16,fd00:10:96::/112
`,
			},
			key:      "ClusterConfiguration",
			path:     []string{"networking", "podSubnet"},
			expected: "10.244.0.0/16,fd00:10:244::/56",
		},
		{
			name:          "missing key",
			configMapName: "kube-proxy",
			cmData: map[string]string{
				"wrong.conf": "",
			},
			key:  "config.conf",
			path: []string{"clusterCIDR"},
		},
		{
			name:          "no CIDR match",
			configMapName: "kube-proxy",
			cmData: map[string]string{
				"config.conf": `mode: iptables`,
			},
			key:  "config.conf",
			path: []string{"clusterCIDR"},
		},
		{
			name:          "wrong path",
			configMapName: "kube-proxy",
			cmData: map[string]string{
				"config.conf": `
apiVersion: kubeproxy.config.k8s.io/v1alpha1
clusterCIDR: 10.244.0.0/16,fd00:10:244::/56
mode: iptables
`,
			},
			key:  "config.conf",
			path: []string{"clusterCIDRs"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientset(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      tt.configMapName,
					Namespace: metav1.NamespaceSystem,
				},
				Data: tt.cmData,
			})
			got := extractPodCIDRsFromConfigMap(client, tt.configMapName, tt.key, tt.path...)
			assert.Equal(t, tt.expected, got)
		})
	}
}
