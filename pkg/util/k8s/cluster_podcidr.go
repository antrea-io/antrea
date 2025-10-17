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
	"context"
	"net"
	"strings"

	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

func GetPodCIDRsFromConfig(podCIDRStr string) []*net.IPNet {
	return parseCIDRs(podCIDRStr)
}

func GetPodCIDRsFromKubeProxy(k8sClient clientset.Interface) []*net.IPNet {
	podCIDRs, found := extractPodCIDRsFromConfigMap(k8sClient,
		"kube-proxy",
		"config.conf",
		"clusterCIDR")
	if !found {
		klog.V(4).InfoS("ConfigMap kube-proxy not found or no clusterCIDR field; skipping")
	}
	return podCIDRs
}

func GetPodCIDRsFromKubeadm(k8sClient clientset.Interface) []*net.IPNet {
	podCIDRs, found := extractPodCIDRsFromConfigMap(k8sClient,
		"kubeadm-config",
		"ClusterConfiguration",
		"networking",
		"podSubnet")
	if !found {
		klog.V(4).InfoS("ConfigMap kubeadm not found or no networking.podSubnet field; skipping")
	}
	return podCIDRs
}

func extractPodCIDRsFromConfigMap(client clientset.Interface, name, key string, path ...string) ([]*net.IPNet, bool) {
	cm, err := client.CoreV1().ConfigMaps(metav1.NamespaceSystem).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		klog.V(4).InfoS("ConfigMap not found", "configMap", name, "err", err)
		return nil, false
	}
	data, ok := cm.Data[key]
	if !ok {
		klog.V(4).InfoS("Key not found in ConfigMap", "configMap", name, "key", key)
		return nil, false
	}

	var m map[string]interface{}
	if err := yaml.Unmarshal([]byte(data), &m); err != nil {
		klog.V(4).InfoS("Failed to unmarshal data", "configMap", name, "err", err)
		return nil, false
	}

	podCIDRStr, ok := getValueAtPath(m, path...)
	if !ok {
		klog.V(4).InfoS("Path not found in ConfigMap", "configMap", name, "path", strings.Join(path, "."))
		return nil, false
	}

	podCIDRs := parseCIDRs(podCIDRStr)
	if len(podCIDRs) == 0 {
		return nil, false
	}

	return podCIDRs, true
}

func getValueAtPath(m map[string]any, path ...string) (string, bool) {
	cur := any(m)
	for _, k := range path {
		next, ok := cur.(map[string]interface{})
		if !ok {
			return "", false
		}
		cur, ok = next[k]
		if !ok {
			return "", false
		}
	}
	s, ok := cur.(string)
	if !ok {
		return "", false
	}
	return s, true
}

func parseCIDRs(s string) []*net.IPNet {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	var cidrs []*net.IPNet
	for _, cidrStr := range strings.Split(s, ",") {
		cidrStr = strings.TrimSpace(cidrStr)
		if cidrStr == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			klog.ErrorS(err, "Failed to parse CIDR", "cidrStr", cidrStr)
			continue
		}
		cidrs = append(cidrs, cidr)
	}
	return cidrs
}
