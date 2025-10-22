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
	"strings"

	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

func GetPodCIDRsFromKubeProxy(k8sClient clientset.Interface) string {
	return extractPodCIDRsFromConfigMap(k8sClient,
		"kube-proxy",
		"config.conf",
		"clusterCIDR")
}

func GetPodCIDRsFromKubeadm(k8sClient clientset.Interface) string {
	return extractPodCIDRsFromConfigMap(k8sClient,
		"kubeadm-config",
		"ClusterConfiguration",
		"networking",
		"podSubnet")
}

func extractPodCIDRsFromConfigMap(client clientset.Interface, name, key string, path ...string) string {
	cm, err := client.CoreV1().ConfigMaps(metav1.NamespaceSystem).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		klog.V(4).InfoS("ConfigMap not found", "configMap", name, "err", err)
		return ""
	}
	data, ok := cm.Data[key]
	if !ok {
		klog.V(4).InfoS("Key not found in ConfigMap", "configMap", name, "key", key)
		return ""
	}

	var m map[string]interface{}
	if err := yaml.Unmarshal([]byte(data), &m); err != nil {
		klog.V(4).InfoS("Failed to unmarshal data", "configMap", name, "err", err)
		return ""
	}

	podCIDRStr, ok := getValueAtPath(m, path...)
	if !ok {
		klog.V(4).InfoS("Path not found in ConfigMap", "configMap", name, "path", strings.Join(path, "."))
		return ""
	}

	return podCIDRStr
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
