// Copyright 2024 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package monitortool

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

var (
	nodeLatencyMonitor1 = &v1alpha1.NodeLatencyMonitor{
		Spec: v1alpha1.NodeLatencyMonitorSpec{
			PingIntervalSeconds: 1,
		},
	}
	nodeLatencyMonitor2 = &v1alpha1.NodeLatencyMonitor{
		Spec: v1alpha1.NodeLatencyMonitorSpec{
			PingIntervalSeconds: 2,
		},
	}
	latencyConfig1 = &LatencyConfig{
		Enable:   true,
		Interval: time.Second,
	}
	latencyConfig2 = &LatencyConfig{
		Enable:   true,
		Interval: 2 * time.Second,
	}
	latencyConfig3 = &LatencyConfig{
		Enable: false,
	}
)

func TestNewNodeLatencyMonitor(t *testing.T) {
	k8sClient := fake.NewSimpleClientset()
	crdClient := fakeversioned.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	nodeInformer := informerFactory.Core().V1().Nodes()
	nlmInformer := crdInformerFactory.Crd().V1alpha1().NodeLatencyMonitors()
	nodeLatencyMonitor := NewNodeLatencyMonitor(
		nodeInformer,
		nlmInformer,
		&config.NodeConfig{},
		config.TrafficEncapModeNetworkPolicyOnly,
	)
	assert.NotNil(t, nodeLatencyMonitor)

	stopCh := make(chan struct{})
	defer close(stopCh)

	go nodeLatencyMonitor.Run(stopCh)
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)
	crdInformerFactory.Start(stopCh)
	crdInformerFactory.WaitForCacheSync(stopCh)

	nodeName := "node1"
	nodeCIDR := "1.1.1.1/24"
	nodeInternalIP := "2.2.2.2"
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName},
		Spec: corev1.NodeSpec{
			PodCIDRs: []string{nodeCIDR},
		},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: nodeInternalIP},
		}},
	}

	k8sClient.CoreV1().Nodes().Create(context.TODO(), node, metav1.CreateOptions{})
	assert.EventuallyWithT(t, func(c *assert.CollectT) {}, 2*time.Second, 10*time.Millisecond)

	updateNodeCIDR := "1.1.2.1/24"
	updatedNodeInternalIP := "1.1.2.2"
	updatedNode := node.DeepCopy()
	updatedNode.Spec.PodCIDRs = []string{updateNodeCIDR}
	updatedNode.Status.Addresses[0].Address = updatedNodeInternalIP
	k8sClient.CoreV1().Nodes().Update(context.TODO(), updatedNode, metav1.UpdateOptions{})
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		ips := nodeLatencyMonitor.latencyStore.GetNodeIPs(nodeName)
		assert.Equal(c, 1, len(ips))
	}, 2*time.Second, 10*time.Millisecond)

	k8sClient.CoreV1().Nodes().Delete(context.TODO(), node.Name, metav1.DeleteOptions{})
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		ips := nodeLatencyMonitor.latencyStore.GetNodeIPs(nodeName)
		assert.Equal(c, 0, len(ips))
	}, 2*time.Second, 10*time.Millisecond)
}

func TestNodeLatencyMonitor_onNodeLatencyMonitorAdd(t *testing.T) {
	nodeLatencyMonitor := &NodeLatencyMonitor{
		// Buffer size is 10 to avoid blocking
		latencyConfigChanged: make(chan struct{}, 10),
		latencyConfig:        latencyConfig1,
	}
	tests := []struct {
		nodeLatencyMonitor *v1alpha1.NodeLatencyMonitor
		expected           *LatencyConfig
	}{
		{
			nodeLatencyMonitor: nodeLatencyMonitor1,
			expected:           latencyConfig1,
		},
		{
			nodeLatencyMonitor: nodeLatencyMonitor2,
			expected:           latencyConfig2,
		},
	}

	for _, tt := range tests {
		nodeLatencyMonitor.onNodeLatencyMonitorAdd(tt.nodeLatencyMonitor)
		assert.Equal(t, tt.expected, nodeLatencyMonitor.latencyConfig)
	}
}

func TestNodeLatencyMonitor_onNodeLatencyMonitorUpdate(t *testing.T) {
	nodeLatencyMonitor := &NodeLatencyMonitor{
		// Buffer size is 10 to avoid blocking
		latencyConfigChanged: make(chan struct{}, 10),
		latencyConfig:        latencyConfig1,
	}
	tests := []struct {
		oldNodeLatencyMonitor *v1alpha1.NodeLatencyMonitor
		newNodeLatencyMonitor *v1alpha1.NodeLatencyMonitor
		expected              *LatencyConfig
	}{
		{
			oldNodeLatencyMonitor: nodeLatencyMonitor1,
			newNodeLatencyMonitor: nodeLatencyMonitor2,
			expected:              latencyConfig1, // Same generation
		},
	}

	for _, tt := range tests {
		nodeLatencyMonitor.onNodeLatencyMonitorUpdate(tt.oldNodeLatencyMonitor, tt.newNodeLatencyMonitor)
		assert.Equal(t, tt.expected, nodeLatencyMonitor.latencyConfig)
	}
}

func TestNodeLatencyMonitor_onNodeLatencyMonitorDelete(t *testing.T) {
	nodeLatencyMonitor := &NodeLatencyMonitor{
		// Buffer size is 10 to avoid blocking
		latencyConfigChanged: make(chan struct{}, 10),
		latencyConfig:        latencyConfig1,
	}
	tests := []struct {
		nodeLatencyMonitor *v1alpha1.NodeLatencyMonitor
		expected           *LatencyConfig
	}{
		{
			nodeLatencyMonitor: nodeLatencyMonitor1,
			expected:           latencyConfig3,
		},
	}

	for _, tt := range tests {
		nodeLatencyMonitor.onNodeLatencyMonitorDelete(tt.nodeLatencyMonitor)
		assert.Equal(t, tt.expected, nodeLatencyMonitor.latencyConfig)
	}
}
