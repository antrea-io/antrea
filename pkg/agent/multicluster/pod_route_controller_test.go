// Copyright 2023 Antrea Authors
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

package multicluster

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	v1 "k8s.io/client-go/listers/core/v1"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcfake "antrea.io/antrea/multicluster/pkg/client/clientset/versioned/fake"
	mcinformers "antrea.io/antrea/multicluster/pkg/client/informers/externalversions"
	mclisters "antrea.io/antrea/multicluster/pkg/client/listers/multicluster/v1alpha1"
	"antrea.io/antrea/pkg/agent/config"
	oftest "antrea.io/antrea/pkg/agent/openflow/testing"
)

var (
	defaultNs = "default"
	node1Name = "node-1"
	ctx       = context.TODO()

	nginx1NoIPs = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: defaultNs,
			Name:      "nginx1",
		},
		Spec: corev1.PodSpec{
			NodeName: "node-2",
		},
	}

	nginx2WithIPs = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: defaultNs,
			Name:      "nginx2",
		},
		Spec: corev1.PodSpec{
			NodeName: "node-2",
		},
		Status: corev1.PodStatus{
			PodIP:  "192.168.1.12",
			HostIP: "10.170.10.11",
		},
	}

	nginx2PodIP  = net.ParseIP("192.168.1.12")
	nginx2HostIP = net.ParseIP("10.170.10.11")

	nginxWithHostNetwork = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: defaultNs,
			Name:      "nginx-hostnetwork",
		},
		Spec: corev1.PodSpec{
			NodeName:    "node-2",
			HostNetwork: true,
		},
		Status: corev1.PodStatus{
			PodIP:  "10.170.10.15",
			HostIP: "10.170.10.15",
		},
	}
)

type fakeMCPodRouteController struct {
	*MCPodRouteController
	mcClient          *mcfake.Clientset
	k8sClient         *k8sfake.Clientset
	informerFactory   informers.SharedInformerFactory
	mcInformerFactory mcinformers.SharedInformerFactory
	ofClient          *oftest.MockClient
}

func newMCPodRouteController(t *testing.T, nodeConfig *config.NodeConfig,
	k8sClient *k8sfake.Clientset) *fakeMCPodRouteController {
	mcClient := mcfake.NewSimpleClientset()
	mcInformerFactory := mcinformers.NewSharedInformerFactoryWithOptions(mcClient,
		0,
		mcinformers.WithNamespace(defaultNs),
	)
	gwInformer := mcInformerFactory.Multicluster().V1alpha1().Gateways()

	informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)

	ctrl := gomock.NewController(t)
	ofClient := oftest.NewMockClient(ctrl)
	c := NewMCPodRouteController(
		k8sClient,
		gwInformer,
		ofClient,
		nodeConfig,
	)
	return &fakeMCPodRouteController{
		MCPodRouteController: c,
		mcClient:             mcClient,
		k8sClient:            k8sClient,
		mcInformerFactory:    mcInformerFactory,
		informerFactory:      informerFactory,
		ofClient:             ofClient,
	}
}

func TestGatewayEvent(t *testing.T) {
	k8sClient := k8sfake.NewSimpleClientset([]runtime.Object{nginx1NoIPs, nginx2WithIPs}...)
	c := newMCPodRouteController(t, &config.NodeConfig{Name: node1Name}, k8sClient)
	defer c.podQueue.ShutDown()
	defer c.gwQueue.ShutDown()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	c.mcInformerFactory.Start(stopCh)
	c.mcInformerFactory.WaitForCacheSync(stopCh)
	c.createPodInformer()
	go c.podInformer.Run(stopCh)
	c.podWorkersStarted = true

	for _, pod := range []*corev1.Pod{nginx1NoIPs, nginx2WithIPs} {
		if err := waitForPodRealized(c.podLister, pod); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be realized, err: %v", pod.Namespace, pod.Name, err)
		}
	}

	finishCh := make(chan struct{})
	go func() {
		defer close(finishCh)

		// Create a Gateway node-2 in the default Namespace
		c.mcClient.MulticlusterV1alpha1().Gateways(defaultNs).Create(ctx, &gateway2, metav1.CreateOptions{})
		// Delete a Gateway node-2 in the default Namespace
		c.mcClient.MulticlusterV1alpha1().Gateways(defaultNs).Delete(ctx, gateway2.Name, metav1.DeleteOptions{})

		// Create a Gateway node-1
		c.mcClient.MulticlusterV1alpha1().Gateways(defaultNs).Create(ctx, &gateway1, metav1.CreateOptions{})
		if err := waitForGatewayRealized(c.gwLister, &gateway1); err != nil {
			t.Errorf("Error when waiting for Gateway '%s/%s' to be realized, err: %v", gateway1.Namespace, gateway1.Name, err)
		}
		c.processGatewayNextWorkItem()

		c.ofClient.EXPECT().InstallMulticlusterPodFlows(nginx2PodIP, nginx2HostIP)
		c.processPodNextWorkItem()

		// Delete a Gateway node-1
		c.mcClient.MulticlusterV1alpha1().Gateways(defaultNs).Delete(ctx, gateway1.Name, metav1.DeleteOptions{})
		c.ofClient.EXPECT().UninstallMulticlusterPodFlows("")
		c.processGatewayNextWorkItem()
	}()
	select {
	case <-time.After(5 * time.Second):
		t.Errorf("Test didn't finish in time")
	case <-finishCh:
	}
}

func TestPodEvent(t *testing.T) {
	k8sClient := k8sfake.NewSimpleClientset([]runtime.Object{nginx2WithIPs}...)
	c := newMCPodRouteController(t, &config.NodeConfig{Name: node1Name}, k8sClient)
	defer c.podQueue.ShutDown()
	defer c.gwQueue.ShutDown()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	c.mcInformerFactory.Start(stopCh)
	c.mcInformerFactory.WaitForCacheSync(stopCh)
	c.createPodInformer()
	go c.podInformer.Run(stopCh)
	c.podWorkersStarted = true

	if err := waitForPodRealized(c.podLister, nginx2WithIPs); err != nil {
		t.Errorf("Error when waiting for Pod '%s/%s' to be realized, err: %v", nginx2WithIPs.Namespace, nginx2WithIPs.Name, err)
	}

	finishCh := make(chan struct{})
	go func() {
		defer close(finishCh)
		// Create a Gateway
		c.mcClient.MulticlusterV1alpha1().Gateways(defaultNs).Create(ctx, &gateway1, metav1.CreateOptions{})
		c.ofClient.EXPECT().InstallMulticlusterPodFlows(nginx2PodIP, nginx2HostIP)
		c.processPodNextWorkItem()

		// Update a Pod with empty host IP
		nginx2WithEmptyHostIP := nginx2WithIPs.DeepCopy()
		nginx2WithEmptyHostIP.Status.HostIP = ""
		c.k8sClient.CoreV1().Pods(defaultNs).Update(ctx, nginx2WithEmptyHostIP, metav1.UpdateOptions{})
		if err := waitForPodIPUpdate(c.podLister, nginx2WithEmptyHostIP); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be updated, err: %v", nginx2WithEmptyHostIP.Namespace, nginx2WithEmptyHostIP.Name, err)
		}
		c.ofClient.EXPECT().UninstallMulticlusterPodFlows("192.168.1.12")
		c.processPodNextWorkItem()

		// Delete the invalid Pod
		c.k8sClient.CoreV1().Pods(defaultNs).Delete(ctx, nginx2WithEmptyHostIP.Name, metav1.DeleteOptions{})

		// Create a Pod with hostNetwork
		c.k8sClient.CoreV1().Pods(defaultNs).Create(ctx, nginxWithHostNetwork, metav1.CreateOptions{})
		if err := waitForPodRealized(c.podLister, nginxWithHostNetwork); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be realized, err: %v", nginxWithHostNetwork.Namespace, nginxWithHostNetwork.Name, err)
		}

		// Create a Pod without IPs
		c.k8sClient.CoreV1().Pods(defaultNs).Create(ctx, nginx1NoIPs, metav1.CreateOptions{})
		if err := waitForPodRealized(c.podLister, nginx1NoIPs); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be realized, err: %v", nginx1NoIPs.Namespace, nginx1NoIPs.Name, err)
		}

		// Update a Pod's label
		nginx1NoIPsWithLabel := nginx1NoIPs.DeepCopy()
		nginx1NoIPsWithLabel.Labels = map[string]string{"pod": "noip"}
		c.k8sClient.CoreV1().Pods(defaultNs).Update(ctx, nginx1NoIPsWithLabel, metav1.UpdateOptions{})
		if err := waitForPodLabelUpdate(c.podLister, nginx1NoIPsWithLabel); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be updated, err: %v", nginx1NoIPsWithLabel.Namespace, nginx1NoIPsWithLabel.Name, err)
		}

		// Update a Pod with IPs
		nginx1Updated := nginx1NoIPs.DeepCopy()
		nginx1Updated.Status.PodIP = "192.168.10.11"
		nginx1Updated.Status.HostIP = "172.16.10.11"
		c.k8sClient.CoreV1().Pods(defaultNs).Update(ctx, nginx1Updated, metav1.UpdateOptions{})
		if err := waitForPodIPUpdate(c.podLister, nginx1Updated); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be updated, err: %v", nginx1Updated.Namespace, nginx1Updated.Name, err)
		}
		c.ofClient.EXPECT().InstallMulticlusterPodFlows(net.ParseIP("192.168.10.11"), net.ParseIP("172.16.10.11"))
		c.processPodNextWorkItem()

		// Update a Pod with new host IP
		nginx1UpdatedHostIP := nginx1Updated.DeepCopy()
		nginx1UpdatedHostIP.Status.HostIP = "172.16.12.12"
		c.k8sClient.CoreV1().Pods(defaultNs).Update(ctx, nginx1UpdatedHostIP, metav1.UpdateOptions{})
		if err := waitForPodIPUpdate(c.podLister, nginx1UpdatedHostIP); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be updated, err: %v", nginx1UpdatedHostIP.Namespace, nginx1UpdatedHostIP.Name, err)
		}
		c.ofClient.EXPECT().InstallMulticlusterPodFlows(net.ParseIP("192.168.10.11"), net.ParseIP("172.16.12.12"))
		c.processPodNextWorkItem()

		// Update a Pod's label
		nginx1UpdatedLabel := nginx1Updated.DeepCopy()
		nginx1UpdatedLabel.Labels = map[string]string{"env": "test"}
		c.k8sClient.CoreV1().Pods(defaultNs).Update(ctx, nginx1UpdatedLabel, metav1.UpdateOptions{})
		if err := waitForPodLabelUpdate(c.podLister, nginx1UpdatedLabel); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be updated, err: %v", nginx1UpdatedLabel.Namespace, nginx1UpdatedLabel.Name, err)
		}

		// Update the old Pod with a new IP
		nginx1UpdatedWithNewIP := nginx1Updated.DeepCopy()
		nginx1UpdatedWithNewIP.Status.PodIP = "192.168.110.10"
		nginx1UpdatedWithNewIP.Status.HostIP = "172.16.10.11"
		nginx1UpdatedWithNewIP.CreationTimestamp = metav1.NewTime(time.Now())
		c.k8sClient.CoreV1().Pods(defaultNs).Update(ctx, nginx1UpdatedWithNewIP, metav1.UpdateOptions{})
		if err := waitForPodIPUpdate(c.podLister, nginx1UpdatedWithNewIP); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be updated, err: %v", nginx1UpdatedWithNewIP.Namespace, nginx1UpdatedWithNewIP.Name, err)
		}
		c.ofClient.EXPECT().UninstallMulticlusterPodFlows("192.168.10.11")
		c.ofClient.EXPECT().InstallMulticlusterPodFlows(net.ParseIP("192.168.110.10"), net.ParseIP("172.16.10.11"))
		c.processPodNextWorkItem()
		c.processPodNextWorkItem()

		// Create a Pod with the same Pod IP
		nginx1DupIP := nginx1UpdatedWithNewIP.DeepCopy()
		nginx1DupIP.Name = "nginx-1-dup-ip"
		nginx1DupIP.Status.HostIP = "172.16.10.11"
		nginx1DupIP.CreationTimestamp = metav1.NewTime(time.Now().Add(5 * time.Minute))
		c.k8sClient.CoreV1().Pods(defaultNs).Create(ctx, nginx1DupIP, metav1.CreateOptions{})
		if err := waitForPodRealized(c.podLister, nginx1DupIP); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be realized, err: %v", nginx1DupIP.Namespace, nginx1DupIP.Name, err)
		}
		c.ofClient.EXPECT().InstallMulticlusterPodFlows(net.ParseIP("192.168.110.10"), net.ParseIP("172.16.10.11"))
		c.processPodNextWorkItem()

		// Update the old Pod with an empty IP
		nginx1UpdatedWithEmptyIP := nginx1UpdatedWithNewIP.DeepCopy()
		nginx1UpdatedWithEmptyIP.Status.PodIP = ""
		nginx1UpdatedWithEmptyIP.Status.HostIP = "172.16.10.11"
		c.k8sClient.CoreV1().Pods(defaultNs).Update(ctx, nginx1UpdatedWithEmptyIP, metav1.UpdateOptions{})
		if err := waitForPodIPUpdate(c.podLister, nginx1UpdatedWithEmptyIP); err != nil {
			t.Errorf("Error when waiting for Pod '%s/%s' to be updated, err: %v", nginx1UpdatedWithEmptyIP.Namespace, nginx1UpdatedWithEmptyIP.Name, err)
		}
		c.ofClient.EXPECT().InstallMulticlusterPodFlows(net.ParseIP("192.168.110.10"), net.ParseIP("172.16.10.11"))
		c.processPodNextWorkItem()

		// Delete the old Pod
		c.k8sClient.CoreV1().Pods(defaultNs).Delete(ctx, nginx1UpdatedWithEmptyIP.Name, metav1.DeleteOptions{})

		// Delete the new Pod
		c.k8sClient.CoreV1().Pods(defaultNs).Delete(ctx, nginx1DupIP.Name, metav1.DeleteOptions{})
		c.ofClient.EXPECT().UninstallMulticlusterPodFlows("192.168.110.10")
		c.processPodNextWorkItem()
	}()
	select {
	case <-time.After(5 * time.Second):
		t.Errorf("Test didn't finish in time")
	case <-finishCh:
	}
}

func waitForGatewayRealized(gwLister mclisters.GatewayLister, gateway *mcv1alpha1.Gateway) error {
	return wait.PollUntilContextTimeout(context.Background(), interval, timeout, false, func(ctx context.Context) (bool, error) {
		_, err := gwLister.Gateways(gateway.Namespace).Get(gateway.Name)
		if err != nil {
			return false, nil
		}
		return true, err
	})
}

func waitForPodIPUpdate(podLister v1.PodLister, pod *corev1.Pod) error {
	return wait.PollUntilContextTimeout(context.Background(), interval, timeout, false, func(ctx context.Context) (bool, error) {
		getPod, err := podLister.Pods(pod.Namespace).Get(pod.Name)
		if err != nil || pod.Status.PodIP != getPod.Status.PodIP || pod.Status.HostIP != getPod.Status.HostIP {
			return false, nil
		}
		return true, err
	})
}
