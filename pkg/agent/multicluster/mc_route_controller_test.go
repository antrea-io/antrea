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

package multicluster

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcfake "antrea.io/antrea/multicluster/pkg/client/clientset/versioned/fake"
	mcinformers "antrea.io/antrea/multicluster/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/agent/config"
	oftest "antrea.io/antrea/pkg/agent/openflow/testing"
	antrearoute "antrea.io/antrea/pkg/agent/route"
	routemock "antrea.io/antrea/pkg/agent/route/testing"
	"antrea.io/antrea/pkg/agent/wireguard"
	wgtest "antrea.io/antrea/pkg/agent/wireguard/testing"
	"antrea.io/antrea/pkg/config/agent"
)

type fakeRouteController struct {
	*MCDefaultRouteController
	mcClient        *mcfake.Clientset
	informerFactory mcinformers.SharedInformerFactory
	ofClient        *oftest.MockClient
	wireGuardClient *wgtest.MockInterface
}

func newMCDefaultRouteController(t *testing.T,
	nodeConfig *config.NodeConfig,
	networkConfig *config.NetworkConfig,
	wireGuardConfig agent.WireGuardConfig,
	routeClient antrearoute.Interface,
	trafficEncryptionMode string,
	wireGuardClient *wgtest.MockInterface,
) *fakeRouteController {
	mcClient := mcfake.NewSimpleClientset()
	mcInformerFactory := mcinformers.NewSharedInformerFactoryWithOptions(mcClient,
		60*time.Second,
		mcinformers.WithNamespace(defaultNs),
	)
	gwInformer := mcInformerFactory.Multicluster().V1alpha1().Gateways()
	ciImportInformer := mcInformerFactory.Multicluster().V1alpha1().ClusterInfoImports()

	multiclusterConfig := agent.MulticlusterConfig{
		Enable:                       true,
		EnableGateway:                true,
		Namespace:                    "default",
		EnableStretchedNetworkPolicy: true,
		EnablePodToPodConnectivity:   true,
		WireGuard:                    wireGuardConfig,
		TrafficEncryptionMode:        trafficEncryptionMode,
	}
	ctrl := gomock.NewController(t)
	ofClient := oftest.NewMockClient(ctrl)
	c := NewMCDefaultRouteController(
		mcClient,
		gwInformer,
		ciImportInformer,
		ofClient,
		nodeConfig,
		networkConfig,
		routeClient,
		multiclusterConfig,
	)
	c.wireGuardClient = wireGuardClient
	return &fakeRouteController{
		MCDefaultRouteController: c,
		mcClient:                 mcClient,
		informerFactory:          mcInformerFactory,
		ofClient:                 ofClient,
		wireGuardClient:          wireGuardClient,
	}
}

var (
	gw1CreationTime = metav1.NewTime(time.Now())
	gw2CreationTime = metav1.NewTime(time.Now().Add(10 * time.Minute))
	gw4CreationTime = metav1.NewTime(time.Now())
	gateway1        = mcv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "node-1",
			Namespace:         "default",
			CreationTimestamp: gw1CreationTime,
		},
		GatewayIP:  "172.17.0.11",
		InternalIP: "192.17.0.11",
	}
	gateway2 = mcv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "node-2",
			Namespace:         "default",
			CreationTimestamp: gw2CreationTime,
		},
		GatewayIP:  "172.17.0.12",
		InternalIP: "192.17.0.12",
	}
	gw1GatewayIP  = net.ParseIP(gateway1.GatewayIP)
	gw2InternalIP = net.ParseIP(gateway2.InternalIP)

	gateway4 = mcv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "node-4",
			Namespace:         "default",
			CreationTimestamp: gw4CreationTime,
		},
		GatewayIP:   "172.17.0.14",
		InternalIP:  "192.17.0.14",
		ServiceCIDR: "10.100.0.0/16",
		WireGuard: &mcv1alpha1.WireGuardInfo{
			PublicKey: "key",
		},
	}

	clusterInfoImport1 = mcv1alpha1.ClusterInfoImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-b-default-clusterinfo",
			Namespace: "default",
		},
		Spec: mcv1alpha1.ClusterInfo{
			ClusterID:   "cluster-b",
			ServiceCIDR: "10.12.2.0/12",
			GatewayInfos: []mcv1alpha1.GatewayInfo{
				{
					GatewayIP: "172.18.0.10",
				},
			},
		},
	}

	clusterInfoImport2 = mcv1alpha1.ClusterInfoImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-c-default-clusterinfo",
			Namespace: "default",
		},
		Spec: mcv1alpha1.ClusterInfo{
			ClusterID:   "cluster-c",
			ServiceCIDR: "13.13.2.0/12",
			GatewayInfos: []mcv1alpha1.GatewayInfo{
				{
					GatewayIP: "12.11.0.10",
				},
			},
		},
	}

	clusterInfoImport3 = mcv1alpha1.ClusterInfoImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-d-default-clusterinfo",
			Namespace: "default",
		},
		Spec: mcv1alpha1.ClusterInfo{
			ClusterID:   "cluster-d",
			ServiceCIDR: "14.14.4.0/12",
			GatewayInfos: []mcv1alpha1.GatewayInfo{
				{
					GatewayIP: "12.13.0.10",
				},
			},
			PodCIDRs: []string{
				"10.10.0.0/16",
			},
			WireGuard: &mcv1alpha1.WireGuardInfo{
				PublicKey: "key",
			},
		},
	}
)

func TestMCRouteControllerAsWireGuardGateway(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockInterface := routemock.NewMockInterface(ctrl)
	networkConfig := &config.NetworkConfig{}
	wgClient := wgtest.NewMockInterface(ctrl)
	c := newMCDefaultRouteController(t,
		&config.NodeConfig{
			Name: "node-4",
			PodIPv4CIDR: &net.IPNet{
				IP: net.ParseIP("10.10.0.0"),
			},
		},
		networkConfig,
		agent.WireGuardConfig{},
		mockInterface,
		"wireGuard",
		wgClient,
	)
	defer c.queue.ShutDown()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	wireGuardNewFunc = func(nodeConfig *config.NodeConfig, wireGuardConfig *config.WireGuardConfig) (wireguard.Interface, error) {
		return wgClient, nil
	}

	finishCh := make(chan struct{})
	go func() {
		defer close(finishCh)

		// Create Gateway4
		c.mcClient.MulticlusterV1alpha1().Gateways(gateway4.GetNamespace()).Create(context.TODO(),
			&gateway4, metav1.CreateOptions{})
		c.wireGuardClient.EXPECT().CleanUp().AnyTimes()
		c.wireGuardClient.EXPECT().Init(net.ParseIP("10.100.0.0"), nil)
		c.ofClient.EXPECT().InstallMulticlusterClassifierFlows(uint32(1), true).Times(1)
		c.processNextWorkItem()
		c.processNextWorkItem()

		// Create ClusterInfoImport3
		c.mcClient.MulticlusterV1alpha1().ClusterInfoImports(clusterInfoImport3.GetNamespace()).
			Create(context.TODO(), &clusterInfoImport3, metav1.CreateOptions{})
		peerNodeIP3 := getPeerGatewayTunnelIP(clusterInfoImport3.Spec, true)
		remoteWGIP, _, _ := net.ParseCIDR(clusterInfoImport3.Spec.ServiceCIDR)
		remoteWireGuardNet := &net.IPNet{IP: remoteWGIP, Mask: net.CIDRMask(32, 32)}
		c.wireGuardClient.EXPECT().UpdatePeer(clusterInfoImport3.Name, clusterInfoImport3.Spec.WireGuard.PublicKey,
			net.ParseIP(clusterInfoImport3.Spec.GatewayInfos[0].GatewayIP), []*net.IPNet{remoteWireGuardNet})
		c.ofClient.EXPECT().InstallMulticlusterGatewayFlows(clusterInfoImport3.Name,
			gomock.Any(), peerNodeIP3, gomock.Any(), true).Times(1)
		mockInterface.EXPECT().AddRouteForLink(gomock.Any(), 0).Times(1)
		c.processNextWorkItem()

		// Delete Gateway
		c.mcClient.MulticlusterV1alpha1().Gateways(gateway4.GetNamespace()).Delete(context.TODO(),
			gateway4.Name, metav1.DeleteOptions{})
		c.ofClient.EXPECT().UninstallMulticlusterFlows(clusterInfoImport3.Name).Times(1)
		c.processNextWorkItem()
	}()
	select {
	case <-time.After(5 * time.Second):
		t.Errorf("Test didn't finish in time")
	case <-finishCh:
	}
}

func TestMCRouteControllerAsGateway(t *testing.T) {
	c := newMCDefaultRouteController(
		t,
		&config.NodeConfig{Name: "node-1"},
		&config.NetworkConfig{},
		agent.WireGuardConfig{},
		nil,
		"none",
		nil,
	)
	defer c.queue.ShutDown()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)

	finishCh := make(chan struct{})
	go func() {
		defer close(finishCh)

		// Create Gateway1
		c.mcClient.MulticlusterV1alpha1().Gateways(gateway1.GetNamespace()).Create(context.TODO(),
			&gateway1, metav1.CreateOptions{})
		c.ofClient.EXPECT().InstallMulticlusterClassifierFlows(uint32(1), true).Times(1)
		c.processNextWorkItem()

		// Create two ClusterInfoImports
		c.mcClient.MulticlusterV1alpha1().ClusterInfoImports(clusterInfoImport1.GetNamespace()).
			Create(context.TODO(), &clusterInfoImport1, metav1.CreateOptions{})
		peerNodeIP1 := getPeerGatewayTunnelIP(clusterInfoImport1.Spec, false)
		c.ofClient.EXPECT().InstallMulticlusterGatewayFlows(clusterInfoImport1.Name,
			gomock.Any(), peerNodeIP1, gw1GatewayIP, true).Times(1)
		c.processNextWorkItem()

		c.mcClient.MulticlusterV1alpha1().ClusterInfoImports(clusterInfoImport2.GetNamespace()).
			Create(context.TODO(), &clusterInfoImport2, metav1.CreateOptions{})
		peerNodeIP2 := getPeerGatewayTunnelIP(clusterInfoImport2.Spec, false)
		c.ofClient.EXPECT().InstallMulticlusterGatewayFlows(clusterInfoImport2.Name,
			gomock.Any(), peerNodeIP2, gw1GatewayIP, true).Times(1)
		c.processNextWorkItem()

		// Update a ClusterInfoImport
		clusterInfoImport1.Spec.ServiceCIDR = "192.10.1.0/24"
		c.mcClient.MulticlusterV1alpha1().ClusterInfoImports(clusterInfoImport1.GetNamespace()).
			Update(context.TODO(), &clusterInfoImport1, metav1.UpdateOptions{})
		c.ofClient.EXPECT().InstallMulticlusterGatewayFlows(clusterInfoImport1.Name,
			gomock.Any(), peerNodeIP1, gw1GatewayIP, true).Times(1)
		c.processNextWorkItem()

		// Delete a ClusterInfoImport
		c.mcClient.MulticlusterV1alpha1().ClusterInfoImports(clusterInfoImport2.GetNamespace()).Delete(context.TODO(),
			clusterInfoImport2.Name, metav1.DeleteOptions{})
		c.ofClient.EXPECT().UninstallMulticlusterFlows(clusterInfoImport2.Name).Times(1)
		c.processNextWorkItem()

		// Update Gateway1's GatewayIP
		updatedGateway1a := gateway1.DeepCopy()
		updatedGateway1a.GatewayIP = "10.16.0.100"
		updatedGateway1aIP := net.ParseIP("10.16.0.100")
		c.mcClient.MulticlusterV1alpha1().Gateways(updatedGateway1a.GetNamespace()).Update(context.TODO(),
			updatedGateway1a, metav1.UpdateOptions{})
		c.ofClient.EXPECT().InstallMulticlusterGatewayFlows(clusterInfoImport1.Name,
			gomock.Any(), peerNodeIP1, updatedGateway1aIP, true).Times(1)
		c.processNextWorkItem()

		// Update Gateway1's InternalIP
		updatedGateway1b := updatedGateway1a.DeepCopy()
		updatedGateway1b.InternalIP = "17.162.0.10"
		c.mcClient.MulticlusterV1alpha1().Gateways(updatedGateway1b.GetNamespace()).Update(context.TODO(),
			updatedGateway1b, metav1.UpdateOptions{})
		c.processNextWorkItem()

		// Delete Gateway1
		c.mcClient.MulticlusterV1alpha1().Gateways(gateway1.GetNamespace()).Delete(context.TODO(),
			gateway1.Name, metav1.DeleteOptions{})
		c.ofClient.EXPECT().UninstallMulticlusterFlows(clusterInfoImport1.Name).Times(1)
		c.processNextWorkItem()

		// Create Gateway2 as active Gateway
		c.mcClient.MulticlusterV1alpha1().Gateways(gateway2.GetNamespace()).Create(context.TODO(),
			&gateway2, metav1.CreateOptions{})
		c.ofClient.EXPECT().InstallMulticlusterClassifierFlows(uint32(1), false).Times(1)
		c.ofClient.EXPECT().InstallMulticlusterNodeFlows(clusterInfoImport1.Name, gomock.Any(), gw2InternalIP, true).Times(1)
		c.processNextWorkItem()
	}()
	select {
	case <-time.After(5 * time.Second):
		t.Errorf("Test didn't finish in time")
	case <-finishCh:
	}
}

func TestMCRouteControllerAsRegularNode(t *testing.T) {
	c := newMCDefaultRouteController(
		t,
		&config.NodeConfig{Name: "node-3"},
		&config.NetworkConfig{},
		agent.WireGuardConfig{},
		nil,
		"none",
		nil,
	)
	defer c.queue.ShutDown()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)

	finishCh := make(chan struct{})
	go func() {
		defer close(finishCh)
		peerNodeIP1 := net.ParseIP(gateway1.InternalIP)
		peerNodeIP2 := net.ParseIP(gateway2.InternalIP)

		// Create Gateway1
		c.mcClient.MulticlusterV1alpha1().Gateways(gateway1.GetNamespace()).Create(context.TODO(),
			&gateway1, metav1.CreateOptions{})
		c.ofClient.EXPECT().InstallMulticlusterClassifierFlows(uint32(1), false).Times(1)
		c.processNextWorkItem()

		// Create two ClusterInfoImports
		c.mcClient.MulticlusterV1alpha1().ClusterInfoImports(clusterInfoImport1.GetNamespace()).
			Create(context.TODO(), &clusterInfoImport1, metav1.CreateOptions{})
		c.ofClient.EXPECT().InstallMulticlusterNodeFlows(clusterInfoImport1.Name,
			gomock.Any(), peerNodeIP1, true).Times(1)
		c.processNextWorkItem()

		c.mcClient.MulticlusterV1alpha1().ClusterInfoImports(clusterInfoImport2.GetNamespace()).
			Create(context.TODO(), &clusterInfoImport2, metav1.CreateOptions{})
		c.ofClient.EXPECT().InstallMulticlusterNodeFlows(clusterInfoImport2.Name,
			gomock.Any(), peerNodeIP1, true).Times(1)
		c.processNextWorkItem()

		// Update a ClusterInfoImport
		clusterInfoImport1.Spec.ServiceCIDR = "192.12.1.0/24"
		c.mcClient.MulticlusterV1alpha1().ClusterInfoImports(clusterInfoImport1.GetNamespace()).
			Update(context.TODO(), &clusterInfoImport1, metav1.UpdateOptions{})
		c.ofClient.EXPECT().InstallMulticlusterNodeFlows(clusterInfoImport1.Name,
			gomock.Any(), peerNodeIP1, true).Times(1)
		c.processNextWorkItem()

		// Delete a ClusterInfoImport
		c.mcClient.MulticlusterV1alpha1().ClusterInfoImports(clusterInfoImport2.GetNamespace()).Delete(context.TODO(),
			clusterInfoImport2.Name, metav1.DeleteOptions{})
		c.ofClient.EXPECT().UninstallMulticlusterFlows(clusterInfoImport2.Name).Times(1)
		c.processNextWorkItem()

		// Update Gateway1's GatewayIP
		updatedGateway1a := gateway1.DeepCopy()
		updatedGateway1a.GatewayIP = "10.16.0.100"
		c.mcClient.MulticlusterV1alpha1().Gateways(updatedGateway1a.GetNamespace()).Update(context.TODO(),
			updatedGateway1a, metav1.UpdateOptions{})
		c.processNextWorkItem()

		// Update Gateway1's InternalIP
		updatedGateway1b := updatedGateway1a.DeepCopy()
		updatedGateway1b.InternalIP = "17.162.0.10"
		updatedGateway1bIP := net.ParseIP("17.162.0.10")
		c.mcClient.MulticlusterV1alpha1().Gateways(updatedGateway1b.GetNamespace()).Update(context.TODO(),
			updatedGateway1b, metav1.UpdateOptions{})
		c.ofClient.EXPECT().InstallMulticlusterNodeFlows(clusterInfoImport1.Name,
			gomock.Any(), updatedGateway1bIP, true).Times(1)
		c.processNextWorkItem()

		// Delete Gateway1
		c.mcClient.MulticlusterV1alpha1().Gateways(gateway1.GetNamespace()).Delete(context.TODO(),
			gateway1.Name, metav1.DeleteOptions{})
		c.ofClient.EXPECT().UninstallMulticlusterFlows(clusterInfoImport1.Name).Times(1)
		c.processNextWorkItem()

		// Create Gateway2 as the active Gateway
		c.mcClient.MulticlusterV1alpha1().Gateways(gateway2.GetNamespace()).Create(context.TODO(),
			&gateway2, metav1.CreateOptions{})
		c.ofClient.EXPECT().InstallMulticlusterClassifierFlows(uint32(1), false).Times(1)
		c.ofClient.EXPECT().InstallMulticlusterNodeFlows(clusterInfoImport1.Name, gomock.Any(), peerNodeIP2, true).Times(1)
		c.processNextWorkItem()
	}()
	select {
	case <-time.After(5 * time.Second):
		t.Errorf("Test didn't finish in time")
	case <-finishCh:
	}
}

func TestRemoveWireGuardRouteAndPeer(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockInterface := routemock.NewMockInterface(ctrl)
	wgClient := wgtest.NewMockInterface(ctrl)
	networkConfig := &config.NetworkConfig{}
	c := newMCDefaultRouteController(t,
		&config.NodeConfig{
			Name: "node-4",
			PodIPv4CIDR: &net.IPNet{
				IP: net.ParseIP("10.10.0.0/16"),
			},
		},
		networkConfig,
		agent.WireGuardConfig{},
		mockInterface,
		"wireGuard",
		wgClient,
	)
	defer c.queue.ShutDown()
	mockInterface.EXPECT().DeleteRouteForLink(gomock.Any(), gomock.Any()).Times(1)

	ciImport := &mcv1alpha1.ClusterInfoImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-a-info",
			Namespace: "default",
		},
		Spec: mcv1alpha1.ClusterInfo{
			ServiceCIDR: "10.100.0.0/16",
		},
	}

	wgClient.EXPECT().DeletePeer(ciImport.Name)
	err := c.removeWireGuardRouteAndPeer(ciImport)
	assert.NoError(t, err)
}

func TestEnqueueGateway(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockInterface := routemock.NewMockInterface(ctrl)
	networkConfig := &config.NetworkConfig{}
	c := newMCDefaultRouteController(t,
		&config.NodeConfig{
			Name: "node-4",
			PodIPv4CIDR: &net.IPNet{
				IP: net.ParseIP("10.10.0.0/16"),
			},
		},
		networkConfig,
		agent.WireGuardConfig{},
		mockInterface,
		"wireGuard",
		nil,
	)
	defer c.queue.ShutDown()

	testCases := []struct {
		name      string
		obj       interface{}
		isDeleted bool
		expectNum int
	}{
		{
			name:      "gateway is deleted, enqueue successfully",
			obj:       &mcv1alpha1.Gateway{},
			isDeleted: true,
			expectNum: 1,
		},
		{
			name: "gateway deleted, enqueue successfully",
			obj: &mcv1alpha1.Gateway{
				InternalIP: "10.10.1.1",
				GatewayIP:  "10.10.1.1",
			},
			isDeleted: true,
			expectNum: 1,
		},
		{
			name:      "gateway not deleted, enqueue failed",
			obj:       &mcv1alpha1.Gateway{},
			isDeleted: false,
			expectNum: 0,
		},
		{
			name:      "unexpect object",
			obj:       map[string]string{},
			isDeleted: false,
			expectNum: 0,
		},

		{
			name: "invalid delete state",
			obj: cache.DeletedFinalStateUnknown{
				Obj: map[string]string{},
			},
			isDeleted: false,
			expectNum: 0,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "gatewayroute")
			c.enqueueGateway(tt.obj, tt.isDeleted)
			assert.Equal(t, tt.expectNum, c.queue.Len())
		})
	}
}

func TestEnqueueClusterInfoImport(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockInterface := routemock.NewMockInterface(ctrl)
	networkConfig := &config.NetworkConfig{}
	c := newMCDefaultRouteController(t,
		&config.NodeConfig{
			Name: "node-4",
			PodIPv4CIDR: &net.IPNet{
				IP: net.ParseIP("10.10.0.0/16"),
			},
		},
		networkConfig,
		agent.WireGuardConfig{},
		mockInterface,
		"wireGuard",
		nil,
	)
	defer c.queue.ShutDown()

	testCases := []struct {
		name      string
		obj       interface{}
		isDeleted bool
		expectNum int
	}{
		{
			name:      "ClusterInfoImport without GatewayInfo",
			obj:       &mcv1alpha1.ClusterInfoImport{},
			isDeleted: false,
			expectNum: 0,
		},
		{
			name: "ClusterInfoImport without Gateway IP",
			obj: &mcv1alpha1.ClusterInfoImport{
				Spec: mcv1alpha1.ClusterInfo{
					GatewayInfos: []mcv1alpha1.GatewayInfo{
						{
							GatewayIP: "abc",
						},
					},
				},
			},
			isDeleted: false,
			expectNum: 0,
		},
		{
			name:      "unexpected object",
			obj:       map[string]string{},
			expectNum: 0,
		},
		{
			name:      "invalid delete state",
			obj:       cache.DeletedFinalStateUnknown{},
			expectNum: 0,
		},
		{
			name:      "ClusterInfoImport delete, enqueue successfully",
			obj:       &mcv1alpha1.ClusterInfoImport{},
			isDeleted: true,
			expectNum: 1,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "gatewayroute")
			c.enqueueClusterInfoImport(tt.obj, tt.isDeleted)
			assert.Equal(t, tt.expectNum, c.queue.Len())
		})
	}
}
