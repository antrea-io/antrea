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

	"github.com/golang/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcfake "antrea.io/antrea/multicluster/pkg/client/clientset/versioned/fake"
	mcinformers "antrea.io/antrea/multicluster/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	oftest "antrea.io/antrea/pkg/agent/openflow/testing"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
)

type fakeRouteController struct {
	*MCRouteController
	mcClient        *mcfake.Clientset
	informerFactory mcinformers.SharedInformerFactory
	ofClient        *oftest.MockClient
	ovsClient       *ovsconfigtest.MockOVSBridgeClient
	interfaceStore  interfacestore.InterfaceStore
}

func newMCRouteController(t *testing.T, nodeConfig *config.NodeConfig) (*fakeRouteController, func()) {
	mcClient := mcfake.NewSimpleClientset()
	mcInformerFactory := mcinformers.NewSharedInformerFactory(mcClient, 60*time.Second)
	gwInformer := mcInformerFactory.Multicluster().V1alpha1().Gateways()
	ciImpInformer := mcInformerFactory.Multicluster().V1alpha1().ClusterInfoImports()

	ctrl := gomock.NewController(t)
	ofClient := oftest.NewMockClient(ctrl)
	ovsClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	interfaceStore := interfacestore.NewInterfaceStore()
	c := NewMCRouteController(
		mcClient,
		gwInformer,
		ciImpInformer,
		ofClient,
		ovsClient,
		interfaceStore,
		nodeConfig,
		"default",
		true,
	)
	return &fakeRouteController{
		MCRouteController: c,
		mcClient:          mcClient,
		informerFactory:   mcInformerFactory,
		ofClient:          ofClient,
		ovsClient:         ovsClient,
		interfaceStore:    interfaceStore,
	}, ctrl.Finish
}

var (
	gw1CreationTime = metav1.NewTime(time.Now())
	gw2CreationTime = metav1.NewTime(time.Now().Add(10 * time.Minute))
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
)

func TestMCRouteControllerAsGateway(t *testing.T) {
	c, closeFn := newMCRouteController(t, &config.NodeConfig{Name: "node-1"})
	defer closeFn()
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
		peerNodeIP1 := getPeerGatewayIP(clusterInfoImport1.Spec)
		c.ofClient.EXPECT().InstallMulticlusterGatewayFlows(clusterInfoImport1.Name,
			gomock.Any(), peerNodeIP1, gw1GatewayIP, true).Times(1)
		c.processNextWorkItem()

		c.mcClient.MulticlusterV1alpha1().ClusterInfoImports(clusterInfoImport2.GetNamespace()).
			Create(context.TODO(), &clusterInfoImport2, metav1.CreateOptions{})
		peerNodeIP2 := getPeerGatewayIP(clusterInfoImport2.Spec)
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

		// Create Gateway2 as active Gateway
		c.mcClient.MulticlusterV1alpha1().Gateways(gateway2.GetNamespace()).Create(context.TODO(),
			&gateway2, metav1.CreateOptions{})
		c.ofClient.EXPECT().UninstallMulticlusterFlows(clusterInfoImport1.Name).Times(1)
		c.ofClient.EXPECT().InstallMulticlusterClassifierFlows(uint32(1), false).Times(1)
		c.ofClient.EXPECT().InstallMulticlusterNodeFlows(clusterInfoImport1.Name, gomock.Any(), gw2InternalIP, true).Times(1)
		c.processNextWorkItem()

		// Delete Gateway2, then Gateway1 become active Gateway
		c.mcClient.MulticlusterV1alpha1().Gateways(gateway2.GetNamespace()).Delete(context.TODO(),
			gateway2.Name, metav1.DeleteOptions{})
		c.ofClient.EXPECT().UninstallMulticlusterFlows(clusterInfoImport1.Name).Times(1)
		c.ofClient.EXPECT().InstallMulticlusterClassifierFlows(uint32(1), true).Times(1)
		c.ofClient.EXPECT().InstallMulticlusterGatewayFlows(clusterInfoImport1.Name,
			gomock.Any(), peerNodeIP1, updatedGateway1aIP, true).Times(1)
		c.processNextWorkItem()

		// Delete last Gateway
		c.mcClient.MulticlusterV1alpha1().Gateways(gateway1.GetNamespace()).Delete(context.TODO(),
			gateway1.Name, metav1.DeleteOptions{})
		c.ofClient.EXPECT().UninstallMulticlusterFlows(clusterInfoImport1.Name).Times(1)
		c.processNextWorkItem()
	}()
	select {
	case <-time.After(5 * time.Second):
		t.Errorf("Test didn't finish in time")
	case <-finishCh:
	}
}

func TestMCRouteControllerAsRegularNode(t *testing.T) {
	c, closeFn := newMCRouteController(t, &config.NodeConfig{Name: "node-3"})
	defer closeFn()
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

		// Create Gateway2 as the active Gateway
		c.mcClient.MulticlusterV1alpha1().Gateways(gateway2.GetNamespace()).Create(context.TODO(),
			&gateway2, metav1.CreateOptions{})
		c.ofClient.EXPECT().InstallMulticlusterClassifierFlows(uint32(1), false).Times(1)
		c.ofClient.EXPECT().InstallMulticlusterNodeFlows(clusterInfoImport1.Name, gomock.Any(), peerNodeIP2, true).Times(1)
		c.ofClient.EXPECT().UninstallMulticlusterFlows(clusterInfoImport1.Name).Times(1)
		c.processNextWorkItem()

		// Delete Gateway2, then Gateway1 become active Gateway
		c.mcClient.MulticlusterV1alpha1().Gateways(gateway2.GetNamespace()).Delete(context.TODO(),
			gateway2.Name, metav1.DeleteOptions{})
		c.ofClient.EXPECT().UninstallMulticlusterFlows(clusterInfoImport1.Name).Times(1)
		c.ofClient.EXPECT().InstallMulticlusterClassifierFlows(uint32(1), false).Times(1)
		c.ofClient.EXPECT().InstallMulticlusterNodeFlows(clusterInfoImport1.Name,
			gomock.Any(), updatedGateway1bIP, true).Times(1)
		c.processNextWorkItem()

		// Delete last Gateway
		c.mcClient.MulticlusterV1alpha1().Gateways(gateway1.GetNamespace()).Delete(context.TODO(),
			gateway1.Name, metav1.DeleteOptions{})
		c.ofClient.EXPECT().UninstallMulticlusterFlows(clusterInfoImport1.Name).Times(1)
		c.processNextWorkItem()
	}()
	select {
	case <-time.After(5 * time.Second):
		t.Errorf("Test didn't finish in time")
	case <-finishCh:
	}
}
