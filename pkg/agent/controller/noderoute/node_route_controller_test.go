// Copyright 2020 Antrea Authors
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

package noderoute

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/golang/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	oftest "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	routetest "github.com/vmware-tanzu/antrea/pkg/agent/route/testing"
	ovsconfigtest "github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig/testing"
)

var (
	gatewayMAC, _  = net.ParseMAC("00:00:00:00:00:01")
	_, podCIDR, _  = net.ParseCIDR("1.1.1.0/24")
	podCIDRGateway = ip.NextIP(podCIDR.IP)
	nodeIP1        = net.ParseIP("10.10.10.10")
	nodeIP2        = net.ParseIP("10.10.10.11")
)

type fakeController struct {
	*Controller
	clientset       *fake.Clientset
	informerFactory informers.SharedInformerFactory
	ofClient        *oftest.MockClient
	ovsClient       *ovsconfigtest.MockOVSBridgeClient
	routeClient     *routetest.MockInterface
	interfaceStore  interfacestore.InterfaceStore
}

func newController(t *testing.T) (*fakeController, func()) {
	clientset := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(clientset, 12*time.Hour)
	ctrl := gomock.NewController(t)
	ofClient := oftest.NewMockClient(ctrl)
	ovsClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	routeClient := routetest.NewMockInterface(ctrl)
	interfaceStore := interfacestore.NewInterfaceStore()
	c := NewNodeRouteController(clientset, informerFactory, ofClient, ovsClient, routeClient, interfaceStore, &config.NetworkConfig{}, &config.NodeConfig{GatewayConfig: &config.GatewayConfig{
		IPv4: nil,
		MAC:  gatewayMAC,
	}})
	return &fakeController{
		Controller:      c,
		clientset:       clientset,
		informerFactory: informerFactory,
		ofClient:        ofClient,
		ovsClient:       ovsClient,
		routeClient:     routeClient,
		interfaceStore:  interfaceStore,
	}, ctrl.Finish
}

func TestControllerWithDuplicatePodCIDR(t *testing.T) {
	c, closeFn := newController(t)
	defer closeFn()
	defer c.queue.ShutDown()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	// Must wait for cache sync, otherwise resource creation events will be missing if the resources are created
	// in-between list and watch call of an informer. This is because fake clientset doesn't support watching with
	// resourceVersion. A watcher of fake clientset only gets events that happen after the watcher is created.
	c.informerFactory.WaitForCacheSync(stopCh)

	node1 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
		},
		Spec: corev1.NodeSpec{
			PodCIDR:  podCIDR.String(),
			PodCIDRs: []string{podCIDR.String()},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: nodeIP1.String(),
				},
			},
		},
	}
	node2 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node2",
		},
		Spec: corev1.NodeSpec{
			PodCIDR:  podCIDR.String(),
			PodCIDRs: []string{podCIDR.String()},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: nodeIP2.String(),
				},
			},
		},
	}

	finishCh := make(chan struct{})
	go func() {
		defer close(finishCh)

		c.clientset.CoreV1().Nodes().Create(context.TODO(), node1, metav1.CreateOptions{})
		// The 2nd argument is Any() because the argument is unpredictable when it uses pointer as the key of map.
		// The argument type is map[*net.IPNet]net.IP.
		c.ofClient.EXPECT().InstallNodeFlows("node1", gomock.Any(), nodeIP1, uint32(0), nil).Times(1)
		c.routeClient.EXPECT().AddRoutes(podCIDR, "node1", nodeIP1, podCIDRGateway).Times(1)
		c.processNextWorkItem()

		// Since node1 is not deleted yet, routes and flows for node2 shouldn't be installed as its PodCIDR is duplicate.
		c.clientset.CoreV1().Nodes().Create(context.TODO(), node2, metav1.CreateOptions{})
		c.processNextWorkItem()

		// node1 is deleted, its routes and flows should be deleted.
		c.clientset.CoreV1().Nodes().Delete(context.TODO(), node1.Name, metav1.DeleteOptions{})
		c.ofClient.EXPECT().UninstallNodeFlows("node1").Times(1)
		c.routeClient.EXPECT().DeleteRoutes(podCIDR).Times(1)
		c.processNextWorkItem()

		// After node1 is deleted, routes and flows should be installed for node2 successfully.
		// The 2nd argument is Any() because the argument is unpredictable when it uses pointer as the key of map.
		// The argument type is map[*net.IPNet]net.IP.
		c.ofClient.EXPECT().InstallNodeFlows("node2", gomock.Any(), nodeIP2, uint32(0), nil).Times(1)
		c.routeClient.EXPECT().AddRoutes(podCIDR, "node2", nodeIP2, podCIDRGateway).Times(1)
		c.processNextWorkItem()
	}()

	select {
	case <-time.After(5 * time.Second):
		t.Errorf("Test didn't finish in time")
	case <-finishCh:
	}
}
