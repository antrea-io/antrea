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
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	oftest "antrea.io/antrea/pkg/agent/openflow/testing"
	routetest "antrea.io/antrea/pkg/agent/route/testing"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
)

var (
	gatewayMAC, _   = net.ParseMAC("00:00:00:00:00:01")
	_, podCIDR, _   = net.ParseCIDR("1.1.1.0/24")
	_, podCIDR2, _  = net.ParseCIDR("1.1.2.0/24")
	podCIDRGateway  = ip.NextIP(podCIDR.IP)
	podCIDR2Gateway = ip.NextIP(podCIDR2.IP)
	nodeIP1         = net.ParseIP("10.10.10.10")
	nodeIP2         = net.ParseIP("10.10.10.11")
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

func newController(t *testing.T, networkConfig *config.NetworkConfig) (*fakeController, func()) {
	clientset := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(clientset, 12*time.Hour)
	ctrl := gomock.NewController(t)
	ofClient := oftest.NewMockClient(ctrl)
	ovsClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	routeClient := routetest.NewMockInterface(ctrl)
	interfaceStore := interfacestore.NewInterfaceStore()

	c := NewNodeRouteController(clientset, informerFactory, ofClient, ovsClient, routeClient, interfaceStore, networkConfig, &config.NodeConfig{GatewayConfig: &config.GatewayConfig{
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
	c, closeFn := newController(t, &config.NetworkConfig{})
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

func TestIPInPodSubnets(t *testing.T) {
	c, closeFn := newController(t, &config.NetworkConfig{})
	defer closeFn()
	defer c.queue.ShutDown()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	// Must wait for cache sync, otherwise resource creation events will be missing if the resources are created
	// in-between list and watch call of an informer. This is because fake clientset doesn't support watching with
	// resourceVersion. A watcher of fake clientset only gets events that happen after the watcher is created.
	c.informerFactory.WaitForCacheSync(stopCh)
	c.Controller.nodeConfig.PodIPv4CIDR = podCIDR

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
			PodCIDR:  podCIDR2.String(),
			PodCIDRs: []string{podCIDR2.String()},
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

	c.clientset.CoreV1().Nodes().Create(context.TODO(), node1, metav1.CreateOptions{})
	// The 2nd argument is Any() because the argument is unpredictable when it uses pointer as the key of map.
	// The argument type is map[*net.IPNet]net.IP.
	c.ofClient.EXPECT().InstallNodeFlows("node1", gomock.Any(), nodeIP1, uint32(0), nil).Times(1)
	c.routeClient.EXPECT().AddRoutes(podCIDR, "node1", nodeIP1, podCIDRGateway).Times(1)
	c.processNextWorkItem()

	c.clientset.CoreV1().Nodes().Create(context.TODO(), node2, metav1.CreateOptions{})
	c.ofClient.EXPECT().InstallNodeFlows("node2", gomock.Any(), nodeIP2, uint32(0), nil).Times(1)
	c.routeClient.EXPECT().AddRoutes(podCIDR2, "node2", nodeIP2, podCIDR2Gateway).Times(1)
	c.processNextWorkItem()

	assert.Equal(t, true, c.Controller.IPInPodSubnets(net.ParseIP("1.1.1.1")))
	assert.Equal(t, true, c.Controller.IPInPodSubnets(net.ParseIP("1.1.2.1")))
	assert.Equal(t, false, c.Controller.IPInPodSubnets(net.ParseIP("10.10.10.10")))
	assert.Equal(t, false, c.Controller.IPInPodSubnets(net.ParseIP("8.8.8.8")))
}

func setup(t *testing.T, ifaces []*interfacestore.InterfaceConfig) (*fakeController, func()) {
	c, closeFn := newController(t, &config.NetworkConfig{
		TrafficEncapMode:  0,
		TunnelType:        ovsconfig.TunnelType("vxlan"),
		EnableIPSecTunnel: true,
		IPSecPSK:          "changeme",
	})
	for _, i := range ifaces {
		c.interfaceStore.AddInterface(i)
	}
	return c, closeFn
}

func TestRemoveStaleTunnelPorts(t *testing.T) {
	c, closeFn := setup(t, []*interfacestore.InterfaceConfig{
		{
			Type:          interfacestore.TunnelInterface,
			InterfaceName: util.GenerateNodeTunnelInterfaceName("xyz-k8s-0-1"),
			TunnelInterfaceConfig: &interfacestore.TunnelInterfaceConfig{
				NodeName: "xyz-k8s-0-1",
				Type:     ovsconfig.TunnelType("vxlan"),
				PSK:      "mismatchpsk",
				RemoteIP: nodeIP1,
			},
			OVSPortConfig: &interfacestore.OVSPortConfig{
				PortUUID: "123",
			},
		},
	})

	defer closeFn()
	defer c.queue.ShutDown()
	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	node1 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "xyz-k8s-0-1",
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

	c.clientset.CoreV1().Nodes().Create(context.TODO(), node1, metav1.CreateOptions{})
	c.ovsClient.EXPECT().DeletePort("123").Times(1)

	err := c.removeStaleTunnelPorts()
	assert.NoError(t, err)
}

func TestCreateIPSecTunnelPort(t *testing.T) {
	c, closeFn := setup(t, []*interfacestore.InterfaceConfig{
		{
			Type:          interfacestore.TunnelInterface,
			InterfaceName: "mismatchedname",
			TunnelInterfaceConfig: &interfacestore.TunnelInterfaceConfig{
				NodeName: "xyz-k8s-0-2",
				Type:     "vxlan",
				PSK:      "changeme",
				RemoteIP: nodeIP2,
			},
			OVSPortConfig: &interfacestore.OVSPortConfig{
				PortUUID: "123",
			},
		},
		{
			Type:          interfacestore.TunnelInterface,
			InterfaceName: util.GenerateNodeTunnelInterfaceName("xyz-k8s-0-3"),
			TunnelInterfaceConfig: &interfacestore.TunnelInterfaceConfig{
				NodeName: "xyz-k8s-0-3",
				Type:     "vxlan",
				PSK:      "changeme",
				RemoteIP: net.ParseIP("10.10.10.1"),
			},
			OVSPortConfig: &interfacestore.OVSPortConfig{
				PortUUID: "abc",
				OFPort:   int32(5),
			},
		},
	})

	defer closeFn()
	defer c.queue.ShutDown()
	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)

	node1PortName := util.GenerateNodeTunnelInterfaceName("xyz-k8s-0-1")
	c.ovsClient.EXPECT().CreateTunnelPortExt(
		node1PortName, ovsconfig.TunnelType("vxlan"), int32(0),
		false, "", nodeIP1.String(), "changeme",
		map[string]interface{}{ovsExternalIDNodeName: "xyz-k8s-0-1"}).Times(1)
	c.ovsClient.EXPECT().GetOFPort(node1PortName).Return(int32(1), nil)

	tests := []struct {
		name       string
		nodeName   string
		peerNodeIP net.IP
		wantErr    bool
		want       int32
	}{
		{
			name:       "create new port",
			nodeName:   "xyz-k8s-0-1",
			peerNodeIP: nodeIP1,
			wantErr:    false,
			want:       1,
		},
		{
			name:       "hit cache but interface name changed for the same node",
			nodeName:   "xyz-k8s-0-2",
			peerNodeIP: nodeIP2,
			wantErr:    true,
		},
		{
			name:       "hit cache and return directly",
			nodeName:   "xyz-k8s-0-3",
			peerNodeIP: net.ParseIP("10.10.10.1"),
			wantErr:    false,
			want:       5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.createIPSecTunnelPort(tt.nodeName, tt.peerNodeIP)
			hasErr := err != nil
			assert.Equal(t, tt.wantErr, hasErr)
			assert.Equal(t, tt.want, got)
		})
	}
}
