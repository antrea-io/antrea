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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	oftest "antrea.io/antrea/pkg/agent/openflow/testing"
	routetest "antrea.io/antrea/pkg/agent/route/testing"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	wgtest "antrea.io/antrea/pkg/agent/wireguard/testing"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	ovsctltest "antrea.io/antrea/pkg/ovs/ovsctl/testing"
	utilip "antrea.io/antrea/pkg/util/ip"
)

var (
	gatewayMAC, _   = net.ParseMAC("00:00:00:00:00:01")
	_, podCIDR, _   = net.ParseCIDR("1.1.1.0/24")
	_, podCIDR2, _  = net.ParseCIDR("1.1.2.0/24")
	_, podCIDR3, _  = net.ParseCIDR("2001:4860:4860::8888/32")
	podCIDRGateway  = ip.NextIP(podCIDR.IP)
	podCIDR2Gateway = ip.NextIP(podCIDR2.IP)
	podCIDR3Gateway = ip.NextIP(podCIDR3.IP)
	nodeIP1         = net.ParseIP("10.10.10.10")
	dsIPs1          = utilip.DualStackIPs{IPv4: nodeIP1}
	nodeIP2         = net.ParseIP("10.10.10.11")
	dsIPs2          = utilip.DualStackIPs{IPv4: nodeIP2}
	nodeIP3         = net.ParseIP("2001:db8::68")
	dsIPs3          = utilip.DualStackIPs{IPv6: nodeIP3}

	node1 = &corev1.Node{
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
)

type fakeController struct {
	*Controller
	clientset       *fake.Clientset
	informerFactory informers.SharedInformerFactory
	ofClient        *oftest.MockClient
	ovsClient       *ovsconfigtest.MockOVSBridgeClient
	routeClient     *routetest.MockInterface
	interfaceStore  interfacestore.InterfaceStore
	ovsCtlClient    *ovsctltest.MockOVSCtlClient
	wireguardClient *wgtest.MockInterface
}

type fakeIPsecCertificateManager struct{}

func (f *fakeIPsecCertificateManager) HasSynced() bool {
	return true
}

func newController(t *testing.T, networkConfig *config.NetworkConfig, objects ...runtime.Object) *fakeController {
	clientset := fake.NewSimpleClientset(objects...)
	informerFactory := informers.NewSharedInformerFactory(clientset, 12*time.Hour)
	ctrl := gomock.NewController(t)
	ofClient := oftest.NewMockClient(ctrl)
	ovsClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	routeClient := routetest.NewMockInterface(ctrl)
	interfaceStore := interfacestore.NewInterfaceStore()
	ipsecCertificateManager := &fakeIPsecCertificateManager{}
	ovsCtlClient := ovsctltest.NewMockOVSCtlClient(ctrl)
	wireguardClient := wgtest.NewMockInterface(ctrl)
	c := NewNodeRouteController(informerFactory.Core().V1().Nodes(), ofClient, ovsCtlClient, ovsClient, routeClient, interfaceStore, networkConfig, &config.NodeConfig{GatewayConfig: &config.GatewayConfig{
		IPv4: nil,
		MAC:  gatewayMAC,
	}}, wireguardClient, ipsecCertificateManager)
	return &fakeController{
		Controller:      c,
		clientset:       clientset,
		informerFactory: informerFactory,
		ofClient:        ofClient,
		ovsClient:       ovsClient,
		routeClient:     routeClient,
		ovsCtlClient:    ovsCtlClient,
		interfaceStore:  interfaceStore,
		wireguardClient: wireguardClient,
	}
}

func TestControllerWithDuplicatePodCIDR(t *testing.T) {
	c := newController(t, &config.NetworkConfig{})
	defer c.queue.ShutDown()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	// Must wait for cache sync, otherwise resource creation events will be missing if the resources are created
	// in-between list and watch call of an informer. This is because fake clientset doesn't support watching with
	// resourceVersion. A watcher of fake clientset only gets events that happen after the watcher is created.
	c.informerFactory.WaitForCacheSync(stopCh)

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
		c.ofClient.EXPECT().InstallNodeFlows("node1", gomock.Any(), &dsIPs1, uint32(0), nil).Times(1)
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
		c.ofClient.EXPECT().InstallNodeFlows("node2", gomock.Any(), &dsIPs2, uint32(0), nil).Times(1)
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
	c := newController(t, &config.NetworkConfig{})
	defer c.queue.ShutDown()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	// Must wait for cache sync, otherwise resource creation events will be missing if the resources are created
	// in-between list and watch call of an informer. This is because fake clientset doesn't support watching with
	// resourceVersion. A watcher of fake clientset only gets events that happen after the watcher is created.
	c.informerFactory.WaitForCacheSync(stopCh)
	c.Controller.nodeConfig.PodIPv4CIDR = podCIDR
	c.Controller.nodeConfig.PodIPv6CIDR = podCIDR3

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
	node3 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node3",
		},
		Spec: corev1.NodeSpec{
			PodCIDR:  podCIDR3.String(),
			PodCIDRs: []string{podCIDR3.String()},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: nodeIP3.String(),
				},
			},
		},
	}

	c.clientset.CoreV1().Nodes().Create(context.TODO(), node1, metav1.CreateOptions{})
	c.ofClient.EXPECT().InstallNodeFlows("node1", gomock.Any(), &dsIPs1, uint32(0), nil).Times(1)
	c.routeClient.EXPECT().AddRoutes(podCIDR, "node1", nodeIP1, podCIDRGateway).Times(1)
	c.processNextWorkItem()

	c.clientset.CoreV1().Nodes().Create(context.TODO(), node2, metav1.CreateOptions{})
	c.ofClient.EXPECT().InstallNodeFlows("node2", gomock.Any(), &dsIPs2, uint32(0), nil).Times(1)
	c.routeClient.EXPECT().AddRoutes(podCIDR2, "node2", nodeIP2, podCIDR2Gateway).Times(1)
	c.processNextWorkItem()

	c.clientset.CoreV1().Nodes().Create(context.TODO(), node3, metav1.CreateOptions{})
	c.ofClient.EXPECT().InstallNodeFlows("node3", gomock.Any(), &dsIPs3, uint32(0), nil).Times(1)
	c.routeClient.EXPECT().AddRoutes(podCIDR3, "node3", nodeIP3, podCIDR3Gateway).Times(1)
	c.processNextWorkItem()

	assert.Equal(t, true, c.Controller.IPInPodSubnets(net.ParseIP("1.1.1.1")))
	assert.Equal(t, true, c.Controller.IPInPodSubnets(net.ParseIP("2001:4860:4860::8889")))
	assert.Equal(t, true, c.Controller.IPInPodSubnets(net.ParseIP("1.1.2.1")))
	assert.Equal(t, false, c.Controller.IPInPodSubnets(net.ParseIP("10.10.10.10")))
	assert.Equal(t, false, c.Controller.IPInPodSubnets(net.ParseIP("8.8.8.8")))
}

func setup(t *testing.T, ifaces []*interfacestore.InterfaceConfig, authenticationMode config.IPsecAuthenticationMode) *fakeController {
	c := newController(t, &config.NetworkConfig{
		TrafficEncapMode:      0,
		TunnelType:            ovsconfig.TunnelType("vxlan"),
		TrafficEncryptionMode: config.TrafficEncryptionModeIPSec,
		IPsecConfig: config.IPsecConfig{
			PSK:                "changeme",
			AuthenticationMode: authenticationMode,
		},
	})
	for _, i := range ifaces {
		c.interfaceStore.AddInterface(i)
	}
	return c
}

func TestRemoveStaleTunnelPorts(t *testing.T) {
	c := setup(t, []*interfacestore.InterfaceConfig{
		{
			Type:          interfacestore.IPSecTunnelInterface,
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
	}, config.IPsecAuthenticationModePSK)

	defer c.queue.ShutDown()
	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	nodeWithTunnel := &corev1.Node{
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

	c.clientset.CoreV1().Nodes().Create(context.TODO(), nodeWithTunnel, metav1.CreateOptions{})
	c.ovsClient.EXPECT().DeletePort("123").Times(1)

	err := c.removeStaleTunnelPorts()
	assert.NoError(t, err)
}

func TestCreateIPSecTunnelPortPSK(t *testing.T) {
	c := setup(t, []*interfacestore.InterfaceConfig{
		{
			Type:          interfacestore.IPSecTunnelInterface,
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
			Type:          interfacestore.IPSecTunnelInterface,
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
	}, config.IPsecAuthenticationModePSK)

	defer c.queue.ShutDown()
	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)

	node1PortName := util.GenerateNodeTunnelInterfaceName("xyz-k8s-0-1")
	node2PortName := util.GenerateNodeTunnelInterfaceName("xyz-k8s-0-2")
	node3PortName := util.GenerateNodeTunnelInterfaceName("xyz-k8s-0-3")
	c.ovsClient.EXPECT().CreateTunnelPortExt(
		node1PortName, ovsconfig.TunnelType("vxlan"), int32(0),
		false, "", nodeIP1.String(), "", "changeme", nil,
		map[string]interface{}{ovsExternalIDNodeName: "xyz-k8s-0-1",
			interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaIPsecTunnel,
		}).Times(1)
	c.ovsClient.EXPECT().CreateTunnelPortExt(
		node2PortName, ovsconfig.TunnelType("vxlan"), int32(0),
		false, "", nodeIP2.String(), "", "changeme", nil,
		map[string]interface{}{ovsExternalIDNodeName: "xyz-k8s-0-2",
			interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaIPsecTunnel,
		}).Times(1)
	c.ovsClient.EXPECT().GetOFPort(node1PortName, false).Return(int32(1), nil)
	c.ovsCtlClient.EXPECT().SetPortNoFlood(1)
	c.ovsClient.EXPECT().GetOFPort(node2PortName, false).Return(int32(2), nil)
	c.ovsCtlClient.EXPECT().SetPortNoFlood(2)
	c.ovsClient.EXPECT().GetOFPort(node3PortName, false).Return(int32(5), nil)
	c.ovsCtlClient.EXPECT().SetPortNoFlood(5)
	c.ovsClient.EXPECT().DeletePort("123").Times(1)

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
			wantErr:    false,
			want:       2,
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

func TestCreateIPSecTunnelPortCert(t *testing.T) {
	c := setup(t, nil, config.IPsecAuthenticationModeCert)

	defer c.queue.ShutDown()
	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)

	node1PortName := util.GenerateNodeTunnelInterfaceName("xyz-k8s-0-1")
	c.ovsClient.EXPECT().CreateTunnelPortExt(
		node1PortName, ovsconfig.TunnelType("vxlan"), int32(0),
		false, "", nodeIP1.String(), "xyz-k8s-0-1", "", nil,
		map[string]interface{}{ovsExternalIDNodeName: "xyz-k8s-0-1",
			interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaIPsecTunnel,
		}).Times(1)
	c.ovsClient.EXPECT().GetOFPort(node1PortName, false).Return(int32(1), nil)
	c.ovsCtlClient.EXPECT().SetPortNoFlood(1)

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

func TestGetNodeMAC(t *testing.T) {
	validMac, _ := net.ParseMAC("00:1B:44:11:3A:B7")

	tests := []struct {
		name        string
		mac         string
		node        *corev1.Node
		expectedMac net.HardwareAddr
		expectedErr string
	}{
		{
			name: "valid MAC address",
			mac:  validMac.String(),
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{types.NodeMACAddressAnnotationKey: validMac.String()},
				},
			},
			expectedMac: validMac,
		},
		{
			name: "empty MAC in Node annotation",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{types.NodeMACAddressAnnotationKey: ""},
				},
			},
		},
		{
			name: "invalid MAC address",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{types.NodeMACAddressAnnotationKey: "00:1B:44:11:3A:BG"},
				},
			},
			expectedErr: "failed to parse MAC",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getNodeMAC(tt.node)
			if tt.expectedErr == "" {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedMac, got)
			} else {
				assert.ErrorContains(t, err, tt.expectedErr)
			}
		})
	}
}

func TestParseTunnelInterfaceConfig(t *testing.T) {
	tests := []struct {
		name                    string
		portData                *ovsconfig.OVSPortData
		portConfig              *interfacestore.OVSPortConfig
		expectedInterfaceConfig *interfacestore.InterfaceConfig
	}{
		{
			name: "Tunnel interface",
			portData: &ovsconfig.OVSPortData{
				Name:   "antrea-tun0",
				IFType: "gre",
				Options: map[string]string{
					"dst_port": "2",
				},
				OFPort: 1,
			},
			portConfig: &interfacestore.OVSPortConfig{
				OFPort: 1,
			},
			expectedInterfaceConfig: &interfacestore.InterfaceConfig{
				InterfaceName: "antrea-tun0",
				Type:          interfacestore.TunnelInterface,
				TunnelInterfaceConfig: &interfacestore.TunnelInterfaceConfig{
					Type:            ovsconfig.TunnelType("gre"),
					DestinationPort: 2,
				},
				OVSPortConfig: &interfacestore.OVSPortConfig{OFPort: 1}},
		},
		{
			name: "IPSec tunnel interface",
			portData: &ovsconfig.OVSPortData{
				Name:   "antrea-ipsec-tun",
				IFType: "gre",
				Options: map[string]string{
					"remote_name": "testNode",
					"dst_port":    "2",
				},
				OFPort:      1,
				ExternalIDs: map[string]string{ovsExternalIDNodeName: "testNode"},
			},
			portConfig: &interfacestore.OVSPortConfig{
				OFPort: 1,
			},
			expectedInterfaceConfig: &interfacestore.InterfaceConfig{
				InterfaceName: "antrea-ipsec-tun",
				Type:          interfacestore.IPSecTunnelInterface,
				TunnelInterfaceConfig: &interfacestore.TunnelInterfaceConfig{
					Type:       ovsconfig.TunnelType("gre"),
					NodeName:   "testNode",
					RemoteName: "testNode",
				},
				OVSPortConfig: &interfacestore.OVSPortConfig{OFPort: 1}},
		},
		{
			name:       "portData with no options",
			portData:   &ovsconfig.OVSPortData{},
			portConfig: &interfacestore.OVSPortConfig{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseTunnelInterfaceConfig(tt.portData, tt.portConfig)
			assert.Equal(t, tt.expectedInterfaceConfig, got)
		})
	}
}

func TestGetPodCIDRsOnNode(t *testing.T) {
	tests := []struct {
		name     string
		node     *corev1.Node
		expected []string
	}{
		{
			name: "non-empty PodCIDRs",
			node: &corev1.Node{
				Spec: corev1.NodeSpec{
					PodCIDRs: []string{"192.168.2.0/24"},
				},
			},
			expected: []string{"192.168.2.0/24"},
		},
		{
			name: "non-empty PodCIDR",
			node: &corev1.Node{
				Spec: corev1.NodeSpec{
					PodCIDR: "192.168.1.0/24",
				},
			},
			expected: []string{"192.168.1.0/24"},
		},
		{
			name: "empty PodCIDRs and PodCIDR",
			node: &corev1.Node{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPodCIDRsOnNode(tt.node)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestRemoveStaleGatewayRoutes(t *testing.T) {
	c := newController(t, &config.NetworkConfig{}, node1)
	defer c.queue.ShutDown()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)

	c.routeClient.EXPECT().Reconcile([]string{podCIDR.String()})
	err := c.removeStaleGatewayRoutes()
	assert.NoError(t, err)
}

func TestRemoveStaleWireGuardPeers(t *testing.T) {
	nodeWithWireGuard := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "nodeWithWireGuard",
			Annotations: map[string]string{types.NodeWireGuardPublicAnnotationKey: "fakekey"},
		},
	}
	c := newController(t, &config.NetworkConfig{
		TrafficEncryptionMode: config.TrafficEncryptionModeWireGuard,
	}, nodeWithWireGuard)
	defer c.queue.ShutDown()

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)

	c.wireguardClient.EXPECT().RemoveStalePeers(map[string]string{nodeWithWireGuard.Name: "fakekey"})
	err := c.removeStaleWireGuardPeers()
	assert.NoError(t, err)
}

func TestDeleteNodeRoute(t *testing.T) {
	nodeWithWireGuard := node1.DeepCopy()
	nodeWithWireGuard.Name = "nodeWithWireGuard"
	nodeWithWireGuard.Annotations = map[string]string{types.NodeWireGuardPublicAnnotationKey: "wgkey"}

	tests := []struct {
		name          string
		node          *corev1.Node
		mode          config.TrafficEncryptionModeType
		intface       *interfacestore.InterfaceConfig
		expectedCalls func(ovsClient *ovsconfigtest.MockOVSBridgeClient, mockRouteClient *routetest.MockInterface,
			ofClient *oftest.MockClient, wgClient *wgtest.MockInterface)
	}{
		{
			name: "delete a Node with IPSec mode",
			node: node1,
			mode: config.TrafficEncryptionModeIPSec,
			intface: &interfacestore.InterfaceConfig{
				Type:          interfacestore.IPSecTunnelInterface,
				InterfaceName: "node1-ipsec",
				TunnelInterfaceConfig: &interfacestore.TunnelInterfaceConfig{
					NodeName: node1.Name,
					Type:     "vxlan",
					PSK:      "changeme",
					RemoteIP: nodeIP2,
				},
				OVSPortConfig: &interfacestore.OVSPortConfig{
					PortUUID: "123",
				},
			},
			expectedCalls: func(ovsClient *ovsconfigtest.MockOVSBridgeClient, routeClient *routetest.MockInterface,
				ofClient *oftest.MockClient, wgClient *wgtest.MockInterface) {
				ovsClient.EXPECT().DeletePort("123")
				routeClient.EXPECT().DeleteRoutes(podCIDR)
				ofClient.EXPECT().UninstallNodeFlows(node1.Name)
			},
		},
		{
			name: "delete a Node with WireGuard mode",
			node: nodeWithWireGuard,
			mode: config.TrafficEncryptionModeWireGuard,
			expectedCalls: func(ovsClient *ovsconfigtest.MockOVSBridgeClient, routeClient *routetest.MockInterface,
				ofClient *oftest.MockClient, wgClient *wgtest.MockInterface) {
				routeClient.EXPECT().DeleteRoutes(podCIDR)
				ofClient.EXPECT().UninstallNodeFlows(nodeWithWireGuard.Name)
				wgClient.EXPECT().DeletePeer(nodeWithWireGuard.Name)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newController(t, &config.NetworkConfig{
				TrafficEncryptionMode: tt.mode,
			}, tt.node)
			c.installedNodes.Add(&nodeRouteInfo{
				nodeName: tt.node.Name,
				podCIDRs: []*net.IPNet{podCIDR},
			})

			defer c.queue.ShutDown()

			stopCh := make(chan struct{})
			defer close(stopCh)
			c.informerFactory.Start(stopCh)
			c.informerFactory.WaitForCacheSync(stopCh)

			if tt.intface != nil {
				c.interfaceStore.AddInterface(tt.intface)
			}

			tt.expectedCalls(c.ovsClient, c.routeClient, c.ofClient, c.wireguardClient)
			err := c.deleteNodeRoute(tt.node.Name)
			assert.NoError(t, err)
		})
	}
}
