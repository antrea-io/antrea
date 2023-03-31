// Copyright 2019 Antrea Authors
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

package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	mock "github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/agent/cniserver"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/wireguard"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	ovsctltest "antrea.io/antrea/pkg/ovs/ovsctl/testing"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/runtime"
)

func newAgentInitializer(ovsBridgeClient ovsconfig.OVSBridgeClient, ifaceStore interfacestore.InterfaceStore) *Initializer {
	return &Initializer{ovsBridgeClient: ovsBridgeClient, ifaceStore: ifaceStore, hostGateway: "antrea-gw0"}
}

func convertExternalIDMap(in map[string]interface{}) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v.(string)
	}
	return out
}

func TestInitstore(t *testing.T) {
	controller := mock.NewController(t)
	defer controller.Finish()
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)

	mockOVSBridgeClient.EXPECT().GetPortList().Return(nil, ovsconfig.NewTransactionError(fmt.Errorf("Failed to list OVS ports"), true))

	store := interfacestore.NewInterfaceStore()
	initializer := newAgentInitializer(mockOVSBridgeClient, store)
	uplinkNetConfig := config.AdapterNetConfig{Name: "eth-antrea-test-1"}
	initializer.nodeConfig = &config.NodeConfig{UplinkNetConfig: &uplinkNetConfig}

	err := initializer.initInterfaceStore()
	assert.Error(t, err, "failed to handle OVS return error")

	uuid1 := uuid.New().String()
	uuid2 := uuid.New().String()
	p1MAC := "11:22:33:44:55:66"
	p1IP := "1.1.1.1"
	p2MAC := "11:22:33:44:55:77"
	p2IP := "1.1.1.2"
	p1NetMAC, _ := net.ParseMAC(p1MAC)
	p1NetIP := net.ParseIP(p1IP)
	p2NetMAC, _ := net.ParseMAC(p2MAC)
	p2NetIP := net.ParseIP(p2IP)

	ovsPort1 := ovsconfig.OVSPortData{UUID: uuid1, Name: "p1", IFName: "p1", OFPort: 11,
		ExternalIDs: convertExternalIDMap(cniserver.BuildOVSPortExternalIDs(
			interfacestore.NewContainerInterface("p1", uuid1, "pod1", "ns1", p1NetMAC, []net.IP{p1NetIP}, 0)))}
	ovsPort2 := ovsconfig.OVSPortData{UUID: uuid2, Name: "p2", IFName: "p2", OFPort: 12,
		ExternalIDs: convertExternalIDMap(cniserver.BuildOVSPortExternalIDs(
			interfacestore.NewContainerInterface("p2", uuid2, "pod2", "ns2", p2NetMAC, []net.IP{p2NetIP}, 0)))}
	initOVSPorts := []ovsconfig.OVSPortData{ovsPort1, ovsPort2}

	mockOVSBridgeClient.EXPECT().GetPortList().Return(initOVSPorts, ovsconfig.NewTransactionError(fmt.Errorf("Failed to list OVS ports"), true))
	initializer.initInterfaceStore()
	if store.Len() != 0 {
		t.Errorf("Failed to load OVS port in store")
	}

	mockOVSBridgeClient.EXPECT().GetPortList().Return(initOVSPorts, nil)
	initializer.initInterfaceStore()
	if store.Len() != 2 {
		t.Errorf("Failed to load OVS port in store")
	}
	container1, found1 := store.GetContainerInterface(uuid1)
	if !found1 {
		t.Errorf("Failed to load OVS port into local store")
	} else if container1.OFPort != 11 || len(container1.IPs) == 0 || container1.IPs[0].String() != p1IP || container1.MAC.String() != p1MAC || container1.InterfaceName != "p1" {
		t.Errorf("Failed to load OVS port configuration into local store")
	}
	_, found2 := store.GetContainerInterface(uuid2)
	if !found2 {
		t.Errorf("Failed to load OVS port into local store")
	}

	// OVS port external_ids should be updated to set AntreaInterfaceTypeKey if it doesn't exist in OVSPortData.
	delete(ovsPort1.ExternalIDs, interfacestore.AntreaInterfaceTypeKey)
	delete(ovsPort2.ExternalIDs, interfacestore.AntreaInterfaceTypeKey)
	initOVSPorts2 := []ovsconfig.OVSPortData{ovsPort1, ovsPort2}
	mockOVSBridgeClient.EXPECT().GetPortList().Return(initOVSPorts2, nil)
	updateExtIDsFunc := func(p ovsconfig.OVSPortData) map[string]interface{} {
		extIDs := make(map[string]interface{})
		for k, v := range p.ExternalIDs {
			extIDs[k] = v
		}
		extIDs[interfacestore.AntreaInterfaceTypeKey] = interfacestore.AntreaContainer
		return extIDs
	}
	mockOVSBridgeClient.EXPECT().SetPortExternalIDs(ovsPort1.Name, updateExtIDsFunc(ovsPort1)).Return(nil)
	mockOVSBridgeClient.EXPECT().SetPortExternalIDs(ovsPort2.Name, updateExtIDsFunc(ovsPort2)).Return(nil)
	initializer.initInterfaceStore()
}

func TestPersistRoundNum(t *testing.T) {
	const maxRetries = 3
	const roundNum uint64 = 5555

	controller := mock.NewController(t)
	defer controller.Finish()
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)

	transactionError := ovsconfig.NewTransactionError(fmt.Errorf("Failed to get external IDs"), true)
	firstCall := mockOVSBridgeClient.EXPECT().GetExternalIDs().Return(nil, transactionError)
	externalIDs := make(map[string]string)
	mockOVSBridgeClient.EXPECT().GetExternalIDs().Return(externalIDs, nil).After(firstCall)
	newExternalIDs := make(map[string]interface{})
	newExternalIDs[roundNumKey] = fmt.Sprint(roundNum)
	mockOVSBridgeClient.EXPECT().SetExternalIDs(mock.Eq(newExternalIDs)).Times(1)

	// The first call to saveRoundNum will fail. Because we set the retry interval to 0,
	// persistRoundNum should retry immediately and the second call will succeed (as per the
	// expectations above).
	persistRoundNum(roundNum, mockOVSBridgeClient, 0, maxRetries)
}

func TestGetRoundInfo(t *testing.T) {
	controller := mock.NewController(t)
	defer controller.Finish()
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)

	mockOVSBridgeClient.EXPECT().GetExternalIDs().Return(nil, ovsconfig.NewTransactionError(fmt.Errorf("Failed to get external IDs"), true))
	roundInfo := getRoundInfo(mockOVSBridgeClient)
	assert.Equal(t, uint64(initialRoundNum), roundInfo.RoundNum, "Unexpected round number")
	externalIDs := make(map[string]string)
	mockOVSBridgeClient.EXPECT().GetExternalIDs().Return(externalIDs, nil)
	roundInfo = getRoundInfo(mockOVSBridgeClient)
	assert.Equal(t, uint64(initialRoundNum), roundInfo.RoundNum, "Unexpected round number")
}

func TestInitK8sNodeLocalConfig(t *testing.T) {
	nodeName := "node1"
	ovsBridge := "br-int"
	nodeIPStr := "192.168.10.10"
	_, nodeIPNet, _ := net.ParseCIDR("192.168.10.10/24")
	macAddr, _ := net.ParseMAC("00:00:5e:00:53:01")
	ipDevice := &net.Interface{
		Index:        10,
		MTU:          1500,
		Name:         "ens160",
		HardwareAddr: macAddr,
	}
	podCIDRStr := "172.16.10.0/24"
	transportCIDRs := []string{"172.16.100.7/24", "2002:1a23:fb46::11:3/32"}
	_, podCIDR, _ := net.ParseCIDR(podCIDRStr)
	transportIfaceMAC, _ := net.ParseMAC("00:0c:29:f5:e2:ce")
	type testTransInterface struct {
		iface   *net.Interface
		ipV4Net *net.IPNet
		ipV6Net *net.IPNet
	}
	testTransportIface := &testTransInterface{
		iface: &net.Interface{
			Index:        11,
			MTU:          1500,
			Name:         "ens192",
			HardwareAddr: transportIfaceMAC,
		},
	}
	for _, cidr := range transportCIDRs {
		parsedIP, parsedIPNet, _ := net.ParseCIDR(cidr)
		parsedIPNet.IP = parsedIP
		if parsedIP.To4() != nil {
			testTransportIface.ipV4Net = parsedIPNet
		} else {
			testTransportIface.ipV6Net = parsedIPNet
		}
	}
	transportAddresses := strings.Join([]string{testTransportIface.ipV4Net.IP.String(), testTransportIface.ipV6Net.IP.String()}, ",")
	tests := []struct {
		name                      string
		trafficEncapMode          config.TrafficEncapModeType
		transportIfName           string
		transportIfCIDRs          []string
		transportInterface        *testTransInterface
		tunnelType                ovsconfig.TunnelType
		mtu                       int
		expectedMTU               int
		expectedNodeLocalIfaceMTU int
		expectedNodeAnnotation    map[string]string
	}{
		{
			name:                      "noencap mode",
			trafficEncapMode:          config.TrafficEncapModeNoEncap,
			mtu:                       0,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1500,
			expectedNodeAnnotation:    map[string]string{types.NodeMACAddressAnnotationKey: macAddr.String()},
		},
		{
			name:                      "hybrid mode",
			trafficEncapMode:          config.TrafficEncapModeHybrid,
			mtu:                       0,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1500,
			expectedNodeAnnotation:    map[string]string{types.NodeMACAddressAnnotationKey: macAddr.String()},
		},
		{
			name:                      "encap mode, geneve tunnel",
			trafficEncapMode:          config.TrafficEncapModeEncap,
			tunnelType:                ovsconfig.GeneveTunnel,
			mtu:                       0,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1450,
			expectedNodeAnnotation:    nil,
		},
		{
			name:                      "encap mode, mtu specified",
			trafficEncapMode:          config.TrafficEncapModeEncap,
			tunnelType:                ovsconfig.GeneveTunnel,
			mtu:                       1400,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1400,
			expectedNodeAnnotation:    nil,
		},
		{
			name:                      "noencap mode with transportInterface",
			trafficEncapMode:          config.TrafficEncapModeNoEncap,
			transportIfName:           testTransportIface.iface.Name,
			transportInterface:        testTransportIface,
			mtu:                       0,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1500,
			expectedNodeAnnotation: map[string]string{
				types.NodeMACAddressAnnotationKey:       transportIfaceMAC.String(),
				types.NodeTransportAddressAnnotationKey: transportAddresses,
			},
		},
		{
			name:                      "hybrid mode with transportInterface",
			trafficEncapMode:          config.TrafficEncapModeHybrid,
			transportIfName:           testTransportIface.iface.Name,
			transportInterface:        testTransportIface,
			mtu:                       0,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1500,
			expectedNodeAnnotation: map[string]string{
				types.NodeMACAddressAnnotationKey:       transportIfaceMAC.String(),
				types.NodeTransportAddressAnnotationKey: transportAddresses,
			},
		},
		{
			name:                      "encap mode with transportInterface, geneve tunnel",
			trafficEncapMode:          config.TrafficEncapModeEncap,
			transportIfName:           testTransportIface.iface.Name,
			transportInterface:        testTransportIface,
			tunnelType:                ovsconfig.GeneveTunnel,
			mtu:                       0,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1450,
			expectedNodeAnnotation: map[string]string{
				types.NodeTransportAddressAnnotationKey: transportAddresses,
			},
		},
		{
			name:                      "encap mode with transportInterface, mtu specified",
			trafficEncapMode:          config.TrafficEncapModeEncap,
			transportIfName:           testTransportIface.iface.Name,
			transportInterface:        testTransportIface,
			tunnelType:                ovsconfig.GeneveTunnel,
			mtu:                       1400,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1400,
			expectedNodeAnnotation: map[string]string{
				types.NodeTransportAddressAnnotationKey: transportAddresses,
			},
		},
		{
			name:                      "noencap mode with transportInterfaceCIDRs",
			trafficEncapMode:          config.TrafficEncapModeNoEncap,
			transportIfCIDRs:          transportCIDRs,
			transportInterface:        testTransportIface,
			mtu:                       0,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1500,
			expectedNodeAnnotation: map[string]string{
				types.NodeMACAddressAnnotationKey:       transportIfaceMAC.String(),
				types.NodeTransportAddressAnnotationKey: transportAddresses,
			},
		},
		{
			name:                      "hybrid mode with transportInterfaceCIDRs",
			trafficEncapMode:          config.TrafficEncapModeHybrid,
			transportIfCIDRs:          transportCIDRs,
			transportInterface:        testTransportIface,
			mtu:                       0,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1500,
			expectedNodeAnnotation: map[string]string{
				types.NodeMACAddressAnnotationKey:       transportIfaceMAC.String(),
				types.NodeTransportAddressAnnotationKey: transportAddresses,
			},
		},
		{
			name:                      "encap mode with transportInterfaceCIDRs, geneve tunnel",
			trafficEncapMode:          config.TrafficEncapModeEncap,
			transportIfCIDRs:          transportCIDRs,
			transportInterface:        testTransportIface,
			tunnelType:                ovsconfig.GeneveTunnel,
			mtu:                       0,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1450,
			expectedNodeAnnotation: map[string]string{
				types.NodeTransportAddressAnnotationKey: transportAddresses,
			},
		},
		{
			name:                      "encap mode with transportInterfaceCIDRs, mtu specified",
			trafficEncapMode:          config.TrafficEncapModeEncap,
			transportIfCIDRs:          transportCIDRs,
			transportInterface:        testTransportIface,
			tunnelType:                ovsconfig.GeneveTunnel,
			mtu:                       1400,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1400,
			expectedNodeAnnotation: map[string]string{
				types.NodeTransportAddressAnnotationKey: transportAddresses,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
				},
				Spec: corev1.NodeSpec{
					PodCIDR: podCIDRStr,
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: nodeIPStr,
						},
					},
				},
			}
			client := fake.NewSimpleClientset(node)
			ifaceStore := interfacestore.NewInterfaceStore()
			expectedNodeConfig := config.NodeConfig{
				Name:                       nodeName,
				Type:                       config.K8sNode,
				OVSBridge:                  ovsBridge,
				DefaultTunName:             defaultTunInterfaceName,
				PodIPv4CIDR:                podCIDR,
				NodeIPv4Addr:               nodeIPNet,
				NodeTransportInterfaceName: ipDevice.Name,
				NodeTransportIPv4Addr:      nodeIPNet,
				NodeTransportInterfaceMTU:  tt.expectedNodeLocalIfaceMTU,
				UplinkNetConfig:            new(config.AdapterNetConfig),
			}

			initializer := &Initializer{
				client:     client,
				ifaceStore: ifaceStore,
				mtu:        tt.mtu,
				ovsBridge:  ovsBridge,
				networkConfig: &config.NetworkConfig{
					TrafficEncapMode: tt.trafficEncapMode,
					TunnelType:       tt.tunnelType,
				},
			}
			if tt.transportIfName != "" {
				initializer.networkConfig.TransportIface = tt.transportInterface.iface.Name
				expectedNodeConfig.NodeTransportInterfaceName = tt.transportInterface.iface.Name
				expectedNodeConfig.NodeTransportIPv4Addr = tt.transportInterface.ipV4Net
				expectedNodeConfig.NodeTransportIPv6Addr = tt.transportInterface.ipV6Net
				defer mockGetTransportIPNetDeviceByName(tt.transportInterface.ipV4Net, tt.transportInterface.ipV6Net, tt.transportInterface.iface)()
			} else if len(tt.transportIfCIDRs) > 0 {
				initializer.networkConfig.TransportIfaceCIDRs = tt.transportIfCIDRs
				expectedNodeConfig.NodeTransportInterfaceName = tt.transportInterface.iface.Name
				expectedNodeConfig.NodeTransportIPv4Addr = tt.transportInterface.ipV4Net
				expectedNodeConfig.NodeTransportIPv6Addr = tt.transportInterface.ipV6Net
				defer mockGetIPNetDeviceByCIDRs(tt.transportInterface.ipV4Net, tt.transportInterface.ipV6Net, tt.transportInterface.iface)()
			}
			defer mockGetIPNetDeviceFromIP(nodeIPNet, ipDevice)()
			defer mockNodeNameEnv(nodeName)()

			require.NoError(t, initializer.initK8sNodeLocalConfig(nodeName))
			assert.Equal(t, expectedNodeConfig, *initializer.nodeConfig)
			node, err := client.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedNodeAnnotation, node.Annotations)
		})
	}
}

func mockGetIPNetDeviceFromIP(ipNet *net.IPNet, ipDevice *net.Interface) func() {
	prevGetIPNetDeviceFromIP := getIPNetDeviceFromIP
	getIPNetDeviceFromIP = func(localIP *ip.DualStackIPs, ignoredHostInterfaces sets.String) (*net.IPNet, *net.IPNet, *net.Interface, error) {
		return ipNet, nil, ipDevice, nil
	}
	return func() { getIPNetDeviceFromIP = prevGetIPNetDeviceFromIP }
}

func mockNodeNameEnv(name string) func() {
	_ = os.Setenv(env.NodeNameEnvKey, name)
	return func() { os.Unsetenv(env.NodeNameEnvKey) }
}

func mockGetTransportIPNetDeviceByName(ipV4Net, ipV6Net *net.IPNet, ipDevice *net.Interface) func() {
	prevGetIPNetDeviceByName := getTransportIPNetDeviceByName
	getTransportIPNetDeviceByName = func(ifName, brName string) (*net.IPNet, *net.IPNet, *net.Interface, error) {
		return ipV4Net, ipV6Net, ipDevice, nil
	}
	return func() { getTransportIPNetDeviceByName = prevGetIPNetDeviceByName }
}

func mockGetIPNetDeviceByCIDRs(ipV4Net, ipV6Net *net.IPNet, ipDevice *net.Interface) func() {
	prevGetIPNetDeviceByCIDRs := getIPNetDeviceByCIDRs
	getIPNetDeviceByCIDRs = func(cidr []string) (*net.IPNet, *net.IPNet, *net.Interface, error) {
		return ipV4Net, ipV6Net, ipDevice, nil
	}
	return func() { getIPNetDeviceByCIDRs = prevGetIPNetDeviceByCIDRs }
}

func TestSetupDefaultTunnelInterface(t *testing.T) {
	_, nodeIPNet, _ := net.ParseCIDR("192.168.10.10/24")
	var tunnelPortLocalIP net.IP
	var tunnelPortLocalIPStr string
	if runtime.IsWindowsPlatform() {
		tunnelPortLocalIP = nodeIPNet.IP
		tunnelPortLocalIPStr = tunnelPortLocalIP.String()
	}
	tests := []struct {
		name                    string
		nodeConfig              *config.NodeConfig
		networkConfig           *config.NetworkConfig
		existingTunnelInterface *interfacestore.InterfaceConfig
		expectedOVSCalls        func(client *ovsconfigtest.MockOVSBridgeClientMockRecorder)
		expectedErr             error
	}{
		{
			name: "create default Geneve tunnel",
			nodeConfig: &config.NodeConfig{
				DefaultTunName:        defaultTunInterfaceName,
				NodeTransportIPv4Addr: nodeIPNet,
			},
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeEncap,
				TunnelType:       ovsconfig.GeneveTunnel,
			},
			expectedOVSCalls: func(client *ovsconfigtest.MockOVSBridgeClientMockRecorder) {
				client.CreateTunnelPortExt(defaultTunInterfaceName,
					ovsconfig.TunnelType(ovsconfig.GeneveTunnel),
					int32(config.DefaultTunOFPort),
					false,
					tunnelPortLocalIPStr,
					"",
					"",
					"",
					map[string]interface{}{},
					map[string]interface{}{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaTunnel})
				client.GetOFPort(defaultTunInterfaceName, false)
			},
		},
		{
			name: "update Geneve tunnel csum",
			nodeConfig: &config.NodeConfig{
				DefaultTunName:        defaultTunInterfaceName,
				NodeTransportIPv4Addr: nodeIPNet,
			},
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeEncap,
				TunnelType:       ovsconfig.GeneveTunnel,
				TunnelCsum:       false,
			},
			existingTunnelInterface: interfacestore.NewTunnelInterface(defaultTunInterfaceName, ovsconfig.GeneveTunnel, 0, tunnelPortLocalIP, true, &interfacestore.OVSPortConfig{OFPort: 1}),
			expectedOVSCalls: func(client *ovsconfigtest.MockOVSBridgeClientMockRecorder) {
				client.GetInterfaceOptions(defaultTunInterfaceName).Return(map[string]string{"csum": "true"}, nil)
				client.SetInterfaceOptions(defaultTunInterfaceName, map[string]interface{}{"csum": "false"})
			},
		},
		{
			name: "update tunnel type and port",
			nodeConfig: &config.NodeConfig{
				DefaultTunName:        defaultTunInterfaceName,
				NodeTransportIPv4Addr: nodeIPNet,
			},
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeEncap,
				TunnelType:       ovsconfig.VXLANTunnel,
				TunnelPort:       9999,
			},
			existingTunnelInterface: interfacestore.NewTunnelInterface(defaultTunInterfaceName, ovsconfig.GeneveTunnel, 0, tunnelPortLocalIP, true, &interfacestore.OVSPortConfig{
				PortUUID: "foo",
				OFPort:   1,
			}),
			expectedOVSCalls: func(client *ovsconfigtest.MockOVSBridgeClientMockRecorder) {
				client.DeletePort("foo")
				client.CreateTunnelPortExt(defaultTunInterfaceName,
					ovsconfig.TunnelType(ovsconfig.VXLANTunnel),
					int32(config.DefaultTunOFPort),
					false,
					tunnelPortLocalIPStr,
					"",
					"",
					"",
					map[string]interface{}{"dst_port": "9999"},
					map[string]interface{}{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaTunnel})
				client.GetOFPort(defaultTunInterfaceName, false)
			},
		},
		{
			name: "no change",
			nodeConfig: &config.NodeConfig{
				DefaultTunName:        defaultTunInterfaceName,
				NodeTransportIPv4Addr: nodeIPNet,
			},
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeEncap,
				TunnelType:       ovsconfig.GeneveTunnel,
				TunnelCsum:       false,
			},
			existingTunnelInterface: interfacestore.NewTunnelInterface(defaultTunInterfaceName, ovsconfig.GeneveTunnel, 0, tunnelPortLocalIP, false, &interfacestore.OVSPortConfig{OFPort: 1}),
			expectedOVSCalls:        func(client *ovsconfigtest.MockOVSBridgeClientMockRecorder) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := mock.NewController(t)
			defer controller.Finish()
			mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
			client := fake.NewSimpleClientset()
			ifaceStore := interfacestore.NewInterfaceStore()
			if tt.existingTunnelInterface != nil {
				ifaceStore.AddInterface(tt.existingTunnelInterface)
			}
			initializer := &Initializer{
				client:          client,
				ifaceStore:      ifaceStore,
				ovsBridgeClient: mockOVSBridgeClient,
				ovsBridge:       "br-int",
				networkConfig:   tt.networkConfig,
				nodeConfig:      tt.nodeConfig,
			}
			tt.expectedOVSCalls(mockOVSBridgeClient.EXPECT())
			err := initializer.setupDefaultTunnelInterface()
			assert.Equal(t, err, tt.expectedErr)
		})
	}
}

func TestSetupGatewayInterface(t *testing.T) {
	fakeMAC, _ := net.ParseMAC("12:34:56:78:76:54")
	defer mockSetLinkUp(fakeMAC, 10, nil)()
	defer mockConfigureLinkAddress(nil)()
	defer mockSetInterfaceMTU(nil)()

	controller := mock.NewController(t)
	defer controller.Finish()

	podCIDRStr := "172.16.10.0/24"
	_, podCIDR, _ := net.ParseCIDR(podCIDRStr)
	nodeConfig := &config.NodeConfig{
		Name:        "n1",
		Type:        config.K8sNode,
		OVSBridge:   "br-int",
		PodIPv4CIDR: podCIDR,
	}
	networkConfig := &config.NetworkConfig{
		TrafficEncapMode: config.TrafficEncapModeEncap,
		TunnelType:       ovsconfig.GeneveTunnel,
		TunnelCsum:       false,
		InterfaceMTU:     1450,
	}

	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
	client := fake.NewSimpleClientset()
	ifaceStore := interfacestore.NewInterfaceStore()
	stopCh := make(chan struct{})
	initializer := &Initializer{
		client:          client,
		ifaceStore:      ifaceStore,
		ovsBridgeClient: mockOVSBridgeClient,
		ovsBridge:       "br-int",
		networkConfig:   networkConfig,
		nodeConfig:      nodeConfig,
		hostGateway:     "antrea-gw0",
		stopCh:          stopCh,
	}
	close(stopCh)
	portUUID := "123456780a"
	ofport := int32(config.HostGatewayOFPort)
	mockOVSBridgeClient.EXPECT().CreateInternalPort(initializer.hostGateway, ofport, mock.Any(), mock.Any()).Return(portUUID, nil)
	mockOVSBridgeClient.EXPECT().SetInterfaceMAC(initializer.hostGateway, fakeMAC).Return(nil)
	mockOVSBridgeClient.EXPECT().GetOFPort(initializer.hostGateway, false).Return(ofport, nil)
	mockOVSBridgeClient.EXPECT().SetInterfaceMTU(initializer.hostGateway, networkConfig.InterfaceMTU).Return(nil)
	err := initializer.setupGatewayInterface()
	assert.NoError(t, err)
}

func mockSetLinkUp(returnedMAC net.HardwareAddr, returnIndex int, returnErr error) func() {
	originalSetLinkUp := setLinkUp
	setLinkUp = func(name string) (net.HardwareAddr, int, error) {
		return returnedMAC, returnIndex, returnErr
	}
	return func() {
		setLinkUp = originalSetLinkUp
	}
}

func mockConfigureLinkAddress(returnedErr error) func() {
	originalConfigureLinkAddresses := configureLinkAddresses
	configureLinkAddresses = func(idx int, ipNets []*net.IPNet) error {
		return returnedErr
	}
	return func() {
		configureLinkAddresses = originalConfigureLinkAddresses
	}
}

func TestRestorePortConfigs(t *testing.T) {
	tests := []struct {
		name                string
		existingInterfaces  []*interfacestore.InterfaceConfig
		expectedOVSCtlCalls func(client *ovsctltest.MockOVSCtlClientMockRecorder)
		expectedErr         string
	}{
		{
			name: "success",
			existingInterfaces: []*interfacestore.InterfaceConfig{
				interfacestore.NewIPSecTunnelInterface("antrea-ipsec1",
					ovsconfig.GeneveTunnel,
					"node1",
					net.ParseIP("1.1.1.1"),
					"abcdefg",
					"node1",
					&interfacestore.OVSPortConfig{OFPort: 11, PortUUID: "uuid1"}),
				interfacestore.NewTunnelInterface(defaultTunInterfaceName,
					ovsconfig.GeneveTunnel,
					0,
					net.ParseIP("1.1.1.10"),
					true,
					&interfacestore.OVSPortConfig{OFPort: 12}),
				interfacestore.NewTrafficControlInterface("antrea-tap1",
					&interfacestore.OVSPortConfig{OFPort: 13, PortUUID: "uuid3"}),
				interfacestore.NewTrafficControlInterface("antrea-tap2",
					&interfacestore.OVSPortConfig{OFPort: -1, PortUUID: "uuid3"}),
			},
			expectedOVSCtlCalls: func(client *ovsctltest.MockOVSCtlClientMockRecorder) {
				client.SetPortNoFlood(11).Return(nil)
				client.SetPortNoFlood(13).Return(nil)
			},
		},
		{
			name: "fail",
			existingInterfaces: []*interfacestore.InterfaceConfig{
				interfacestore.NewTrafficControlInterface("antrea-tap1",
					&interfacestore.OVSPortConfig{OFPort: 10, PortUUID: "uuid3"}),
			},
			expectedOVSCtlCalls: func(client *ovsctltest.MockOVSCtlClientMockRecorder) {
				client.SetPortNoFlood(10).Return(fmt.Errorf("server unavailable"))
			},
			expectedErr: "failed to set no-flood for port antrea-tap1: server unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := mock.NewController(t)
			defer controller.Finish()
			mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(controller)
			ifaceStore := interfacestore.NewInterfaceStore()
			initializer := &Initializer{
				ifaceStore:   ifaceStore,
				ovsCtlClient: mockOVSCtlClient,
			}
			ifaceStore.Initialize(tt.existingInterfaces)
			tt.expectedOVSCtlCalls(mockOVSCtlClient.EXPECT())
			err := initializer.restorePortConfigs()
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.expectedErr)
			}
		})
	}
}

func TestSetOVSDatapath(t *testing.T) {
	tests := []struct {
		name          string
		expectedCalls func(m *ovsconfigtest.MockOVSBridgeClient)
		expectedErr   string
	}{
		{
			name: "fail to read OVS bridge other_config",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOVSOtherConfig().Return(nil, ovsconfig.InvalidArgumentsError("failed to read OVS bridge other_config"))
			},
			expectedErr: "failed to read OVS bridge other_config",
		},
		{
			name: "fail to set OVS bridge datapath_id",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOVSOtherConfig().Return(map[string]string{}, nil)
				m.EXPECT().SetDatapathID(mock.Any()).Return(ovsconfig.InvalidArgumentsError("failed to set OVS bridge datapath_id"))
			},
			expectedErr: "failed to set OVS bridge datapath_id",
		},
		{
			name: "datapath-id exists in other_config on OVS bridge",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOVSOtherConfig().Return(map[string]string{
					ovsconfig.OVSOtherConfigDatapathIDKey: "datapathId",
				}, nil)
			},
		},
		{
			name: "generate and set datapath ID for OVS bridge",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOVSOtherConfig().Return(map[string]string{}, nil)
				m.EXPECT().SetDatapathID(mock.Any())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := mock.NewController(t)
			mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
			initializer := newAgentInitializer(mockOVSBridgeClient, nil)
			tt.expectedCalls(mockOVSBridgeClient)

			err := initializer.setOVSDatapath()
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPrepareOVSBridge(t *testing.T) {
	tests := []struct {
		name          string
		nodeType      config.NodeType
		expectedCalls func(m *ovsconfigtest.MockOVSBridgeClient)
	}{
		{
			name:     "k8s node",
			nodeType: config.K8sNode,
		},
		{
			name:     "external node",
			nodeType: config.ExternalNode,
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOVSOtherConfig().Return(map[string]string{
					ovsconfig.OVSOtherConfigDatapathIDKey: "datapathId",
				}, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := mock.NewController(t)
			mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
			initializer := newAgentInitializer(mockOVSBridgeClient, nil)
			initializer.nodeType = tt.nodeType
			if tt.expectedCalls != nil {
				tt.expectedCalls(mockOVSBridgeClient)
			}

			err := initializer.prepareOVSBridge()
			require.NoError(t, err)
		})
	}
}

func TestInitNodeLocalConfig(t *testing.T) {
	testNode := &crdv1alpha1.ExternalNode{
		ObjectMeta: metav1.ObjectMeta{Name: "testNode", Namespace: "external"},
	}

	tests := []struct {
		name              string
		nodeName          string
		client            *fake.Clientset
		crdClient         *fakeversioned.Clientset
		nodeType          config.NodeType
		externalNamespace string
		expectedErr       string
	}{
		{
			name:        "k8s node unavailable",
			nodeName:    "testNode",
			client:      fake.NewSimpleClientset(),
			nodeType:    config.K8sNode,
			expectedErr: "node retrieval failed with the following error",
		},
		{
			name:              "Finished VM config initialization",
			nodeName:          "testNode",
			crdClient:         fakeversioned.NewSimpleClientset(testNode),
			nodeType:          config.ExternalNode,
			externalNamespace: "external",
		},
		{
			name:              "provided external node unavailable",
			nodeName:          "testNode",
			crdClient:         fakeversioned.NewSimpleClientset(),
			nodeType:          config.ExternalNode,
			externalNamespace: "external",
			expectedErr:       "timed out waiting for the condition",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer mockNodeNameEnv(tt.nodeName)()
			stopCh := make(chan struct{})
			initializer := &Initializer{
				client:                tt.client,
				crdClient:             tt.crdClient,
				ovsBridge:             "br-int",
				stopCh:                stopCh,
				networkConfig:         &config.NetworkConfig{},
				nodeType:              tt.nodeType,
				externalNodeNamespace: tt.externalNamespace,
			}
			close(stopCh)

			err := initializer.initNodeLocalConfig()
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func mockIPsecPSKEnv(name string) func() {
	_ = os.Setenv(ipsecPSKEnvKey, name)
	return func() { os.Unsetenv(ipsecPSKEnvKey) }
}

func TestReadIPSecPSK(t *testing.T) {
	tests := []struct {
		name        string
		expectedErr string
	}{
		{
			name:        "IPsec PSK env variable not set",
			expectedErr: "IPsec PSK environment variable 'ANTREA_IPSEC_PSK' is not set or is empty",
		},
		{
			name: "IPsec PSK env variable set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initializer := &Initializer{
				networkConfig: &config.NetworkConfig{
					IPsecConfig: config.IPsecConfig{},
				},
			}
			if tt.expectedErr == "" {
				defer mockIPsecPSKEnv("key")()
			}

			err := initializer.readIPSecPSK()
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetNodeConfig(t *testing.T) {
	nodeConfig := &config.NodeConfig{}
	initializer := &Initializer{
		nodeConfig: nodeConfig,
	}
	assert.Equal(t, nodeConfig, initializer.GetNodeConfig())
}

func TestGetWireGuardClient(t *testing.T) {
	client := fake.NewSimpleClientset()
	nodeConfig := &config.NodeConfig{}
	wireGuardConfig := &config.WireGuardConfig{}
	wireGuardClient, err := wireguard.New(client, nodeConfig, wireGuardConfig)
	require.NoError(t, err)
	initializer := &Initializer{
		wireGuardClient: wireGuardClient,
	}
	assert.Equal(t, wireGuardClient, initializer.GetWireGuardClient())
}

func TestSetupOVSBridge(t *testing.T) {
	tests := []struct {
		name          string
		expectedCalls func(m *ovsconfigtest.MockOVSBridgeClient)
		expectedErr   string
	}{
		{
			name: "error creating OVS bridge",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().Create().Return(ovsconfig.InvalidArgumentsError("failed to create OVS bridge"))
			},
			expectedErr: "failed to create OVS bridge",
		},
		{
			name: "error validating supported DP features",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().Create()
			},
			expectedErr: "error listing DP features",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := mock.NewController(t)
			mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
			initializer := &Initializer{
				ovsBridgeClient: mockOVSBridgeClient,
			}
			tt.expectedCalls(mockOVSBridgeClient)

			err := initializer.setupOVSBridge()
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestWaitForIPSecMonitorDaemon(t *testing.T) {
	tests := []struct {
		name        string
		expectedErr string
	}{
		{
			name:        "IPsec monitor is not running",
			expectedErr: "IPsec was requested, but the OVS IPsec monitor does not seem to be running",
		},
		{
			name: "IPsec monitor running",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initializer := &Initializer{}
			if tt.expectedErr == "" {
				appFS := afero.NewMemMapFs()
				err := appFS.MkdirAll("/var/run/openvswitch", 0777)
				require.NoError(t, err)
				_, err = appFS.Create("/var/run/openvswitch/ovs-monitor-ipsec.pid")
				require.NoError(t, err)
				appFs = appFS
				defer func() { appFs = afero.NewOsFs() }()
			}

			err := initializer.waitForIPsecMonitorDaemon()
			if tt.expectedErr != "" {
				assert.ErrorContains(t, initializer.waitForIPsecMonitorDaemon(), tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
