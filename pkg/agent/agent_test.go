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
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
	"uuid"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mock "go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	clockutils "k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"

	"antrea.io/antrea/v2/pkg/agent/cniserver"
	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/interfacestore"
	openflowtest "antrea.io/antrea/v2/pkg/agent/openflow/testing"
	"antrea.io/antrea/v2/pkg/agent/types"
	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	fakeversioned "antrea.io/antrea/v2/pkg/client/clientset/versioned/fake"
	"antrea.io/antrea/v2/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/v2/pkg/ovs/ovsconfig/testing"
	"antrea.io/antrea/v2/pkg/ovs/ovsctl"
	ovsctltest "antrea.io/antrea/v2/pkg/ovs/ovsctl/testing"
	"antrea.io/antrea/v2/pkg/util/env"
	"antrea.io/antrea/v2/pkg/util/ip"
	"antrea.io/antrea/v2/pkg/util/runtime"
)

func newAgentInitializer(ovsBridgeClient ovsconfig.OVSBridgeClient, ifaceStore interfacestore.InterfaceStore) *Initializer {
	return &Initializer{ovsBridgeClient: ovsBridgeClient, ifaceStore: ifaceStore, hostGateway: "antrea-gw0"}
}

func TestInitInterfaceStore(t *testing.T) {
	controller := mock.NewController(t)
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)

	mockOVSBridgeClient.EXPECT().GetPortList().Return(nil, fmt.Errorf("Failed to list OVS ports"))

	store := interfacestore.NewInterfaceStore()
	initializer := newAgentInitializer(mockOVSBridgeClient, store)
	uplinkNetConfig := config.AdapterNetConfig{Name: "eth-antrea-test-1"}
	initializer.nodeConfig = &config.NodeConfig{UplinkNetConfig: &uplinkNetConfig}

	err := initializer.initInterfaceStore()
	assert.Error(t, err, "failed to handle OVS return error")

	uuid1 := uuid.NewV4().String()
	uuid2 := uuid.NewV4().String()
	p1MAC := "11:22:33:44:55:66"
	p1IP := "1.1.1.1"
	p2MAC := "11:22:33:44:55:77"
	p2IP := "1.1.1.2"
	p1NetMAC, _ := net.ParseMAC(p1MAC)
	p1NetIP := net.ParseIP(p1IP)
	p2NetMAC, _ := net.ParseMAC(p2MAC)
	p2NetIP := net.ParseIP(p2IP)

	ovsPort1 := ovsconfig.OVSPortData{UUID: uuid1, Name: "p1", IFName: "p1", OFPort: 11,
		ExternalIDs: cniserver.BuildOVSPortExternalIDs(
			interfacestore.NewContainerInterface("p1", uuid1, "pod1", "ns1", "eth0", "netns1", p1NetMAC, []net.IP{p1NetIP}, 0))}
	ovsPort2 := ovsconfig.OVSPortData{UUID: uuid2, Name: "p2", IFName: "p2", OFPort: 12,
		ExternalIDs: cniserver.BuildOVSPortExternalIDs(
			interfacestore.NewContainerInterface("p2", uuid2, "pod2", "ns2", "eth0", "netns2", p2NetMAC, []net.IP{p2NetIP}, 0),
		),
	}
	uuid3 := uuid.NewV4().String()
	ovsPortUplinkInternal := ovsconfig.OVSPortData{UUID: uuid3, Name: "eth-antrea-test-1", IFName: "eth-antrea-test-1", OFPort: 100,
		ExternalIDs: map[string]string{
			interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
		},
	}
	initOVSPorts := []ovsconfig.OVSPortData{ovsPort1, ovsPort2, ovsPortUplinkInternal}

	mockOVSBridgeClient.EXPECT().GetPortList().Return(initOVSPorts, fmt.Errorf("Failed to list OVS ports"))
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
	} else if container1.OFPort != 11 || len(container1.IPs) == 0 || container1.IPs[0].String() != p1IP || container1.MAC.String() != p1MAC ||
		container1.InterfaceName != "p1" || container1.NetNS != "netns1" {
		t.Errorf("Failed to load OVS port configuration into local store")
	}
	_, found2 := store.GetContainerInterface(uuid2)
	if !found2 {
		t.Errorf("Failed to load OVS port into local store")
	}
}

func TestPersistRoundNum(t *testing.T) {
	const maxRetries = 3
	const roundNum uint64 = 5555

	controller := mock.NewController(t)
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)

	transactionError := fmt.Errorf("Failed to get external IDs")
	firstCall := mockOVSBridgeClient.EXPECT().GetExternalIDs().Return(nil, transactionError)
	externalIDs := make(map[string]string)
	mockOVSBridgeClient.EXPECT().GetExternalIDs().Return(externalIDs, nil).After(firstCall)
	newExternalIDs := make(map[string]string)
	newExternalIDs[roundNumKey] = fmt.Sprint(roundNum)
	mockOVSBridgeClient.EXPECT().SetExternalIDs(mock.Eq(newExternalIDs)).Times(1)

	// The first call to saveRoundNum will fail. Because we set the retry interval to 0,
	// persistRoundNum should retry immediately and the second call will succeed (as per the
	// expectations above).
	persistRoundNum(roundNum, mockOVSBridgeClient, 0, maxRetries)
}

func TestGetRoundInfo(t *testing.T) {
	controller := mock.NewController(t)
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)

	mockOVSBridgeClient.EXPECT().GetExternalIDs().Return(nil, fmt.Errorf("Failed to get external IDs"))
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
		getNodeReaction           k8stesting.ReactionFunc
		trafficEncapMode          config.TrafficEncapModeType
		transportIfName           string
		transportIfCIDRs          []string
		transportInterface        *testTransInterface
		tunnelType                ovsconfig.TunnelType
		mtu                       int
		podCIDR                   string
		expectedErr               string
		expectedMTU               int
		expectedNodeLocalIfaceMTU int
		expectedNodeAnnotation    map[string]string
	}{
		{
			name:                      "noencap mode",
			trafficEncapMode:          config.TrafficEncapModeNoEncap,
			mtu:                       0,
			podCIDR:                   podCIDRStr,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1500,
			expectedNodeAnnotation:    map[string]string{types.NodeMACAddressAnnotationKey: macAddr.String()},
		},
		{
			name:                      "hybrid mode",
			trafficEncapMode:          config.TrafficEncapModeHybrid,
			mtu:                       0,
			podCIDR:                   podCIDRStr,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1500,
			expectedNodeAnnotation:    map[string]string{types.NodeMACAddressAnnotationKey: macAddr.String()},
		},
		{
			name:                      "encap mode, geneve tunnel",
			trafficEncapMode:          config.TrafficEncapModeEncap,
			tunnelType:                ovsconfig.GeneveTunnel,
			mtu:                       0,
			podCIDR:                   podCIDRStr,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1450,
			expectedNodeAnnotation:    nil,
		},
		{
			name:                      "encap mode, mtu specified",
			trafficEncapMode:          config.TrafficEncapModeEncap,
			tunnelType:                ovsconfig.GeneveTunnel,
			mtu:                       1400,
			podCIDR:                   podCIDRStr,
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
			podCIDR:                   podCIDRStr,
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
			podCIDR:                   podCIDRStr,
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
			podCIDR:                   podCIDRStr,
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
			podCIDR:                   podCIDRStr,
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
			podCIDR:                   podCIDRStr,
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
			podCIDR:                   podCIDRStr,
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
			podCIDR:                   podCIDRStr,
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
			podCIDR:                   podCIDRStr,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1400,
			expectedNodeAnnotation: map[string]string{
				types.NodeTransportAddressAnnotationKey: transportAddresses,
			},
		},
		{
			name: "error getting Node",
			getNodeReaction: func(action k8stesting.Action) (handled bool, ret k8sruntime.Object, err error) {
				return true, nil, fmt.Errorf("connection error")
			},
			trafficEncapMode: config.TrafficEncapModeEncap,
			tunnelType:       ovsconfig.GeneveTunnel,
			expectedErr:      "failed to get Node with name \"node1\" from K8s: connection error",
		},
		{
			name:             "empty node podCIDR",
			trafficEncapMode: config.TrafficEncapModeEncap,
			tunnelType:       ovsconfig.GeneveTunnel,
			expectedErr:      "Spec.PodCIDR is empty for Node \"node1\"",
		},
		{
			name:                      "networkPolicyOnly mode",
			trafficEncapMode:          config.TrafficEncapModeNetworkPolicyOnly,
			transportIfCIDRs:          transportCIDRs,
			transportInterface:        testTransportIface,
			expectedNodeLocalIfaceMTU: 1500,
			expectedMTU:               1500,
			expectedNodeAnnotation: map[string]string{
				types.NodeMACAddressAnnotationKey:       transportIfaceMAC.String(),
				types.NodeTransportAddressAnnotationKey: transportAddresses,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
					UID:  "initialized-node-uid",
				},
				Spec: corev1.NodeSpec{
					PodCIDR: tt.podCIDR,
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
			if tt.getNodeReaction != nil {
				client.PrependReactor("get", "nodes", tt.getNodeReaction)
			}

			ifaceStore := interfacestore.NewInterfaceStore()
			_, podCIDR, _ := net.ParseCIDR(tt.podCIDR)
			expectedNodeConfig := config.NodeConfig{
				UID:                        node.UID,
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
				mockGetTransportIPNetDeviceByName(t, tt.transportInterface.ipV4Net, tt.transportInterface.ipV6Net, tt.transportInterface.iface)
			} else if len(tt.transportIfCIDRs) > 0 {
				initializer.networkConfig.TransportIfaceCIDRs = tt.transportIfCIDRs
				expectedNodeConfig.NodeTransportInterfaceName = tt.transportInterface.iface.Name
				expectedNodeConfig.NodeTransportIPv4Addr = tt.transportInterface.ipV4Net
				expectedNodeConfig.NodeTransportIPv6Addr = tt.transportInterface.ipV6Net
				mockGetIPNetDeviceByCIDRs(t, tt.transportInterface.ipV4Net, tt.transportInterface.ipV6Net, tt.transportInterface.iface)
			}

			t.Setenv(env.NodeNameEnvKey, nodeName)
			mockGetIPNetDeviceFromIP(t, nodeIPNet, ipDevice)
			mockGetNodeTimeout(t, 100*time.Millisecond)

			err := initializer.initK8sNodeLocalConfig(context.Background(), nodeName)
			if tt.expectedErr == "" {
				require.NoError(t, err)
				assert.Equal(t, expectedNodeConfig, *initializer.nodeConfig)
				node, err := client.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, tt.expectedNodeAnnotation, node.Annotations)
			} else {
				assert.ErrorContains(t, err, tt.expectedErr)
			}
		})
	}
}

func mockGetIPNetDeviceFromIP(t *testing.T, ipNet *net.IPNet, ipDevice *net.Interface) {
	prevGetIPNetDeviceFromIP := getIPNetDeviceFromIP
	getIPNetDeviceFromIP = func(localIP *ip.DualStackIPs, ignoredHostInterfaces sets.Set[string]) (*net.IPNet, *net.IPNet, *net.Interface, error) {
		return ipNet, nil, ipDevice, nil
	}
	t.Cleanup(func() { getIPNetDeviceFromIP = prevGetIPNetDeviceFromIP })
}

func mockGetNodeTimeout(t *testing.T, timeout time.Duration) {
	prevTimeout := getNodeTimeout
	getNodeTimeout = timeout
	t.Cleanup(func() { getNodeTimeout = prevTimeout })
}

func mockGetTransportIPNetDeviceByName(t *testing.T, ipV4Net, ipV6Net *net.IPNet, ipDevice *net.Interface) {
	prevGetIPNetDeviceByName := getTransportIPNetDeviceByNameFn
	getTransportIPNetDeviceByNameFn = func(ifName, brName string) (*net.IPNet, *net.IPNet, *net.Interface, error) {
		return ipV4Net, ipV6Net, ipDevice, nil
	}
	t.Cleanup(func() { getTransportIPNetDeviceByNameFn = prevGetIPNetDeviceByName })
}

func mockGetIPNetDeviceByCIDRs(t *testing.T, ipV4Net, ipV6Net *net.IPNet, ipDevice *net.Interface) {
	prevGetIPNetDeviceByCIDRs := getIPNetDeviceByCIDRs
	getIPNetDeviceByCIDRs = func(cidr []string) (*net.IPNet, *net.IPNet, *net.Interface, error) {
		return ipV4Net, ipV6Net, ipDevice, nil
	}
	t.Cleanup(func() { getIPNetDeviceByCIDRs = prevGetIPNetDeviceByCIDRs })
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
					map[string]string{},
					map[string]string{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaTunnel})
				client.GetOFPort(defaultTunInterfaceName)
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
			existingTunnelInterface: interfacestore.NewTunnelInterface(defaultTunInterfaceName, ovsconfig.GeneveTunnel, 0, tunnelPortLocalIP, true, &interfacestore.OVSPortConfig{OFPort: config.DefaultTunOFPort}),
			expectedOVSCalls: func(client *ovsconfigtest.MockOVSBridgeClientMockRecorder) {
				client.GetInterfaceOptions(defaultTunInterfaceName).Return(map[string]string{"csum": "true"}, nil)
				client.SetInterfaceOptions(defaultTunInterfaceName, map[string]string{"csum": "false"})
			},
		},
		{
			name: "update tunnel type",
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
				OFPort:   config.DefaultTunOFPort,
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
					map[string]string{"dst_port": "9999"},
					map[string]string{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaTunnel})
				client.GetOFPort(defaultTunInterfaceName)
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
			existingTunnelInterface: interfacestore.NewTunnelInterface(defaultTunInterfaceName, ovsconfig.GeneveTunnel, 0, tunnelPortLocalIP, false, &interfacestore.OVSPortConfig{OFPort: config.DefaultTunOFPort}),
			expectedOVSCalls:        func(client *ovsconfigtest.MockOVSBridgeClientMockRecorder) {},
		},
		{
			name: "no change if ofport is not default",
			nodeConfig: &config.NodeConfig{
				DefaultTunName:        defaultTunInterfaceName,
				NodeTransportIPv4Addr: nodeIPNet,
			},
			networkConfig: &config.NetworkConfig{
				TrafficEncapMode: config.TrafficEncapModeEncap,
				TunnelType:       ovsconfig.GeneveTunnel,
				TunnelCsum:       false,
			},
			// port already exists with an ofport value (123) which is not the default
			// (config.DefaultTunOFPort). In this case, we keep the port as is.
			existingTunnelInterface: interfacestore.NewTunnelInterface(defaultTunInterfaceName, ovsconfig.GeneveTunnel, 0, tunnelPortLocalIP, false, &interfacestore.OVSPortConfig{OFPort: 123}),
			expectedOVSCalls:        func(client *ovsconfigtest.MockOVSBridgeClientMockRecorder) {},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := mock.NewController(t)
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
	mockSetLinkUp(t, fakeMAC, 10, nil)
	mockConfigureLinkAddress(t, nil)
	mockSetInterfaceMTU(t, nil)
	mockSetInterfaceARPAnnounce(t, nil)

	controller := mock.NewController(t)

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
	ofport := int32(config.DefaultHostGatewayOFPort)
	mockOVSBridgeClient.EXPECT().CreateInternalPort(initializer.hostGateway, ofport, mock.Any(), mock.Any()).Return(portUUID, nil)
	mockOVSBridgeClient.EXPECT().SetInterfaceMAC(initializer.hostGateway, fakeMAC).Return(nil)
	mockOVSBridgeClient.EXPECT().GetOFPort(initializer.hostGateway).Return(ofport, nil)
	mockOVSBridgeClient.EXPECT().SetInterfaceMTU(initializer.hostGateway, networkConfig.InterfaceMTU).Return(nil)
	err := initializer.setupGatewayInterface()
	assert.NoError(t, err)
}

func mockSetLinkUp(t *testing.T, returnedMAC net.HardwareAddr, returnIndex int, returnErr error) {
	originalSetLinkUp := setLinkUp
	setLinkUp = func(name string) (net.HardwareAddr, int, error) {
		return returnedMAC, returnIndex, returnErr
	}
	t.Cleanup(func() { setLinkUp = originalSetLinkUp })
}

func mockConfigureLinkAddress(t *testing.T, returnedErr error) {
	originalConfigureLinkAddresses := configureLinkAddresses
	configureLinkAddresses = func(idx int, ipNets []*net.IPNet) error {
		return returnedErr
	}
	t.Cleanup(func() { configureLinkAddresses = originalConfigureLinkAddresses })
}

func mockSetInterfaceARPAnnounce(t *testing.T, returnedErr error) {
	originalSetInterfaceARPAnnounce := setInterfaceARPAnnounce
	setInterfaceARPAnnounce = func(ifaceName string, value int) error {
		return returnedErr
	}
	t.Cleanup(func() { setInterfaceARPAnnounce = originalSetInterfaceARPAnnounce })
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
		{
			name: "fail for some ports, the others are still set",
			existingInterfaces: []*interfacestore.InterfaceConfig{
				interfacestore.NewTrafficControlInterface("antrea-tap1",
					&interfacestore.OVSPortConfig{OFPort: 10, PortUUID: "uuid1"}),
				interfacestore.NewTrafficControlInterface("antrea-tap2",
					&interfacestore.OVSPortConfig{OFPort: 11, PortUUID: "uuid2"}),
				interfacestore.NewTrafficControlInterface("antrea-tap3",
					&interfacestore.OVSPortConfig{OFPort: 12, PortUUID: "uuid3"}),
			},
			expectedOVSCtlCalls: func(client *ovsctltest.MockOVSCtlClientMockRecorder) {
				client.SetPortNoFlood(10).Return(fmt.Errorf("server unavailable"))
				client.SetPortNoFlood(11).Return(nil)
				client.SetPortNoFlood(12).Return(fmt.Errorf("connection refused"))
			},
			expectedErr: "failed to set no-flood for port antrea-tap1: server unavailable\nfailed to set no-flood for port antrea-tap3: connection refused",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := mock.NewController(t)
			mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(controller)
			ifaceStore := interfacestore.NewInterfaceStore()
			initializer := &Initializer{
				ifaceStore:   ifaceStore,
				ovsCtlClient: mockOVSCtlClient,
			}
			ifaceStore.AddInterfaces(tt.existingInterfaces)
			tt.expectedOVSCtlCalls(mockOVSCtlClient.EXPECT())
			err := initializer.restorePortConfigs()
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				// The errors of different ports are joined, in an unspecified order.
				for expectedErr := range strings.SplitSeq(tt.expectedErr, "\n") {
					assert.ErrorContains(t, err, expectedErr)
				}
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
				m.EXPECT().GetOVSOtherConfig().Return(nil, fmt.Errorf("failed to read OVS bridge other_config"))
			},
			expectedErr: "failed to read OVS bridge other_config",
		},
		{
			name: "fail to set OVS bridge datapath_id",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOVSOtherConfig().Return(map[string]string{}, nil)
				m.EXPECT().SetDatapathID(mock.Any()).Return(fmt.Errorf("failed to set OVS bridge datapath_id"))
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

func TestReadIPSecPSK(t *testing.T) {
	tests := []struct {
		name        string
		isIPsecPSK  bool
		expectedErr string
	}{
		{
			name:        "IPsec PSK env variable not set",
			expectedErr: "IPsec PSK environment variable 'ANTREA_IPSEC_PSK' is not set or is empty",
		},
		{
			name:       "IPsec PSK env variable set",
			isIPsecPSK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initializer := &Initializer{
				networkConfig: &config.NetworkConfig{
					IPsecConfig: config.IPsecConfig{},
				},
			}
			if tt.isIPsecPSK {
				t.Setenv(ipsecPSKEnvKey, "key")
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

func TestWaitForIPSecMonitorDaemon(t *testing.T) {
	tests := []struct {
		name                  string
		isIPsecMonitorRunning bool
		expectedErr           string
	}{
		{
			name:        "IPsec monitor is not running",
			expectedErr: "IPsec was requested, but the OVS IPsec monitor does not seem to be running",
		},
		{
			name:                  "IPsec monitor running",
			isIPsecMonitorRunning: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initializer := &Initializer{}
			if tt.isIPsecMonitorRunning {
				appFS := afero.NewMemMapFs()
				err := appFS.MkdirAll("/var/run/openvswitch", 0777)
				require.NoError(t, err)
				_, err = appFS.Create("/var/run/openvswitch/ovs-monitor-ipsec.pid")
				require.NoError(t, err)
				defaultFs = appFS
				defer func() {
					defaultFs = afero.NewOsFs()
				}()
			} else {
				fakeClock := clocktesting.NewFakeClock(time.Now())
				clock = fakeClock
				defer func() {
					clock = clockutils.RealClock{}
				}()
				go func() {
					require.Eventually(t, func() bool {
						return fakeClock.HasWaiters()
					}, 1*time.Second, 10*time.Millisecond)
					fakeClock.Step(10 * time.Second)
				}()
			}

			err := initializer.waitForIPsecMonitorDaemon()
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestInitVMLocalConfig(t *testing.T) {
	ipDevice := &net.Interface{
		Name: "fakeUplinkInterface",
	}
	testNode := &crdv1alpha1.ExternalNode{
		ObjectMeta: metav1.ObjectMeta{Name: "testNode", Namespace: "external"},
		Spec: crdv1alpha1.ExternalNodeSpec{
			Interfaces: []crdv1alpha1.NetworkInterface{
				{
					IPs: []string{"192.168.1.2"},
				},
			},
		},
	}

	tests := []struct {
		name        string
		nodeName    string
		crdClient   *fakeversioned.Clientset
		expectedErr string
	}{
		{
			name:      "Finished VM config initialization",
			nodeName:  "testNode",
			crdClient: fakeversioned.NewSimpleClientset(testNode),
		},
		{
			name:        "provided external Node unavailable",
			nodeName:    "testNode",
			crdClient:   fakeversioned.NewSimpleClientset(),
			expectedErr: "context canceled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			initializer := &Initializer{
				crdClient:             tt.crdClient,
				ovsBridge:             "br-int",
				stopCh:                stopCh,
				networkConfig:         &config.NetworkConfig{},
				nodeType:              config.ExternalNode,
				externalNodeNamespace: "external",
			}
			close(stopCh)
			mockGetIPNetDeviceFromIP(t, nil, ipDevice)
			err := initializer.initVMLocalConfig(tt.nodeName)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateSupportedDPFeatures(t *testing.T) {
	tests := []struct {
		name          string
		expectedCalls func(m *ovsctltest.MockOVSCtlClient)
		expectedErr   string
	}{
		{
			name: "error listing DP features",
			expectedCalls: func(m *ovsctltest.MockOVSCtlClient) {
				m.EXPECT().GetDPFeatures().Return(map[ovsctl.DPFeature]bool{}, fmt.Errorf("error listing DP features"))
			},
			expectedErr: "error listing DP features",
		},
		{
			name: "required feature is unknown",
			expectedCalls: func(m *ovsctltest.MockOVSCtlClient) {
				m.EXPECT().GetDPFeatures().Return(map[ovsctl.DPFeature]bool{}, nil)
			},
			expectedErr: "the required OVS DP feature 'CT state' support is unknown",
		},
		{
			name: "required feature is not supported",
			expectedCalls: func(m *ovsctltest.MockOVSCtlClient) {
				m.EXPECT().GetDPFeatures().Return(map[ovsctl.DPFeature]bool{
					ovsctl.CTStateFeature: false,
				}, nil)
			},
			expectedErr: "the required OVS DP feature 'CT state' is not supported",
		},
		{
			name: "required features supported",
			expectedCalls: func(m *ovsctltest.MockOVSCtlClient) {
				m.EXPECT().GetDPFeatures().Return(map[ovsctl.DPFeature]bool{
					ovsctl.CTStateFeature:    true,
					ovsctl.CTZoneFeature:     true,
					ovsctl.CTMarkFeature:     true,
					ovsctl.CTLabelFeature:    true,
					ovsctl.CTStateNATFeature: true,
				}, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := mock.NewController(t)
			mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(controller)
			tt.expectedCalls(mockOVSCtlClient)
			initializer := &Initializer{
				ovsCtlClient: mockOVSCtlClient,
			}
			err := initializer.validateSupportedDPFeatures()
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDeleteStaleFlowsWithRetry(t *testing.T) {
	testErr := errors.New("delete stale flows error")

	t.Run("succeeds on first attempt", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctrl := mock.NewController(t)
			mockOFClient := openflowtest.NewMockClient(ctrl)
			mockOFClient.EXPECT().DeleteStaleFlows().Return(nil)

			initializer := &Initializer{
				ofClient: mockOFClient,
				stopCh:   make(chan struct{}),
			}

			result := initializer.deleteStaleFlowsWithRetry()
			assert.True(t, result)
		})
	})

	t.Run("succeeds after transient failures", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctrl := mock.NewController(t)
			mockOFClient := openflowtest.NewMockClient(ctrl)
			mock.InOrder(
				mockOFClient.EXPECT().DeleteStaleFlows().Return(testErr),
				mockOFClient.EXPECT().DeleteStaleFlows().Return(testErr),
				mockOFClient.EXPECT().DeleteStaleFlows().Return(nil),
			)

			initializer := &Initializer{
				ofClient: mockOFClient,
				stopCh:   make(chan struct{}),
			}

			var result bool
			done := make(chan struct{})
			go func() {
				defer close(done)
				result = initializer.deleteStaleFlowsWithRetry()
			}()

			// Let the retry loop block on time.After, then advance the fake clock
			// through each retry interval.
			synctest.Wait()
			time.Sleep(staleFlowDeleteRetryInterval)
			synctest.Wait()
			select {
			case <-done:
				t.Fatal("deleteStaleFlowsWithRetry should not return until after the third DeleteStaleFlows succeeds")
			default:
			}
			time.Sleep(staleFlowDeleteRetryInterval)
			synctest.Wait()

			<-done
			assert.True(t, result)
		})
	})

	t.Run("stops retrying when stopCh is closed", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctrl := mock.NewController(t)
			mockOFClient := openflowtest.NewMockClient(ctrl)
			mockOFClient.EXPECT().DeleteStaleFlows().Return(testErr).AnyTimes()

			stopCh := make(chan struct{})
			initializer := &Initializer{
				ofClient: mockOFClient,
				stopCh:   stopCh,
			}

			var result bool
			done := make(chan struct{})
			go func() {
				defer close(done)
				result = initializer.deleteStaleFlowsWithRetry()
			}()

			synctest.Wait()
			close(stopCh)

			<-done
			assert.False(t, result)
		})
	})
}

// reconnectionTest runs restoreOVSOnReconnection with mocks which fake OVS, and records the times
// at which the steps run, relative to the start of the test. It must run in a synctest bubble.
type reconnectionTest struct {
	ofConnCh chan struct{}
	stopCh   chan struct{}
	done     chan struct{}
	start    time.Time

	mutex sync.Mutex
	// connected is whether the fake OpenFlow connection is up.
	connected bool
	// flowRestoreWait is the value of the flow-restore-wait config in the fake OVSDB.
	flowRestoreWait bool
	// replayed is whether the last flow replay succeeded.
	replayed bool
	// replayTimes and portConfigTimes are the times of the calls to ReplayFlows and
	// SetPortNoFlood. flagRemovalTimes are the times at which flow-restore-wait was removed.
	replayTimes, portConfigTimes, flagRemovalTimes []time.Duration
}

// reconnectionTestConfig sets the faults which a reconnectionTest injects.
type reconnectionTestConfig struct {
	// replayErr and portConfigErr return the error of the n-th call, starting from 1, to
	// ReplayFlows and SetPortNoFlood. If they are nil, every call succeeds.
	replayErr, portConfigErr func(n int) error
	// ovsdbErrUntil is the time, relative to the start of the test, until which OVSDB calls
	// fail. The OVSDB client waits for the connection when it is down, so this is another error,
	// e.g. a failed transaction.
	ovsdbErrUntil time.Duration
}

func startReconnectionTest(t *testing.T, cfg reconnectionTestConfig) *reconnectionTest {
	ctrl := mock.NewController(t)
	mockOFClient := openflowtest.NewMockClient(ctrl)
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(ctrl)
	ifaceStore := interfacestore.NewInterfaceStore()
	ifaceStore.AddInterfaces([]*interfacestore.InterfaceConfig{
		interfacestore.NewTrafficControlInterface("antrea-tap1", &interfacestore.OVSPortConfig{OFPort: 10, PortUUID: "uuid1"}),
	})
	rt := &reconnectionTest{
		ofConnCh: make(chan struct{}),
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
		start:    time.Now(),
	}
	callErr := func(errFn func(int) error, n int) error {
		if errFn == nil {
			return nil
		}
		return errFn(n)
	}

	mockOFClient.EXPECT().IsConnected().DoAndReturn(func() bool {
		rt.mutex.Lock()
		defer rt.mutex.Unlock()
		return rt.connected
	}).AnyTimes()
	mockOFClient.EXPECT().ReplayFlows().DoAndReturn(func() error {
		rt.mutex.Lock()
		defer rt.mutex.Unlock()
		assert.True(t, rt.connected, "flows should not be replayed while disconnected from OVS")
		rt.replayTimes = append(rt.replayTimes, time.Since(rt.start))
		err := callErr(cfg.replayErr, len(rt.replayTimes))
		rt.replayed = err == nil
		return err
	}).AnyTimes()
	mockOVSCtlClient.EXPECT().SetPortNoFlood(10).DoAndReturn(func(int) error {
		rt.mutex.Lock()
		defer rt.mutex.Unlock()
		rt.portConfigTimes = append(rt.portConfigTimes, time.Since(rt.start))
		return callErr(cfg.portConfigErr, len(rt.portConfigTimes))
	}).AnyTimes()
	mockOVSBridgeClient.EXPECT().GetOVSOtherConfig().DoAndReturn(func() (map[string]string, error) {
		rt.mutex.Lock()
		defer rt.mutex.Unlock()
		assert.True(t, rt.replayed, "flow-restore-wait should only be removed after a successful flow replay")
		if time.Since(rt.start) < cfg.ovsdbErrUntil {
			return nil, errors.New("transaction failed")
		}
		if rt.flowRestoreWait {
			return map[string]string{"flow-restore-wait": "true"}, nil
		}
		return map[string]string{}, nil
	}).AnyTimes()
	mockOVSBridgeClient.EXPECT().DeleteOVSOtherConfig([]string{"flow-restore-wait"}).DoAndReturn(func([]string) error {
		rt.mutex.Lock()
		defer rt.mutex.Unlock()
		rt.flowRestoreWait = false
		rt.flagRemovalTimes = append(rt.flagRemovalTimes, time.Since(rt.start))
		return nil
	}).AnyTimes()

	initializer := &Initializer{
		ofClient:        mockOFClient,
		ovsBridgeClient: mockOVSBridgeClient,
		ovsCtlClient:    mockOVSCtlClient,
		ifaceStore:      ifaceStore,
		stopCh:          rt.stopCh,
	}
	go func() {
		defer close(rt.done)
		initializer.restoreOVSOnReconnection(rt.ofConnCh)
	}()
	return rt
}

// reconnect notifies a reconnection to OVS, after an ovs-vswitchd restart which set
// flow-restore-wait.
func (rt *reconnectionTest) reconnect() {
	rt.mutex.Lock()
	rt.connected = true
	rt.flowRestoreWait = true
	rt.mutex.Unlock()
	rt.ofConnCh <- struct{}{}
}

// disconnect makes the fake OpenFlow connection go down.
func (rt *reconnectionTest) disconnect() {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	rt.connected = false
}

// advance lets restoreOVSOnReconnection run for d.
func (rt *reconnectionTest) advance(d time.Duration) {
	time.Sleep(d)
	synctest.Wait()
}

// stop stops restoreOVSOnReconnection and waits for it to return.
func (rt *reconnectionTest) stop() {
	close(rt.stopCh)
	<-rt.done
}

func TestRestoreOVSOnReconnection(t *testing.T) {
	testErr := errors.New("bundle reply is timeout")
	failFirst := func(failures int) func(int) error {
		return func(n int) error {
			if n <= failures {
				return testErr
			}
			return nil
		}
	}
	failAlways := func(int) error { return testErr }

	t.Run("retries failed replay with backoff, then removes flow-restore-wait", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rt := startReconnectionTest(t, reconnectionTestConfig{replayErr: failFirst(2)})
			rt.reconnect()
			rt.advance(10 * ovsRestoreMaxRetryDelay)
			rt.stop()

			// The retry delay doubles after each failure, and no more replay happens after a
			// successful one.
			assert.Equal(t, []time.Duration{0, 1 * time.Second, 3 * time.Second}, rt.replayTimes)
			// The port configs are restored right after the first replay, even though it
			// failed, and not again as that succeeded.
			assert.Equal(t, []time.Duration{0}, rt.portConfigTimes)
			// flow-restore-wait is only removed once the replay succeeds.
			assert.Equal(t, []time.Duration{3 * time.Second}, rt.flagRemovalTimes)
		})
	})

	t.Run("failed steps are retried independently", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// OVSDB fails the first two attempts to remove flow-restore-wait, at 0s and 1s.
			rt := startReconnectionTest(t, reconnectionTestConfig{
				portConfigErr: failFirst(1),
				ovsdbErrUntil: 2 * time.Second,
			})
			rt.reconnect()
			rt.advance(10 * ovsRestoreMaxRetryDelay)
			rt.stop()

			// The replay is not run again when the steps which depend on it are retried.
			assert.Equal(t, []time.Duration{0}, rt.replayTimes)
			// The port configs are restored on the first retry, and not again as that
			// succeeded.
			assert.Equal(t, []time.Duration{0, 1 * time.Second}, rt.portConfigTimes)
			// The removal is retried even though the port configs restoration failed in the
			// same attempt, and with the same backoff.
			assert.Equal(t, []time.Duration{3 * time.Second}, rt.flagRemovalTimes)
		})
	})

	t.Run("no retry while disconnected", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rt := startReconnectionTest(t, reconnectionTestConfig{
				replayErr:     failFirst(1),
				portConfigErr: failFirst(1),
			})
			rt.reconnect()
			synctest.Wait()
			// The OpenFlow connection goes down before the first retry, which is due in 1s.
			rt.disconnect()
			rt.advance(10 * ovsRestoreMaxRetryDelay)
			// The steps are not retried while disconnected, and the reconnection runs them.
			assert.Equal(t, []time.Duration{0}, rt.replayTimes)
			assert.Equal(t, []time.Duration{0}, rt.portConfigTimes)
			assert.Empty(t, rt.flagRemovalTimes)
			assert.True(t, rt.flowRestoreWait)

			rt.reconnect()
			rt.advance(10 * ovsRestoreMaxRetryDelay)
			rt.stop()

			reconnectionTime := 10 * ovsRestoreMaxRetryDelay
			assert.Equal(t, []time.Duration{0, reconnectionTime}, rt.replayTimes)
			assert.Equal(t, []time.Duration{0, reconnectionTime}, rt.portConfigTimes)
			assert.Equal(t, []time.Duration{reconnectionTime}, rt.flagRemovalTimes)
		})
	})

	t.Run("flow-restore-wait is kept while the replay fails", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rt := startReconnectionTest(t, reconnectionTestConfig{replayErr: failAlways, portConfigErr: failAlways})
			rt.reconnect()
			rt.advance(10 * ovsRestoreMaxRetryDelay)
			rt.stop()

			assert.Greater(t, len(rt.replayTimes), 1)
			// A failed replay does not prevent restoring the port configs.
			assert.Equal(t, rt.replayTimes, rt.portConfigTimes)
			assert.Empty(t, rt.flagRemovalTimes)
			assert.True(t, rt.flowRestoreWait)
		})
	})

	t.Run("a reconnection requires the flows to be replayed again", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// The replay fails after the second reconnection only.
			rt := startReconnectionTest(t, reconnectionTestConfig{replayErr: func(n int) error {
				if n == 2 {
					return testErr
				}
				return nil
			}})
			rt.reconnect()
			rt.advance(5 * time.Second)
			rt.reconnect()
			rt.advance(10 * ovsRestoreMaxRetryDelay)
			rt.stop()

			assert.Equal(t, []time.Duration{0, 5 * time.Second, 6 * time.Second}, rt.replayTimes)
			assert.Equal(t, []time.Duration{0, 5 * time.Second}, rt.portConfigTimes)
			// The replay which succeeded before the second reconnection does not count.
			assert.Equal(t, []time.Duration{0, 6 * time.Second}, rt.flagRemovalTimes)
		})
	})

	t.Run("retry delay is capped", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rt := startReconnectionTest(t, reconnectionTestConfig{replayErr: failAlways})
			expectedDelays := []time.Duration{
				1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second,
				30 * time.Second, 30 * time.Second, 30 * time.Second,
			}
			var total time.Duration
			for _, d := range expectedDelays {
				total += d
			}
			rt.reconnect()
			// Stop half-way between the last expected retry and the next one.
			rt.advance(total + ovsRestoreMaxRetryDelay/2)
			rt.stop()

			var delays []time.Duration
			for i := 1; i < len(rt.replayTimes); i++ {
				delays = append(delays, rt.replayTimes[i]-rt.replayTimes[i-1])
			}
			assert.Equal(t, expectedDelays, delays)
		})
	})

	t.Run("reconnection runs all steps immediately and resets the retry delay", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rt := startReconnectionTest(t, reconnectionTestConfig{replayErr: failFirst(3)})
			rt.reconnect()
			rt.advance(ovsRestoreInitialRetryDelay)
			// The next retry is due in 2s; a reconnection runs all the steps immediately instead.
			rt.reconnect()
			rt.advance(10 * ovsRestoreMaxRetryDelay)
			rt.stop()

			// After the reconnection, the retry delay is reset to its initial value.
			assert.Equal(t, []time.Duration{0, 1 * time.Second, 1 * time.Second, 2 * time.Second}, rt.replayTimes)
			// All steps run after each reconnection, but only the failed ones after a retry.
			assert.Equal(t, []time.Duration{0, 1 * time.Second}, rt.portConfigTimes)
			assert.Equal(t, []time.Duration{2 * time.Second}, rt.flagRemovalTimes)
		})
	})

	t.Run("returns when ofConnCh is closed", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rt := startReconnectionTest(t, reconnectionTestConfig{replayErr: failAlways})
			rt.reconnect()
			synctest.Wait()
			close(rt.ofConnCh)
			<-rt.done
		})
	})
}
