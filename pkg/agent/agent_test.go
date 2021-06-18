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
	"testing"

	mock "github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/agent/cniserver"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	"antrea.io/antrea/pkg/util/env"
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
			interfacestore.NewContainerInterface("p1", uuid1, "pod1", "ns1", p1NetMAC, []net.IP{p1NetIP})))}
	ovsPort2 := ovsconfig.OVSPortData{UUID: uuid2, Name: "p2", IFName: "p2", OFPort: 12,
		ExternalIDs: convertExternalIDMap(cniserver.BuildOVSPortExternalIDs(
			interfacestore.NewContainerInterface("p2", uuid2, "pod2", "ns2", p2NetMAC, []net.IP{p2NetIP})))}
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

func TestInitNodeLocalConfig(t *testing.T) {
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
	_, podCIDR, _ := net.ParseCIDR(podCIDRStr)
	tests := []struct {
		name                   string
		trafficEncapMode       config.TrafficEncapModeType
		tunnelType             ovsconfig.TunnelType
		mtu                    int
		expectedMTU            int
		expectedNodeAnnotation map[string]string
	}{
		{
			name:                   "noencap mode",
			trafficEncapMode:       config.TrafficEncapModeNoEncap,
			mtu:                    0,
			expectedMTU:            1500,
			expectedNodeAnnotation: map[string]string{types.NodeMACAddressAnnotationKey: macAddr.String()},
		},
		{
			name:                   "hybrid mode",
			trafficEncapMode:       config.TrafficEncapModeHybrid,
			mtu:                    0,
			expectedMTU:            1500,
			expectedNodeAnnotation: map[string]string{types.NodeMACAddressAnnotationKey: macAddr.String()},
		},
		{
			name:                   "encap mode, geneve tunnel",
			trafficEncapMode:       config.TrafficEncapModeEncap,
			tunnelType:             ovsconfig.GeneveTunnel,
			mtu:                    0,
			expectedMTU:            1450,
			expectedNodeAnnotation: nil,
		},
		{
			name:                   "encap mode, mtu specified",
			trafficEncapMode:       config.TrafficEncapModeEncap,
			tunnelType:             ovsconfig.GeneveTunnel,
			mtu:                    1400,
			expectedMTU:            1400,
			expectedNodeAnnotation: nil,
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
			defer mockGetIPNetDeviceFromIP(nodeIPNet, ipDevice)()
			defer mockNodeNameEnv(nodeName)()

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
			require.NoError(t, initializer.initNodeLocalConfig())
			expectedNodeConfig := config.NodeConfig{
				Name:            nodeName,
				OVSBridge:       ovsBridge,
				DefaultTunName:  defaultTunInterfaceName,
				PodIPv4CIDR:     podCIDR,
				NodeIPAddr:      nodeIPNet,
				NodeMTU:         tt.expectedMTU,
				UplinkNetConfig: new(config.AdapterNetConfig),
			}
			assert.Equal(t, expectedNodeConfig, *initializer.nodeConfig)
			node, err := client.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedNodeAnnotation, node.Annotations)
		})
	}
}

func mockGetIPNetDeviceFromIP(ipNet *net.IPNet, ipDevice *net.Interface) func() {
	prevGetIPNetDeviceFromIP := getIPNetDeviceFromIP
	getIPNetDeviceFromIP = func(localIP net.IP) (*net.IPNet, *net.Interface, error) {
		return ipNet, ipDevice, nil
	}
	return func() { getIPNetDeviceFromIP = prevGetIPNetDeviceFromIP }
}

func mockNodeNameEnv(name string) func() {
	_ = os.Setenv(env.NodeNameEnvKey, name)
	return func() { os.Unsetenv(env.NodeNameEnvKey) }
}
