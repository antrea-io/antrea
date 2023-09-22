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

package externalnode

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"antrea.io/antrea/pkg/agent/interfacestore"
	interfacestoretest "antrea.io/antrea/pkg/agent/interfacestore/testing"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha1informers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	ovsctltest "antrea.io/antrea/pkg/ovs/ovsctl/testing"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/ip"
)

var (
	ifaceName1      = "intf1"
	ifaceName2      = "intf2"
	uplinkName      = "uplinkName"
	entityName      = "entityName"
	entityNamespace = "entityNamespace"
	ifaceUUID1      = uuid.NewString()
	ifaceUUID2      = uuid.NewString()
	portUUID1       = uuid.NewString()
	portUUID2       = uuid.NewString()
	_, cidr1, _     = net.ParseCIDR("10.20.30.40")
	intf1           = interfacestore.InterfaceConfig{
		InterfaceName: ifaceName1,
		IPs:           []net.IP{net.ParseIP("10.5.6.9")},
		OVSPortConfig: &interfacestore.OVSPortConfig{OFPort: 1, PortUUID: portUUID1},
		EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
			EntityName:      "externalEntity",
			EntityNamespace: "externalEntityNamespace",
			UplinkPort: &interfacestore.OVSPortConfig{
				PortUUID: ifaceUUID1,
				OFPort:   5,
			},
		},
	}
	intf2 = interfacestore.InterfaceConfig{
		InterfaceName: ifaceName2,
		IPs:           []net.IP{net.ParseIP("10.5.6.9")},
		OVSPortConfig: &interfacestore.OVSPortConfig{OFPort: 2},
		EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
			EntityName:      "externalEntity",
			EntityNamespace: "externalEntityNamespace",
			UplinkPort: &interfacestore.OVSPortConfig{
				PortUUID: ifaceUUID2,
				OFPort:   6,
			},
		},
	}
	portData1 = &ovsconfig.OVSPortData{
		Name: "portName",
		ExternalIDs: map[string]string{
			ovsExternalIDUplinkName:      "uplinkName",
			ovsExternalIDUplinkPort:      portUUID2,
			ovsExternalIDEntityName:      "externalEntity",
			ovsExternalIDEntityNamespace: "externalEntityNamespace",
			ovsExternalIDIPs:             "10.22.33.44",
		},
	}
)

func TestCreateOVSPortsAndFlowsFailure(t *testing.T) {
	controller := gomock.NewController(t)
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
	mockOFClient := openflowtest.NewMockClient(controller)
	mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(controller)
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(controller)
	c := newExternalNodeController(t, controller, mockOVSBridgeClient, mockOFClient, mockOVSCtlClient, mockIfaceStore)

	iface := &net.Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		MTU:          1500,
	}
	uplinkUUID := uuid.NewString()
	hostIfUUID := uuid.NewString()
	hostOFPort := int32(3)
	uplinkOFPort := int32(4)
	hostIfName := "hostIfName"
	ipAddrs := []string{"10.20.30.40"}
	expectedInfo := map[string]interface{}{
		"uplink-name":      uplinkName,
		"entity-name":      entityName,
		"antrea-type":      "host",
		"entity-namespace": entityNamespace,
		"ip-address":       strings.Join(ipAddrs, ipsSplitter),
		"uplink-port":      uplinkUUID,
	}
	defer mockRenameInterface(nil)()
	defer mockGetInterfaceConfig([]mockGetInterfaceConfigParam{{iface, []*net.IPNet{cidr1}, nil}})()

	mockOVSBridgeClient.EXPECT().CreatePort(uplinkName, uplinkName, map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUplink,
	}).Return(uplinkUUID, nil)
	mockOVSBridgeClient.EXPECT().CreateInternalPort(hostIfName, int32(0), "22:33:44:55:66:77:88", expectedInfo).Return(hostIfUUID, nil).Times(1)
	mockOVSBridgeClient.EXPECT().GetOFPort(uplinkName, false).Return(uplinkOFPort, nil).Times(1)
	mockOVSBridgeClient.EXPECT().GetOFPort(hostIfName, false).Return(hostOFPort, ovsconfig.NewTransactionError(fmt.Errorf("interface %s not found", hostIfName), false)).Times(1)
	mockOVSBridgeClient.EXPECT().DeletePort(uplinkUUID).Times(1)
	mockOVSBridgeClient.EXPECT().DeletePort(hostIfUUID).Times(1)
	hostIFConfig, err := c.createOVSPortsAndFlows(uplinkName, hostIfName, entityNamespace, entityName, ipAddrs)
	assert.Equal(t, ovsconfig.NewTransactionError(fmt.Errorf("interface %s not found", hostIfName), false), err)
	assert.Nil(t, hostIFConfig)
}

func TestUpdateOVSPortsData(t *testing.T) {
	controller := gomock.NewController(t)
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
	mockOFClient := openflowtest.NewMockClient(controller)
	mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(controller)
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(controller)
	c := newExternalNodeController(t, controller, mockOVSBridgeClient, mockOFClient, mockOVSCtlClient, mockIfaceStore)
	interfaceConfig := &intf1
	eeName := "eeName"
	ips := []string{"10.20.30.40"}
	attachInfo := map[string]interface{}{
		"antrea-type":      "host",
		"entity-name":      "eeName",
		"entity-namespace": "externalEntityNamespace",
		"ip-address":       "10.20.30.40",
		"uplink-name":      "uplinkName",
		"uplink-port":      portUUID2,
	}
	mockOVSBridgeClient.EXPECT().SetPortExternalIDs(intf1.InterfaceName, attachInfo)
	expectedIface := &interfacestore.InterfaceConfig{
		InterfaceName: interfaceConfig.InterfaceName,
		Type:          interfacestore.ExternalEntityInterface,
		OVSPortConfig: &interfacestore.OVSPortConfig{
			PortUUID: interfaceConfig.PortUUID,
			OFPort:   interfaceConfig.OFPort,
		},
		EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
			EntityName:      eeName,
			EntityNamespace: interfaceConfig.EntityNamespace,
			UplinkPort: &interfacestore.OVSPortConfig{
				PortUUID: interfaceConfig.UplinkPort.PortUUID,
				OFPort:   interfaceConfig.UplinkPort.OFPort,
			},
		},
		IPs: []net.IP{net.ParseIP("10.20.30.40")},
	}
	iface, err := c.updateOVSPortsData(interfaceConfig, portData1, eeName, ips)
	assert.Equal(t, expectedIface, iface)
	assert.NoError(t, err)
}

func TestParseProtocol(t *testing.T) {
	for _, tt := range []struct {
		name           string
		protocol       string
		expectProtocol binding.Protocol
	}{
		{
			name:           "UDP protocol",
			protocol:       "udp",
			expectProtocol: binding.ProtocolUDP,
		},
		{
			name:           "TCP protocol",
			protocol:       "tcp",
			expectProtocol: binding.ProtocolTCP,
		},
		{
			name:           "ICMP protocol",
			protocol:       "icmp",
			expectProtocol: binding.ProtocolICMP,
		},
		{
			name:           "IP protocol",
			protocol:       "ip",
			expectProtocol: binding.ProtocolIP,
		},
		{
			name:           "IGMP protocol",
			protocol:       "igmp",
			expectProtocol: "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			protocol := parseProtocol(tt.protocol)
			assert.Equal(t, tt.expectProtocol, protocol)
		})
	}
}

func TestParseHostInterfaceConfig(t *testing.T) {
	randomUUID := uuid.NewString()
	portUUID := uuid.NewString()

	for _, tt := range []struct {
		name                  string
		portData              *ovsconfig.OVSPortData
		portConfig            *interfacestore.OVSPortConfig
		uplinkPortData        *ovsconfig.OVSPortData
		getPortDataErr        error
		expectInterfaceConfig *interfacestore.InterfaceConfig
		expectedErr           error
	}{
		{
			name: "GetPortData error",
			portData: &ovsconfig.OVSPortData{
				Name: "intf1",
				ExternalIDs: map[string]string{
					ovsExternalIDUplinkName:      "uplinkName",
					ovsExternalIDUplinkPort:      randomUUID,
					ovsExternalIDEntityName:      "externalEntity",
					ovsExternalIDEntityNamespace: "externalEntityNamespace",
					ovsExternalIDIPs:             "10.22.33.44",
				},
			},
			portConfig:            &interfacestore.OVSPortConfig{PortUUID: portUUID, OFPort: 3},
			uplinkPortData:        nil,
			getPortDataErr:        ovsconfig.NewTransactionError(fmt.Errorf("port %s not found", portUUID), false),
			expectInterfaceConfig: nil,
			expectedErr:           ovsconfig.NewTransactionError(fmt.Errorf("port %s not found", portUUID), false),
		},
		{
			name: "ParseHostInterfaceConfig and return interfaceConfig",
			portData: &ovsconfig.OVSPortData{
				Name: "intf1",
				ExternalIDs: map[string]string{
					ovsExternalIDUplinkName:      "uplinkName",
					ovsExternalIDUplinkPort:      randomUUID,
					ovsExternalIDEntityName:      "externalEntity",
					ovsExternalIDEntityNamespace: "externalEntityNamespace",
					ovsExternalIDIPs:             "10.22.33.44",
				},
			},
			portConfig:     &interfacestore.OVSPortConfig{PortUUID: portUUID, OFPort: 3},
			uplinkPortData: &ovsconfig.OVSPortData{OFPort: 5},
			expectInterfaceConfig: &interfacestore.InterfaceConfig{
				InterfaceName: "intf1",
				Type:          interfacestore.ExternalEntityInterface,
				OVSPortConfig: &interfacestore.OVSPortConfig{PortUUID: portUUID, OFPort: 3},
				EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
					EntityName:      "externalEntity",
					EntityNamespace: "externalEntityNamespace",
					UplinkPort: &interfacestore.OVSPortConfig{
						PortUUID: randomUUID,
						OFPort:   5,
					},
				},
				IPs: []net.IP{
					net.ParseIP("10.22.33.44"),
				},
			},
			expectedErr: nil,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
			mockOVSBridgeClient.EXPECT().GetPortData(
				tt.portData.ExternalIDs[ovsExternalIDUplinkPort],
				tt.portData.ExternalIDs[ovsExternalIDUplinkName],
			).Return(
				tt.uplinkPortData,
				tt.getPortDataErr,
			)
			config, err := ParseHostInterfaceConfig(mockOVSBridgeClient, tt.portData, tt.portConfig)
			assert.Equal(t, tt.expectInterfaceConfig, config)
			assert.Equal(t, tt.expectedErr, err)
		})
	}
}

func TestReconcile(t *testing.T) {
	controller := gomock.NewController(t)
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
	mockOFClient := openflowtest.NewMockClient(controller)
	mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(controller)
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(controller)
	c := newExternalNodeController(t, controller, mockOVSBridgeClient, mockOFClient, mockOVSCtlClient, mockIfaceStore)

	mockIfaceStore.EXPECT().GetInterfacesByType(interfacestore.ExternalEntityInterface).Return(
		[]*interfacestore.InterfaceConfig{&intf1, &intf2},
	)
	mockOFClient.EXPECT().InstallVMUplinkFlows(intf1.InterfaceName, int32(1), int32(5)).Times(1)
	mockOFClient.EXPECT().InstallVMUplinkFlows(intf2.InterfaceName, int32(2), int32(6)).Times(1)
	c.policyBypassRules = []agentconfig.PolicyBypassRule{
		{
			Direction: "ingress",
			Protocol:  "tcp",
			CIDR:      "10.20.0.0/16",
			Port:      233,
		},
		{
			Direction: "engress",
			Protocol:  "udp",
			CIDR:      "10.30.0.0/16",
			Port:      244,
		},
	}
	_, cidrIngress, _ := net.ParseCIDR("10.20.0.0/16")
	_, cidrEgress, _ := net.ParseCIDR("10.30.0.0/16")
	mockOFClient.EXPECT().InstallPolicyBypassFlows(binding.ProtocolTCP, cidrIngress, uint16(233), true).Times(1)
	mockOFClient.EXPECT().InstallPolicyBypassFlows(binding.ProtocolUDP, cidrEgress, uint16(244), false).Times(1)
	c.reconcile()
}

func TestAddExternalNode(t *testing.T) {
	controller := gomock.NewController(t)
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
	mockOFClient := openflowtest.NewMockClient(controller)
	mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(controller)
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(controller)
	c := newExternalNodeController(t, controller, mockOVSBridgeClient, mockOFClient, mockOVSCtlClient, mockIfaceStore)
	defer mockGetIPNetDeviceFromIP([]mockGetIPNetDeviceFromIPParam{
		{&net.Interface{Name: "intf1"}, nil},
	})()
	externalNode := &v1alpha1.ExternalNode{
		ObjectMeta: metav1.ObjectMeta{Name: "eeName", Namespace: "ns1", Labels: map[string]string{"en": "vm1"}},
		Spec: v1alpha1.ExternalNodeSpec{
			Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"1.1.1.2"}}},
		},
	}
	mockIfaceStore.EXPECT().GetInterfaceByName("intf1").Return(&intf1, true)
	mockOVSBridgeClient.EXPECT().GetPortData(portUUID1, "intf1").Return(portData1, nil)
	expectedInfo := map[string]interface{}{
		"uplink-name":      "uplinkName",
		"entity-name":      "eeName",
		"antrea-type":      "host",
		"entity-namespace": "externalEntityNamespace",
		"ip-address":       "1.1.1.2",
		"uplink-port":      portUUID2,
	}
	mockOVSBridgeClient.EXPECT().SetPortExternalIDs(intf1.InterfaceName, expectedInfo)
	iface := &interfacestore.InterfaceConfig{
		InterfaceName: intf1.InterfaceName,
		Type:          interfacestore.ExternalEntityInterface,
		OVSPortConfig: &interfacestore.OVSPortConfig{
			PortUUID: intf1.PortUUID,
			OFPort:   intf1.OFPort,
		},
		EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
			EntityName:      "eeName",
			EntityNamespace: intf1.EntityNamespace,
			UplinkPort: &interfacestore.OVSPortConfig{
				PortUUID: intf1.UplinkPort.PortUUID,
				OFPort:   intf1.UplinkPort.OFPort,
			},
		},
		IPs: []net.IP{net.ParseIP("1.1.1.2")},
	}
	mockIfaceStore.EXPECT().AddInterface(iface)
	c.addExternalNode(externalNode)
	assert.Equal(t, externalNode, c.syncedExternalNode)
}

func TestEnqueueExternalNodeUpdate(t *testing.T) {
	controller := gomock.NewController(t)
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
	mockOFClient := openflowtest.NewMockClient(controller)
	mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(controller)
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(controller)
	c := newExternalNodeController(t, controller, mockOVSBridgeClient, mockOFClient, mockOVSCtlClient, mockIfaceStore)
	externalNode1 := &v1alpha1.ExternalNode{
		ObjectMeta: metav1.ObjectMeta{Name: "vm1", Namespace: "ns1", Labels: map[string]string{"en": "vm1"}},
		Spec: v1alpha1.ExternalNodeSpec{
			Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"1.1.1.2"}}},
		},
	}
	externalNode2 := &v1alpha1.ExternalNode{
		ObjectMeta: metav1.ObjectMeta{Name: "vm1", Namespace: "ns1", Labels: map[string]string{"en": "vm1"}},
		Spec: v1alpha1.ExternalNodeSpec{
			Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"1.1.1.3"}}},
		},
	}
	for _, tt := range []struct {
		name           string
		oldObj         *v1alpha1.ExternalNode
		newObj         *v1alpha1.ExternalNode
		expectEnqueued bool
	}{
		{
			name:           "same externalnode",
			newObj:         externalNode1,
			oldObj:         externalNode1,
			expectEnqueued: false,
		},
		{
			name:           "different externalnode",
			newObj:         externalNode2,
			oldObj:         externalNode1,
			expectEnqueued: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "externalNode")
			c.enqueueExternalNodeUpdate(tt.oldObj, tt.newObj)
			if tt.expectEnqueued {
				assert.Equal(t, 1, c.queue.Len())
			} else {
				assert.Zero(t, c.queue.Len())
			}
		})
	}
}

func newExternalNodeController(t *testing.T, controller *gomock.Controller, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient, mockOFClient *openflowtest.MockClient, mockOVSCtlClient *ovsctltest.MockOVSCtlClient, mockIfaceStore *interfacestoretest.MockInterfaceStore) *ExternalNodeController {
	mockOVSBridgeClient.EXPECT().GetBridgeName().Times(1)
	localExternalNodeInformer := crdv1alpha1informers.NewExternalNodeInformer(
		nil,
		"external-ns",
		time.Second,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	c, err := NewExternalNodeController(
		mockOVSBridgeClient,
		mockOFClient,
		localExternalNodeInformer,
		mockIfaceStore,
		channel.NewSubscribableChannel("ExternalEntityUpdate", 100),
		"external-ns",
		[]agentconfig.PolicyBypassRule{},
	)
	c.ovsctlClient = mockOVSCtlClient
	require.NoError(t, err)
	return c
}

func TestGetHostInterfaceName(t *testing.T) {
	for _, tt := range []struct {
		name                       string
		iface                      v1alpha1.NetworkInterface
		getIPNetDeviceFromIPParams []mockGetIPNetDeviceFromIPParam
		expectedIfName             string
		expectedIPs                []string
		expectedError              error
	}{
		{
			name:  "getHostInterfaceName successfully",
			iface: v1alpha1.NetworkInterface{IPs: []string{"1.1.1.3"}},
			getIPNetDeviceFromIPParams: []mockGetIPNetDeviceFromIPParam{
				{
					link: &net.Interface{
						Name:         "enp0s3",
						HardwareAddr: net.HardwareAddr{0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
						Index:        4,
						Flags:        net.FlagUp,
					},
					getIPNetDeviceFromIPErr: nil,
				},
			},
			expectedIfName: "enp0s3",
			expectedIPs:    []string{"1.1.1.3"},
			expectedError:  nil,
		},
		{
			name:  "Failed to get device from IP",
			iface: v1alpha1.NetworkInterface{IPs: []string{"1.1.1.3"}},
			getIPNetDeviceFromIPParams: []mockGetIPNetDeviceFromIPParam{
				{
					getIPNetDeviceFromIPErr: fmt.Errorf("unable to find local IPs and device"),
				},
			},
			expectedIfName: "",
			expectedIPs:    []string{},
			expectedError:  fmt.Errorf("cannot find interface via IPs [1.1.1.3]"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			defer mockGetIPNetDeviceFromIP(tt.getIPNetDeviceFromIPParams)()
			ifaceName, IPs, err := getHostInterfaceName(tt.iface)
			assert.Equal(t, tt.expectedIfName, ifaceName)
			assert.Equal(t, tt.expectedIPs, IPs)
			assert.Equal(t, tt.expectedError, err)
		})
	}
}

func TestGetOVSAttachInfo(t *testing.T) {
	uplinkUUID := uuid.NewString()

	ips := []string{"10.20.30.40"}
	info := GetOVSAttachInfo(uplinkName, uplinkUUID, entityName, entityNamespace, ips)
	expectedInfo := map[string]interface{}{
		"uplink-name":      uplinkName,
		"uplink-port":      uplinkUUID,
		"antrea-type":      "host",
		"entity-name":      entityName,
		"entity-namespace": entityNamespace,
		"ip-address":       "10.20.30.40",
	}
	assert.Equal(t, expectedInfo, info)
}

func mockRenameInterface(renameIntefaceErr error) func() {
	originalRenameInterface := renameInterface
	renameInterface = func(from, to string) error {
		return renameIntefaceErr
	}
	return func() {
		renameInterface = originalRenameInterface
	}
}

type mockGetIPNetDeviceFromIPParam struct {
	link                    *net.Interface
	getIPNetDeviceFromIPErr error
}

func mockGetIPNetDeviceFromIP(params []mockGetIPNetDeviceFromIPParam) func() {
	originalGetIPNetDeviceFromIP := getIPNetDeviceFromIP
	counter := 0
	getIPNetDeviceFromIP = func(_ *ip.DualStackIPs, _ sets.Set[string]) (v4IPNet *net.IPNet, v6IPNet *net.IPNet, iface *net.Interface, err error) {
		param := params[counter]
		counter++
		return &net.IPNet{}, &net.IPNet{}, param.link, param.getIPNetDeviceFromIPErr
	}
	return func() {
		getIPNetDeviceFromIP = originalGetIPNetDeviceFromIP
	}
}

type mockGetInterfaceConfigParam struct {
	iface                 *net.Interface
	addrs                 []*net.IPNet
	getInterfaceConfigErr error
}

func mockGetInterfaceConfig(ifaceConfigs []mockGetInterfaceConfigParam) func() {
	originalGetInterfaceConfig := getInterfaceConfig
	counter := 0
	getInterfaceConfig = func(_ string) (*net.Interface, []*net.IPNet, []interface{}, error) {
		ifaceConfig := ifaceConfigs[counter]
		counter++
		return ifaceConfig.iface, ifaceConfig.addrs, []interface{}{}, ifaceConfig.getInterfaceConfigErr
	}
	return func() {
		getInterfaceConfig = originalGetInterfaceConfig
	}
}
