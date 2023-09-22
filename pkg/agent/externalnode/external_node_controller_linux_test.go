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
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	interfacestoretest "antrea.io/antrea/pkg/agent/interfacestore/testing"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	ovsctltest "antrea.io/antrea/pkg/ovs/ovsctl/testing"
)

var (
	eeNamespace = "eeNamespace"
	hostIfName  = "hostIfName"
	eeName      = "eeName"
	_, cidr2, _ = net.ParseCIDR("10.20.30.50")
	intf3       = interfacestore.InterfaceConfig{
		InterfaceName: ifaceName1,
		IPs:           []net.IP{net.ParseIP("10.5.6.9")},
		OVSPortConfig: &interfacestore.OVSPortConfig{OFPort: 1, PortUUID: portUUID1},
		EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
			EntityName:      "externalEntity",
			EntityNamespace: "externalEntityNamespace",
			UplinkPort: &interfacestore.OVSPortConfig{
				PortUUID: ifaceUUID1,
				OFPort:   6,
			},
		},
	}
)

func TestUpdateExternalNode(t *testing.T) {
	iface := &net.Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		MTU:          1500,
	}
	defer mockGetInterfaceConfig(
		[]mockGetInterfaceConfigParam{
			{iface, []*net.IPNet{cidr1}, nil},
		},
	)()
	defer mockConfigureLinkRoutes(nil)()
	externalNode1 := v1alpha1.ExternalNode{
		ObjectMeta: metav1.ObjectMeta{Name: "intf1", Namespace: "ns1", Labels: map[string]string{"en": "intf1"}},
		Spec: v1alpha1.ExternalNodeSpec{
			Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"10.5.6.9"}}},
		},
	}
	externalNode2 := v1alpha1.ExternalNode{
		ObjectMeta: metav1.ObjectMeta{Name: "intf1", Namespace: "ns1", Labels: map[string]string{"en": "intf1"}},
		Spec: v1alpha1.ExternalNodeSpec{
			Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"10.5.6.8"}}},
		},
	}
	for _, tt := range []struct {
		name                  string
		preExternalNode       *v1alpha1.ExternalNode
		curExternalNode       *v1alpha1.ExternalNode
		preIf                 *interfacestore.InterfaceConfig
		curIf                 *interfacestore.InterfaceConfig
		syncedExternalNode    *v1alpha1.ExternalNode
		linkByNameCalledTimes int
		existingIfaceMap      map[string]bool
		expectedCalls         func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient, mockIfaceStore *interfacestoretest.MockInterfaceStore, mockOVSCtlClient *ovsctltest.MockOVSCtlClient)
	}{
		{
			name:               "ip changed",
			preIf:              &intf1,
			curIf:              &intf3,
			preExternalNode:    &externalNode1,
			curExternalNode:    &externalNode2,
			syncedExternalNode: &externalNode2,
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient, mockIfaceStore *interfacestoretest.MockInterfaceStore, mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				mockIfaceStore.EXPECT().GetInterfaceByName(intf3.InterfaceName).Return(&intf3, true)
				returnedPortData := &ovsconfig.OVSPortData{
					ExternalIDs: map[string]string{
						ovsExternalIDUplinkName:      intf3.InterfaceName,
						ovsExternalIDUplinkPort:      intf3.UplinkPort.PortUUID,
						ovsExternalIDEntityName:      intf3.EntityName,
						ovsExternalIDEntityNamespace: externalNode2.Namespace,
						ovsExternalIDIPs:             "10.5.6.8",
					},
				}
				expectedAttachInfo := map[string]interface{}{
					"uplink-name":      intf3.InterfaceName,
					"entity-name":      externalNode2.Name,
					"antrea-type":      "host",
					"entity-namespace": externalNode2.Namespace,
					"ip-address":       "10.5.6.8",
					"uplink-port":      intf3.UplinkPort.PortUUID,
				}
				expectedUpdatedInterface := &interfacestore.InterfaceConfig{
					InterfaceName: intf3.InterfaceName,
					Type:          interfacestore.ExternalEntityInterface,
					OVSPortConfig: intf3.OVSPortConfig,
					EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
						EntityName:      externalNode2.Name,
						EntityNamespace: intf3.EntityNamespace,
						UplinkPort:      intf3.UplinkPort,
					},
					IPs: []net.IP{net.ParseIP("10.5.6.8")},
				}
				mockOVSBridgeClient.EXPECT().GetPortData(intf3.PortUUID, intf3.InterfaceName).Return(returnedPortData, nil).Times(1)
				mockOVSBridgeClient.EXPECT().SetPortExternalIDs(intf3.InterfaceName, expectedAttachInfo).Times(1)
				mockIfaceStore.EXPECT().AddInterface(expectedUpdatedInterface).Times(1)
			},
			existingIfaceMap: map[string]bool{},
		},
		{
			name:            "no change for Interface[0]",
			preIf:           &intf1,
			curIf:           &intf1,
			preExternalNode: &externalNode1,
			curExternalNode: &externalNode1,
			expectedCalls: func(_ *openflowtest.MockClient, _ *ovsconfigtest.MockOVSBridgeClient, _ *interfacestoretest.MockInterfaceStore, _ *ovsctltest.MockOVSCtlClient) {
			},
			existingIfaceMap: map[string]bool{},
		},
		{
			name:                  "different interface name",
			preExternalNode:       &externalNode1,
			curExternalNode:       &externalNode2,
			preIf:                 &intf1,
			curIf:                 &intf2,
			syncedExternalNode:    &externalNode2,
			linkByNameCalledTimes: 1,
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient, mockIfaceStore *interfacestoretest.MockInterfaceStore, mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				mockIfaceStore.EXPECT().GetInterfaceByName(intf2.InterfaceName).Return(&intf2, true)
				returnedPortData := &ovsconfig.OVSPortData{
					ExternalIDs: map[string]string{
						ovsExternalIDUplinkName:      intf2.InterfaceName,
						ovsExternalIDUplinkPort:      intf2.UplinkPort.PortUUID,
						ovsExternalIDEntityName:      intf2.EntityName,
						ovsExternalIDEntityNamespace: externalNode2.Namespace,
						ovsExternalIDIPs:             "10.5.6.8",
					},
				}
				mockOVSBridgeClient.EXPECT().GetPortData(intf2.PortUUID, intf2.InterfaceName).Return(returnedPortData, nil).Times(1)
				expectedAttachInfo := map[string]interface{}{
					"uplink-name":      intf2.InterfaceName,
					"entity-name":      externalNode2.Name,
					"antrea-type":      "host",
					"entity-namespace": externalNode2.Namespace,
					"ip-address":       "10.5.6.8",
					"uplink-port":      intf2.UplinkPort.PortUUID,
				}
				mockOVSBridgeClient.EXPECT().SetPortExternalIDs(intf2.InterfaceName, expectedAttachInfo).Times(1)
				expectedUpdatedInterface := &interfacestore.InterfaceConfig{
					InterfaceName: intf2.InterfaceName,
					Type:          interfacestore.ExternalEntityInterface,
					OVSPortConfig: intf2.OVSPortConfig,
					EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
						EntityName:      externalNode2.GetObjectMeta().GetName(),
						EntityNamespace: intf2.EntityNamespace,
						UplinkPort:      intf2.UplinkPort,
					},
					IPs: []net.IP{net.ParseIP("10.5.6.8")},
				}
				mockIfaceStore.EXPECT().AddInterface(expectedUpdatedInterface).Times(1)
				mockIfaceStore.EXPECT().GetInterfaceByName(intf1.InterfaceName).Return(&intf1, true).Times(1)
				mockOFClient.EXPECT().UninstallVMUplinkFlows(intf1.InterfaceName).Return(nil).Times(1)
				mockOVSBridgeClient.EXPECT().DeletePort(intf1.PortUUID).Return(nil).Times(1)
				mockOVSBridgeClient.EXPECT().DeletePort(intf1.UplinkPort.PortUUID).Return(nil).Times(1)
				mockOVSCtlClient.EXPECT().DeleteDPInterface(intf1.InterfaceName).Times(1)
				mockIfaceStore.EXPECT().DeleteInterface(&intf1).Times(1)
			},
			existingIfaceMap: map[string]bool{
				ifaceName1:                              false,
				ifaceName2:                              false,
				fmt.Sprintf("%s~", intf1.InterfaceName): true,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			defer mockRemoveLinkRoutes(nil)()
			defer mockRemoveLinkIPs(nil)()
			defer mockLinkSetUp(nil)()
			defer mockLinkSetMTU(nil)()
			defer mockRenameInterface(nil)()
			defer mockHostInterfaceExists(tt.existingIfaceMap)()
			defer mockConfigureLinkAddresses(nil)()
			defer mockConfigureLinkRoutes(nil)()
			defer mockLinkByName(t, tt.linkByNameCalledTimes)()

			controller := gomock.NewController(t)
			mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
			mockOFClient := openflowtest.NewMockClient(controller)
			mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(controller)
			mockIfaceStore := interfacestoretest.NewMockInterfaceStore(controller)
			c := newExternalNodeController(t, controller, mockOVSBridgeClient, mockOFClient, mockOVSCtlClient, mockIfaceStore)
			defer mockGetIPNetDeviceFromIP(
				[]mockGetIPNetDeviceFromIPParam{
					{&net.Interface{Name: tt.preIf.InterfaceName}, nil},
					{&net.Interface{Name: tt.curIf.InterfaceName}, nil},
				})()
			tt.expectedCalls(mockOFClient, mockOVSBridgeClient, mockIfaceStore, mockOVSCtlClient)
			err := c.updateExternalNode(tt.preExternalNode, tt.curExternalNode)
			assert.NoError(t, err)
			assert.Equal(t, tt.syncedExternalNode, c.syncedExternalNode)
		})
	}
}

func TestAddInterface(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("172.16.1.0/24")
	for _, tt := range []struct {
		name                    string
		iface                   *interfacestore.InterfaceConfig
		ips                     []string
		preIPs                  []string
		preEEName               string
		ifaceExist              bool
		linkByNameCalledTimes   int
		getInterfaceConfigParam mockGetInterfaceConfigParam
		expectedCalls           func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient, mockIfaceStore *interfacestoretest.MockInterfaceStore, mockOVSCtlClient *ovsctltest.MockOVSCtlClient)
	}{
		{
			name:       "update already existed interface successfully",
			iface:      &intf1,
			ifaceExist: true,
			ips:        []string{"10.20.30.40"},
			preIPs:     []string{"10.20.30.50"},
			preEEName:  "externalEntity",
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient, mockIfaceStore *interfacestoretest.MockInterfaceStore, mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				expectedAttachInfo := map[string]interface{}{
					"uplink-name":      intf1.InterfaceName,
					"entity-name":      eeName,
					"antrea-type":      "host",
					"entity-namespace": eeNamespace,
					"ip-address":       "10.20.30.40",
					"uplink-port":      intf1.UplinkPort.PortUUID,
				}
				returnedPortData := &ovsconfig.OVSPortData{
					ExternalIDs: map[string]string{
						ovsExternalIDUplinkName:      intf1.InterfaceName,
						ovsExternalIDUplinkPort:      intf1.UplinkPort.PortUUID,
						ovsExternalIDEntityName:      intf1.EntityName,
						ovsExternalIDEntityNamespace: eeNamespace,
						ovsExternalIDIPs:             "10.20.30.40",
					},
				}
				expectedAddInterface := &interfacestore.InterfaceConfig{
					InterfaceName: intf1.InterfaceName,
					Type:          interfacestore.ExternalEntityInterface,
					IPs:           []net.IP{net.ParseIP("10.20.30.40")},
					OVSPortConfig: intf1.OVSPortConfig,
					EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
						EntityName:      eeName,
						EntityNamespace: intf1.EntityNamespace,
						UplinkPort:      intf1.UplinkPort,
					},
				}
				mockIfaceStore.EXPECT().AddInterface(expectedAddInterface).Times(1)
				mockOVSBridgeClient.EXPECT().GetPortData(intf1.PortUUID, intf1.InterfaceName).Return(returnedPortData, nil).Times(1)
				mockOVSBridgeClient.EXPECT().SetPortExternalIDs(intf1.InterfaceName, expectedAttachInfo).Times(1)
			},
		},
		{
			name:       "skip adding interface",
			iface:      &intf1,
			ifaceExist: true,
			ips:        []string{"10.20.30.40"},
			preIPs:     []string{"10.20.30.40"},
			preEEName:  eeName,
			expectedCalls: func(_ *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient, _ *interfacestoretest.MockInterfaceStore, _ *ovsctltest.MockOVSCtlClient) {
				returnedPortData := &ovsconfig.OVSPortData{
					ExternalIDs: map[string]string{
						ovsExternalIDUplinkName:      intf1.InterfaceName,
						ovsExternalIDUplinkPort:      intf1.UplinkPort.PortUUID,
						ovsExternalIDEntityName:      eeName,
						ovsExternalIDEntityNamespace: intf1.EntityNamespace,
						ovsExternalIDIPs:             "10.20.30.40",
					},
				}
				mockOVSBridgeClient.EXPECT().GetPortData(intf1.PortUUID, intf1.InterfaceName).Return(returnedPortData, nil).Times(1)
			},
		},
		{
			name:       "add new interface",
			iface:      &intf1,
			ifaceExist: false,
			ips:        []string{"10.20.30.40"},
			preIPs:     []string{"10.20.30.40"},
			preEEName:  "externalEntity",
			getInterfaceConfigParam: mockGetInterfaceConfigParam{
				&net.Interface{
					Index:        1,
					HardwareAddr: net.HardwareAddr{0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
					MTU:          1500,
				},
				[]*net.IPNet{cidr},
				nil,
			},
			linkByNameCalledTimes: 2,
			expectedCalls: func(mockOFClient *openflowtest.MockClient, mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient, mockIfaceStore *interfacestoretest.MockInterfaceStore, mockOVSCtlClient *ovsctltest.MockOVSCtlClient) {
				uplinkName := intf1.InterfaceName + "~"
				mockOVSBridgeClient.EXPECT().CreatePort(
					uplinkName,
					uplinkName,
					map[string]interface{}{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUplink},
				).Return(intf1.UplinkPort.PortUUID, nil).Times(1)
				expectedAttachInfo := map[string]interface{}{
					"uplink-name":      intf1.InterfaceName + "~",
					"entity-name":      eeName,
					"antrea-type":      "host",
					"entity-namespace": eeNamespace,
					"ip-address":       "10.20.30.40",
					"uplink-port":      intf1.UplinkPort.PortUUID,
				}
				expectedAddInterface := &interfacestore.InterfaceConfig{
					InterfaceName: intf1.InterfaceName,
					Type:          interfacestore.ExternalEntityInterface,
					IPs:           []net.IP{net.ParseIP("10.20.30.40")},
					OVSPortConfig: intf1.OVSPortConfig,
					EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
						EntityName:      eeName,
						EntityNamespace: eeNamespace,
						UplinkPort:      intf1.UplinkPort,
					},
				}
				mockOVSBridgeClient.EXPECT().CreateInternalPort(intf1.InterfaceName, int32(0), net.HardwareAddr{0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}.String(), expectedAttachInfo).Return(intf1.PortUUID, nil)
				mockOVSBridgeClient.EXPECT().GetOFPort(intf1.InterfaceName, false).Times(1).Return(intf1.OFPort, nil)
				mockOVSBridgeClient.EXPECT().GetOFPort(uplinkName, false).Times(1).Return(intf1.UplinkPort.OFPort, nil)
				mockOFClient.EXPECT().InstallVMUplinkFlows(intf1.InterfaceName, intf1.OFPort, intf1.UplinkPort.OFPort).Times(1)
				mockIfaceStore.EXPECT().AddInterface(expectedAddInterface).Times(1)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			defer mockGetInterfaceConfig([]mockGetInterfaceConfigParam{tt.getInterfaceConfigParam})()
			defer mockConfigureLinkRoutes(nil)()
			defer mockConfigureLinkAddresses(nil)()
			defer mockRemoveLinkRoutes(nil)()
			defer mockRenameInterface(nil)()
			defer mockRemoveLinkIPs(nil)()
			defer mockLinkSetUp(nil)()
			defer mockLinkSetMTU(nil)()
			defer mockLinkByName(t, tt.linkByNameCalledTimes)()

			controller := gomock.NewController(t)
			mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
			mockOFClient := openflowtest.NewMockClient(controller)
			mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(controller)
			mockIfaceStore := interfacestoretest.NewMockInterfaceStore(controller)
			c := newExternalNodeController(t, controller, mockOVSBridgeClient, mockOFClient, mockOVSCtlClient, mockIfaceStore)
			mockIfaceStore.EXPECT().GetInterfaceByName(tt.iface.InterfaceName).Return(tt.iface, tt.ifaceExist).Times(1)
			tt.expectedCalls(mockOFClient, mockOVSBridgeClient, mockIfaceStore, mockOVSCtlClient)
			c.addInterface(tt.iface.InterfaceName, eeNamespace, eeName, tt.ips)
		})
	}
}

func TestCreateOVSPortsAndFlowsSuccess(t *testing.T) {
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
	ipAddrs := []string{"10.20.30.40"}
	expectedInfo := map[string]interface{}{
		"uplink-name":      uplinkName,
		"entity-name":      entityName,
		"antrea-type":      "host",
		"entity-namespace": entityNamespace,
		"ip-address":       "10.20.30.40",
		"uplink-port":      uplinkUUID,
	}
	defer mockRenameInterface(nil)()
	defer mockGetInterfaceConfig([]mockGetInterfaceConfigParam{{iface, []*net.IPNet{cidr1}, nil}})()
	defer mockConfigureLinkRoutes(nil)()
	defer mockConfigureLinkAddresses(nil)()
	defer mockRemoveLinkRoutes(nil)()
	defer mockRemoveLinkIPs(nil)()
	defer mockLinkSetUp(nil)()
	defer mockLinkSetMTU(nil)()
	defer mockLinkByName(t, 2)()

	mockOVSBridgeClient.EXPECT().CreatePort(uplinkName, uplinkName, map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUplink,
	}).Return(uplinkUUID, nil)
	mockOVSBridgeClient.EXPECT().CreateInternalPort(hostIfName, int32(0), "22:33:44:55:66:77:88", expectedInfo).Return(hostIfUUID, nil)
	mockOVSBridgeClient.EXPECT().GetOFPort(uplinkName, false).Times(1).Return(uplinkOFPort, nil)
	mockOVSBridgeClient.EXPECT().GetOFPort(hostIfName, false).Times(1).Return(hostOFPort, nil)
	mockOFClient.EXPECT().InstallVMUplinkFlows(hostIfName, hostOFPort, uplinkOFPort).Times(1)

	ips := make([]net.IP, 0, len(ipAddrs))
	for _, ip := range ipAddrs {
		ips = append(ips, net.ParseIP(ip))
	}
	hostIFConfig, err := c.createOVSPortsAndFlows(uplinkName, hostIfName, entityNamespace, entityName, ipAddrs)
	expectedHostIFConfig := &interfacestore.InterfaceConfig{
		Type:          interfacestore.ExternalEntityInterface,
		InterfaceName: hostIfName,
		IPs:           ips,
		OVSPortConfig: &interfacestore.OVSPortConfig{
			PortUUID: hostIfUUID,
			OFPort:   hostOFPort,
		},
		EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
			EntityName:      entityName,
			EntityNamespace: entityNamespace,
			UplinkPort: &interfacestore.OVSPortConfig{
				PortUUID: uplinkUUID,
				OFPort:   uplinkOFPort,
			},
		},
	}
	assert.NoError(t, err)
	assert.Equal(t, expectedHostIFConfig, hostIFConfig)
}

func TestDeleteExternalNode(t *testing.T) {
	controller := gomock.NewController(t)
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
	mockOFClient := openflowtest.NewMockClient(controller)
	mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(controller)
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(controller)
	c := newExternalNodeController(t, controller, mockOVSBridgeClient, mockOFClient, mockOVSCtlClient, mockIfaceStore)
	iface1 := &net.Interface{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		MTU:          1500,
	}
	iface2 := &net.Interface{
		Index:        2,
		HardwareAddr: net.HardwareAddr{0x33, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		MTU:          1500,
	}
	defer mockGetInterfaceConfig([]mockGetInterfaceConfigParam{
		{iface1, []*net.IPNet{cidr1}, nil},
		{iface2, []*net.IPNet{cidr2}, nil},
	})()
	defer mockLinkByName(t, 2)()
	defer mockRenameInterface(nil)()
	defer mockHostInterfaceExists(map[string]bool{
		fmt.Sprintf("%s~", intf1.InterfaceName): true,
		fmt.Sprintf("%s~", intf2.InterfaceName): true,
	})()
	defer mockConfigureLinkAddresses(nil)()
	defer mockConfigureLinkRoutes(nil)()
	mockIfaceStore.EXPECT().GetInterfacesByType(interfacestore.ExternalEntityInterface).Return([]*interfacestore.InterfaceConfig{
		&intf1,
		&intf2,
	})
	mockOFClient.EXPECT().UninstallVMUplinkFlows(intf1.InterfaceName).Return(nil).Times(1)
	mockOVSBridgeClient.EXPECT().DeletePort(intf1.PortUUID).Return(nil).Times(1)
	mockOVSBridgeClient.EXPECT().DeletePort(intf1.UplinkPort.PortUUID).Return(nil).Times(1)
	mockOVSCtlClient.EXPECT().DeleteDPInterface(intf1.InterfaceName).Times(1)
	mockIfaceStore.EXPECT().DeleteInterface(&intf1).Times(1)
	mockOFClient.EXPECT().UninstallVMUplinkFlows(intf2.InterfaceName).Return(nil).Times(1)
	mockOVSBridgeClient.EXPECT().DeletePort(intf2.PortUUID).Return(nil).Times(1)
	mockOVSBridgeClient.EXPECT().DeletePort(intf2.UplinkPort.PortUUID).Return(nil).Times(1)
	mockOVSCtlClient.EXPECT().DeleteDPInterface(intf2.InterfaceName).Times(1)
	mockIfaceStore.EXPECT().DeleteInterface(&intf2).Times(1)
	c.deleteExternalNode()
	assert.Nil(t, c.syncedExternalNode)
}

func TestMoveIFConfigurations(t *testing.T) {
	controller := gomock.NewController(t)
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
	mockOFClient := openflowtest.NewMockClient(controller)
	mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(controller)
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(controller)
	c := newExternalNodeController(t, controller, mockOVSBridgeClient, mockOFClient, mockOVSCtlClient, mockIfaceStore)
	linkSetMTUError := fmt.Errorf("link set MTU error")
	linkSetUpError := fmt.Errorf("link setup error")
	removeLinkIPsError := fmt.Errorf("remove link IP error")
	removeLinkRoutesError := fmt.Errorf("remove link routes error")
	for _, tt := range []struct {
		name                  string
		linkSetMTUError       error
		linkSetUpError        error
		removeLinkIPsError    error
		removeLinkRoutesError error
		expectedError         error
	}{
		{
			name:            "link set MTU error",
			linkSetMTUError: linkSetMTUError,
			expectedError:   linkSetMTUError,
		},
		{
			name:           "link setup error",
			linkSetUpError: linkSetUpError,
			expectedError:  linkSetUpError,
		},
		{
			name:               "remove link IP error",
			removeLinkIPsError: removeLinkIPsError,
			expectedError:      removeLinkIPsError,
		},
		{
			name:                  "remove link routes error",
			removeLinkRoutesError: removeLinkRoutesError,
			expectedError:         removeLinkRoutesError,
		},
		{
			name:          "move interface configurations successfully",
			expectedError: nil,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			defer mockLinkByName(t, 2)()
			defer mockLinkSetMTU(tt.linkSetMTUError)()
			defer mockLinkSetUp(tt.linkSetUpError)()
			defer mockRemoveLinkIPs(tt.removeLinkIPsError)()
			defer mockRemoveLinkRoutes(tt.removeLinkRoutesError)()
			defer mockConfigureLinkAddresses(nil)()
			defer mockConfigureLinkRoutes(nil)()
			err := c.moveIFConfigurations(&config.AdapterNetConfig{MTU: 1500}, "intf1", "intf2")
			assert.Equal(t, tt.expectedError, err)
		})
	}
}

func mockConfigureLinkRoutes(configureLinkRoutesErr error) func() {
	originalConfigureLinkRoutes := configureLinkRoutes
	configureLinkRoutes = func(link netlink.Link, routes []interface{}) error {
		return configureLinkRoutesErr
	}
	return func() {
		configureLinkRoutes = originalConfigureLinkRoutes
	}
}

func mockConfigureLinkAddresses(configureLinkAddressesErr error) func() {
	originalRemoveLinkRoutes := configureLinkAddresses
	configureLinkAddresses = func(idx int, ipNets []*net.IPNet) error {
		return configureLinkAddressesErr
	}
	return func() {
		configureLinkAddresses = originalRemoveLinkRoutes
	}
}

func mockRemoveLinkRoutes(removeLinkRoutesErr error) func() {
	originalRemoveLinkRoutes := removeLinkRoutes
	removeLinkRoutes = func(link netlink.Link) error {
		return removeLinkRoutesErr
	}
	return func() {
		removeLinkRoutes = originalRemoveLinkRoutes
	}
}

func mockRemoveLinkIPs(removeLinkIPsErr error) func() {
	originalRemoveLinkIPs := removeLinkIPs
	removeLinkIPs = func(link netlink.Link) error {
		return removeLinkIPsErr
	}
	return func() {
		removeLinkIPs = originalRemoveLinkIPs
	}
}

func mockLinkSetUp(linkSetUpErr error) func() {
	originalLinkSetUp := linkSetUp
	linkSetUp = func(link netlink.Link) error {
		return linkSetUpErr
	}
	return func() {
		linkSetUp = originalLinkSetUp
	}
}

func mockLinkSetMTU(linkSetMTUErr error) func() {
	originalLinkSetMTU := linkSetMTU
	linkSetMTU = func(link netlink.Link, mtu int) error {
		return linkSetMTUErr
	}
	return func() {
		linkSetMTU = originalLinkSetMTU
	}
}

func mockLinkByName(t *testing.T, calledTimes int) func() {
	originalLinkByName := linkByName
	counter := 0
	linkByName = func(_ string) (netlink.Link, error) {
		counter++
		return &netlink.Dummy{}, nil
	}
	return func() {
		linkByName = originalLinkByName
		if counter != calledTimes {
			t.Errorf("mockLinkByName should be called %d times, but was actually called %d times", calledTimes, counter)
		}
	}
}

func mockHostInterfaceExists(existingIfaces map[string]bool) func() {
	originalHostInterfaceExists := hostInterfaceExists
	hostInterfaceExists = func(ifName string) bool {
		exists, ok := existingIfaces[ifName]
		if ok {
			return exists
		}
		return false
	}
	return func() {
		hostInterfaceExists = originalHostInterfaceExists
	}
}
