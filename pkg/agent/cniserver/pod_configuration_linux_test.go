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

package cniserver

import (
	"fmt"
	"net"
	"testing"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	ipamtest "antrea.io/antrea/pkg/agent/cniserver/ipam/testing"
	"antrea.io/antrea/pkg/agent/interfacestore"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	routetest "antrea.io/antrea/pkg/agent/route/testing"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	"antrea.io/antrea/pkg/util/channel"
)

var (
	containerMAC = "01:02:03:04:05:06"
	hostIfaceMAC = "06:05:04:03:02:01"
	containerIP  = net.ParseIP("10.1.2.100")
)

type fakeInterfaceConfigurator struct {
	configureContainerLinkError         error
	removeContainerLinkError            error
	advertiseContainerAddrError         error
	ovsInterfaceTypeMapping             map[string]int
	validateVFRepInterfaceError         error
	validateContainerPeerInterfaceError error
	containerVethPair                   *vethPair
	containerMAC                        string
	hostIfaceMAC                        string
	hostIfaceName                       string
	getInterceptedInterfacesError       error
	checkContainerInterfaceError        error
	containerVFLink                     interface{}
}

func (c *fakeInterfaceConfigurator) configureContainerLink(podName string, podNamespace string, containerID string, containerNetNS string, containerIfaceName string, mtu int, brSriovVFDeviceID string, podSriovVFDeviceID string, result *current.Result, containerAccess *containerAccessArbitrator) error {
	if c.configureContainerLinkError != nil {
		return c.configureContainerLinkError
	}
	hostIface := &current.Interface{}
	containerIface := &current.Interface{Name: containerIfaceName, Sandbox: containerNetNS}
	if podSriovVFDeviceID != "" {
		hostIface.Name = containerIfaceName
	} else {
		hostIface.Name = c.hostIfaceName
		hostIface.Mac = hostIfaceMAC
		containerIface.Mac = containerMAC
	}
	result.Interfaces = []*current.Interface{hostIface, containerIface}
	return nil
}

func (c *fakeInterfaceConfigurator) removeContainerLink(containerID, hostInterfaceName string) error {
	if c.removeContainerLinkError != nil {
		return c.removeContainerLinkError
	}
	c.hostIfaceName = ""
	return nil
}

func (c *fakeInterfaceConfigurator) advertiseContainerAddr(containerNetNS string, containerIfaceName string, result *current.Result) error {
	return c.advertiseContainerAddrError
}

func (c *fakeInterfaceConfigurator) validateVFRepInterface(sriovVFDeviceID string) (string, error) {
	return c.hostIfaceName, c.validateVFRepInterfaceError
}

func (c *fakeInterfaceConfigurator) validateContainerPeerInterface(interfaces []*current.Interface, containerVeth *vethPair) (*vethPair, error) {
	return containerVeth, c.validateContainerPeerInterfaceError
}

func (c *fakeInterfaceConfigurator) getInterceptedInterfaces(sandbox string, containerNetNS string, containerIFDev string) (*current.Interface, *current.Interface, error) {
	containerIface := &current.Interface{
		Name:    containerIFDev,
		Sandbox: sandbox,
		Mac:     c.containerMAC,
	}
	hostIface := &current.Interface{
		Name: c.hostIfaceName,
		Mac:  c.hostIfaceMAC,
	}
	return containerIface, hostIface, c.getInterceptedInterfacesError
}

func (c *fakeInterfaceConfigurator) addPostInterfaceCreateHook(containerID, endpointName string, containerAccess *containerAccessArbitrator, hook postInterfaceCreateHook) error {
	return nil
}

func (c *fakeInterfaceConfigurator) checkContainerInterface(containerNetns, containerID string, containerIface *current.Interface, containerIPs []*current.IPConfig, containerRoutes []*cnitypes.Route, sriovVFDeviceID string) (interface{}, error) {
	if c.checkContainerInterfaceError != nil {
		return nil, c.checkContainerInterfaceError
	}
	if sriovVFDeviceID != "" {
		return c.containerVFLink, nil
	}
	return c.containerVethPair, nil
}

func (c *fakeInterfaceConfigurator) changeContainerMTU(containerNetNS string, containerIFDev string, mtuDeduction int) error {
	return nil
}

func newTestInterfaceConfigurator() *fakeInterfaceConfigurator {
	return &fakeInterfaceConfigurator{
		containerMAC: "01:02:03:04:05:06",
		hostIfaceMAC: hostIfaceMAC,
	}
}

func TestConnectInterceptedInterface(t *testing.T) {
	controller := gomock.NewController(t)
	testPodName := "test-pod"
	podNamespace := testPodNamespace
	hostInterfaceName := util.GenerateContainerInterfaceName(testPodName, testPodNamespace, testPodInfraContainerID)
	containerID := generateUUID()
	containerNetNS := "container-ns"
	containerDev := "eth0"

	createIfaceConfigurator := func(getInterceptedInterfacesError error) *fakeInterfaceConfigurator {
		testIfaceConfigurator := newTestInterfaceConfigurator()
		testIfaceConfigurator.hostIfaceName = hostInterfaceName
		if getInterceptedInterfacesError != nil {
			testIfaceConfigurator.getInterceptedInterfacesError = getInterceptedInterfacesError
		}
		return testIfaceConfigurator
	}
	for _, tc := range []struct {
		name              string
		getInterfaceErr   error
		getNSPathErr      error
		migratedRoute     bool
		migrateRouteErr   error
		connectedOVS      bool
		createOVSPortErr  error
		getOFPortErr      error
		installPodFlowErr error
		expectedErr       bool
	}{
		{
			name:         "error-get-net-ns",
			getNSPathErr: fmt.Errorf("failed to open netns"),
			expectedErr:  true,
		},
		{
			name:            "error-get-intercepted-interfaces",
			getInterfaceErr: fmt.Errorf("unable to get intercepted interfaces"),
			expectedErr:     true,
		},
		{
			name:            "error-migrate-route",
			migratedRoute:   true,
			migrateRouteErr: fmt.Errorf("unable to get host interface"),
			expectedErr:     true,
		},
		{
			name:             "error-ovs-create-port",
			migratedRoute:    true,
			connectedOVS:     true,
			createOVSPortErr: ovsconfig.NewTransactionError(fmt.Errorf("unable to create OVS port"), true),
			expectedErr:      true,
		},
		{
			name:          "error-ovs-get-ofport",
			migratedRoute: true,
			connectedOVS:  true,
			getOFPortErr:  ovsconfig.NewTransactionError(fmt.Errorf("timeout to get OpenFlow port"), true),
			expectedErr:   true,
		},
		{
			name:              "error-ovs-install-flows",
			migratedRoute:     true,
			connectedOVS:      true,
			installPodFlowErr: fmt.Errorf("failed to install Pod OpenFlow"),
			expectedErr:       true,
		},
		{
			name:          "success",
			migratedRoute: true,
			connectedOVS:  true,
			expectedErr:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer mockGetNSPath(tc.getNSPathErr)()
			pc := createPodConfigurator(controller, createIfaceConfigurator(tc.getInterfaceErr))
			if tc.migratedRoute {
				mockRoute.EXPECT().MigrateRoutesToGw(hostInterfaceName).Return(tc.migrateRouteErr)
			}
			ovsPortID := generateUUID()
			if tc.connectedOVS {
				mockOVSBridgeClient.EXPECT().CreatePort(hostInterfaceName, gomock.Any(), gomock.Any()).Return(ovsPortID, tc.createOVSPortErr).Times(1)
				if tc.createOVSPortErr == nil {
					mockOVSBridgeClient.EXPECT().GetOFPort(hostInterfaceName, false).Return(int32(100), tc.getOFPortErr).Times(1)
					if tc.getOFPortErr == nil {
						mockOFClient.EXPECT().InstallPodFlows(hostInterfaceName, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(tc.installPodFlowErr).Times(1)
					}
					if tc.getOFPortErr != nil || tc.installPodFlowErr != nil {
						mockOVSBridgeClient.EXPECT().DeletePort(ovsPortID).Times(1)
					}
				}
			}
			err := pc.connectInterceptedInterface(podName, podNamespace, containerID, containerNetNS, containerDev, ipamResult.IPs, nil)
			if tc.expectedErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				containerConfig, exists := ifaceStore.GetContainerInterface(containerID)
				assert.True(t, exists)
				assert.Equal(t, containerID, containerConfig.ContainerID)
				assert.Equal(t, ovsPortID, containerConfig.OVSPortConfig.PortUUID)
			}
		})
	}
}

func TestCreateOVSPort(t *testing.T) {
	controller := gomock.NewController(t)
	containerID := generateUUID()
	podName := "p0"
	podNamespace := testPodNamespace

	for _, tc := range []struct {
		name                string
		portName            string
		portType            int
		vlanID              uint16
		createOVSPort       bool
		createOVSAccessPort bool
	}{
		{
			name:          "create-general-port",
			portName:      "p1",
			portType:      defaultOVSInterfaceType,
			vlanID:        0,
			createOVSPort: true,
		}, {
			name:                "create-access-port",
			portName:            "p3",
			portType:            defaultOVSInterfaceType,
			vlanID:              10,
			createOVSAccessPort: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testIfaceConfigurator := &fakeInterfaceConfigurator{ovsInterfaceTypeMapping: map[string]int{tc.portName: tc.portType}}
			podConfigurator := createPodConfigurator(controller, testIfaceConfigurator)
			containerConfig := buildContainerConfig(tc.portName, containerID, podName, podNamespace, &current.Interface{Mac: "01:02:03:04:05:06"}, ipamResult.IPs, tc.vlanID)
			attachInfo := BuildOVSPortExternalIDs(containerConfig)
			if tc.createOVSPort {
				mockOVSBridgeClient.EXPECT().CreatePort(tc.portName, tc.portName, attachInfo).Times(1).Return(generateUUID(), nil)
			}
			if tc.createOVSAccessPort {
				mockOVSBridgeClient.EXPECT().CreateAccessPort(tc.portName, tc.portName, attachInfo, tc.vlanID).Times(1).Return(generateUUID(), nil)
			}
			_, err := podConfigurator.createOVSPort(tc.portName, attachInfo, tc.vlanID)
			assert.NoError(t, err)
		})
	}
}

func TestParseOVSPortInterfaceConfig(t *testing.T) {
	containerID := generateUUID()
	portUUID := generateUUID()
	ofPort := int32(1)
	containerIPs := "1.1.1.2,aabb:1122::101:102"
	parsedIPs := []net.IP{net.ParseIP("1.1.1.2"), net.ParseIP("aabb:1122::101:102")}
	containerMACStr := "11:22:33:44:55:66"
	containerMAC, _ := net.ParseMAC(containerMACStr)
	podName := "pod0"
	portName := "p0"
	for _, tc := range []struct {
		name        string
		portData    *ovsconfig.OVSPortData
		portConfig  *interfacestore.OVSPortConfig
		ifaceConfig *interfacestore.InterfaceConfig
	}{
		{
			name: "no-externalIDs",
			portData: &ovsconfig.OVSPortData{
				Name: portName,
			},
			portConfig: &interfacestore.OVSPortConfig{
				PortUUID: portUUID,
				OFPort:   ofPort,
			},
		},
		{
			name: "no-containerID",
			portData: &ovsconfig.OVSPortData{
				Name: portName,
				ExternalIDs: map[string]string{
					ovsExternalIDIP:           containerIPs,
					ovsExternalIDMAC:          containerMACStr,
					ovsExternalIDPodName:      podName,
					ovsExternalIDPodNamespace: testPodNamespace,
				},
			},
			portConfig: &interfacestore.OVSPortConfig{
				PortUUID: portUUID,
				OFPort:   ofPort,
			},
		},
		{
			name: "invalid-MAC",
			portData: &ovsconfig.OVSPortData{
				Name: portName,
				ExternalIDs: map[string]string{
					ovsExternalIDContainerID:  containerID,
					ovsExternalIDIP:           containerIPs,
					ovsExternalIDMAC:          "1:2:3:4:5:6",
					ovsExternalIDPodName:      podName,
					ovsExternalIDPodNamespace: testPodNamespace,
				},
			},
			portConfig: &interfacestore.OVSPortConfig{
				PortUUID: portUUID,
				OFPort:   ofPort,
			},
			ifaceConfig: &interfacestore.InterfaceConfig{
				Type:          interfacestore.ContainerInterface,
				InterfaceName: portName,
				IPs:           parsedIPs,
				OVSPortConfig: &interfacestore.OVSPortConfig{
					PortUUID: portUUID,
					OFPort:   ofPort,
				},
				ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
					ContainerID:  containerID,
					PodName:      podName,
					PodNamespace: testPodNamespace,
				},
			},
		},
		{
			name: "valid-configuration",
			portData: &ovsconfig.OVSPortData{
				Name: portName,
				ExternalIDs: map[string]string{
					ovsExternalIDContainerID:  containerID,
					ovsExternalIDIP:           containerIPs,
					ovsExternalIDMAC:          containerMACStr,
					ovsExternalIDPodName:      podName,
					ovsExternalIDPodNamespace: testPodNamespace,
				},
			},
			portConfig: &interfacestore.OVSPortConfig{
				PortUUID: portUUID,
				OFPort:   ofPort,
			},
			ifaceConfig: &interfacestore.InterfaceConfig{
				Type:          interfacestore.ContainerInterface,
				InterfaceName: portName,
				IPs:           parsedIPs,
				MAC:           containerMAC,
				OVSPortConfig: &interfacestore.OVSPortConfig{
					PortUUID: portUUID,
					OFPort:   ofPort,
				},
				ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
					ContainerID:  containerID,
					PodName:      podName,
					PodNamespace: testPodNamespace,
				},
			},
		},
		{
			name: "secondary",
			portData: &ovsconfig.OVSPortData{
				Name: portName,
				ExternalIDs: map[string]string{
					ovsExternalIDContainerID:  containerID,
					ovsExternalIDIP:           containerIPs,
					ovsExternalIDMAC:          containerMACStr,
					ovsExternalIDPodName:      podName,
					ovsExternalIDPodNamespace: testPodNamespace,
					ovsExternalIDIFDev:        "eth1",
				},
			},
			portConfig: &interfacestore.OVSPortConfig{
				PortUUID: portUUID,
				OFPort:   ofPort,
			},
			ifaceConfig: &interfacestore.InterfaceConfig{
				Type:          interfacestore.ContainerInterface,
				InterfaceName: portName,
				IPs:           parsedIPs,
				MAC:           containerMAC,
				OVSPortConfig: &interfacestore.OVSPortConfig{
					PortUUID: portUUID,
					OFPort:   ofPort,
				},
				ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
					ContainerID:  containerID,
					PodName:      podName,
					PodNamespace: testPodNamespace,
					IFDev:        "eth1",
				},
			},
		},
		{
			name: "secondary-no-ip",
			portData: &ovsconfig.OVSPortData{
				Name: portName,
				ExternalIDs: map[string]string{
					ovsExternalIDContainerID:  containerID,
					ovsExternalIDIP:           "",
					ovsExternalIDMAC:          containerMACStr,
					ovsExternalIDPodName:      podName,
					ovsExternalIDPodNamespace: testPodNamespace,
					ovsExternalIDIFDev:        "eth1",
				},
			},
			portConfig: &interfacestore.OVSPortConfig{
				PortUUID: portUUID,
				OFPort:   ofPort,
			},
			ifaceConfig: &interfacestore.InterfaceConfig{
				Type:          interfacestore.ContainerInterface,
				InterfaceName: portName,
				MAC:           containerMAC,
				OVSPortConfig: &interfacestore.OVSPortConfig{
					PortUUID: portUUID,
					OFPort:   ofPort,
				},
				ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
					ContainerID:  containerID,
					PodName:      podName,
					PodNamespace: testPodNamespace,
					IFDev:        "eth1",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iface := ParseOVSPortInterfaceConfig(tc.portData, tc.portConfig)
			assert.Equal(t, tc.ifaceConfig, iface)
		})
	}
}

func TestCheckHostInterface(t *testing.T) {
	controller := gomock.NewController(t)
	hostIfaceName := "port1"
	containerID := generateUUID()
	containerIntf := &current.Interface{Name: ifname, Sandbox: netns, Mac: "01:02:03:04:05:06"}
	interfaces := []*current.Interface{containerIntf, {Name: hostIfaceName}}
	containeIPs := ipamResult.IPs
	ifaceMAC, _ := net.ParseMAC("01:02:03:04:05:06")
	containerInterface := interfacestore.NewContainerInterface(hostIfaceName, containerID,
		"pod1", testPodNamespace, "eth0", ifaceMAC, []net.IP{containerIP}, 1)
	containerInterface.OVSPortConfig = &interfacestore.OVSPortConfig{
		PortUUID: generateUUID(),
		OFPort:   int32(10),
	}

	for _, tc := range []struct {
		name             string
		vfRepIfaceError  error
		containerPeerErr error
		containerIfKind  interface{}
		sriovVFDeviceID  string
		expectedErr      error
	}{
		{
			name:            "vf-validation-failure",
			vfRepIfaceError: fmt.Errorf("fail to validate VF representor"),
			sriovVFDeviceID: "vf1",
			expectedErr:     fmt.Errorf("fail to validate VF representor"),
		}, {
			name:            "vf-validation-success",
			sriovVFDeviceID: "vf1",
		}, {
			name:             "vethpair-validation-failure",
			containerPeerErr: fmt.Errorf("fail to validate container peer"),
			containerIfKind:  &vethPair{name: hostIfaceName, ifIndex: 10, peerIndex: 20},
			expectedErr:      fmt.Errorf("fail to validate container peer"),
		}, {
			name:            "vethpair-validation-success",
			containerIfKind: &vethPair{name: hostIfaceName, ifIndex: 10, peerIndex: 20},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeIfaceConfigrator := newTestInterfaceConfigurator()
			fakeIfaceConfigrator.hostIfaceName = hostIfaceName
			fakeIfaceConfigrator.validateVFRepInterfaceError = tc.vfRepIfaceError
			fakeIfaceConfigrator.validateContainerPeerInterfaceError = tc.containerPeerErr
			configurator := createPodConfigurator(controller, fakeIfaceConfigrator)
			configurator.ifaceStore.AddInterface(containerInterface)
			err := configurator.checkHostInterface(containerID, containerIntf, tc.containerIfKind, containeIPs, interfaces, tc.sriovVFDeviceID)
			if tc.expectedErr != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigureSriovSecondaryInterface(t *testing.T) {
	containerID := generateUUID()
	containerNS := "containerNS"

	for _, tc := range []struct {
		name               string
		podSriovVFDeviceID string
		configureLinkErr   error
		advertiseErr       error
		expectedErr        error
		intfConfig         *interfacestore.InterfaceConfig
	}{
		{
			name:        "sriov-vf-not-set",
			expectedErr: fmt.Errorf("error getting the Pod SR-IOV VF device ID"),
		}, {
			name:               "configure-link-failure",
			podSriovVFDeviceID: "vf1",
			configureLinkErr:   fmt.Errorf("unable to create sriov VF link"),
			expectedErr:        fmt.Errorf("unable to create sriov VF link"),
		}, {
			name:               "advertise-failure",
			podSriovVFDeviceID: "vf2",
			advertiseErr:       fmt.Errorf("unable to advertise on the sriov link"),
			// When advertiseContainerAddr returns an error, it is logged, but does not
			// cause ConfigureSriovSecondaryInterface to also return an error.
			intfConfig: &interfacestore.InterfaceConfig{
				Type:          interfacestore.ContainerInterface,
				InterfaceName: "vf2",
				ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
					ContainerID:  containerID,
					PodName:      podName,
					PodNamespace: testPodNamespace,
					IFDev:        "eth0",
				},
			},
		}, {
			name:               "success",
			podSriovVFDeviceID: "vf3",
			intfConfig: &interfacestore.InterfaceConfig{
				Type:          interfacestore.ContainerInterface,
				InterfaceName: "vf3",
				ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
					ContainerID:  containerID,
					PodName:      podName,
					PodNamespace: testPodNamespace,
					IFDev:        "eth0",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ifaceConfigurator := newTestInterfaceConfigurator()
			ifaceConfigurator.configureContainerLinkError = tc.configureLinkErr
			ifaceConfigurator.advertiseContainerAddrError = tc.advertiseErr
			podConfigurator, _ := NewSecondaryInterfaceConfigurator(nil, interfacestore.NewInterfaceStore())
			podConfigurator.ifConfigurator = ifaceConfigurator
			err := podConfigurator.ConfigureSriovSecondaryInterface(podName, testPodNamespace, containerID, containerNS, containerIfaceName, mtu, tc.podSriovVFDeviceID, &current.Result{})
			assert.Equal(t, tc.expectedErr, err)
			if tc.expectedErr != nil {
				assert.Equal(t, 0, podConfigurator.ifaceStore.Len())
				return
			}

			assert.Equal(t, 1, podConfigurator.ifaceStore.Len())
			intfConfig, _ := podConfigurator.ifaceStore.GetContainerInterface(containerID)
			assert.Equal(t, tc.intfConfig, intfConfig)
			assert.NoError(t, podConfigurator.DeleteSriovSecondaryInterface(intfConfig))
			assert.Equal(t, 0, podConfigurator.ifaceStore.Len())
		})
	}
}

func newTestContainerInterfaceConfig(podName, containerID, ifDev string, vlan int) *interfacestore.InterfaceConfig {
	hostIfaceName := util.GenerateContainerHostVethName(podName, testPodNamespace, containerID, ifDev)
	fakePortUUID := generateUUID()
	podMAC, _ := net.ParseMAC("01:02:03:04:05:06")
	podIP := net.ParseIP("1.1.1.11")
	podIPv6 := net.ParseIP("3ffe:ffff:10:1ff::111")
	containerConfig := interfacestore.NewContainerInterface(
		hostIfaceName, containerID, podName, testPodNamespace,
		ifDev, podMAC, []net.IP{podIP, podIPv6}, uint16(vlan))
	containerConfig.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: fakePortUUID, OFPort: 0}
	return containerConfig
}

func TestConfigureVLANSecondaryInterface(t *testing.T) {
	controller := gomock.NewController(t)
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
	ifaceStore := interfacestore.NewInterfaceStore()
	pc, err := NewSecondaryInterfaceConfigurator(mockOVSBridgeClient, ifaceStore)
	require.NoError(t, err, "No error expected in podConfigurator constructor")
	testIfaceConfigurator := newTestInterfaceConfigurator()
	pc.ifConfigurator = testIfaceConfigurator

	containerNS := "containerNS"
	podName := "pod1"
	containerID := generateUUID()
	containerCfg1 := newTestContainerInterfaceConfig(podName, containerID, "eth1", 100)
	containerCfg2 := newTestContainerInterfaceConfig(podName, containerID, "eth2", 0)
	// Secondary interface with no IP.
	containerCfg2.IPs = nil

	result := ipamtest.GenerateIPAMResult([]string{"1.1.1.11/24,1.1.1.1,4", "3ffe:ffff:10:1ff::111/64,3ffe:ffff:10::1,6"}, routes, dns)
	ipamResult := &ipam.IPAMResult{Result: *result, VLANID: 100}
	testIfaceConfigurator.hostIfaceName = containerCfg1.InterfaceName
	testIfaceConfigurator.containerMAC = containerCfg1.MAC.String()

	mockOVSBridgeClient.EXPECT().CreateAccessPort(
		containerCfg1.InterfaceName, containerCfg1.InterfaceName,
		gomock.Any(), uint16(100)).Return(containerCfg1.PortUUID, nil).Times(1)
	assert.NoError(t, pc.ConfigureVLANSecondaryInterface(podName, testPodNamespace, containerID, containerNS, "eth1", 1500, ipamResult))
	assert.Equal(t, 1, ifaceStore.Len())
	intfConfig, _ := ifaceStore.GetContainerInterface(containerID)
	assert.Equal(t, containerCfg1, intfConfig)

	testIfaceConfigurator.hostIfaceName = containerCfg2.InterfaceName
	testIfaceConfigurator.containerMAC = containerCfg2.MAC.String()
	ipamResult = &ipam.IPAMResult{}
	mockOVSBridgeClient.EXPECT().CreatePort(
		containerCfg2.InterfaceName, containerCfg2.InterfaceName,
		gomock.Any()).Return(containerCfg2.PortUUID, nil).Times(1)
	assert.NoError(t, pc.ConfigureVLANSecondaryInterface(podName, testPodNamespace, containerID, containerNS, "eth2", 1600, ipamResult))
	assert.Equal(t, 2, ifaceStore.Len())
	intfConfigs := ifaceStore.GetContainerInterfacesByPod(podName, testPodNamespace)
	assert.Len(t, intfConfigs, 2)
	for _, intfConfig := range intfConfigs {
		if intfConfig.InterfaceName == containerCfg1.InterfaceName {
			assert.Equal(t, containerCfg1, intfConfig)
		} else {
			assert.Equal(t, containerCfg2, intfConfig)
		}
	}
}

func TestDeleteVLANSecondaryInterface(t *testing.T) {
	controller := gomock.NewController(t)
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
	ifaceStore := interfacestore.NewInterfaceStore()
	pc, err := NewSecondaryInterfaceConfigurator(mockOVSBridgeClient, ifaceStore)
	require.Nil(t, err, "No error expected in podConfigurator constructor")

	podName := "pod1"
	containerID := generateUUID()
	containerCfg1 := newTestContainerInterfaceConfig(podName, containerID, "eth1", 100)
	containerCfg2 := newTestContainerInterfaceConfig(podName, containerID, "eth2", 0)
	// Secondary interface with no IP.
	containerCfg2.IPs = nil
	ifaceStore.AddInterface(containerCfg1)
	ifaceStore.AddInterface(containerCfg2)

	mockOVSBridgeClient.EXPECT().DeletePort(containerCfg1.PortUUID).Return(nil)
	assert.NoError(t, pc.DeleteVLANSecondaryInterface(containerCfg1))
	intfConfig, _ := ifaceStore.GetContainerInterface(containerID)
	assert.Equal(t, containerCfg2, intfConfig)

	mockOVSBridgeClient.EXPECT().DeletePort(containerCfg2.PortUUID).Return(nil)
	assert.NoError(t, pc.DeleteVLANSecondaryInterface(containerCfg2))
	_, found := ifaceStore.GetContainerInterface(containerID)
	assert.False(t, found, "Interface should not be in the local cache anymore")
}

func createPodConfigurator(controller *gomock.Controller, testIfaceConfigurator *fakeInterfaceConfigurator) *podConfigurator {
	gwMAC, _ := net.ParseMAC("00:00:11:11:11:11")
	mockOVSBridgeClient = ovsconfigtest.NewMockOVSBridgeClient(controller)
	mockOFClient = openflowtest.NewMockClient(controller)
	ifaceStore = interfacestore.NewInterfaceStore()
	mockRoute = routetest.NewMockInterface(controller)
	configurator, _ := newPodConfigurator(mockOVSBridgeClient, mockOFClient, mockRoute, ifaceStore, gwMAC, "system", false, false, channel.NewSubscribableChannel("PodUpdate", 100))
	configurator.ifConfigurator = testIfaceConfigurator
	return configurator
}

func mockGetNSPath(err error) func() {
	originalGetNSPath := getNSPath
	getNSPath = func(netnsName string) (string, error) {
		return netnsName, err
	}
	return func() {
		getNSPath = originalGetNSPath
	}
}
