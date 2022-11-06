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
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	ipamtest "antrea.io/antrea/pkg/agent/cniserver/ipam/testing"
	cniservertest "antrea.io/antrea/pkg/agent/cniserver/testing"
	types "antrea.io/antrea/pkg/agent/cniserver/types"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	routetest "antrea.io/antrea/pkg/agent/route/testing"
	"antrea.io/antrea/pkg/agent/secondarynetwork/cnipodcache"
	"antrea.io/antrea/pkg/agent/util"
	cnipb "antrea.io/antrea/pkg/apis/cni/v1beta1"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	"antrea.io/antrea/pkg/util/channel"
)

func TestValidatePrevResult(t *testing.T) {
	cniServer := newCNIServer(t)
	cniVersion := "0.4.0"
	networkCfg := generateNetworkConfiguration("", cniVersion, "", testIpamType)
	k8sPodArgs := &types.K8sArgs{}
	cnitypes.LoadArgs(args, k8sPodArgs)
	networkCfg.PrevResult = nil
	ipamResult := ipamtest.GenerateIPAMResult(cniVersion, ips, routes, dns)
	networkCfg.RawPrevResult, _ = translateRawPrevResult(ipamResult, cniVersion)

	prevResult, _ := cniServer.parsePrevResultFromRequest(networkCfg)
	containerIface := &current.Interface{Name: ifname, Sandbox: netns}
	containerID := uuid.New().String()
	hostIfaceName := util.GenerateContainerInterfaceName(testPodNameA, testPodNamespace, containerID)
	hostIface := &current.Interface{Name: hostIfaceName}
	prevResult.Interfaces = []*current.Interface{hostIface, containerIface}

	baseCNIConfig := func() *CNIConfig {
		cniConfig := &CNIConfig{NetworkConfig: networkCfg, CniCmdArgs: &cnipb.CniCmdArgs{Args: args}}
		cniConfig.ContainerId = containerID
		return cniConfig
	}

	t.Run("Invalid container interface veth", func(t *testing.T) {
		cniConfig := baseCNIConfig()
		cniConfig.Ifname = "invalid_iface" // invalid
		sriovVFDeviceID := ""
		response := cniServer.validatePrevResult(cniConfig.CniCmdArgs, prevResult, sriovVFDeviceID)
		checkErrorResponse(
			t, response, cnipb.ErrorCode_INVALID_NETWORK_CONFIG,
			"prevResult does not match network configuration",
		)
	})

	t.Run("Invalid container interface SR-IOV VF", func(t *testing.T) {
		cniConfig := baseCNIConfig()
		cniConfig.Ifname = "invalid_iface" // invalid
		sriovVFDeviceID := "0000:03:00.6"
		response := cniServer.validatePrevResult(cniConfig.CniCmdArgs, prevResult, sriovVFDeviceID)
		checkErrorResponse(
			t, response, cnipb.ErrorCode_INVALID_NETWORK_CONFIG,
			"prevResult does not match network configuration",
		)
	})

	t.Run("Interface check failure veth", func(t *testing.T) {
		cniConfig := baseCNIConfig()
		cniConfig.Ifname = ifname
		cniConfig.Netns = "invalid_netns"
		sriovVFDeviceID := ""
		cniServer.podConfigurator, _ = newPodConfigurator(nil, nil, nil, nil, nil, "", false, channel.NewSubscribableChannel("PodUpdate", 100), nil, false)
		response := cniServer.validatePrevResult(cniConfig.CniCmdArgs, prevResult, sriovVFDeviceID)
		checkErrorResponse(t, response, cnipb.ErrorCode_CHECK_INTERFACE_FAILURE, "")
	})

	t.Run("Interface check failure SR-IOV VF", func(t *testing.T) {
		cniConfig := baseCNIConfig()
		cniConfig.Ifname = ifname
		cniConfig.Netns = "invalid_netns"
		sriovVFDeviceID := "0000:03:00.6"
		prevResult.Interfaces = []*current.Interface{hostIface, containerIface}
		cniServer.podConfigurator, _ = newPodConfigurator(nil, nil, nil, nil, nil, "", true, channel.NewSubscribableChannel("PodUpdate", 100), nil, false)
		response := cniServer.validatePrevResult(cniConfig.CniCmdArgs, prevResult, sriovVFDeviceID)
		checkErrorResponse(t, response, cnipb.ErrorCode_CHECK_INTERFACE_FAILURE, "")
	})
}

func TestRemoveInterface(t *testing.T) {
	controller := gomock.NewController(t)
	defer controller.Finish()
	mockOVSBridgeClient = ovsconfigtest.NewMockOVSBridgeClient(controller)
	mockOFClient = openflowtest.NewMockClient(controller)
	ifaceStore = interfacestore.NewInterfaceStore()
	routeMock = routetest.NewMockInterface(controller)
	gwMAC, _ := net.ParseMAC("00:00:11:11:11:11")
	podConfigurator, err := newPodConfigurator(mockOVSBridgeClient, mockOFClient, routeMock, ifaceStore, gwMAC, "system", false, channel.NewSubscribableChannel("PodUpdate", 100), nil, false)
	require.Nil(t, err, "No error expected in podConfigurator constructor")

	containerMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	containerIP := net.ParseIP("1.1.1.1")

	var cniConfig *CNIConfig
	var containerID string
	var podName string
	var hostIfaceName string
	var fakePortUUID string
	var containerConfig *interfacestore.InterfaceConfig

	setup := func(name string) {
		containerID = uuid.New().String()
		podName = name
		hostIfaceName = util.GenerateContainerInterfaceName(podName, testPodNamespace, containerID)
		fakePortUUID = uuid.New().String()

		netcfg := generateNetworkConfiguration("", supportedCNIVersion, "", testIpamType)
		cniConfig = &CNIConfig{NetworkConfig: netcfg, CniCmdArgs: &cnipb.CniCmdArgs{}}
		cniConfig.Ifname = "eth0"
		cniConfig.ContainerId = containerID
		cniConfig.Netns = ""

		containerConfig = interfacestore.NewContainerInterface(
			hostIfaceName,
			containerID,
			podName,
			testPodNamespace,
			containerMAC,
			[]net.IP{containerIP},
			0)
		containerConfig.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: fakePortUUID, OFPort: 0}
	}

	t.Run("Successful removal", func(t *testing.T) {
		setup("test1")
		ifaceStore.AddInterface(containerConfig)

		mockOFClient.EXPECT().UninstallPodFlows(hostIfaceName).Return(nil)
		mockOVSBridgeClient.EXPECT().DeletePort(fakePortUUID).Return(nil)
		routeMock.EXPECT().DeleteLocalAntreaFlexibleIPAMPodRule([]net.IP{containerIP}).Return(nil).Times(1)

		err := podConfigurator.removeInterfaces(containerID)
		require.Nil(t, err, "Failed to remove interface")
		_, found := ifaceStore.GetContainerInterface(containerID)
		assert.False(t, found, "Interface should not be in the local cache anymore")
	})

	t.Run("Error in OVS port delete", func(t *testing.T) {
		setup("test2")
		ifaceStore.AddInterface(containerConfig)

		mockOVSBridgeClient.EXPECT().DeletePort(fakePortUUID).Return(ovsconfig.NewTransactionError(fmt.Errorf("error while deleting OVS port"), true))
		mockOFClient.EXPECT().UninstallPodFlows(hostIfaceName).Return(nil)

		err := podConfigurator.removeInterfaces(containerID)
		require.NotNil(t, err, "Expected interface remove to fail")
		_, found := ifaceStore.GetContainerInterface(containerID)
		assert.True(t, found, "Interface should still be in local cache because of port deletion failure")
	})

	t.Run("Error in Pod flows delete", func(t *testing.T) {
		setup("test3")
		ifaceStore.AddInterface(containerConfig)

		mockOFClient.EXPECT().UninstallPodFlows(hostIfaceName).Return(fmt.Errorf("failed to delete openflow entry"))

		err := podConfigurator.removeInterfaces(containerID)
		require.NotNil(t, err, "Expected interface remove to fail")
		_, found := ifaceStore.GetContainerInterface(containerID)
		assert.True(t, found, "Interface should still be in local cache because of flow deletion failure")
	})
}

func mockCNIServer(t *testing.T, controller *gomock.Controller, ipamDriver ipam.IPAMDriver, ipamType string, enableSecondaryNetworkIPAM, isChaining, secondaryNetworkEnabled bool) *CNIServer {
	mockOVSBridgeClient = ovsconfigtest.NewMockOVSBridgeClient(controller)
	mockOFClient = openflowtest.NewMockClient(controller)
	ifaceStore = interfacestore.NewInterfaceStore()
	routeMock = routetest.NewMockInterface(controller)
	ipam.ResetIPAMDriver(ipamType, ipamDriver)
	cniServer := newCNIServer(t)
	cniServer.routeClient = routeMock
	_, nodePodCIDRv4, _ := net.ParseCIDR("192.168.1.0/24")
	gwMAC, _ := net.ParseMAC("00:00:11:11:11:11")
	gateway := &config.GatewayConfig{Name: "", IPv4: gwIPv4, MAC: gwMAC}
	cniServer.nodeConfig = &config.NodeConfig{Name: "node1", PodIPv4CIDR: nodePodCIDRv4, GatewayConfig: gateway}
	cniServer.podConfigurator, _ = newPodConfigurator(mockOVSBridgeClient, mockOFClient, routeMock, ifaceStore, gwMAC, "system", false, channel.NewSubscribableChannel("PodUpdate", 100), nil, false)
	cniServer.enableSecondaryNetworkIPAM = enableSecondaryNetworkIPAM
	cniServer.isChaining = isChaining
	cniServer.secondaryNetworkEnabled = secondaryNetworkEnabled
	if secondaryNetworkEnabled {
		cniServer.podConfigurator.podInfoStore = cnipodcache.NewCNIPodInfoStore()
	}
	return cniServer
}

func prepareSetup(t *testing.T, name string, cniType string, result *current.Result, ipamType string, withPreviousResult bool) (*cnipb.CniCmdRequest, string) {
	networkCfg := generateNetworkConfiguration("", supportedCNIVersion, cniType, ipamType)
	networkCfg.DNS = cnitypes.DNS{
		Nameservers: dns,
	}
	if withPreviousResult {
		networkCfg.RawPrevResult, _ = translateRawPrevResult(result, supportedCNIVersion)
	}
	podArgs := cniservertest.GenerateCNIArgs(name, testPodNamespace, testPodInfraContainerID)
	requestMsg, _ := newRequest(podArgs, networkCfg, "", t)
	return requestMsg, util.GenerateContainerInterfaceName(name, testPodNamespace, testPodInfraContainerID)
}

func TestCmdAdd(t *testing.T) {
	controller := gomock.NewController(t)
	defer controller.Finish()
	ipamMock := ipamtest.NewMockIPAMDriver(controller)
	ctx := context.TODO()

	getNSPath = func(netnsName string) (string, error) {
		return netnsName, nil
	}
	defer func() {
		getNSPath = util.GetNSPath
		restoreSecondaryIPAM()
	}()

	for _, tc := range []struct {
		name                       string
		podName                    string
		ipamType                   string
		ipamAdd                    bool
		ipamError                  error
		cniType                    string
		enableSecondaryNetworkIPAM bool
		isChaining                 bool
		secondaryNetworkEnabled    bool
		connectOVS                 bool
		migrateRoute               bool
		addLocalIPAMRoute          bool
		addLocalIPAMRouteError     error
		containerIfaceExist        bool
		response                   *cnipb.CniCmdResponse
	}{
		{
			name:                       "secondary-IPAM",
			podName:                    "pod0",
			ipamType:                   ipam.AntreaIPAMType,
			cniType:                    "cniType",
			enableSecondaryNetworkIPAM: true,
			isChaining:                 false,
			ipamAdd:                    true,
			response:                   resultToResponse(ipamResult),
		}, {
			name:                       "secondary-IPAM-failure",
			podName:                    "pod1",
			ipamType:                   ipam.AntreaIPAMType,
			cniType:                    "cniType",
			enableSecondaryNetworkIPAM: true,
			isChaining:                 false,
			ipamAdd:                    true,
			ipamError:                  fmt.Errorf("failed to parse static addresses in the IPAM config"),
			response: &cnipb.CniCmdResponse{
				Error: &cnipb.Error{
					Code:    cnipb.ErrorCode_IPAM_FAILURE,
					Message: "failed to parse static addresses in the IPAM config",
				},
			},
		}, {
			name:                       "chaining",
			podName:                    "pod2",
			ipamType:                   "test-cni-ipam",
			enableSecondaryNetworkIPAM: false,
			isChaining:                 true,
			connectOVS:                 true,
			migrateRoute:               true,
			containerIfaceExist:        true,
		}, {
			name:                       "add-general-cni",
			podName:                    "pod3",
			ipamType:                   "test-cni-ipam",
			ipamAdd:                    true,
			enableSecondaryNetworkIPAM: false,
			isChaining:                 false,
			connectOVS:                 true,
			addLocalIPAMRoute:          true,
			containerIfaceExist:        true,
		}, {
			name:                       "add-general-cni-failure",
			podName:                    "pod3",
			ipamType:                   "test-cni-ipam",
			ipamAdd:                    true,
			enableSecondaryNetworkIPAM: false,
			isChaining:                 false,
			connectOVS:                 true,
			addLocalIPAMRoute:          true,
			addLocalIPAMRouteError:     fmt.Errorf("failed to configure route"),
			containerIfaceExist:        false,
		}, {
			name:                       "add-secondary-network",
			podName:                    "pod4",
			ipamType:                   "test-cni-ipam",
			ipamAdd:                    true,
			enableSecondaryNetworkIPAM: false,
			secondaryNetworkEnabled:    true,
			isChaining:                 false,
			connectOVS:                 true,
			addLocalIPAMRoute:          true,
			containerIfaceExist:        true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cniserver := mockCNIServer(t, controller, ipamMock, tc.ipamType, tc.enableSecondaryNetworkIPAM, tc.isChaining, tc.secondaryNetworkEnabled)
			testIfaceConfigurator := newTestInterfaceConfigurator()
			requestMsg, hostInterfaceName := prepareSetup(t, tc.podName, tc.cniType, ipamResult, tc.ipamType, true)
			testIfaceConfigurator.hostIfaceName = hostInterfaceName
			cniserver.podConfigurator.ifConfigurator = testIfaceConfigurator
			if tc.ipamAdd {
				if tc.enableSecondaryNetworkIPAM {
					mockIPAMResult := ipamResult
					if tc.ipamError != nil {
						mockIPAMResult = nil
					}
					ipamSecondaryNetworkAdd = func(cniArgs *cnipb.CniCmdArgs, k8sArgs *types.K8sArgs, networkConfig *types.NetworkConfig) (*current.Result, error) {
						return mockIPAMResult, tc.ipamError
					}
				} else {
					ipamMock.EXPECT().Add(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, &ipam.IPAMResult{Result: *ipamResult}, tc.ipamError).Times(1)
				}
			}
			if tc.migrateRoute {
				routeMock.EXPECT().MigrateRoutesToGw(hostInterfaceName).Return(nil).Times(1)
			}
			if tc.addLocalIPAMRoute {
				routeMock.EXPECT().AddLocalAntreaFlexibleIPAMPodRule(gomock.Any()).Return(tc.addLocalIPAMRouteError).Times(1)
			}
			ovsPortID := generateUUID(t)
			if tc.connectOVS {
				mockOVSBridgeClient.EXPECT().CreatePort(hostInterfaceName, gomock.Any(), gomock.Any()).Return(ovsPortID, nil).Times(1)
				mockOVSBridgeClient.EXPECT().GetOFPort(hostInterfaceName, false).Return(int32(100), nil).Times(1)
				mockOFClient.EXPECT().InstallPodFlows(hostInterfaceName, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			}
			if tc.addLocalIPAMRouteError != nil {
				mockOFClient.EXPECT().UninstallPodFlows(hostInterfaceName).Return(nil).Times(1)
				mockOVSBridgeClient.EXPECT().DeletePort(ovsPortID).Return(nil).Times(1)
				ipamMock.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil).Times(1)
			}
			resp, err := cniserver.CmdAdd(ctx, requestMsg)
			assert.NoError(t, err)
			assert.NotNil(t, resp)
			containerID := requestMsg.CniArgs.ContainerId
			_, exists := ifaceStore.GetContainerInterface(containerID)
			assert.Equal(t, exists, tc.containerIfaceExist)
			if tc.response != nil {
				assert.Equal(t, tc.response, resp)
			} else if tc.addLocalIPAMRouteError != nil {
				assert.Equal(t, cnipb.ErrorCode_CONFIG_INTERFACE_FAILURE, resp.Error.Code)
				assert.Equal(t, "", testIfaceConfigurator.hostIfaceName)
			} else if !tc.isChaining {
				// The response with chaining mode uses the previous result provided in the CmdAdd request, so
				// it is not checked in the test.
				cniResult := *ipamResult
				cniResult.Interfaces = []*current.Interface{
					{Name: hostInterfaceName, Mac: hostIfaceMAC, Sandbox: ""},
					{Name: "eth0", Mac: containerMAC, Sandbox: cniserver.hostNetNsPath(requestMsg.CniArgs.Netns)},
				}
				successResponse := resultToResponse(&cniResult)
				assert.Equal(t, successResponse, resp)
			}
			if tc.secondaryNetworkEnabled {
				cniConfigInfo := cniserver.podConfigurator.podInfoStore.GetCNIConfigInfoByContainerID(tc.podName, testPodNamespace, containerID)
				assert.NotNil(t, cniConfigInfo)
			}
		})
	}
}

func TestCmdDel(t *testing.T) {
	controller := gomock.NewController(t)
	defer controller.Finish()
	defer restoreSecondaryIPAM()

	ipamMock := ipamtest.NewMockIPAMDriver(controller)
	ovsPortID := generateUUID(t)
	ovsPort := int32(100)
	ctx := context.TODO()

	for _, tc := range []struct {
		name                       string
		podName                    string
		ipamType                   string
		ipamDel                    bool
		ipamError                  error
		cniType                    string
		enableSecondaryNetworkIPAM bool
		isChaining                 bool
		secondaryNetworkEnabled    bool
		disconnectOVS              bool
		migrateRoute               bool
		delLocalIPAMRoute          bool
		delLocalIPAMRouteError     error
		response                   *cnipb.CniCmdResponse
	}{
		{
			name:                       "secondary-IPAM",
			podName:                    "pod1",
			ipamType:                   ipam.AntreaIPAMType,
			cniType:                    "cniType",
			ipamDel:                    true,
			enableSecondaryNetworkIPAM: true,
			isChaining:                 false,
			response:                   emptyResponse,
		},
		{
			name:                       "secondary-IPAM-failure",
			podName:                    "pod1",
			ipamType:                   ipam.AntreaIPAMType,
			cniType:                    "cniType",
			ipamDel:                    true,
			ipamError:                  fmt.Errorf("failed to delete secondary IPAM response"),
			enableSecondaryNetworkIPAM: true,
			isChaining:                 false,
			response: &cnipb.CniCmdResponse{
				Error: &cnipb.Error{
					Code:    cnipb.ErrorCode_IPAM_FAILURE,
					Message: "failed to delete secondary IPAM response",
				},
			},
		},
		{
			name:                       "chaining",
			podName:                    "pod2",
			ipamType:                   "test-delete",
			enableSecondaryNetworkIPAM: false,
			isChaining:                 true,
			migrateRoute:               true,
			disconnectOVS:              true,
		},
		{
			name:                       "del-general-cni",
			podName:                    "pod3",
			ipamType:                   "test-delete",
			ipamDel:                    true,
			enableSecondaryNetworkIPAM: false,
			isChaining:                 false,
			disconnectOVS:              true,
			delLocalIPAMRoute:          true,
		},
		{
			name:                       "del-general-cni-failure",
			podName:                    "pod3",
			ipamType:                   "test-delete",
			ipamDel:                    true,
			enableSecondaryNetworkIPAM: false,
			isChaining:                 false,
			disconnectOVS:              true,
			delLocalIPAMRoute:          true,
			delLocalIPAMRouteError:     fmt.Errorf("unable to delete flexible IPAM rule"),
		},
		{
			name:                       "del-secondary-network",
			podName:                    "pod4",
			ipamType:                   "test-delete",
			ipamDel:                    true,
			enableSecondaryNetworkIPAM: false,
			secondaryNetworkEnabled:    true,
			isChaining:                 false,
			disconnectOVS:              true,
			delLocalIPAMRoute:          true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cniserver := mockCNIServer(t, controller, ipamMock, tc.ipamType, tc.enableSecondaryNetworkIPAM, tc.isChaining, tc.secondaryNetworkEnabled)
			requestMsg, hostInterfaceName := prepareSetup(t, tc.podName, tc.cniType, ipamResult, tc.ipamType, true)
			containerID := requestMsg.CniArgs.ContainerId
			containerIfaceConfig := interfacestore.NewContainerInterface(hostInterfaceName, containerID, tc.podName, testPodNamespace, containerVethMac, []net.IP{net.ParseIP("10.1.2.100")}, 0)
			containerIfaceConfig.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: ovsPortID, OFPort: ovsPort}
			ifaceStore.AddInterface(containerIfaceConfig)
			testIfaceConfigurator := newTestInterfaceConfigurator()
			testIfaceConfigurator.hostIfaceName = hostInterfaceName
			cniserver.podConfigurator.ifConfigurator = testIfaceConfigurator
			if tc.secondaryNetworkEnabled {
				cniInfo := &cnipodcache.CNIConfigInfo{CNIVersion: supportedCNIVersion, PodName: tc.podName, PodNameSpace: testPodNamespace,
					ContainerID: containerID, ContainerNetNS: netns, PodCNIDeleted: false,
					MTU: 1450}
				cniserver.podConfigurator.podInfoStore.AddCNIConfigInfo(cniInfo)
			}
			if tc.ipamDel {
				if tc.enableSecondaryNetworkIPAM {
					ipamSecondaryNetworkDel = func(cniArgs *cnipb.CniCmdArgs, k8sArgs *types.K8sArgs, networkConfig *types.NetworkConfig) error {
						return tc.ipamError
					}
				} else {
					ipamMock.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, tc.ipamError).Times(1)
				}
			}
			if tc.disconnectOVS {
				mockOVSBridgeClient.EXPECT().DeletePort(ovsPortID).Return(nil).Times(1)
				mockOFClient.EXPECT().UninstallPodFlows(hostInterfaceName).Return(nil).Times(1)
			}
			if tc.migrateRoute {
				routeMock.EXPECT().UnMigrateRoutesFromGw(gomock.Any(), "").Return(nil).Times(1)
			}
			if tc.delLocalIPAMRoute {
				routeMock.EXPECT().DeleteLocalAntreaFlexibleIPAMPodRule(gomock.Any()).Return(tc.delLocalIPAMRouteError).Times(1)
			}
			resp, err := cniserver.CmdDel(ctx, requestMsg)
			assert.NoError(t, err)
			if tc.response != nil {
				assert.Equal(t, tc.response, resp)
			} else {
				if tc.delLocalIPAMRouteError != nil {
					assert.Equal(t, cnipb.ErrorCode_CONFIG_INTERFACE_FAILURE, resp.Error.Code)
				} else {
					assert.Equal(t, emptyResponse, resp)
				}
			}
			if tc.secondaryNetworkEnabled {
				cniConfigInfo := cniserver.podConfigurator.podInfoStore.GetCNIConfigInfoByContainerID(tc.podName, testPodNamespace, containerID)
				assert.NotNil(t, cniConfigInfo)
				assert.True(t, cniConfigInfo.PodCNIDeleted)
			}
		})
	}
}

func TestCmdCheck(t *testing.T) {
	controller := gomock.NewController(t)
	defer controller.Finish()
	defer restoreSecondaryIPAM()

	ipamMock := ipamtest.NewMockIPAMDriver(controller)
	ovsPortID := generateUUID(t)
	ovsPort := int32(100)
	ctx := context.TODO()

	prepareRequest := func(name string, cniType string, ipamType string, withPreviousResult bool) (*cnipb.CniCmdRequest, string) {
		hostInterfaceName := util.GenerateContainerInterfaceName(name, testPodNamespace, testPodInfraContainerID)
		networkCfg := generateNetworkConfiguration("", supportedCNIVersion, cniType, ipamType)
		if withPreviousResult {
			prevResult := ipamResult
			prevResult.Interfaces = []*current.Interface{
				{Name: hostInterfaceName},
				{Name: "eth0", Sandbox: netns, Mac: "01:02:03:04:05:06"},
			}
			networkCfg.RawPrevResult, _ = translateRawPrevResult(prevResult, supportedCNIVersion)
		}
		podArgs := cniservertest.GenerateCNIArgs(name, testPodNamespace, testPodInfraContainerID)
		requestMsg, containerID := newRequest(podArgs, networkCfg, "", t)
		containerIfaceConfig := interfacestore.NewContainerInterface(hostInterfaceName, containerID, name, testPodNamespace, containerVethMac, []net.IP{net.ParseIP("10.1.2.100")}, 0)
		containerIfaceConfig.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: ovsPortID, OFPort: ovsPort}
		ifaceStore.AddInterface(containerIfaceConfig)
		return requestMsg, hostInterfaceName
	}
	t.Run("secondary-IPAM", func(t *testing.T) {
		ipamType := ipam.AntreaIPAMType
		cniserver := mockCNIServer(t, controller, ipamMock, ipamType, true, false, false)
		requestMsg, _ := prepareRequest("pod0", "cniType", ipamType, false)
		ipamSecondaryNetworkCheck = func(cniArgs *cnipb.CniCmdArgs, k8sArgs *types.K8sArgs, networkConfig *types.NetworkConfig) error {
			return nil
		}
		resp, err := cniserver.CmdCheck(ctx, requestMsg)
		assert.NoError(t, err)
		assert.Equal(t, emptyResponse, resp)
	})
	t.Run("secondary-IPAM-failure", func(t *testing.T) {
		ipamType := ipam.AntreaIPAMType
		cniserver := mockCNIServer(t, controller, ipamMock, ipamType, true, false, false)
		requestMsg, _ := prepareRequest("pod0", "cniType", ipamType, false)
		ipamSecondaryNetworkCheck = func(cniArgs *cnipb.CniCmdArgs, k8sArgs *types.K8sArgs, networkConfig *types.NetworkConfig) error {
			return errors.New("failed to check secondary IPAM response")
		}
		resp, err := cniserver.CmdCheck(ctx, requestMsg)
		assert.NoError(t, err)
		expResponse := &cnipb.CniCmdResponse{
			Error: &cnipb.Error{
				Code:    cnipb.ErrorCode_IPAM_FAILURE,
				Message: "failed to check secondary IPAM response",
			},
		}
		assert.Equal(t, expResponse, resp)
	})
	t.Run("chaining", func(t *testing.T) {
		ipamType := "test-check"
		cniserver := mockCNIServer(t, controller, ipamMock, ipamType, false, true, false)
		requestMsg, hostInterfaceName := prepareRequest("pod1", "", ipamType, true)
		testIfaceConfigurator := newTestInterfaceConfigurator()
		testIfaceConfigurator.hostIfaceName = hostInterfaceName
		cniserver.podConfigurator.ifConfigurator = testIfaceConfigurator
		resp, err := cniserver.CmdCheck(ctx, requestMsg)
		assert.NoError(t, err)
		assert.Equal(t, emptyResponse, resp)
	})
	t.Run("check-general-cni", func(t *testing.T) {
		ipamType := "test-check"
		cniserver := mockCNIServer(t, controller, ipamMock, ipamType, false, false, false)
		requestMsg, hostInterfaceName := prepareRequest("pod2", "", ipamType, true)
		testIfaceConfigurator := newTestInterfaceConfigurator()
		testIfaceConfigurator.hostIfaceName = hostInterfaceName
		testIfaceConfigurator.containerVethPair = &vethPair{
			name:      "eth0",
			ifIndex:   20,
			peerIndex: 40,
		}
		cniserver.podConfigurator.ifConfigurator = testIfaceConfigurator
		ipamMock.EXPECT().Check(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil).Times(1)
		resp, err := cniserver.CmdCheck(ctx, requestMsg)
		assert.NoError(t, err)
		assert.Equal(t, emptyResponse, resp)
	})
}

func TestReconcile(t *testing.T) {
	controller := gomock.NewController(t)
	defer controller.Finish()
	mockOVSBridgeClient = ovsconfigtest.NewMockOVSBridgeClient(controller)
	mockOFClient = openflowtest.NewMockClient(controller)
	ifaceStore = interfacestore.NewInterfaceStore()
	routeMock = routetest.NewMockInterface(controller)
	nodeName := "node1"
	cniServer := newCNIServer(t)
	cniServer.routeClient = routeMock
	gwMAC, _ := net.ParseMAC("00:00:11:11:11:11")
	cniServer.podConfigurator, _ = newPodConfigurator(mockOVSBridgeClient, mockOFClient, routeMock, ifaceStore, gwMAC, "system", false, channel.NewSubscribableChannel("PodUpdate", 100), nil, false)
	cniServer.podConfigurator.ifConfigurator = newTestInterfaceConfigurator()
	cniServer.nodeConfig = &config.NodeConfig{
		Name: nodeName,
	}
	pods := []runtime.Object{
		&v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "p1",
				Namespace: testPodNamespace,
			},
			Spec: v1.PodSpec{
				NodeName: nodeName,
			},
		},
		&v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "p2",
				Namespace: testPodNamespace,
			},
			Spec: v1.PodSpec{
				NodeName:    nodeName,
				HostNetwork: true,
			},
		},
		&v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "p4",
				Namespace: testPodNamespace,
			},
			Spec: v1.PodSpec{
				NodeName: nodeName,
			},
		},
	}
	containerIfaces := map[string]*interfacestore.InterfaceConfig{
		"iface1": {
			InterfaceName: "iface1",
			Type:          interfacestore.ContainerInterface,
			OVSPortConfig: &interfacestore.OVSPortConfig{
				PortUUID: generateUUID(t),
				OFPort:   int32(3),
			},
			ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
				PodName:      "p1",
				PodNamespace: testPodNamespace,
				ContainerID:  generateUUID(t),
			},
		},
		"iface3": {
			InterfaceName: "iface3",
			Type:          interfacestore.ContainerInterface,
			OVSPortConfig: &interfacestore.OVSPortConfig{
				PortUUID: generateUUID(t),
				OFPort:   int32(4),
			},
			ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
				PodName:      "p3",
				PodNamespace: testPodNamespace,
				ContainerID:  generateUUID(t),
			},
		},
		"iface4": {
			InterfaceName: "iface4",
			Type:          interfacestore.ContainerInterface,
			OVSPortConfig: &interfacestore.OVSPortConfig{
				PortUUID: generateUUID(t),
				OFPort:   int32(-1),
			},
			ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
				PodName:      "p4",
				PodNamespace: testPodNamespace,
				ContainerID:  generateUUID(t),
			},
		},
	}
	kubeClient := fakeclientset.NewSimpleClientset(pods...)
	cniServer.kubeClient = kubeClient
	for _, containerIface := range containerIfaces {
		ifaceStore.AddInterface(containerIface)
	}
	mockOFClient.EXPECT().InstallPodFlows("iface1", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	iface := containerIfaces["iface3"]
	mockOFClient.EXPECT().UninstallPodFlows("iface3").Return(nil).Times(1)
	mockOVSBridgeClient.EXPECT().DeletePort(iface.PortUUID).Return(nil).Times(1)
	routeMock.EXPECT().DeleteLocalAntreaFlexibleIPAMPodRule(gomock.Any()).Return(nil).Times(1)
	err := cniServer.reconcile()
	assert.NoError(t, err)
	_, exists := ifaceStore.GetInterfaceByName("iface3")
	assert.False(t, exists)
}

func restoreSecondaryIPAM() {
	ipamSecondaryNetworkAdd = ipam.SecondaryNetworkAdd
	ipamSecondaryNetworkDel = ipam.SecondaryNetworkDel
	ipamSecondaryNetworkCheck = ipam.SecondaryNetworkCheck
}
