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

// +build linux
// TODO: fix the CNI ADD test for Windows.

package cniserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/antrea/pkg/agent/cniserver/ipam"
	ipamtest "github.com/vmware-tanzu/antrea/pkg/agent/cniserver/ipam/testing"
	cniservertest "github.com/vmware-tanzu/antrea/pkg/agent/cniserver/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	openflowtest "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	cnipb "github.com/vmware-tanzu/antrea/pkg/apis/cni/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/cni"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig/testing"
)

const (
	netns                   = "ns-1"
	ifname                  = "eth0"
	testSocket              = "/tmp/test.sock"
	testIpamType            = "test"
	testPodNamespace        = "test"
	testPodName             = "test-1"
	testPodInfraContainerID = "test-infra-11111111"
	supportedCNIVersion     = "0.4.0"
	unsupportedCNIVersion   = "0.5.1"
)

var routes = []string{"10.0.0.0/8,10.1.2.1", "0.0.0.0/0,10.1.2.1"}
var dns = []string{"192.168.100.1"}
var ips = []string{"10.1.2.100/24,10.1.2.1,4"}
var args = cniservertest.GenerateCNIArgs(testPodName, testPodNamespace, testPodInfraContainerID)
var testNodeConfig *config.NodeConfig
var gwIPv4 net.IP
var gwIPv6 net.IP

func TestLoadNetConfig(t *testing.T) {
	assert := assert.New(t)

	cniService := newCNIServer(t)
	networkCfg := generateNetworkConfiguration("testCfg", supportedCNIVersion)
	requestMsg, containerID := newRequest(args, networkCfg, "", t)
	netCfg, err := cniService.loadNetworkConfig(&requestMsg)

	// just make sure that cniService.nodeConfig matches the testNodeConfig.
	require.Equal(t, testNodeConfig, cniService.nodeConfig)

	assert.Nil(err, "Error while parsing request message, %v", err)
	assert.Equal(supportedCNIVersion, netCfg.CNIVersion)
	assert.Equal(containerID, netCfg.ContainerId)
	assert.Equal(netns, netCfg.Netns)
	assert.Equal(ifname, netCfg.Ifname)
	assert.Equal(networkCfg.Name, netCfg.Name)
	assert.Equal(networkCfg.IPAM.Type, netCfg.IPAM.Type)
	assert.Equal(
		netCfg.IPAM.Ranges[0][0].Subnet, testNodeConfig.PodIPv4CIDR.String(),
		"Network configuration (PodIPv4CIDR) was not updated",
	)
	assert.Equal(
		netCfg.IPAM.Ranges[0][0].Gateway, testNodeConfig.GatewayConfig.IPv4.String(),
		"Network configuration (Gateway IP) was not updated",
	)
	assert.Equal(
		netCfg.IPAM.Ranges[1][0].Subnet, testNodeConfig.PodIPv6CIDR.String(),
		"Network configuration (PodIPv6CIDR) was not updated",
	)
	assert.Equal(
		netCfg.IPAM.Ranges[1][0].Gateway, testNodeConfig.GatewayConfig.IPv6.String(),
		"Network configuration (Gateway IPv6) was not updated",
	)
}

func TestRequestCheck(t *testing.T) {
	cniService := newCNIServer(t)
	valid := cniService.isCNIVersionSupported(unsupportedCNIVersion)
	if valid {
		t.Error("Failed to return error for unsupported version")
	}
	valid = cniService.isCNIVersionSupported(supportedCNIVersion)
	if !valid {
		t.Error("Failed accept supported version")
	}
}

func checkErrorResponse(t *testing.T, resp *cnipb.CniCmdResponse, code cnipb.ErrorCode, message string) {
	assert.NotNil(t, resp, "Response is nil")
	assert.NotNil(t, resp.GetError(), "Error field is not set")
	assert.Equalf(
		t, code, resp.GetError().GetCode(),
		// this will print the error code names and not just their integral values.
		"Error code does not match: expected '%v' but got '%v'", code, resp.GetError().GetCode(),
	)
	if message != "" {
		assert.Contains(t, resp.GetError().GetMessage(), message, "Error message does not match")
	}
}

func TestIPAMService(t *testing.T) {
	controller := gomock.NewController(t)
	defer controller.Finish()
	ipamMock := ipamtest.NewMockIPAMDriver(controller)
	_ = ipam.RegisterIPAMDriver(testIpamType, ipamMock)
	cniServer := newCNIServer(t)
	ifaceStore := interfacestore.NewInterfaceStore()
	cniServer.podConfigurator = &podConfigurator{ifaceStore: ifaceStore}

	require.True(t, ipam.IsIPAMTypeValid(testIpamType), "Failed to register IPAM service")
	require.False(t, ipam.IsIPAMTypeValid("not_a_valid_IPAM_driver"))

	// Test IPAM_Failure cases
	cxt := context.Background()
	networkCfg := generateNetworkConfiguration("testCfg", "0.4.0")
	requestMsg, _ := newRequest(args, networkCfg, "", t)

	t.Run("Error on ADD", func(t *testing.T) {
		ipamMock.EXPECT().Add(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("IPAM add error"))
		ipamMock.EXPECT().Del(gomock.Any(), gomock.Any()).Return(nil)
		response, err := cniServer.CmdAdd(cxt, &requestMsg)
		require.Nil(t, err, "expected no rpc error")
		checkErrorResponse(t, response, cnipb.ErrorCode_IPAM_FAILURE, "IPAM add error")
	})

	t.Run("Error on DEL", func(t *testing.T) {
		// Prepare cached IPAM result which will be deleted later.
		ipamMock.EXPECT().Add(gomock.Any(), gomock.Any()).Times(1)
		cniConfig, _ := cniServer.checkRequestMessage(&requestMsg)
		_, err := ipam.ExecIPAMAdd(cniConfig.CniCmdArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no Add error")

		ipamMock.EXPECT().Del(gomock.Any(), gomock.Any()).Return(fmt.Errorf("IPAM delete error"))
		response, err := cniServer.CmdDel(cxt, &requestMsg)
		require.Nil(t, err, "expected no rpc error")
		checkErrorResponse(t, response, cnipb.ErrorCode_IPAM_FAILURE, "IPAM delete error")

		// Cached result would be removed after a successful retry of IPAM DEL.
		ipamMock.EXPECT().Del(gomock.Any(), gomock.Any()).Return(nil)
		err = ipam.ExecIPAMDelete(cniConfig.CniCmdArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no Del error")

	})

	t.Run("Error on CHECK", func(t *testing.T) {
		ipamMock.EXPECT().Check(gomock.Any(), gomock.Any()).Return(fmt.Errorf("IPAM check error"))
		response, err := cniServer.CmdCheck(cxt, &requestMsg)
		require.Nil(t, err, "expected no rpc error")
		checkErrorResponse(t, response, cnipb.ErrorCode_IPAM_FAILURE, "IPAM check error")
	})

	t.Run("Idempotent Call of IPAM ADD/DEL for the same Pod", func(t *testing.T) {
		ipamMock.EXPECT().Add(gomock.Any(), gomock.Any()).Times(1)
		ipamMock.EXPECT().Del(gomock.Any(), gomock.Any()).Times(2)
		cniConfig, response := cniServer.checkRequestMessage(&requestMsg)
		require.Nil(t, response, "expected no rpc error")
		ipamResult, err := ipam.ExecIPAMAdd(cniConfig.CniCmdArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no IPAM add error")
		ipamResult2, err := ipam.ExecIPAMAdd(cniConfig.CniCmdArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no IPAM add error")
		assert.Equal(t, ipamResult, ipamResult2)
		err = ipam.ExecIPAMDelete(cniConfig.CniCmdArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no IPAM del error")
		err = ipam.ExecIPAMDelete(cniConfig.CniCmdArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no IPAM del error")
	})

	t.Run("Idempotent Call of IPAM ADD/DEL for the same Pod with different containers", func(t *testing.T) {
		ipamMock.EXPECT().Add(gomock.Any(), gomock.Any()).Times(2)
		ipamMock.EXPECT().Del(gomock.Any(), gomock.Any()).Times(2)
		cniConfig, response := cniServer.checkRequestMessage(&requestMsg)
		require.Nil(t, response, "expected no rpc error")
		_, err := ipam.ExecIPAMAdd(cniConfig.CniCmdArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no IPAM add error")
		workerContainerID := "test-infra-2222222"
		args2 := cniservertest.GenerateCNIArgs(testPodName, testPodNamespace, workerContainerID)
		requestMsg2, _ := newRequest(args2, networkCfg, "", t)
		cniConfig2, response := cniServer.checkRequestMessage(&requestMsg2)
		require.Nil(t, response, "expected no rpc error")
		_, err = ipam.ExecIPAMAdd(cniConfig2.CniCmdArgs, cniConfig.IPAM.Type, cniConfig2.getInfraContainer())
		require.Nil(t, err, "expected no IPAM add error")
		err = ipam.ExecIPAMDelete(cniConfig.CniCmdArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no IPAM del error")
		err = ipam.ExecIPAMDelete(cniConfig2.CniCmdArgs, cniConfig.IPAM.Type, cniConfig2.getInfraContainer())
		require.Nil(t, err, "expected no IPAM del error")
	})
}

func TestCheckRequestMessage(t *testing.T) {
	cniServer := newCNIServer(t)

	t.Run("Incompatible CNI version", func(t *testing.T) {
		networkCfg := generateNetworkConfiguration("testCfg", unsupportedCNIVersion)
		requestMsg, _ := newRequest(args, networkCfg, "", t)
		_, response := cniServer.checkRequestMessage(&requestMsg)
		checkErrorResponse(t, response, cnipb.ErrorCode_INCOMPATIBLE_CNI_VERSION, "")
	})

	t.Run("Unknown IPAM type", func(t *testing.T) {
		networkCfg := generateNetworkConfiguration("testCfg", supportedCNIVersion)
		networkCfg.IPAM.Type = "unknown"
		requestMsg, _ := newRequest(args, networkCfg, "", t)
		_, response := cniServer.checkRequestMessage(&requestMsg)
		checkErrorResponse(t, response, cnipb.ErrorCode_UNSUPPORTED_FIELD, "")
	})
}

func TestValidatePrevResult(t *testing.T) {
	cniServer := newCNIServer(t)
	cniVersion := "0.4.0"
	networkCfg := generateNetworkConfiguration("testCfg", cniVersion)
	k8sPodArgs := &k8sArgs{}
	cnitypes.LoadArgs(args, k8sPodArgs)
	networkCfg.PrevResult = nil
	ips := []string{"10.1.2.100/24,10.1.2.1,4"}
	routes := []string{"10.0.0.0/8,10.1.2.1", "0.0.0.0/0,10.1.2.1"}
	dns := []string{"192.168.100.1"}
	ipamResult := ipamtest.GenerateIPAMResult(cniVersion, ips, routes, dns)
	networkCfg.RawPrevResult, _ = translateRawPrevResult(ipamResult, cniVersion)

	prevResult, _ := cniServer.parsePrevResultFromRequest(networkCfg)
	containerIface := &current.Interface{Name: ifname, Sandbox: netns}
	containerID := uuid.New().String()
	hostIfaceName := util.GenerateContainerInterfaceName(testPodName, testPodNamespace, containerID)
	hostIface := &current.Interface{Name: hostIfaceName}

	baseCNIConfig := func() *CNIConfig {
		cniConfig := &CNIConfig{NetworkConfig: networkCfg, CniCmdArgs: &cnipb.CniCmdArgs{Args: args}}
		cniConfig.ContainerId = containerID
		return cniConfig
	}

	t.Run("Invalid container interface veth", func(t *testing.T) {
		cniConfig := baseCNIConfig()
		cniConfig.Ifname = "invalid_iface" // invalid
		sriovVFDeviceID := ""
		prevResult.Interfaces = []*current.Interface{hostIface, containerIface}
		response := cniServer.validatePrevResult(cniConfig.CniCmdArgs, k8sPodArgs, prevResult, sriovVFDeviceID)
		checkErrorResponse(
			t, response, cnipb.ErrorCode_INVALID_NETWORK_CONFIG,
			"prevResult does not match network configuration",
		)
	})

	t.Run("Invalid container interface SR-IOV VF", func(t *testing.T) {
		cniConfig := baseCNIConfig()
		cniConfig.Ifname = "invalid_iface" // invalid
		sriovVFDeviceID := "0000:03:00.6"
		prevResult.Interfaces = []*current.Interface{hostIface, containerIface}
		response := cniServer.validatePrevResult(cniConfig.CniCmdArgs, k8sPodArgs, prevResult, sriovVFDeviceID)
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
		prevResult.Interfaces = []*current.Interface{hostIface, containerIface}
		cniServer.podConfigurator, _ = newPodConfigurator(nil, nil, nil, nil, nil, "", false, make(chan antreatypes.EntityReference, 100))
		response := cniServer.validatePrevResult(cniConfig.CniCmdArgs, k8sPodArgs, prevResult, sriovVFDeviceID)
		checkErrorResponse(t, response, cnipb.ErrorCode_CHECK_INTERFACE_FAILURE, "")
	})

	t.Run("Interface check failure SR-IOV VF", func(t *testing.T) {
		cniConfig := baseCNIConfig()
		cniConfig.Ifname = ifname
		cniConfig.Netns = "invalid_netns"
		sriovVFDeviceID := "0000:03:00.6"
		prevResult.Interfaces = []*current.Interface{hostIface, containerIface}
		cniServer.podConfigurator, _ = newPodConfigurator(nil, nil, nil, nil, nil, "", true, make(chan antreatypes.EntityReference, 100))
		response := cniServer.validatePrevResult(cniConfig.CniCmdArgs, k8sPodArgs, prevResult, sriovVFDeviceID)
		checkErrorResponse(t, response, cnipb.ErrorCode_CHECK_INTERFACE_FAILURE, "")
	})
}

func TestParsePrevResultFromRequest(t *testing.T) {
	cniServer := newCNIServer(t)

	getNetworkCfg := func(cniVersion string) *NetworkConfig {
		networkCfg := generateNetworkConfiguration("testCfg", cniVersion)
		networkCfg.PrevResult = nil
		networkCfg.RawPrevResult = nil
		return networkCfg
	}

	t.Run("Correct prevResult", func(t *testing.T) {
		networkCfg := getNetworkCfg(supportedCNIVersion)
		prevResult := ipamtest.GenerateIPAMResult(supportedCNIVersion, ips, routes, dns)
		var err error
		networkCfg.RawPrevResult, err = translateRawPrevResult(prevResult, supportedCNIVersion)
		require.Nil(t, err, "Cannot generate RawPrevResult for test")
		parsedPrevResult, _ := cniServer.parsePrevResultFromRequest(networkCfg)
		assert.NotNil(t, parsedPrevResult)
		// TODO: check that parsedPrevResult matches prevResult
	})

	t.Run("Missing prevResult", func(t *testing.T) {
		networkCfg := getNetworkCfg(supportedCNIVersion)
		_, response := cniServer.parsePrevResultFromRequest(networkCfg)
		checkErrorResponse(t, response, cnipb.ErrorCode_UNSUPPORTED_FIELD, "prevResult")
	})

	t.Run("Unsupported CNI version", func(t *testing.T) {
		networkCfg := getNetworkCfg(unsupportedCNIVersion)
		prevResult := ipamtest.GenerateIPAMResult(supportedCNIVersion, ips, routes, dns)
		var err error
		networkCfg.RawPrevResult, err = translateRawPrevResult(prevResult, supportedCNIVersion)
		require.Nil(t, err, "Cannot generate RawPrevResult for test")
		_, response := cniServer.parsePrevResultFromRequest(networkCfg)
		checkErrorResponse(t, response, cnipb.ErrorCode_DECODING_FAILURE, "prevResult")
	})
}

func TestUpdateResultIfaceConfig(t *testing.T) {
	require := require.New(t)

	testIps := []string{"192.168.1.100/24, , 4", "fd74:ca9b:172:18::8/64, , 6"}

	require.Equal(gwIPv4, testNodeConfig.GatewayConfig.IPv4)
	require.Equal(gwIPv6, testNodeConfig.GatewayConfig.IPv6)

	t.Run("Gateways updated", func(t *testing.T) {
		assert := assert.New(t)

		result := ipamtest.GenerateIPAMResult(supportedCNIVersion, testIps, routes, dns)
		updateResultIfaceConfig(result, gwIPv4, gwIPv6)

		assert.Len(result.IPs, 2, "Failed to construct result")
		for _, ipc := range result.IPs {
			switch ipc.Address.IP.String() {
			case "192.168.1.100":
				assert.Equal("192.168.1.1", ipc.Gateway.String())
			case "fd74:ca9b:172:18::8":
				assert.Equal("fd74:ca9b:172:18::1", ipc.Gateway.String())
			default:
				t.Errorf("Unexpected IP address in CNI result")
			}
		}
	})

	t.Run("Default route added", func(t *testing.T) {
		emptyRoutes := []string{}
		result := ipamtest.GenerateIPAMResult(supportedCNIVersion, testIps, emptyRoutes, dns)
		updateResultIfaceConfig(result, gwIPv4, gwIPv6)
		require.NotEmpty(t, result.Routes)
		require.Equal(2, len(result.Routes))
		for _, route := range result.Routes {
			switch route.Dst.String() {
			case "0.0.0.0/0":
				require.Equal("192.168.1.1", route.GW.String())
			case "::/0":
				require.Equal("fd74:ca9b:172:18::1", route.GW.String())
			default:
				t.Errorf("Unexpected Route in CNI result")
			}
		}
	})
}

func TestValidateOVSInterface(t *testing.T) {
	controller := gomock.NewController(t)
	defer controller.Finish()
	ifaceStore := interfacestore.NewInterfaceStore()
	podConfigurator := &podConfigurator{ifaceStore: ifaceStore}
	containerID := uuid.New().String()
	containerMACStr := "11:22:33:44:55:66"
	containerIP := []string{"10.1.2.100/24,10.1.2.1,4"}
	result := ipamtest.GenerateIPAMResult(supportedCNIVersion, containerIP, routes, dns)
	containerIface := &current.Interface{Name: ifname, Sandbox: netns, Mac: containerMACStr}
	hostIfaceName := util.GenerateContainerInterfaceName(testPodName, testPodNamespace, containerID)
	hostIface := &current.Interface{Name: hostIfaceName}
	result.Interfaces = []*current.Interface{hostIface, containerIface}
	portUUID := uuid.New().String()
	containerConfig := buildContainerConfig(hostIfaceName, containerID, testPodName, testPodNamespace, containerIface, result.IPs)
	containerConfig.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID}

	ifaceStore.AddInterface(containerConfig)
	err := podConfigurator.validateOVSInterfaceConfig(containerID, containerMACStr, result.IPs)
	assert.Nil(t, err, "Failed to validate OVS port configuration")
}

func TestRemoveInterface(t *testing.T) {
	controller := gomock.NewController(t)
	defer controller.Finish()
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
	mockOFClient := openflowtest.NewMockClient(controller)
	ifaceStore := interfacestore.NewInterfaceStore()
	gwMAC, _ := net.ParseMAC("00:00:11:11:11:11")
	podConfigurator, err := newPodConfigurator(mockOVSBridgeClient, mockOFClient, nil, ifaceStore, gwMAC, "system", false, make(chan antreatypes.EntityReference, 100))
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

		netcfg := generateNetworkConfiguration("testCfg", supportedCNIVersion)
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
			[]net.IP{containerIP})
		containerConfig.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: fakePortUUID, OFPort: 0}
	}

	t.Run("Successful remove", func(t *testing.T) {
		setup("test1")
		ifaceStore.AddInterface(containerConfig)

		mockOFClient.EXPECT().UninstallPodFlows(hostIfaceName).Return(nil)
		mockOVSBridgeClient.EXPECT().DeletePort(fakePortUUID).Return(nil)

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

func TestBuildOVSPortExternalIDs(t *testing.T) {
	containerID := uuid.New().String()
	containerMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	containerIP1 := net.ParseIP("10.1.2.100")
	containerIP2 := net.ParseIP("2001:fd1a::2")
	containerIPs := []net.IP{containerIP1, containerIP2}
	containerConfig := interfacestore.NewContainerInterface("pod1-abcd", containerID, "test-1", "t1", containerMAC, containerIPs)
	externalIds := BuildOVSPortExternalIDs(containerConfig)
	parsedIP, existed := externalIds[ovsExternalIDIP]
	parsedIPStr := parsedIP.(string)
	if !existed || !strings.Contains(parsedIPStr, "10.1.2.100") || !strings.Contains(parsedIPStr, "2001:fd1a::2") {
		t.Errorf("Failed to parse container configuration")
	}
	parsedMac, existed := externalIds[ovsExternalIDMAC]
	if !existed || parsedMac != containerMAC.String() {
		t.Errorf("Failed to parse container configuration")
	}
	parsedID, existed := externalIds[ovsExternalIDContainerID]
	if !existed || parsedID != containerID {
		t.Errorf("Failed to parse container configuration")
	}
	portExternalIDs := make(map[string]string)
	for k, v := range externalIds {
		val := v.(string)
		portExternalIDs[k] = val
	}
	mockPort := &ovsconfig.OVSPortData{
		Name:        "testPort",
		ExternalIDs: portExternalIDs,
	}
	portConfig := &interfacestore.OVSPortConfig{
		PortUUID: "12345678",
		OFPort:   int32(1),
	}
	ifaceConfig := ParseOVSPortInterfaceConfig(mockPort, portConfig, true)
	assert.Equal(t, len(containerIPs), len(ifaceConfig.IPs))
	for _, ip1 := range containerIPs {
		existed := false
		for _, ip2 := range ifaceConfig.IPs {
			if ip2.Equal(ip1) {
				existed = true
				break
			}
		}
		assert.True(t, existed, fmt.Sprintf("IP %s should exist in the restored InterfaceConfig", ip1.String()))
	}
}

func translateRawPrevResult(prevResult *current.Result, cniVersion string) (map[string]interface{}, error) {
	config := map[string]interface{}{
		"cniVersion": cniVersion,
		"prevResult": prevResult,
	}

	newBytes, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	conf := &cnitypes.NetConf{}
	if err := json.Unmarshal(newBytes, &conf); err != nil {
		return nil, fmt.Errorf("Error while parsing configuration: %s", err)
	}
	return conf.RawPrevResult, nil
}

func newCNIServer(t *testing.T) *CNIServer {
	networkReadyCh := make(chan struct{})
	cniServer := &CNIServer{
		cniSocket:       testSocket,
		nodeConfig:      testNodeConfig,
		serverVersion:   cni.AntreaCNIVersion,
		containerAccess: newContainerAccessArbitrator(),
		networkReadyCh:  networkReadyCh,
	}
	close(networkReadyCh)
	cniServer.supportedCNIVersions = buildVersionSet()
	return cniServer
}

func generateNetworkConfiguration(name string, cniVersion string) *NetworkConfig {
	netCfg := new(NetworkConfig)
	netCfg.Name = name
	netCfg.CNIVersion = cniVersion
	netCfg.Type = "antrea"
	netCfg.IPAM = ipam.IPAMConfig{Type: testIpamType}
	return netCfg
}

func newRequest(args string, netCfg *NetworkConfig, path string, t *testing.T) (cnipb.CniCmdRequest, string) {
	containerID := generateUUID(t)
	networkConfig, err := json.Marshal(netCfg)
	if err != nil {
		t.Error("Failed to generate Network configuration")
	}

	cmdRequest := cnipb.CniCmdRequest{
		CniArgs: &cnipb.CniCmdArgs{
			ContainerId:          containerID,
			Ifname:               ifname,
			Args:                 args,
			Netns:                netns,
			NetworkConfiguration: networkConfig,
			Path:                 path,
		},
	}
	return cmdRequest, containerID
}

func generateUUID(t *testing.T) string {
	newID, err := uuid.NewUUID()
	if err != nil {
		t.Fatal("Failed to generate UUID")
	}
	return newID.String()
}

func init() {
	nodeName := "node1"
	gwIPv4 = net.ParseIP("192.168.1.1")
	gwIPv6 = net.ParseIP("fd74:ca9b:172:18::1")
	_, nodePodCIDRv4, _ := net.ParseCIDR("192.168.1.0/24")
	_, nodePodCIDRv6, _ := net.ParseCIDR("fd74:ca9b:172:18::/64")
	gwMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	gateway := &config.GatewayConfig{Name: "", IPv4: gwIPv4, IPv6: gwIPv6, MAC: gwMAC}
	testNodeConfig = &config.NodeConfig{Name: nodeName, PodIPv4CIDR: nodePodCIDRv4, PodIPv6CIDR: nodePodCIDRv6, GatewayConfig: gateway}
}
