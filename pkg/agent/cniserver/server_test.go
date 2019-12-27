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

package cniserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	openflowtest "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
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
	testBr                  = "br0"
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
var testNodeConfig *types.NodeConfig
var gwIP net.IP

func TestLoadNetConfig(t *testing.T) {
	assert := assert.New(t)

	cniService := newCNIServer(t)
	networkCfg := generateNetworkConfiguration("testCfg", supportedCNIVersion)
	requestMsg, containerId := newRequest(args, networkCfg, "", t)
	netCfg, err := cniService.loadNetworkConfig(&requestMsg)

	// just make sure that cniService.nodeConfig matches the testNodeConfig.
	require.Equal(t, testNodeConfig, cniService.nodeConfig)

	assert.Nil(err, "Error while parsing request message, %v", err)
	assert.Equal(supportedCNIVersion, netCfg.CNIVersion)
	assert.Equal(containerId, netCfg.ContainerId)
	assert.Equal(netns, netCfg.Netns)
	assert.Equal(ifname, netCfg.Ifname)
	assert.Equal(networkCfg.Name, netCfg.Name)
	assert.Equal(networkCfg.IPAM.Type, netCfg.IPAM.Type)
	assert.Equal(
		netCfg.IPAM.Subnet, testNodeConfig.PodCIDR.String(),
		"Network configuration (PodCIDR) was not updated",
	)
	assert.Equal(
		netCfg.IPAM.Gateway, testNodeConfig.GatewayConfig.IP.String(),
		"Network configuration (Gateway IP) was not updated",
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

	require.True(t, ipam.IsIPAMTypeValid(testIpamType), "Failed to register IPAM service")
	require.False(t, ipam.IsIPAMTypeValid("not_a_valid_IPAM_driver"))

	// Test IPAM_Failure cases
	cxt := context.Background()
	networkCfg := generateNetworkConfiguration("testCfg", "0.4.0")
	requestMsg, _ := newRequest(args, networkCfg, "", t)

	t.Run("Error on ADD", func(t *testing.T) {
		ipamMock.EXPECT().Add(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("IPAM add error"))
		// A rollback will be tried if add failed.
		ipamMock.EXPECT().Del(gomock.Any(), gomock.Any()).Times(1)
		response, err := cniServer.CmdAdd(cxt, &requestMsg)
		require.Nil(t, err, "expected no rpc error")
		checkErrorResponse(t, response, cnipb.ErrorCode_IPAM_FAILURE, "IPAM add error")
	})

	t.Run("Error on DEL", func(t *testing.T) {
		ipamMock.EXPECT().Del(gomock.Any(), gomock.Any()).Return(fmt.Errorf("IPAM delete error"))
		response, err := cniServer.CmdDel(cxt, &requestMsg)
		require.Nil(t, err, "expected no rpc error")
		checkErrorResponse(t, response, cnipb.ErrorCode_IPAM_FAILURE, "IPAM delete error")
	})

	t.Run("Error on CHECK", func(t *testing.T) {
		ipamMock.EXPECT().Check(gomock.Any(), gomock.Any()).Return(fmt.Errorf("IPAM check error"))
		response, err := cniServer.CmdCheck(cxt, &requestMsg)
		require.Nil(t, err, "expected no rpc error")
		checkErrorResponse(t, response, cnipb.ErrorCode_IPAM_FAILURE, "IPAM check error")
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
	hostIfaceName := util.GenerateContainerInterfaceName(testPodName, testPodNamespace)
	hostIface := &current.Interface{Name: hostIfaceName}

	baseCNIConfig := func() *CNIConfig {
		cniConfig := &CNIConfig{NetworkConfig: networkCfg, CniCmdArgs: &cnipb.CniCmdArgs{Args: args}}
		containerID := uuid.New().String()
		cniConfig.ContainerId = containerID
		return cniConfig
	}

	t.Run("Invalid container interface", func(t *testing.T) {
		cniConfig := baseCNIConfig()
		cniConfig.Ifname = "invalid_iface" // invalid
		prevResult.Interfaces = []*current.Interface{hostIface, containerIface}
		response, _ := cniServer.validatePrevResult(cniConfig.CniCmdArgs, k8sPodArgs, prevResult)
		checkErrorResponse(
			t, response, cnipb.ErrorCode_INVALID_NETWORK_CONFIG,
			"prevResult does not match network configuration",
		)
	})

	t.Run("Invalid host interface", func(t *testing.T) {
		cniConfig := baseCNIConfig()
		cniConfig.Ifname = ifname
		hostIface := &current.Interface{Name: "unknown_iface"}
		prevResult.Interfaces = []*current.Interface{hostIface, containerIface}
		response, _ := cniServer.validatePrevResult(cniConfig.CniCmdArgs, k8sPodArgs, prevResult)
		checkErrorResponse(
			t, response, cnipb.ErrorCode_INVALID_NETWORK_CONFIG,
			"prevResult does not match network configuration",
		)
	})

	t.Run("Interface check failure", func(t *testing.T) {
		cniConfig := baseCNIConfig()
		cniConfig.Ifname = ifname
		cniConfig.Netns = "invalid_netns"
		prevResult.Interfaces = []*current.Interface{hostIface, containerIface}
		response, _ := cniServer.validatePrevResult(cniConfig.CniCmdArgs, k8sPodArgs, prevResult)
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

	// TODO: it may be better to have a v4 address and a v6 address, as the IPAM plugin will not
	// return a Result with 2 v4 addresses.
	testIps := []string{"10.1.2.100/24, ,4", "192.168.1.100/24, 192.168.2.253, 4"}

	require.Equal(gwIP, testNodeConfig.GatewayConfig.IP)

	t.Run("Gateways updated", func(t *testing.T) {
		assert := assert.New(t)

		result := ipamtest.GenerateIPAMResult(supportedCNIVersion, testIps, routes, dns)
		updateResultIfaceConfig(result, gwIP)

		assert.Len(result.IPs, 2, "Failed to construct result")
		for _, ipc := range result.IPs {
			switch ipc.Address.IP.String() {
			case "10.1.2.100":
				assert.Equal("10.1.2.1", ipc.Gateway.String())
			case "192.168.1.100":
				assert.Equal("192.168.2.253", ipc.Gateway.String())
			default:
				t.Errorf("Unexpected IP address in CNI result")
			}
		}
	})

	t.Run("Default route added", func(t *testing.T) {
		emptyRoutes := []string{}
		result := ipamtest.GenerateIPAMResult(supportedCNIVersion, testIps, emptyRoutes, dns)
		updateResultIfaceConfig(result, gwIP)
		require.NotEmpty(t, result.Routes)
		defaultRoute := func() *cnitypes.Route {
			for _, route := range result.Routes {
				if route.Dst.String() == "0.0.0.0/0" {
					return route
				}
			}
			return nil
		}()
		assert.NotNil(t, defaultRoute.GW)
	})
}

func TestValidateOVSPort(t *testing.T) {
	controller := gomock.NewController(t)
	defer controller.Finish()
	ifaceStore := interfacestore.NewInterfaceStore()
	podConfigurator := &podConfigurator{ifaceStore: ifaceStore}
	containerID := uuid.New().String()
	containerMACStr := "11:22:33:44:55:66"
	containerIp := []string{"10.1.2.100/24,10.1.2.1,4"}
	result := ipamtest.GenerateIPAMResult(supportedCNIVersion, containerIp, routes, dns)
	containerIface := &current.Interface{Name: ifname, Sandbox: netns, Mac: containerMACStr}
	hostIfaceName := util.GenerateContainerInterfaceName(testPodName, testPodNamespace)
	hostIface := &current.Interface{Name: hostIfaceName}
	result.Interfaces = []*current.Interface{hostIface, containerIface}
	portUUID := uuid.New().String()
	containerConfig := buildContainerConfig(hostIfaceName, containerID, testPodName, testPodNamespace, containerIface, result.IPs)
	containerConfig.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID}

	ifaceStore.AddInterface(containerConfig)
	err := podConfigurator.validateOVSPort(hostIfaceName, containerMACStr, containerID, result.IPs)
	assert.Nil(t, err, "Failed to validate OVS port configuration")
}

func TestRemoveInterface(t *testing.T) {
	controller := gomock.NewController(t)
	defer controller.Finish()
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)
	mockOFClient := openflowtest.NewMockClient(controller)
	ifaceStore := interfacestore.NewInterfaceStore()
	podConfigurator := &podConfigurator{
		ovsBridgeClient: mockOVSBridgeClient,
		ofClient:        mockOFClient,
		ifaceStore:      ifaceStore,
	}
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
		hostIfaceName = util.GenerateContainerInterfaceName(podName, testPodNamespace)
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
			containerIP)
		containerConfig.OVSPortConfig = &interfacestore.OVSPortConfig{fakePortUUID, 0}
	}

	t.Run("Successful remove", func(t *testing.T) {
		setup("test1")
		ifaceStore.AddInterface(containerConfig)

		mockOFClient.EXPECT().UninstallPodFlows(hostIfaceName).Return(nil)
		mockOVSBridgeClient.EXPECT().DeletePort(fakePortUUID).Return(nil)

		err := podConfigurator.removeInterfaces(podName, testPodNamespace, containerID, cniConfig.Netns, cniConfig.Ifname)
		require.Nil(t, err, "Failed to remove interface")
		_, found := ifaceStore.GetContainerInterface(podName, testPodNamespace)
		assert.False(t, found, "Interface should not be in the local cache anymore")
	})

	t.Run("Error in OVS port delete", func(t *testing.T) {
		setup("test2")
		ifaceStore.AddInterface(containerConfig)

		mockOVSBridgeClient.EXPECT().DeletePort(fakePortUUID).Return(ovsconfig.NewTransactionError(fmt.Errorf("error while deleting OVS port"), true))
		mockOFClient.EXPECT().UninstallPodFlows(hostIfaceName).Return(nil)

		err := podConfigurator.removeInterfaces(podName, testPodNamespace, containerID, "", cniConfig.Ifname)
		require.NotNil(t, err, "Expected interface remove to fail")
		_, found := ifaceStore.GetContainerInterface(podName, testPodNamespace)
		assert.True(t, found, "Interface should still be in local cache because of port deletion failure")
	})

	t.Run("Error in Pod flows delete", func(t *testing.T) {
		setup("test3")
		ifaceStore.AddInterface(containerConfig)

		mockOFClient.EXPECT().UninstallPodFlows(hostIfaceName).Return(fmt.Errorf("failed to delete openflow entry"))

		err := podConfigurator.removeInterfaces(podName, testPodNamespace, containerID, "", cniConfig.Ifname)
		require.NotNil(t, err, "Expected interface remove to fail")
		_, found := ifaceStore.GetContainerInterface(podName, testPodNamespace)
		assert.True(t, found, "Interface should still be in local cache because of flow deletion failure")
	})
}

func TestBuildOVSPortExternalIDs(t *testing.T) {
	containerID := uuid.New().String()
	containerMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	containerIP := net.ParseIP("10.1.2.100")
	containerConfig := interfacestore.NewContainerInterface("pod1-abcd", containerID, "test-1", "t1", containerMAC, containerIP)
	externalIds := BuildOVSPortExternalIDs(containerConfig)
	parsedIP, existed := externalIds[ovsExternalIDIP]
	if !existed || parsedIP != "10.1.2.100" {
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
	supportedVersions := "0.3.0,0.3.1,0.4.0"
	cniServer := &CNIServer{
		cniSocket:       testSocket,
		nodeConfig:      testNodeConfig,
		serverVersion:   cni.AntreaCNIVersion,
		containerAccess: newContainerAccessArbitrator(),
	}
	cniServer.supportedCNIVersions = buildVersionSet(supportedVersions)
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
	containerId := generateUUID(t)
	networkConfig, err := json.Marshal(netCfg)
	if err != nil {
		t.Error("Failed to generate Network configuration")
	}

	cmdRequest := cnipb.CniCmdRequest{
		CniArgs: &cnipb.CniCmdArgs{
			ContainerId:          containerId,
			Ifname:               ifname,
			Args:                 args,
			Netns:                netns,
			NetworkConfiguration: networkConfig,
			Path:                 path,
		},
	}
	return cmdRequest, containerId
}

func generateUUID(t *testing.T) string {
	newId, err := uuid.NewUUID()
	if err != nil {
		t.Fatal("Failed to generate UUID")
	}
	return newId.String()
}

func init() {
	nodeName := "node1"
	gwIP = net.ParseIP("192.168.1.1")
	_, nodePodCIDR, _ := net.ParseCIDR("192.168.1.0/24")
	gwMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	gateway := &types.GatewayConfig{Name: "gw", IP: gwIP, MAC: gwMAC}
	testNodeConfig = &types.NodeConfig{testBr, nodeName, nodePodCIDR, gateway}
}
