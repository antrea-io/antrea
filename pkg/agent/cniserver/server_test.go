package cniserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	mock "github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"okn/pkg/agent"
	"okn/pkg/agent/cniserver/ipam"
	"okn/pkg/apis/cni"
	"okn/pkg/cni"
	"okn/pkg/test"
	"okn/pkg/test/mocks"
)

const (
	netns                   = "ns-1"
	ifname                  = "eth0"
	testScock               = "/tmp/test.sock"
	testIpamType            = "test"
	testBr                  = "br0"
	testPodNamespace        = "test"
	testPodName             = "test-1"
	testPodInfraContainerID = "test-infra-11111111"
)

var routes = []string{"10.0.0.0/8,10.1.2.1", "0.0.0.0/0,10.1.2.1"}
var dns = []string{"192.168.100.1"}
var ips = []string{"10.1.2.100/24,10.1.2.1,4"}
var args string = test.GenerateCNIArgs(testPodName, testPodNamespace, testPodInfraContainerID)
var containerNamespace = "test"
var testNodeConfig *agent.NodeConfig
var gwIP net.IP

func TestLoadNetConfig(t *testing.T) {
	cniService := generateCNIServer(t)
	var version = "0.5.1"
	networkCfg := generateNetworkConfiguration("testCfg", version)
	requestMsg, containerId := newRequest(version, args, networkCfg, "", t)
	netCfg, err := cniService.loadNetworkConfig(&requestMsg)
	if err != nil {
		t.Errorf("Found error while parsing request message, %v", err)
	}
	reqVersion := netCfg.CNIVersion
	if (reqVersion != version) || reqVersion != netCfg.CNIVersion {
		t.Error("Failed to parse version from request")
	}
	if netCfg.ContainerId != containerId {
		t.Error("Failed to parse ContainerId")
	}
	if netCfg.Netns != netns {
		t.Error("Failed to parse netns")
	}
	if netCfg.Ifname != ifname {
		t.Error("Failed to parse ifname")
	}
	if netCfg.Name != networkCfg.Name {
		t.Error("Failed to parse network configuration")
	}
	if netCfg.IPAM.Type != networkCfg.IPAM.Type {
		t.Error("Failed to parse network configuration")
	}
	if netCfg.IPAM.Subnet != cniService.nodeConfig.PodCIDR.String() {
		t.Error("Failed to update local IPAM configuration")
	}
	if netCfg.IPAM.Gateway != testNodeConfig.Gateway.IP.String() {
		t.Error("Failed to update local IPAM configuration")
	}
}

func TestRequestCheck(t *testing.T) {
	cniService := generateCNIServer(t)
	var version1 = "0.5.1"
	valid := cniService.isCNIVersionSupported(version1)
	if valid {
		t.Error("Failed to check version")
	}
	var version2 = "0.4.0"
	valid = cniService.isCNIVersionSupported(version2)
	if !valid {
		t.Error("Failed to support version")
	}
}

func TestNewCNIServer(t *testing.T) {
	controller := mock.NewController(t)
	defer controller.Finish()
	ipamMock := mocks.NewMockIPAMDriver(controller)
	_ = ipam.RegisterIPAMDriver(testIpamType, ipamMock)
	testSupportedVersionStr := "0.3.0, 0.3.1, 0.4.0"
	var supporteVersions = []string{"0.3.0", "0.3.1", "0.4.0"}
	cniServer := generateCNIServer(t)
	cniServer.supportedCNIVersions = buildVersionSet(testSupportedVersionStr)
	for _, ver := range supporteVersions {
		if !cniServer.isCNIVersionSupported(ver) {
			t.Errorf("CniService init failed for wrong supportedCNIVersions")
		}
	}
	isValid := ipam.IsIPAMTypeValid(testIpamType)
	if !isValid {
		t.Errorf("Failed to load Ipam service")
	}
	isValid = ipam.IsIPAMTypeValid("test1")
	if isValid {
		t.Errorf("Failed to register Ipam service")
	}

	// Test IPAM_Failure cases
	cxt := context.Background()
	networkCfg := generateNetworkConfiguration("testCfg", "0.4.0")
	requestMsg, _ := newRequest(cni.OKNVersion, args, networkCfg, "", t)
	ipamMock.EXPECT().Add(mock.Any(), mock.Any()).Return(nil, fmt.Errorf("IPAM add error"))
	// A rollback might be tried if add failed
	ipamMock.EXPECT().Del(mock.Any(), mock.Any()).Times(1)
	response, _ := cniServer.CmdAdd(cxt, &requestMsg)
	if response == nil || response.StatusCode != cnimsg.CniCmdResponseMessage_IPAM_FAILURE {
		t.Errorf("Failed to return IPAM_Failure error")
	}

	ipamMock.EXPECT().Del(mock.Any(), mock.Any()).Return(fmt.Errorf("IPAM delete error"))
	response, _ = cniServer.CmdDel(cxt, &requestMsg)
	if response == nil || response.StatusCode != cnimsg.CniCmdResponseMessage_IPAM_FAILURE {
		t.Errorf("Failed to return IPAM_Failure error")
	}

	ipamMock.EXPECT().Check(mock.Any(), mock.Any()).Return(fmt.Errorf("IPAM check error"))
	response, _ = cniServer.CmdCheck(cxt, &requestMsg)
	if response == nil || response.StatusCode != cnimsg.CniCmdResponseMessage_IPAM_FAILURE {
		t.Errorf("Failed to return IPAM_Failure error")
	}
}

func TestCheckRequestMessage(t *testing.T) {
	cniServer := generateCNIServer(t)
	networkCfg := generateNetworkConfiguration("testCfg", "0.3.1")
	requestMsg, _ := newRequest("2.0", args, networkCfg, "", t)
	_, response := cniServer.checkRequestMessage(&requestMsg)
	if response == nil {
		t.Errorf("Failed to identify error request")
	} else if response.StatusCode != cnimsg.CniCmdResponseMessage_INCOMPATIBLE_PROTO_VERSION {
		t.Errorf("Failed to identify incompatible request version from client")
	}

	networkCfg = generateNetworkConfiguration("testCfg", "0.5.1")
	requestMsg, _ = newRequest(cni.OKNVersion, args, networkCfg, "", t)
	_, response = cniServer.checkRequestMessage(&requestMsg)
	if response == nil {
		t.Errorf("Failed to identify error request")
	} else if response.StatusCode != cnimsg.CniCmdResponseMessage_INCOMPATIBLE_CNI_VERSION {
		t.Errorf("Failed to identify incompatible CNI version from request")
	}

	networkCfg = generateNetworkConfiguration("testCfg", "0.3.1")
	networkCfg.IPAM.Type = "unknown"
	requestMsg, _ = newRequest(cni.OKNVersion, args, networkCfg, "", t)
	_, response = cniServer.checkRequestMessage(&requestMsg)
	if response == nil {
		t.Errorf("Failed to identify error request")
	} else if response.StatusCode != cnimsg.CniCmdResponseMessage_UNSUPPORTED_NETWORK_CONFIGURATION {
		t.Errorf("Failed to identify unsupported network configuration")
	}
}

func TestValidatePrevResult(t *testing.T) {
	cniServer := generateCNIServer(t)
	cniVersion := "0.4.0"
	networkCfg := generateNetworkConfiguration("testCfg", cniVersion)
	k8sPodArgs := &k8sArgs{}
	types.LoadArgs(args, k8sPodArgs)
	networkCfg.PrevResult = nil
	ips := []string{"10.1.2.100/24,10.1.2.1,4"}
	routes := []string{"10.0.0.0/8,10.1.2.1", "0.0.0.0/0,10.1.2.1"}
	dns := []string{"192.168.100.1"}
	ipamResult := test.GenerateIPAMResult(cniVersion, ips, routes, dns)
	networkCfg.RawPrevResult, _ = translateRawPrevResult(ipamResult, cniVersion)

	cniConfig := &CNIConfig{NetworkConfig: networkCfg, CniCmdArgsMessage: &cnimsg.CniCmdArgsMessage{Args: args}}
	cniConfig.Ifname = "eth1"
	prevResult, _ := cniServer.parsePrevResultFromRequest(networkCfg)
	containerID := uuid.New().String()
	cniConfig.ContainerId = containerID
	containerIface := &current.Interface{Name: ifname, Sandbox: netns}
	hostIfaceName := agent.GenerateContainerInterfaceName(testPodName, testPodNamespace)
	hostIface := &current.Interface{Name: hostIfaceName}
	prevResult.Interfaces = []*current.Interface{hostIface, containerIface}
	response, _ := cniServer.validatePrevResult(cniConfig.CniCmdArgsMessage, k8sPodArgs, prevResult)
	if response == nil || response.StatusCode != cnimsg.CniCmdResponseMessage_UNKNOWN_CONTAINER {
		t.Errorf("Failed to catch invalid container interface from request")
	}

	cniConfig.Ifname = ifname
	cniConfig.Netns = "invalid_netns"
	response, _ = cniServer.validatePrevResult(cniConfig.CniCmdArgsMessage, k8sPodArgs, prevResult)
	if response == nil || response.StatusCode != cnimsg.CniCmdResponseMessage_CHECK_INTERFACE_FAILURE {
		t.Errorf("Failed to catch invalid container interface from request")
	}
	hostIface = &current.Interface{Name: "unknown_iface"}
	prevResult.Interfaces = []*current.Interface{hostIface, containerIface}
	response, _ = cniServer.validatePrevResult(cniConfig.CniCmdArgsMessage, k8sPodArgs, prevResult)
	if response == nil || response.StatusCode != cnimsg.CniCmdResponseMessage_UNKNOWN_CONTAINER {
		t.Errorf("Failed to catch invalid host interface from request")
	}
}

func TestParsePrevResultFromRequest(t *testing.T) {
	cniServer := generateCNIServer(t)
	cniVersion := "0.4.0"
	networkCfg := generateNetworkConfiguration("testCfg", cniVersion)

	networkCfg.PrevResult = nil
	networkCfg.RawPrevResult = nil
	_, response := cniServer.parsePrevResultFromRequest(networkCfg)
	if response == nil {
		t.Errorf("Failed to catch invalid PrevResult from request")
	} else if response.StatusCode != cnimsg.CniCmdResponseMessage_UNSUPPORTED_NETWORK_CONFIGURATION {
		t.Errorf("Failed to catch invalid PrevResult from request")
	}

	networkCfg1 := generateNetworkConfiguration("testCfg", cniVersion)
	networkCfg1.PrevResult = nil
	prevResult := test.GenerateIPAMResult(cniVersion, ips, routes, dns)
	networkCfg1.RawPrevResult, _ = translateRawPrevResult(prevResult, cniVersion)
	prevResult, response = cniServer.parsePrevResultFromRequest(networkCfg1)
	if prevResult == nil {
		t.Errorf("Failed to parse PrevResult from request")
	}

	prevResult = test.GenerateIPAMResult("", ips, routes, dns)
	networkCfg2 := generateNetworkConfiguration("testCfg", "0.5.1")
	networkCfg2.RawPrevResult, _ = translateRawPrevResult(prevResult, cniVersion)
	prevResult, response = cniServer.parsePrevResultFromRequest(networkCfg2)
	if response == nil {
		t.Errorf("Failed to catch invalid PrevResult from request")
	} else if response.StatusCode != cnimsg.CniCmdResponseMessage_UNSUPPORTED_NETWORK_CONFIGURATION {
		t.Errorf("Failed to catch invalid PrevResult from request")
	}
}

func TestUpdateResultIfaceConfig(t *testing.T) {
	cniVersion := "0.3.1"
	testIps := []string{"10.1.2.100/24, ,4", "192.168.1.100/24, 192.168.2.253, 4"}
	result := test.GenerateIPAMResult(cniVersion, testIps, routes, dns)
	updateResultIfaceConfig(result, gwIP)
	if len(result.IPs) != 2 {
		t.Errorf("Failed to construct result")
	}
	for _, ipc := range result.IPs {
		if ipc.Address.IP.String() == "10.1.2.100" {
			if ipc.Gateway == nil || ipc.Gateway.String() != "10.1.2.1" {
				t.Errorf("Failed to calculate gateway")
			}
		} else if ipc.Address.IP.String() == "192.168.1.100" {
			if ipc.Gateway == nil || ipc.Gateway.String() != "192.168.2.253" {
				t.Errorf("Failed to calculate gateway")
			}
		} else {
			t.Errorf("Failed to identify ip address from result")
		}
	}
	emptyRoute := []string{}
	result = test.GenerateIPAMResult(cniVersion, testIps, emptyRoute, dns)
	updateResultIfaceConfig(result, testNodeConfig.Gateway.IP)
	if result.Routes == nil || len(result.Routes) == 0 {
		t.Error("Failed to add default route via node host gateway interface")
	} else {
		found := false
		for _, route := range result.Routes {
			if route.Dst.String() == "0.0.0.0/0" && route.GW.Equal(testNodeConfig.Gateway.IP) {
				found = true
				break
			}
		}
		if !found {
			t.Error("Failed to add default route via node host gateway interface")
		}
	}
}

func TestOVSOperations(t *testing.T) {
	controller := mock.NewController(t)
	defer controller.Finish()
	mockOVSdbClient := mocks.NewMockOVSdbClient(controller)
	ifaceStore := agent.NewInterfaceStore()
	cniVersion := "0.3.1"
	containerID := uuid.New().String()
	containerMACStr := "11:22:33:44:55:66"
	containerMAC, _ := net.ParseMAC(containerMACStr)
	containerIp := []string{"10.1.2.100/24,10.1.2.1,4"}
	result := test.GenerateIPAMResult(cniVersion, containerIp, routes, dns)
	containerIface := &current.Interface{Name: ifname, Sandbox: netns, Mac: containerMACStr}
	hostIfaceName := agent.GenerateContainerInterfaceName(testPodName, testPodNamespace)
	hostIface := &current.Interface{Name: hostIfaceName}
	result.Interfaces = []*current.Interface{hostIface, containerIface}
	fakePortUUID := uuid.New().String()
	containerConfig := buildContainerConfig(containerID, testPodName, testPodNamespace, containerIface, result.IPs)

	// Test successful add/check OVS port operations
	mockOVSdbClient.EXPECT().CreatePort(hostIfaceName, hostIfaceName, mock.Any()).Return(fakePortUUID, nil)
	portUUID, err := setupContainerOVSPort(mockOVSdbClient, containerConfig, hostIfaceName)
	if err != nil {
		t.Errorf("Failed to handle OVS success add")
	} else {
		containerConfig.OvsPortConfig = &agent.OvsPortConfig{PortUUID: portUUID, IfaceName: hostIfaceName}
		ifaceStore.AddInterface(hostIfaceName, containerConfig)
		if containerConfig.PortUUID != fakePortUUID {
			t.Errorf("Failed to cache OVS port UUID")
		}
	}
	err = validateOVSPort(ifaceStore, hostIfaceName, containerMACStr, containerID, result.IPs)
	if err != nil {
		t.Errorf("Failed to validate OVS port configuration")
	}

	// Test failed add OVS port and then remove local cache case
	failedContainerID := uuid.New().String()
	pod2 := "test-2"
	containerIP := net.ParseIP("10.1.2.101")
	failedOVSPortName := agent.GenerateContainerInterfaceName(pod2, testPodNamespace)
	containerConfig2 := agent.NewContainerInterface(failedContainerID, testPodName, testPodNamespace, "", containerMAC, containerIP)
	ifaceStore.AddInterface(failedOVSPortName, containerConfig2)
	mockOVSdbClient.EXPECT().CreatePort(failedOVSPortName, failedOVSPortName, mock.Any()).Return(
		"", test.NewDummyOVSConfigError("Error while create OVS port", true, true))
	failedhostIface := &current.Interface{Name: failedOVSPortName}
	result.Interfaces = []*current.Interface{failedhostIface, containerIface}
	_ = buildContainerConfig(failedContainerID, pod2, testPodNamespace, containerIface, result.IPs)
	_, err = setupContainerOVSPort(mockOVSdbClient, containerConfig2, failedOVSPortName)
	if err == nil {
		t.Errorf("Failed to handle OVS failed operation")
	}

	err = validateOVSPort(ifaceStore, hostIfaceName, containerMACStr, containerID, result.IPs)
	if err != nil {
		t.Errorf("Failed to compare success result from OVS service")
	}
}

func TestRemoveInterface(t *testing.T) {
	controller := mock.NewController(t)
	defer controller.Finish()
	ifaceStore := agent.NewInterfaceStore()
	mockOVSdbClient := mocks.NewMockOVSdbClient(controller)
	mockOFClient := mocks.NewMockOFClient(controller)
	cniVersion := "0.4.0"
	netcfg := generateNetworkConfiguration("testCfg", cniVersion)
	cniConfig := &CNIConfig{NetworkConfig: netcfg, CniCmdArgsMessage: &cnimsg.CniCmdArgsMessage{}}
	cniConfig.Ifname = "eth0"
	containerID := uuid.New().String()
	pod1 := "test1"
	hostIfaceName := agent.GenerateContainerInterfaceName(pod1, testPodNamespace)
	cniConfig.ContainerId = containerID
	cniConfig.Netns = ""
	containerMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	containerIP := net.ParseIP("1.1.1.1")
	fakePortUUID := uuid.New().String()
	containerConfig := agent.NewContainerInterface(containerID, pod1, testPodNamespace, "", containerMAC, containerIP)
	containerConfig.OvsPortConfig = &agent.OvsPortConfig{hostIfaceName, fakePortUUID, 0}
	mockOFClient.EXPECT().UninstallPodFlows(hostIfaceName).Return(nil)
	mockOVSdbClient.EXPECT().DeletePort(fakePortUUID).Return(nil)
	ifaceStore.AddInterface(hostIfaceName, containerConfig)

	err := removeInterfaces(mockOVSdbClient, mockOFClient, ifaceStore, pod1, testPodNamespace, containerID, cniConfig.Netns, cniConfig.Ifname)
	if err != nil {
		t.Errorf("Failed to remove interfaces")
	} else {
		_, found := ifaceStore.GetContainerInterface(pod1, testPodNamespace)
		if found {
			t.Errorf("Failed to remove from local cache")
		}
	}

	containerID2 := uuid.New().String()
	pod2 := "test2"
	hostIfaceName2 := agent.GenerateContainerInterfaceName(pod2, testPodNamespace)
	cniConfig.ContainerId = containerID2
	fakePortUUID2 := uuid.New().String()
	containerConfig2 := agent.NewContainerInterface(containerID2, pod2, testPodNamespace, "", containerMAC, containerIP)
	containerConfig2.OvsPortConfig = &agent.OvsPortConfig{hostIfaceName2, fakePortUUID2, 0}
	ifaceStore.AddInterface(hostIfaceName2, containerConfig2)
	mockOVSdbClient.EXPECT().DeletePort(fakePortUUID2).Return(test.NewDummyOVSConfigError("Failed to delete", true, true))
	mockOFClient.EXPECT().UninstallPodFlows(hostIfaceName2).Return(nil)
	err = removeInterfaces(mockOVSdbClient, mockOFClient, ifaceStore, pod2, testPodNamespace, containerID, "", cniConfig.Ifname)
	if err == nil {
		t.Errorf("Failed delete port on OVS")
	} else {
		_, found := ifaceStore.GetContainerInterface(pod2, testPodNamespace)
		if !found {
			t.Errorf("Failed to return after OVS delete failure")
		}
	}

	containerID3 := uuid.New().String()
	pod3 := "test3"
	hostIfaceName3 := agent.GenerateContainerInterfaceName(pod3, testPodNamespace)
	cniConfig.ContainerId = containerID3
	fakePortUUID3 := uuid.New().String()
	containerConfig3 := agent.NewContainerInterface(containerID3, pod3, testPodNamespace, "", containerMAC, containerIP)
	containerConfig3.OvsPortConfig = &agent.OvsPortConfig{hostIfaceName3, fakePortUUID3, 0}
	ifaceStore.AddInterface(hostIfaceName3, containerConfig3)
	mockOFClient.EXPECT().UninstallPodFlows(hostIfaceName3).Return(fmt.Errorf("failed to delete openflow entry"))
	err = removeInterfaces(mockOVSdbClient, mockOFClient, ifaceStore, pod3, testPodNamespace, containerID3, "", cniConfig.Ifname)
	if err == nil {
		t.Errorf("Failed delete openflow entries on OVS")
	} else {
		_, found := ifaceStore.GetContainerInterface(pod3, testPodNamespace)
		if !found {
			t.Errorf("Failed to return after OVS delete failure")
		}
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

	conf := &types.NetConf{}
	if err := json.Unmarshal(newBytes, &conf); err != nil {
		return nil, fmt.Errorf("Error while parsing configuration: %s", err)
	}
	return conf.RawPrevResult, nil
}

func generateCNIServer(t *testing.T) *CNIServer {
	supportedVersions := "0.3.0,0.3.1,0.4.0"
	cniServer := &CNIServer{cniSocket: testScock, nodeConfig: testNodeConfig, serverVersion: cni.OKNVersion}
	cniServer.supportedCNIVersions = buildVersionSet(supportedVersions)
	return cniServer
}

func generateNetworkConfiguration(name string, cniVersion string) *NetworkConfig {
	netCfg := new(NetworkConfig)
	netCfg.Name = name
	netCfg.CNIVersion = cniVersion
	netCfg.Type = "okn"
	netCfg.IPAM = ipam.IPAMConfig{Type: testIpamType}
	return netCfg
}

func newRequest(reqVersion string, args string, netCfg *NetworkConfig, path string, t *testing.T) (cnimsg.CniCmdRequestMessage, string) {
	containerId := generateUUID(t)
	networkConfig, err := json.Marshal(netCfg)
	if err != nil {
		t.Error("Failed to generate Network configuration")
	}

	cmdRequest := cnimsg.CniCmdRequestMessage{
		CniArgs: &cnimsg.CniCmdArgsMessage{
			ContainerId:          containerId,
			Ifname:               ifname,
			Args:                 args,
			Netns:                netns,
			NetworkConfiguration: networkConfig,
			Path:                 path,
		},
		Version: reqVersion,
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
	gwIP := net.ParseIP("192.168.1.1")
	_, nodePodCIDR, _ := net.ParseCIDR("192.168.1.0/24")
	gwMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	gateway := &agent.Gateway{Name: "gw", IP: gwIP, MAC: gwMAC}
	testNodeConfig = &agent.NodeConfig{testBr, nodeName, nodePodCIDR, gateway}
}
