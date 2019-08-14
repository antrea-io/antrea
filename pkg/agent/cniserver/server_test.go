package cniserver

import (
	"context"
	"encoding/json"
	"fmt"
	"okn/pkg/ovs/ovsconfig"
	"testing"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	mock "github.com/golang/mock/gomock"
	"github.com/google/uuid"
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
	test_ipam_type          = "test"
	testPodNamespace        = "test"
	testPodName             = "test-1"
	testPodInfraContainerID = "test-infra-11111111"
)

var routes = []string{"10.0.0.0/8,10.1.2.1", "0.0.0.0/0,10.1.2.1"}
var dns = []string{"192.168.100.1"}
var ips = []string{"10.1.2.100/24,10.1.2.1,4"}
var args string = test.GenerateCNIArgs(testPodName, testPodNamespace, testPodInfraContainerID)

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
	_ = ipam.RegisterIPAMDriver(test_ipam_type, ipamMock)
	testSupportedVersionStr := "0.3.0, 0.3.1, 0.4.0"
	var supporteVersions = []string{"0.3.0", "0.3.1", "0.4.0"}
	cniServer := &CNIServer{cniSocket: testScock, supportedCNIVersions: supportedCNIVersionSet, serverVersion: cni.OKNVersion}
	cniServer.supportedCNIVersions = buildVersionSet(testSupportedVersionStr)
	for _, ver := range supporteVersions {
		if !cniServer.isCNIVersionSupported(ver) {
			t.Errorf("CniService init failed for wrong supportedCNIVersions")
		}
	}
	isValid := ipam.IsIPAMTypeValid(test_ipam_type)
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

	networkCfg.Ifname = "eth1"
	prevResult, _ := cniServer.parsePrevResultFromRequest(networkCfg)
	containerID := uuid.New().String()
	networkCfg.ContainerId = containerID
	containerIface := &current.Interface{Name: ifname, Sandbox: netns}
	hostIfaceName := GenerateContainerPeerName(testPodName, testPodNamespace)
	hostIface := &current.Interface{Name: hostIfaceName}
	prevResult.Interfaces = []*current.Interface{hostIface, containerIface}
	response, _ := cniServer.validatePrevResult(networkCfg.CniCmdArgsMessage, k8sPodArgs, prevResult)
	if response == nil || response.StatusCode != cnimsg.CniCmdResponseMessage_UNKNOWN_CONTAINER {
		t.Errorf("Failed to catch invalid container interface from request")
	}

	networkCfg.Ifname = ifname
	networkCfg.Netns = "invalid_netns"
	response, _ = cniServer.validatePrevResult(networkCfg.CniCmdArgsMessage, k8sPodArgs, prevResult)
	if response == nil || response.StatusCode != cnimsg.CniCmdResponseMessage_CHECK_INTERFACE_FAILURE {
		t.Errorf("Failed to catch invalid container interface from request")
	}
	hostIface = &current.Interface{Name: "unknown_iface"}
	prevResult.Interfaces = []*current.Interface{hostIface, containerIface}
	response, _ = cniServer.validatePrevResult(networkCfg.CniCmdArgsMessage, k8sPodArgs, prevResult)
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
	updateResultIfaceConfig(result)
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
}

func TestParseContainerAttachInfo(t *testing.T) {
	containerID := uuid.New().String()
	cniVersion := "0.3.1"
	containerMAC := "aa:bb:cc:dd:ee:ff"
	result := test.GenerateIPAMResult(cniVersion, ips, routes, dns)
	containerIface := &current.Interface{Name: ifname, Sandbox: netns, Mac: containerMAC}
	containerConfig := buildContainerConfig(containerID, testPodName, testPodNamespace, containerIface, result.IPs)
	externalIds := parseContainerAttachInfo(containerID, containerConfig)
	parsedIP, existed := externalIds[OVSExternalIDIP]
	if !existed || parsedIP != "10.1.2.100" {
		t.Errorf("Failed to parse container configuration")
	}
	parsedMac, existed := externalIds[OVSExternalIDMAC]
	if !existed || parsedMac != containerMAC {
		t.Errorf("Failed to parse container configuration")
	}
	parsedID, existed := externalIds[OVSExternalIDContainerID]
	if !existed || parsedID != containerID {
		t.Errorf("Failed to parse container configuration")
	}
}

func TestOVSOperations(t *testing.T) {
	containerConfigCache = make(map[string]*ContainerConfig)
	controller := mock.NewController(t)
	defer controller.Finish()
	mockOVSdbClient := mocks.NewMockOVSdbClient(controller)
	cniVersion := "0.3.1"
	containerID := uuid.New().String()
	containerMAC := "11:22:33:44:55:66"
	containerIp := []string{"10.1.2.100/24,10.1.2.1,4"}
	result := test.GenerateIPAMResult(cniVersion, containerIp, routes, dns)
	containerIface := &current.Interface{Name: ifname, Sandbox: netns, Mac: containerMAC}
	hostIfaceName := GenerateContainerPeerName(testPodName, testPodNamespace)
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
		containerConfig.ovsPortConfig = &ovsPortConfig{ifaceName: hostIfaceName, portUUID: portUUID}
		containerConfigCache[containerID] = containerConfig
	}
	err = validateOVSPort(hostIfaceName, containerMAC, containerID, result.IPs)
	if err != nil {
		t.Errorf("Failed to validate OVS port configuration")
	}

	// Test failed add OVS port and then remove local cache case
	failedContainerID := uuid.New().String()
	pod2 := "test-2"
	failedOVSPortName := GenerateContainerPeerName(pod2, testPodNamespace)
	containerConfig2 := &ContainerConfig{id: failedContainerID, ip: "10.1.2.101", mac: containerMAC}
	containerConfigCache[failedContainerID] = containerConfig2
	mockOVSdbClient.EXPECT().CreatePort(failedOVSPortName, failedOVSPortName, mock.Any()).Return(
		"", mocks.NewMockOVSConfigError("Error while create OVS port", true, true))
	failedhostIface := &current.Interface{Name: failedOVSPortName}
	result.Interfaces = []*current.Interface{failedhostIface, containerIface}
	_ = buildContainerConfig(failedContainerID, pod2, testPodNamespace, containerIface, result.IPs)
	_, err = setupContainerOVSPort(mockOVSdbClient, containerConfig2, failedOVSPortName)
	if err == nil {
		t.Errorf("Failed to handle OVS failed operation")
	}

	ovsExternalIDs := make(map[string]string)
	ovsExternalIDs[OVSExternalIDContainerID] = containerID
	ovsExternalIDs[OVSExternalIDIP] = "10.1.2.100"
	ovsExternalIDs[OVSExternalIDMAC] = containerMAC
	err = validateOVSPort(hostIfaceName, containerMAC, containerID, result.IPs)
	if err != nil {
		t.Errorf("Failed to compare success result from OVS service")
	}
}

func TestRemoveInterface(t *testing.T) {
	containerConfigCache = make(map[string]*ContainerConfig)
	controller := mock.NewController(t)
	defer controller.Finish()
	mockOVSdbClient := mocks.NewMockOVSdbClient(controller)
	cniVersion := "0.4.0"
	netcfg := generateNetworkConfiguration("testCfg", cniVersion)
	netcfg.Ifname = "eth0"
	containerID := uuid.New().String()
	hostIfaceName := GenerateContainerPeerName(testPodName, testPodNamespace)
	netcfg.ContainerId = containerID
	netcfg.Netns = ""
	fakePortUUID := uuid.New().String()
	containerConfig := &ContainerConfig{id: containerID, ovsPortConfig: &ovsPortConfig{portUUID: fakePortUUID, ifaceName: hostIfaceName}}
	containerConfigCache[containerID] = containerConfig
	mockOVSdbClient.EXPECT().DeletePort(fakePortUUID).Return(nil)
	err := removeInterfaces(mockOVSdbClient, netcfg.ContainerId, netcfg.Netns, netcfg.Ifname)
	if err != nil {
		t.Errorf("Failed to remove interfaces")
	} else {
		_, found := containerConfigCache[containerID]
		if found {
			t.Errorf("Failed to remove from local cache")
		}
	}

	containerID2 := uuid.New().String()
	pod2 := "test2"
	hostIfaceName2 := GenerateContainerPeerName(pod2, testPodNamespace)
	netcfg.ContainerId = containerID2
	netcfg.Netns = ""
	fakePortUUID2 := uuid.New().String()
	containerConfig2 := &ContainerConfig{id: containerID2, ovsPortConfig: &ovsPortConfig{portUUID: fakePortUUID2, ifaceName: hostIfaceName2}}
	containerConfigCache[containerID2] = containerConfig2
	mockOVSdbClient.EXPECT().DeletePort(fakePortUUID2).Return(mocks.NewMockOVSConfigError("Failed to delete", true, true))
	err = removeInterfaces(mockOVSdbClient, containerID2, "", netcfg.Ifname)
	if err == nil {
		t.Errorf("Failed delete port on OVS")
	} else {
		_, found := containerConfigCache[containerID2]
		if !found {
			t.Errorf("Failed to return after OVS delete failure")
		}
	}
}

func TestInitCache(t *testing.T) {
	containerConfigCache = make(map[string]*ContainerConfig)
	controller := mock.NewController(t)
	defer controller.Finish()
	mockOVSdbClient := mocks.NewMockOVSdbClient(controller)

	mockOVSdbClient.EXPECT().GetPortList().Return(nil, mocks.NewMockOVSConfigError("Failed to list OVS ports", true, true))
	err := initCache(mockOVSdbClient)
	if err == nil {
		t.Errorf("Failed to handle OVS return error")
	}

	uuid1 := uuid.New().String()
	p1Mac := "11:22:33:44:55:66"
	p1IP := "1.1.1.1"
	ovsPort1 := ovsconfig.OVSPortData{UUID: uuid.New().String(), Name: "p1", IFName: "p1", OFPort: 1,
		ExternalIDs: map[string]string{OVSExternalIDContainerID: uuid1,
			OVSExternalIDMAC: p1Mac, OVSExternalIDIP: p1IP}}
	uuid2 := uuid.New().String()
	ovsPort2 := ovsconfig.OVSPortData{UUID: uuid.New().String(), Name: "p2", IFName: "p2", OFPort: 2,
		ExternalIDs: map[string]string{OVSExternalIDContainerID: uuid2,
			OVSExternalIDMAC: "11:22:33:44:55:77", OVSExternalIDIP: "1.1.1.2"}}
	initOVSPorts := []ovsconfig.OVSPortData{ovsPort1, ovsPort2}

	mockOVSdbClient.EXPECT().GetPortList().Return(initOVSPorts, mocks.NewMockOVSConfigError("Failed to list OVS ports", true, true))
	err = initCache(mockOVSdbClient)
	if len(containerConfigCache) != 0 {
		t.Errorf("Failed to load OVS port in initCache")
	}

	ovsPort2.OFPort = 2
	mockOVSdbClient.EXPECT().GetPortList().Return(initOVSPorts, nil)
	err = initCache(mockOVSdbClient)
	if len(containerConfigCache) != 2 {
		t.Errorf("Failed to load OVS port in initCache")
	}
	container1, found1 := containerConfigCache[uuid1]
	if !found1 {
		t.Errorf("Failed to load OVS port into local cache")
	} else if container1.ofport != 1 || container1.ip != p1IP || container1.mac != p1Mac || container1.ifaceName != "p1" {
		t.Errorf("Failed to load OVS port configuration into local cache")
	}
	_, found2 := containerConfigCache[uuid2]
	if !found2 {
		t.Errorf("Failed to load OVS port into local cache")
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
	cniServer := &CNIServer{
		cniSocket:            testScock,
		supportedCNIVersions: buildVersionSet(supportedVersions),
		serverVersion:        cni.OKNVersion,
	}
	return cniServer
}

func generateNetworkConfiguration(name string, cniVersion string) *NetworkConfig {
	netCfg := new(NetworkConfig)
	netCfg.Name = name
	netCfg.CNIVersion = cniVersion
	netCfg.Type = "okn"
	netCfg.IPAM = types.IPAM{Type: test_ipam_type}
	netCfg.CniCmdArgsMessage = &cnimsg.CniCmdArgsMessage{Args: args}
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
