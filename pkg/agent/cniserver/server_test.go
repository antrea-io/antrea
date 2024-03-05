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
	"reflect"
	"strings"
	"testing"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	ipamtest "antrea.io/antrea/pkg/agent/cniserver/ipam/testing"
	cniservertest "antrea.io/antrea/pkg/agent/cniserver/testing"
	types "antrea.io/antrea/pkg/agent/cniserver/types"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	routetest "antrea.io/antrea/pkg/agent/route/testing"
	"antrea.io/antrea/pkg/agent/util"
	cnipb "antrea.io/antrea/pkg/apis/cni/v1beta1"
	"antrea.io/antrea/pkg/cni"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	utilip "antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/wait"
)

const (
	netns                   = "ns-1"
	ifname                  = "eth0"
	testSocket              = "/tmp/test.sock"
	testIpamType            = "test"
	testIpamType2           = "test-2"
	testPodNamespace        = "test"
	testPodNameA            = "A-1"
	testPodNameB            = "B-1"
	testPodInfraContainerID = "test-infra-11111111"
	supportedCNIVersion     = "0.4.0"
	unsupportedCNIVersion   = "0.5.1"
)

var (
	routes         = []string{"10.0.0.0/8,10.1.2.1", "0.0.0.0/0,10.1.2.1"}
	dns            = []string{"192.168.100.1"}
	ips            = []string{"10.1.2.100/24,10.1.2.1,4"}
	ipamResult     = ipamtest.GenerateIPAMResult([]string{"10.1.2.100/24,10.1.2.1,4"}, []string{"10.0.0.0/8,10.1.2.1", "0.0.0.0/0,10.1.2.1"}, []string{"192.168.100.1"})
	args           = cniservertest.GenerateCNIArgs(testPodNameA, testPodNamespace, testPodInfraContainerID)
	testNodeConfig *config.NodeConfig
	gwIPv4         net.IP
	gwIPv6         net.IP

	mockOVSBridgeClient *ovsconfigtest.MockOVSBridgeClient
	mockRoute           *routetest.MockInterface
	mockOFClient        *openflowtest.MockClient
	ifaceStore          interfacestore.InterfaceStore

	emptyResponse = &cnipb.CniCmdResponse{CniResult: []byte("")}

	nodeName = "node1"
	gwMAC    = utilip.MustParseMAC("00:00:11:11:11:11")
	pod1     = &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "p1",
			Namespace: testPodNamespace,
		},
		Spec: v1.PodSpec{
			NodeName: nodeName,
		},
	}
	pod2 = &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "p2",
			Namespace: testPodNamespace,
		},
		Spec: v1.PodSpec{
			NodeName:    nodeName,
			HostNetwork: true,
		},
	}
	pod3 = &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "p3",
			Namespace: testPodNamespace,
		},
		Spec: v1.PodSpec{
			NodeName: nodeName,
		},
	}
	normalInterface = &interfacestore.InterfaceConfig{
		InterfaceName: "iface1",
		Type:          interfacestore.ContainerInterface,
		IPs:           []net.IP{net.ParseIP("1.1.1.1")},
		MAC:           utilip.MustParseMAC("00:11:22:33:44:01"),
		OVSPortConfig: &interfacestore.OVSPortConfig{
			PortUUID: generateUUID(),
			OFPort:   int32(3),
		},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
			PodName:      pod1.Name,
			PodNamespace: testPodNamespace,
			ContainerID:  generateUUID(),
		},
	}
	staleInterface = &interfacestore.InterfaceConfig{
		InterfaceName: "iface3",
		Type:          interfacestore.ContainerInterface,
		OVSPortConfig: &interfacestore.OVSPortConfig{
			PortUUID: generateUUID(),
			OFPort:   int32(4),
		},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
			PodName:      "non-existing-pod",
			PodNamespace: testPodNamespace,
			ContainerID:  generateUUID(),
		},
	}
	unconnectedInterface = &interfacestore.InterfaceConfig{
		InterfaceName: "iface4",
		Type:          interfacestore.ContainerInterface,
		IPs:           []net.IP{net.ParseIP("1.1.1.2")},
		MAC:           utilip.MustParseMAC("00:11:22:33:44:02"),
		OVSPortConfig: &interfacestore.OVSPortConfig{
			PortUUID: generateUUID(),
			OFPort:   int32(-1),
		},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
			PodName:      pod3.Name,
			PodNamespace: testPodNamespace,
			ContainerID:  generateUUID(),
		},
	}
)

func TestLoadNetConfig(t *testing.T) {
	assert := assert.New(t)
	cniService := newCNIServer(t)
	ipamType := "TestLoadNetConfig"
	networkCfg := generateNetworkConfiguration("", supportedCNIVersion, "", ipamType)
	requestMsg, containerID := newRequest(args, networkCfg, "", t)
	ipam.RegisterIPAMDriver(ipamType, nil)
	netCfg, resp := cniService.validateRequestMessage(requestMsg)

	// just make sure that cniService.nodeConfig matches the testNodeConfig.
	require.Equal(t, testNodeConfig, cniService.nodeConfig)

	assert.Nil(resp, "Error while parsing request message, %v", resp)
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

func TestCNIVersionCheck(t *testing.T) {
	valid := IsCNIVersionSupported(unsupportedCNIVersion)
	if valid {
		t.Error("Failed to return error for unsupported version")
	}
	valid = IsCNIVersionSupported(supportedCNIVersion)
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

// networkConfigIPAMMatcher is used to validate the IPAMConfig received by the IPAM driver mock.
type networkConfigIPAMMatcher struct {
	ipamConfig *types.IPAMConfig
}

func (m *networkConfigIPAMMatcher) Matches(x interface{}) bool {
	var networkConfig types.NetworkConfig
	if err := json.Unmarshal(x.([]byte), &networkConfig); err != nil {
		return false
	}
	return reflect.DeepEqual(networkConfig.IPAM, m.ipamConfig)
}

func (m *networkConfigIPAMMatcher) String() string {
	return fmt.Sprintf("IPAMConfig is equal to %v", m.ipamConfig)
}

func TestIPAMService(t *testing.T) {
	networkCfg := generateNetworkConfiguration("", supportedCNIVersion, "", testIpamType)

	setup := func(t *testing.T) (*ipamtest.MockIPAMDriver, *CNIServer, *cnipb.CniCmdRequest) {
		// required to provide isolation between subtests
		// note that subtests CANNOT share an instance of gomock.Controller
		ipam.ResetIPAMDrivers(testIpamType)
		controller := gomock.NewController(t)
		ipamMock := ipamtest.NewMockIPAMDriver(controller)
		ipam.RegisterIPAMDriver(testIpamType, ipamMock)
		cniServer := newCNIServer(t)
		ifaceStore := interfacestore.NewInterfaceStore()
		cniServer.podConfigurator = &podConfigurator{ifaceStore: ifaceStore}

		require.True(t, ipam.IsIPAMTypeValid(testIpamType), "Failed to register IPAM service")
		require.False(t, ipam.IsIPAMTypeValid("not_a_valid_IPAM_driver"))
		requestMsg, _ := newRequest(args, networkCfg, "", t)
		return ipamMock, cniServer, requestMsg
	}

	// Test IPAM_Failure cases
	cxt := context.Background()

	expectedIPAMConfig := &types.IPAMConfig{
		Type: testIpamType,
		Ranges: []types.RangeSet{
			[]types.Range{
				{
					Subnet:  testNodeConfig.PodIPv4CIDR.String(),
					Gateway: testNodeConfig.GatewayConfig.IPv4.String(),
				},
			},
			[]types.Range{
				{
					Subnet:  testNodeConfig.PodIPv6CIDR.String(),
					Gateway: testNodeConfig.GatewayConfig.IPv6.String(),
				},
			},
		},
	}

	t.Run("Error on ADD", func(t *testing.T) {
		ipamMock, cniServer, requestMsg := setup(t)
		ipamMock.EXPECT().Add(gomock.Any(), gomock.Any(), &networkConfigIPAMMatcher{expectedIPAMConfig}).Return(true, nil, fmt.Errorf("IPAM add error"))
		// Del call triggered by automatic rollback.
		// IPAMConfig should be the same for both calls (Add and Del).
		ipamMock.EXPECT().Del(gomock.Any(), gomock.Any(), &networkConfigIPAMMatcher{expectedIPAMConfig}).Return(true, nil)
		response, err := cniServer.CmdAdd(cxt, requestMsg)
		require.Nil(t, err, "expected no rpc error")
		checkErrorResponse(t, response, cnipb.ErrorCode_IPAM_FAILURE, "IPAM add error")
	})

	t.Run("Error on DEL", func(t *testing.T) {
		ipamMock, cniServer, requestMsg := setup(t)
		// Prepare cached IPAM result which will be deleted later.
		ipamMock.EXPECT().Add(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil, nil)
		cniConfig, _ := cniServer.validateRequestMessage(requestMsg)
		_, err := ipam.ExecIPAMAdd(cniConfig.CniCmdArgs, cniConfig.K8sArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no Add error")
		ipamMock.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, fmt.Errorf("IPAM delete error"))
		response, err := cniServer.CmdDel(cxt, requestMsg)
		require.Nil(t, err, "expected no rpc error")
		checkErrorResponse(t, response, cnipb.ErrorCode_IPAM_FAILURE, "IPAM delete error")

		// Cached result would be removed after a successful retry of IPAM DEL.
		ipamMock.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
		err = ipam.ExecIPAMDelete(cniConfig.CniCmdArgs, cniConfig.K8sArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no Del error")

	})

	t.Run("Error on CHECK", func(t *testing.T) {
		ipamMock, cniServer, requestMsg := setup(t)
		ipamMock.EXPECT().Check(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, fmt.Errorf("IPAM check error"))
		response, err := cniServer.CmdCheck(cxt, requestMsg)
		require.Nil(t, err, "expected no rpc error")
		checkErrorResponse(t, response, cnipb.ErrorCode_IPAM_FAILURE, "IPAM check error")
	})

	t.Run("Idempotent Call of IPAM ADD/DEL for the same Pod", func(t *testing.T) {
		ipamMock, cniServer, requestMsg := setup(t)
		ipamMock.EXPECT().Add(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil, nil)
		ipamMock.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil).Times(2)
		cniConfig, response := cniServer.validateRequestMessage(requestMsg)
		require.Nil(t, response, "expected no rpc error")
		ipamResult, err := ipam.ExecIPAMAdd(cniConfig.CniCmdArgs, cniConfig.K8sArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no IPAM add error")
		ipamResult2, err := ipam.ExecIPAMAdd(cniConfig.CniCmdArgs, cniConfig.K8sArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no IPAM add error")
		assert.Equal(t, ipamResult, ipamResult2)
		err = ipam.ExecIPAMDelete(cniConfig.CniCmdArgs, cniConfig.K8sArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no IPAM del error")
		err = ipam.ExecIPAMDelete(cniConfig.CniCmdArgs, cniConfig.K8sArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no IPAM del error")
	})

	t.Run("Idempotent Call of IPAM ADD/DEL for the same Pod with different containers", func(t *testing.T) {
		ipamMock, cniServer, requestMsg := setup(t)
		ipamMock.EXPECT().Add(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil, nil).Times(2)
		ipamMock.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil).Times(2)
		cniConfig, response := cniServer.validateRequestMessage(requestMsg)
		require.Nil(t, response, "expected no rpc error")
		_, err := ipam.ExecIPAMAdd(cniConfig.CniCmdArgs, cniConfig.K8sArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no IPAM add error")
		workerContainerID := "test-infra-2222222"
		args2 := cniservertest.GenerateCNIArgs(testPodNameA, testPodNamespace, workerContainerID)
		requestMsg2, _ := newRequest(args2, networkCfg, "", t)
		cniConfig2, response := cniServer.validateRequestMessage(requestMsg2)
		require.Nil(t, response, "expected no rpc error")
		_, err = ipam.ExecIPAMAdd(cniConfig2.CniCmdArgs, cniConfig.K8sArgs, cniConfig.IPAM.Type, cniConfig2.getInfraContainer())
		require.Nil(t, err, "expected no IPAM add error")
		err = ipam.ExecIPAMDelete(cniConfig.CniCmdArgs, cniConfig.K8sArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no IPAM del error")
		err = ipam.ExecIPAMDelete(cniConfig2.CniCmdArgs, cniConfig.K8sArgs, cniConfig.IPAM.Type, cniConfig2.getInfraContainer())
		require.Nil(t, err, "expected no IPAM del error")
	})
}

func TestIPAMServiceMultiDriver(t *testing.T) {
	controller := gomock.NewController(t)

	mockDriverA := ipamtest.NewMockIPAMDriver(controller)
	mockDriverB := ipamtest.NewMockIPAMDriver(controller)

	ipam.RegisterIPAMDriver(testIpamType2, mockDriverA)
	ipam.RegisterIPAMDriver(testIpamType2, mockDriverB)
	cniServer := newCNIServer(t)
	ifaceStore := interfacestore.NewInterfaceStore()
	cniServer.podConfigurator = &podConfigurator{ifaceStore: ifaceStore}

	require.True(t, ipam.IsIPAMTypeValid(testIpamType2), "Failed to register IPAM service")
	require.False(t, ipam.IsIPAMTypeValid("not_a_valid_IPAM_driver"))

	// Test IPAM_Failure cases
	cxt := context.Background()
	networkCfg := generateNetworkConfiguration("", supportedCNIVersion, "", testIpamType2)

	argsPodA := cniservertest.GenerateCNIArgs(testPodNameA, testPodNamespace, testPodInfraContainerID)
	argsPodB := cniservertest.GenerateCNIArgs(testPodNameB, testPodNamespace, testPodInfraContainerID)
	requestMsgA, _ := newRequest(argsPodA, networkCfg, "", t)
	requestMsgB, _ := newRequest(argsPodB, networkCfg, "", t)

	ips := []string{"10.1.2.100/24,10.1.2.1,4"}
	routes := []string{"10.0.0.0/8,10.1.2.1", "0.0.0.0/0,10.1.2.1"}
	dns := []string{"192.168.100.1"}
	ipamResult := &ipam.IPAMResult{Result: *ipamtest.GenerateIPAMResult(ips, routes, dns)}

	t.Run("Error on ADD for first registered driver", func(t *testing.T) {
		mockDriverA.EXPECT().Add(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil, fmt.Errorf("IPAM add error"))
		mockDriverA.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
		response, err := cniServer.CmdAdd(cxt, requestMsgA)
		require.Nil(t, err, "expected no rpc error")
		checkErrorResponse(t, response, cnipb.ErrorCode_IPAM_FAILURE, "IPAM add error")
	})

	t.Run("Error on ADD for second registered driver", func(t *testing.T) {
		mockDriverA.EXPECT().Add(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil, nil)
		mockDriverB.EXPECT().Add(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil, fmt.Errorf("IPAM add error"))
		mockDriverA.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil)
		mockDriverB.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
		response, err := cniServer.CmdAdd(cxt, requestMsgB)
		require.Nil(t, err, "expected no rpc error")
		checkErrorResponse(t, response, cnipb.ErrorCode_IPAM_FAILURE, "IPAM add error")
	})

	t.Run("Error on DEL for first registered driver", func(t *testing.T) {
		// Prepare cached IPAM result which will be deleted later.
		mockDriverA.EXPECT().Add(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, ipamResult, nil)
		cniConfig, _ := cniServer.validateRequestMessage(requestMsgA)
		_, err := ipam.ExecIPAMAdd(cniConfig.CniCmdArgs, cniConfig.K8sArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no Add error")

		mockDriverA.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, fmt.Errorf("IPAM delete error"))
		response, err := cniServer.CmdDel(cxt, requestMsgA)
		require.Nil(t, err, "expected no rpc error")
		checkErrorResponse(t, response, cnipb.ErrorCode_IPAM_FAILURE, "IPAM delete error")

		// Cached result would be removed after a successful retry of IPAM DEL.
		mockDriverA.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
		err = ipam.ExecIPAMDelete(cniConfig.CniCmdArgs, cniConfig.K8sArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no Del error")

	})

	t.Run("Error on DEL for second registered driver", func(t *testing.T) {
		// Prepare cached IPAM result which will be deleted later.
		mockDriverA.EXPECT().Add(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil, nil)
		mockDriverB.EXPECT().Add(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, ipamResult, nil)
		cniConfig, _ := cniServer.validateRequestMessage(requestMsgB)
		_, err := ipam.ExecIPAMAdd(cniConfig.CniCmdArgs, cniConfig.K8sArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no Add error")

		mockDriverA.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil)
		mockDriverB.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, fmt.Errorf("IPAM delete error"))
		response, err := cniServer.CmdDel(cxt, requestMsgB)
		require.Nil(t, err, "expected no rpc error")
		checkErrorResponse(t, response, cnipb.ErrorCode_IPAM_FAILURE, "IPAM delete error")

		// Cached result would be removed after a successful retry of IPAM DEL.
		mockDriverA.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil)
		mockDriverB.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
		err = ipam.ExecIPAMDelete(cniConfig.CniCmdArgs, cniConfig.K8sArgs, cniConfig.IPAM.Type, cniConfig.getInfraContainer())
		require.Nil(t, err, "expected no Del error")

	})

	t.Run("Error on CHECK for first registered driver", func(t *testing.T) {
		mockDriverA.EXPECT().Check(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, fmt.Errorf("IPAM check error"))
		response, err := cniServer.CmdCheck(cxt, requestMsgA)
		require.Nil(t, err, "expected no rpc error")
		checkErrorResponse(t, response, cnipb.ErrorCode_IPAM_FAILURE, "IPAM check error")
	})

	t.Run("Error on CHECK for second registered driver", func(t *testing.T) {
		mockDriverA.EXPECT().Check(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil)
		mockDriverB.EXPECT().Check(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, fmt.Errorf("IPAM check error"))
		response, err := cniServer.CmdCheck(cxt, requestMsgB)
		require.Nil(t, err, "expected no rpc error")
		checkErrorResponse(t, response, cnipb.ErrorCode_IPAM_FAILURE, "IPAM check error")
	})
}

func TestValidateRequestMessage(t *testing.T) {
	hostLocal := "host-local"
	ipam.RegisterIPAMDriver(hostLocal, nil)
	ipam.RegisterIPAMDriver(ipam.AntreaIPAMType, nil)
	cniServer := newCNIServer(t)

	type testCase struct {
		test                       string
		cniVersion                 string
		cniType                    string
		ipamType                   string
		isChaining                 bool
		enableBridgingMode         bool
		enableSecondaryNetworkIPAM bool
		resIPAMType                string
		resSecondaryNetworkIPAM    bool
		errorCode                  cnipb.ErrorCode
	}

	testCases := []testCase{
		{
			test:       "Incompatible CNI version",
			cniVersion: unsupportedCNIVersion,
			errorCode:  cnipb.ErrorCode_INCOMPATIBLE_CNI_VERSION,
		},
		{
			test:      "Unknown CNI type",
			cniType:   "unknown",
			errorCode: cnipb.ErrorCode_UNSUPPORTED_FIELD,
		},
		{
			test:      "Unknown IPAM type",
			ipamType:  "unknown",
			errorCode: cnipb.ErrorCode_UNSUPPORTED_FIELD,
		},
		{
			test:        "host-local",
			ipamType:    hostLocal,
			resIPAMType: hostLocal,
		},
		{
			test:        "antrea-ipam",
			ipamType:    ipam.AntreaIPAMType,
			resIPAMType: ipam.AntreaIPAMType,
		},
		{
			test:               "host-local in bridging mode",
			ipamType:           hostLocal,
			enableBridgingMode: true,
			resIPAMType:        ipam.AntreaIPAMType,
		},
		{
			test:        "chaining",
			ipamType:    "unknown",
			isChaining:  true,
			resIPAMType: "unknown",
		},
		{
			test:      "IPAM for other CNI not enabled",
			cniType:   "unknown",
			ipamType:  ipam.AntreaIPAMType,
			errorCode: cnipb.ErrorCode_UNSUPPORTED_FIELD,
		},
		{
			test:                       "IPAM for other CNI with unsupported IPAM type",
			cniType:                    "unknown",
			ipamType:                   hostLocal,
			enableSecondaryNetworkIPAM: true,
			errorCode:                  cnipb.ErrorCode_UNSUPPORTED_FIELD,
		},
		{
			test:                       "IPAM for other CNI",
			cniType:                    "unknown",
			ipamType:                   ipam.AntreaIPAMType,
			resIPAMType:                ipam.AntreaIPAMType,
			resSecondaryNetworkIPAM:    true,
			enableSecondaryNetworkIPAM: true,
		},
	}

	for _, c := range testCases {
		t.Run(c.test, func(t *testing.T) {
			cniVersion := c.cniVersion
			if cniVersion == "" {
				cniVersion = supportedCNIVersion
			}
			ipamType := c.ipamType
			if ipamType == "" {
				ipamType = hostLocal
			}

			networkCfg := generateNetworkConfiguration("", cniVersion, c.cniType, ipamType)
			requestMsg, _ := newRequest(args, networkCfg, "", t)
			cniServer.isChaining = c.isChaining
			cniServer.enableBridgingMode = c.enableBridgingMode
			cniServer.enableSecondaryNetworkIPAM = c.enableSecondaryNetworkIPAM

			resCfg, response := cniServer.validateRequestMessage(requestMsg)
			if c.errorCode != 0 {
				assert.NotNil(t, response, "Error code %v is expected", c.errorCode)
				checkErrorResponse(t, response, c.errorCode, "")
				return
			}
			assert.Nil(t, response, "Unexpected error response: %v", response)

			assert.Equal(t, resCfg.IPAM.Type, c.resIPAMType)
			assert.Equal(t, resCfg.secondaryNetworkIPAM, c.resSecondaryNetworkIPAM)
		})
	}
}

func TestParsePrevResultFromRequest(t *testing.T) {
	cniServer := newCNIServer(t)

	getNetworkCfg := func(cniVersion string) *types.NetworkConfig {
		networkCfg := generateNetworkConfiguration("", cniVersion, "", testIpamType)
		networkCfg.PrevResult = nil
		networkCfg.RawPrevResult = nil
		return networkCfg
	}

	t.Run("Correct prevResult", func(t *testing.T) {
		networkCfg := getNetworkCfg(supportedCNIVersion)
		prevResult := ipamtest.GenerateIPAMResult(ips, routes, dns)
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
		prevResult := ipamtest.GenerateIPAMResult(ips, routes, dns)
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

		result := ipamtest.GenerateIPAMResult(testIps, routes, dns)
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
		result := ipamtest.GenerateIPAMResult(testIps, emptyRoutes, dns)
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
	ifaceStore := interfacestore.NewInterfaceStore()
	podConfigurator := &podConfigurator{ifaceStore: ifaceStore}
	containerID := uuid.New().String()
	containerMACStr := "11:22:33:44:55:66"
	containerIP := []string{"10.1.2.100/24,10.1.2.1,4"}
	result := ipamtest.GenerateIPAMResult(containerIP, routes, dns)
	containerIface := &current.Interface{Name: ifname, Sandbox: netns, Mac: containerMACStr}
	hostIfaceName := util.GenerateContainerInterfaceName(testPodNameA, testPodNamespace, containerID)
	hostIface := &current.Interface{Name: hostIfaceName}
	result.Interfaces = []*current.Interface{hostIface, containerIface}
	portUUID := uuid.New().String()
	containerConfig := buildContainerConfig(hostIfaceName, containerID, testPodNameA, testPodNamespace, containerIface, result.IPs, 0)
	containerConfig.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID}

	ifaceStore.AddInterface(containerConfig)
	err := podConfigurator.validateOVSInterfaceConfig(containerID, containerMACStr, result.IPs)
	assert.Nil(t, err, "Failed to validate OVS port configuration")
}

func TestBuildOVSPortExternalIDs(t *testing.T) {
	containerID := uuid.New().String()
	containerMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	containerIP1 := net.ParseIP("10.1.2.100")
	containerIP2 := net.ParseIP("2001:fd1a::2")
	containerIPs := []net.IP{containerIP1, containerIP2}
	containerConfig := interfacestore.NewContainerInterface("pod1-abcd", containerID,
		"test-1", "t1", "eth0", containerMAC, containerIPs, 0)
	externalIDs := BuildOVSPortExternalIDs(containerConfig)
	_, existed := externalIDs[ovsExternalIDIFDev]
	assert.False(t, existed, "External IDs should not include interface name eth0")
	parsedIP, existed := externalIDs[ovsExternalIDIP]
	parsedIPStr := parsedIP.(string)
	if !existed || !strings.Contains(parsedIPStr, "10.1.2.100") || !strings.Contains(parsedIPStr, "2001:fd1a::2") {
		t.Errorf("Failed to store IPs to external IDs")
	}
	parsedMac, existed := externalIDs[ovsExternalIDMAC]
	if !existed || parsedMac != containerMAC.String() {
		t.Errorf("Failed to store MAC to external IDs")
	}
	parsedID, existed := externalIDs[ovsExternalIDContainerID]
	if !existed || parsedID != containerID {
		t.Errorf("Failed to store container ID to external IDs")
	}

	testConfigParsingFn := func() {
		portExternalIDs := make(map[string]string)
		for k, v := range externalIDs {
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
		ifaceConfig := ParseOVSPortInterfaceConfig(mockPort, portConfig)
		assert.Equal(t, len(containerIPs), len(ifaceConfig.IPs))
		for _, ip1 := range containerIPs {
			existed := false
			for _, ip2 := range ifaceConfig.IPs {
				if ip2.Equal(ip1) {
					existed = true
					break
				}
			}
			assert.Truef(t, existed, "IP %s should exist in the restored InterfaceConfig", ip1.String())
		}
	}
	testConfigParsingFn()

	// Secondary interface with no IP.
	containerIPs = nil
	containerConfig = interfacestore.NewContainerInterface("pod1-abcd", containerID,
		"test-1", "t1", "eth1", containerMAC, containerIPs, 0)
	externalIDs = BuildOVSPortExternalIDs(containerConfig)
	parsedIFDev, existed := externalIDs[ovsExternalIDIFDev]
	assert.True(t, existed && parsedIFDev == "eth1")
	parsedIP, existed = externalIDs[ovsExternalIDIP]
	assert.True(t, existed && parsedIP.(string) == "")
	testConfigParsingFn()

}

func translateRawPrevResult(prevResult *current.Result, cniVersion string) (map[string]interface{}, error) {
	prevVersionedResult, err := prevResult.GetAsVersion(cniVersion)
	if err != nil {
		return nil, err
	}
	config := map[string]interface{}{
		"cniVersion": cniVersion,
		"prevResult": prevVersionedResult,
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
	cniServer := &CNIServer{
		cniSocket:       testSocket,
		nodeConfig:      testNodeConfig,
		serverVersion:   cni.AntreaCNIVersion,
		containerAccess: newContainerAccessArbitrator(),
		podNetworkWait:  wait.NewGroup(),
	}
	cniServer.networkConfig = &config.NetworkConfig{InterfaceMTU: 1450}
	return cniServer
}

func generateNetworkConfiguration(name, cniVersion, cniType, ipamType string) *types.NetworkConfig {
	netCfg := new(types.NetworkConfig)
	if name == "" {
		netCfg.Name = "test-network"
	} else {
		netCfg.Name = name
	}
	netCfg.CNIVersion = cniVersion
	if cniType == "" {
		netCfg.Type = AntreaCNIType
	} else {
		netCfg.Type = cniType
	}
	netCfg.IPAM = &types.IPAMConfig{Type: ipamType}
	return netCfg
}

func newRequest(args string, netCfg *types.NetworkConfig, path string, t *testing.T) (*cnipb.CniCmdRequest, string) {
	_, _, containerID := cniservertest.ParseCNIArgs(args)
	networkConfig, err := json.Marshal(netCfg)
	if err != nil {
		t.Error("Failed to generate Network configuration")
	}

	cmdRequest := &cnipb.CniCmdRequest{
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

func generateUUID() string {
	newID, _ := uuid.NewUUID()
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
