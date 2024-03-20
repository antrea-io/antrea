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
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/util/wait"
	fakeclientset "k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	ipamtest "antrea.io/antrea/pkg/agent/cniserver/ipam/testing"
	cniservertest "antrea.io/antrea/pkg/agent/cniserver/testing"
	"antrea.io/antrea/pkg/agent/cniserver/types"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	routetest "antrea.io/antrea/pkg/agent/route/testing"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	cnipb "antrea.io/antrea/pkg/apis/cni/v1beta1"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	"antrea.io/antrea/pkg/util/channel"
)

var (
	containerMACStr = "23:34:56:23:22:45"
	dnsSearches     = []string{"a.b.c.d"}
)

func TestUpdateResultDNSConfig(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cniConfig *CNIConfig
		expDNS    cnitypes.DNS
	}{
		{
			name: "only-dns",
			cniConfig: &CNIConfig{
				NetworkConfig: &types.NetworkConfig{
					DNS: cnitypes.DNS{
						Nameservers: []string{"8.8.8.8", "8.8.4.4"},
						Search:      []string{"a.b.c"},
					}},
			},
			expDNS: cnitypes.DNS{
				Nameservers: []string{"8.8.8.8", "8.8.4.4"},
				Search:      []string{"a.b.c"},
			},
		}, {
			name: "only-runtime-nameservers",
			cniConfig: &CNIConfig{
				NetworkConfig: &types.NetworkConfig{
					RuntimeConfig: types.RuntimeConfig{
						DNS: types.RuntimeDNS{
							Nameservers: []string{"1.1.1.1"},
						},
					},
				},
			},
			expDNS: cnitypes.DNS{
				Nameservers: []string{"1.1.1.1"},
			},
		}, {
			name: "only-runtime-search",
			cniConfig: &CNIConfig{
				NetworkConfig: &types.NetworkConfig{
					RuntimeConfig: types.RuntimeConfig{
						DNS: types.RuntimeDNS{
							Search: []string{"c.b.a"},
						},
					},
				},
			},
			expDNS: cnitypes.DNS{
				Search: []string{"c.b.a"},
			},
		}, {
			name: "replace-by-runtime-config",
			cniConfig: &CNIConfig{
				NetworkConfig: &types.NetworkConfig{
					DNS: cnitypes.DNS{
						Nameservers: []string{"8.8.8.8", "8.8.4.4"},
						Search:      []string{"a.b.c"},
					},
					RuntimeConfig: types.RuntimeConfig{
						DNS: types.RuntimeDNS{
							Nameservers: []string{"1.1.1.1"},
							Search:      []string{"c.b.a"},
						},
					},
				},
			},
			expDNS: cnitypes.DNS{
				Nameservers: []string{"1.1.1.1"},
				Search:      []string{"c.b.a"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := &current.Result{}
			updateResultDNSConfig(result, tc.cniConfig)
			assert.Equal(t, tc.expDNS, result.DNS)
		})
	}
}

func TestGetInfraContainer(t *testing.T) {
	for _, tc := range []struct {
		cniConfig           *CNIConfig
		expInfraContainerID string
		expDockerContainer  bool
	}{
		{
			cniConfig:           &CNIConfig{CniCmdArgs: &cnipb.CniCmdArgs{ContainerId: "a78fcd2a-ea86-4e36-b3c0-467c81423567", Netns: "none"}},
			expInfraContainerID: "a78fcd2a-ea86-4e36-b3c0-467c81423567",
			expDockerContainer:  true,
		},
		{
			cniConfig:           &CNIConfig{CniCmdArgs: &cnipb.CniCmdArgs{ContainerId: "a78fcd2a-ea86-4e36-b3c0-467c81423567", Netns: "container:14f294ed-4a06-444b-8198-eb44b4c26962"}},
			expInfraContainerID: "14f294ed-4a06-444b-8198-eb44b4c26962",
			expDockerContainer:  true,
		},
		{
			cniConfig:           &CNIConfig{CniCmdArgs: &cnipb.CniCmdArgs{ContainerId: "a78fcd2a-ea86-4e36-b3c0-467c81423567", Netns: "14f294ed-4a06-444b-8198-eb44b4c26962"}},
			expInfraContainerID: "a78fcd2a-ea86-4e36-b3c0-467c81423567",
			expDockerContainer:  false,
		},
	} {
		infraContainer := tc.cniConfig.getInfraContainer()
		assert.Equal(t, tc.expInfraContainerID, infraContainer)
		assert.Equal(t, tc.expDockerContainer, isDockerContainer(tc.cniConfig.Netns))
	}
}

var hostIfaces = sync.Map{}

func testHostInterfaceExists(ifaceName string) bool {
	_, exists := hostIfaces.Load(ifaceName)
	return exists
}

type hnsTestUtil struct {
	endpointID           string
	hostIfaceName        string
	existingHnsEndpoints []hcsshim.HNSEndpoint
	hnsEndpoint          *hcsshim.HNSEndpoint
	hcnEndpoint          *hcn.HostComputeEndpoint
	isDocker             bool
	isAttached           bool
	hnsEndpointCreatErr  error
	endpointAttachErr    error
}

func newHnsTestUtil(endpointID string, existingHnsEndpoints []hcsshim.HNSEndpoint, isDocker, isAttached bool, hnsEndpointCreatErr, endpointAttachErr error) *hnsTestUtil {
	return &hnsTestUtil{
		endpointID:           endpointID,
		existingHnsEndpoints: existingHnsEndpoints,
		isDocker:             isDocker,
		isAttached:           isAttached,
		hnsEndpointCreatErr:  hnsEndpointCreatErr,
		endpointAttachErr:    endpointAttachErr,
	}
}

func (t *hnsTestUtil) listHnsEndpointFunc() ([]hcsshim.HNSEndpoint, error) {
	return t.existingHnsEndpoints, nil
}

func (t *hnsTestUtil) createHnsEndpoint(request *hcsshim.HNSEndpoint) (*hcsshim.HNSEndpoint, error) {
	request.Id = t.endpointID
	request.MacAddress = containerMACStr
	t.hnsEndpoint = request
	t.hcnEndpoint = &hcn.HostComputeEndpoint{
		Id:                   request.Id,
		Name:                 request.Name,
		HostComputeNetwork:   request.VirtualNetworkName,
		HostComputeNamespace: "00000000-0000-0000-0000-000000000000",
	}
	t.hostIfaceName = fmt.Sprintf("vEthernet (%s)", request.Name)
	return request, t.hnsEndpointCreatErr
}

func (t *hnsTestUtil) getNamespaceEndpointIDs(namespace string) ([]string, error) {
	if t.isAttached {
		t.addHostInterface()
		return []string{t.endpointID}, nil
	}
	return []string{}, nil
}

func (t *hnsTestUtil) hotAttachEndpoint(containerID string, epID string) error {
	if t.endpointAttachErr == nil {
		hostIfaces.Store(t.hostIfaceName, false)
	}
	return t.endpointAttachErr
}

func (t *hnsTestUtil) isContainerAttachOnEndpoint(ep *hcsshim.HNSEndpoint, containerID string) (bool, error) {
	return t.isAttached, nil
}

func (t *hnsTestUtil) getHcnEndpointByID(epID string) (*hcn.HostComputeEndpoint, error) {
	return t.hcnEndpoint, nil
}

func (t *hnsTestUtil) deleteHnsEndpoint(endpoint *hcsshim.HNSEndpoint) (*hcsshim.HNSEndpoint, error) {
	return t.hnsEndpoint, nil
}

func (t *hnsTestUtil) attachEndpointInNamespace(ep *hcn.HostComputeEndpoint, namespace string) error {
	t.hcnEndpoint.HostComputeNamespace = namespace
	if t.endpointAttachErr == nil {
		t.addHostInterface()
	}
	return t.endpointAttachErr
}

func (t *hnsTestUtil) removeEndpointFromNamespace(namespace string, epID string) error {
	return nil
}

func (t *hnsTestUtil) setFunctions() {
	listHnsEndpointFunc = t.listHnsEndpointFunc
	createHnsEndpointFunc = t.createHnsEndpoint
	getNamespaceEndpointIDsFunc = t.getNamespaceEndpointIDs
	hotAttachEndpointFunc = t.hotAttachEndpoint
	attachEndpointInNamespaceFunc = t.attachEndpointInNamespace
	isContainerAttachOnEndpointFunc = t.isContainerAttachOnEndpoint
	getHcnEndpointByIDFunc = t.getHcnEndpointByID
	deleteHnsEndpointFunc = t.deleteHnsEndpoint
	removeEndpointFromNamespaceFunc = t.removeEndpointFromNamespace
}

func (t *hnsTestUtil) restore() {
	listHnsEndpointFunc = hcsshim.HNSListEndpointRequest
	createHnsEndpointFunc = createHnsEndpoint
	getNamespaceEndpointIDsFunc = hcn.GetNamespaceEndpointIds
	hotAttachEndpointFunc = hcsshim.HotAttachEndpoint
	attachEndpointInNamespaceFunc = attachEndpointInNamespace
	isContainerAttachOnEndpointFunc = isContainerAttachOnEndpoint
	getHcnEndpointByIDFunc = hcn.GetEndpointByID
	deleteHnsEndpointFunc = deleteHnsEndpoint
	removeEndpointFromNamespaceFunc = hcn.RemoveNamespaceEndpoint
}

func (t *hnsTestUtil) addHostInterface() {
	if _, exists := hostIfaces.Load(t.hostIfaceName); exists {
		return
	}
	go func() {
		select {
		case <-time.After(time.Millisecond * 650):
			hostIfaces.Store(t.hostIfaceName, false)
		}
	}()
}

func newMockCNIServer(t *testing.T, controller *gomock.Controller, podUpdateNotifier *channel.SubscribableChannel) *CNIServer {
	mockOVSBridgeClient = ovsconfigtest.NewMockOVSBridgeClient(controller)
	mockOFClient = openflowtest.NewMockClient(controller)
	mockRoute = routetest.NewMockInterface(controller)
	ifaceStore = interfacestore.NewInterfaceStore()
	cniServer := newCNIServer(t)
	cniServer.routeClient = mockRoute
	_, nodePodCIDRv4, _ := net.ParseCIDR("192.168.1.0/24")
	gwMAC, _ := net.ParseMAC("00:00:11:11:11:11")
	gateway := &config.GatewayConfig{Name: "", IPv4: gwIPv4, MAC: gwMAC}
	cniServer.nodeConfig = &config.NodeConfig{Name: "node1", PodIPv4CIDR: nodePodCIDRv4, GatewayConfig: gateway}
	cniServer.podConfigurator, _ = newPodConfigurator(mockOVSBridgeClient, mockOFClient, mockRoute, ifaceStore, gwMAC, "system", false, false, podUpdateNotifier)
	return cniServer
}

func prepareSetup(t *testing.T, ipamType string, name string, containerID, infraContainerID, netns string, prevResult *current.Result) (*cnipb.CniCmdRequest, string) {
	networkCfg := generateNetworkConfiguration("", supportedCNIVersion, "", ipamType)
	networkCfg.RuntimeConfig = types.RuntimeConfig{
		DNS: types.RuntimeDNS{
			Nameservers: dns,
			Search:      dnsSearches,
		},
	}
	if prevResult != nil {
		networkCfg.RawPrevResult, _ = translateRawPrevResult(prevResult, supportedCNIVersion)
	}
	podArgs := cniservertest.GenerateCNIArgs(name, testPodNamespace, containerID)
	requestMsg, _ := newRequest(podArgs, networkCfg, "", t)
	requestMsg.CniArgs.ContainerId = containerID
	requestMsg.CniArgs.Netns = netns
	hostIfaceName := util.GenerateContainerInterfaceName(name, testPodNamespace, infraContainerID)
	return requestMsg, hostIfaceName
}

func TestCmdAdd(t *testing.T) {
	controller := gomock.NewController(t)
	ipamType := "windows-test"
	ipamMock := ipamtest.NewMockIPAMDriver(controller)
	ipam.ResetIPAMDriver(ipamType, ipamMock)
	oriIPAMResult := &ipam.IPAMResult{Result: *ipamResult}
	ctx := context.TODO()

	dockerInfraContainer := "261a1970-5b6c-11ed-8caf-000c294e5d03"
	dockerWorkContainer := "261e579a-5b6c-11ed-8caf-000c294e5d03"
	unknownInfraContainer := generateUUID()
	containerdInfraContainer := generateUUID()

	defer mockHostInterfaceExists()()
	defer mockGetHnsNetworkByName()()
	defer mockSetInterfaceMTU(nil)()

	for _, tc := range []struct {
		name                 string
		podName              string
		containerID          string
		infraContainerID     string
		netns                string
		ipamAdd              bool
		ipamDel              bool
		ipamError            error
		oriIPAMResult        *ipam.IPAMResult
		hnsEndpointCreateErr error
		endpointAttachErr    error
		ifaceExist           bool
		isAttached           bool
		existingHnsEndpoints []hcsshim.HNSEndpoint
		endpointExists       bool
		connectOVS           bool
		containerIfaceExist  bool
		errResponse          *cnipb.CniCmdResponse
		expectedErr          error
	}{
		{
			name:                 "docker-infra-create-failure",
			podName:              "pod0",
			containerID:          dockerInfraContainer,
			infraContainerID:     dockerInfraContainer,
			netns:                "none",
			ipamAdd:              true,
			ipamDel:              true,
			hnsEndpointCreateErr: fmt.Errorf("unable to create HnsEndpoint"),
			errResponse: &cnipb.CniCmdResponse{
				Error: &cnipb.Error{
					Code:    cnipb.ErrorCode_CONFIG_INTERFACE_FAILURE,
					Message: "unable to create HnsEndpoint",
				},
			},
		}, {
			name:              "docker-infra-attach-failure",
			podName:           "pod1",
			containerID:       dockerInfraContainer,
			infraContainerID:  dockerInfraContainer,
			netns:             "none",
			ipamAdd:           true,
			ipamDel:           true,
			endpointAttachErr: fmt.Errorf("unable to attach HnsEndpoint"),
			errResponse: &cnipb.CniCmdResponse{
				Error: &cnipb.Error{
					Code:    cnipb.ErrorCode_CONFIG_INTERFACE_FAILURE,
					Message: "failed to configure container IP: unable to attach HnsEndpoint",
				},
			},
		}, {
			name:                "docker-infra-success",
			podName:             "pod2",
			containerID:         dockerInfraContainer,
			infraContainerID:    dockerInfraContainer,
			netns:               "none",
			ipamAdd:             true,
			connectOVS:          true,
			containerIfaceExist: true,
		}, {
			name:             "docker-workload-allocate-ip-failure",
			podName:          "pod3",
			containerID:      dockerWorkContainer,
			infraContainerID: unknownInfraContainer,
			netns:            fmt.Sprintf("container:%s", unknownInfraContainer),
			expectedErr:      fmt.Errorf("allocated IP address not found"),
		}, {
			name:             "docker-workload-no-endpoint",
			podName:          "pod4",
			containerID:      dockerWorkContainer,
			infraContainerID: dockerInfraContainer,
			netns:            fmt.Sprintf("container:%s", dockerInfraContainer),
			oriIPAMResult:    oriIPAMResult,
			errResponse: &cnipb.CniCmdResponse{
				Error: &cnipb.Error{
					Code:    cnipb.ErrorCode_CONFIG_INTERFACE_FAILURE,
					Message: "failed to find HNSEndpoint: pod4-6631b7",
				},
			},
		}, {
			name:              "docker-workload-attach-failure",
			podName:           "pod5",
			containerID:       dockerWorkContainer,
			infraContainerID:  dockerInfraContainer,
			netns:             fmt.Sprintf("container:%s", dockerInfraContainer),
			oriIPAMResult:     oriIPAMResult,
			endpointAttachErr: fmt.Errorf("unable to attach HnsEndpoint"),
			endpointExists:    true,
			errResponse: &cnipb.CniCmdResponse{
				Error: &cnipb.Error{
					Code:    cnipb.ErrorCode_CONFIG_INTERFACE_FAILURE,
					Message: "failed to configure container IP: unable to attach HnsEndpoint",
				},
			},
		}, {
			name:             "docker-workload-success",
			podName:          "pod6",
			containerID:      dockerWorkContainer,
			infraContainerID: dockerInfraContainer,
			netns:            fmt.Sprintf("container:%s", dockerInfraContainer),
			oriIPAMResult:    oriIPAMResult,
			endpointExists:   true,
		}, {
			name:             "docker-workload-already-attached",
			podName:          "pod7",
			containerID:      dockerWorkContainer,
			infraContainerID: dockerInfraContainer,
			netns:            fmt.Sprintf("container:%s", dockerInfraContainer),
			isAttached:       true,
			endpointExists:   true,
			oriIPAMResult:    oriIPAMResult,
		}, {
			name:                "containerd-success",
			podName:             "pod8",
			containerID:         containerdInfraContainer,
			infraContainerID:    containerdInfraContainer,
			netns:               generateUUID(),
			ipamAdd:             true,
			connectOVS:          true,
			containerIfaceExist: true,
		}, {
			name:                "containerd-already-attached",
			podName:             "pod9",
			containerID:         containerdInfraContainer,
			infraContainerID:    containerdInfraContainer,
			netns:               generateUUID(),
			oriIPAMResult:       oriIPAMResult,
			connectOVS:          true,
			containerIfaceExist: true,
			isAttached:          true,
		}, {
			name:              "containerd-attach-failure",
			podName:           "pod10",
			containerID:       containerdInfraContainer,
			infraContainerID:  containerdInfraContainer,
			netns:             generateUUID(),
			ipamDel:           true,
			oriIPAMResult:     oriIPAMResult,
			endpointAttachErr: fmt.Errorf("unable to attach HnsEndpoint"),
			errResponse: &cnipb.CniCmdResponse{
				Error: &cnipb.Error{
					Code:    cnipb.ErrorCode_CONFIG_INTERFACE_FAILURE,
					Message: "failed to configure container IP: unable to attach HnsEndpoint",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isDocker := isDockerContainer(tc.netns)
			testUtil := newHnsTestUtil(generateUUID(), tc.existingHnsEndpoints, isDocker, tc.isAttached, tc.hnsEndpointCreateErr, tc.endpointAttachErr)
			testUtil.setFunctions()
			defer testUtil.restore()
			waiter := newAsyncWaiter(tc.podName, tc.infraContainerID)
			server := newMockCNIServer(t, controller, waiter.notifier)
			requestMsg, ovsPortName := prepareSetup(t, ipamType, tc.podName, tc.containerID, tc.infraContainerID, tc.netns, nil)
			if tc.endpointExists {
				server.podConfigurator.ifConfigurator.(*ifConfigurator).addEndpoint(getHnsEndpoint(generateUUID(), ovsPortName))
			}
			if tc.oriIPAMResult != nil {
				ipam.AddIPAMResult(tc.infraContainerID, tc.oriIPAMResult)
			}
			if tc.ipamAdd {
				ipamMock.EXPECT().Add(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, oriIPAMResult, tc.ipamError).Times(1)
			}
			if tc.ipamDel {
				ipamMock.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil).Times(1)
			}
			ovsPortID := generateUUID()
			if tc.connectOVS {
				if isDocker {
					mockOVSBridgeClient.EXPECT().CreateInternalPort(ovsPortName, int32(0), gomock.Any(), gomock.Any()).Return(ovsPortID, nil).Times(1)
					mockOVSBridgeClient.EXPECT().GetOFPort(ovsPortName, false).Return(int32(100), nil).Times(1)
				} else {
					mockOVSBridgeClient.EXPECT().CreatePort(ovsPortName, ovsPortName, gomock.Any()).Return(ovsPortID, nil).Times(1)
					mockOVSBridgeClient.EXPECT().SetInterfaceType(ovsPortName, "internal").Return(nil).Times(1)
					mockOVSBridgeClient.EXPECT().GetOFPort(ovsPortName, true).Return(int32(100), nil).Times(1)
				}
				mockOFClient.EXPECT().InstallPodFlows(ovsPortName, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				mockRoute.EXPECT().AddLocalAntreaFlexibleIPAMPodRule(gomock.Any()).Return(nil).Times(1)
			}
			resp, err := server.CmdAdd(ctx, requestMsg)
			assert.Equal(t, tc.expectedErr, err)
			if tc.errResponse != nil {
				assert.Equal(t, tc.errResponse, resp)
			} else if tc.expectedErr == nil {
				cniResult := &current.Result{
					IPs:    oriIPAMResult.IPs,
					Routes: oriIPAMResult.Routes,
					DNS: cnitypes.DNS{
						Nameservers: dns,
						Search:      dnsSearches,
					},
					Interfaces: []*current.Interface{
						{Name: ovsPortName, Mac: containerMACStr, Sandbox: ""},
						{Name: "eth0", Mac: containerMACStr, Sandbox: tc.netns},
					},
				}
				versionedResult, err := cniResult.GetAsVersion(supportedCNIVersion)
				assert.NoError(t, err)
				successResponse := resultToResponse(versionedResult)
				assert.Equal(t, successResponse, resp)
			}
			containerID := requestMsg.CniArgs.ContainerId
			_, exists := ifaceStore.GetContainerInterface(containerID)
			assert.Equal(t, exists, tc.containerIfaceExist)
			if tc.connectOVS {
				waiter.wait()
				// Wait for the completion of async function "setInterfaceMTUFunc", otherwise it may lead to the
				// race condition failure.
				wait.PollUntilContextTimeout(context.Background(), time.Millisecond*10, time.Second, true,
					func(ctx context.Context) (done bool, err error) {
						mtuSet, exist := hostIfaces.Load(ovsPortName)
						if !exist {
							return false, nil
						}
						return mtuSet.(bool), nil
					})
			}
			waiter.close()
		})
	}
}

func TestCmdDel(t *testing.T) {
	controller := gomock.NewController(t)
	ipamType := "windows-test"
	ipamMock := ipamtest.NewMockIPAMDriver(controller)
	ipam.ResetIPAMDriver(ipamType, ipamMock)
	ctx := context.TODO()

	containerID := "261a1970-5b6c-11ed-8caf-000c294e5d03"
	containerMAC, _ := net.ParseMAC("11:22:33:44:33:22")

	defer mockHostInterfaceExists()()
	defer mockGetHnsNetworkByName()()
	defer mockSetInterfaceMTU(nil)()

	for _, tc := range []struct {
		name           string
		netns          string
		ipamDel        bool
		ipamError      error
		endpointExists bool
		disconnectOVS  bool
		ifaceExists    bool
		errResponse    *cnipb.CniCmdResponse
	}{
		{
			name:           "docker-infra-success",
			netns:          "none",
			ipamDel:        true,
			disconnectOVS:  true,
			endpointExists: true,
			ifaceExists:    true,
		},
		{
			name:    "interface-not-exist",
			netns:   "none",
			ipamDel: true,
		},
		{
			name:           "ipam-delete-failure",
			netns:          "none",
			ipamDel:        true,
			ipamError:      fmt.Errorf("unable to delete IP"),
			disconnectOVS:  true,
			endpointExists: true,
			ifaceExists:    true,
			errResponse: &cnipb.CniCmdResponse{
				Error: &cnipb.Error{
					Code:    cnipb.ErrorCode_IPAM_FAILURE,
					Message: "unable to delete IP",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isDocker := isDockerContainer(tc.netns)
			requestMsg, ovsPortName := prepareSetup(t, ipamType, testPodNameA, containerID, containerID, tc.netns, nil)
			hnsEndpoint := getHnsEndpoint(generateUUID(), ovsPortName)
			var existingHnsEndpoints []hcsshim.HNSEndpoint
			if tc.endpointExists {
				existingHnsEndpoints = append(existingHnsEndpoints, *hnsEndpoint)
			}
			testUtil := newHnsTestUtil(hnsEndpoint.Id, existingHnsEndpoints, isDocker, true, nil, nil)
			testUtil.setFunctions()
			defer testUtil.restore()
			waiter := newAsyncWaiter(testPodNameA, containerID)
			server := newMockCNIServer(t, controller, waiter.notifier)
			ovsPortID := generateUUID()
			if tc.endpointExists {
				server.podConfigurator.ifConfigurator.(*ifConfigurator).addEndpoint(hnsEndpoint)
			}
			if tc.ifaceExists {
				containerIface := interfacestore.NewContainerInterface(ovsPortName, containerID, testPodNameA, testPodNamespace, "", containerMAC, []net.IP{net.ParseIP("10.1.2.100")}, 0)
				containerIface.OVSPortConfig = &interfacestore.OVSPortConfig{
					OFPort:   100,
					PortUUID: ovsPortID,
				}
				ifaceStore.AddInterface(containerIface)
			}
			if tc.ipamDel {
				ipamMock.EXPECT().Del(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, tc.ipamError).Times(1)
			}
			if tc.disconnectOVS {
				mockOVSBridgeClient.EXPECT().DeletePort(ovsPortID).Return(nil).Times(1)
				mockOFClient.EXPECT().UninstallPodFlows(ovsPortName).Return(nil).Times(1)
				mockRoute.EXPECT().DeleteLocalAntreaFlexibleIPAMPodRule(gomock.Any()).Return(nil).Times(1)
			}
			resp, err := server.CmdDel(ctx, requestMsg)
			assert.NoError(t, err)
			if tc.errResponse != nil {
				assert.Equal(t, tc.errResponse, resp)
			} else {
				assert.Equal(t, emptyResponse, resp)
			}
			_, exists := ifaceStore.GetContainerInterface(containerID)
			assert.False(t, exists)
			if tc.endpointExists {
				_, exists = server.podConfigurator.ifConfigurator.(*ifConfigurator).getEndpoint(ovsPortName)
				assert.False(t, exists)
			}
			if tc.disconnectOVS {
				waiter.wait()
			}
			waiter.close()
		})
	}
}

func TestCmdCheck(t *testing.T) {
	controller := gomock.NewController(t)
	ipamType := "windows-test"
	ipamMock := ipamtest.NewMockIPAMDriver(controller)
	ipam.ResetIPAMDriver(ipamType, ipamMock)
	ctx := context.TODO()

	containerID := "261a1970-5b6c-11ed-8caf-000c294e5d03"
	mac, _ := net.ParseMAC("11:22:33:44:33:22")
	containerIP, containerIPNet, _ := net.ParseCIDR("10.1.2.100/24")
	containerIPNet.IP = containerIP

	defer mockHostInterfaceExists()()
	defer mockGetHnsNetworkByName()()
	defer mockSetInterfaceMTU(nil)()
	defer mockListHnsEndpoint(nil, nil)()
	defer mockGetNetInterfaceAddrs(containerIPNet, nil)()
	defer mockGetHnsEndpointByName(generateUUID(), mac)()

	wrapperIPAMResult := func(ipamResult current.Result, interfaces []*current.Interface) *current.Result {
		result := ipamResult
		index := 1
		result.IPs[0].Interface = &index
		result.Interfaces = interfaces
		return &result
	}
	wrapperContainerInterface := func(ifaceName, containerID, podName, ovsPortID string, mac net.HardwareAddr, containerIP net.IP) *interfacestore.InterfaceConfig {
		containerIface := interfacestore.NewContainerInterface(ifaceName, containerID, podName, testPodNamespace, "", mac, []net.IP{containerIP}, 0)
		containerIface.OVSPortConfig = &interfacestore.OVSPortConfig{
			PortUUID: ovsPortID,
			OFPort:   10,
		}
		return containerIface
	}

	for _, tc := range []struct {
		name               string
		podName            string
		containerID        string
		netns              string
		existingIface      *interfacestore.InterfaceConfig
		prevResult         *current.Result
		netInterface       *net.Interface
		getNetInterfaceErr error
		errResponse        *cnipb.CniCmdResponse
	}{
		{
			name:        "check-success",
			podName:     "pod0",
			netns:       "none",
			containerID: containerID,
			prevResult: wrapperIPAMResult(*ipamResult, []*current.Interface{
				{Name: "pod0-6631b7", Mac: "11:22:33:44:33:22", Sandbox: ""},
				{Name: "pod0-6631b7_eth0", Mac: "11:22:33:44:33:22", Sandbox: "none"},
			}),
			existingIface: wrapperContainerInterface("pod0-6631b7", containerID, "pod0", generateUUID(), mac, containerIP),
			netInterface: &net.Interface{
				Name:         "vEthernet (pod0-6631b7)",
				HardwareAddr: mac,
				Index:        4,
				Flags:        net.FlagUp,
			},
		}, {
			name:        "pod-namespace-mismatch",
			podName:     "pod1",
			netns:       "none",
			containerID: containerID,
			prevResult: wrapperIPAMResult(*ipamResult, []*current.Interface{
				{Name: "pod1-6631b7", Mac: "11:22:33:44:33:22", Sandbox: ""},
				{Name: "pod1-6631b7_eth0", Mac: "11:22:33:44:33:22", Sandbox: "invalid-namespace"},
			}),
			existingIface: wrapperContainerInterface("pod1-6631b7", containerID, "pod1", generateUUID(), mac, containerIP),
			netInterface: &net.Interface{
				Name:         "vEthernet (pod1-6631b7)",
				HardwareAddr: mac,
				Index:        4,
				Flags:        net.FlagUp,
			},
			errResponse: &cnipb.CniCmdResponse{
				Error: &cnipb.Error{
					Code:    cnipb.ErrorCode_CHECK_INTERFACE_FAILURE,
					Message: "sandbox in prevResult invalid-namespace doesn't match configured netns: none",
				},
			},
		}, {
			name:        "container-host-names-mismatch",
			podName:     "pod2",
			netns:       "none",
			containerID: containerID,
			prevResult: wrapperIPAMResult(*ipamResult, []*current.Interface{
				{Name: "pod2-6631b7", Mac: "11:22:33:44:33:22", Sandbox: ""},
				{Name: "eth0", Mac: "11:22:33:44:33:22", Sandbox: "none"},
			}),
			existingIface: wrapperContainerInterface("pod2-6631b7", containerID, "pod2", generateUUID(), mac, containerIP),
			netInterface: &net.Interface{
				Name:         "vEthernet (pod2-6631b7)",
				HardwareAddr: mac,
				Index:        4,
				Flags:        net.FlagUp,
			},
			errResponse: &cnipb.CniCmdResponse{
				Error: &cnipb.Error{
					Code:    cnipb.ErrorCode_CHECK_INTERFACE_FAILURE,
					Message: "unable to get net Interface with name vEthernet (eth0)",
				},
			},
		}, {
			name:        "container-host-MAC-mismatch",
			podName:     "pod3",
			netns:       "none",
			containerID: containerID,
			prevResult: wrapperIPAMResult(*ipamResult, []*current.Interface{
				{Name: "pod3-6631b7", Mac: "11:22:33:44:33:22", Sandbox: ""},
				{Name: "pod3-6631b7_eth0", Mac: "11:22:33:44:33:33", Sandbox: "none"},
			}),
			existingIface: wrapperContainerInterface("pod3-6631b7", containerID, "pod3", generateUUID(), mac, containerIP),
			netInterface: &net.Interface{
				Name:         "vEthernet (pod3-6631b7)",
				HardwareAddr: mac,
				Index:        4,
				Flags:        net.FlagUp,
			},
			errResponse: &cnipb.CniCmdResponse{
				Error: &cnipb.Error{
					Code:    cnipb.ErrorCode_CHECK_INTERFACE_FAILURE,
					Message: "container MAC in prevResult 11:22:33:44:33:33 doesn't match configured address: 11:22:33:44:33:22",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer mockGetNetInterfaceByName(tc.netInterface)()
			cniserver := newMockCNIServer(t, controller, channel.NewSubscribableChannel("podUpdate", 100))
			requestMsg, _ := prepareSetup(t, ipamType, tc.podName, tc.containerID, tc.containerID, tc.netns, tc.prevResult)
			ipamMock.EXPECT().Check(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil).Times(1)
			ifaceStore.AddInterface(tc.existingIface)
			resp, err := cniserver.CmdCheck(ctx, requestMsg)
			assert.NoError(t, err)
			if tc.errResponse != nil {
				assert.Equal(t, tc.errResponse, resp)
			} else {
				assert.Equal(t, emptyResponse, resp)
			}
		})
	}
}

type asyncWaiter struct {
	podName     string
	containerID string
	waitCh      chan struct{}
	stopCh      chan struct{}
	notifier    *channel.SubscribableChannel
}

func (w *asyncWaiter) notify(e interface{}) {
	podUpdate := e.(agenttypes.PodUpdate)
	if podUpdate.PodName == w.podName && podUpdate.ContainerID == w.containerID {
		w.waitCh <- struct{}{}
	}
}

func (w *asyncWaiter) wait() {
	<-w.waitCh
}

func (w *asyncWaiter) close() {
	close(w.waitCh)
	close(w.stopCh)
}

func newAsyncWaiter(podName, containerID string) *asyncWaiter {
	waiter := &asyncWaiter{
		podName:     podName,
		containerID: containerID,
		waitCh:      make(chan struct{}),
		stopCh:      make(chan struct{}),
		notifier:    channel.NewSubscribableChannel("PodUpdate", 100),
	}
	waiter.notifier.Subscribe(waiter.notify)
	go waiter.notifier.Run(waiter.stopCh)
	return waiter
}

func TestReconcile(t *testing.T) {
	controller := gomock.NewController(t)
	mockOVSBridgeClient = ovsconfigtest.NewMockOVSBridgeClient(controller)
	mockOFClient = openflowtest.NewMockClient(controller)
	ifaceStore = interfacestore.NewInterfaceStore()
	mockRoute = routetest.NewMockInterface(controller)

	defer mockHostInterfaceExists()()
	defer mockGetHnsNetworkByName()()
	missingEndpoint := getHnsEndpoint(generateUUID(), "iface4")
	testUtil := newHnsTestUtil(missingEndpoint.Id, []hcsshim.HNSEndpoint{*missingEndpoint}, false, true, nil, nil)
	testUtil.createHnsEndpoint(missingEndpoint)
	testUtil.setFunctions()
	defer testUtil.restore()

	cniServer := newCNIServer(t)
	cniServer.routeClient = mockRoute
	kubeClient := fakeclientset.NewSimpleClientset(pod1, pod2, pod3)
	cniServer.kubeClient = kubeClient
	for _, containerIface := range []*interfacestore.InterfaceConfig{normalInterface, staleInterface, unconnectedInterface} {
		ifaceStore.AddInterface(containerIface)
	}
	waiter := newAsyncWaiter(unconnectedInterface.PodName, unconnectedInterface.ContainerID)
	cniServer.podConfigurator, _ = newPodConfigurator(mockOVSBridgeClient, mockOFClient, mockRoute, ifaceStore, gwMAC, "system", false, false, waiter.notifier)
	cniServer.nodeConfig = &config.NodeConfig{Name: nodeName}

	// Re-install Pod1 flows
	podFlowsInstalled := make(chan string, 2)
	mockOFClient.EXPECT().InstallPodFlows(normalInterface.InterfaceName, normalInterface.IPs, normalInterface.MAC, uint32(normalInterface.OFPort), uint16(0), nil).
		Do(func(interfaceName string, _ []net.IP, _ net.HardwareAddr, _ uint32, _ uint16, _ *uint32) {
			podFlowsInstalled <- interfaceName
		}).Times(1)
	// Uninstall Pod3 flows which is deleted.
	mockOFClient.EXPECT().UninstallPodFlows(staleInterface.InterfaceName).Return(nil).Times(1)
	mockOVSBridgeClient.EXPECT().DeletePort(staleInterface.PortUUID).Return(nil).Times(1)
	mockRoute.EXPECT().DeleteLocalAntreaFlexibleIPAMPodRule(gomock.Any()).Return(nil).Times(1)
	// Re-connect to Pod4
	hostIfaces.Store(fmt.Sprintf("vEthernet (%s)", unconnectedInterface.InterfaceName), true)
	mockOVSBridgeClient.EXPECT().SetInterfaceType(unconnectedInterface.InterfaceName, "internal").Return(nil).Times(1)
	mockOVSBridgeClient.EXPECT().GetOFPort(unconnectedInterface.InterfaceName, true).Return(int32(5), nil).Times(1)
	mockOFClient.EXPECT().InstallPodFlows(unconnectedInterface.InterfaceName, unconnectedInterface.IPs, unconnectedInterface.MAC, uint32(5), uint16(0), nil).
		Do(func(interfaceName string, _ []net.IP, _ net.HardwareAddr, _ uint32, _ uint16, _ *uint32) {
			podFlowsInstalled <- interfaceName
		}).Times(1)
	err := cniServer.reconcile()
	assert.NoError(t, err)
	_, exists := ifaceStore.GetInterfaceByName("iface3")
	assert.False(t, exists)
	for i := 0; i < 2; i++ {
		select {
		case <-podFlowsInstalled:
		case <-time.After(500 * time.Millisecond):
			t.Errorf("InstallPodFlows should be called 2 times but was only called %d times", i)
			break
		}
	}
	waiter.wait()
	waiter.close()
}

func getHnsEndpoint(id, name string) *hcsshim.HNSEndpoint {
	return &hcsshim.HNSEndpoint{
		Id:                 id,
		Name:               name,
		VirtualNetworkName: util.LocalHNSNetwork,
		IPAddress:          net.ParseIP("10.1.2.100"),
		MacAddress:         containerMACStr,
		GatewayAddress:     "10.1.2.1",
		PrefixLength:       24,
	}
}

func getFakeHnsNetworkByName(network string) (*hcsshim.HNSNetwork, error) {
	return &hcsshim.HNSNetwork{
		Name:               network,
		Id:                 "8B692948-6FB3-4127-ABC7-BE9D12BE1E84",
		Type:               util.HNSNetworkType,
		NetworkAdapterName: "Ethernet0",
		SourceMac:          "00:50:56:b1:29:a2",
		Subnets: []hcsshim.Subnet{
			{
				AddressPrefix:  "10.1.2.0/24",
				GatewayAddress: "10.1.2.1",
			},
		},
		DNSSuffix:     "test.antrea",
		DNSServerList: "92.168.100.1",
		ManagementIP:  "10.10.10.10/28",
	}, nil
}

func mockHostInterfaceExists() func() {
	originalHostInterfaceExistsFunc := hostInterfaceExistsFunc
	hostInterfaceExistsFunc = testHostInterfaceExists
	return func() {
		hostInterfaceExistsFunc = originalHostInterfaceExistsFunc
	}
}

func mockGetHnsNetworkByName() func() {
	originalGetHnsNetworkByName := getHnsNetworkByNameFunc
	getHnsNetworkByNameFunc = getFakeHnsNetworkByName
	return func() {
		getHnsNetworkByNameFunc = originalGetHnsNetworkByName
	}
}
func mockGetNetInterfaceByName(netInterface *net.Interface) func() {
	originalGetNetInterfaceByName := getNetInterfaceByNameFunc
	getNetInterfaceByNameFunc = func(name string) (*net.Interface, error) {
		if netInterface.Name == name {
			return netInterface, nil
		}
		return nil, fmt.Errorf("unable to get net Interface with name %s", name)
	}
	return func() {
		getNetInterfaceByNameFunc = originalGetNetInterfaceByName
	}
}

func mockGetHnsEndpointByName(uuid string, mac net.HardwareAddr) func() {
	originalGetHnsEndpointByName := getHnsEndpointByNameFunc
	getHnsEndpointByNameFunc = func(endpointName string) (*hcsshim.HNSEndpoint, error) {
		endpoint := getHnsEndpoint(uuid, endpointName)
		endpoint.MacAddress = mac.String()
		return endpoint, nil
	}
	return func() {
		getHnsEndpointByNameFunc = originalGetHnsEndpointByName
	}
}

func mockGetNetInterfaceAddrs(containerIPNet *net.IPNet, err error) func() {
	originalGetNetInterfaceAddrs := getNetInterfaceAddrsFunc
	getNetInterfaceAddrsFunc = func(intf *net.Interface) ([]net.Addr, error) {
		return []net.Addr{containerIPNet}, nil
	}
	return func() {
		getNetInterfaceAddrsFunc = originalGetNetInterfaceAddrs
	}
}

func mockListHnsEndpoint(endpoints []hcsshim.HNSEndpoint, listError error) func() {
	originalListHnsEndpoint := listHnsEndpointFunc
	listHnsEndpointFunc = func() ([]hcsshim.HNSEndpoint, error) {
		return endpoints, listError
	}
	return func() {
		listHnsEndpointFunc = originalListHnsEndpoint
	}
}

func mockSetInterfaceMTU(setMTUError error) func() {
	originalSetInterfaceMTU := setInterfaceMTUFunc
	setInterfaceMTUFunc = func(ifaceName string, mtu int) error {
		if setMTUError == nil {
			hostIfaces.Store(ifaceName, true)
		}
		return setMTUError
	}
	return func() {
		setInterfaceMTUFunc = originalSetInterfaceMTU
	}
}
