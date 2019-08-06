package cniserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"google.golang.org/grpc"
	"k8s.io/klog"
	"okn/pkg/agent"
	"okn/pkg/agent/cniserver/ipam"
	"okn/pkg/apis/cni"
	"okn/pkg/cni"
	"okn/pkg/ovs/ovsconfig"
)

type CNIServer struct {
	cniSocket            string
	supportedCNIVersions map[string]bool
	serverVersion        string
	ovsBridgeClient      ovsconfig.OVSBridgeClient
	nodeConfig           *agent.NodeConfig
	ifaceStore           agent.InterfaceStore
}

const (
	hostVethLength       = 15
	supportedCNIVersions = "0.1.0,0.2.0,0.3.0,0.3.1,0.4.0"
	defaultMTU           = 1500
)

var supportedCNIVersionSet map[string]bool

type NetworkConfig struct {
	CNIVersion string          `json:"cniVersion,omitempty"`
	Name       string          `json:"name,omitempty"`
	Type       string          `json:"type,omitempty"`
	DNS        types.DNS       `json:"dns"`
	IPAM       ipam.IPAMConfig `json:"ipam,omitempty"`

	RawPrevResult map[string]interface{} `json:"prevResult,omitempty"`
	PrevResult    types.Result           `json:"-"`
}

type CNIConfig struct {
	*NetworkConfig
	*cnimsg.CniCmdArgsMessage
	*k8sArgs
}

func updateResultIfaceConfig(result *current.Result, defaultV4Gateway net.IP) {
	for _, ipc := range result.IPs {
		// result.Interfaces[0] is host interface, and result.Interfaces[1] is container interface
		ipc.Interface = current.Int(1)
		if ipc.Gateway == nil {
			ipn := ipc.Address
			netID := ipn.IP.Mask(ipn.Mask)
			ipc.Gateway = ip.NextIP(netID)
		}
	}

	foundDefaultRoute := false
	defaultRouteDst := "0.0.0.0/0"
	if result.Routes != nil {
		for _, route := range result.Routes {
			if route.Dst.String() == defaultRouteDst {
				foundDefaultRoute = true
				break
			}
		}
	} else {
		result.Routes = []*types.Route{}
	}
	if !foundDefaultRoute {
		_, defaultRouteDstNet, _ := net.ParseCIDR(defaultRouteDst)
		result.Routes = append(result.Routes, &types.Route{Dst: *defaultRouteDstNet, GW: defaultV4Gateway})
	}
}

func (s *CNIServer) loadNetworkConfig(request *cnimsg.CniCmdRequestMessage) (*CNIConfig, error) {
	cniConfig := &CNIConfig{}
	cniConfig.CniCmdArgsMessage = request.CniArgs
	if err := json.Unmarshal(request.CniArgs.NetworkConfiguration, cniConfig); err != nil {
		return cniConfig, err
	}
	cniConfig.k8sArgs = &k8sArgs{}
	if err := types.LoadArgs(request.CniArgs.Args, cniConfig.k8sArgs); err != nil {
		return cniConfig, err
	}
	s.updateLocalIPAMSubnet(cniConfig)
	klog.Infof("Load network configurations: %v", cniConfig)
	return cniConfig, nil
}

func (s *CNIServer) isCNIVersionSupported(reqVersion string) bool {
	_, exist := s.supportedCNIVersions[reqVersion]
	return exist
}

func (s *CNIServer) checkRequestMessage(request *cnimsg.CniCmdRequestMessage) (
	*CNIConfig, *cnimsg.CniCmdResponseMessage) {
	if request.Version != s.serverVersion {
		klog.Error(fmt.Sprintf("Unsupported request version %s, supported versions: %s", request.Version, s.serverVersion))
		return nil, s.incompatibleProtocolVersionResponse(request.Version)
	}
	cniConfig, err := s.loadNetworkConfig(request)
	if err != nil {
		klog.Errorf("Failed to parse network configuration: %v", err)
		return nil, s.unsupportedNetworkConfigResponse("networkconfiguration",
			string(request.CniArgs.NetworkConfiguration))
	}
	cniVersion := cniConfig.CNIVersion
	// Check if CNI version in the request is supported
	if !s.isCNIVersionSupported(cniVersion) {
		klog.Errorf(fmt.Sprintf("Unsupported CNI version [%s], supported CNI versions [%s]", cniVersion, supportedCNIVersions))
		return cniConfig, s.incompatibleCniVersionResponse(cniVersion)
	}
	// Find IPAM Service according configuration
	ipamType := cniConfig.IPAM.Type
	isValid := ipam.IsIPAMTypeValid(ipamType)
	if !isValid {
		klog.Errorf("Unsupported IPAM type %s", ipamType)
		return cniConfig, s.unsupportedNetworkConfigResponse("ipam/type", ipamType)
	}
	return cniConfig, nil
}

func (s *CNIServer) updateLocalIPAMSubnet(cniConfig *CNIConfig) {
	cniConfig.NetworkConfig.IPAM.Gateway = s.nodeConfig.Gateway.IP.String()
	cniConfig.NetworkConfig.IPAM.Subnet = s.nodeConfig.PodCIDR.String()
	cniConfig.NetworkConfiguration, _ = json.Marshal(cniConfig.NetworkConfig)
}

func (s *CNIServer) generateCNIErrorResponse(cniErrorCode cnimsg.CniCmdResponseMessage_ErrorCode,
	cniErrorMsg string) *cnimsg.CniCmdResponseMessage {
	return &cnimsg.CniCmdResponseMessage{
		Version:      s.serverVersion,
		StatusCode:   cniErrorCode,
		ErrorMessage: cniErrorMsg,
	}
}

func (s *CNIServer) incompatibleCniVersionResponse(cniVersion string) *cnimsg.CniCmdResponseMessage {
	cniErrorCode := cnimsg.CniCmdResponseMessage_INCOMPATIBLE_CNI_VERSION
	cniErrorMsg := fmt.Sprintf("Unsupported CNI version [%s], supported versions [%s]", cniVersion, supportedCNIVersions)
	return s.generateCNIErrorResponse(cniErrorCode, cniErrorMsg)
}

func (s *CNIServer) unsupportedNetworkConfigResponse(key string, value interface{}) *cnimsg.CniCmdResponseMessage {
	cniErrorCode := cnimsg.CniCmdResponseMessage_UNSUPPORTED_NETWORK_CONFIGURATION
	cniErrorMsg := fmt.Sprintf("Network configuration does not support key %s and value %v", key, value)
	return s.generateCNIErrorResponse(cniErrorCode, cniErrorMsg)
}

func (s *CNIServer) unknownContainerError(containerID string) *cnimsg.CniCmdResponseMessage {
	cniErrorCode := cnimsg.CniCmdResponseMessage_UNKNOWN_CONTAINER
	cniErrorMsg := fmt.Sprintf("Container id  %s is unknown or non-existent", containerID)
	return s.generateCNIErrorResponse(cniErrorCode, cniErrorMsg)
}

func (s *CNIServer) tryAgainLaterResponse() *cnimsg.CniCmdResponseMessage {
	cniErrorCode := cnimsg.CniCmdResponseMessage_TRY_AGAIN_LATER
	cniErrorMsg := fmt.Sprintf("Server is busy, please retry later")
	return s.generateCNIErrorResponse(cniErrorCode, cniErrorMsg)
}

func (s *CNIServer) ipamFailureResponse(err error) *cnimsg.CniCmdResponseMessage {
	cniErrorCode := cnimsg.CniCmdResponseMessage_IPAM_FAILURE
	cniErrorMsg := err.Error()
	return s.generateCNIErrorResponse(cniErrorCode, cniErrorMsg)
}

func (s *CNIServer) incompatibleProtocolVersionResponse(requestVersion string) *cnimsg.CniCmdResponseMessage {
	cniErrorCode := cnimsg.CniCmdResponseMessage_INCOMPATIBLE_PROTO_VERSION
	cniErrorMsg := fmt.Sprintf("Unsupported protocol version [%s], supported versions [%s]", requestVersion, s.serverVersion)
	return s.generateCNIErrorResponse(cniErrorCode, cniErrorMsg)
}

func (s *CNIServer) configInterfaceFailureResponse(err error) *cnimsg.CniCmdResponseMessage {
	cniErrorCode := cnimsg.CniCmdResponseMessage_CONFIG_INTERFACE_FAILURE
	cniErrorMsg := err.Error()
	return s.generateCNIErrorResponse(cniErrorCode, cniErrorMsg)
}

func (s *CNIServer) checkInterfaceFailureResponse(err error) *cnimsg.CniCmdResponseMessage {
	cniErrorCode := cnimsg.CniCmdResponseMessage_CHECK_INTERFACE_FAILURE
	cniErrorMsg := err.Error()
	return s.generateCNIErrorResponse(cniErrorCode, cniErrorMsg)
}

func buildVersionSet(versions string) map[string]bool {
	versionSet := make(map[string]bool)
	for _, ver := range strings.Split(versions, ",") {
		versionSet[strings.Trim(ver, " ")] = true
	}
	return versionSet
}

func (s *CNIServer) parsePrevResultFromRequest(networkConfig *NetworkConfig) (*current.Result, *cnimsg.CniCmdResponseMessage) {
	if networkConfig.PrevResult == nil && networkConfig.RawPrevResult == nil {
		klog.Errorf("Previous network configuration not specified")
		return nil, s.unsupportedNetworkConfigResponse("prevResult", "")
	}

	if err := parsePrevResult(networkConfig); err != nil {
		klog.Errorf("Failed to parse previous network configuration")
		return nil, s.unsupportedNetworkConfigResponse("prevResult", networkConfig.RawPrevResult)
	}
	prevResult, err := current.NewResultFromResult(networkConfig.PrevResult)
	if err != nil {
		klog.Errorf("Failed to construct prevResult using previous network configuration")
		return nil, s.unsupportedNetworkConfigResponse("prevResult", networkConfig.PrevResult)
	}
	return prevResult, nil
}

func (s *CNIServer) validatePrevResult(cfgArgs *cnimsg.CniCmdArgsMessage, k8sCNIArgs *k8sArgs, prevResult *current.Result) (*cnimsg.CniCmdResponseMessage, error) {
	var containerIntf, hostIntf *current.Interface
	hostVethName := GenerateContainerPeerName(string(k8sCNIArgs.K8S_POD_NAME), string(k8sCNIArgs.K8S_POD_NAMESPACE))
	containerID := cfgArgs.ContainerId
	netNS := cfgArgs.Netns

	// Find interfaces from previous configuration
	for _, intf := range prevResult.Interfaces {
		if cfgArgs.Ifname == intf.Name {
			containerIntf = intf
			continue
		} else if hostVethName == intf.Name {
			hostIntf = intf
			continue
		} else {
			klog.Errorf("Unknown interface name %s", intf.Name)
		}
	}
	if containerIntf == nil {
		klog.Errorf("Failed to find interfaces of container: %s", containerID)
		return s.unknownContainerError(containerID), nil
	}
	if hostIntf == nil {
		klog.Errorf("Failed to find host interface peering for container : %s", containerID)
		return s.unknownContainerError(containerID), nil
	}

	if err := checkInterfaces(s.ifaceStore, containerID, netNS, containerIntf, hostIntf, hostVethName, prevResult); err != nil {
		return s.checkInterfaceFailureResponse(err), nil
	}

	return &cnimsg.CniCmdResponseMessage{
		Version:    s.serverVersion,
		CniResult:  []byte(""),
		StatusCode: cnimsg.CniCmdResponseMessage_SUCCESS,
	}, nil
}

func (s *CNIServer) CmdAdd(ctx context.Context, request *cnimsg.CniCmdRequestMessage) (
	*cnimsg.CniCmdResponseMessage, error) {
	klog.Infof("Receive CmdAdd request %v", request)
	cniConfig, response := s.checkRequestMessage(request)
	if response != nil {
		return response, nil
	}
	cniVersion := cniConfig.CNIVersion
	result := &current.Result{CNIVersion: cniVersion}

	success := false
	defer func() {
		// Rollback to delete configurations once ADD is failure.
		if !success {
			klog.Warningf("CmdAdd has failed, and try to rollback")
			if _, err := s.CmdDel(ctx, request); err != nil {
				klog.Warningf("Failed to rollback after CNI add failure: %v", err)
			}
		}
	}()

	// Request IP Address from IPAM driver
	ipamResult, err := ipam.ExecIPAMAdd(cniConfig.CniCmdArgsMessage, cniConfig.IPAM.Type)
	if err != nil {
		klog.Errorf("Failed to add ip addresses from IPAM driver: %v", err)
		return s.ipamFailureResponse(err), nil
	}
	klog.Infof("Added ip addresses from IPAM driver, %v", ipamResult)
	result.IPs = ipamResult.IPs
	result.Routes = ipamResult.Routes
	// Ensure interface gateway setting and mapping relations between result.Interfaces and result.IPs
	updateResultIfaceConfig(result, s.nodeConfig.Gateway.IP)
	// Setup pod interfaces and connect to ovs bridge
	if err = configureInterface(s.ovsBridgeClient, s.ifaceStore, cniConfig.ContainerId, cniConfig.k8sArgs, cniConfig.Netns, cniConfig.Ifname, result); err != nil {
		klog.Errorf("Failed to configure container %s interface: %v", cniConfig.ContainerId, err)
		return s.configInterfaceFailureResponse(err), nil
	}
	result.DNS = cniConfig.DNS
	var resultBytes bytes.Buffer
	result.PrintTo(&resultBytes)
	klog.Infof("CmdAdd request success")
	// mark success as true to avoid rollback
	success = true
	return &cnimsg.CniCmdResponseMessage{
		Version:    s.serverVersion,
		CniResult:  resultBytes.Bytes(),
		StatusCode: cnimsg.CniCmdResponseMessage_SUCCESS,
	}, nil
}

func (s *CNIServer) CmdDel(ctx context.Context, request *cnimsg.CniCmdRequestMessage) (
	*cnimsg.CniCmdResponseMessage, error) {
	klog.Infof("Receive CmdDel request %v", request)
	cniConfig, response := s.checkRequestMessage(request)
	if response != nil {
		return response, nil
	}

	// Release IP to IPAM driver
	if err := ipam.ExecIPAMDelete(cniConfig.CniCmdArgsMessage, cniConfig.IPAM.Type); err != nil {
		klog.Errorf("Failed to delete IP addresses by IPAM driver: %v", err)
		return s.ipamFailureResponse(err), nil
	}
	klog.Info("Deleted IP addresses by IPAM driver")
	// Remove host interface and OVS configuration
	if err := removeInterfaces(s.ovsBridgeClient, s.ifaceStore, cniConfig.ContainerId, cniConfig.Netns, cniConfig.Ifname); err != nil {
		klog.Errorf("Failed to remove container %s interface configuration: %v", cniConfig.ContainerId, err)
		return s.configInterfaceFailureResponse(err), nil
	}
	return &cnimsg.CniCmdResponseMessage{
		Version:    s.serverVersion,
		CniResult:  []byte(""),
		StatusCode: cnimsg.CniCmdResponseMessage_SUCCESS,
	}, nil
}

func (s *CNIServer) CmdCheck(ctx context.Context, request *cnimsg.CniCmdRequestMessage) (
	*cnimsg.CniCmdResponseMessage, error) {
	klog.Infof("Receive CmdCheck request %v", request)
	cniConfig, response := s.checkRequestMessage(request)
	if response != nil {
		return response, nil
	}
	cniVersion := cniConfig.CNIVersion
	if err := ipam.ExecIPAMCheck(cniConfig.CniCmdArgsMessage, cniConfig.IPAM.Type); err != nil {
		klog.Errorf("Failed to check IPAM configuration: %v", err)
		return s.ipamFailureResponse(err), nil
	}

	if valid, _ := version.GreaterThanOrEqualTo(cniVersion, "0.4.0"); valid {
		if prevResult, response := s.parsePrevResultFromRequest(cniConfig.NetworkConfig); response != nil {
			return response, nil
		} else if response, err := s.validatePrevResult(cniConfig.CniCmdArgsMessage, cniConfig.k8sArgs, prevResult); err != nil {
			return response, err
		}
	}
	klog.Info("Succeed to check network configuration")
	return &cnimsg.CniCmdResponseMessage{
		Version:    s.serverVersion,
		CniResult:  []byte(""),
		StatusCode: cnimsg.CniCmdResponseMessage_SUCCESS,
	}, nil
}

func New(cniSocket string, nodeConfig *agent.NodeConfig, ovsBridgeClient ovsconfig.OVSBridgeClient, ifaceStore agent.InterfaceStore) (*CNIServer, error) {
	return &CNIServer{cniSocket: cniSocket, ovsBridgeClient: ovsBridgeClient, supportedCNIVersions: supportedCNIVersionSet, serverVersion: cni.OKNVersion, nodeConfig: nodeConfig}, nil
}

func (s *CNIServer) Run(stopCh <-chan struct{}) {
	klog.Info("Starting CNI server")
	defer klog.Info("Shutting down CNI server")
	listener, err := net.Listen("unix", s.cniSocket)
	if err != nil {
		klog.Errorf("Failed to bind on %s: %v", s.cniSocket, err)
		os.Exit(1)
	}
	rpcServer := grpc.NewServer()

	cnimsg.RegisterCniServer(rpcServer, s)
	klog.Info("CNI server is listening ...")
	go func() {
		if err := rpcServer.Serve(listener); err != nil {
			klog.Errorf("Failed to serve connections: %v", err)
		}
	}()
	<-stopCh
}

func init() {
	supportedCNIVersionSet = buildVersionSet(supportedCNIVersions)
}
