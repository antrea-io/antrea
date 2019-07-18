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
	"github.com/containernetworking/plugins/pkg/ns"
	"google.golang.org/grpc"
	"k8s.io/klog"
	"okn/pkg/agent/cniserver/ipam"
	"okn/pkg/apis/cni"
)

type CNIServer struct {
	cniSocket            string
	supportedCNIVersions map[string]bool
	serverVersion        string
}

const (
	supportedCniVersions = "0.1.0,0.2.0,0.3.0,0.3.1,0.4.0"
	serverVersion        = "1.0"
)

var supportedCNIVersionSet map[string]bool

type NetworkConfig struct {
	types.NetConf
	cnimsg.CniCmdArgsMessage
}

func (s *CNIServer) loadNetworkConfig(request *cnimsg.CniCmdRequestMessage) (*NetworkConfig, error) {
	networkConfig := &NetworkConfig{}
	networkConfig.CniCmdArgsMessage = *request.CniArgs
	if err := json.Unmarshal(request.CniArgs.NetworkConfiguration, networkConfig); err != nil {
		return networkConfig, err
	}
	klog.Infof("Load network configurations: %v", networkConfig)
	return networkConfig, nil
}

func (s *CNIServer) isCNIVersionSupported(reqVersion string) bool {
	_, exist := s.supportedCNIVersions[reqVersion]
	return exist
}

func (s *CNIServer) checkRequestMessage(request *cnimsg.CniCmdRequestMessage) (
	*NetworkConfig, *cnimsg.CniCmdResponseMessage) {
	if request.Version != serverVersion {
		klog.Error(fmt.Sprintf("Unsupported request version %s, supported versions: %s", request.Version, serverVersion))
		return nil, incompatibleProtocolVersionResponse(request.Version)
	}
	networkConfig, err := s.loadNetworkConfig(request)
	if err != nil {
		klog.Errorf("Failed to parse network configuration, err: %v", err)
		return nil, unsupportedNetworkConfigResponse("networkconfiguration",
			string(request.CniArgs.NetworkConfiguration))
	}
	cniVersion := networkConfig.CNIVersion
	// Check if CNI version in the request is supported
	if !s.isCNIVersionSupported(cniVersion) {
		klog.Errorf(fmt.Sprintf("Unsupported CNI version [%s], supported CNI versions [%s]", cniVersion, supportedCniVersions))
		return networkConfig, incompatibleCniVersionResponse(cniVersion)
	}
	// Find IPAM Service according configuration
	ipamType := networkConfig.IPAM.Type
	isValid := ipam.IsIPAMTypeValid(ipamType)
	if !isValid {
		klog.Errorf("Unsupported IPAM type %s", ipamType)
		return networkConfig, unsupportedNetworkConfigResponse("ipam/type", ipamType)
	}

	return networkConfig, nil
}

func generateCNIErrorResponse(cniErrorCode cnimsg.CniCmdResponseMessage_ErrorCode,
	cniErrorMsg string) *cnimsg.CniCmdResponseMessage {
	return &cnimsg.CniCmdResponseMessage{
		Version:      serverVersion,
		StatusCode:   cniErrorCode,
		ErrorMessage: cniErrorMsg,
	}
}

func incompatibleCniVersionResponse(cniVersion string) *cnimsg.CniCmdResponseMessage {
	cniErrorCode := cnimsg.CniCmdResponseMessage_INCOMPATIBLE_CNI_VERSION
	cniErrorMsg := fmt.Sprintf("Unsupported CNI version [%s], supported versions [%s]", cniVersion, supportedCniVersions)
	return generateCNIErrorResponse(cniErrorCode, cniErrorMsg)
}

func unsupportedNetworkConfigResponse(key string, value interface{}) *cnimsg.CniCmdResponseMessage {
	cniErrorCode := cnimsg.CniCmdResponseMessage_UNSUPPORTED_NETWORK_CONFIGURATION
	cniErrorMsg := fmt.Sprintf("Network configuration does not support key %s and value %v", key, value)
	return generateCNIErrorResponse(cniErrorCode, cniErrorMsg)
}

func unknownContainerError(containerID string) *cnimsg.CniCmdResponseMessage {
	cniErrorCode := cnimsg.CniCmdResponseMessage_UNKNOWN_CONTAINER
	cniErrorMsg := fmt.Sprintf("Container ID  %s is unknown or non-existent", containerID)
	return generateCNIErrorResponse(cniErrorCode, cniErrorMsg)
}

func tryAgainLaterResponse() *cnimsg.CniCmdResponseMessage {
	cniErrorCode := cnimsg.CniCmdResponseMessage_TRY_AGAIN_LATER
	cniErrorMsg := fmt.Sprintf("Server is busy, please retry later")
	return generateCNIErrorResponse(cniErrorCode, cniErrorMsg)
}

func ipamFailureResponse(err error) *cnimsg.CniCmdResponseMessage {
	cniErrorCode := cnimsg.CniCmdResponseMessage_IPAM_FAILURE
	cniErrorMsg := err.Error()
	return generateCNIErrorResponse(cniErrorCode, cniErrorMsg)
}

func incompatibleProtocolVersionResponse(requestVersion string) *cnimsg.CniCmdResponseMessage {
	cniErrorCode := cnimsg.CniCmdResponseMessage_INCOMPATIBLE_PROTO_VERSION
	cniErrorMsg := fmt.Sprintf("Unsupported protocol version [%s], supported versions [%s]", requestVersion, serverVersion)
	return generateCNIErrorResponse(cniErrorCode, cniErrorMsg)
}

func buildVersionSet(versions string) map[string]bool {
	versionSet := make(map[string]bool)
	for _, ver := range strings.Split(versions, ",") {
		versionSet[strings.Trim(ver, " ")] = true
	}
	return versionSet
}

func (s *CNIServer) CmdAdd(ctx context.Context, request *cnimsg.CniCmdRequestMessage) (
	*cnimsg.CniCmdResponseMessage, error) {
	klog.Infof("Receive CmdAdd request %v", request)
	networkConfig, response := s.checkRequestMessage(request)
	if response != nil {
		return response, nil
	}
	cniVersion := networkConfig.CNIVersion
	result := &current.Result{CNIVersion: cniVersion}

	success := false
	defer func() {
		// Rollback to delete configurations once ADD is failure.
		if !success {
			if _, err := s.CmdDel(ctx, request); err != nil {
				klog.Warningf("Failed to rollback after CNI add failure, err: %v", err)
			}
		}
	}()

	// Request IP Address from IPAM driver
	ipamResult, err := ipam.ExecIPAMAdd(networkConfig.CniCmdArgsMessage, networkConfig.IPAM.Type)
	if err != nil {
		klog.Errorf("Failed to add IP addresses from IPAM driver, err: %v", err)
		return ipamFailureResponse(err), nil
	}
	klog.Infof("Added IP addresses from IPAM driver, %v", ipamResult)
	result.IPs = ipamResult.IPs
	result.Routes = ipamResult.Routes

	result.DNS = networkConfig.DNS
	var resultBytes bytes.Buffer
	result.PrintTo(&resultBytes)
	klog.Infof("CmdAdd request success")
	// mark success as true to avoid rollback
	success = true
	return &cnimsg.CniCmdResponseMessage{
		Version:    serverVersion,
		CniResult:  resultBytes.Bytes(),
		StatusCode: cnimsg.CniCmdResponseMessage_SUCCESS,
	}, nil
}

func (s *CNIServer) CmdDel(ctx context.Context, request *cnimsg.CniCmdRequestMessage) (
	*cnimsg.CniCmdResponseMessage, error) {
	klog.Infof("Receive CmdDel request %v", request)
	networkConfig, response := s.checkRequestMessage(request)
	if response != nil {
		return response, nil
	}

	// Release IP to IPAM driver
	if err := ipam.ExecIPAMDelete(networkConfig.CniCmdArgsMessage, networkConfig.IPAM.Type); err != nil {
		klog.Errorf("Failed to delete IP addresses by IPAM driver, err: %v", err)
		return ipamFailureResponse(err), nil
	}
	klog.Info("Deleted IP addresses by IPAM driver")
	return &cnimsg.CniCmdResponseMessage{
		Version:    serverVersion,
		CniResult:  []byte(""),
		StatusCode: cnimsg.CniCmdResponseMessage_SUCCESS,
	}, nil
}

func (s *CNIServer) CmdCheck(ctx context.Context, request *cnimsg.CniCmdRequestMessage) (
	*cnimsg.CniCmdResponseMessage, error) {
	klog.Infof("Receive CmdCheck request %v", request)
	networkConfig, response := s.checkRequestMessage(request)
	if response != nil {
		return response, nil
	}
	cniVersion := networkConfig.CNIVersion
	if err := ipam.ExecIPAMCheck(networkConfig.CniCmdArgsMessage, networkConfig.IPAM.Type); err != nil {
		klog.Errorf("Failed to check IPAM configuration, err: %v", err)
		return ipamFailureResponse(err), nil
	}

	netns, err := ns.GetNS(networkConfig.Netns)
	if err != nil {
		klog.Errorf("Failed to check netns config %s, err: %v", networkConfig.Netns, err)
		return unsupportedNetworkConfigResponse("netns", networkConfig.Netns), nil
	}
	defer netns.Close()

	if valid, _ := version.GreaterThanOrEqualTo(cniVersion, "0.4.0"); valid {
		if networkConfig.NetConf.PrevResult == nil {
			klog.Errorf("Previous network configuration not provided")
			return unsupportedNetworkConfigResponse("prevResult", ""), nil
		}

		if err := version.ParsePrevResult(&networkConfig.NetConf); err != nil {
			klog.Errorf("Failed to parse previous network configuration")
			return unsupportedNetworkConfigResponse("prevResult", networkConfig.RawPrevResult),
				nil
		}
		_, err := current.NewResultFromResult(networkConfig.PrevResult)
		if err != nil {
			klog.Errorf("Failed to construct prevResult using previous network configuration")
			return unsupportedNetworkConfigResponse("prevResult", networkConfig.PrevResult), nil
		}
	}
	klog.Info("Succeed to check network configuration")
	return &cnimsg.CniCmdResponseMessage{
		Version:    serverVersion,
		CniResult:  []byte(""),
		StatusCode: cnimsg.CniCmdResponseMessage_SUCCESS,
	}, nil
}

func New(cniSocket string) (*CNIServer, error) {
	return &CNIServer{cniSocket: cniSocket, supportedCNIVersions: supportedCNIVersionSet, serverVersion: serverVersion}, nil
}

func (s *CNIServer) Run(stopCh <-chan struct{}) {
	klog.Info("Starting CNI server")
	defer klog.Info("Shutting down CNI server")
	listener, err := net.Listen("unix", s.cniSocket)
	if err != nil {
		klog.Errorf("Failed to bind on %s, err: %v", s.cniSocket, err)
		os.Exit(1)
	}
	rpcServer := grpc.NewServer()

	cnimsg.RegisterCniServer(rpcServer, s)
	klog.Info("CNI server is listening ...")
	go func() {
		if err := rpcServer.Serve(listener); err != nil {
			klog.Errorf("Failed to serve connections, err: %v", err)
		}
	}()
	<-stopCh
}

func init() {
	supportedCNIVersionSet = buildVersionSet(supportedCniVersions)
}
