//go:build windows
// +build windows

// Copyright 2020 Antrea Authors
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
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/util"
	cnipb "antrea.io/antrea/pkg/apis/cni/v1beta1"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

const (
	notFoundHNSEndpoint = "The endpoint was not found"
)

var (
	getHnsNetworkByNameFunc         = hcsshim.GetHNSNetworkByName
	listHnsEndpointFunc             = hcsshim.HNSListEndpointRequest
	setInterfaceMTUFunc             = util.SetInterfaceMTU
	hostInterfaceExistsFunc         = util.HostInterfaceExists
	getNetInterfaceAddrsFunc        = getNetInterfaceAddrs
	createHnsEndpointFunc           = createHnsEndpoint
	getNamespaceEndpointIDsFunc     = hcn.GetNamespaceEndpointIds
	hotAttachEndpointFunc           = hcsshim.HotAttachEndpoint
	attachEndpointInNamespaceFunc   = attachEndpointInNamespace
	isContainerAttachOnEndpointFunc = isContainerAttachOnEndpoint
	getHcnEndpointByIDFunc          = hcn.GetEndpointByID
	deleteHnsEndpointFunc           = deleteHnsEndpoint
	removeEndpointFromNamespaceFunc = hcn.RemoveNamespaceEndpoint
	getHnsEndpointByNameFunc        = hcsshim.GetHNSEndpointByName
	getNetInterfaceByNameFunc       = net.InterfaceByName
)

type ifConfigurator struct {
	hnsNetwork *hcsshim.HNSNetwork
	epCache    *sync.Map
}

// disableTXChecksumOffload is ignored on Windows.
func newInterfaceConfigurator(ovsDatapathType ovsconfig.OVSDatapathType, isOvsHardwareOffloadEnabled bool, disableTXChecksumOffload bool) (*ifConfigurator, error) {
	hnsNetwork, err := getHnsNetworkByNameFunc(util.LocalHNSNetwork)
	if err != nil {
		return nil, err
	}
	eps, err := listHnsEndpointFunc()
	if err != nil {
		return nil, err
	}
	epCache := &sync.Map{}
	for i := range eps {
		hnsEP := &eps[i]
		epCache.Store(hnsEP.Name, hnsEP)
	}
	return &ifConfigurator{
		hnsNetwork: hnsNetwork,
		epCache:    epCache,
	}, nil
}

func (ic *ifConfigurator) addEndpoint(ep *hcsshim.HNSEndpoint) {
	ic.epCache.Store(ep.Name, ep)
}

func (ic *ifConfigurator) getEndpoint(name string) (*hcsshim.HNSEndpoint, bool) {
	value, ok := ic.epCache.Load(name)
	if !ok {
		return nil, false
	}
	ep, _ := value.(*hcsshim.HNSEndpoint)
	return ep, true
}

func (ic *ifConfigurator) delEndpoint(name string) {
	ic.epCache.Delete(name)
}

// findContainerIPConfig finds a valid IPv4 address since IPv6 is not supported for Windows at this stage.
func findContainerIPConfig(ips []*current.IPConfig) (*current.IPConfig, error) {
	for _, ipc := range ips {
		if ipc.Address.IP.To4() != nil {
			return ipc, nil
		}
	}
	return nil, fmt.Errorf("failed to find a valid IP address")
}

// configureContainerLink creates a HNSEndpoint for the container using the IPAM result, and then attach it on the container interface.
func (ic *ifConfigurator) configureContainerLink(
	podName string,
	podNamespace string,
	containerID string,
	containerNetNS string,
	containerIFDev string,
	mtu int,
	brSriovVFDeviceID string,
	podSriovVFDeviceID string,
	result *current.Result,
	containerAccess *containerAccessArbitrator,
) error {
	if brSriovVFDeviceID != "" {
		return fmt.Errorf("OVS hardware offload is not supported on windows")
	}
	if podSriovVFDeviceID != "" {
		return fmt.Errorf("Pod SR-IOV interface is not supported on windows")
	}
	// We must use the infra container to generate the endpoint name to ensure infra and workload containers use the
	// same HNSEndpoint.
	infraContainerID := getInfraContainer(containerID, containerNetNS)
	epName := util.GenerateContainerInterfaceName(podName, podNamespace, infraContainerID)
	// Search endpoint from local cache.
	endpoint, found := ic.getEndpoint(epName)
	if !found {
		if !isInfraContainer(containerNetNS) {
			return fmt.Errorf("failed to find HNSEndpoint: %s", epName)
		}
		// Only create HNS Endpoint for infra container.
		ep, err := ic.createContainerLink(epName, result, containerID, podName, podNamespace)
		if err != nil {
			return err
		}
		endpoint = ep
	}
	// Attach HNSEndpoint to the container. Note that HNSEndpoint must be attached to the container before adding OVS port,
	// otherwise an error will be returned when creating OVS port.
	klog.V(2).Infof("Configuring IP address for container %s", containerID)
	containerIface, err := attachContainerLink(endpoint, containerID, containerNetNS, containerIFDev)
	if err != nil {
		klog.V(2).Infof("Failed to attach HNS Endpoint to the container, remove it.")
		if isInfraContainer(containerNetNS) {
			ic.removeHNSEndpoint(endpoint, containerID)
		}
		return fmt.Errorf("failed to configure container IP: %v", err)
	}

	hostIface := &current.Interface{
		Name:    endpoint.Name,
		Mac:     endpoint.MacAddress,
		Sandbox: "",
	}
	result.Interfaces = []*current.Interface{hostIface, containerIface}

	containerIP, _ := findContainerIPConfig(result.IPs)
	// Update IPConfig with the index of target interface in the result. The index is used in CNI CmdCheck.
	ifaceIdx := 1
	containerIP.Interface = &ifaceIdx

	// MTU is configured only when the infrastructure container is created.
	if containerID == infraContainerID {
		// Configure MTU in another separate goroutine to ensure it is executed after the host interface is created.
		// The reasons include, 1) for containerd runtime, the interface is created by containerd after the CNI
		// CmdAdd request is returned; 2) for Docker runtime, the interface is created after hcsshim.HotAttachEndpoint,
		// and the hcsshim call is not synchronized from the observation.
		return ic.addPostInterfaceCreateHook(infraContainerID, epName, containerAccess, func() error {
			ifaceName := util.VirtualAdapterName(epName)
			if err := setInterfaceMTUFunc(ifaceName, mtu); err != nil {
				return fmt.Errorf("failed to configure MTU on container interface '%s': %v", ifaceName, err)
			}
			return nil
		})
	}
	return nil
}

// changeContainerMTU is only used for Antrea Multi-cluster with networkPolicyOnly
// mode, and this mode doesn't support Windows platform yet.
func (ic *ifConfigurator) changeContainerMTU(containerNetNS string, containerIFDev string, mtuDeduction int) error {
	return errors.New("changeContainerMTU is unsupported on Windows")
}

// createContainerLink creates HNSEndpoint using the IP configuration in the IPAM result.
func (ic *ifConfigurator) createContainerLink(endpointName string, result *current.Result, containerID, podName, podNamespace string) (hostLink *hcsshim.HNSEndpoint, err error) {
	containerIP, err := findContainerIPConfig(result.IPs)
	if err != nil {
		return nil, err
	}
	epRequest := &hcsshim.HNSEndpoint{
		Name:           endpointName,
		VirtualNetwork: ic.hnsNetwork.Id,
		DNSServerList:  strings.Join(result.DNS.Nameservers, ","),
		DNSSuffix:      strings.Join(result.DNS.Search, ","),
		GatewayAddress: containerIP.Gateway.String(),
		IPAddress:      containerIP.Address.IP,
	}
	hnsEP, err := createHnsEndpointFunc(epRequest)
	if err != nil {
		return nil, err
	}
	// Add the new created Endpoint into local cache.
	ic.addEndpoint(hnsEP)
	return hnsEP, nil
}

// attachContainerLink takes the result of the IPAM plugin, and adds the appropriate IP
// addresses and routes to the interface.
// For different CRI runtimes we need to use the appropriate Windows container API:
//   - Docker runtime: HNS API
//   - containerd runtime: HCS API
func attachContainerLink(ep *hcsshim.HNSEndpoint, containerID, sandbox, containerIFDev string) (*current.Interface, error) {
	var attached bool
	var err error
	var hcnEp *hcn.HostComputeEndpoint
	if isDockerContainer(sandbox) {
		// Docker runtime
		attached, err = isContainerAttachOnEndpointFunc(ep, containerID)
		if err != nil {
			return nil, err
		}
	} else {
		// containerd runtime
		if hcnEp, err = getHcnEndpointByIDFunc(ep.Id); err != nil {
			return nil, err
		}
		attachedEpIds, err := getNamespaceEndpointIDsFunc(sandbox)
		if err != nil {
			return nil, err
		}
		for _, existingEP := range attachedEpIds {
			if existingEP == hcnEp.Id {
				attached = true
				break
			}
		}
	}

	if attached {
		klog.V(2).Infof("HNS Endpoint %s already attached on container %s", ep.Id, containerID)
	} else {
		if hcnEp == nil {
			// Docker runtime
			if err := hotAttachEndpointFunc(containerID, ep.Id); err != nil {
				return nil, err
			}
		} else {
			// containerd runtime
			if err := attachEndpointInNamespaceFunc(hcnEp, sandbox); err != nil {
				return nil, err
			}
		}
	}
	containerIface := &current.Interface{
		Name:    containerIFDev,
		Mac:     ep.MacAddress,
		Sandbox: sandbox,
	}
	return containerIface, nil
}

func isContainerAttachOnEndpoint(endpoint *hcsshim.HNSEndpoint, containerID string) (bool, error) {
	return endpoint.IsAttached(containerID)
}

func attachEndpointInNamespace(hcnEp *hcn.HostComputeEndpoint, sandbox string) error {
	return hcnEp.NamespaceAttach(sandbox)
}

// advertiseContainerAddr returns immediately as the address is advertised automatically after it is configured on an
// network interface on Windows.
func (ic *ifConfigurator) advertiseContainerAddr(containerNetNS string, containerIfaceName string, result *current.Result) error {
	klog.V(2).Info("Send gratuitous ARP from container interface is not supported on Windows, return nil")
	return nil
}

// removeContainerLink removes the HNSEndpoint attached on the Pod.
func (ic *ifConfigurator) removeContainerLink(containerID, epName string) error {
	ep, found := ic.getEndpoint(epName)
	if !found {
		return nil
	}
	return ic.removeHNSEndpoint(ep, containerID)
}

// removeHNSEndpoint removes the HNSEndpoint from HNS and local cache.
func (ic *ifConfigurator) removeHNSEndpoint(endpoint *hcsshim.HNSEndpoint, containerID string) error {
	epName := endpoint.Name
	deleteCh := make(chan error)
	// Remove HNSEndpoint.
	go func() {
		hcnEndpoint, _ := getHcnEndpointByIDFunc(endpoint.Id)
		if hcnEndpoint != nil && isValidHostNamespace(hcnEndpoint.HostComputeNamespace) {
			err := removeEndpointFromNamespaceFunc(hcnEndpoint.HostComputeNamespace, hcnEndpoint.Id)
			if err != nil {
				klog.Errorf("Failed to remove HostComputeEndpoint %s from HostComputeNamespace %s: %v", hcnEndpoint.Name, hcnEndpoint.HostComputeNamespace, err)
				deleteCh <- err
				return
			}
		}
		_, err := deleteHnsEndpointFunc(endpoint)
		if err != nil && strings.Contains(err.Error(), notFoundHNSEndpoint) {
			err = nil
		}
		if err != nil {
			klog.Errorf("Failed to delete container interface %s: %v", containerID, err)
		}
		deleteCh <- err
	}()

	// Deleting HNS Endpoint is blocking in some corner cases. It might be a bug in Windows HNS service. To avoid
	// hanging in cniserver, add timeout control in HNSEndpoint deletion.
	select {
	case err := <-deleteCh:
		if err != nil {
			if !strings.Contains(err.Error(), notFoundHNSEndpoint) {
				klog.Errorf("Failed to delete container interface %s: %v", containerID, err)
				return err
			}
		}
	case <-time.After(1 * time.Second):
		return fmt.Errorf("timeout when deleting HNSEndpoint %s", epName)
	}

	// Delete HNSEndpoint from local cache.
	ic.delEndpoint(epName)
	return nil
}

func deleteHnsEndpoint(endpoint *hcsshim.HNSEndpoint) (*hcsshim.HNSEndpoint, error) {
	return endpoint.Delete()
}

// isValidHostNamespace checks if the hostNamespace is valid or not. When using Docker runtime, the hostNamespace
// is not set, and Windows HCN should use a default value "00000000-0000-0000-0000-000000000000". An error returns
// when removing HostComputeEndpoint in this namespace. This field is set with a valid value when containerd is used.
func isValidHostNamespace(hostNamespace string) bool {
	return hostNamespace != "" && hostNamespace != "00000000-0000-0000-0000-000000000000"
}

func parseContainerIfaceFromResults(cfgArgs *cnipb.CniCmdArgs, prevResult *current.Result) *current.Interface {
	for _, intf := range prevResult.Interfaces {
		if strings.HasSuffix(intf.Name, cfgArgs.Ifname) {
			return intf
		}
	}
	return nil
}

// checkContainerInterface finds the virtual interface of the container, and compares the network configurations with
// the previous result.
func (ic *ifConfigurator) checkContainerInterface(
	sandboxID, containerID string,
	containerIface *current.Interface,
	containerIPs []*current.IPConfig,
	containerRoutes []*cnitypes.Route,
	sriovVFDeviceID string) (interface{}, error) {

	if sriovVFDeviceID != "" {
		return "", fmt.Errorf("OVS hardware offload is not supported in windows")
	}

	// Check container sandbox configuration.
	if sandboxID != containerIface.Sandbox {
		return nil, fmt.Errorf("sandbox in prevResult %s doesn't match configured netns: %s",
			containerIface.Sandbox, sandboxID)
	}
	hnsEP := strings.Split(containerIface.Name, "_")[0]
	containerIfaceName := util.VirtualAdapterName(hnsEP)
	intf, err := getNetInterfaceByNameFunc(containerIfaceName)
	if err != nil {
		klog.Errorf("Failed to get container %s interface: %v", containerID, err)
		return nil, err
	}
	// Check container MAC configuration.
	if intf.HardwareAddr.String() != containerIface.Mac {
		klog.Errorf("Container MAC in prevResult %s doesn't match configured address: %s", containerIface.Mac, intf.HardwareAddr.String())
		return nil, fmt.Errorf("container MAC in prevResult %s doesn't match configured address: %s", containerIface.Mac, intf.HardwareAddr.String())
	}

	// Parse container IP configuration from previous result.
	var containerIPConfig *current.IPConfig
	for _, ipConfig := range containerIPs {
		if ipConfig.Interface != nil {
			containerIPConfig = ipConfig
		}
	}
	if containerIPConfig == nil {
		return nil, fmt.Errorf("not find container IP configuration from result")
	}
	// Check container IP configuration.
	if err := validateExpectedInterfaceIPs(containerIPConfig, intf); err != nil {
		return nil, err
	}

	// Todo: add check for container route configuration.
	contVeth := &vethPair{
		name:    hnsEP,
		ifIndex: intf.Index,
	}
	return contVeth, nil
}

func getNetInterfaceAddrs(intf *net.Interface) ([]net.Addr, error) {
	return intf.Addrs()
}

// validateExpectedInterfaceIPs checks if the vNIC for the container has configured with correct IP address.
func validateExpectedInterfaceIPs(containerIPConfig *current.IPConfig, intf *net.Interface) error {
	addrs, err := getNetInterfaceAddrsFunc(intf)
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		if strings.Contains(addr.String(), containerIPConfig.Address.String()) {
			return nil
		}
	}
	return fmt.Errorf("container IP %s not exist on target interface %d", containerIPConfig.Address.String(), intf.Index)
}

func (ic *ifConfigurator) validateVFRepInterface(sriovVFDeviceID string) (string, error) {
	return "", fmt.Errorf("OVS hardware offload is not supported in windows")
}

// validateContainerPeerInterface checks HNSEndpoint configuration.
func (ic *ifConfigurator) validateContainerPeerInterface(interfaces []*current.Interface, containerVeth *vethPair) (*vethPair, error) {
	// Iterate all the passed interfaces and look up the host interface by
	// matching the veth peer interface index.
	for _, hostIntf := range interfaces {
		if hostIntf.Sandbox != "" {
			// Not in the default Namespace. Must be the container interface.
			continue
		}

		expectedContainerIfname := containerVeth.name
		if hostIntf.Name != expectedContainerIfname {
			klog.Errorf("Host interface name %s doesn't match configured name %s", hostIntf.Name, expectedContainerIfname)
			return nil, fmt.Errorf("Host interface name %s doesn't match configured name %s", hostIntf.Name, expectedContainerIfname)
		}

		ep, err := getHnsEndpointByNameFunc(hostIntf.Name)
		if err != nil {
			klog.Errorf("Failed to get HNSEndpoint %s: %v", hostIntf.Name, err)
			return nil, err
		}
		if hostIntf.Mac != ep.MacAddress {
			klog.Errorf("Host interface %s MAC %s doesn't match link address %s",
				hostIntf.Name, hostIntf.Mac, ep.MacAddress)
			return nil, fmt.Errorf("host interface %s MAC %s doesn't match",
				hostIntf.Name, hostIntf.Mac)
		}
		return &vethPair{
			name:      ep.Name,
			peerIndex: containerVeth.ifIndex,
		}, nil

	}

	return nil, fmt.Errorf("peer veth interface not found for container interface %s",
		containerVeth.name)
}

// getInterceptedInterfaces is not supported on Windows.
func (ic *ifConfigurator) getInterceptedInterfaces(
	sandbox string,
	containerNetNS string,
	containerIFDev string,
) (*current.Interface, *current.Interface, error) {
	return nil, nil, errors.New("getInterceptedInterfaces is unsupported on Windows")
}

// getOVSInterfaceType returns "internal". Windows uses internal OVS interface for container vNIC.
func getOVSInterfaceType(ovsPortName string) int {
	ifaceName := fmt.Sprintf("vEthernet (%s)", ovsPortName)
	if !hostInterfaceExistsFunc(ifaceName) {
		return defaultOVSInterfaceType
	}
	return internalOVSInterfaceType
}

func (ic *ifConfigurator) addPostInterfaceCreateHook(containerID, endpointName string, containerAccess *containerAccessArbitrator, hook postInterfaceCreateHook) error {
	if containerAccess == nil {
		return fmt.Errorf("container lock cannot be null")
	}
	expectedEP, ok := ic.getEndpoint(endpointName)
	if !ok {
		return fmt.Errorf("failed to find HNSEndpoint %s", endpointName)
	}
	go func() {
		ifaceName := fmt.Sprintf("vEthernet (%s)", endpointName)
		var err error
		pollErr := wait.PollUntilContextTimeout(context.TODO(), 100*time.Millisecond, 60*time.Second, true,
			func(ctx context.Context) (bool, error) {
				containerAccess.lockContainer(containerID)
				defer containerAccess.unlockContainer(containerID)
				currentEP, ok := ic.getEndpoint(endpointName)
				if !ok {
					klog.InfoS("HNSEndpoint doesn't exist in cache, exit current goroutine", "HNSEndpoint", endpointName)
					return true, nil
				}
				if currentEP.Id != expectedEP.Id {
					klog.InfoS("Detected HNSEndpoint change, exit current goroutine", "HNSEndpoint", endpointName)
					return true, nil
				}
				if !hostInterfaceExistsFunc(ifaceName) {
					klog.V(2).InfoS("Waiting for interface to be created", "interface", ifaceName)
					return false, nil
				}
				if err = hook(); err != nil {
					return false, err
				}
				return true, nil
			})

		if pollErr != nil {
			if err != nil {
				klog.ErrorS(err, "Failed to execute postInterfaceCreateHook", "interface", ifaceName)
			} else {
				klog.ErrorS(pollErr, "Failed to wait for host interface creation in 1min", "interface", ifaceName)
			}
		}
	}()
	return nil
}

func createHnsEndpoint(epRequest *hcsshim.HNSEndpoint) (*hcsshim.HNSEndpoint, error) {
	return epRequest.Create()
}
