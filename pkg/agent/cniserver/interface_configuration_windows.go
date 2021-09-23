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
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/util"
	cnipb "antrea.io/antrea/pkg/apis/cni/v1beta1"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	notFoundHNSEndpoint = "The endpoint was not found"
)

type postInterfaceCreateHook func() error

type ifConfigurator struct {
	hnsNetwork *hcsshim.HNSNetwork
	epCache    *sync.Map
}

func newInterfaceConfigurator(ovsDatapathType ovsconfig.OVSDatapathType, isOvsHardwareOffloadEnabled bool) (*ifConfigurator, error) {
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(util.LocalHNSNetwork)
	if err != nil {
		return nil, err
	}
	eps, err := hcsshim.HNSListEndpointRequest()
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
		if ipc.Version == "4" {
			return ipc, nil
		}
	}
	return nil, fmt.Errorf("failed to find a valid IP address")
}

// configureContainerLink creates a HNSEndpoint for the container using the IPAM result, and then attach it on the container interface.
func (ic *ifConfigurator) configureContainerLink(
	podName string,
	podNameSpace string,
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
	epName := util.GenerateContainerInterfaceName(podName, podNameSpace, infraContainerID)
	// Search endpoint from local cache.
	endpoint, found := ic.getEndpoint(epName)
	if !found {
		if !isInfraContainer(containerNetNS) {
			return fmt.Errorf("failed to find HNSEndpoint: %s", epName)
		}
		// Only create HNS Endpoint for infra container.
		ep, err := ic.createContainerLink(epName, result, containerID, podName, podNameSpace)
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
		ic.removeHNSEndpoint(endpoint, containerID)
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
			ifaceName := fmt.Sprintf("%s (%s)", util.ContainerVNICPrefix, epName)
			if err := util.SetInterfaceMTU(ifaceName, mtu); err != nil {
				return fmt.Errorf("failed to configure MTU on container interface '%s': %v", ifaceName, err)
			}
			return nil
		})
	}
	return nil
}

// createContainerLink creates HNSEndpoint using the IP configuration in the IPAM result.
func (ic *ifConfigurator) createContainerLink(endpointName string, result *current.Result, containerID, podName, podNamespace string) (hostLink *hcsshim.HNSEndpoint, err error) {
	containerIP, err := findContainerIPConfig(result.IPs)
	if err != nil {
		return nil, err
	}
	containerIPStr, err := parseContainerIPs(result.IPs)
	if err != nil {
		klog.Errorf("Failed to find container %s IP", containerID)
	}
	// Save interface config to HNSEndpoint. It's used for creating missing OVS
	// ports during antrea-agent boot stage. The change is introduced mainly for
	// Containerd support. When working with Containerd runtime, antrea-agent creates
	// OVS ports in an asynchronous way. So the OVS ports can be lost if antrea-agent
	// gets stopped/restarted before port creation completes.
	//
	// The interface config will be rebuilt based on the params saved in the "AdditionalParams"
	// field of HNSEndpoint.
	//   - endpointName: the name of the host interface without Hyper-V prefix(vEthernet).
	//     The name is same as the OVS port name and HNSEndpoint name.
	//   - containerID: used as the goroutine lock to avoid concurrency issue.
	//   - podName and PodNamespace: Used to identify the owner of the HNSEndpoint.
	//   - Other params will be passed to OVS port.
	ifaceConfig := interfacestore.NewContainerInterface(
		endpointName,
		containerID,
		podName,
		podNamespace,
		nil,
		containerIPStr)
	ovsAttachInfoData := BuildOVSPortExternalIDs(ifaceConfig)
	ovsAttachInfo := make(map[string]string)
	for k, v := range ovsAttachInfoData {
		valueStr, _ := v.(string)
		ovsAttachInfo[k] = valueStr
	}
	epRequest := &hcsshim.HNSEndpoint{
		Name:             endpointName,
		VirtualNetwork:   ic.hnsNetwork.Id,
		DNSServerList:    strings.Join(result.DNS.Nameservers, ","),
		DNSSuffix:        strings.Join(result.DNS.Search, ","),
		GatewayAddress:   containerIP.Gateway.String(),
		IPAddress:        containerIP.Address.IP,
		AdditionalParams: ovsAttachInfo,
	}
	hnsEP, err := epRequest.Create()
	if err != nil {
		return nil, err
	}
	// Add the new created Endpoint into local cache.
	ic.addEndpoint(hnsEP)
	return hnsEP, nil
}

func (ic *ifConfigurator) getInterfaceConfigForPods(pods sets.String) map[string]*interfacestore.InterfaceConfig {
	interfaces := make(map[string]*interfacestore.InterfaceConfig)
	ic.epCache.Range(func(key, value interface{}) bool {
		ep, _ := value.(*hcsshim.HNSEndpoint)
		ifConfig := parseOVSPortInterfaceConfigFromHNSEndpoint(ep)
		if ifConfig == nil {
			return true
		}
		namespacedName := k8s.NamespacedName(ifConfig.PodNamespace, ifConfig.PodName)
		if pods.Has(namespacedName) {
			interfaces[namespacedName] = ifConfig
		}
		return true
	})
	return interfaces
}

func parseOVSPortInterfaceConfigFromHNSEndpoint(ep *hcsshim.HNSEndpoint) *interfacestore.InterfaceConfig {
	portData := &ovsconfig.OVSPortData{
		Name:        ep.Name,
		ExternalIDs: ep.AdditionalParams,
	}
	ifaceConfig := ParseOVSPortInterfaceConfig(portData, nil, false)
	if ifaceConfig != nil {
		var err error
		ifaceConfig.MAC, err = net.ParseMAC(ep.MacAddress)
		if err != nil {
			klog.Errorf("Failed to parse MAC address from HNSEndpoint %s: %v", ep.MacAddress, err)
			return nil
		}
	}
	return ifaceConfig
}

// attachContainerLink takes the result of the IPAM plugin, and adds the appropriate IP
// addresses and routes to the interface.
// For different CRI runtimes we need to use the appropriate Windows container API:
//   - Docker runtime: HNS API
//   - Containerd runtime: HCS API
func attachContainerLink(ep *hcsshim.HNSEndpoint, containerID, sandbox, containerIFDev string) (*current.Interface, error) {
	var attached bool
	var err error
	var hcnEp *hcn.HostComputeEndpoint
	isDocker := isDockerContainer(sandbox)
	if isDocker {
		// Docker runtime
		attached, err = ep.IsAttached(containerID)
		if err != nil {
			return nil, err
		}
	} else {
		// Containerd runtime
		if hcnEp, err = hcn.GetEndpointByID(ep.Id); err != nil {
			return nil, err
		}
		attachedEpIds, err := hcn.GetNamespaceEndpointIds(sandbox)
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

	containerIface := &current.Interface{
		Name:    containerIFDev,
		Mac:     ep.MacAddress,
		Sandbox: sandbox,
	}

	if attached {
		klog.V(2).Infof("HNS Endpoint %s already attached on container %s", ep.Id, containerID)
		return containerIface, nil
	}

	if isDocker {
		// Docker runtime
		if pollErr := wait.PollImmediate(2*time.Second, 60*time.Second, func() (bool, error) {
			if err = hcsshim.HotAttachEndpoint(containerID, ep.Id); err != nil {
				if err == hcsshim.ErrComputeSystemDoesNotExist {
					return false, err
				}
				klog.ErrorS(err, "Failed to attach endpoint to container, will retry later", "endpoint", ep.Id, "container", containerID)
				return false, nil
			}
			return true, nil
		}); pollErr != nil {
			return nil, err
		}
	} else {
		// Containerd runtime
		if err := hcnEp.NamespaceAttach(sandbox); err != nil {
			return nil, err
		}
	}
	return containerIface, nil
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
		hcnEndpoint, _ := hcn.GetEndpointByID(endpoint.Id)
		if hcnEndpoint != nil && isValidHostNamespace(hcnEndpoint.HostComputeNamespace) {
			err := hcn.RemoveNamespaceEndpoint(hcnEndpoint.HostComputeNamespace, hcnEndpoint.Id)
			if err != nil {
				klog.Errorf("Failed to remove HostComputeEndpoint %s from HostComputeNameSpace %s: %v", hcnEndpoint.Name, hcnEndpoint.HostComputeNamespace, err)
				deleteCh <- err
				return
			}
		}
		_, err := endpoint.Delete()
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
	containerIfaceName := fmt.Sprintf("%s (%s)", util.ContainerVNICPrefix, hnsEP)
	intf, err := net.InterfaceByName(containerIfaceName)
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

// validateExpectedInterfaceIPs checks if the vNIC for the container has configured with correct IP address.
func validateExpectedInterfaceIPs(containerIPConfig *current.IPConfig, intf *net.Interface) error {
	addrs, err := intf.Addrs()
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

		ep, err := hcsshim.GetHNSEndpointByName(hostIntf.Name)
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
func (ic *ifConfigurator) getOVSInterfaceType() int {
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
		pollErr := wait.PollImmediate(time.Second, 60*time.Second, func() (bool, error) {
			containerAccess.lockContainer(containerID)
			defer containerAccess.unlockContainer(containerID)
			currentEP, ok := ic.getEndpoint(endpointName)
			if !ok {
				klog.InfoS("HNSEndpoint doesn't exist in cache, exit current goroutine", "HNSEndpoint Name", endpointName)
				return true, nil
			}
			if currentEP.Id != expectedEP.Id {
				klog.InfoS("Detected HNSEndpoint change, exit current goroutine", "HNSEndpoint Name", endpointName)
				return true, nil
			}
			if !util.HostInterfaceExists(ifaceName) {
				klog.InfoS("Waiting for interface to be created", "interface name", ifaceName)
				return false, nil
			}
			if err = hook(); err != nil {
				return false, err
			}
			return true, nil
		})

		if pollErr != nil {
			klog.ErrorS(err, "Failed to execute postInterfaceCreateHook", "interface name", ifaceName)
		}
	}()
	return nil
}
