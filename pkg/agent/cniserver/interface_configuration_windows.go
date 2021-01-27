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
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	cnipb "github.com/vmware-tanzu/antrea/pkg/apis/cni/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/k8s"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
)

const (
	notFoundHNSEndpoint = "The endpoint was not found"
)

var dummyMac, _ = net.ParseMAC("00:00:00:00:00:00")

type ifConfigurator struct {
	hnsNetwork *hcsshim.HNSNetwork
	epCache    *sync.Map
	ifCache    *sync.Map
}

func newInterfaceConfigurator(ovsDataPathType string, isOvsHardwareOffloadEnabled bool) (*ifConfigurator, error) {
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
		epCache: epCache,
	}, nil

}

func (ic *ifConfigurator) addEndpoint(ep *hcsshim.HNSEndpoint) {
	ic.epCache.Store(ep.Name, ep)
}

// ensureHNSNetwork checks if the target HNSNetwork is created on the node or not. If the HNSNetwork does not exit,
// return error.
func (ic *ifConfigurator) ensureHNSNetwork() error {
	if ic.hnsNetwork != nil {
		return nil
	}
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(util.LocalHNSNetwork)
	if err != nil {
		return err
	}
	ic.hnsNetwork = hnsNetwork
	return nil
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
	sriovVFDeviceID string,
	result *current.Result,
) error {
	if sriovVFDeviceID != "" {
		return fmt.Errorf("OVS hardware offload is not supported on windows")
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
	return nil
}

// createContainerLink creates HNSEndpoint using the IP configuration in the IPAM result.
func (ic *ifConfigurator) createContainerLink(endpointName string, result *current.Result, containerID, podName, podNamespace string) (hostLink *hcsshim.HNSEndpoint, err error) {
	// Create a new Endpoint if not found.
	if err := ic.ensureHNSNetwork(); err != nil {
		return nil, err
	}
	containerIP, err := findContainerIPConfig(result.IPs)
	if err != nil {
		return nil, err
	}
	containerIPStr, err := parseContainerIPs(result.IPs)
	if err != nil {
		klog.Errorf("Failed to find container %s IP", containerID)
	}
	// Save interface config to HNSEndpoint. It's mainly used for creating missing
	// OVS ports during antrea-agent boot stage. The interface config will be rebuilt
	// based on the params saved in AdditionalParams field of HNSEndpoint.
	//   - endpointName: the name of host interface without Hyper-V prefix(vEthernet).
	//     The name is same with OVS port name and HNSEndpoint name.
	//   - containerID: Used as key for goroutine lock to avid concurrency issue.
	//   - podName and PodNamespace: Used to identify the owner of the HNSEndpoint.
	//   - dummyMac: the MAC address of the HNSEndpoint is unknown before we creating it.
	//     Use a dummy MAC address here. The real MAC is retrieved from HNSEndopint when we
	//     parse the config.
	//   - Other params will be passed to OVS port

	ifaceConfig := interfacestore.NewContainerInterface(
		endpointName,
		containerID,
		podName,
		podNamespace,
		dummyMac,
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

func (ic *ifConfigurator) getInterfacesConfigForPods(pods sets.String) map[string]*interfacestore.InterfaceConfig {
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
	ifaceConfig := ParseOVSPortInterfaceConfig(portData, nil)
	if ifaceConfig != nil {
		var err error
		ifaceConfig.MAC, err = net.ParseMAC(ep.MacAddress)
		if err != nil {
			klog.Errorf("Failed to parse MAC address from OVS external config %s: %v", ep.MacAddress, err)
			return nil
		}
	}
	return ifaceConfig
}

// attachContainerLink takes the result of the IPAM plugin, and adds the appropriate IP
// addresses and routes to the interface.
func attachContainerLink(ep *hcsshim.HNSEndpoint, containerID, sandbox, containerIFDev string) (*current.Interface, error) {
	var attached bool
	var err error
	var hcnEp *hcn.HostComputeEndpoint
	if sandbox == "none" || strings.Contains(sandbox, ":") {
		attached, err = ep.IsAttached(containerID)
		if err != nil {
			return nil, err
		}
	} else {
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

	if attached {
		klog.V(2).Infof("HNS Endpoint %s already attached on container %s", ep.Id, containerID)
	} else {
		if hcnEp == nil {
			if err := hcsshim.HotAttachEndpoint(containerID, ep.Id); err != nil {
				if isInfraContainer(sandbox) || hcsshim.ErrComputeSystemDoesNotExist != err {
					return nil, err
				}
			}
		} else {
			if err := hcn.AddNamespaceEndpoint(sandbox, hcnEp.Id); err != nil {
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
		if hcnEndpoint != nil && hcnEndpoint.HostComputeNamespace != "" {
			err := hcn.RemoveNamespaceEndpoint(hcnEndpoint.HostComputeNamespace, hcnEndpoint.Id)
			if err != nil {
				klog.Errorf("Failed to remove HostComputeEndpoint %s from HostComputeNameSpace %s: %v", hcnEndpoint.Name, hcnEndpoint.HostComputeNamespace, err)
				deleteCh <- err
				return
			}
		}
		_, err := endpoint.Delete()
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
