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
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/Microsoft/hcsshim"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	cnipb "github.com/vmware-tanzu/antrea/pkg/apis/cni/v1beta1"
)

const (
	notFoundHNSEndpoint = "The endpoint was not found"
)

type endpoint struct {
	hnsEP      *hcsshim.HNSEndpoint
	containers []string
}

type ifConfigurator struct {
	hnsNetwork *hcsshim.HNSNetwork
	epCache    *sync.Map
}

func newInterfaceConfigurator(ovsDataPathType string) (*ifConfigurator, error) {
	eps, err := hcsshim.HNSListEndpointRequest()
	if err != nil {
		return nil, err
	}
	epCache := &sync.Map{}
	for i := range eps {
		hnsEP := eps[i]
		ep := &endpoint{
			hnsEP: &hnsEP,
		}
		epCache.Store(hnsEP.Name, ep)
	}
	return &ifConfigurator{
		epCache: epCache,
	}, nil

}

func (ic *ifConfigurator) addEndpoint(ep *endpoint) {
	ic.epCache.Store(ep.hnsEP.Name, ep)
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

func (ic *ifConfigurator) getEndpoint(name string) (*endpoint, bool) {
	value, ok := ic.epCache.Load(name)
	if !ok {
		return nil, false
	}
	ep, _ := value.(*endpoint)
	return ep, true
}

func (ic *ifConfigurator) delEndpoint(name string) {
	ic.epCache.Delete(name)
}

// configureContainerLink creates a HNSEndpoint for the container using the IPAM result, and then attach it on the container interface.
func (ic *ifConfigurator) configureContainerLink(
	podName string,
	podNameSpace string,
	containerID string,
	containerNetNS string,
	containerIFDev string,
	mtu int,
	result *current.Result,
) error {
	// Create HNS Endpoint.
	endpoint, err := ic.createContainerLink(podName, podNameSpace, containerID, result)
	if err != nil {
		return err
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
		Name:    endpoint.hnsEP.Name,
		Mac:     endpoint.hnsEP.MacAddress,
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
func (ic *ifConfigurator) createContainerLink(podName string, podNameSpace string, containerID string, result *current.Result) (hostLink *endpoint, err error) {
	epName := util.GenerateContainerInterfaceName(podName, podNameSpace)
	// Search endpoint from local cache.
	ep, found := ic.getEndpoint(epName)
	if found {
		return ep, nil
	}

	// Create a new Endpoint if not found.
	if err := ic.ensureHNSNetwork(); err != nil {
		return nil, err
	}
	containerIP, err := findContainerIPConfig(result.IPs)
	if err != nil {
		return nil, err
	}
	epRequest := &hcsshim.HNSEndpoint{
		Name:           epName,
		VirtualNetwork: ic.hnsNetwork.Id,
		DNSServerList:  strings.Join(result.DNS.Nameservers, ","),
		DNSSuffix:      result.DNS.Domain,
		GatewayAddress: containerIP.Gateway.String(),
		IPAddress:      containerIP.Address.IP,
	}
	hnsEP, err := epRequest.Create()
	if err != nil {
		return nil, err
	}
	ep = &endpoint{
		hnsEP: hnsEP,
	}
	// Add the new created Endpoint into local cache.
	ic.addEndpoint(ep)
	return ep, nil
}

// attachContainerLink takes the result of the IPAM plugin, and adds the appropriate IP
// addresses and routes to the interface. It then sends a gratuitous ARP to the network.
func attachContainerLink(ep *endpoint, containerID, sandbox, containerIFDev string) (*current.Interface, error) {
	var found bool
	for _, c := range ep.containers {
		if c == containerID {
			found = true
		}
	}

	if !found {
		if err := hcsshim.HotAttachEndpoint(containerID, ep.hnsEP.Id); err != nil {
			return nil, err
		}
		ep.containers = append(ep.containers, containerID)
	}
	containerIface := &current.Interface{
		Name:    strings.Join([]string{ep.hnsEP.Name, containerIFDev}, "_"),
		Mac:     ep.hnsEP.MacAddress,
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
func (ic *ifConfigurator) removeHNSEndpoint(endpoint *endpoint, containerID string) error {
	epName := endpoint.hnsEP.Name
	// Remove HNSEndpoint.
	_, err := endpoint.hnsEP.Delete()
	if err != nil {
		if !strings.Contains(err.Error(), notFoundHNSEndpoint) {
			klog.Errorf("Failed to delete container interface %s: %v", containerID, err)
			return err
		}
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
	containerRoutes []*cnitypes.Route) (*vethPair, error) {

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

// getOVSInterfaceType returns "internal". Windows uses internal OVS interface for container vNIC.
func (ic *ifConfigurator) getOVSInterfaceType() int {
	return internalOVSInterfaceType
}
