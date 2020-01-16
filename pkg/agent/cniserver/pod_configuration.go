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
	"encoding/json"
	"fmt"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/j-keck/arping"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog"
	"net"
	"time"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/agent/util/ethtool"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
)

type vethPair struct {
	name      string
	ifIndex   int
	peerIndex int
}

type k8sArgs struct {
	cnitypes.CommonArgs
	K8S_POD_NAME               cnitypes.UnmarshallableString
	K8S_POD_NAMESPACE          cnitypes.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID cnitypes.UnmarshallableString
}

const (
	ovsExternalIDMAC          = "attached-mac"
	ovsExternalIDIP           = "ip-address"
	ovsExternalIDContainerID  = "container-id"
	ovsExternalIDPodName      = "pod-name"
	ovsExternalIDPodNamespace = "pod-namespace"
)

type podConfigurator struct {
	ovsBridgeClient ovsconfig.OVSBridgeClient
	ofClient        openflow.Client
	ifaceStore      interfacestore.InterfaceStore
	gatewayMAC      net.HardwareAddr
	ovsDatapathType string
}

func newPodConfigurator(
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	ofClient openflow.Client,
	ifaceStore interfacestore.InterfaceStore,
	gatewayMAC net.HardwareAddr,
	ovsDatapathType string,
) *podConfigurator {
	return &podConfigurator{ovsBridgeClient, ofClient, ifaceStore, gatewayMAC, ovsDatapathType}
}

// setupInterfaces creates a veth pair: containerIface is in the container
// network namespace and hostIface is in the host network namespace.
func (pc *podConfigurator) setupInterfaces(
	podName, podNamespace, ifname string,
	netns ns.NetNS,
	mtu int) (hostIface *current.Interface, containerIface *current.Interface, err error) {
	hostVethName := util.GenerateContainerInterfaceName(podName, podNamespace)
	hostIface = &current.Interface{}
	containerIface = &current.Interface{}

	if err := netns.Do(func(hostNS ns.NetNS) error {
		hostVeth, containerVeth, err := ip.SetupVethWithName(ifname, hostVethName, mtu, hostNS)
		if err != nil {
			return err
		}
		klog.V(2).Infof("Setup interfaces host: %s, container %s", hostVeth.Name, containerVeth.Name)
		containerIface.Name = containerVeth.Name
		containerIface.Mac = containerVeth.HardwareAddr.String()
		containerIface.Sandbox = netns.Path()
		hostIface.Name = hostVeth.Name
		hostIface.Mac = hostVeth.HardwareAddr.String()
		// OVS netdev datapath doesn't support TX checksum offloading, i.e. if packet
		// arrives with bad/no checksum it will be sent to the output port with same bad/no checksum.
		if pc.ovsDatapathType == ovsconfig.OVSDatapathNetdev {
			if err := ethtool.EthtoolTXHWCsumOff(containerVeth.Name); err != nil {
				return fmt.Errorf("error when disabling TX checksum offload on container veth: %v", err)
			}
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}

	return hostIface, containerIface, nil
}

// configureContainerAddr takes the result of the IPAM plugin, and adds the appropriate IP
// addresses and routes to the interface. It then sends a gratuitous ARP to the network.
func configureContainerAddr(netns ns.NetNS, containerInterface *current.Interface, result *current.Result) error {
	var containerVeth *net.Interface
	if err := netns.Do(func(containerNs ns.NetNS) error {
		var err error
		containerVeth, err = net.InterfaceByName(containerInterface.Name)
		if err != nil {
			klog.Errorf("Failed to find container interface %s in ns %s", containerInterface.Name, netns.Path())
			return err
		}
		if err := ipam.ConfigureIface(containerInterface.Name, result); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	if containerVeth != nil {
		// Send 3 GARP packets in another goroutine with 50ms interval. It's because Openflow entries are installed async,
		// and the gratuitous ARP could be sent out after the Openflow entries are installed. Using another goroutine
		// ensures the processing of CNI ADD request is not blocked.
		go func() {
			netns.Do(func(containerNs ns.NetNS) error {
				count := 0
				for count < 3 {
					select {
					case <-time.Tick(50 * time.Millisecond):
						// Send gratuitous ARP to network in case of stale mappings for this IP address
						// (e.g. if a previous - deleted - Pod was using the same IP).
						for _, ipc := range result.IPs {
							if ipc.Version == "4" {
								arping.GratuitousArpOverIface(ipc.Address.IP, *containerVeth)
							}
						}
					}
					count += 1
				}
				return nil
			})
		}()
	}
	return nil
}

func validateInterface(intf *current.Interface, inNetns bool) (netlink.Link, error) {
	if intf.Name == "" {
		return nil, fmt.Errorf("interface name is missing")
	}
	if inNetns {
		if intf.Sandbox == "" {
			return nil, fmt.Errorf("interface %s is expected in netns", intf.Name)
		}
	} else {
		if intf.Sandbox != "" {
			return nil, fmt.Errorf("interface %s is expected not in netns", intf.Name)
		}
	}

	link, err := netlink.LinkByName(intf.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to find link for interface %s", intf.Name)
	}

	_, isVeth := link.(*netlink.Veth)
	if !isVeth {
		return nil, fmt.Errorf("interface %s is not of type veth", intf.Name)
	}
	return link, nil
}

func validateContainerInterface(intf *current.Interface) (*vethPair, error) {
	link, err := validateInterface(intf, true)
	if err != nil {
		return nil, err
	}

	linkName := link.Attrs().Name
	veth := &vethPair{}
	_, veth.peerIndex, err = ip.GetVethPeerIfindex(linkName)
	if err != nil {
		return nil, fmt.Errorf("failed to get veth peer index for veth %s: %v", linkName, err)
	}
	veth.ifIndex = link.Attrs().Index
	if intf.Mac != link.Attrs().HardwareAddr.String() {
		return nil, fmt.Errorf("interface %s MAC %s doesn't match container MAC: %s",
			intf.Name, intf.Mac, link.Attrs().HardwareAddr.String())
	}
	veth.name = linkName
	return veth, nil
}

func validateContainerPeerInterface(interfaces []*current.Interface, containerVeth *vethPair) (*vethPair, error) {
	// Interate all the passed interfaces and look up the host interface by
	// matching the veth peer interface index.
	for _, hostIntf := range interfaces {
		if hostIntf.Sandbox != "" {
			// Not in the default Namespace. Must be the container interface.
			continue
		}
		link, err := validateInterface(hostIntf, false)
		if err != nil {
			klog.Errorf("Failed to validate interface %s: %v",
				hostIntf.Name, err)
			continue
		}

		if link.Attrs().Index != containerVeth.peerIndex {
			continue
		}

		hostVeth := &vethPair{ifIndex: link.Attrs().Index, name: link.Attrs().Name}
		_, hostVeth.peerIndex, err = ip.GetVethPeerIfindex(hostVeth.name)
		if err != nil {
			return nil, fmt.Errorf("failed to get veth peer index for host interface %s: %v",
				hostIntf.Name, err)
		}

		if hostVeth.peerIndex != containerVeth.ifIndex {
			return nil, fmt.Errorf("host interface %s peer index doesn't match container interface %s index",
				hostIntf.Name, containerVeth.name)
		}

		if hostIntf.Mac != "" {
			if hostIntf.Mac != link.Attrs().HardwareAddr.String() {
				klog.Errorf("Host interface %s MAC %s doesn't match link address %s",
					hostIntf.Name, hostIntf.Mac, link.Attrs().HardwareAddr.String())
				return nil, fmt.Errorf("host interface %s MAC %s doesn't match",
					hostIntf.Name, hostIntf.Mac)
			}
		}
		return hostVeth, nil

	}

	return nil, fmt.Errorf("peer veth interface not found for container interface %s",
		containerVeth.name)
}

func parseContainerIP(ips []*current.IPConfig) (net.IP, error) {
	for _, ipc := range ips {
		if ipc.Version == "4" {
			return ipc.Address.IP, nil
		}
	}
	return nil, fmt.Errorf("failed to find a valid IP address")
}

func buildContainerConfig(
	interfaceName, containerID, podName, podNamespace string,
	containerIface *current.Interface,
	ips []*current.IPConfig) *interfacestore.InterfaceConfig {
	containerIP, err := parseContainerIP(ips)
	if err != nil {
		klog.Errorf("Failed to find container %s IP", containerID)
	}
	// containerIface.Mac should be a valid MAC string, otherwise it should throw error before
	containerMAC, _ := net.ParseMAC(containerIface.Mac)
	return interfacestore.NewContainerInterface(
		interfaceName,
		containerID,
		podName,
		podNamespace,
		containerMAC,
		containerIP)
}

// BuildOVSPortExternalIDs parses OVS port external_ids from InterfaceConfig.
// external_ids are used to compare and sync container interface configuration.
func BuildOVSPortExternalIDs(containerConfig *interfacestore.InterfaceConfig) map[string]interface{} {
	externalIDs := make(map[string]interface{})
	externalIDs[ovsExternalIDMAC] = containerConfig.MAC.String()
	externalIDs[ovsExternalIDContainerID] = containerConfig.ContainerID
	externalIDs[ovsExternalIDIP] = containerConfig.IP.String()
	externalIDs[ovsExternalIDPodName] = containerConfig.PodName
	externalIDs[ovsExternalIDPodNamespace] = containerConfig.PodNamespace
	return externalIDs
}

// ParseOVSPortInterfaceConfig reads the Pod properties saved in the OVS port
// external_ids, initializes and returns an InterfaceConfig struct.
// nill will be returned, if the OVS port does not have external IDs or it is
// not created for a Pod interface.
func ParseOVSPortInterfaceConfig(portData *ovsconfig.OVSPortData, portConfig *interfacestore.OVSPortConfig) *interfacestore.InterfaceConfig {
	if portData.ExternalIDs == nil {
		klog.V(2).Infof("OVS port %s has no external_ids", portData.Name)
		return nil
	}

	containerID, found := portData.ExternalIDs[ovsExternalIDContainerID]
	if !found {
		klog.V(2).Infof("OVS port %s has no %s in external_ids", portData.Name, ovsExternalIDContainerID)
		return nil
	}
	containerIP := net.ParseIP(portData.ExternalIDs[ovsExternalIDIP])
	containerMAC, err := net.ParseMAC(portData.ExternalIDs[ovsExternalIDMAC])
	if err != nil {
		klog.Errorf("Failed to parse MAC address from OVS external config %s: %v",
			portData.ExternalIDs[ovsExternalIDMAC], err)
	}
	podName, _ := portData.ExternalIDs[ovsExternalIDPodName]
	podNamespace, _ := portData.ExternalIDs[ovsExternalIDPodNamespace]

	interfaceConfig := interfacestore.NewContainerInterface(
		portData.Name,
		containerID,
		podName,
		podNamespace,
		containerMAC,
		containerIP)
	interfaceConfig.OVSPortConfig = portConfig
	return interfaceConfig
}

func (pc *podConfigurator) configureInterfaces(
	podName string,
	podNameSpace string,
	containerID string,
	containerNetNS string,
	containerIFDev string,
	mtu int,
	result *current.Result,
) error {
	netns, err := ns.GetNS(containerNetNS)
	if err != nil {
		return fmt.Errorf("failed to open netns %s: %v", containerNetNS, err)
	}
	defer netns.Close()
	// Create veth pair and link up
	hostIface, containerIface, err := pc.setupInterfaces(podName, podNameSpace, containerIFDev, netns, mtu)
	if err != nil {
		return fmt.Errorf("failed to create veth devices for container %s: %v", containerID, err)
	}
	// Delete veth pair if any failure occurs in later manipulation.
	success := false
	defer func() {
		if !success {
			ip.DelLinkByName(hostIface.Name)
		}
	}()

	result.Interfaces = []*current.Interface{hostIface, containerIface}

	// Use the outer veth interface name as the OVS port name.
	ovsPortName := hostIface.Name
	containerConfig := buildContainerConfig(ovsPortName, containerID, podName, podNameSpace, containerIface, result.IPs)

	// create OVS Port and add attach container configuration into external_ids
	klog.V(2).Infof("Adding OVS port %s for container %s", ovsPortName, containerID)
	portUUID, err := pc.setupContainerOVSPort(containerConfig, ovsPortName)
	if err != nil {
		return fmt.Errorf("failed to add OVS port for container %s: %v", containerID, err)
	}
	// Remove OVS port if any failure occurs in later manipulation.
	defer func() {
		if !success {
			pc.ovsBridgeClient.DeletePort(portUUID)
		}
	}()

	// GetOFPort will wait for up to 1 second for OVSDB to report the OFPort number.
	ofPort, err := pc.ovsBridgeClient.GetOFPort(ovsPortName)
	if err != nil {
		return fmt.Errorf("failed to get of_port of OVS port %s: %v", ovsPortName, err)
	}

	klog.V(2).Infof("Setting up Openflow entries for container %s", containerID)
	err = pc.ofClient.InstallPodFlows(ovsPortName, containerConfig.IP, containerConfig.MAC, pc.gatewayMAC, uint32(ofPort))
	if err != nil {
		return fmt.Errorf("failed to add Openflow entries for container %s: %v", containerID, err)
	}
	defer func() {
		if !success {
			pc.ofClient.UninstallPodFlows(ovsPortName)
		}
	}()

	// Note that configuring IP will send gratuitous ARP, it must be executed
	// after Pod Openflow entries are installed, otherwise gratuitous ARP would
	// be dropped.
	klog.V(2).Infof("Configuring IP address for container %s", containerID)
	if err = configureContainerAddr(netns, containerIface, result); err != nil {
		return fmt.Errorf("failed to configure IP address for container %s: %v", containerID, err)
	}

	containerConfig.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID, OFPort: ofPort}
	// Add containerConfig into local cache
	pc.ifaceStore.AddInterface(containerConfig)
	// Mark the manipulation as success to cancel deferred operations.
	success = true
	klog.Infof("Configured interfaces for container %s", containerID)
	return nil
}

func (pc *podConfigurator) setupContainerOVSPort(
	containerConfig *interfacestore.InterfaceConfig,
	ovsPortName string) (string, error) {
	ovsAttchInfo := BuildOVSPortExternalIDs(containerConfig)
	if portUUID, err := pc.ovsBridgeClient.CreatePort(ovsPortName, ovsPortName, ovsAttchInfo); err != nil {
		klog.Errorf("Failed to add OVS port %s, remove from local cache: %v", ovsPortName, err)
		return "", err
	} else {
		return portUUID, nil
	}
}

func (pc *podConfigurator) removeInterfaces(podName, podNamespace, containerID string) error {
	containerConfig, found := pc.ifaceStore.GetContainerInterface(podName, podNamespace)
	if !found {
		klog.V(2).Infof("Did not find the port for container %s in local cache", containerID)
		return nil
	}

	klog.V(2).Infof("Deleting veth devices for container %s", containerID)
	// Don't return an error if the device is already removed as CniDel can be called multiple times.
	if err := ip.DelLinkByName(containerConfig.InterfaceName); err != nil {
		if err != ip.ErrLinkNotFound {
			return fmt.Errorf("failed to delete veth devices for container %s: %v", containerID, err)
		}
		klog.V(2).Infof("Did not find interface %s for container %s", containerConfig.InterfaceName, containerID)
	}

	klog.V(2).Infof("Deleting Openflow entries for container %s", containerID)
	if err := pc.ofClient.UninstallPodFlows(containerConfig.InterfaceName); err != nil {
		return fmt.Errorf("failed to delete Openflow entries for container %s: %v", containerID, err)
	}

	klog.V(2).Infof("Deleting OVS port %s for container %s", containerConfig.PortUUID, containerID)
	// TODO: handle error and introduce garbage collection for failure on deletion
	if err := pc.ovsBridgeClient.DeletePort(containerConfig.PortUUID); err != nil {
		return fmt.Errorf("failed to delete OVS port for container %s: %v", containerID, err)
	}
	// Remove container configuration from cache.
	pc.ifaceStore.DeleteInterface(containerConfig)
	klog.Infof("Removed interfaces for container %s", containerID)
	return nil
}

func (pc *podConfigurator) checkInterfaces(
	containerID, containerNetNS, podName, podNamespace string,
	containerIface *current.Interface,
	prevResult *current.Result) error {
	netns, err := ns.GetNS(containerNetNS)
	if err != nil {
		klog.Errorf("Failed to check netns config %s: %v", containerNetNS, err)
		return err
	}
	defer netns.Close()

	if containerVeth, err := pc.checkContainerInterface(
		containerNetNS,
		containerID,
		netns,
		containerIface,
		prevResult.IPs,
		prevResult.Routes); err != nil {
		return err
	} else if err := pc.checkHostInterface(
		containerID,
		podName,
		podNamespace,
		containerIface,
		containerVeth,
		prevResult.IPs,
		prevResult.Interfaces); err != nil {
		return err
	}
	return nil
}

func (pc *podConfigurator) checkContainerInterface(
	containerNetns, containerID string,
	netns ns.NetNS,
	containerIface *current.Interface,
	containerIPs []*current.IPConfig,
	containerRoutes []*cnitypes.Route) (*vethPair, error) {
	var contVeth *vethPair
	// Check netns configuration
	if containerNetns != containerIface.Sandbox {
		klog.Errorf("Sandbox in prevResult %s doesn't match configured netns: %s",
			containerIface.Sandbox, containerNetns)
		return nil, fmt.Errorf("sandbox in prevResult %s doesn't match configured netns: %s",
			containerIface.Sandbox, containerNetns)
	}
	// Check container interface configuration
	if err := netns.Do(func(netNS ns.NetNS) error {
		var errlink error
		// Check container link config
		contVeth, errlink = validateContainerInterface(containerIface)
		if errlink != nil {
			return errlink
		}
		// Check container IP config
		if err := ip.ValidateExpectedInterfaceIPs(containerIface.Name, containerIPs); err != nil {
			return err
		}
		// Check container route config
		if err := ip.ValidateExpectedRoute(containerRoutes); err != nil {
			return err
		}
		return nil
	}); err != nil {
		klog.Errorf("Failed to check container %s interface configurations in netns %s: %v",
			containerID, containerNetns, err)
		return nil, err
	}
	return contVeth, nil
}

func (pc *podConfigurator) checkHostInterface(
	containerID, podName, podNamespace string,
	containerIntf *current.Interface,
	containerVeth *vethPair,
	containerIPs []*current.IPConfig,
	interfaces []*current.Interface) error {
	hostVeth, errlink := validateContainerPeerInterface(interfaces, containerVeth)
	if errlink != nil {
		klog.Errorf("Failed to check container %s interface on the host: %v",
			containerID, errlink)
		return errlink
	}
	if err := pc.validateOVSInterfaceConfig(containerID,
		podName,
		podNamespace,
		containerIntf.Mac,
		containerIPs); err != nil {
		klog.Errorf("Failed to check host link %s for container %s attaching status on ovs. err: %v",
			hostVeth.name, containerID, err)
		return err
	}
	return nil
}

func (pc *podConfigurator) validateOVSInterfaceConfig(
	containerID, podName, podNamespace string,
	containerMAC string,
	ips []*current.IPConfig) error {
	if containerConfig, found := pc.ifaceStore.GetContainerInterface(podName, podNamespace); found {
		if containerConfig.MAC.String() != containerMAC {
			return fmt.Errorf("interface MAC %s does not match container %s MAC",
				containerConfig.MAC.String(), containerID)
		}

		for _, ipc := range ips {
			if ipc.Version == "4" {
				if containerConfig.IP.Equal(ipc.Address.IP) {
					return nil
				}
			}
		}
		return fmt.Errorf("interface IP %s does not match container %s IP",
			containerConfig.IP.String(), containerID)
	} else {
		return fmt.Errorf("container %s interface not found from local cache", containerID)
	}
}

func parsePrevResult(conf *NetworkConfig) error {
	if conf.RawPrevResult == nil {
		return nil
	}

	resultBytes, err := json.Marshal(conf.RawPrevResult)
	if err != nil {
		return fmt.Errorf("could not serialize prevResult: %v", err)
	}
	conf.RawPrevResult = nil
	conf.PrevResult, err = version.NewResult(conf.CNIVersion, resultBytes)
	if err != nil {
		return fmt.Errorf("could not parse prevResult: %v", err)
	}
	return nil
}

func (pc *podConfigurator) reconcile(pods []corev1.Pod) error {
	// desiredInterfaces is the exact set of interfaces that should be present, based on the
	// current list of Pods.
	desiredInterfaces := make(map[string]bool)
	// knownInterfaces is the list of interfaces currently in the local cache.
	knownInterfaces := pc.ifaceStore.GetInterfaceKeysByType(interfacestore.ContainerInterface)

	for _, pod := range pods {
		// Skip Pods for which we are not in charge of the networking.
		if pod.Spec.HostNetwork {
			continue
		}

		// We rely on the interface cache / store - which is initialized from the persistent
		// OVSDB - to map the Pod to its interface configuration. The interface
		// configuration includes the parameters we need to replay the flows.
		containerConfig, found := pc.ifaceStore.GetContainerInterface(pod.Name, pod.Namespace)
		if !found {
			// This should not happen since OVSDB is persisted on the Node.
			// TODO: is there anything else we should be doing? Assuming that the Pod's
			// interface still exists, we can repair the interface store since we can
			// retrieve the name of the host interface for the Pod by calling
			// GenerateContainerInterfaceName. One thing we would not be able to
			// retrieve is the container ID which is part of the container configuration
			// we store in the cache, but this ID is not used for anything at the
			// moment. However, if the interface does not exist, there is nothing we can
			// do since we do not have the original CNI parameters.
			klog.Warningf("Interface for Pod %s/%s not found in the interface store", pod.Namespace, pod.Name)
			continue
		}
		klog.V(4).Infof("Syncing interface %s for Pod %s/%s", containerConfig.InterfaceName, pod.Namespace, pod.Name)
		if err := pc.ofClient.InstallPodFlows(
			containerConfig.InterfaceName,
			containerConfig.IP,
			containerConfig.MAC,
			pc.gatewayMAC,
			uint32(containerConfig.OFPort),
		); err != nil {
			klog.Errorf("Error when re-installing flows for Pod %s/%s", pod.Namespace, pod.Name)
			continue
		}
		desiredInterfaces[util.GenerateContainerInterfaceKey(pod.Name, pod.Namespace)] = true
	}

	for _, ifaceID := range knownInterfaces {
		if _, found := desiredInterfaces[ifaceID]; found {
			// this interface matches an existing Pod.
			continue
		}
		// clean-up and delete interface
		containerConfig, found := pc.ifaceStore.GetInterface(ifaceID)
		if !found {
			// should not happen, nothing should have concurrent access to the interface
			// store.
			klog.Errorf("Interface %s can no longer be found in the interface store", ifaceID)
			continue
		}
		klog.V(4).Infof("Deleting interface %s", ifaceID)
		if err := pc.removeInterfaces(
			containerConfig.PodName,
			containerConfig.PodNamespace,
			containerConfig.ContainerID,
		); err != nil {
			klog.Errorf("Failed to delete interface %s: %v", ifaceID, err)
		}
		// interface should no longer be in store after the call to removeInterfaces
	}
	return nil
}
