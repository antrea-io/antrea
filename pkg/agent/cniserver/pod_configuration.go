package cniserver

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/j-keck/arping"
	"github.com/vishvananda/netlink"
	"k8s.io/klog"
	"okn/pkg/agent"
	"okn/pkg/agent/openflow"
	"okn/pkg/ovs/ovsconfig"
)

type vethPair struct {
	name      string
	ifIndex   int
	peerIndex int
}

type k8sArgs struct {
	types.CommonArgs
	K8S_POD_NAME               types.UnmarshallableString
	K8S_POD_NAMESPACE          types.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString
}

// TODO: mock the ip dependency by defining an interface and write unit tests for this code.

// setupInterface creates veth pair, containerVeth plugged in the netns, and hostVeth will be attached to OVS bridge
func setupInterface(podName string, podNamespace string, ifname string, netns ns.NetNS) (*current.Interface, *current.Interface, error) {
	hostVethName := agent.GenerateContainerInterfaceName(podName, podNamespace)
	containerIface := &current.Interface{}
	hostIface := &current.Interface{}

	if err := netns.Do(func(hostNS ns.NetNS) error {
		hostVeth, containerVeth, err := ip.SetupVethWithName(ifname, hostVethName, defaultMTU, hostNS)
		if err != nil {
			return err
		}
		klog.Infof("Setup interfaces host: %s, container %s", hostVeth.Name, containerVeth.Name)
		containerIface.Name = containerVeth.Name
		containerIface.Mac = containerVeth.HardwareAddr.String()
		containerIface.Sandbox = netns.Path()
		hostIface.Name = hostVeth.Name
		return nil
	}); err != nil {
		return nil, nil, err
	}

	hostVeth, err := netlink.LinkByName(hostIface.Name)
	if err != nil {
		// Todo: Add retry before remove interfaces
		// Remove veth pair if not find peer link on host
		_ = netns.Do(func(hostNS ns.NetNS) error {
			_, err := ip.DelLinkByNameAddr(ifname)
			return err
		})
		return nil, nil, fmt.Errorf("failed to lookup host interface %q: %v", hostIface.Name, err)
	}

	hostIface.Mac = hostVeth.Attrs().HardwareAddr.String()
	return hostIface, containerIface, nil
}

// configureContainerAddr configures container address and routes if existed in IPAM result, and send GARP after that.
func configureContainerAddr(netns ns.NetNS, contIntf *current.Interface, result *current.Result) error {
	if err := netns.Do(func(containerNs ns.NetNS) error {
		contVeth, err := net.InterfaceByName(contIntf.Name)
		if err != nil {
			klog.Errorf("Failed to find container interface %s in ns %s", contIntf.Name, netns.Path())
			return err
		}
		if err := ipam.ConfigureIface(contIntf.Name, result); err != nil {
			return err
		}
		// Send ARP to activate container interface
		// Todo: change the maxRetry times and use async mode
		for _, ipc := range result.IPs {
			if ipc.Version == "4" {
				_ = arping.GratuitousArpOverIface(ipc.Address.IP, *contVeth)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func validateInterface(intf *current.Interface, inNetns bool) (*vethPair, netlink.Link, error) {
	veth := &vethPair{}
	if intf.Name == "" {
		return veth, nil, fmt.Errorf("interface name is missing")
	}
	link, err := netlink.LinkByName(intf.Name)
	if err != nil {
		return veth, link, fmt.Errorf("failed to find interface with name %s", intf.Name)
	}
	if inNetns {
		if intf.Sandbox == "" {
			return veth, link, fmt.Errorf("interface %s is expected in netns", intf.Name)
		}
	} else {
		if intf.Sandbox != "" {
			return veth, link, fmt.Errorf("interface %s is expected not in netns", intf.Name)
		}
	}
	return veth, link, nil
}

func validateContainerInterface(intf *current.Interface) (*vethPair, error) {
	veth, link, err := validateInterface(intf, true)
	if err != nil {
		return veth, err
	}

	linkAddrName := link.Attrs().Name
	_, isVeth := link.(*netlink.Veth)
	if !isVeth {
		return veth, fmt.Errorf("container interface %s is not of type veth", linkAddrName)
	}
	_, veth.peerIndex, err = ip.GetVethPeerIfindex(linkAddrName)
	if err != nil {
		return veth, fmt.Errorf("unable to obtain veth peer index for veth %s", linkAddrName)
	}
	veth.ifIndex = link.Attrs().Index
	if intf.Mac != link.Attrs().HardwareAddr.String() {
		return veth, fmt.Errorf("interface %s MAC %s doesn't match container MAC: %s",
			intf.Name, intf.Mac, link.Attrs().HardwareAddr.String())
	}
	veth.name = linkAddrName
	return veth, nil
}

func validateContainerPeerInterface(hostIntf *current.Interface, contVeth *vethPair) (*vethPair, error) {
	hostVeth, link, err := validateInterface(hostIntf, false)
	if err != nil {
		return hostVeth, err
	}
	_, isVeth := link.(*netlink.Veth)
	if !isVeth {
		klog.Infof("Link %s is not created by CNI", hostIntf.Name)
		return hostVeth, nil
	}
	linkName := link.Attrs().Name
	_, hostVeth.peerIndex, err = ip.GetVethPeerIfindex(linkName)
	if err != nil {
		return hostVeth, fmt.Errorf("unable to obtain veth peer index for veth %s", linkName)
	}

	hostVeth.ifIndex = link.Attrs().Index
	if (hostVeth.ifIndex != contVeth.peerIndex) || (hostVeth.peerIndex != contVeth.ifIndex) {
		return hostVeth, fmt.Errorf("host interface %s doesn't match container %s peer configuration",
			linkName, contVeth.name)
	}

	if hostIntf.Mac != "" {
		if hostIntf.Mac != link.Attrs().HardwareAddr.String() {
			klog.Errorf("Host interface mac %s doesn't match link address %s", hostIntf.Mac,
				link.Attrs().HardwareAddr.String())
			return hostVeth, fmt.Errorf("interface %s mac doesn't match: %s not found", hostIntf.Name, hostIntf.Mac)
		}
	}
	hostVeth.name = linkName
	return hostVeth, nil
}

func parseContainerIP(ips []*current.IPConfig) (net.IP, error) {
	for _, ipc := range ips {
		if ipc.Version == "4" {
			return ipc.Address.IP, nil
		}
	}
	return nil, fmt.Errorf("failed to find a valid IP address")
}

func buildContainerConfig(containerID string, podName string, podNamespace string, containerIface *current.Interface, ips []*current.IPConfig) *agent.InterfaceConfig {
	containerIP, err := parseContainerIP(ips)
	if err != nil {
		klog.Errorf("Failed to find container %s IP", containerID)
	}
	// containerIface.Mac should be a valid MAC string, otherwise it should throw error before
	containerMAC, _ := net.ParseMAC(containerIface.Mac)
	return agent.NewContainerInterface(containerID, podName, podNamespace, containerIface.Sandbox, containerMAC, containerIP)
}

func configureInterface(ovsBridge ovsconfig.OVSBridgeClient, ofClient openflow.Client, gateway *agent.Gateway, ifaceStore agent.InterfaceStore, podName string, podNameSpace string, containerID string, containerNetNS string, ifname string, result *current.Result) error {
	netns, err := ns.GetNS(containerNetNS)
	if err != nil {
		klog.Errorf("Failed to open netns with %s: %v", containerNetNS, err)
		return err
	}
	defer netns.Close()
	// Create veth pair and link up
	hostIface, containerIface, err := setupInterface(podName, podNameSpace, ifname, netns)
	if err != nil {
		return err
	}
	// defer to delete container link once some failures occurred in later manipulation
	success := false
	defer func() {
		if !success {
			removeContainerLink(containerID, containerNetNS, ifname)
		}
	}()

	result.Interfaces = []*current.Interface{hostIface, containerIface}

	// build container configuration
	containerConfig := buildContainerConfig(containerID, podName, podNameSpace, containerIface, result.IPs)

	// create OVS Port and add attach container configuration into external_ids
	ovsPortName := hostIface.Name
	portUUID, err := setupContainerOVSPort(ovsBridge, containerConfig, ovsPortName)
	if err != nil {
		return err
	}

	// Rollback to remove OVS port if hit error in later manipulations
	defer func() {
		if !success {
			ovsBridge.DeletePort(portUUID)
		}
	}()

	// Configure IP for container
	if err = configureContainerAddr(netns, containerIface, result); err != nil {
		klog.Errorf("Failed to configure IP address on container %s:%v", containerID, err)
		return fmt.Errorf("failed to configure container ip")
	}

	// Todo: need to decide whether to retrieve OFport asynchronously to reduce CNI command delay
	ofPort, err := ovsBridge.GetOFPort(ovsPortName)
	if err != nil {
		klog.Errorf("Failed to get of_port of OVS interface %s: %v", ovsPortName, err)
		return err
	}
	// Setup openflow entries for OVS interface
	err = ofClient.InstallPodFlows(ovsPortName, containerConfig.IP, containerConfig.MAC, gateway.MAC, uint32(ofPort))
	if err != nil {
		klog.Errorf("Failed to add openflow entries for container %s: %v", containerID, err)
		return err
	}
	containerConfig.OvsPortConfig = &agent.OvsPortConfig{PortUUID: portUUID, IfaceName: ovsPortName}
	// Add containerConfig into local cache
	ifaceStore.AddInterface(ovsPortName, containerConfig)
	// Mark the manipulation as success to cancel defer deletion
	success = true
	return nil
}

func setupContainerOVSPort(ovsBridge ovsconfig.OVSBridgeClient, containerConfig *agent.InterfaceConfig, ovsPortName string) (string, error) {
	ovsAttchInfo := agent.BuildOVSPortExternalIDs(containerConfig)
	if portUUID, err := ovsBridge.CreatePort(ovsPortName, ovsPortName, ovsAttchInfo); err != nil {
		klog.Errorf("Failed to add OVS port %s, remove from local cache: %v", ovsPortName, err)
		return "", err
	} else {
		return portUUID, nil
	}
}

func removeContainerLink(containerID string, containerNetns string, ifname string) error {
	if err := ns.WithNetNSPath(containerNetns, func(_ ns.NetNS) error {
		var err error
		_, err = ip.DelLinkByNameAddr(ifname)
		if err != nil && err == ip.ErrLinkNotFound {
			// Not found link should return success for deletion
			return nil
		}
		return err
	}); err != nil {
		klog.Errorf("Failed to delete interfaces of container %s: %v", containerID, err)
		return err
	}
	return nil
}

func removeInterfaces(ovsBridgeClient ovsconfig.OVSBridgeClient, ofClient openflow.Client, ifaceStore agent.InterfaceStore, podName string, podNamespace string, containerID string, containerNetns string, ifname string) error {
	if containerNetns != "" {
		if err := removeContainerLink(containerID, containerNetns, ifname); err != nil {
			return err
		}
	} else {
		klog.Infof("Target netns not specified, return success")
	}

	containerConfig, found := ifaceStore.GetContainerInterface(podName, podNamespace)
	if !found {
		klog.Infof("Not find container %s port from local cache", containerID)
		return nil
	}

	portUUID := containerConfig.PortUUID
	ovsPortName := containerConfig.IfaceName
	klog.Infof("Delete OVS port with UUID %s peer container %s", portUUID, containerID)
	// Remove openflow entries of target container
	if err := ofClient.UninstallPodFlows(ovsPortName); err != nil {
		klog.Errorf("Failed to delete Openflow entries for container %s: %v", containerID, err)
		return err
	}
	// Todo: handle error and introduce garbage collection for deletion failure
	if err := ovsBridgeClient.DeletePort(portUUID); err != nil {
		klog.Errorf("Failed to delete OVS port %s: %v", portUUID, err)
		return err
	}
	// Remove container configuration from cache.
	ifaceStore.DeleteInterface(ovsPortName)
	klog.Infof("Succeed to remove interfaces")
	return nil
}

func checkInterfaces(ifaceStore agent.InterfaceStore, containerID string, containerNetNS string, containerIface, hostIface *current.Interface, hostVethName string, prevResult *current.Result) error {
	netns, err := ns.GetNS(containerNetNS)
	if err != nil {
		klog.Errorf("Failed to check netns config %s: %v", containerNetNS, err)
		return err
	}
	defer netns.Close()
	if containerlink, err := checkContainerInterface(netns, containerNetNS, containerID, containerIface, prevResult); err != nil {
		return err
	} else if err := checkHostInterface(ifaceStore, hostIface, containerIface, containerlink, containerID, hostVethName, prevResult.IPs); err != nil {
		return err
	}
	return nil
}

func checkContainerInterface(netns ns.NetNS, containerNetns, containerID string, containerIface *current.Interface, prevResult *current.Result) (*vethPair, error) {
	var contlink *vethPair
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
		contlink, errlink = validateContainerInterface(containerIface)
		if errlink != nil {
			return errlink
		}
		// Check container IP config
		if err := ip.ValidateExpectedInterfaceIPs(containerIface.Name, prevResult.IPs); err != nil {
			return err
		}
		// Check container route config
		if err := ip.ValidateExpectedRoute(prevResult.Routes); err != nil {
			return err
		}
		return nil
	}); err != nil {
		klog.Errorf("Failed to check container %s interface configurations in netns %s: %v",
			containerID, containerNetns, err)
		return contlink, err
	}
	return contlink, nil
}

func checkHostInterface(ifaceStore agent.InterfaceStore, hostIntf, containerIntf *current.Interface, containerLink *vethPair, containerID, vethName string, containerIPs []*current.IPConfig) error {
	hostVeth, errlink := validateContainerPeerInterface(hostIntf, containerLink)
	if errlink != nil {
		klog.Errorf("Failed to check container interface %s peer %s in the host: %v",
			containerID, vethName, errlink)
		return errlink
	}
	if err := validateOVSPort(ifaceStore, hostVeth.name, containerIntf.Mac, containerID, containerIPs); err != nil {
		klog.Errorf("Failed to check host link %s for container %s attaching status on ovs. err: %v",
			hostVeth.name, containerID, err)
		return err
	}
	return nil
}

func validateOVSPort(ifaceStore agent.InterfaceStore, ovsPortName string, containerMAC string, containerID string, ips []*current.IPConfig) error {
	if containerConfig, found := ifaceStore.GetInterface(ovsPortName); found {
		if containerConfig.MAC.String() != containerMAC {
			return fmt.Errorf("failed to check container MAC %s on OVS port %s",
				containerID, ovsPortName)
		}

		for _, ipc := range ips {
			if ipc.Version == "4" {
				if containerConfig.IP.Equal(ipc.Address.IP) {
					return nil
				}
			}
		}
		return fmt.Errorf("failed to find a valid IP equal to attached address")
	} else {
		klog.Infof("Not found container %s config from local cache", containerID)
		return fmt.Errorf("not found OVS port %s", ovsPortName)
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
