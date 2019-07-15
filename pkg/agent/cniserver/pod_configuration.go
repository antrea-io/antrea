package cniserver

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/containernetworking/cni/pkg/types"
	"io"
	"net"
	"strings"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/j-keck/arping"
	"github.com/vishvananda/netlink"
	"k8s.io/klog"
	"okn/pkg/ovs/ovsconfig"
)

const (
	OVSExternalIDMAC         = "attached-mac"
	OVSExternalIDIP          = "ip-address"
	OVSExternalIDContainerID = "container-id"
	containerKeyConnector    = `/`
)

type ovsPortConfig struct {
	ifaceName string
	portUUID  string
	ofport    int32
}

type ContainerConfig struct {
	id           string
	ip           string
	mac          string
	podName      string
	podNamespace string
	netNS        string
	*ovsPortConfig
}

type vethPair struct {
	name      string
	ifIndex   int
	peerIndex int
}

type k8sArgs struct {
	types.CommonArgs
	K8S_POD_NAME               types.UnmarshallableString
	K8S_POD_NAMESPACE          types.UnmarshallableString
	K8S_POD_INFRA_CONTAINRE_ID types.UnmarshallableString
}

// Local cache for container configuration, including containerID, podName, podNamespace, netns, IP, MAC
// and OVS Port configurations, such as ifacename, portUUID and OFport. OFPort might be filled
// later when it is used to install openflow entry.
// Key of this cache should be container ID
// Container configuration is added into cache after invocation of cniserver.CmdAdd, and removed
// from cache after invocation of cniserver.CmdDel. For cniserver.CmdCheck, the server would
// also check previousResult with local cache.
// If some errors occurred during OVS manipulation for adding Port, it also would remove from
// local cache.
// Todo: add periodic task to sync local cache with container veth pair
var containerConfigCache = make(map[string]*ContainerConfig)

func GenerateContainerPeerName(podName string, podNamespace string) string {
	hash := sha1.New()
	containerKey := strings.Join([]string{podNamespace, podName}, containerKeyConnector)
	io.WriteString(hash, containerKey)
	hashValue := hex.EncodeToString(hash.Sum(nil))
	return hashValue[:hostVethLength]
}

// Create veth pair: containerVeth plugged in the netns, and hostVeth will be attached to OVS bridge
func setupInterface(containerID string, k8sCNIArgs *k8sArgs, ifname string, netns ns.NetNS) (*current.Interface, *current.Interface, error) {
	hostVethName := GenerateContainerPeerName(string(k8sCNIArgs.K8S_POD_NAME), string(k8sCNIArgs.K8S_POD_NAMESPACE))
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
		return nil, nil, fmt.Errorf("Failed to lookup host interface %q: %v", hostIface.Name, err)
	}

	hostIface.Mac = hostVeth.Attrs().HardwareAddr.String()
	return hostIface, containerIface, nil
}

// Configure container address and routes if existed in IPAM result, and send GARP after that.
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
		return veth, nil, fmt.Errorf("Interface name is missing")
	}
	link, err := netlink.LinkByName(intf.Name)
	if err != nil {
		return veth, link, fmt.Errorf("Failed to find interface with name %s", intf.Name)
	}
	if inNetns {
		if intf.Sandbox == "" {
			return veth, link, fmt.Errorf("Interface %s is expected in netns", intf.Name)
		}
	} else {
		if intf.Sandbox != "" {
			return veth, link, fmt.Errorf("Interface %s is expected not in netns", intf.Name)
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
		return veth, fmt.Errorf("Container interface %s is not of type veth", linkAddrName)
	}
	_, veth.peerIndex, err = ip.GetVethPeerIfindex(linkAddrName)
	if err != nil {
		return veth, fmt.Errorf("Unable to obtain veth peer index for veth %s", linkAddrName)
	}
	veth.ifIndex = link.Attrs().Index
	if intf.Mac != link.Attrs().HardwareAddr.String() {
		return veth, fmt.Errorf("Interface %s MAC %s doesn't match container MAC: %s",
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
		return hostVeth, fmt.Errorf("Unable to obtain veth peer index for veth %s", linkName)
	}

	hostVeth.ifIndex = link.Attrs().Index
	if (hostVeth.ifIndex != contVeth.peerIndex) || (hostVeth.peerIndex != contVeth.ifIndex) {
		return hostVeth, fmt.Errorf("Host interface %s doesn't match container %s peer configuration",
			linkName, contVeth.name)
	}

	if hostIntf.Mac != "" {
		if hostIntf.Mac != link.Attrs().HardwareAddr.String() {
			klog.Errorf("Host interface mac %s doesn't match link address %s", hostIntf.Mac,
				link.Attrs().HardwareAddr.String())
			return hostVeth, fmt.Errorf("Interface %s mac doesn't match: %s not found", hostIntf.Name, hostIntf.Mac)
		}
	}
	hostVeth.name = linkName
	return hostVeth, nil
}

func parseContainerIP(ips []*current.IPConfig) (string, error) {
	for _, ipc := range ips {
		if ipc.Version == "4" {
			return ipc.Address.IP.String(), nil
		}
	}
	return "", fmt.Errorf("Failed to find a valid IP address")
}

func parseContainerAttachInfo(containerID string, containerConfig *ContainerConfig) map[string]interface{} {
	externalIDs := make(map[string]interface{})
	externalIDs[OVSExternalIDMAC] = containerConfig.mac
	externalIDs[OVSExternalIDContainerID] = containerID
	externalIDs[OVSExternalIDIP] = containerConfig.ip
	return externalIDs
}

func buildContainerConfig(containerID string, podName string, podNamespace string, containerIface *current.Interface, ips []*current.IPConfig) *ContainerConfig {
	containerConfig := &ContainerConfig{id: containerID, netNS: containerIface.Sandbox, mac: containerIface.Mac, podName: podName, podNamespace: podNamespace}
	var err error
	containerConfig.ip, err = parseContainerIP(ips)
	if err != nil {
		klog.Errorf("Failed to find container %s IP", containerID)
	}
	return containerConfig
}

func configureInterface(ovsBridge ovsconfig.OVSBridgeClient, containerID string, k8sCNIArgs *k8sArgs, containerNetNS string, ifname string, result *current.Result) error {
	netns, err := ns.GetNS(containerNetNS)
	if err != nil {
		klog.Errorf("Failed to open netns with %s: %v", containerNetNS, err)
		return err
	}
	defer netns.Close()
	// Create veth pair and link up
	hostIface, containerIface, err := setupInterface(containerID, k8sCNIArgs, ifname, netns)
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
	containerConfig := buildContainerConfig(containerID, string(k8sCNIArgs.K8S_POD_NAME), string(k8sCNIArgs.K8S_POD_NAMESPACE), containerIface, result.IPs)

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

	// Configure ip for container
	if err = configureContainerAddr(netns, containerIface, result); err != nil {
		klog.Errorf("Failed to configure ip address on container %s:%v", containerID, err)
		return fmt.Errorf("Failed to configure container ip")
	}
	// containerConfig OFPort field is not filled after create OVS port, need to check and retrieve
	// when used it when install openflow
	// Todo: need to decide whether to retrieve OFPort asynchronously to reduce CNI command delay
	containerConfig.ovsPortConfig = &ovsPortConfig{ifaceName: ovsPortName, portUUID: portUUID}
	// Add containerConfig into local cache
	containerConfigCache[containerID] = containerConfig
	// Mark the manipulation as success to cancel defer deletion
	success = true
	return nil
}

func setupContainerOVSPort(ovsBridge ovsconfig.OVSBridgeClient, containerConfig *ContainerConfig, ovsPortName string) (string, error) {
	containerID := containerConfig.id
	ovsAttchInfo := parseContainerAttachInfo(containerID, containerConfig)
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

func removeInterfaces(ovsBridgeClient ovsconfig.OVSBridgeClient, containerID string, containerNetns string, ifname string) error {
	if containerNetns != "" {
		if err := removeContainerLink(containerID, containerNetns, ifname); err != nil {
			return err
		}
	} else {
		klog.Infof("Target netns not specified, return success")
	}
	containerConfig, found := containerConfigCache[containerID]
	if !found {
		klog.Infof("Not find container %s port from local cache", containerID)
		return nil
	}

	portUUID := containerConfig.portUUID
	klog.Infof("Delete OVS port with UUID %s peer container %s", portUUID, containerID)
	// Todo: handle error and introduce garbage collection for deletion failure
	if err := ovsBridgeClient.DeletePort(portUUID); err != nil {
		klog.Errorf("Failed to delete OVS port %s: %v", portUUID, err)
		return err
	}
	// Remove container configuration from cache.
	delete(containerConfigCache, containerID)
	klog.Infof("Succeed to remove interfaces")
	return nil
}

func checkInterfaces(containerID string, containerNetNS string, containerIface, hostIface *current.Interface, hostVethName string, prevResult *current.Result) error {
	netns, err := ns.GetNS(containerNetNS)
	if err != nil {
		klog.Errorf("Failed to check netns config %s: %v", containerNetNS, err)
		return err
	}
	defer netns.Close()
	if containerlink, err := checkContainerInterface(netns, containerNetNS, containerID, containerIface, prevResult); err != nil {
		return err
	} else if err := checkHostInterface(hostIface, containerIface, containerlink, containerID, hostVethName, prevResult.IPs); err != nil {
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
		return nil, fmt.Errorf("Sandbox in prevResult %s doesn't match configured netns: %s",
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
		// Check container ip config
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

func checkHostInterface(hostIntf, containerIntf *current.Interface, containerLink *vethPair, containerID, vethName string, containerIPs []*current.IPConfig) error {
	hostVeth, errlink := validateContainerPeerInterface(hostIntf, containerLink)
	if errlink != nil {
		klog.Errorf("Failed to check container interface %s peer %s in the host: %v",
			containerID, vethName, errlink)
		return errlink
	}
	if err := validateOVSPort(hostVeth.name, containerIntf.Mac, containerID, containerIPs); err != nil {
		klog.Errorf("Failed to check host link %s for container %s attaching status on ovs. err: %v",
			hostVeth.name, containerID, err)
		return err
	}
	return nil
}

func validateOVSPort(ovsPortName string, containerMAC string, containerID string, ips []*current.IPConfig) error {
	if containerConfig, found := containerConfigCache[containerID]; found {
		if containerConfig.mac != containerMAC {
			return fmt.Errorf("Failed to check container MAC %s on OVS port %s",
				containerID, ovsPortName)
		}

		for _, ipc := range ips {
			if ipc.Version == "4" {
				if containerConfig.ip == ipc.Address.IP.String() {
					return nil
				}
			}
		}
		return fmt.Errorf("Failed to find a valid ip equal to attached address")
	} else {
		klog.Infof("Not found container %s config from local cache", containerID)
		return fmt.Errorf("Not found OVS port %s", ovsPortName)
	}
}

func initCache(ovsBridgeClient ovsconfig.OVSBridgeClient) error {
	if ovsPorts, err := ovsBridgeClient.GetPortList(); err != nil {
		klog.Errorf("Failed to list OVS ports: %v", err)
		return err
	} else {
		for _, port := range ovsPorts {
			if port.ExternalIDs != nil {
				if containerID, found := port.ExternalIDs[OVSExternalIDContainerID]; found {
					containerConfig := &ContainerConfig{id: containerID}
					containerConfig.ip, _ = port.ExternalIDs[OVSExternalIDIP]
					containerConfig.mac, _ = port.ExternalIDs[OVSExternalIDMAC]
					containerConfig.ovsPortConfig = &ovsPortConfig{ifaceName: port.IFName, portUUID: port.UUID, ofport: port.OFPort}
					containerConfigCache[containerID] = containerConfig
				}
			}
		}
	}
	return nil
}
