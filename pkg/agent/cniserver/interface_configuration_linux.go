// +build linux

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
	"time"

	"github.com/Mellanox/sriovnet"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/agent/util/arping"
	"github.com/vmware-tanzu/antrea/pkg/agent/util/ethtool"
	cnipb "github.com/vmware-tanzu/antrea/pkg/apis/cni/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
)

// NetDeviceType type Enum
const (
	netDeviceTypeVeth = "veth"
	netDeviceTypeVF   = "vf"
)

type ifConfigurator struct {
	ovsDatapathType             ovsconfig.OVSDatapathType
	isOvsHardwareOffloadEnabled bool
}

func newInterfaceConfigurator(ovsDatapathType ovsconfig.OVSDatapathType, isOvsHardwareOffloadEnabled bool) (*ifConfigurator, error) {
	return &ifConfigurator{ovsDatapathType: ovsDatapathType, isOvsHardwareOffloadEnabled: isOvsHardwareOffloadEnabled}, nil
}

func renameLink(curName, newName string) error {
	link, err := netlink.LinkByName(curName)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetDown(link); err != nil {
		return err
	}
	if err := netlink.LinkSetName(link, newName); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}

	return nil
}

func moveIfToNetns(ifname string, netns ns.NetNS) error {
	vfDev, err := netlink.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("failed to lookup VF device %v: %q", ifname, err)
	}
	// move VF device to ns
	if err = netlink.LinkSetNsFd(vfDev, int(netns.Fd())); err != nil {
		return fmt.Errorf("failed to move VF device %+v to netns: %q", ifname, err)
	}

	return nil
}

// configureContainerLinkSriov move VF to the container namesapce
func (ic *ifConfigurator) configureContainerLinkSriov(
	podName string,
	podNamespace string,
	containerID string,
	containerNetNS string,
	containerIfaceName string,
	mtu int,
	pciAddress string,
	result *current.Result,
) error {
	hostIfaceName := util.GenerateContainerInterfaceName(podName, podNamespace, containerID)

	hostIface := &current.Interface{Name: hostIfaceName}
	containerIface := &current.Interface{Name: containerIfaceName, Sandbox: containerNetNS}
	result.Interfaces = []*current.Interface{hostIface, containerIface}

	// 1. get VF netdevice from PCI
	vfNetdevices, err := sriovnet.GetNetDevicesFromPci(pciAddress)
	if err != nil {
		return err
	}
	// Make sure we have 1 netdevice per PCI address
	if len(vfNetdevices) != 1 {
		return fmt.Errorf("failed to get one netdevice interface per %s", pciAddress)
	}
	vfNetdevice := vfNetdevices[0]
	// 2. get Uplink netdevice
	uplink, err := sriovnet.GetUplinkRepresentor(pciAddress)
	if err != nil {
		return fmt.Errorf("failed to get uplink representor error: %s", err)
	}
	// 3. get VF index from PCI
	vfIndex, err := sriovnet.GetVfIndexByPciAddress(pciAddress)
	if err != nil {
		return fmt.Errorf("failed to get VF index error: %s", err)
	}
	// 4. lookup representor
	repPortName, err := sriovnet.GetVfRepresentor(uplink, vfIndex)
	if err != nil {
		return fmt.Errorf("failed to get VF representor error: %s", err)
	}
	// 5. rename VF representor to hostIfaceName
	if err = renameLink(repPortName, hostIfaceName); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %v", repPortName, hostIfaceName, err)
	}
	hostIface.Name = hostIfaceName
	link, err := netlink.LinkByName(hostIface.Name)
	if err != nil {
		return err
	}
	hostIface.Mac = link.Attrs().HardwareAddr.String()
	// 6. Move VF to Container namespace
	netns, err := ns.GetNS(containerNetNS)
	if err != nil {
		return fmt.Errorf("failed to open netns %s: %v", containerNetNS, err)
	}
	err = moveIfToNetns(vfNetdevice, netns)
	if err != nil {
		return err
	}
	netns.Close()
	if err := ns.WithNetNSPath(containerNetNS, func(hostNS ns.NetNS) error {
		err = renameLink(vfNetdevice, containerIfaceName)
		if err != nil {
			return fmt.Errorf("failed to rename VF netdevice %s: %v", containerIfaceName, err)
		}
		link, err = netlink.LinkByName(containerIfaceName)
		if err != nil {
			return fmt.Errorf("failed to find VF netdevice %s: %v", containerIfaceName, err)
		}
		err = netlink.LinkSetMTU(link, mtu)
		if err != nil {
			return fmt.Errorf("failed to set MTU for VF netdevice %s: %v", containerIfaceName, err)
		}
		err = netlink.LinkSetUp(link)
		if err != nil {
			return fmt.Errorf("failed to set link up to VF netdevice %s: %v", containerIfaceName, err)
		}
		klog.V(2).Infof("Setup interfaces host: %s, container %s", repPortName, containerIfaceName)
		containerIface.Name = containerIfaceName
		containerIface.Mac = link.Attrs().HardwareAddr.String()
		containerIface.Sandbox = netns.Path()
		klog.V(2).Infof("Configuring IP address for container %s", containerID)
		// result.Interfaces must be set before this.
		if err := ipam.ConfigureIface(containerIface.Name, result); err != nil {
			return fmt.Errorf("failed to configure IP address for container %s: %v", containerID, err)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// configureContainerLinkVeth creates a veth pair: one in the container netns and one in the host netns, and configures IP
// address and routes to the container veth.
func (ic *ifConfigurator) configureContainerLinkVeth(
	podName string,
	podNamespace string,
	containerID string,
	containerNetNS string,
	containerIfaceName string,
	mtu int,
	result *current.Result,
) error {
	hostIfaceName := util.GenerateContainerInterfaceName(podName, podNamespace, containerID)

	hostIface := &current.Interface{Name: hostIfaceName}
	containerIface := &current.Interface{Name: containerIfaceName, Sandbox: containerNetNS}
	result.Interfaces = []*current.Interface{hostIface, containerIface}

	if err := ns.WithNetNSPath(containerNetNS, func(hostNS ns.NetNS) error {
		klog.V(2).Infof("Creating veth devices (%s, %s) for container %s", containerIfaceName, hostIfaceName, containerID)
		hostVeth, containerVeth, err := ip.SetupVethWithName(containerIfaceName, hostIfaceName, mtu, hostNS)
		if err != nil {
			return fmt.Errorf("failed to create veth devices for container %s: %v", containerID, err)
		}
		containerIface.Mac = containerVeth.HardwareAddr.String()
		hostIface.Mac = hostVeth.HardwareAddr.String()
		// OVS netdev datapath doesn't support TX checksum offloading, i.e. if packet
		// arrives with bad/no checksum it will be sent to the output port with same bad/no checksum.
		if ic.ovsDatapathType == ovsconfig.OVSDatapathNetdev {
			if err := ethtool.EthtoolTXHWCsumOff(containerVeth.Name); err != nil {
				return fmt.Errorf("error when disabling TX checksum offload on container veth: %v", err)
			}
		}

		klog.V(2).Infof("Configuring IP address for container %s", containerID)
		// result.Interfaces must be set before this.
		if err := ipam.ConfigureIface(containerIface.Name, result); err != nil {
			return fmt.Errorf("failed to configure IP address for container %s: %v", containerID, err)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// advertiseContainerAddr sends 3 GARP packets in another goroutine with 50ms interval, if the
// container interface is assigned an IPv4 address. It's because Openflow entries are installed
// asynchronously, and the gratuitous ARP could be sent out after the Openflow entries are
// installed. Using another goroutine to ensure the processing of CNI ADD request is not blocked.
func (ic *ifConfigurator) advertiseContainerAddr(containerNetNS string, containerIfaceName string, result *current.Result) error {
	if err := ns.IsNSorErr(containerNetNS); err != nil {
		return fmt.Errorf("%s is not a valid network namespace: %v", containerNetNS, err)
	}
	if len(result.IPs) == 0 {
		klog.Warningf("Expected at least one IP address in CNI result, skip sending Gratuitous ARP")
		return nil
	}
	// Sending Gratuitous ARP is a best-effort action and is unlikely to fail as we have ensured the netns is valid.
	go ns.WithNetNSPath(containerNetNS, func(_ ns.NetNS) error {
		iface, err := net.InterfaceByName(containerIfaceName)
		if err != nil {
			klog.Errorf("Failed to find container interface %s in ns %s: %v", containerIfaceName, containerNetNS, err)
			return nil
		}
		var targetIP net.IP
		for _, ipc := range result.IPs {
			if ipc.Version == "4" {
				targetIP = ipc.Address.IP
			}
		}
		if targetIP == nil {
			klog.V(2).Infof("No IPv4 address found for container interface %s in ns %s, skip sending Gratuitous ARP", containerIfaceName, containerNetNS)
			return nil
		}
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		count := 0
		for {
			// Send gratuitous ARP to network in case of stale mappings for this IP address
			// (e.g. if a previous - deleted - Pod was using the same IP).
			if err := arping.GratuitousARPOverIface(targetIP, iface); err != nil {
				klog.Warningf("Failed to send gratuitous ARP #%d: %v", count, err)
			}
			count++
			if count == 3 {
				break
			}
			<-ticker.C
		}
		return nil
	})
	return nil
}

// configureContainerLink creates a veth pair: one in the container netns and one in the host netns, and configures IP
// address and routes to the container veth.
func (ic *ifConfigurator) configureContainerLink(
	podName string,
	podNamespace string,
	containerID string,
	containerNetNS string,
	containerIfaceName string,
	mtu int,
	sriovVFDeviceID string,
	result *current.Result,
) error {
	if sriovVFDeviceID != "" {
		if !ic.isOvsHardwareOffloadEnabled {
			return fmt.Errorf("OVS is configured with hardware offload disabled, but SR-IOV VF was requested; please set hardware offload to true via antrea yaml")
		}
		klog.V(2).Infof("Moving SR-IOV %s device to network namespace of container %s", sriovVFDeviceID, containerID)
		// Move SR-IOV VF to network namespace
		return ic.configureContainerLinkSriov(podName, podNamespace, containerID, containerNetNS, containerIfaceName, mtu, sriovVFDeviceID, result)
	} else {
		klog.V(2).Infof("Create veth pair for container %s", containerID)
		// Create veth pair and link up
		return ic.configureContainerLinkVeth(podName, podNamespace, containerID, containerNetNS, containerIfaceName, mtu, result)
	}
}

func (ic *ifConfigurator) removeContainerLink(containerID, hostInterfaceName string) error {
	klog.V(2).Infof("Deleting veth devices for container %s", containerID)
	// Don't return an error if the device is already removed as CniDel can be called multiple times.
	if err := ip.DelLinkByName(hostInterfaceName); err != nil {
		if err != ip.ErrLinkNotFound {
			return fmt.Errorf("failed to delete veth devices for container %s: %v", containerID, err)
		}
		klog.V(2).Infof("Did not find interface %s for container %s", hostInterfaceName, containerID)
	}
	return nil
}

func parseContainerIfaceFromResults(cfgArgs *cnipb.CniCmdArgs, prevResult *current.Result) *current.Interface {
	for _, intf := range prevResult.Interfaces {
		if intf.Name == cfgArgs.Ifname {
			return intf
		}
	}
	return nil
}

func (ic *ifConfigurator) checkContainerInterface(
	containerNetns, containerID string,
	containerIface *current.Interface,
	containerIPs []*current.IPConfig,
	containerRoutes []*cnitypes.Route,
	sriovVFDeviceID string) (interface{}, error) {
	var networkInterface interface{}
	// Check netns configuration
	if containerNetns != containerIface.Sandbox {
		klog.Errorf("Sandbox in prevResult %s doesn't match configured netns: %s",
			containerIface.Sandbox, containerNetns)
		return nil, fmt.Errorf("sandbox in prevResult %s doesn't match configured netns: %s",
			containerIface.Sandbox, containerNetns)
	}

	// Check container interface configuration
	if err := ns.WithNetNSPath(containerNetns, func(_ ns.NetNS) error {
		var errlink error
		// Check container link config
		if sriovVFDeviceID != "" {
			networkInterface, errlink = validateContainerVFInterface(containerIface, sriovVFDeviceID)
		} else {
			networkInterface, errlink = validateContainerVethInterface(containerIface)
		}
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
	return networkInterface, nil
}

func validateContainerVFInterface(intf *current.Interface, sriovVFDeviceID string) (netlink.Link, error) {
	link, err := validateInterface(intf, true, netDeviceTypeVF)
	if err != nil {
		return nil, err
	}
	netdevices, _ := sriovnet.GetNetDevicesFromPci(sriovVFDeviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to find netdevice to PCI address %s: %v", sriovVFDeviceID, err)
	}
	// the check makes sure that the SR-IOV VF netdevice is not in the host namespace
	// the GetNetDevicesFromPci is using linux sysfs to find the VF netdevice
	// the method is running in container network namespace, but we are still in the antrea agent filesystem
	// the antrea agent container is privileged, which allow access to the host sysfs
	// therefore the validation is to make sure that the VF netdevice is not in the host network
	// namespace
	if len(netdevices) != 0 {
		return nil, fmt.Errorf("VF netdevice still in host network namespace %s %+v", sriovVFDeviceID, netdevices)
	}
	if intf.Mac != link.Attrs().HardwareAddr.String() {
		return nil, fmt.Errorf("interface %s MAC %s doesn't match container MAC: %s",
			intf.Name, intf.Mac, link.Attrs().HardwareAddr.String())
	}
	return link, nil
}

func validateContainerVethInterface(intf *current.Interface) (*vethPair, error) {
	link, err := validateInterface(intf, true, netDeviceTypeVeth)
	if err != nil {
		return nil, err
	}
	veth := &vethPair{}
	linkName := link.Attrs().Name
	veth.ifIndex = link.Attrs().Index
	_, veth.peerIndex, err = ip.GetVethPeerIfindex(linkName)
	if err != nil {
		return nil, fmt.Errorf("failed to get veth peer index for veth %s: %v", linkName, err)
	}
	if intf.Mac != link.Attrs().HardwareAddr.String() {
		return nil, fmt.Errorf("interface %s MAC %s doesn't match container MAC: %s",
			intf.Name, intf.Mac, link.Attrs().HardwareAddr.String())
	}
	veth.name = linkName
	return veth, nil
}

func (ic *ifConfigurator) validateVFRepInterface(sriovVFDeviceID string) (string, error) {
	uplink, err := sriovnet.GetUplinkRepresentor(sriovVFDeviceID)
	if err != nil {
		return "", fmt.Errorf("failed to get uplink representor for PCI Address %s", sriovVFDeviceID)
	}
	vfIndex, err := sriovnet.GetVfIndexByPciAddress(sriovVFDeviceID)
	if err != nil {
		return "", fmt.Errorf("failed to vf index for PCI Address %s", sriovVFDeviceID)
	}
	return sriovnet.GetVfRepresentor(uplink, vfIndex)
}

func (ic *ifConfigurator) validateContainerPeerInterface(interfaces []*current.Interface, containerVeth *vethPair) (*vethPair, error) {
	// Iterate all the passed interfaces and look up the host interface by
	// matching the veth peer interface index.
	for _, hostIntf := range interfaces {
		if hostIntf.Sandbox != "" {
			// Not in the default Namespace. Must be the container interface.
			continue
		}
		link, err := validateInterface(hostIntf, false, netDeviceTypeVeth)
		if err != nil {
			klog.Errorf("Failed to validate interface %s: %v", hostIntf.Name, err)
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

func (ic *ifConfigurator) getInterceptedInterfaces(
	sandbox string,
	containerNetNS string,
	containerIFDev string,
) (*current.Interface, *current.Interface, error) {
	containerIface := &current.Interface{}
	intf, err := util.GetNSDevInterface(containerNetNS, containerIFDev)
	if err != nil {
		return nil, nil, fmt.Errorf("connectInterceptedInterface failed to get veth info: %w", err)
	}
	containerIface.Name = containerIFDev
	containerIface.Sandbox = sandbox
	containerIface.Mac = intf.HardwareAddr.String()

	// Setup dev in host ns.
	hostIface := &current.Interface{}
	intf, br, err := util.GetNSPeerDevBridge(containerNetNS, containerIFDev)
	if err != nil {
		return nil, nil, fmt.Errorf("connectInterceptedInterface failed to get veth peer info: %w", err)
	}
	if len(br) > 0 {
		return nil, nil, fmt.Errorf("connectInterceptedInterface: does not expect device %s attached to bridge", intf.Name)
	}
	hostIface.Name = intf.Name
	hostIface.Mac = intf.HardwareAddr.String()
	return containerIface, hostIface, nil
}

func validateInterface(intf *current.Interface, inNetns bool, ifType string) (netlink.Link, error) {
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
	if ifType == netDeviceTypeVeth {
		if !isVeth(link) {
			return nil, fmt.Errorf("interface %s is not of type veth", intf.Name)
		}
	} else if ifType == netDeviceTypeVF {

		return link, nil
	}
	return nil, fmt.Errorf("unknown device type %s", ifType)
}

func isVeth(link netlink.Link) bool {
	_, isVeth := link.(*netlink.Veth)
	return isVeth
}

func (ic *ifConfigurator) getOVSInterfaceType() int {
	return defaultOVSInterfaceType
}
