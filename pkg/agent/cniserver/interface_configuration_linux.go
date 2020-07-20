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

type ifConfigurator struct {
	ovsDatapathType string
}

func newInterfaceConfigurator(ovsDatapathType string) (*ifConfigurator, error) {
	return &ifConfigurator{ovsDatapathType: ovsDatapathType}, nil
}

// advertiseContainerAddr sends 3 GARP packets in another goroutine with 50ms interval. It's because Openflow entries are
// installed async, and the gratuitous ARP could be sent out after the Openflow entries are installed. Using another
// goroutine to ensure the processing of CNI ADD request is not blocked.
func (ic *ifConfigurator) advertiseContainerAddr(containerNetNS string, containerIfaceName string, result *current.Result) error {
	if err := ns.IsNSorErr(containerNetNS); err != nil {
		return fmt.Errorf("%s is not a valid network namespace: %v", containerNetNS, err)
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
			klog.Warning("Failed to find an IPv4 address, skipped sending Gratuitous ARP")
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
	containerRoutes []*cnitypes.Route) (*vethPair, error) {
	var contVeth *vethPair
	// Check netns configuration
	if containerNetns != containerIface.Sandbox {
		klog.Errorf("Sandbox in prevResult %s doesn't match configured netns: %s",
			containerIface.Sandbox, containerNetns)
		return nil, fmt.Errorf("sandbox in prevResult %s doesn't match configured netns: %s",
			containerIface.Sandbox, containerNetns)
	}
	netns, err := ns.GetNS(containerNetns)
	if err != nil {
		klog.Errorf("Failed to check netns config %s: %v", containerNetns, err)
		return nil, err
	}
	defer netns.Close()
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

func (ic *ifConfigurator) validateContainerPeerInterface(interfaces []*current.Interface, containerVeth *vethPair) (*vethPair, error) {
	// Iterate all the passed interfaces and look up the host interface by
	// matching the veth peer interface index.
	for _, hostIntf := range interfaces {
		if hostIntf.Sandbox != "" {
			// Not in the default Namespace. Must be the container interface.
			continue
		}
		link, err := validateInterface(hostIntf, false)
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

func (ic *ifConfigurator) getOVSInterfaceType() int {
	return defaultOVSInterfaceType
}
