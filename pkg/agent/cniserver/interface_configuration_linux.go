//go:build linux
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
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/util/arping"
	"antrea.io/antrea/pkg/agent/util/ethtool"
	"antrea.io/antrea/pkg/agent/util/ndp"
	netlinkutil "antrea.io/antrea/pkg/agent/util/netlink"
	cnipb "antrea.io/antrea/pkg/apis/cni/v1beta1"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

// NetDeviceType type Enum
const (
	netDeviceTypeVeth = "veth"
	netDeviceTypeVF   = "vf"
)

// Declared variables for test
var (
	ipSetupVethWithName            = ip.SetupVethWithName
	ipDelLinkByName                = ip.DelLinkByName
	ipamConfigureIface             = ipam.ConfigureIface
	ethtoolTXHWCsumOff             = ethtool.EthtoolTXHWCsumOff
	renameInterface                = util.RenameInterface
	netInterfaceByName             = net.InterfaceByName
	netInterfaceByIndex            = net.InterfaceByIndex
	arpingGratuitousARPOverIface   = arping.GratuitousARPOverIface
	ndpGratuitousNDPOverIface      = ndp.GratuitousNDPOverIface
	ipValidateExpectedInterfaceIPs = ip.ValidateExpectedInterfaceIPs
	ipValidateExpectedRoute        = ip.ValidateExpectedRoute
	ipGetVethPeerIfindex           = ip.GetVethPeerIfindex
	getNSDevInterface              = util.GetNSDevInterface
	getNSPeerDevBridge             = util.GetNSPeerDevBridge
	nsGetNS                        = ns.GetNS
	nsWithNetNSPath                = ns.WithNetNSPath
	nsIsNSorErr                    = ns.IsNSorErr
	tempNetNS                      = ns.TempNetNS
)

type ifConfigurator struct {
	ovsDatapathType             ovsconfig.OVSDatapathType
	isOvsHardwareOffloadEnabled bool
	disableTXChecksumOffload    bool
	netlink                     netlinkutil.Interface
	sriovnet                    SriovNet
}

func newInterfaceConfigurator(ovsDatapathType ovsconfig.OVSDatapathType, isOvsHardwareOffloadEnabled bool, disableTXChecksumOffload bool) (*ifConfigurator, error) {
	configurator := &ifConfigurator{ovsDatapathType: ovsDatapathType, isOvsHardwareOffloadEnabled: isOvsHardwareOffloadEnabled, disableTXChecksumOffload: disableTXChecksumOffload, netlink: &netlink.Handle{}, sriovnet: newSriovNet()}
	return configurator, nil
}

func (ic *ifConfigurator) moveIFToNetNS(ifname string, netns ns.NetNS) error {
	vfDev, err := ic.netlink.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("failed to lookup VF device %v: %q", ifname, err)
	}
	// Move VF device to ns
	if err = ic.netlink.LinkSetNsFd(vfDev, int(netns.Fd())); err != nil {
		return fmt.Errorf("failed to move VF device %+v to netns: %q", ifname, err)
	}

	return nil
}

func (ic *ifConfigurator) configureVFLinkAndIPAM(link netlink.Link, containerID string, containerIfaceName string, netnsPath string, mtu int, result *current.Result) error {
	hostIface := result.Interfaces[0]
	containerIface := result.Interfaces[1]

	err := ic.netlink.LinkSetMTU(link, mtu)
	if err != nil {
		return fmt.Errorf("failed to set MTU for VF netdevice %s: %w", containerIfaceName, err)
	}
	err = ic.netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("failed to set link up to VF netdevice %s: %w", containerIfaceName, err)
	}
	containerIface.Name = containerIfaceName
	containerIface.Mac = link.Attrs().HardwareAddr.String()
	containerIface.Sandbox = netnsPath
	klog.V(2).InfoS("Configuring IP address for VF netdevice", "containerID", containerID, "hostIface", hostIface, "containerIface", containerIface)
	// result.Interfaces must be set before this.
	if err := ipamConfigureIface(containerIface.Name, result); err != nil {
		return fmt.Errorf("failed to configure IP address for container %s: %w", containerID, err)
	}
	klog.V(2).InfoS("IPAM interface configuration result for VF netdevice", "result", result, "containerIface", containerIfaceName)
	return nil
}

func (ic *ifConfigurator) moveOffloadVFToContainerNS(vfNetDevice string, containerID string, containerNetNS string, containerIfaceName string, mtu int, result *current.Result) error {
	// Move VF to Container namespace
	netns, err := nsGetNS(containerNetNS)
	if err != nil {
		return fmt.Errorf("failed to open container netns %s: %w", containerNetNS, err)
	}
	err = ic.moveIFToNetNS(vfNetDevice, netns)
	if err != nil {
		return fmt.Errorf("failed to move VF %s to container netns %s: %w", vfNetDevice, containerNetNS, err)
	}
	netns.Close()

	if err := nsWithNetNSPath(containerNetNS, func(hostNS ns.NetNS) error {
		err = renameInterface(vfNetDevice, containerIfaceName)
		if err != nil {
			return fmt.Errorf("failed to rename VF netdevice as containerIfaceName %s: %w", containerIfaceName, err)
		}
		link, err := ic.netlink.LinkByName(containerIfaceName)
		if err != nil {
			return fmt.Errorf("failed to find VF netdevice %s: %w", containerIfaceName, err)
		}
		return ic.configureVFLinkAndIPAM(link, containerID, containerIfaceName, containerNetNS, mtu, result)
	}); err != nil {
		return err
	}

	return nil
}

func (ic *ifConfigurator) moveVFtoContainerNS(vfNetDevice string, containerID string, containerNetNS string, containerIfaceName string, mtu int, result *current.Result) error {
	link, err := ic.netlink.LinkByName(vfNetDevice)
	if err != nil {
		return fmt.Errorf("error getting VF link: %w", err)
	}
	klog.V(2).InfoS("Got link of vfNetDevice", "vfNetDevice", vfNetDevice, "link", link)

	// Rename the device in a temp NS to avoid race condition.
	// This rename logic is mainly referring to the code of host-device CNI.
	// https://github.com/containernetworking/plugins/blob/a5d507e2b884d8bd6a001c9e5a9118113ffef444/plugins/main/host-device/host-device.go#L238-L464
	tempNS, err := tempNetNS()
	if err != nil {
		return fmt.Errorf("failed to create tempNS: %w", err)
	}
	defer tempNS.Close()

	// Move the host VF device into tempNS
	if err = ic.netlink.LinkSetNsFd(link, int(tempNS.Fd())); err != nil {
		return fmt.Errorf("failed to move %s to tempNS: %w", vfNetDevice, err)
	}

	netns, err := nsGetNS(containerNetNS)
	if err != nil {
		return fmt.Errorf("failed to open container netns %s: %w", containerNetNS, err)
	}
	defer netns.Close()

	if err = tempNS.Do(func(hostNS ns.NetNS) error {
		// Look up the device in tempNS, as the index might have changed
		tempNSDev, err := ic.netlink.LinkByName(vfNetDevice)
		if err != nil {
			return fmt.Errorf("failed to find %s in tempNS: %w", vfNetDevice, err)
		}
		defer func() {
			if err != nil && tempNSDev != nil {
				tmpErr := ic.netlink.LinkSetNsFd(tempNSDev, int(hostNS.Fd()))
				if tmpErr != nil {
					klog.ErrorS(tmpErr, "Failed to set network namespace back to hostNS for the device", "device", tempNSDev.Attrs().Name, "hostNS", hostNS.Path())
				}
			}
		}()

		// Rename the device to the wanted name
		if err = ic.netlink.LinkSetName(tempNSDev, containerIfaceName); err != nil {
			return fmt.Errorf("failed to rename VF device %s to %s: %w", vfNetDevice, containerIfaceName, err)
		}

		// Restore the original device name in case of error
		defer func() {
			if err != nil && tempNSDev != nil {
				tmpErr := ic.netlink.LinkSetName(tempNSDev, vfNetDevice)
				if tmpErr != nil {
					klog.ErrorS(tmpErr, "Failed to restore device name", "device", tempNSDev.Attrs().Name, "originalName", vfNetDevice)
				}
			}
		}()

		err = ic.netlink.LinkSetAlias(tempNSDev, vfNetDevice)
		if err != nil {
			return fmt.Errorf("failed to set alias as %s for VF netdevice %s: %w", vfNetDevice, vfNetDevice, err)
		}
		klog.V(2).InfoS("Link's alias has been updated", "alias", vfNetDevice)

		// Remove the alias on error
		defer func() {
			if err != nil && tempNSDev != nil {
				tmpErr := ic.netlink.LinkSetAlias(tempNSDev, "")
				if tmpErr != nil {
					klog.ErrorS(tmpErr, "Failed to empty the alias", "device", tempNSDev.Attrs().Name)
				}
			}
		}()

		// Move VF to Container namespace
		err = ic.moveIFToNetNS(containerIfaceName, netns)
		if err != nil {
			return fmt.Errorf("failed to move VF %s to container netns %s: %w", vfNetDevice, containerNetNS, err)
		}

		// Look up the device again on error, as the index might have changed
		defer func() {
			if err != nil {
				var tmpErr error
				tempNSDev, tmpErr = ic.netlink.LinkByName(containerIfaceName)
				if tmpErr != nil {
					klog.ErrorS(tmpErr, "Failed to look up the device", "device", containerIfaceName)
				}
			}
		}()

		err = netns.Do(func(_ ns.NetNS) error {
			link, err := ic.netlink.LinkByName(containerIfaceName)
			if err != nil {
				return fmt.Errorf("failed to find VF netdevice %s: %v", containerIfaceName, err)
			}
			// Move the interface back to tempNS on error, so that we can undo VF
			// rename and alias setting in the previous steps.
			defer func() {
				if err != nil {
					klog.InfoS("Move the interface back to tempNS on error", "device", vfNetDevice)
					tmpErr := ic.netlink.LinkSetNsFd(link, int(tempNS.Fd()))
					if tmpErr != nil {
						klog.ErrorS(tmpErr, "Failed to set network namespace to tempNS for the device", "device", tempNSDev.Attrs().Name, "tempNS", tempNS.Path())
					}
				}
			}()
			err = ic.configureVFLinkAndIPAM(link, containerID, containerIfaceName, containerNetNS, mtu, result)
			return err
		})
		return err
	}); err != nil {
		return err
	}

	return nil
}

// configureContainerSriovLinkOnBridge moves the VF to the container namespace for OVS offload.
func (ic *ifConfigurator) configureContainerSriovLinkOnBridge(
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
	vfNetdevices, err := ic.sriovnet.GetNetDevicesFromPCI(pciAddress)
	if err != nil {
		return err
	}
	// Make sure we have 1 netdevice per PCI address
	if len(vfNetdevices) != 1 {
		return fmt.Errorf("failed to get one netdevice interface per %s", pciAddress)
	}
	vfNetdevice := vfNetdevices[0]
	// 2. get Uplink netdevice
	uplink, err := ic.sriovnet.GetUplinkRepresentor(pciAddress)
	if err != nil {
		return fmt.Errorf("failed to get uplink representor error: %s", err)
	}
	// 3. get VF index from PCI
	vfIndex, err := ic.sriovnet.GetVFIndexByPCIAddress(pciAddress)
	if err != nil {
		return fmt.Errorf("failed to get VF index error: %s", err)
	}
	// 4. lookup representor
	repPortName, err := ic.sriovnet.GetVFRepresentor(uplink, vfIndex)
	if err != nil {
		return fmt.Errorf("failed to get VF representor error: %s", err)
	}
	// 5. rename VF representor to hostIfaceName
	if err = renameInterface(repPortName, hostIfaceName); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %v", repPortName, hostIfaceName, err)
	}
	hostIface.Name = hostIfaceName
	link, err := ic.netlink.LinkByName(hostIface.Name)
	if err != nil {
		return err
	}
	hostIface.Mac = link.Attrs().HardwareAddr.String()

	return ic.moveOffloadVFToContainerNS(vfNetdevice, containerID, containerNetNS, containerIfaceName, mtu, result)
}

// configureContainerSriovLink moves the VF to the container namespace for Pod link SR-IOV interface;
// intended for multiple interfaces other than the primary interface.
func (ic *ifConfigurator) configureContainerSriovLink(
	podName string,
	podNamespace string,
	containerID string,
	containerNetNS string,
	containerIfaceName string,
	mtu int,
	pciAddress string,
	result *current.Result,
) error {
	hostIface := &current.Interface{Name: containerIfaceName}
	containerIface := &current.Interface{Name: containerIfaceName, Sandbox: containerNetNS}
	result.Interfaces = []*current.Interface{hostIface, containerIface}

	vfIFName, err := ic.getVFLinkName(pciAddress)
	if err != nil || vfIFName == "" {
		return fmt.Errorf("VF interface not found for pciAddress %s: %v", pciAddress, err)
	}

	link, err := ic.netlink.LinkByName(vfIFName)
	if err != nil {
		return fmt.Errorf("error getting VF link: %v", err)
	}
	klog.V(2).InfoS("Got link of vfIFName", "vfIFName", vfIFName, "link", link)

	hostIface.Mac = link.Attrs().HardwareAddr.String()
	hostIface.Name = vfIFName
	klog.V(2).InfoS("hostIface info", "hostIface.Name", hostIface.Name, "hostIface.Mac", hostIface.Mac, "vfIFName", vfIFName)

	return ic.moveVFtoContainerNS(vfIFName, containerID, containerNetNS, containerIfaceName, mtu, result)
}

// recoverVFInterfaceName rename the interface back to the original VF interface name.
func (ic *ifConfigurator) recoverVFInterfaceName(containerIfaceName string, containerNetNS string) error {
	klog.V(2).InfoS("Recovering VF interface name and moving it back to hostNS", "containerNetNS", containerNetNS, "containerIfaceName", containerIfaceName)
	tempNS, err := tempNetNS()
	if err != nil {
		return fmt.Errorf("failed to create tempNS: %v", err)
	}
	defer tempNS.Close()

	containerNS, err := nsGetNS(containerNetNS)
	if err != nil {
		return fmt.Errorf("failed to open container netns %s: %v", containerNetNS, err)
	}
	defer containerNS.Close()

	var originalVFName string
	if err = containerNS.Do(func(_ ns.NetNS) error {
		link, err := ic.netlink.LinkByName(containerIfaceName)
		if err != nil {
			return fmt.Errorf("failed to find container interface %s: %v", containerIfaceName, err)
		}

		originalVFName = link.Attrs().Alias
		if originalVFName == "" {
			return fmt.Errorf("failed to find original VF device name for %s: no alias set", containerIfaceName)
		}

		// Move VF from container namespace to tempNS
		if err = ic.netlink.LinkSetNsFd(link, int(tempNS.Fd())); err != nil {
			return fmt.Errorf("failed to move VF device %s to tempNS: %v", containerIfaceName, err)
		}
		return nil
	}); err != nil {
		return err
	}

	if err := tempNS.Do(func(hostNS ns.NetNS) error {
		// Lookup the device in tempNS (index might have changed)
		tempNSDev, err := ic.netlink.LinkByName(containerIfaceName)
		if err != nil {
			return fmt.Errorf("failed to find %s in tempNS: %v", containerIfaceName, err)
		}
		defer func() {
			if err != nil && tempNSDev != nil {
				// Move VF back to container namespace on error
				netns, _ := nsGetNS(containerNetNS)
				_ = ic.netlink.LinkSetNsFd(tempNSDev, int(netns.Fd()))
			}
		}()

		// Rename container device to originalVFName
		if err = ic.netlink.LinkSetName(tempNSDev, originalVFName); err != nil {
			return fmt.Errorf("failed to rename device %s to %s: %v", containerIfaceName, originalVFName, err)
		}

		// Rename the device back to containerIfaceName on error
		defer func() {
			if err != nil {
				_ = ic.netlink.LinkSetName(tempNSDev, containerIfaceName)
			}
		}()

		// Unset device's alias property
		if err = ic.netlink.LinkSetAlias(tempNSDev, ""); err != nil {
			return fmt.Errorf("failed to unset alias of %q: %v", originalVFName, err)
		}

		// Set back the device alias to originalVFName on error
		defer func() {
			if err != nil {
				_ = ic.netlink.LinkSetAlias(tempNSDev, originalVFName)
			}
		}()

		// Move VF from container namespace back to hostNS
		if err = ic.netlink.LinkSetNsFd(tempNSDev, int(hostNS.Fd())); err != nil {
			return fmt.Errorf("failed to move VF %s to hostNS %s: %v", originalVFName, hostNS, err)
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
	mac net.HardwareAddr,
) error {
	// Include the container veth interface name in the name generation, as one Pod can have more
	// than one interfaces inc. secondary interfaces, while the host interface name must be unique.
	hostIfaceName := util.GenerateContainerHostVethName(podName, podNamespace, containerID, containerIfaceName)

	if mac == nil {
		mac = util.GenerateRandomMAC()
	}

	hostIface := &current.Interface{Name: hostIfaceName}
	containerIface := &current.Interface{Name: containerIfaceName, Sandbox: containerNetNS, Mac: mac.String()}
	result.Interfaces = []*current.Interface{hostIface, containerIface}

	if err := nsWithNetNSPath(containerNetNS, func(hostNS ns.NetNS) error {
		klog.V(2).InfoS("Creating veth devices for container", "containerIfaceName", containerIfaceName, "hostIfaceName", hostIfaceName, "containerID", containerID)
		hostVeth, containerVeth, err := ipSetupVethWithName(containerIfaceName, hostIfaceName, mtu, mac.String(), hostNS)
		if err != nil {
			return fmt.Errorf("failed to create veth devices for container %s: %v", containerID, err)
		}
		success := false
		defer func() {
			if !success {
				klog.V(2).InfoS("Deleting veth devices for container during rollback", "containerID", containerID)
				if err := ipDelLinkByName(containerVeth.Name); err != nil && err != ip.ErrLinkNotFound {
					klog.ErrorS(err, "Failed to delete veth devices for container during rollback", "containerID", containerID)
				}
			}
		}()
		containerIface.Mac = mac.String()
		hostIface.Mac = hostVeth.HardwareAddr.String()

		// Disable TX checksum offloading when it's configured explicitly.
		if ic.disableTXChecksumOffload {
			if err := ethtoolTXHWCsumOff(containerVeth.Name); err != nil {
				return fmt.Errorf("error when disabling TX checksum offload on container veth: %v", err)
			}
		}

		klog.V(2).InfoS("Configuring IP address for container interface", "result", *result)
		// result.Interfaces must be set before this.
		if err := ipamConfigureIface(containerIface.Name, result); err != nil {
			return fmt.Errorf("failed to configure IP address for container %s: %v", containerID, err)
		}
		success = true
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
	if err := nsIsNSorErr(containerNetNS); err != nil {
		return fmt.Errorf("%s is not a valid network namespace: %v", containerNetNS, err)
	}
	if len(result.IPs) == 0 {
		klog.Warningf("Expected at least one IP address in CNI result, skip sending Gratuitous ARP")
		return nil
	}
	// Sending Gratuitous ARP is a best-effort action and is unlikely to fail as we have ensured the netns is valid.
	go nsWithNetNSPath(containerNetNS, func(_ ns.NetNS) error {
		iface, err := netInterfaceByName(containerIfaceName)
		if err != nil {
			klog.Errorf("Failed to find container interface %s in ns %s: %v", containerIfaceName, containerNetNS, err)
			return nil
		}
		var targetIPv4, targetIPv6 net.IP
		for _, ipc := range result.IPs {
			if ipc.Address.IP.To4() != nil {
				targetIPv4 = ipc.Address.IP
			} else {
				targetIPv6 = ipc.Address.IP
			}
		}
		if targetIPv4 == nil && targetIPv6 == nil {
			klog.V(2).InfoS("No IPv4 and IPv6 address found for container interface in ns, skip sending Gratuitous ARP/NDP", "interface", containerIfaceName, "ns", containerNetNS)
			return nil
		}
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		count := 0
		for {
			// Send gratuitous ARP/NDP to network in case of stale mappings for this IP address
			// (e.g. if a previous - deleted - Pod was using the same IP).
			if targetIPv4 != nil {
				if err := arpingGratuitousARPOverIface(targetIPv4, iface); err != nil {
					klog.Warningf("Failed to send gratuitous ARP #%d: %v", count, err)
				}
			}
			if targetIPv6 != nil {
				if err := ndpGratuitousNDPOverIface(targetIPv6, iface); err != nil {
					klog.Warningf("Failed to send gratuitous NDP #%d: %v", count, err)
				}
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
	brSriovVFDeviceID string,
	podSriovVFDeviceID string,
	result *current.Result,
	containerAccess *containerAccessArbitrator,
	mac net.HardwareAddr,
) error {
	if brSriovVFDeviceID != "" {
		if !ic.isOvsHardwareOffloadEnabled {
			return fmt.Errorf("OVS is configured with hardware offload disabled, but SR-IOV VF was requested; please set hardware offload to true via antrea yaml")
		}
		klog.V(2).InfoS("Moving SR-IOV device to network namespace of container", "deviceID", brSriovVFDeviceID, "containerID", containerID)
		// Move SR-IOV VF to network namespace
		return ic.configureContainerSriovLinkOnBridge(podName, podNamespace, containerID, containerNetNS, containerIfaceName, mtu, brSriovVFDeviceID, result)
	} else if podSriovVFDeviceID != "" {
		// For Pod link SR-IOV interface not attached to the OVS bridge
		klog.V(2).InfoS("Moving SR-IOV device to network namespace of container", "deviceID", podSriovVFDeviceID, "containerID", containerID)
		return ic.configureContainerSriovLink(podName, podNamespace, containerID, containerNetNS, containerIfaceName, mtu, podSriovVFDeviceID, result)
	} else {
		klog.V(2).InfoS("Create veth pair for container", "containerID", containerID)
		// Create veth pair and link up
		return ic.configureContainerLinkVeth(podName, podNamespace, containerID, containerNetNS, containerIfaceName, mtu, result, mac)
	}
}

func (ic *ifConfigurator) changeContainerMTU(containerNetNS string, containerIFDev string, mtuDeduction int) error {
	var peerIdx int
	if err := nsWithNetNSPath(containerNetNS, func(hostNS ns.NetNS) error {
		link, err := ic.netlink.LinkByName(containerIFDev)
		if err != nil {
			return fmt.Errorf("failed to find interface %s in container netns %s: %v", containerIFDev, containerNetNS, err)
		}
		_, peerIdx, err = ipGetVethPeerIfindex(containerIFDev)
		if err != nil {
			return fmt.Errorf("failed to get peer index for dev %s in container netns %s: %w", containerIFDev, containerNetNS, err)
		}
		err = ic.netlink.LinkSetMTU(link, link.Attrs().MTU-mtuDeduction)
		if err != nil {
			return fmt.Errorf("failed to set MTU for interface %s in container netns %s: %v", containerIFDev, containerNetNS, err)
		}
		return nil
	}); err != nil {
		return err
	}

	peerIntf, err := netInterfaceByIndex(peerIdx)
	if err != nil {
		return fmt.Errorf("failed to get host interface for index %d: %w", peerIdx, err)
	}

	hostInterfaceName := peerIntf.Name
	link, err := ic.netlink.LinkByName(hostInterfaceName)
	if err != nil {
		return fmt.Errorf("failed to find host interface %s: %v", hostInterfaceName, err)
	}
	err = ic.netlink.LinkSetMTU(link, link.Attrs().MTU-mtuDeduction)
	if err != nil {
		return fmt.Errorf("failed to set MTU for host interface %s: %v", hostInterfaceName, err)
	}
	return nil
}

func (ic *ifConfigurator) removeContainerLink(containerID, hostInterfaceName string) error {
	klog.V(2).InfoS("Deleting veth devices for container", "containerID", containerID)
	// Don't return an error if the device is already removed as CniDel can be called multiple times.
	if err := ip.DelLinkByName(hostInterfaceName); err != nil {
		if err != ip.ErrLinkNotFound {
			return fmt.Errorf("failed to delete veth devices for container %s: %v", containerID, err)
		}
		klog.V(2).InfoS("Did not find interface for container", "interface", hostInterfaceName, "containerID", containerID)
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
	err := nsWithNetNSPath(containerNetns, func(_ ns.NetNS) error {
		var errlink error
		// Check container link config
		if sriovVFDeviceID != "" {
			networkInterface, errlink = ic.validateContainerVFInterface(containerIface, sriovVFDeviceID)
		} else {
			networkInterface, errlink = ic.validateContainerVethInterface(containerIface)
		}
		if errlink != nil {
			return errlink
		}
		// Check container IP config
		if err := ipValidateExpectedInterfaceIPs(containerIface.Name, containerIPs); err != nil {
			return err
		}
		// Check container route config
		if err := ipValidateExpectedRoute(containerRoutes); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		klog.Errorf("Failed to check container %s interface configurations in netns %s: %v",
			containerID, containerNetns, err)
		return nil, err
	}
	return networkInterface, nil
}

func (ic *ifConfigurator) validateContainerVFInterface(intf *current.Interface, sriovVFDeviceID string) (netlink.Link, error) {
	link, err := ic.validateInterface(intf, true, netDeviceTypeVF)
	if err != nil {
		return nil, err
	}
	netdevices, err := ic.sriovnet.GetNetDevicesFromPCI(sriovVFDeviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to find netdevice to PCI address %s: %v", sriovVFDeviceID, err)
	}
	// The check makes sure that the SR-IOV VF netdevice is not in the host namespace.
	// GetNetDevicesFromPCI is using linux sysfs to find the VF netdevice. The method
	// is running in container network namespace, but we are still in the antrea-agent
	// filesystem. The antrea-agent container is privileged, which allows access to
	// the host sysfs, therefore the validation is to make sure that the VF netdevice
	// is not in the host network namespace.
	if len(netdevices) != 0 {
		return nil, fmt.Errorf("VF netdevice still in host network namespace %s %+v", sriovVFDeviceID, netdevices)
	}
	if intf.Mac != link.Attrs().HardwareAddr.String() {
		return nil, fmt.Errorf("interface %s MAC %s doesn't match container MAC: %s",
			intf.Name, intf.Mac, link.Attrs().HardwareAddr.String())
	}
	return link, nil
}

func (ic *ifConfigurator) validateContainerVethInterface(intf *current.Interface) (*vethPair, error) {
	link, err := ic.validateInterface(intf, true, netDeviceTypeVeth)
	if err != nil {
		return nil, err
	}
	veth := &vethPair{}
	linkName := link.Attrs().Name
	veth.ifIndex = link.Attrs().Index
	_, veth.peerIndex, err = ipGetVethPeerIfindex(linkName)
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
	uplink, err := ic.sriovnet.GetUplinkRepresentor(sriovVFDeviceID)
	if err != nil {
		return "", fmt.Errorf("failed to get uplink representor for PCI Address %s", sriovVFDeviceID)
	}
	vfIndex, err := ic.sriovnet.GetVFIndexByPCIAddress(sriovVFDeviceID)
	if err != nil {
		return "", fmt.Errorf("failed to vf index for PCI Address %s", sriovVFDeviceID)
	}
	return ic.sriovnet.GetVFRepresentor(uplink, vfIndex)
}

func (ic *ifConfigurator) validateContainerPeerInterface(interfaces []*current.Interface, containerVeth *vethPair) (*vethPair, error) {
	// Iterate all the passed interfaces and look up the host interface by
	// matching the veth peer interface index.
	for _, hostIntf := range interfaces {
		if hostIntf.Sandbox != "" {
			// Not in the default Namespace. Must be the container interface.
			continue
		}
		link, err := ic.validateInterface(hostIntf, false, netDeviceTypeVeth)
		if err != nil {
			klog.Errorf("Failed to validate interface %s: %v", hostIntf.Name, err)
			continue
		}

		if link.Attrs().Index != containerVeth.peerIndex {
			continue
		}

		hostVeth := &vethPair{ifIndex: link.Attrs().Index, name: link.Attrs().Name}
		_, hostVeth.peerIndex, err = ipGetVethPeerIfindex(hostVeth.name)
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
	intf, err := getNSDevInterface(containerNetNS, containerIFDev)
	if err != nil {
		return nil, nil, fmt.Errorf("connectInterceptedInterface failed to get veth info: %w", err)
	}
	containerIface.Name = containerIFDev
	containerIface.Sandbox = sandbox
	containerIface.Mac = intf.HardwareAddr.String()

	// Setup dev in host ns.
	hostIface := &current.Interface{}
	intf, br, err := getNSPeerDevBridge(containerNetNS, containerIFDev)
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

// addPostInterfaceCreateHook is called only on Windows. Adding this function in this file because it is defined in the
// interface `podInterfaceConfigurator`.
func (ic *ifConfigurator) addPostInterfaceCreateHook(containerID, endpointName string, containerAccess *containerAccessArbitrator, hook postInterfaceCreateHook) error {
	return nil
}

func (ic *ifConfigurator) validateInterface(intf *current.Interface, inNetns bool, ifType string) (netlink.Link, error) {
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
	link, err := ic.netlink.LinkByName(intf.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to find link for interface %s", intf.Name)
	}
	switch ifType {
	case netDeviceTypeVeth:
		if !isVeth(link) {
			return nil, fmt.Errorf("interface %s is not of type veth", intf.Name)
		}
		return link, nil
	case netDeviceTypeVF:
		return link, nil
	}
	return nil, fmt.Errorf("unknown device type %s", ifType)
}

func isVeth(link netlink.Link) bool {
	_, isVeth := link.(*netlink.Veth)
	return isVeth
}
