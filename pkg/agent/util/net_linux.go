//go:build linux
// +build linux

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

package util

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	utilnetlink "antrea.io/antrea/pkg/agent/util/netlink"
	"antrea.io/antrea/pkg/agent/util/sysctl"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

var (
	netlinkUtil utilnetlink.Interface = &netlink.Handle{}

	// Declared variables which are meant to be overridden for testing.
	getNS              = ns.GetNS
	netNSDo            = ns.NetNS.Do
	netNSPath          = ns.NetNS.Path
	netNSClose         = ns.NetNS.Close
	getVethPeerIfindex = ip.GetVethPeerIfindex
	netlinkAttrs       = netlink.Link.Attrs
)

// GetNSPeerDevBridge returns peer device and its attached bridge (if applicable)
// for device dev in network space indicated by nsPath
func GetNSPeerDevBridge(nsPath, dev string) (*net.Interface, string, error) {
	var peerIdx int
	netNS, err := getNS(nsPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get NS for path %s: %w", nsPath, err)
	}
	if err := netNSDo(netNS, func(_ ns.NetNS) error {
		_, peerIdx, err = getVethPeerIfindex(dev)
		if err != nil {
			return fmt.Errorf("failed to get peer idx for dev %s in container %s: %w", dev, nsPath, err)
		}
		return nil
	}); err != nil {
		return nil, "", err
	}

	peerIntf, err := netInterfaceByIndex(peerIdx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get interface for idx %d: %w", peerIdx, err)
	}
	peerLink, err := netlinkUtil.LinkByIndex(peerIdx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get link for idx %d: %w", peerIdx, err)
	}

	// not attached to a bridge.
	if peerLink.Attrs().MasterIndex <= 0 {
		return peerIntf, "", nil
	}

	bridgeLink, err := netlinkUtil.LinkByIndex(peerLink.Attrs().MasterIndex)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get master link for dev %s: %w", peerLink.Attrs().Name, err)
	}
	bridge, ok := bridgeLink.(*netlink.Bridge)
	if !ok {
		// master link is not bridge
		return peerIntf, "", nil
	}
	return peerIntf, bridge.Name, nil
}

// GetNSDevInterface returns interface of dev in namespace nsPath.
func GetNSDevInterface(nsPath, dev string) (*net.Interface, error) {
	netNS, err := getNS(nsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get NS for path %s: %w", nsPath, err)
	}
	var intf *net.Interface
	if err := netNSDo(netNS, func(_ ns.NetNS) error {
		intf, err = netInterfaceByName(dev)
		if err != nil {
			return fmt.Errorf("failed to get interface %s in container %s: %w", dev, nsPath, err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return intf, nil
}

// GetNSPath returns the path of the specified netns.
func GetNSPath(netnsName string) (string, error) {
	netNS, err := getNS(netnsName)
	if err != nil {
		return "", fmt.Errorf("failed to open netns %s: %v", netnsName, err)
	}
	defer netNSClose(netNS)
	return netNSPath(netNS), nil
}

func SetLinkUp(name string) (net.HardwareAddr, int, error) {
	link, err := netlinkUtil.LinkByName(name)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil, 0, newLinkNotFoundError(name)
		}
		return nil, 0, err
	}
	// Set host gateway interface up.
	if err := netlinkUtil.LinkSetUp(link); err != nil {
		klog.Errorf("Failed to set host link for %s up: %v", name, err)
		return nil, 0, err
	}
	mac := netlinkAttrs(link).HardwareAddr
	index := netlinkAttrs(link).Index
	return mac, index, nil
}

// addrSliceDifference returns elements in s1 but not in s2.
func addrSliceDifference(s1, s2 []netlink.Addr) []*netlink.Addr {
	var diff []*netlink.Addr

	for i, e1 := range s1 {
		found := false
		for _, e2 := range s2 {
			if e1.Equal(e2) {
				found = true
				break
			}
		}
		if !found {
			diff = append(diff, &s1[i])
		}
	}

	return diff
}

// ConfigureLinkAddresses adds the provided addresses to the interface identified by index idx, if
// they are missing from the interface. Any other existing address already configured for the
// interface will be removed, unless it is a link-local address.
func ConfigureLinkAddresses(idx int, ipNets []*net.IPNet) error {
	link, err := netlinkUtil.LinkByIndex(idx)
	if err != nil {
		return err
	}
	ifaceName := netlinkAttrs(link).Name
	var newAddrs []netlink.Addr
	for _, ipNet := range ipNets {
		newAddrs = append(newAddrs, netlink.Addr{IPNet: ipNet, Label: ""})
	}

	allAddrs, err := netlinkUtil.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to query address list for interface %s: %v", ifaceName, err)
	}
	// Remove link-local address from list
	addrs := make([]netlink.Addr, 0, len(allAddrs))
	for _, addr := range allAddrs {
		if !addr.IP.IsLinkLocalUnicast() {
			addrs = append(addrs, addr)
		}
	}

	addrsToAdd := addrSliceDifference(newAddrs, addrs)
	addrsToRemove := addrSliceDifference(addrs, newAddrs)

	if len(addrsToAdd) == 0 && len(addrsToRemove) == 0 {
		klog.V(2).Infof("IP configuration for interface %s does not need to change", ifaceName)
		return nil
	}

	for _, addr := range addrsToRemove {
		klog.V(2).Infof("Removing address %v from interface %s", addr, ifaceName)
		if err := netlinkUtil.AddrDel(link, addr); err != nil {
			return fmt.Errorf("failed to remove address %v from interface %s: %v", addr, ifaceName, err)
		}
	}

	for _, addr := range addrsToAdd {
		klog.V(2).Infof("Adding address %v to interface %s", addr, ifaceName)
		if err := netlinkUtil.AddrAdd(link, addr); err != nil && !strings.Contains(err.Error(), "file exists") {
			return fmt.Errorf("failed to add address %v to interface %s: %v", addr, ifaceName, err)
		}
	}

	return nil
}

// ListenLocalSocket creates a listener on a Unix domain socket.
func ListenLocalSocket(address string) (net.Listener, error) {
	// remove before bind to avoid "address already in use" errors
	_ = os.Remove(address)

	if err := os.MkdirAll(filepath.Dir(address), 0750); err != nil {
		klog.Fatalf("Failed to create directory %s: %v", filepath.Dir(address), err)
	}
	listener, err := listenUnix(address)
	if err != nil {
		return nil, err
	}
	err = os.Chmod(address, 0750)
	if err != nil {
		klog.Fatalf("Failed to change permissions for socket file %s: %v", address, err)
	}
	return listener, nil
}

// SetAdapterMACAddress set specified MAC address on interface.
func SetAdapterMACAddress(adapterName string, macConfig *net.HardwareAddr) error {
	link, err := netlinkUtil.LinkByName(adapterName)
	if err != nil {
		return err
	}
	return netlinkUtil.LinkSetHardwareAddr(link, *macConfig)
}

// deleteOVSPort deletes specific OVS port. This function calls ovs-vsctl command to bypass
// OVS bridge client to work when agent exiting.
func deleteOVSPort(brName, portName string) error {
	cmd := exec.Command("ovs-vsctl", "--if-exists", "del-port", brName, portName)
	return cmd.Run()
}

func HostInterfaceExists(ifName string) bool {
	_, err := netlinkUtil.LinkByName(ifName)
	if err == nil {
		return true
	}
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		return false
	}
	klog.ErrorS(err, "Failed to find host interface", "name", ifName)
	return false
}

func GetInterfaceConfig(ifName string) (*net.Interface, []*net.IPNet, []interface{}, error) {
	iface, err := netInterfaceByName(ifName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get interface by name %s: %v", ifName, err)
	}
	addrs, err := getIPNetsByLink(iface)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get address for interface %s: %v", ifName, err)
	}
	routes, err := getRoutesOnInterface(iface.Index)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get routes for iface.Index %d: %v", iface.Index, err)
	}
	return iface, addrs, routes, nil
}

func RenameInterface(from, to string) error {
	klog.InfoS("Renaming interface", "oldName", from, "newName", to)
	var renameErr error
	pollErr := wait.PollUntilContextTimeout(context.TODO(), time.Millisecond*100, time.Second, false,
		func(ctx context.Context) (done bool, err error) {
			renameErr = renameHostInterface(from, to)
			if renameErr != nil {
				klog.InfoS("Unable to rename host interface name with error, retrying", "oldName", from, "newName", to, "err", renameErr)
				return false, nil
			}
			return true, nil
		})
	if pollErr != nil {
		return fmt.Errorf("failed to rename host interface name %s to %s", from, to)
	}
	// Fix for the issue https://github.com/antrea-io/antrea/issues/6301.
	// In some new Linux versions which support AltName, if the only valid altname of the interface is the same as the
	// interface name, it would be left empty when the name is occupied by the interface name; after we rename the
	// interface name to another value, the altname of the interface would be set to the original interface name by the
	// system.
	// This altname must be removed as we need to reserve the name for an OVS internal port.
	if err := removeInterfaceAltName(to, from); err != nil {
		return fmt.Errorf("failed to remove AltName %s on interface %s: %w", from, to, err)
	}
	return nil
}

func RemoveLinkIPs(link netlink.Link) error {
	addrs, err := netlinkUtil.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for i := range addrs {
		if err = netlinkUtil.AddrDel(link, &addrs[i]); err != nil {
			return err
		}
	}
	return nil
}

func RemoveLinkRoutes(link netlink.Link) error {
	routes, err := netlinkUtil.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for i := range routes {
		if err = netlinkUtil.RouteDel(&routes[i]); err != nil {
			return err
		}
	}
	return nil
}

func ConfigureLinkRoutes(link netlink.Link, routes []interface{}) error {
	for _, r := range routes {
		rt := r.(netlink.Route)
		rt.LinkIndex = netlinkAttrs(link).Index
		if err := netlinkUtil.RouteReplace(&rt); err != nil {
			return err
		}
	}
	return nil
}

func EnsureIPv6EnabledOnInterface(ifaceName string) error {
	path := fmt.Sprintf("ipv6/conf/%s/disable_ipv6", ifaceName)
	return sysctl.EnsureSysctlNetValue(path, 0)
}

func EnsureARPAnnounceOnInterface(ifaceName string, value int) error {
	path := fmt.Sprintf("ipv4/conf/%s/arp_announce", ifaceName)
	return sysctl.EnsureSysctlNetValue(path, value)
}

func EnsureRPFilterOnInterface(ifaceName string, value int) error {
	path := fmt.Sprintf("ipv4/conf/%s/rp_filter", ifaceName)
	return sysctl.EnsureSysctlNetValue(path, value)
}

func EnsurePromoteSecondariesOnInterface(ifaceName string) error {
	path := fmt.Sprintf("ipv4/conf/%s/promote_secondaries", ifaceName)
	return sysctl.EnsureSysctlNetValue(path, 1)
}

func getRoutesOnInterface(linkIndex int) ([]interface{}, error) {
	link, err := netlinkUtil.LinkByIndex(linkIndex)
	if err != nil {
		return nil, err
	}
	rs, err := netlinkUtil.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	var routes []interface{}
	for _, r := range rs {
		routes = append(routes, r)
	}
	return routes, nil
}

func renameHostInterface(oriName string, newName string) error {
	link, err := netlinkUtil.LinkByName(oriName)
	if err != nil {
		return err
	}
	if err := netlinkUtil.LinkSetDown(link); err != nil {
		return err
	}
	if err := netlinkUtil.LinkSetName(link, newName); err != nil {
		return err
	}
	if err := netlinkUtil.LinkSetUp(link); err != nil {
		return err
	}
	return nil
}

// removeInterfaceAltName removes altName on interface with provided name. altName not found will return nil.
func removeInterfaceAltName(name string, altName string) error {
	link, err := netlinkUtil.LinkByName(name)
	if err != nil {
		return err
	}
	for _, existAltName := range link.Attrs().AltNames {
		if existAltName == altName {
			return netlinkUtil.LinkDelAltName(link, altName)
		}
	}
	return nil
}

// PrepareHostInterfaceConnection prepares host interface connection to the OVS bridge client by:
// 1. Renaming the host interface (a bridged suffix will be added to it).
// 2. Creating an internal port (original name of the host interface will be used here).
// 3. Set the MTU of this new link/internal-port to the provided mtu parameter value, unless mtu is zero.
// 4. Moving IPs of host interface to this new link/internal-port.
// 5. Moving routes of host interface to the new link/internal-port.
// and returns the bridged name, true if it already exists, and error.
func PrepareHostInterfaceConnection(
	bridge ovsconfig.OVSBridgeClient,
	ifaceName string,
	ifaceOFPort int32,
	externalIDs map[string]interface{},
	mtu int,
) (string, bool, error) {
	bridgedName := GenerateUplinkInterfaceName(ifaceName)
	// If the port already exists, just return.
	if ofPort, err := bridge.GetOFPort(bridgedName, false); err == nil {
		klog.InfoS("Port already exists, skip the configuration", "port", bridgedName, "ofPort", ofPort)
		return bridgedName, true, nil
	}

	iface, ifaceIPs, ifaceRoutes, err := GetInterfaceConfig(ifaceName)
	if err != nil {
		return "", false, err
	}

	if err = RenameInterface(ifaceName, bridgedName); err != nil {
		return "", false, err
	}
	if _, err = bridge.CreateInternalPort(ifaceName, ifaceOFPort, iface.HardwareAddr.String(), externalIDs); err != nil {
		return "", false, fmt.Errorf("failed to create internal port: %v", err)
	}

	// Wait a few seconds for OVS bridge local port.
	if err = wait.PollUntilContextTimeout(context.TODO(), 100*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		link, err := netlink.LinkByName(ifaceName)
		if err != nil {
			klog.V(4).InfoS("OVS bridge local port is not ready", "port", ifaceName, "err", err)
			return false, nil
		}
		klog.InfoS("OVS bridge local port is ready", "type", link.Type(), "attrs", link.Attrs())
		return true, nil
	}); err != nil {
		return "", false, fmt.Errorf("failed waiting for internal port to show up: %v", err)
	}

	localLink, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return "", false, err
	}
	if _, _, err = SetLinkUp(ifaceName); err != nil {
		return "", false, fmt.Errorf("failed to set link up: %v", err)
	}

	if mtu > 0 {
		if err := bridge.SetInterfaceMTU(ifaceName, mtu); err != nil {
			return "", false, fmt.Errorf("failed to set bridge interface MTU: %w", err)
		}
	}

	// Check if interface is configured with an IPv6 address: if it is, we need to ensure that IPv6
	// is enabled on the OVS internal port as we need to move all IP addresses over.
	for _, ip := range ifaceIPs {
		if ip.IP.To4() == nil {
			klog.InfoS("Interface has IPv6 address, ensuring that IPv6 is enabled on bridge local port", "port", ifaceName)
			if err := EnsureIPv6EnabledOnInterface(ifaceName); err != nil {
				klog.ErrorS(err, "Failed to ensure that IPv6 is enabled on bridge local port, moving uplink IPs to bridge is likely to fail", "port", ifaceName)
			}
			break
		}
	}

	if err = ConfigureLinkAddresses(localLink.Attrs().Index, ifaceIPs); err != nil {
		return "", false, err
	}
	if err = ConfigureLinkAddresses(iface.Index, nil); err != nil {
		return "", false, err
	}
	// Restore the host routes which are lost when moving the network configuration of the
	// host interface to OVS bridge interface.
	if err = ConfigureLinkRoutes(localLink, ifaceRoutes); err != nil {
		return "", false, err
	}
	return bridgedName, false, nil
}

// RestoreHostInterfaceConfiguration restore the configuration from bridge back to host interface, reverting the
// actions taken in PrepareHostInterfaceConnection.
func RestoreHostInterfaceConfiguration(brName string, interfaceName string) {
	klog.V(4).InfoS("Restoring bridge config to host interface")
	bridgedName := GenerateUplinkInterfaceName(interfaceName)
	// restore only when interface eth0~ exists
	if !HostInterfaceExists(bridgedName) {
		return
	}

	// get interface config
	var err error
	var interfaceIPs []*net.IPNet
	var interfaceRoutes []interface{}
	if HostInterfaceExists(interfaceName) {
		_, interfaceIPs, interfaceRoutes, err = GetInterfaceConfig(interfaceName)
		if err != nil {
			klog.ErrorS(err, "Failed to get interface config", "interface", interfaceName)
		}

		// delete internal port (eth0)
		if err = deleteOVSPort(brName, interfaceName); err != nil {
			klog.ErrorS(err, "Delete OVS port failed", "port", bridgedName)
		}
	}
	// remove host interface (eth0~) from bridge
	if err = deleteOVSPort(brName, bridgedName); err != nil {
		klog.ErrorS(err, "Delete OVS port failed", "port", bridgedName)
		return
	}

	// rename host interface(eth0~ -> eth0)
	if err = RenameInterface(bridgedName, interfaceName); err != nil {
		klog.ErrorS(err, "Restore host interface name failed", "from", bridgedName, "to", interfaceName)
		return
	}
	var link netlink.Link
	if link, err = netlink.LinkByName(interfaceName); err != nil {
		klog.ErrorS(err, "Failed to get link", "interface", interfaceName)
		return
	}
	if len(interfaceIPs) > 0 {
		// restore IPs to eth0
		if err = ConfigureLinkAddresses(link.Attrs().Index, interfaceIPs); err != nil {
			klog.ErrorS(err, "Restore IPs to host interface failed", "interface", interfaceName)
			return
		}
	}
	if len(interfaceRoutes) > 0 {
		// restore routes to eth0
		if err = ConfigureLinkRoutes(link, interfaceRoutes); err != nil {
			klog.ErrorS(err, "Restore routes to host interface failed", "interface", interfaceName)
			return
		}
	}
	klog.V(2).InfoS("Finished restoring bridge config to host interface", "interface", interfaceName, "bridge", brName)
}
