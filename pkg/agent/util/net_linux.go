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
)

var (
	// netlinkUtil is introduced for testing.
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

// DeleteOVSPort deletes specific OVS port. This function calls ovs-vsctl command to bypass OVS bridge client to work when agent exiting.
func DeleteOVSPort(brName, portName string) error {
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
	addrs, err := GetIPNetsByLink(iface)
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
