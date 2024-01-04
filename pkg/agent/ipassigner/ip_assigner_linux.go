// Copyright 2021 Antrea Authors
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

package ipassigner

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/pkg/agent/ipassigner/responder"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/util/arping"
	"antrea.io/antrea/pkg/agent/util/ndp"
	"antrea.io/antrea/pkg/agent/util/sysctl"
	crdv1b1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

// VLAN interfaces created by antrea-agent will be named with the prefix.
// For example, when VLAN ID is 10, the name will be antrea-ext.10.
// It can be used to determine whether it's safe to delete an interface when it's no longer used.
const vlanInterfacePrefix = "antrea-ext."

// assignee is the unit that IPs are assigned to. All IPs from the same VLAN share an assignee.
type assignee struct {
	// logicalInterface is the interface IPs should be logically assigned to. It's also used for IP advertisement.
	// The field must not be nil.
	logicalInterface *net.Interface
	// link is used for IP link management and IP address add/del operation. The field can be nil if IPs don't need to
	// be assigned to an interface physically.
	link netlink.Link
	// arpResponder is used for ARP responder for IPv4 address. The field should be nil if the interface can respond to
	// ARP queries itself.
	arpResponder responder.Responder
	// ndpResponder is used for NDP responder for IPv6 address. The field should be nil if the interface can respond to
	// NDP queries itself.
	ndpResponder responder.Responder
	// ips tracks IPs that have been assigned to this assignee.
	ips sets.Set[string]
}

// deletable returns whether this assignee can be safely deleted.
func (as *assignee) deletable() bool {
	if as.ips.Len() > 0 {
		return false
	}
	// It never has a real link.
	if as.link == nil {
		return false
	}
	// Do not delete non VLAN interfaces.
	if _, ok := as.link.(*netlink.Vlan); !ok {
		return false
	}
	// Do not delete VLAN interfaces not created by antrea-agent.
	if !strings.HasPrefix(as.link.Attrs().Name, vlanInterfacePrefix) {
		return false
	}
	return true
}

func (as *assignee) destroy() error {
	if err := netlink.LinkDel(as.link); err != nil {
		return fmt.Errorf("error deleting interface %v: %w", as.link, err)
	}
	return nil
}

func (as *assignee) assign(ip net.IP, subnetInfo *crdv1b1.SubnetInfo) error {
	// If there is a real link, add the IP to its address list.
	if as.link != nil {
		addr := getIPNet(ip, subnetInfo)
		if err := netlink.AddrAdd(as.link, &netlink.Addr{IPNet: addr}); err != nil {
			if !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("failed to add IP %v to interface %s: %v", addr, as.link.Attrs().Name, err)
			} else {
				klog.InfoS("IP was already assigned to interface", "ip", ip, "interface", as.link.Attrs().Name)
			}
		} else {
			klog.InfoS("Assigned IP to interface", "ip", ip, "interface", as.link.Attrs().Name)
		}
	}

	if utilnet.IsIPv4(ip) && as.arpResponder != nil {
		if err := as.arpResponder.AddIP(ip); err != nil {
			return fmt.Errorf("failed to assign IP %v to ARP responder: %v", ip, err)
		}
	}
	if utilnet.IsIPv6(ip) && as.ndpResponder != nil {
		if err := as.ndpResponder.AddIP(ip); err != nil {
			return fmt.Errorf("failed to assign IP %v to NDP responder: %v", ip, err)
		}
	}
	// Always advertise the IP when the IP is newly assigned to this Node.
	as.advertise(ip)
	as.ips.Insert(ip.String())
	return nil
}

func (as *assignee) advertise(ip net.IP) {
	if utilnet.IsIPv4(ip) {
		klog.V(2).InfoS("Sending gratuitous ARP", "ip", ip)
		if err := arping.GratuitousARPOverIface(ip, as.logicalInterface); err != nil {
			klog.ErrorS(err, "Failed to send gratuitous ARP", "ip", ip)
		}
	} else {
		klog.V(2).InfoS("Sending neighbor advertisement", "ip", ip)
		if err := ndp.NeighborAdvertisement(ip, as.logicalInterface); err != nil {
			klog.ErrorS(err, "Failed to send neighbor advertisement", "ip", ip)
		}
	}
}

func (as *assignee) unassign(ip net.IP, subnetInfo *crdv1b1.SubnetInfo) error {
	// If there is a real link, delete the IP from its address list.
	if as.link != nil {
		addr := getIPNet(ip, subnetInfo)
		if err := netlink.AddrDel(as.link, &netlink.Addr{IPNet: addr}); err != nil {
			if !errors.Is(err, unix.EADDRNOTAVAIL) {
				return fmt.Errorf("failed to delete IP %v from interface %s: %v", ip, as.link.Attrs().Name, err)
			} else {
				klog.InfoS("IP does not exist on interface", "ip", ip, "interface", as.link.Attrs().Name)
			}
		}
		klog.InfoS("Deleted IP from interface", "ip", ip, "interface", as.link.Attrs().Name)
	}

	if utilnet.IsIPv4(ip) && as.arpResponder != nil {
		if err := as.arpResponder.RemoveIP(ip); err != nil {
			return fmt.Errorf("failed to remove IP %v from ARP responder: %v", ip, err)
		}
	}
	if utilnet.IsIPv6(ip) && as.ndpResponder != nil {
		if err := as.ndpResponder.RemoveIP(ip); err != nil {
			return fmt.Errorf("failed to remove IP %v from NDP responder: %v", ip, err)
		}
	}
	as.ips.Delete(ip.String())
	return nil
}

func (as *assignee) getVLANID() (int, bool) {
	if as.link == nil {
		return 0, false
	}
	vlan, ok := as.link.(*netlink.Vlan)
	if !ok {
		return 0, false
	}
	return vlan.VlanId, true
}

func (as *assignee) loadIPAddresses() (map[string]*crdv1b1.SubnetInfo, error) {
	assignedIPs := map[string]*crdv1b1.SubnetInfo{}
	addresses, err := netlink.AddrList(as.link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	vlanID, isVLAN := as.getVLANID()
	for _, address := range addresses {
		// Only include global unicast addresses, otherwise addresses like link local ones may be mistakenly deleted.
		if address.IP.IsGlobalUnicast() {
			// subnetInfo should be nil for the dummy interface.
			var subnetInfo *crdv1b1.SubnetInfo
			if isVLAN {
				prefixLength, _ := address.Mask.Size()
				subnetInfo = &crdv1b1.SubnetInfo{
					PrefixLength: int32(prefixLength),
					VLAN:         int32(vlanID),
				}
			}
			assignedIPs[address.IP.String()] = subnetInfo
			as.ips.Insert(address.IP.String())
		}
	}
	return assignedIPs, nil
}

// ipAssigner creates dummy/vlan devices and assigns IPs to them.
// It's supposed to be used in the cases that external IPs should be configured on the system so that they can be used
// for SNAT (egress scenario) or DNAT (ingress scenario).
// By default, a dummy device is used because the IPs just need to be present in any device to be functional, and using
// dummy device avoids touching system managed devices and is easy to know IPs that are assigned by antrea-agent.
// If an IP is associated with a VLAN ID, it will be assigned to a vlan device which is a sub-interface of the external
// device for proper VLAN tagging and untagging.
type ipAssigner struct {
	// externalInterface is the device that GARP (IPv4) and Unsolicited NA (IPv6) will eventually be sent from.
	externalInterface *net.Interface
	// defaultAssignee is the assignee that IPs without VLAN tag will be assigned to.
	defaultAssignee *assignee
	// vlanAssignees contains the vlan-based assignees that IPs with VLAN tag will be assigned to, keyed by VLAN ID.
	vlanAssignees map[int32]*assignee
	// assignIPs caches the IPs that have been assigned.
	// TODO: Add a goroutine to ensure that the cache is in sync with the IPs assigned to the dummy device in case the
	// IPs are removed by users accidentally.
	assignedIPs map[string]*crdv1b1.SubnetInfo
	mutex       sync.RWMutex
}

// NewIPAssigner returns an *ipAssigner.
func NewIPAssigner(nodeTransportInterface string, dummyDeviceName string) (IPAssigner, error) {
	ipv4, ipv6, externalInterface, err := util.GetIPNetDeviceByName(nodeTransportInterface)
	if err != nil {
		return nil, fmt.Errorf("get IPNetDevice from name %s error: %+v", nodeTransportInterface, err)
	}
	a := &ipAssigner{
		externalInterface: externalInterface,
		assignedIPs:       map[string]*crdv1b1.SubnetInfo{},
		defaultAssignee: &assignee{
			logicalInterface: externalInterface,
			ips:              sets.New[string](),
		},
		vlanAssignees: map[int32]*assignee{},
	}
	if ipv4 != nil {
		// For the Egress scenario, the external IPs should always be present on the dummy
		// interface as they are used as tunnel endpoints. If arp_ignore is set to a value
		// other than 0, the host will not reply to ARP requests received on the transport
		// interface when the target IPs are assigned on the dummy interface. So a userspace
		// ARP responder is needed to handle ARP requests for the Egress IPs.
		arpIgnore, err := getARPIgnoreForInterface(externalInterface.Name)
		if err != nil {
			return nil, err
		}
		if dummyDeviceName == "" || arpIgnore > 0 {
			a.defaultAssignee.arpResponder, err = responder.NewARPResponder(externalInterface)
			if err != nil {
				return nil, fmt.Errorf("failed to create ARP responder for link %s: %v", externalInterface.Name, err)
			}
		}
	}
	if ipv6 != nil {
		a.defaultAssignee.ndpResponder, err = responder.NewNDPResponder(externalInterface)
		if err != nil {
			return nil, fmt.Errorf("failed to create NDP responder for link %s: %v", externalInterface.Name, err)
		}
	}
	if dummyDeviceName != "" {
		a.defaultAssignee.link, err = ensureDummyDevice(dummyDeviceName)
		if err != nil {
			return nil, fmt.Errorf("error when ensuring dummy device exists: %v", err)
		}
	}
	vlans, err := getVLANInterfaces(externalInterface.Index)
	if err != nil {
		return nil, fmt.Errorf("error when getting vlan devices: %w", err)
	}
	for _, vlan := range vlans {
		a.addVLANAssignee(vlan, int32(vlan.VlanId))
	}
	return a, nil
}

// getVLANInterfaces returns all VLAN sub-interfaces of the given parent interface.
func getVLANInterfaces(parentIndex int) ([]*netlink.Vlan, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	var vlans []*netlink.Vlan
	for _, link := range links {
		if vlan, ok := link.(*netlink.Vlan); ok && vlan.ParentIndex == parentIndex {
			vlans = append(vlans, vlan)
		}
	}
	return vlans, nil
}

// getARPIgnoreForInterface gets the max value of conf/{all,interface}/arp_ignore form sysctl.
func getARPIgnoreForInterface(iface string) (int, error) {
	arpIgnoreAll, err := sysctl.GetSysctlNet("ipv4/conf/all/arp_ignore")
	if err != nil {
		return 0, fmt.Errorf("failed to get arp_ignore for all interfaces: %w", err)
	}
	arpIgnore, err := sysctl.GetSysctlNet(fmt.Sprintf("ipv4/conf/%s/arp_ignore", iface))
	if err != nil {
		return 0, fmt.Errorf("failed to get arp_ignore for %s: %w", iface, err)
	}
	if arpIgnore > arpIgnoreAll {
		return arpIgnore, nil
	}
	return arpIgnoreAll, nil

}

// ensureDummyDevice creates the dummy device if it doesn't exist.
func ensureDummyDevice(deviceName string) (netlink.Link, error) {
	link, err := netlink.LinkByName(deviceName)
	if err == nil {
		return link, nil
	}
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: deviceName},
	}
	if err = netlink.LinkAdd(dummy); err != nil {
		return nil, err
	}
	return dummy, nil
}

// loadIPAddresses gets the IP addresses on the default device and the vlan devices.
func (a *ipAssigner) loadIPAddresses() error {
	// Load IPs assigned to the default interface.
	var err error
	a.assignedIPs, err = a.defaultAssignee.loadIPAddresses()
	if err != nil {
		return err
	}
	// Load IPs assigned to the vlan interfaces.
	for _, vlanAssignee := range a.vlanAssignees {
		newAssignedIPs, err := vlanAssignee.loadIPAddresses()
		if err != nil {
			return err
		}
		for k, v := range newAssignedIPs {
			a.assignedIPs[k] = v
		}
	}
	return nil
}

// AssignIP ensures the provided IP is assigned to the system and advertised to its neighbors.
//   - If subnetInfo is nil or the vlan is 0, the IP will be assigned to the default interface, and its advertisement
//     will be sent through the external interface.
//   - Otherwise, the IP will be assigned to a corresponding vlan sub-interface of the external interface, and its
//     advertisement will be sent through the vlan sub-interface (though via the external interface eventually).
func (a *ipAssigner) AssignIP(ip string, subnetInfo *crdv1b1.SubnetInfo, forceAdvertise bool) (bool, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, fmt.Errorf("invalid IP %s", ip)
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()

	as, err := a.getAssignee(subnetInfo, true)
	if err != nil {
		return false, err
	}

	oldSubnetInfo, exists := a.assignedIPs[ip]
	if exists {
		// ipAssigner doesn't care about the gateway.
		if crdv1b1.CompareSubnetInfo(subnetInfo, oldSubnetInfo, true) {
			klog.V(2).InfoS("The IP is already assigned", "ip", ip)
			if forceAdvertise {
				as.advertise(parsedIP)
			}
			return false, nil
		}
		if err := a.unassign(parsedIP, oldSubnetInfo); err != nil {
			return false, err
		}
	}

	if err := as.assign(parsedIP, subnetInfo); err != nil {
		return false, err
	}
	a.assignedIPs[ip] = subnetInfo
	return true, nil
}

// UnassignIP ensures the provided IP is not assigned to the dummy/vlan device.
func (a *ipAssigner) UnassignIP(ip string) (bool, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, fmt.Errorf("invalid IP %s", ip)
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()

	subnetInfo, exists := a.assignedIPs[ip]
	if !exists {
		klog.V(2).InfoS("The IP is not assigned", "ip", ip)
		return false, nil
	}
	if err := a.unassign(parsedIP, subnetInfo); err != nil {
		return false, err
	}
	return true, nil
}

func (a *ipAssigner) unassign(ip net.IP, subnetInfo *crdv1b1.SubnetInfo) error {
	as, _ := a.getAssignee(subnetInfo, false)
	// The assignee doesn't exist, meaning the IP has been unassigned previously.
	if as == nil {
		return nil
	}
	if err := as.unassign(ip, subnetInfo); err != nil {
		return err
	}
	if as.deletable() {
		klog.InfoS("Deleting VLAN sub-interface", "interface", as.logicalInterface.Name, "vlan", subnetInfo.VLAN)
		if err := as.destroy(); err != nil {
			return err
		}
		delete(a.vlanAssignees, subnetInfo.VLAN)
	}
	delete(a.assignedIPs, ip.String())
	return nil
}

// AssignedIPs return the IPs that are assigned to the dummy device.
func (a *ipAssigner) AssignedIPs() map[string]*crdv1b1.SubnetInfo {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	// Return a copy.
	copy := map[string]*crdv1b1.SubnetInfo{}
	for k, v := range a.assignedIPs {
		copy[k] = v
	}
	return copy
}

// InitIPs loads the IPs from the dummy/vlan devices and replaces the IPs that are assigned to it
// with the given ones. This function also adds the given IPs to the ARP/NDP responder if
// applicable. It can be used to recover the IP assigner to the desired state after Agent restarts.
// It's not thread-safe and should only be called once for initialization before calling other methods.
func (a *ipAssigner) InitIPs(desired map[string]*crdv1b1.SubnetInfo) error {
	if err := a.loadIPAddresses(); err != nil {
		return fmt.Errorf("error when loading IP addresses from the system: %v", err)
	}
	staleIPs := sets.StringKeySet(a.assignedIPs)
	for ip, desiredSubnetInfo := range desired {
		if _, err := a.AssignIP(ip, desiredSubnetInfo, true); err != nil {
			return err
		}
		staleIPs.Delete(ip)
	}
	for ip := range staleIPs {
		if _, err := a.UnassignIP(ip); err != nil {
			return err
		}
	}
	return nil
}

func (a *ipAssigner) GetInterfaceID(subnetInfo *crdv1b1.SubnetInfo) (int, bool) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	as, _ := a.getAssignee(subnetInfo, false)
	// The assignee doesn't exist, meaning the IP has been unassigned previously.
	if as == nil {
		return 0, false
	}
	return as.logicalInterface.Index, true
}

// Run starts the ARP responder and NDP responder.
func (a *ipAssigner) Run(ch <-chan struct{}) {
	if a.defaultAssignee.arpResponder != nil {
		go a.defaultAssignee.arpResponder.Run(ch)
	}
	if a.defaultAssignee.ndpResponder != nil {
		go a.defaultAssignee.ndpResponder.Run(ch)
	}
	<-ch
}

// getAssignee gets or creates the vlan device for the subnet if it doesn't exist.
func (a *ipAssigner) getAssignee(subnetInfo *crdv1b1.SubnetInfo, createIfNotExist bool) (*assignee, error) {
	// Use the default assignee if subnet info is nil or the vlan is not set.
	if subnetInfo == nil || subnetInfo.VLAN == 0 {
		return a.defaultAssignee, nil
	}
	if as, exists := a.vlanAssignees[subnetInfo.VLAN]; exists {
		return as, nil
	}
	if !createIfNotExist {
		return nil, nil
	}

	name := fmt.Sprintf("%s%d", vlanInterfacePrefix, subnetInfo.VLAN)
	klog.InfoS("Creating VLAN sub-interface", "interface", name, "parent", a.externalInterface.Name, "vlan", subnetInfo.VLAN)
	vlan := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        name,
			ParentIndex: a.externalInterface.Index,
		},
		VlanId: int(subnetInfo.VLAN),
	}
	if err := netlink.LinkAdd(vlan); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("error creating VLAN sub-interface for VLAN %d", subnetInfo.VLAN)
		}
	}
	// Loose mode is needed because incoming traffic received on the interface is expected to be received on the parent
	// external interface when looking up the main table. To make it look up the custom table, we will need to restore
	// the mark on the reply traffic and turn on src_valid_mark on this interface, which is more complicated.
	if err := util.EnsureRPFilterOnInterface(name, 2); err != nil {
		return nil, err
	}
	as, err := a.addVLANAssignee(vlan, subnetInfo.VLAN)
	if err != nil {
		return nil, err
	}
	return as, nil
}

func (a *ipAssigner) addVLANAssignee(link netlink.Link, vlan int32) (*assignee, error) {
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("error setting up interface %v", link)
	}
	iface, err := net.InterfaceByName(link.Attrs().Name)
	if err != nil {
		return nil, err
	}
	// VLAN interface can answer ARP/NDP directly, no need to create userspace responders.
	as := &assignee{
		logicalInterface: iface,
		link:             link,
		ips:              sets.New[string](),
	}
	a.vlanAssignees[vlan] = as
	return as, nil
}

func getIPNet(ip net.IP, subnetInfo *crdv1b1.SubnetInfo) *net.IPNet {
	ones, bits := 32, 32
	if ip.To4() == nil {
		ones, bits = 128, 128
	}
	if subnetInfo != nil {
		ones = int(subnetInfo.PrefixLength)
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(ones, bits)}
}
