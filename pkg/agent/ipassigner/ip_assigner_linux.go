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
)

// ipAssigner creates a dummy device and assigns IPs to it.
// It's supposed to be used in the cases that external IPs should be configured on the system so that they can be used
// for SNAT (egress scenario) or DNAT (ingress scenario). A dummy device is used because the IPs just need to be present
// in any device to be functional, and using dummy device avoids touching system managed devices and is easy to know IPs
// that are assigned by antrea-agent.
type ipAssigner struct {
	// externalInterface is the device that GARP (IPv4) and Unsolicited NA (IPv6) will be sent from.
	externalInterface *net.Interface
	// dummyDevice is the device that IPs will be assigned to.
	dummyDevice netlink.Link
	// assignIPs caches the IPs that are assigned to the dummy device.
	// TODO: Add a goroutine to ensure that the cache is in sync with the IPs assigned to the dummy device in case the
	// IPs are removed by users accidentally.
	assignedIPs  sets.Set[string]
	mutex        sync.RWMutex
	arpResponder responder.Responder
	ndpResponder responder.Responder
}

// NewIPAssigner returns an *ipAssigner.
func NewIPAssigner(nodeTransportInterface string, dummyDeviceName string) (IPAssigner, error) {
	ipv4, ipv6, externalInterface, err := util.GetIPNetDeviceByName(nodeTransportInterface)
	if err != nil {
		return nil, fmt.Errorf("get IPNetDevice from name %s error: %+v", nodeTransportInterface, err)
	}
	a := &ipAssigner{
		externalInterface: externalInterface,
		assignedIPs:       sets.New[string](),
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
			arpResponder, err := responder.NewARPResponder(externalInterface)
			if err != nil {
				return nil, fmt.Errorf("failed to create ARP responder for link %s: %v", externalInterface.Name, err)
			}
			a.arpResponder = arpResponder
		}
	}
	if ipv6 != nil {
		ndpResponder, err := responder.NewNDPResponder(externalInterface)
		if err != nil {
			return nil, fmt.Errorf("failed to create NDP responder for link %s: %v", externalInterface.Name, err)
		}
		a.ndpResponder = ndpResponder
	}
	if dummyDeviceName != "" {
		dummyDevice, err := ensureDummyDevice(dummyDeviceName)
		if err != nil {
			return nil, fmt.Errorf("error when ensuring dummy device exists: %v", err)
		}
		a.dummyDevice = dummyDevice
	}
	return a, nil
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

// loadIPAddresses gets the IP addresses on the dummy device and caches them in memory.
func (a *ipAssigner) loadIPAddresses() (sets.Set[string], error) {
	addresses, err := netlink.AddrList(a.dummyDevice, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	newAssignIPs := sets.New[string]()
	for _, address := range addresses {
		newAssignIPs.Insert(address.IP.String())
	}
	return newAssignIPs, nil
}

// AssignIP ensures the provided IP is assigned to the dummy device and the ARP/NDP responders.
func (a *ipAssigner) AssignIP(ip string, forceAdvertise bool) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP %s", ip)
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if a.assignedIPs.Has(ip) {
		klog.V(2).InfoS("The IP is already assigned", "ip", ip)
		if forceAdvertise {
			a.advertise(parsedIP)
		}
		return nil
	}

	if a.dummyDevice != nil {
		addr := util.NewIPNet(parsedIP)
		if err := netlink.AddrAdd(a.dummyDevice, &netlink.Addr{IPNet: addr}); err != nil {
			if !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("failed to add IP %v to interface %s: %v", ip, a.dummyDevice.Attrs().Name, err)
			} else {
				klog.InfoS("IP was already assigned to interface", "ip", parsedIP, "interface", a.dummyDevice.Attrs().Name)
			}
		} else {
			klog.InfoS("Assigned IP to interface", "ip", parsedIP, "interface", a.dummyDevice.Attrs().Name)
		}
	}

	if utilnet.IsIPv4(parsedIP) && a.arpResponder != nil {
		if err := a.arpResponder.AddIP(parsedIP); err != nil {
			return fmt.Errorf("failed to assign IP %v to ARP responder: %v", ip, err)
		}
	}
	if utilnet.IsIPv6(parsedIP) && a.ndpResponder != nil {
		if err := a.ndpResponder.AddIP(parsedIP); err != nil {
			return fmt.Errorf("failed to assign IP %v to NDP responder: %v", ip, err)
		}
	}
	// Always advertise the IP when the IP is newly assigned to this Node.
	a.advertise(parsedIP)
	a.assignedIPs.Insert(ip)
	return nil
}

func (a *ipAssigner) advertise(ip net.IP) {
	if utilnet.IsIPv4(ip) {
		klog.V(2).InfoS("Sending gratuitous ARP", "ip", ip)
		if err := arping.GratuitousARPOverIface(ip, a.externalInterface); err != nil {
			klog.ErrorS(err, "Failed to send gratuitous ARP", "ip", ip)
		}
	} else {
		klog.V(2).InfoS("Sending neighbor advertisement", "ip", ip)
		if err := ndp.NeighborAdvertisement(ip, a.externalInterface); err != nil {
			klog.ErrorS(err, "Failed to send neighbor advertisement", "ip", ip)
		}
	}
}

// UnassignIP ensures the provided IP is not assigned to the dummy device.
func (a *ipAssigner) UnassignIP(ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP %s", ip)
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if !a.assignedIPs.Has(ip) {
		klog.V(2).InfoS("The IP is not assigned", "ip", ip)
		return nil
	}

	if a.dummyDevice != nil {
		addr := util.NewIPNet(parsedIP)
		if err := netlink.AddrDel(a.dummyDevice, &netlink.Addr{IPNet: addr}); err != nil {
			if !errors.Is(err, unix.EADDRNOTAVAIL) {
				return fmt.Errorf("failed to delete IP %v from interface %s: %v", ip, a.dummyDevice.Attrs().Name, err)
			} else {
				klog.InfoS("IP does not exist on interface", "ip", parsedIP, "interface", a.dummyDevice.Attrs().Name)
			}
		}
		klog.InfoS("Deleted IP from interface", "ip", ip, "interface", a.dummyDevice.Attrs().Name)
	}

	if utilnet.IsIPv4(parsedIP) && a.arpResponder != nil {
		if err := a.arpResponder.RemoveIP(parsedIP); err != nil {
			return fmt.Errorf("failed to remove IP %v from ARP responder: %v", ip, err)
		}
	}
	if utilnet.IsIPv6(parsedIP) && a.ndpResponder != nil {
		if err := a.ndpResponder.RemoveIP(parsedIP); err != nil {
			return fmt.Errorf("failed to remove IP %v from NDP responder: %v", ip, err)
		}
	}

	a.assignedIPs.Delete(ip)
	return nil
}

// AssignedIPs return the IPs that are assigned to the dummy device.
func (a *ipAssigner) AssignedIPs() sets.Set[string] {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	// Return a copy.
	return a.assignedIPs.Union(nil)
}

// InitIPs loads the IPs from the dummy device and replaces the IPs that are assigned to it
// with the given ones. This function also adds the given IPs to the ARP/NDP responder if
// applicable. It can be used to recover the IP assigner to the desired state after Agent restarts.
func (a *ipAssigner) InitIPs(ips sets.Set[string]) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.dummyDevice != nil {
		assigned, err := a.loadIPAddresses()
		if err != nil {
			return fmt.Errorf("error when loading IP addresses from the system: %v", err)
		}
		for ip := range ips.Difference(assigned) {
			addr := util.NewIPNet(net.ParseIP(ip))
			if err := netlink.AddrAdd(a.dummyDevice, &netlink.Addr{IPNet: addr}); err != nil {
				if !errors.Is(err, unix.EEXIST) {
					return fmt.Errorf("failed to add IP %v to interface %s: %v", ip, a.dummyDevice.Attrs().Name, err)
				}
			}
		}
		for ip := range assigned.Difference(ips) {
			addr := util.NewIPNet(net.ParseIP(ip))
			if err := netlink.AddrDel(a.dummyDevice, &netlink.Addr{IPNet: addr}); err != nil {
				if !errors.Is(err, unix.EADDRNOTAVAIL) {
					return fmt.Errorf("failed to delete IP %v from interface %s: %v", ip, a.dummyDevice.Attrs().Name, err)
				}
			}
		}
	}
	for ipStr := range ips {
		ip := net.ParseIP(ipStr)
		var err error
		if utilnet.IsIPv4(ip) && a.arpResponder != nil {
			err = a.arpResponder.AddIP(ip)
		}
		if utilnet.IsIPv6(ip) && a.ndpResponder != nil {
			err = a.ndpResponder.AddIP(ip)
		}
		if err != nil {
			return err
		}
		a.advertise(ip)
	}
	a.assignedIPs = ips.Union(nil)
	return nil
}

// Run starts the ARP responder and NDP responder.
func (a *ipAssigner) Run(ch <-chan struct{}) {
	if a.arpResponder != nil {
		go a.arpResponder.Run(ch)
	}
	if a.ndpResponder != nil {
		go a.ndpResponder.Run(ch)
	}
	<-ch
}
