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
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/util/arping"
)

var ipv6NotSupportErr = errors.New("IPv6 not supported")

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
	assignedIPs sets.String
	mutex       sync.RWMutex
}

// NewIPAssigner returns an *ipAssigner.
func NewIPAssigner(nodeIPAddr net.IP, dummyDeviceName string) (*ipAssigner, error) {
	_, egressInterface, err := util.GetIPNetDeviceFromIP(nodeIPAddr)
	if err != nil {
		return nil, fmt.Errorf("get IPNetDevice from ip %v error: %+v", nodeIPAddr, err)
	}

	dummyDevice, err := ensureDummyDevice(dummyDeviceName)
	if err != nil {
		return nil, fmt.Errorf("error when ensuring dummy device exist: %v", err)
	}

	a := &ipAssigner{
		externalInterface: egressInterface,
		dummyDevice:       dummyDevice,
		assignedIPs:       sets.NewString(),
	}
	if err := a.loadIPAddresses(); err != nil {
		return nil, fmt.Errorf("error when loading IP addresses from the system: %v", err)
	}
	return a, nil
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
func (a *ipAssigner) loadIPAddresses() error {
	addresses, err := netlink.AddrList(a.dummyDevice, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	newAssignIPs := sets.NewString()
	for _, address := range addresses {
		newAssignIPs.Insert(address.IP.String())
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.assignedIPs = newAssignIPs
	return nil
}

// AssignIP ensures the provided IP is assigned to the dummy device.
func (a *ipAssigner) AssignIP(ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP %s", ip)
	}

	if err := func() error {
		a.mutex.Lock()
		defer a.mutex.Unlock()

		if a.assignedIPs.Has(ip) {
			klog.V(2).InfoS("The IP is already assigned", "ip", ip)
			return nil
		}

		addr := netlink.Addr{IPNet: &net.IPNet{IP: parsedIP, Mask: net.CIDRMask(32, 32)}}
		if err := netlink.AddrAdd(a.dummyDevice, &addr); err != nil {
			return fmt.Errorf("failed to add IP %v to interface %s: %v", ip, a.dummyDevice.Attrs().Name, err)
		}
		klog.InfoS("Assigned IP to interface", "ip", parsedIP, "interface", a.dummyDevice.Attrs().Name)

		a.assignedIPs.Insert(ip)
		return nil
	}(); err != nil {
		return err
	}

	isIPv4 := parsedIP.To4()
	if isIPv4 != nil {
		if err := arping.GratuitousARPOverIface(isIPv4, a.externalInterface); err != nil {
			return fmt.Errorf("failed to send gratuitous ARP: %v", err)
		}
		klog.V(2).InfoS("Sent gratuitous ARP", "ip", parsedIP)
	} else {
		klog.ErrorS(ipv6NotSupportErr, "Failed to send Advertisement", "ip", parsedIP)
	}
	return nil
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

	addr := netlink.Addr{IPNet: &net.IPNet{IP: parsedIP, Mask: net.CIDRMask(32, 32)}}
	if err := netlink.AddrDel(a.dummyDevice, &addr); err != nil {
		return fmt.Errorf("failed to delete IP %v from interface %s: %v", ip, a.dummyDevice.Attrs().Name, err)
	}
	klog.InfoS("Deleted IP from interface", "ip", ip, "interface", a.dummyDevice.Attrs().Name)

	a.assignedIPs.Delete(ip)
	return nil
}

// AssignedIPs return the IPs that are assigned to the dummy device.
func (a *ipAssigner) AssignedIPs() sets.String {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	// Return a copy.
	return a.assignedIPs.Union(nil)
}
