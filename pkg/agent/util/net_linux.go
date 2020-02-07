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

// +build linux

package util

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog"
)

// GetIPNetDeviceFromIP returns a local IP/mask and associated device from IP.
func GetIPNetDeviceFromIP(localIP net.IP) (*net.IPNet, netlink.Link, error) {
	linkList, err := netlink.LinkList()
	if err != nil {
		return nil, nil, err
	}

	for _, link := range linkList {
		addrList, err := netlink.AddrList(link, unix.AF_INET)
		if err != nil {
			klog.Errorf("Failed to get addr list for device %s", link)
			continue
		}
		for _, addr := range addrList {
			if addr.IP.Equal(localIP) {
				return addr.IPNet, link, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("unable to find local IP and device")
}

func SetLinkUp(name string) (net.HardwareAddr, int, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil, 0, newLinkNoteFoundError(name)
		} else {
			return nil, 0, err
		}
	}
	// Set host gateway interface up.
	if err := netlink.LinkSetUp(link); err != nil {
		klog.Errorf("Failed to set host link for %s up: %v", name, err)
		return nil, 0, err
	}
	mac := link.Attrs().HardwareAddr
	index := link.Attrs().Index
	return mac, index, nil
}

func ConfigureLinkAddress(idx int, gwIPNet *net.IPNet) error {
	// No need to check the error here, since the link is found in previous steps.
	link, _ := netlink.LinkByIndex(idx)
	gwAddr := &netlink.Addr{IPNet: gwIPNet, Label: ""}

	if addrs, err := netlink.AddrList(link, netlink.FAMILY_V4); err != nil {
		klog.Errorf("Failed to query IPv4 address list for interface %s: %v", link.Attrs().Name, err)
		return err
	} else if addrs != nil {
		for _, addr := range addrs {
			klog.V(4).Infof("Found IPv4 address %s for interface %s", addr.IP.String(), link.Attrs().Name)
			if addr.IP.Equal(gwAddr.IPNet.IP) {
				klog.V(2).Infof("IPv4 address %s already assigned to interface %s", addr.IP.String(), link.Attrs().Name)
				return nil
			}
		}
	}

	klog.V(2).Infof("Adding address %v to gateway interface %s", gwAddr, link.Attrs().Name)
	if err := netlink.AddrAdd(link, gwAddr); err != nil {
		klog.Errorf("Failed to set gateway interface %s with address %v: %v", link.Attrs().Name, gwAddr, err)
		return err
	}
	return nil
}
