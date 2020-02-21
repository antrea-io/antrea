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

// +build linux darwin

package util

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
	"k8s.io/klog"

	"github.com/vishvananda/netlink"
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
