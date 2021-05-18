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

package egress

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/util/arping"
)

type nodeEgressAssigner struct {
	nodeConfig *config.NodeConfig
}

func NewNodeEgressIPAssigner(c *config.NodeConfig) *nodeEgressAssigner {
	return &nodeEgressAssigner{
		c,
	}
}

func (a *nodeEgressAssigner) AssignOwnerNodeEgressIP(egressIp string) error {
	return assignOwnerNodeEgressIP(egressIp, a.nodeConfig)
}

func (a *nodeEgressAssigner) UnAssignOwnerNodeEgressIP(egressIp string) error {
	return unAssignOwnerNodeEgressIP(egressIp, a.nodeConfig)
}

func assignOwnerNodeEgressIP(egressIP string, nodeConfig *config.NodeConfig) error {
	addr, link, err := getNodeLinkAddr(egressIP, nodeConfig.NodeIPAddr.IP)
	if err != nil {
		return err
	}
	if err := assignEgressIP(addr, link); err != nil {
		return err
	}
	return nil
}

func unAssignOwnerNodeEgressIP(egressIP string, nodeConfig *config.NodeConfig) error {
	addr, link, err := getNodeLinkAddr(egressIP, nodeConfig.NodeIPAddr.IP)
	if err != nil {
		return err
	}
	if err := unassignEgressIP(addr, link); err != nil {
		return err
	}
	return nil
}

func getNodeLinkAddr(egressIP string, nodeIPAddr net.IP) (*netlink.Addr, netlink.Link, error) {
	egressSpecIP := net.ParseIP(egressIP)
	localAddr, localIntf, err := util.GetIPNetDeviceFromIP(nodeIPAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("get IPNetDevice from ip %v error: %+v", nodeIPAddr, err)
	}
	link, err := netlink.LinkByName(localIntf.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("get netlink by name(%s) error: %+v", localIntf.Name, err)
	}
	addr := netlink.Addr{IPNet: &net.IPNet{IP: egressSpecIP, Mask: localAddr.Mask}}

	klog.V(2).Infof("get node iface netlink and address: %+v, %+v", link, addr)
	return &addr, link, nil
}

func assignEgressIP(addr *netlink.Addr, link netlink.Link) error {
	//	assign IP
	ifaceName := link.Attrs().Name
	ifaceH, _ := net.InterfaceByName(ifaceName)
	klog.V(2).Infof("Adding address %+v to interface %s", addr, ifaceName)
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add address %v to interface %s: %v", addr, ifaceName, err)
	}
	egressSpecIP := addr.IP
	isIPv4 := egressSpecIP.To4()
	if isIPv4 != nil {
		if err := arping.GratuitousARPOverIface(isIPv4, ifaceH); err != nil {
			klog.Warningf("Failed to send gratuitous ARP: %v", err)
			return err
		}
		klog.Infof("Send gratuitous ARP: %+v", isIPv4)
	} else if isIPv6 := egressSpecIP.To16(); isIPv6 != nil {
		err := errors.New("IPv6 not support")
		klog.Warningf("Failed to send Advertisement: %v", err)
		return err
	}
	return nil
}

func unassignEgressIP(addr *netlink.Addr, link netlink.Link) error {
	//	 check ip, if existed, uninstall ip
	ifaceName := link.Attrs().Name
	klog.V(2).Infof("Deleting address %v to interface %s", addr, ifaceName)
	if err := netlink.AddrDel(link, addr); err != nil {
		return fmt.Errorf("failed to delete address %v to interface %s: %v", addr, ifaceName, err)
	}
	return nil
}
