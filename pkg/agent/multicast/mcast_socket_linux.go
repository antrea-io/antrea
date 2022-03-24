//go:build linux && (arm || arm64 || amd64)
// +build linux
// +build arm arm64 amd64

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

package multicast

import (
	"fmt"
	"net"
	"syscall"

	"k8s.io/klog/v2"

	multicastsyscall "antrea.io/antrea/pkg/agent/util/syscall"
)

const (
	IGMPMsgNocache = multicastsyscall.IGMPMSG_NOCACHE
	MaxVIFs        = multicastsyscall.MAXVIFS
	MaxMIFs        = multicastsyscall.MAXMIFS
	SizeofIgmpmsg  = multicastsyscall.SizeofIgmpmsg
	SizeofMrt6msg  = multicastsyscall.SizeofMrt6msg
)

// setVIFToInterface adds a virtual interface to the multicast socket for interface with index ifIndex.
func setVIFToInterface(fd int, vif uint16, ifIndex int) error {
	vc := &multicastsyscall.Vifctl{}
	vc.Vifi = vif
	vc.Rate_limit = 0
	vc.Flags = 0
	vc.Flags |= multicastsyscall.VIFF_USE_IFINDEX
	vc.Lcl_ifindex = int32(ifIndex)
	return multicastsyscall.SetsockoptVifctl(fd, syscall.IPPROTO_IP, multicastsyscall.MRT_ADD_VIF, vc)
}

// setVIFToInterface adds a virtual interface to the multicast socket for interface with index ifIndex.
func setMIFToInterface(fd int, vif uint16, ifIndex int) error {
	vc := &multicastsyscall.Mif6ctl{}
	vc.Mif6c_mifi = vif
	vc.Mif6c_flags = 0
	vc.Mif6c_pifi = uint16(ifIndex)
	return multicastsyscall.SetsockoptMif6ctl(fd, syscall.IPPROTO_IPV6, multicastsyscall.MRT6_ADD_VIF, vc)
}

func (s *Socket) AddMrouteEntry(src net.IP, group net.IP, iif uint16, oifVIFs []uint16) (err error) {
	if group.To4() != nil {
		return s.addIPv4MrouteEntry(src, group, iif, oifVIFs)
	}
	return s.addIPv6MrouteEntry(src, group, iif, oifVIFs)
}

func (s *Socket) addIPv4MrouteEntry(src net.IP, group net.IP, iif uint16, oifVIFs []uint16) (err error) {
	mc := &multicastsyscall.Mfcctl{}
	origin := src.To4()
	mc.Origin = [4]byte{origin[0], origin[1], origin[2], origin[3]}
	g := group.To4()
	mc.Mcastgrp = [4]byte{g[0], g[1], g[2], g[3]}
	ttls := [32]byte{}
	for _, v := range oifVIFs {
		ttls[v] = 1
	}
	mc.Ttls = ttls
	mc.Parent = iif
	return multicastsyscall.SetsockoptMfcctl(s.GetIPv4FD(), syscall.IPPROTO_IP, multicastsyscall.MRT_ADD_MFC, mc)
}

func (s *Socket) addIPv6MrouteEntry(src net.IP, group net.IP, iif uint16, oifVIFs []uint16) (err error) {
	mc := &multicastsyscall.Mf6cctl{}
	var origin [16]byte
	copy(origin[:], src.To16())
	mc.Origin = multicastsyscall.RawSockaddrInet6{
		Family: syscall.AF_INET6,
		Addr:   origin,
	}
	var addr [16]byte
	copy(addr[:], group.To16())
	mc.Mcastgrp = multicastsyscall.RawSockaddrInet6{
		Family: syscall.AF_INET6,
		Addr:   addr,
	}
	var bits [8]uint32
	for _, mif := range oifVIFs {
		bits[mif/8] += (1 << (mif % 8))
	}
	mc.Ifset = multicastsyscall.IfSet{
		Bits: bits,
	}
	mc.Parent = iif
	return multicastsyscall.SetsockoptMf6cctl(s.GetIPv6FD(), syscall.IPPROTO_IPV6, multicastsyscall.MRT6_ADD_MFC, mc)
}

func (s *Socket) delIPv4MrouteEntry(src net.IP, group net.IP, iif uint16) (err error) {
	mc := &multicastsyscall.Mfcctl{}
	origin := src.To4()
	mc.Origin = [4]byte{origin[0], origin[1], origin[2], origin[3]}
	g := group.To4()
	mc.Mcastgrp = [4]byte{g[0], g[1], g[2], g[3]}
	mc.Parent = iif
	return multicastsyscall.SetsockoptMfcctl(s.IPv4SockFD, syscall.IPPROTO_IP, multicastsyscall.MRT_DEL_MFC, mc)
}

func (s *Socket) delIPv6MrouteEntry(src net.IP, group net.IP, iif uint16) (err error) {
	mc := &multicastsyscall.Mf6cctl{}
	var origin [16]byte
	copy(origin[:], src.To16())
	mc.Origin = multicastsyscall.RawSockaddrInet6{
		Family: syscall.AF_INET6,
		Addr:   origin,
	}
	var arr [16]byte
	copy(arr[:], group.To16())
	mc.Mcastgrp = multicastsyscall.RawSockaddrInet6{
		Family: syscall.AF_INET6,
		Addr:   arr,
	}
	mc.Parent = iif
	return multicastsyscall.SetsockoptMf6cctl(s.IPv6SockFD, syscall.IPPROTO_IPV6, multicastsyscall.MRT6_DEL_MFC, mc)
}

func (s *Socket) DelMrouteEntry(src net.IP, group net.IP, iif uint16) (err error) {
	if group.To4() != nil {
		return s.delIPv4MrouteEntry(src, group, iif)
	}
	return s.delIPv6MrouteEntry(src, group, iif)
}

func (s *Socket) FlushMRoute() {
	klog.InfoS("Clearing multicast routing table entries")
	err := multicastsyscall.SetsockoptVifctl(s.IPv4SockFD, syscall.IPPROTO_IP, multicastsyscall.MRT_FLUSH, &multicastsyscall.Vifctl{})
	if err != nil {
		klog.ErrorS(err, "Failed to clear IPv4 multicast routing table entries")
	}
	err = multicastsyscall.SetsockoptMif6ctl(s.IPv6SockFD, syscall.IPPROTO_IPV6, multicastsyscall.MRT6_FLUSH, &multicastsyscall.Mif6ctl{})
	if err != nil {
		klog.ErrorS(err, "Failed to clear IPv6 multicast routing table entries")
	}
}

func CreateMulticastSocket() (*Socket, error) {
	IPv4FD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IGMP)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPv4 multicast socket")
	}
	err = syscall.SetsockoptInt(IPv4FD, syscall.IPPROTO_IP, multicastsyscall.MRT_INIT, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to activate IPv4 Multicast routing in kernel: %s", err.Error())
	}
	IPv6FD, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPv6 multicast socket")
	}
	err = syscall.SetsockoptInt(IPv6FD, syscall.IPPROTO_IPV6, multicastsyscall.MRT6_INIT, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to activate IPv6 Multicast routing in kernel: %s", err.Error())
	}
	return &Socket{IPv4SockFD: IPv4FD, IPv6SockFD: IPv6FD}, nil
}

func (s *Socket) AllocateVIFs(interfaceNames []string, startVIF uint16, startMIF uint16) ([]uint16, []uint16, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	vif := startVIF
	mif := startMIF
	vifs := make([]uint16, 0, len(interfaceNames))
	mifs := make([]uint16, 0, len(interfaceNames))
	for _, name := range interfaceNames {
		found := false
		for _, iface := range ifaces {
			if iface.Name == name {
				found = true
				addrs, err := iface.Addrs()
				if err != nil {
					return nil, nil, err
				}
				hasIPv4 := false
				hasIPv6 := false
				for _, addr := range addrs {
					if ipNet, ok := addr.(*net.IPNet); ok {
						if ipNet.IP.To4() != nil {
							hasIPv4 = true
						} else if ipNet.IP.To16() != nil {
							hasIPv6 = true
						}
					}
				}
				if hasIPv4 {
					if vif >= MaxVIFs {
						return nil, nil, fmt.Errorf("VIF reaches MAXVIFS. Failed to allocate available VIF")
					}
					err = setVIFToInterface(s.IPv4SockFD, vif, iface.Index)
					klog.V(2).InfoS("Successfully allocated VIF", "VIF", vif)
					if err != nil {
						return nil, nil, err
					}
					vifs = append(vifs, vif)
					vif += 1
				}
				if hasIPv6 {
					if mif >= MaxMIFs {
						return nil, nil, fmt.Errorf("MIF reaches MAXMIFS. Failed to allocate available MIF")
					}
					err = setMIFToInterface(s.IPv6SockFD, mif, iface.Index)
					klog.V(2).InfoS("Successfully allocated MIF", "MIF", mif)
					if err != nil {
						return nil, nil, err
					}
					mifs = append(mifs, mif)
					mif += 1
				}
				break
			}
		}
		if !found {
			return nil, nil, fmt.Errorf("error finding interface %s to multicast VIF", name)
		}

	}
	return vifs, mifs, nil
}

func (s *Socket) multicastInterfaceJoinIPv4Mgroup(mgroup net.IP, ifIndex uint32, ifaceName string) error {
	err := syscall.SetsockoptIPMreqn(s.IPv4SockFD, syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, &syscall.IPMreqn{
		Multiaddr: [4]byte{mgroup[0], mgroup[1], mgroup[2], mgroup[3]},
		Ifindex:   int32(ifIndex),
	})
	if err != nil {
		return fmt.Errorf("failed to join multicast group %s for %s: %s", mgroup.String(), ifaceName, err.Error())
	}
	return nil
}

func (s *Socket) multicastInterfaceJoinIPv6Mgroup(mgroup net.IP, ifIndex uint32, ifaceName string) error {
	var arr [16]byte
	copy(arr[:], mgroup.To16())
	err := syscall.SetsockoptIPv6Mreq(s.IPv6SockFD, syscall.IPPROTO_IPV6, syscall.IPV6_ADD_MEMBERSHIP, &syscall.IPv6Mreq{
		Multiaddr: arr,
		Interface: ifIndex,
	})
	if err != nil {
		return fmt.Errorf("failed to join multicast group %s for %s: %s", mgroup.String(), ifaceName, err.Error())
	}
	return nil
}

func (s *Socket) MulticastInterfaceJoinMgroup(mgroup net.IP, ifIndex uint32, ifaceName string) error {
	group := mgroup.To4()
	if group != nil {
		return s.multicastInterfaceJoinIPv4Mgroup(group, ifIndex, ifaceName)
	}
	return s.multicastInterfaceJoinIPv6Mgroup(mgroup, ifIndex, ifaceName)
}

func (s *Socket) multicastInterfaceLeaveIPv4Mgroup(mgroup net.IP, ifIndex uint32, ifaceName string) error {
	err := syscall.SetsockoptIPMreqn(s.IPv4SockFD, syscall.IPPROTO_IP, syscall.IP_DROP_MEMBERSHIP, &syscall.IPMreqn{
		Multiaddr: [4]byte{mgroup[0], mgroup[1], mgroup[2], mgroup[3]},
		Ifindex:   int32(ifIndex),
	})
	if err != nil {
		return fmt.Errorf("failed to leave multicast group %s for %s: %s", mgroup.String(), ifaceName, err.Error())
	}
	return nil
}

func (s *Socket) multicastInterfaceLeaveIPv6Mgroup(mgroup net.IP, ifIndex uint32, ifaceName string) error {
	var arr [16]byte
	copy(arr[:], mgroup.To16())
	err := syscall.SetsockoptIPv6Mreq(s.IPv6SockFD, syscall.IPPROTO_IPV6, syscall.IPV6_DROP_MEMBERSHIP, &syscall.IPv6Mreq{
		Multiaddr: arr,
		Interface: ifIndex,
	})
	if err != nil {
		return fmt.Errorf("failed to leave multicast group %s for %s: %s", mgroup.String(), ifaceName, err.Error())
	}
	return nil
}

func (s *Socket) MulticastInterfaceLeaveMgroup(mgroup net.IP, ifIndex uint32, ifaceName string) error {
	group := mgroup.To4()
	if group != nil {
		s.multicastInterfaceLeaveIPv4Mgroup(mgroup, ifIndex, ifaceName)
	}
	return s.multicastInterfaceLeaveIPv6Mgroup(mgroup, ifIndex, ifaceName)
}

func (s *Socket) GetIPv4FD() int {
	return s.IPv4SockFD
}

func (s *Socket) GetIPv6FD() int {
	return s.IPv6SockFD
}

type Socket struct {
	IPv4SockFD int
	IPv6SockFD int
}
