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
	SizeofIgmpmsg  = multicastsyscall.SizeofIgmpmsg
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

func (s *Socket) AddMrouteEntry(src net.IP, group net.IP, iif uint16, oifVIFs []uint16) (err error) {
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
	return multicastsyscall.SetsockoptMfcctl(s.GetFD(), syscall.IPPROTO_IP, multicastsyscall.MRT_ADD_MFC, mc)
}

func (s *Socket) DelMrouteEntry(src net.IP, group net.IP, iif uint16) (err error) {
	mc := &multicastsyscall.Mfcctl{}
	origin := src.To4()
	mc.Origin = [4]byte{origin[0], origin[1], origin[2], origin[3]}
	g := group.To4()
	mc.Mcastgrp = [4]byte{g[0], g[1], g[2], g[3]}
	mc.Parent = iif
	return multicastsyscall.SetsockoptMfcctl(s.sockFD, syscall.IPPROTO_IP, multicastsyscall.MRT_DEL_MFC, mc)
}

func (s *Socket) FlushMRoute() {
	klog.InfoS("Clearing multicast routing table entries")
	err := multicastsyscall.SetsockoptVifctl(s.sockFD, syscall.IPPROTO_IP, multicastsyscall.MRT_FLUSH, &multicastsyscall.Vifctl{})
	if err != nil {
		klog.ErrorS(err, "Failed to clear multicast routing table entries")
	}
}

func CreateMulticastSocket() (*Socket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IGMP)
	if err != nil {
		return nil, fmt.Errorf("failed to create multicast socket")
	}

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, multicastsyscall.MRT_INIT, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to activate Multicast routing in kernel: %s", err.Error())
	}

	return &Socket{sockFD: fd}, nil
}

func (s *Socket) AllocateVIFs(interfaceNames []string, startVIF uint16) ([]uint16, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	vif := startVIF
	vifs := make([]uint16, 0, len(interfaceNames))
	for _, name := range interfaceNames {
		found := false
		for _, iface := range ifaces {
			if iface.Name == name {
				found = true
				if vif >= MaxVIFs {
					return nil, fmt.Errorf("VIF reaches MAXVIFS. Failed to allocate available VIF")
				}
				err = setVIFToInterface(s.sockFD, vif, iface.Index)
				if err != nil {
					return nil, err
				}
				vifs = append(vifs, vif)
				vif += 1
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("error finding interface %s to allocate VIF", name)
		}
		klog.V(2).InfoS("Successfully allocated VIF", "VIF", vif)
	}
	return vifs, nil
}

func (s *Socket) MulticastInterfaceJoinMgroup(mgroup net.IP, ifaceIP net.IP, ifaceName string) error {
	err := syscall.SetsockoptIPMreq(s.sockFD, syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, &syscall.IPMreq{
		Multiaddr: [4]byte{mgroup[0], mgroup[1], mgroup[2], mgroup[3]},
		Interface: [4]byte{ifaceIP[0], ifaceIP[1], ifaceIP[2], ifaceIP[3]},
	})
	if err != nil {
		return fmt.Errorf("failed to join multicast group %s for %s: %s", mgroup.String(), ifaceName, err.Error())
	}
	return nil
}

func (s *Socket) MulticastInterfaceLeaveMgroup(mgroup net.IP, ifaceIP net.IP, ifaceName string) error {
	err := syscall.SetsockoptIPMreq(s.sockFD, syscall.IPPROTO_IP, syscall.IP_DROP_MEMBERSHIP, &syscall.IPMreq{
		Multiaddr: [4]byte{mgroup[0], mgroup[1], mgroup[2], mgroup[3]},
		Interface: [4]byte{ifaceIP[0], ifaceIP[1], ifaceIP[2], ifaceIP[3]},
	})
	if err != nil {
		return fmt.Errorf("failed to leave multicast group %s for %s: %s", mgroup.String(), ifaceName, err.Error())
	}
	return nil
}

func (s *Socket) GetFD() int {
	return s.sockFD
}

type Socket struct {
	sockFD int
}
