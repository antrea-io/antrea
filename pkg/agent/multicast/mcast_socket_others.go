//go:build !linux
// +build !linux

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
	"net"
)

const (
	IGMPMsgNocache = 0
	MaxVIFs        = 0
	MaxMIFs        = 0
	SizeofIgmpmsg  = 0
)

func (s *Socket) AddMrouteEntry(src net.IP, group net.IP, iif uint16, oifVIFs []uint16) (err error) {
	return nil
}

func (s *Socket) DelMrouteEntry(src net.IP, group net.IP, iif uint16) (err error) {
	return nil
}

func (s *Socket) FlushMRoute() {
}

func CreateMulticastSocket() (*Socket, error) {
	return nil, nil
}

func (s *Socket) AllocateVIFs(interfaceNames []string, startVIF uint16, startMIF uint16) ([]uint16, []uint16, error) {
	return nil, nil, nil
}

func (s *Socket) MulticastInterfaceJoinMgroup(mgroup net.IP, ifIndex uint32, ifaceName string) error {
	return nil
}

func (s *Socket) MulticastInterfaceLeaveMgroup(mgroup net.IP, ifIndex uint32, ifaceName string) error {
	return nil
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
