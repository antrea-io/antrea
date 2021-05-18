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

package ndp

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	utilnet "k8s.io/utils/net"
)

const (
	// Option Length, 8-bit unsigned integer. The length of the option (including the type and length fields) in units of 8 octets.
	// The value 0 is invalid. Nodes MUST silently discard a ND packet that contains an option with length zero.
	// https://datatracker.ietf.org/doc/html/rfc4861
	ndpOptionLen = 1

	// ndpOptionType
	// 	Option Name                             Type
	//
	// Source Link-Layer Address                    1
	// Target Link-Layer Address                    2
	// Prefix Information                           3
	// Redirected Header                            4
	// MTU                                          5
	ndpOptionType = 2

	// Minimum byte length values for each type of valid Message.
	naLen = 20

	// Hop limit is always 255, refer RFC 4861.
	hopLimit = 255
)

// NeighborAdvertisement sends an unsolicited Neighbor Advertisement ICMPv6 multicast packet,
// over interface 'iface' from 'srcIP', announcing a given IPv6 address('srcIP') to all IPv6 nodes as per RFC4861.
func NeighborAdvertisement(srcIP net.IP, iface *net.Interface) error {
	if !utilnet.IsIPv6(srcIP) {
		return fmt.Errorf("invalid IPv6 address: %v", srcIP)
	}

	mb, err := newNDPNeighborAdvertisementMessage(srcIP, iface.HardwareAddr)
	if err != nil {
		return fmt.Errorf("new NDP Neighbor Advertisement Message error: %v", err)
	}

	sockInet6, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		return err
	}
	defer syscall.Close(sockInet6)

	syscall.SetsockoptInt(sockInet6, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_HOPS, hopLimit)

	var r [16]byte
	copy(r[:], net.IPv6linklocalallnodes.To16())
	toSockAddrInet6 := syscall.SockaddrInet6{Addr: r}
	if err := syscall.Sendto(sockInet6, mb, 0, &toSockAddrInet6); err != nil {
		return err
	}
	return nil
}

func newNDPNeighborAdvertisementMessage(targetAddress net.IP, hwa net.HardwareAddr) ([]byte, error) {
	naMsgBytes := make([]byte, naLen)
	naMsgBytes[0] |= 1 << 5
	copy(naMsgBytes[4:], targetAddress)

	if 1+1+len(hwa) != int(ndpOptionLen*8) {
		return nil, fmt.Errorf("hardwareAddr length error: %s", hwa)
	}
	optionsBytes := make([]byte, ndpOptionLen*8)
	optionsBytes[0] = ndpOptionType
	optionsBytes[1] = ndpOptionLen
	copy(optionsBytes[2:], hwa)
	naMsgBytes = append(naMsgBytes, optionsBytes...)

	im := icmp.Message{
		// ICMPType = 136, Neighbor Advertisement
		Type: ipv6.ICMPTypeNeighborAdvertisement,
		// Always zero.
		Code: 0,
		// The ICMP checksum. Calculated by caller or OS.
		Checksum: 0,
		Body: &icmp.RawBody{
			Data: naMsgBytes,
		},
	}
	return im.Marshal(nil)
}
