// Copyright 2020 Antrea Authors
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

package ip

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sort"

	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

const (
	V4BitLen = 8 * net.IPv4len
	V6BitLen = 8 * net.IPv6len
)

type DualStackIPs struct {
	IPv4 net.IP
	IPv6 net.IP
}

func (ips DualStackIPs) Equal(x DualStackIPs) bool {
	return ips.IPv4.Equal(x.IPv4) && ips.IPv6.Equal(x.IPv6)
}

// This function takes in one allow CIDR and multiple except CIDRs and gives diff CIDRs
// in allowCIDR eliminating except CIDRs. It currently supports only IPv4. except CIDR input
// can be changed.
func DiffFromCIDRs(allowCIDR *net.IPNet, exceptCIDRs []*net.IPNet) ([]*net.IPNet, error) {
	// Remove the redundant CIDRs
	exceptCIDRs = mergeCIDRs(exceptCIDRs)
	newCIDRs := []*net.IPNet{allowCIDR}
	for _, exceptCIDR := range exceptCIDRs {
	beginLoop:
		for i, indCIDR := range newCIDRs {
			// Consider masked IP from IPNet struct
			if indCIDR.Contains(exceptCIDR.IP.Mask(exceptCIDR.Mask)) {
				result := diffFromCIDR(indCIDR, exceptCIDR)
				// Delete the considered CIDR block and add resulting CIDR blocks
				copy(newCIDRs[i:], newCIDRs[i+1:])
				newCIDRs[len(newCIDRs)-1] = nil
				newCIDRs = newCIDRs[:len(newCIDRs)-1]
				// Append the result CIDRs
				newCIDRs = append(newCIDRs, result...)
				// This step can be optimized by having iterator over just the index. Went with reinitialization of iterator.
				goto beginLoop
			} else if exceptCIDR.Contains(indCIDR.IP) {
				// Just delete the CIDR block
				copy(newCIDRs[i:], newCIDRs[i+1:])
				newCIDRs[len(newCIDRs)-1] = nil
				newCIDRs = newCIDRs[:len(newCIDRs)-1]
				goto beginLoop
			}
		}
	}
	return newCIDRs, nil
}

// This function gives diff CIDRs between a superset CIDR (allow CIDR) and subset CIDR
// (except CIDR)
func diffFromCIDR(allowCIDR, exceptCIDR *net.IPNet) []*net.IPNet {
	allowPrefix, _ := allowCIDR.Mask.Size()
	exceptPrefix, _ := exceptCIDR.Mask.Size()

	// Mask the IP to get the start IP of range
	allowStartIP := allowCIDR.IP.Mask(allowCIDR.Mask)
	exceptStartIP := exceptCIDR.IP.Mask(exceptCIDR.Mask)
	var bits int
	if allowStartIP.To4() != nil {
		bits = V4BitLen
	} else {
		bits = V6BitLen
	}

	// New CIDRs should not contain the IPs in exceptCIDR. Manipulating the bits in start IP of
	// exceptCIDR will give remainder IPs in allowCIDR, specifically the masked IPs for remaining
	// CIDRs with prefix ranging from [allowPrefix+1, exceptPrefix].
	remainingCIDRs := make([]*net.IPNet, 0, exceptPrefix-allowPrefix)
	for i := allowPrefix + 1; i <= exceptPrefix; i++ {
		// Flip the (ipBitLen - i)th bit from LSB in exceptCIDR to get the IP which is not in exceptCIDR
		ipOfNewCIDR := flipSingleBit(&exceptStartIP, uint8(bits-i))
		newCIDRMask := net.CIDRMask(i, bits)
		for j := range allowStartIP {
			ipOfNewCIDR[j] = allowStartIP[j] | ipOfNewCIDR[j]
		}

		newCIDR := net.IPNet{IP: ipOfNewCIDR.Mask(newCIDRMask), Mask: newCIDRMask}
		remainingCIDRs = append(remainingCIDRs, &newCIDR)
	}
	return remainingCIDRs
}

func flipSingleBit(ip *net.IP, bitIndex uint8) net.IP {
	newIP := make(net.IP, len(*ip))
	copy(newIP, *ip)
	byteIndex := uint8(len(newIP)) - (bitIndex / 8) - 1
	// XOR bit operation to flip
	newIP[byteIndex] = newIP[byteIndex] ^ (1 << (bitIndex % 8))
	return newIP
}

// This function is to check for redundant CIDRs in the list that are
// covered by other CIDRs and remove them. Input array can be modified.
func mergeCIDRs(cidrBlocks []*net.IPNet) []*net.IPNet {
	// Sort the list by netmask in ascending order
	sort.Slice(cidrBlocks, func(i, j int) bool {
		return bytes.Compare(cidrBlocks[i].Mask, cidrBlocks[j].Mask) < 0
	})

	// Check and remove if there are redundant CIDRs that are part of bigger CIDRs
	// or repeated CIDRs
	for i := 0; i < len(cidrBlocks); i++ {
		for j := i + 1; j < len(cidrBlocks); j++ {
			if cidrBlocks[i].Contains(cidrBlocks[j].IP) {
				// Delete the CIDR block and truncate the slice
				copy(cidrBlocks[j:], cidrBlocks[j+1:])
				cidrBlocks[len(cidrBlocks)-1] = nil
				cidrBlocks = cidrBlocks[:len(cidrBlocks)-1]
				// Decrement the tracker to consider next element
				j = j - 1
			}
		}
	}
	return cidrBlocks
}

// IPNetToNetIPNet converts Antrea IPNet to *net.IPNet.
// Note that K8s allows non-standard CIDRs to be specified (e.g. 10.0.1.1/16, fe80::7015:efff:fe9a:146b/64). However,
// OVS will report OFPBMC_BAD_WILDCARDS error if using them in the OpenFlow messages. The function will normalize the
// CIDR if it's non-standard.
func IPNetToNetIPNet(ipNet *v1beta2.IPNet) *net.IPNet {
	ip := net.IP(ipNet.IP)
	ipLen := net.IPv4len
	if ip.To4() == nil {
		ipLen = net.IPv6len
	}
	mask := net.CIDRMask(int(ipNet.PrefixLength), 8*ipLen)
	maskedIP := ip.Mask(mask)
	return &net.IPNet{IP: maskedIP, Mask: mask}
}

const (
	ICMPProtocol   = 1
	IGMPProtocol   = 2
	TCPProtocol    = 6
	UDPProtocol    = 17
	ICMPv6Protocol = 58
	SCTPProtocol   = 132
)

// IPProtocolNumberToString returns the string name of the IP protocol with number protocolNum. If
// the number does not match a "known" protocol, we return the defaultValue string.
func IPProtocolNumberToString(protocolNum uint8, defaultValue string) string {
	switch protocolNum {
	case ICMPProtocol:
		return "ICMP"
	case IGMPProtocol:
		return "IGMP"
	case TCPProtocol:
		return "TCP"
	case UDPProtocol:
		return "UDP"
	case ICMPv6Protocol:
		return "IPv6-ICMP"
	case SCTPProtocol:
		return "SCTP"
	default:
		return defaultValue
	}
}

// MustParseCIDR turns the given string into IPNet or panics, for tests or other cases where the string must be valid.
func MustParseCIDR(cidr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Errorf("cannot parse '%v': %v", cidr, err))
	}
	return ipNet
}

func MustParseMAC(mac string) net.HardwareAddr {
	addr, err := net.ParseMAC(mac)
	if err != nil {
		panic(fmt.Errorf("cannot parse '%v': %v", mac, err))
	}
	return addr
}

// IPNetEqual returns if the provided IPNets are the same subnet.
func IPNetEqual(ipNet1, ipNet2 *net.IPNet) bool {
	if ipNet1 == nil && ipNet2 == nil {
		return true
	}
	if ipNet1 == nil || ipNet2 == nil {
		return false
	}
	if !bytes.Equal(ipNet1.Mask, ipNet2.Mask) {
		return false
	}
	if !ipNet1.IP.Equal(ipNet2.IP) {
		return false
	}
	return true
}

// IPNetContains returns if the first IPNet contains the second IPNet.
// For example:
//
// 10.0.0.0/24 contains 10.0.0.0/24.
// 10.0.0.0/24 contains 10.0.0.0/25.
// 10.0.0.0/24 contains 10.0.0.128/25.
// 10.0.0.0/24 does not contain 10.0.0.0/23.
// 10.0.0.0/24 does not contain 10.0.1.0/25.
func IPNetContains(ipNet1, ipNet2 *net.IPNet) bool {
	if ipNet1 == nil || ipNet2 == nil {
		return false
	}
	ones1, bits1 := ipNet1.Mask.Size()
	ones2, bits2 := ipNet2.Mask.Size()
	if bits1 != bits2 {
		return false
	}
	if ones1 > ones2 {
		return false
	}
	if !ipNet1.Contains(ipNet2.IP) {
		return false
	}
	return true
}

func MustIPv6(s string) net.IP {
	ip := net.ParseIP(s)
	if !utilnet.IsIPv6(ip) {
		panic(fmt.Errorf("invalid IPv6 address: %s", s))
	}
	return ip
}

// GetLocalBroadcastIP returns the last IP address in a subnet. This IP is always working as the broadcast address in
// the subnet on Windows, and an active route entry that uses it as the destination is added by default when a new IP is
// configured on the interface.
func GetLocalBroadcastIP(ipNet *net.IPNet) net.IP {
	lastAddr := make(net.IP, len(ipNet.IP.To4()))
	binary.BigEndian.PutUint32(lastAddr, binary.BigEndian.Uint32(ipNet.IP.To4())|^binary.BigEndian.Uint32(net.IP(ipNet.Mask).To4()))
	return lastAddr
}

// AppendPortIfMissing appends the given port to the address if the address doesn't contain any port.
func AppendPortIfMissing(addr, port string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}

	ip := net.ParseIP(addr)
	// Return the address directly if it's not a valid address.
	if ip == nil {
		return addr
	}

	return net.JoinHostPort(addr, port)
}

// GetStartAndEndOfPrefix retrieves the start and end addresses of a netip.Prefix.
// For example:  10.10.40.0/24 -> 10.10.40.0, 10.10.40.255
func GetStartAndEndOfPrefix(prefix netip.Prefix) (netip.Addr, netip.Addr) {
	var start, end netip.Addr
	var mask net.IPMask

	if prefix.Addr().Is4() {
		mask = net.CIDRMask(prefix.Bits(), 32)
	} else {
		mask = net.CIDRMask(prefix.Bits(), 128)
	}

	// use gateway address, of canonical form of prefix, as start address.
	start = prefix.Masked().Addr()

	// calculate the end address by performing bitwise OR with the complement of the mask.
	slice := start.AsSlice()
	for i := 0; i < len(slice); i++ {
		slice[i] |= ^mask[i]
	}

	end, _ = netip.AddrFromSlice(slice)
	return start, end
}
