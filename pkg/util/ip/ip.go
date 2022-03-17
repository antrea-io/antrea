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
	"math/big"
	"net"
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

// ipRangeInfo stores the start and end IP addresses for an IP range.
// As well as a boolean indicating IPv4 or IPv6.
type ipRangeInfo struct {
	startIP net.IP
	endIP   net.IP
	isIPv6  bool
}

func ComplementAddressesInCIDR(ips []net.IP) []*net.IPNet {
	// Sort the IPs to get excluded IP ranges.
	sort.Slice(ips, func(i, j int) bool { return bytes.Compare(ips[i], ips[j]) < 0 })
	excludedIPRanges := excludeIPMultiForm(ips)
	// For each IP range, represent it in CIDR.
	excludedCIDRs := make([]*net.IPNet, 0)
	for _, interval := range excludedIPRanges {
		excludedCIDR := ipRangeToCIDR(interval)
		excludedCIDRs = append(excludedCIDRs, excludedCIDR...)
	}
	return excludedCIDRs
}

// excludeIPMultiForm inputs IP addresses, mixture of IPv4/IPv6.
// It outputs intervals within the entire IPv4/IPv6 range excluding the provided IP addresses.
func excludeIPMultiForm(ips []net.IP) []ipRangeInfo {
	excludedIPs := make([]ipRangeInfo, 0)
	v4IPs := make([]net.IP, 0)
	v6IPs := make([]net.IP, 0)
	for _, ip := range ips {
		if utilnet.IsIPv4(ip) {
			v4IPs = append(v4IPs, ip)
		} else {
			v6IPs = append(v6IPs, ip)
		}
	}
	excludedIPs = append(excludedIPs, excludeIPUniForm(v4IPs, false)...)
	excludedIPs = append(excludedIPs, excludeIPUniForm(v6IPs, true)...)
	return excludedIPs
}

// excludeIPRange inputs IP addresses of consistent IPv4/IPv6, and a boolean indicating IPv4/IPv6.
// It outputs ipRangeInfos within the corresponding IPv4/IPv6 address space excluding the provided IP addresses.
func excludeIPUniForm(ips []net.IP, isIPv6 bool) []ipRangeInfo {
	if ips == nil || len(ips) == 0 {
		return nil
	}
	excludedIPs := make([]ipRangeInfo, 0)
	IPzero := net.IPv4zero
	IPbcast := net.IPv4bcast
	if isIPv6 {
		IPzero = net.IPv6zero
		IPbcast = net.IP{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	}
	// Check if first interval starts from zero.
	if bytes.Compare(ips[0], IPzero) != 0 {
		excludedIPs = append(excludedIPs, ipRangeInfo{IPzero, prevIP(ips[0]), isIPv6})
	}
	// Calculate intermediate intervals.
	for idx := 0; idx < len(ips)-1; idx++ {
		if bytes.Compare(ips[idx], prevIP(ips[idx+1])) == 0 {
			idx += 1
			continue
		}
		excludedIPs = append(excludedIPs, ipRangeInfo{nextIP(ips[idx]), prevIP(ips[idx+1]), isIPv6})
	}
	// Check if last interval ends with all 1-bits.
	if bytes.Compare(ips[len(ips)-1], IPbcast) != 0 {
		excludedIPs = append(excludedIPs, ipRangeInfo{nextIP(ips[len(ips)-1]), IPbcast, isIPv6})
	}
	return excludedIPs
}

// ipRangeToCIDR inputs an IP address range of type ipRangeInfo.
// It outputs CIDRs that cover the provided IP address ranges.
func ipRangeToCIDR(ipRange ipRangeInfo) []*net.IPNet {
	ipRangeInCIDRs := make([]*net.IPNet, 0)
	ipRangeStartInt := ipToInt(ipRange.startIP)
	ipRangeEndInt := ipToInt(ipRange.endIP)
	// Calculate ipRangeLength = ipRangeEnd - ipRangeStart + 1.
	ipRangeLength := new(big.Int)
	ipRangeLength.Sub(ipRangeEndInt, ipRangeStartInt)
	ipRangeLength.Add(ipRangeLength, big.NewInt(1))
	ipRangeStartNeg := new(big.Int)
	step := new(big.Int)

	for ipRangeLength.Cmp(big.NewInt(0)) > 0 {
		ipRangeStartNeg.Neg(ipRangeStartInt)
		step.And(ipRangeStartInt, ipRangeStartNeg)
		// Set default step as largest number for zero IP.
		if step.Cmp(big.NewInt(0)) == 0 {
			step = big.NewInt(1)
			step.Lsh(step, V6BitLen+1)
		}
		for step.Cmp(ipRangeLength) > 0 {
			// Divide step by 2 by shifting to the right.
			step.Rsh(step, 1)
		}
		cidr := stepToCIDR(ipRangeStartInt, step, ipRange.isIPv6)
		ipRangeInCIDRs = append(ipRangeInCIDRs, cidr)
		ipRangeStartInt.Add(ipRangeStartInt, step)
		ipRangeLength.Sub(ipRangeLength, step)
	}
	return ipRangeInCIDRs
}

// Convert IP address to big int. Accepts both IPv4/IPv6.
func ipToInt(ip net.IP) *big.Int {
	if v := ip.To4(); v != nil {
		return big.NewInt(0).SetBytes(v)
	}
	return big.NewInt(0).SetBytes(ip.To16())
}

// Convert IP address in big Int to net IP type. Accepts both IPv4/IPv6.
func bigIntToIP(bigIntIP *big.Int, isIPv6 bool) net.IP {
	ip := make(net.IP, net.IPv4len)
	if isIPv6 {
		ip = make(net.IP, net.IPv6len)
	}
	return bigIntIP.FillBytes(ip)
}

// Return previous IP address. Accepts both IPv4/IPv6.
func prevIP(ip net.IP) net.IP {
	i := ipToInt(ip)
	return bigIntToIP(i.Sub(i, big.NewInt(1)), utilnet.IsIPv6(ip))
}

// Return next IP address. Accepts both IPv4/IPv6.
func nextIP(ip net.IP) net.IP {
	i := ipToInt(ip)
	return bigIntToIP(i.Add(i, big.NewInt(1)), utilnet.IsIPv6(ip))
}

// stepToCIDR inputs an IP address in big int format, and the step as mask length.
// It outputs a CIDR in IPNet format.
func stepToCIDR(ipRangeStartInt *big.Int, step *big.Int, isIPv6 bool) *net.IPNet {
	maskMaxLength := V4BitLen
	if isIPv6 {
		maskMaxLength = V6BitLen
	}
	// Mask = mask max length - log2(step)
	logStep := -1
	stepToShift := new(big.Int).Set(step)
	for stepToShift.Cmp(big.NewInt(0)) > 0 {
		logStep += 1
		stepToShift.Rsh(stepToShift, 1)
	}
	mask := maskMaxLength - logStep
	return &net.IPNet{
		IP:   bigIntToIP(ipRangeStartInt, isIPv6),
		Mask: net.CIDRMask(mask, maskMaxLength),
	}
}

// IPNetToNetIPNet converts Antrea IPNet to *net.IPNet.
// Note that K8s allows non-standard CIDRs to be specified (e.g. 10.0.1.1/16, fe80::7015:efff:fe9a:146b/64). However,
// OVS will report OFPBMC_BAD_WILDCARDS error if using them in the OpenFlow messages. The function will normalize the
// CIDR if it's non-standard.
func IPNetToNetIPNet(ipNet *v1beta2.IPNet) *net.IPNet {
	ip := net.IP(ipNet.IP)
	ipLen := net.IPv4len
	if utilnet.IsIPv6(ip) {
		ipLen = net.IPv6len
	}
	mask := net.CIDRMask(int(ipNet.PrefixLength), 8*ipLen)
	maskedIP := ip.Mask(mask)
	return &net.IPNet{IP: maskedIP, Mask: mask}
}

const (
	ICMPProtocol   = 1
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
