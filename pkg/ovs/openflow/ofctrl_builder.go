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

package openflow

import (
	"net"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/ofnet/ofctrl"
)

type ofFlowBuilder struct {
	ofFlow
}

// MatchVLAN can be used as follows:
// - to match the packets of a specific VLAN, there are two cases:
//   - to match VLAN 0, nonVLAN should be false, vlanID should be 0, value of vlanMask must be 0x1fff.
//   - VLAN 1-4095, nonVLAN should be false, vlanID should be the VLAN ID, vlanMask can be nil, or its value can be 0x1fff.
//
// - to match the packets of all VLANs, nonVLAN should be false, vlanID must be 0, value of vlanMask must be 0x1000.
// - to match the packets of non-VLAN, nonVLAN should be true, vlanID must be 0, vlanMask can be nil, or its value can be 0x1000.
func (b *ofFlowBuilder) MatchVLAN(nonVLAN bool, vlanID uint16, vlanMask *uint16) FlowBuilder {
	if vlanMask == nil {
		var vlanMaskValue uint16
		// To match the packets of a VLAN whose VLAN ID is not 0, when vlanMask is nil, set the value of vlanMask to 0x1ffff.
		if vlanID != 0 {
			vlanMaskValue = uint16(openflow15.OFPVID_PRESENT | protocol.VID_MASK)
		}
		// To match the packets of non-VLAN, when vlanMask is nil, set the value of vlanMask to 0x1000.
		if nonVLAN {
			vlanMaskValue = uint16(openflow15.OFPVID_PRESENT)
		}
		vlanMask = &vlanMaskValue
	}

	value := vlanID
	if !nonVLAN {
		value |= openflow15.OFPVID_PRESENT
	}

	b.Match.NonVlan = nonVLAN
	b.Match.VlanId = &vlanID
	b.Match.VlanMask = vlanMask
	return b
}

func (b *ofFlowBuilder) SetHardTimeout(timout uint16) FlowBuilder {
	b.ofFlow.HardTimeout = timout
	return b
}

func (b *ofFlowBuilder) SetIdleTimeout(timeout uint16) FlowBuilder {
	b.ofFlow.IdleTimeout = timeout
	return b
}

func (b *ofFlowBuilder) Done() Flow {
	if b.ctStates != nil {
		b.Flow.Match.CtStates = b.ctStates
		b.ctStates = nil
	}
	return &b.ofFlow
}

// matchReg adds match condition for matching data in the target register.
func (b *ofFlowBuilder) matchReg(regID int, data uint32) FlowBuilder {
	reg := &ofctrl.NXRegister{
		ID:   regID,
		Data: data,
	}
	b.Match.NxRegs = append(b.Match.NxRegs, reg)
	return b
}

// MatchXXReg adds match condition for matching data in the target xx-register.
func (b *ofFlowBuilder) MatchXXReg(regID int, data []byte) FlowBuilder {
	reg := &ofctrl.XXRegister{
		ID:   regID,
		Data: data,
	}
	b.Match.XxRegs = append(b.Match.XxRegs, reg)
	return b
}

// matchRegRange adds match condition for matching data in the target register at specified range.
func (b *ofFlowBuilder) matchRegRange(regID int, data uint32, rng *Range) FlowBuilder {
	reg := &ofctrl.NXRegister{
		ID:    regID,
		Data:  data,
		Range: rng.ToNXRange(),
	}
	b.Match.NxRegs = append(b.Match.NxRegs, reg)
	return b
}

func (b *ofFlowBuilder) MatchRegMark(marks ...*RegMark) FlowBuilder {
	var fb FlowBuilder
	fb = b
	for _, mark := range marks {
		fb = b.MatchRegFieldWithValue(mark.field, mark.value)
	}
	return fb
}

func (b *ofFlowBuilder) MatchRegFieldWithValue(field *RegField, data uint32) FlowBuilder {
	if field.isFullRange() {
		return b.matchReg(field.regID, data)
	}
	return b.matchRegRange(field.regID, data, field.rng)
}

func (b *ofFlowBuilder) MatchCTState(ctStates *openflow15.CTStates) FlowBuilder {
	b.ctStates = ctStates
	return b
}

func (b *ofFlowBuilder) MatchCTStateNew(set bool) FlowBuilder {
	if b.ctStates == nil {
		b.ctStates = openflow15.NewCTStates()
	}
	if set {
		b.ctStates.SetNew()
	} else {
		b.ctStates.UnsetNew()
	}
	return b
}

func (b *ofFlowBuilder) MatchCTStateRel(set bool) FlowBuilder {
	if b.ctStates == nil {
		b.ctStates = openflow15.NewCTStates()
	}
	if set {
		b.ctStates.SetRel()
	} else {
		b.ctStates.UnsetRel()
	}
	return b
}

func (b *ofFlowBuilder) MatchCTStateRpl(set bool) FlowBuilder {
	if b.ctStates == nil {
		b.ctStates = openflow15.NewCTStates()
	}
	if set {
		b.ctStates.SetRpl()
	} else {
		b.ctStates.UnsetRpl()
	}
	return b
}

func (b *ofFlowBuilder) MatchCTStateEst(set bool) FlowBuilder {
	if b.ctStates == nil {
		b.ctStates = openflow15.NewCTStates()
	}
	if set {
		b.ctStates.SetEst()
	} else {
		b.ctStates.UnsetEst()
	}
	return b
}

func (b *ofFlowBuilder) MatchCTStateTrk(set bool) FlowBuilder {
	if b.ctStates == nil {
		b.ctStates = openflow15.NewCTStates()
	}
	if set {
		b.ctStates.SetTrk()
	} else {
		b.ctStates.UnsetTrk()
	}
	return b
}

func (b *ofFlowBuilder) MatchCTStateInv(set bool) FlowBuilder {
	if b.ctStates == nil {
		b.ctStates = openflow15.NewCTStates()
	}
	if set {
		b.ctStates.SetInv()
	} else {
		b.ctStates.UnsetInv()
	}
	return b
}

func (b *ofFlowBuilder) MatchCTStateDNAT(set bool) FlowBuilder {
	if b.ctStates == nil {
		b.ctStates = openflow15.NewCTStates()
	}
	if set {
		b.ctStates.SetDNAT()
	} else {
		b.ctStates.UnsetDNAT()
	}
	return b
}

func (b *ofFlowBuilder) MatchCTStateSNAT(set bool) FlowBuilder {
	if b.ctStates == nil {
		b.ctStates = openflow15.NewCTStates()
	}
	if set {
		b.ctStates.SetSNAT()
	} else {
		b.ctStates.UnsetSNAT()
	}
	return b
}

func (b *ofFlowBuilder) MatchCTMark(marks ...*CtMark) FlowBuilder {
	if len(marks) == 0 {
		return b
	}
	var value, mask uint32
	for _, mark := range marks {
		value |= mark.GetValue()
		mask |= mark.field.rng.ToNXRange().ToUint32Mask()
	}
	b.ofFlow.Match.CtMark = value
	b.ofFlow.Match.CtMarkMask = &mask
	return b
}

// MatchPktMark adds match condition for matching pkt_mark. If mask is nil, the mask should be not set in the OpenFlow
// message which is sent to OVS, and OVS should match the value exactly.
func (b *ofFlowBuilder) MatchPktMark(value uint32, mask *uint32) FlowBuilder {
	b.ofFlow.Match.PktMark = value
	b.ofFlow.Match.PktMarkMask = mask
	return b
}

// MatchTunnelDst adds match condition for matching tun_dst or tun_ipv6_dst.
func (b *ofFlowBuilder) MatchTunnelDst(dstIP net.IP) FlowBuilder {
	b.ofFlow.Match.TunnelDst = &dstIP
	return b
}

// MatchTunnelID adds match condition for matching tun_id.
func (b *ofFlowBuilder) MatchTunnelID(tunnelID uint64) FlowBuilder {
	b.ofFlow.Match.TunnelId = tunnelID
	return b
}

func ctLabelRange(high, low uint64, rng *Range, match *ofctrl.FlowMatch) {
	// [127..64] [63..0]
	//   high     low
	match.CtLabelHi = high
	match.CtLabelLo = low
	match.CtLabelHiMask = 0xffff_ffff_ffff_ffff
	match.CtLabelLoMask = 0xffff_ffff_ffff_ffff
	if rng[1] < 64 {
		match.CtLabelLoMask &= 0xffff_ffff_ffff_ffff << rng[0]
		match.CtLabelLoMask &= 0xffff_ffff_ffff_ffff >> (63 - rng[1])
		match.CtLabelHi = 0
		match.CtLabelHiMask = 0
	} else if rng[0] >= 64 {
		match.CtLabelHiMask &= 0xffff_ffff_ffff_ffff << (rng[0] - 64)
		match.CtLabelHiMask &= 0xffff_ffff_ffff_ffff >> (127 - rng[1])
		match.CtLabelLo = 0
		match.CtLabelLoMask = 0
	} else {
		match.CtLabelLoMask <<= rng[0]
		match.CtLabelHiMask >>= 127 - rng[1]
	}
}

func (b *ofFlowBuilder) MatchCTLabelField(high, low uint64, field *CtLabel) FlowBuilder {
	ctLabelRange(high, low, field.GetRange(), &b.ofFlow.Match)
	return b
}

// MatchInPort adds match condition for matching in_port.
func (b *ofFlowBuilder) MatchInPort(inPort uint32) FlowBuilder {
	b.Match.InputPort = inPort
	return b
}

// MatchDstIP adds match condition for matching destination IP address.
func (b *ofFlowBuilder) MatchDstIP(ip net.IP) FlowBuilder {
	b.Match.IpDa = &ip
	return b
}

// MatchDstIPNet adds match condition for matching destination IP CIDR.
func (b *ofFlowBuilder) MatchDstIPNet(ipnet net.IPNet) FlowBuilder {
	b.Match.IpDa = &ipnet.IP
	b.Match.IpDaMask = maskToIP(ipnet.Mask)
	return b
}

func (b *ofFlowBuilder) MatchICMPType(icmpType byte) FlowBuilder {
	b.Match.Icmp4Type = &icmpType
	return b
}

func (b *ofFlowBuilder) MatchICMPCode(icmpCode byte) FlowBuilder {
	b.Match.Icmp4Code = &icmpCode
	return b
}

func (b *ofFlowBuilder) MatchICMPv6Type(icmp6Type byte) FlowBuilder {
	b.Match.Icmp6Type = &icmp6Type
	return b
}

func (b *ofFlowBuilder) MatchICMPv6Code(icmp6Code byte) FlowBuilder {
	b.Match.Icmp6Code = &icmp6Code
	return b
}

func maskToIP(mask net.IPMask) *net.IP {
	ip := net.IP(mask)
	return &ip
}

// MatchSrcIP adds match condition for matching source IP address.
func (b *ofFlowBuilder) MatchSrcIP(ip net.IP) FlowBuilder {
	b.Match.IpSa = &ip
	return b
}

// MatchSrcIPNet adds match condition for matching source IP CIDR.
func (b *ofFlowBuilder) MatchSrcIPNet(ipnet net.IPNet) FlowBuilder {
	b.Match.IpSa = &ipnet.IP
	b.Match.IpSaMask = maskToIP(ipnet.Mask)
	return b
}

// MatchDstMAC adds match condition for matching destination MAC address.
func (b *ofFlowBuilder) MatchDstMAC(mac net.HardwareAddr) FlowBuilder {
	b.Match.MacDa = &mac
	return b
}

// MatchSrcMAC adds match condition for matching source MAC address.
func (b *ofFlowBuilder) MatchSrcMAC(mac net.HardwareAddr) FlowBuilder {
	b.Match.MacSa = &mac
	return b
}

// MatchARPSha adds match condition for matching ARP source host address.
func (b *ofFlowBuilder) MatchARPSha(mac net.HardwareAddr) FlowBuilder {
	b.Match.ArpSha = &mac
	return b
}

// MatchARPTha adds match condition for matching ARP target host address.
func (b *ofFlowBuilder) MatchARPTha(mac net.HardwareAddr) FlowBuilder {
	b.Match.ArpTha = &mac
	return b
}

// MatchARPSpa adds match condition for matching ARP source protocol address.
func (b *ofFlowBuilder) MatchARPSpa(ip net.IP) FlowBuilder {
	b.Match.ArpSpa = &ip
	return b
}

// MatchARPTpa adds match condition for matching ARP target protocol address.
func (b *ofFlowBuilder) MatchARPTpa(ip net.IP) FlowBuilder {
	b.Match.ArpTpa = &ip
	return b
}

// MatchARPOp adds match condition for matching ARP operator.
func (b *ofFlowBuilder) MatchARPOp(op uint16) FlowBuilder {
	b.Match.ArpOper = op
	return b
}

// MatchIPDSCP adds match condition for matching DSCP field in the IP header. Note, OVS use TOS to present DSCP, and
// the field name is shown as "nw_tos" with OVS command line, and the value is calculated by shifting the given value
// left 2 bits.
func (b *ofFlowBuilder) MatchIPDSCP(dscp uint8) FlowBuilder {
	b.Match.IpDscp = dscp
	return b
}

// MatchConjID adds match condition for matching conj_id.
func (b *ofFlowBuilder) MatchConjID(value uint32) FlowBuilder {
	b.Match.ConjunctionID = &value
	return b
}

func (b *ofFlowBuilder) MatchPriority(priority uint16) FlowBuilder {
	b.Match.Priority = priority
	return b
}

// MatchProtocol adds match condition for matching protocol type.
func (b *ofFlowBuilder) MatchProtocol(protocol Protocol) FlowBuilder {
	switch protocol {
	case ProtocolIP:
		b.Match.Ethertype = 0x0800
	case ProtocolIPv6:
		b.Match.Ethertype = 0x86dd
	case ProtocolARP:
		b.Match.Ethertype = 0x0806
	case ProtocolTCP:
		b.Match.Ethertype = 0x0800
		b.Match.IpProto = 6
	case ProtocolTCPv6:
		b.Match.Ethertype = 0x86dd
		b.Match.IpProto = 6
	case ProtocolUDP:
		b.Match.Ethertype = 0x0800
		b.Match.IpProto = 17
	case ProtocolUDPv6:
		b.Match.Ethertype = 0x86dd
		b.Match.IpProto = 17
	case ProtocolSCTP:
		b.Match.Ethertype = 0x0800
		b.Match.IpProto = 132
	case ProtocolSCTPv6:
		b.Match.Ethertype = 0x86dd
		b.Match.IpProto = 132
	case ProtocolICMP:
		b.Match.Ethertype = 0x0800
		b.Match.IpProto = 1
	case ProtocolICMPv6:
		b.Match.Ethertype = 0x86dd
		b.Match.IpProto = 58
	case ProtocolIGMP:
		b.Match.Ethertype = 0x0800
		b.Match.IpProto = 2
	}
	b.protocol = protocol
	return b
}

// MatchIPProtocolValue adds match condition for IP protocol with the integer value.
func (b *ofFlowBuilder) MatchIPProtocolValue(isIPv6 bool, protoValue uint8) FlowBuilder {
	if isIPv6 {
		b.Match.Ethertype = 0x86dd
	} else {
		b.Match.Ethertype = 0x0800
	}
	b.Match.IpProto = protoValue
	return b
}

// MatchDstPort adds match condition for matching destination port in transport layer. OVS will match the port exactly
// if portMask is nil.
func (b *ofFlowBuilder) MatchDstPort(port uint16, portMask *uint16) FlowBuilder {
	b.Match.DstPort = port
	b.Match.DstPortMask = portMask
	return b
}

// MatchSrcPort adds match condition for matching source port in transport layer. OVS will match the port exactly
// if portMask is nil.
func (b *ofFlowBuilder) MatchSrcPort(port uint16, portMask *uint16) FlowBuilder {
	b.Match.SrcPort = port
	b.Match.SrcPortMask = portMask
	return b
}

func (b *ofFlowBuilder) MatchTCPFlags(flag, mask uint16) FlowBuilder {
	b.Match.TcpFlags = &flag
	b.Match.TcpFlagsMask = &mask
	return b
}

// MatchCTSrcIP matches the source IPv4 address of the connection tracker original direction tuple. This match requires
// a match to valid connection tracking state as a prerequisite, and valid connection tracking state matches include
// "+new", "+est", "+rel" and "+trk-inv".
func (b *ofFlowBuilder) MatchCTSrcIP(ip net.IP) FlowBuilder {
	if ip.To4() != nil {
		b.Match.CtIpSa = &ip
	} else {
		b.Match.CtIpv6Sa = &ip
	}
	return b
}

// MatchCTSrcIPNet is the same as MatchCTSrcIP but supports IP masking.
func (b *ofFlowBuilder) MatchCTSrcIPNet(ipNet net.IPNet) FlowBuilder {
	if ipNet.IP.To4() != nil {
		b.Match.CtIpSa = &ipNet.IP
		b.Match.CtIpSaMask = maskToIP(ipNet.Mask)
	} else {
		b.Match.CtIpv6Sa = &ipNet.IP
		b.Match.CtIpv6SaMask = maskToIP(ipNet.Mask)
	}
	return b
}

// MatchCTDstIP matches the destination IPv4 address of the connection tracker original direction tuple. This match
// requires a match to valid connection tracking state as a prerequisite, and valid connection tracking state matches
// include "+new", "+est", "+rel" and "+trk-inv".
func (b *ofFlowBuilder) MatchCTDstIP(ip net.IP) FlowBuilder {
	if ip.To4() != nil {
		b.Match.CtIpDa = &ip
	} else {
		b.Match.CtIpv6Da = &ip
	}
	return b
}

// MatchCTDstIPNet is the same as MatchCTDstIP but supports IP masking.
func (b *ofFlowBuilder) MatchCTDstIPNet(ipNet net.IPNet) FlowBuilder {
	if ipNet.IP.To4() != nil {
		b.Match.CtIpDa = &ipNet.IP
		b.Match.CtIpDaMask = maskToIP(ipNet.Mask)
	} else {
		b.Match.CtIpv6Da = &ipNet.IP
		b.Match.CtIpv6DaMask = maskToIP(ipNet.Mask)
	}
	return b
}

// MatchCTSrcPort matches the transport source port of the connection tracker original direction tuple. This match requires
// a match to valid connection tracking state as a prerequisite, and valid connection tracking state matches include
// "+new", "+est", "+rel" and "+trk-inv".
func (b *ofFlowBuilder) MatchCTSrcPort(port uint16) FlowBuilder {
	b.Match.CtTpSrcPort = port
	return b
}

// MatchCTDstPort matches the transport destination port of the connection tracker original direction tuple. This match
// requires a match to valid connection tracking state as a prerequisite, and valid connection tracking state matches
// include "+new", "+est", "+rel" and "+trk-inv".
func (b *ofFlowBuilder) MatchCTDstPort(port uint16) FlowBuilder {
	b.Match.CtTpDstPort = port
	return b
}

// MatchCTProtocol matches the IP protocol type of the connection tracker original direction tuple. This match requires
// a match to valid connection tracking state as a prerequisite, and a valid connection tracking state matches include
// "+new", "+est", "+rel" and "+trk-inv".
func (b *ofFlowBuilder) MatchCTProtocol(proto Protocol) FlowBuilder {
	switch proto {
	case ProtocolTCP, ProtocolTCPv6:
		b.Match.CtIpProto = 6
	case ProtocolUDP, ProtocolUDPv6:
		b.Match.CtIpProto = 17
	case ProtocolSCTP, ProtocolSCTPv6:
		b.Match.CtIpProto = 132
	case ProtocolICMP:
		b.Match.CtIpProto = 1
	case ProtocolICMPv6:
		b.Match.CtIpProto = 58
	}
	return b
}

// Cookie sets cookie ID for the flow entry.
func (b *ofFlowBuilder) Cookie(cookieID uint64) FlowBuilder {
	b.Flow.CookieID = cookieID
	return b
}

func (b *ofFlowBuilder) Action() Action {
	return &ofFlowAction{b}
}
