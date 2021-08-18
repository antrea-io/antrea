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
	"fmt"
	"net"
	"strings"

	"antrea.io/libOpenflow/openflow13"
	"antrea.io/ofnet/ofctrl"
)

type ofFlowBuilder struct {
	ofFlow
}

func (b *ofFlowBuilder) MatchTunMetadata(index int, data uint32) FlowBuilder {
	rng := openflow13.NewNXRange(0, 31)
	tm := &ofctrl.NXTunMetadata{
		ID:    index,
		Data:  data,
		Range: rng,
	}
	b.ofFlow.Match.TunMetadatas = append(b.ofFlow.Match.TunMetadatas, tm)
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
	if b.ctStateString != "" {
		b.matchers = append(b.matchers, b.ctStateString)
		b.ctStateString = ""
	}
	return &b.ofFlow
}

// matchReg adds match condition for matching data in the target register.
func (b *ofFlowBuilder) matchReg(regID int, data uint32) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("reg%d=0x%x", regID, data))
	reg := &ofctrl.NXRegister{
		ID:   regID,
		Data: data,
	}
	b.Match.NxRegs = append(b.Match.NxRegs, reg)
	return b
}

// MatchXXReg adds match condition for matching data in the target xx-register.
func (b *ofFlowBuilder) MatchXXReg(regID int, data []byte) FlowBuilder {
	s := fmt.Sprintf("xxreg%d=0x%x", regID, data)
	b.matchers = append(b.matchers, s)
	reg := &ofctrl.XXRegister{
		ID:   regID,
		Data: data,
	}
	b.Match.XxRegs = append(b.Match.XxRegs, reg)
	return b
}

// matchRegRange adds match condition for matching data in the target register at specified range.
func (b *ofFlowBuilder) matchRegRange(regID int, data uint32, rng *Range) FlowBuilder {
	s := fmt.Sprintf("reg%d[%d..%d]=0x%x", regID, rng[0], rng[1], data)
	b.matchers = append(b.matchers, s)
	if rng[0] > 0 {
		data <<= rng[0]
	}
	reg := &ofctrl.NXRegister{
		ID:    regID,
		Data:  data,
		Range: rng.ToNXRange(),
	}
	b.Match.NxRegs = append(b.Match.NxRegs, reg)
	return b
}

func (b *ofFlowBuilder) MatchRegMark(mark *RegMark) FlowBuilder {
	return b.MatchRegFieldWithValue(mark.field, mark.value)
}

func (b *ofFlowBuilder) MatchRegFieldWithValue(field *RegField, data uint32) FlowBuilder {
	if field.isFullRange() {
		return b.matchReg(field.regID, data)
	}
	return b.matchRegRange(field.regID, data, field.rng)
}

func (b *ofFlowBuilder) addCTStateString(value string) {
	if b.ctStateString == "" {
		b.ctStateString = fmt.Sprintf("ct_state=%s", value)
	} else {
		b.ctStateString += value
	}
}

func (b *ofFlowBuilder) MatchCTStateNew(set bool) FlowBuilder {
	if b.ctStates == nil {
		b.ctStates = openflow13.NewCTStates()
	}
	if set {
		b.ctStates.SetNew()
		b.addCTStateString("+new")
	} else {
		b.ctStates.UnsetNew()
		b.addCTStateString("-trk")
	}
	return b
}

func (b *ofFlowBuilder) MatchCTStateRel(set bool) FlowBuilder {
	if b.ctStates == nil {
		b.ctStates = openflow13.NewCTStates()
	}
	if set {
		b.ctStates.SetRel()
		b.addCTStateString("+rel")
	} else {
		b.ctStates.UnsetRel()
		b.addCTStateString("-rel")
	}
	return b
}

func (b *ofFlowBuilder) MatchCTStateRpl(set bool) FlowBuilder {
	if b.ctStates == nil {
		b.ctStates = openflow13.NewCTStates()
	}
	if set {
		b.ctStates.SetRpl()
		b.addCTStateString("+rpl")
	} else {
		b.ctStates.UnsetRpl()
		b.addCTStateString("-rpl")
	}
	return b
}

func (b *ofFlowBuilder) MatchCTStateEst(set bool) FlowBuilder {
	if b.ctStates == nil {
		b.ctStates = openflow13.NewCTStates()
	}
	if set {
		b.ctStates.SetEst()
		b.addCTStateString("+est")
	} else {
		b.ctStates.UnsetEst()
		b.addCTStateString("-est")
	}
	return b
}

func (b *ofFlowBuilder) MatchCTStateTrk(set bool) FlowBuilder {
	if b.ctStates == nil {
		b.ctStates = openflow13.NewCTStates()
	}
	if set {
		b.ctStates.SetTrk()
		b.addCTStateString("+trk")
	} else {
		b.ctStates.UnsetTrk()
		b.addCTStateString("-trk")
	}
	return b
}

func (b *ofFlowBuilder) MatchCTStateInv(set bool) FlowBuilder {
	if b.ctStates == nil {
		b.ctStates = openflow13.NewCTStates()
	}
	if set {
		b.ctStates.SetInv()
		b.addCTStateString("+inv")
	} else {
		b.ctStates.UnsetInv()
		b.addCTStateString("-inv")
	}
	return b
}

func (b *ofFlowBuilder) MatchCTStateDNAT(set bool) FlowBuilder {
	if b.ctStates == nil {
		b.ctStates = openflow13.NewCTStates()
	}
	if set {
		b.ctStates.SetDNAT()
		b.addCTStateString("+dnat")
	} else {
		b.ctStates.UnsetDNAT()
		b.addCTStateString("-dnat")
	}
	return b
}

func (b *ofFlowBuilder) MatchCTStateSNAT(set bool) FlowBuilder {
	if b.ctStates == nil {
		b.ctStates = openflow13.NewCTStates()
	}
	if set {
		b.ctStates.SetSNAT()
		b.addCTStateString("+snat")
	} else {
		b.ctStates.UnsetSNAT()
		b.addCTStateString("-snat")
	}
	return b
}

func (b *ofFlowBuilder) MatchCTMark(mark *CtMark) FlowBuilder {
	ctmarkKey := fmt.Sprintf("ct_mark=0x%x", mark.value)
	b.ofFlow.Match.CtMark = mark.value
	if mark.isFullRange() {
		b.ofFlow.Match.CtMarkMask = nil
	} else {
		mask := mark.rng.ToNXRange().ToUint32Mask()
		ctmarkKey = fmt.Sprintf("%s/0x%x", ctmarkKey, mask)
		b.ofFlow.Match.CtMarkMask = &mask
	}
	b.matchers = append(b.matchers, ctmarkKey)
	return b
}

// MatchCTMarkMask sets the mask of ct_mark. The mask is used only if ct_mark is set.
func (b *ofFlowBuilder) MatchCTMarkMask(mask uint32) FlowBuilder {
	if b.Flow.Match.CtMark > 0 {
		b.ofFlow.Match.CtMarkMask = &mask
		for i, data := range b.matchers {
			if strings.HasPrefix(data, "ct_mark=") {
				b.matchers[i] = fmt.Sprintf("%s/0x%x", data, mask)
				break
			}
		}
	}
	return b
}

// MatchPktMark adds match condition for matching pkt_mark. If mask is nil, the mask should be not set in the OpenFlow
// message which is sent to OVS, and OVS should match the value exactly.
func (b *ofFlowBuilder) MatchPktMark(value uint32, mask *uint32) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("pkt_mark=%d", value))
	b.ofFlow.Match.PktMark = value
	b.ofFlow.Match.PktMarkMask = mask
	return b
}

// MatchTunnelDst adds match condition for matching tun_dst or tun_ipv6_dst.
func (b *ofFlowBuilder) MatchTunnelDst(dstIP net.IP) FlowBuilder {
	if dstIP.To4() != nil {
		b.matchers = append(b.matchers, fmt.Sprintf("tun_dst=%s", dstIP.String()))
	} else {
		b.matchers = append(b.matchers, fmt.Sprintf("tun_ipv6_dst=%s", dstIP.String()))
	}
	b.ofFlow.Match.TunnelDst = &dstIP
	return b
}

func ctLabelRange(high, low uint64, rng *Range, match *ofctrl.FlowMatch) {
	// [127..64] [63..0]
	//   high     low
	match.CtLabelHi = high
	match.CtLabelLo = low
	match.CtLabelHiMask = 0xffff_ffff_ffff_ffff
	match.CtLabelLoMask = 0xffff_ffff_ffff_ffff
	if rng[0] == rng[1] {
		if rng[0] < 64 {
			match.CtLabelLoMask = 1 << rng[0]
			match.CtLabelHiMask = 0
		} else {
			match.CtLabelHiMask = 1 << (rng[0] - 64)
			match.CtLabelLoMask = 0
		}
	} else if rng[0] < 64 && rng[1] >= 64 {
		match.CtLabelLoMask <<= rng[0]
		match.CtLabelHiMask >>= 127 - rng[1]
	} else if rng[1] < 64 {
		match.CtLabelLoMask &= 0xffff_ffff_ffff_ffff << rng[0]
		match.CtLabelLoMask &= 0xffff_ffff_ffff_ffff >> (63 - rng[1])
		match.CtLabelHiMask = 0
	} else if rng[0] >= 64 {
		match.CtLabelHiMask &= 0xffff_ffff_ffff_ffff << (rng[0] - 64)
		match.CtLabelHiMask &= 0xffff_ffff_ffff_ffff >> (127 - rng[1])
		match.CtLabelLoMask = 0
	}
}

func (b *ofFlowBuilder) MatchCTLabelField(high, low uint64, field *CtLabel) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("ct_label[%d..%d]=0x%x%x", field.rng[0], field.rng[1], high, low))
	ctLabelRange(high, low, field.GetRange(), &b.ofFlow.Match)
	return b
}

// MatchInPort adds match condition for matching in_port.
func (b *ofFlowBuilder) MatchInPort(inPort uint32) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("in_port=%d", inPort))
	b.Match.InputPort = inPort
	return b
}

// MatchDstIP adds match condition for matching destination IP address.
func (b *ofFlowBuilder) MatchDstIP(ip net.IP) FlowBuilder {
	if ip.To4() != nil {
		b.matchers = append(b.matchers, fmt.Sprintf("nw_dst=%s", ip.String()))
	} else {
		b.matchers = append(b.matchers, fmt.Sprintf("ipv6_dst=%s", ip.String()))
	}
	b.Match.IpDa = &ip
	return b
}

// MatchDstIPNet adds match condition for matching destination IP CIDR.
func (b *ofFlowBuilder) MatchDstIPNet(ipnet net.IPNet) FlowBuilder {
	if ipnet.IP.To4() != nil {
		b.matchers = append(b.matchers, fmt.Sprintf("nw_dst=%s", ipnet.String()))
	} else {
		b.matchers = append(b.matchers, fmt.Sprintf("ipv6_dst=%s", ipnet.String()))
	}
	b.Match.IpDa = &ipnet.IP
	b.Match.IpDaMask = maskToIP(ipnet.Mask)
	return b
}

func (b *ofFlowBuilder) MatchICMPv6Type(icmp6Type byte) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("icmp_type=%d", icmp6Type))
	b.Match.Icmp6Type = &icmp6Type
	return b
}

func (b *ofFlowBuilder) MatchICMPv6Code(icmp6Code byte) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("icmp_code=%d", icmp6Code))
	b.Match.Icmp6Code = &icmp6Code
	return b
}

func maskToIP(mask net.IPMask) *net.IP {
	ip := net.IP(mask)
	return &ip
}

// MatchSrcIP adds match condition for matching source IP address.
func (b *ofFlowBuilder) MatchSrcIP(ip net.IP) FlowBuilder {
	if ip.To4() != nil {
		b.matchers = append(b.matchers, fmt.Sprintf("nw_src=%s", ip.String()))
	} else {
		b.matchers = append(b.matchers, fmt.Sprintf("ipv6_src=%s", ip.String()))
	}
	b.Match.IpSa = &ip
	return b
}

// MatchSrcIPNet adds match condition for matching source IP CIDR.
func (b *ofFlowBuilder) MatchSrcIPNet(ipnet net.IPNet) FlowBuilder {
	if ipnet.IP.To4() != nil {
		b.matchers = append(b.matchers, fmt.Sprintf("nw_src=%s", ipnet.String()))
	} else {
		b.matchers = append(b.matchers, fmt.Sprintf("ipv6_src=%s", ipnet.String()))
	}
	b.Match.IpSa = &ipnet.IP
	b.Match.IpSaMask = maskToIP(ipnet.Mask)
	return b
}

// MatchDstMAC adds match condition for matching destination MAC address.
func (b *ofFlowBuilder) MatchDstMAC(mac net.HardwareAddr) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("dl_dst=%s", mac.String()))
	b.Match.MacDa = &mac
	return b
}

// MatchSrcMAC adds match condition for matching source MAC address.
func (b *ofFlowBuilder) MatchSrcMAC(mac net.HardwareAddr) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("dl_src=%s", mac.String()))
	b.Match.MacSa = &mac
	return b
}

// MatchARPSha adds match condition for matching ARP source host address.
func (b *ofFlowBuilder) MatchARPSha(mac net.HardwareAddr) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("arp_sha=%s", mac.String()))
	b.Match.ArpSha = &mac
	return b
}

// MatchARPTha adds match condition for matching ARP target host address.
func (b *ofFlowBuilder) MatchARPTha(mac net.HardwareAddr) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("arp_tha=%s", mac.String()))
	b.Match.ArpTha = &mac
	return b
}

// MatchARPSpa adds match condition for matching ARP source protocol address.
func (b *ofFlowBuilder) MatchARPSpa(ip net.IP) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("arp_spa=%s", ip.String()))
	b.Match.ArpSpa = &ip
	return b
}

// MatchARPTpa adds match condition for matching ARP target protocol address.
func (b *ofFlowBuilder) MatchARPTpa(ip net.IP) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("arp_tpa=%s", ip.String()))
	b.Match.ArpTpa = &ip
	return b
}

// MatchARPOp adds match condition for matching ARP operator.
func (b *ofFlowBuilder) MatchARPOp(op uint16) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("arp_op=%d", op))
	b.Match.ArpOper = op
	return b
}

// MatchIPDSCP adds match condition for matching DSCP field in the IP header. Note, OVS use TOS to present DSCP, and
// the field name is shown as "nw_tos" with OVS command line, and the value is calculated by shifting the given value
// left 2 bits.
func (b *ofFlowBuilder) MatchIPDSCP(dscp uint8) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("nw_tos=%d", dscp<<2))
	b.Match.IpDscp = dscp
	return b
}

// MatchConjID adds match condition for matching conj_id.
func (b *ofFlowBuilder) MatchConjID(value uint32) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("conj_id=%d", value))
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
	}
	b.protocol = protocol
	return b
}

// MatchProtocol adds match condition for IP protocol with the intetger value.
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
	matchStr := fmt.Sprintf("tp_dst=0x%x", port)
	if portMask != nil {
		matchStr = fmt.Sprintf("%s/0x%x", matchStr, portMask)
	}
	b.matchers = append(b.matchers, matchStr)
	return b
}

// MatchSrcPort adds match condition for matching source port in transport layer. OVS will match the port exactly
// if portMask is nil.
func (b *ofFlowBuilder) MatchSrcPort(port uint16, portMask *uint16) FlowBuilder {
	b.Match.SrcPort = port
	b.Match.SrcPortMask = portMask
	matchStr := fmt.Sprintf("tp_src=0x%x", port)
	if portMask != nil {
		matchStr = fmt.Sprintf("%s/0x%x", matchStr, portMask)
	}
	b.matchers = append(b.matchers, matchStr)
	return b
}

// MatchCTSrcIP matches the source IPv4 address of the connection tracker original direction tuple. This match requires
// a match to valid connection tracking state as a prerequisite, and valid connection tracking state matches include
// "+new", "+est", "+rel" and "+trk-inv".
func (b *ofFlowBuilder) MatchCTSrcIP(ip net.IP) FlowBuilder {
	b.Match.CtIpSa = &ip
	b.matchers = append(b.matchers, fmt.Sprintf("ct_nw_src=%s", ip.String()))
	return b
}

// MatchCTSrcIPNet is the same as MatchCTSrcIP but supports IP masking.
func (b *ofFlowBuilder) MatchCTSrcIPNet(ipNet net.IPNet) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("nw_dst=%s", ipNet.String()))
	b.Match.CtIpSa = &ipNet.IP
	b.Match.CtIpSaMask = maskToIP(ipNet.Mask)
	return b
}

// MatchCTDstIP matches the destination IPv4 address of the connection tracker original direction tuple. This match
// requires a match to valid connection tracking state as a prerequisite, and valid connection tracking state matches
// include "+new", "+est", "+rel" and "+trk-inv".
func (b *ofFlowBuilder) MatchCTDstIP(ip net.IP) FlowBuilder {
	b.Match.CtIpDa = &ip
	b.matchers = append(b.matchers, fmt.Sprintf("ct_nw_dst=%s", ip.String()))
	return b
}

// MatchCTDstIPNet is the same as MatchCTDstIP but supports IP masking.
func (b *ofFlowBuilder) MatchCTDstIPNet(ipNet net.IPNet) FlowBuilder {
	b.Match.CtIpDa = &ipNet.IP
	b.Match.CtIpDaMask = maskToIP(ipNet.Mask)
	b.matchers = append(b.matchers, fmt.Sprintf("ct_nw_dst=%s", ipNet.String()))
	return b
}

// MatchCTSrcPort matches the transport source port of the connection tracker original direction tuple. This match requires
// a match to valid connection tracking state as a prerequisite, and valid connection tracking state matches include
// "+new", "+est", "+rel" and "+trk-inv".
func (b *ofFlowBuilder) MatchCTSrcPort(port uint16) FlowBuilder {
	b.Match.CtTpSrcPort = port
	b.matchers = append(b.matchers, fmt.Sprintf("ct_tp_src=%d", port))
	return b
}

// MatchCTDstPort matches the transport destination port of the connection tracker original direction tuple. This match
// requires a match to valid connection tracking state as a prerequisite, and valid connection tracking state matches
// include "+new", "+est", "+rel" and "+trk-inv".
func (b *ofFlowBuilder) MatchCTDstPort(port uint16) FlowBuilder {
	b.Match.CtTpDstPort = port
	b.matchers = append(b.matchers, fmt.Sprintf("ct_tp_dst=%d", port))
	return b
}

// MatchCTProtocol matches the IP protocol type of the connection tracker original direction tuple. This match requires
// a match to valid connection tracking state as a prerequisite, and a valid connection tracking state matches include
// "+new", "+est", "+rel" and "+trk-inv".
func (b *ofFlowBuilder) MatchCTProtocol(proto Protocol) FlowBuilder {
	switch proto {
	case ProtocolTCP:
		b.Match.CtIpProto = 6
	case ProtocolUDP:
		b.Match.CtIpProto = 17
	case ProtocolSCTP:
		b.Match.CtIpProto = 132
	case ProtocolICMP:
		b.Match.CtIpProto = 1
	}
	b.matchers = append(b.matchers, fmt.Sprintf("ct_nw_proto=%d", b.Match.CtIpProto))
	return b
}

// Cookie sets cookie ID for the flow entry.
func (b *ofFlowBuilder) Cookie(cookieID uint64) FlowBuilder {
	b.Flow.CookieID = cookieID
	return b
}

// CookieMask sets cookie mask for the flow entry.
func (b *ofFlowBuilder) CookieMask(cookieMask uint64) FlowBuilder {
	b.Flow.CookieMask = &cookieMask
	return b
}

func (b *ofFlowBuilder) Action() Action {
	return &ofFlowAction{b}
}
