// Copyright 2022 Antrea Authors
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

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"k8s.io/klog/v2"
)

// TableNameCache is for testing.
var TableNameCache map[uint8]string

type fieldMetadata struct {
	name   string
	length uint8
}

func (m *fieldMetadata) getMatchNickname() string {
	name := strings.TrimPrefix(m.name, "NXM_OF_")
	name = strings.TrimPrefix(name, "NXM_NX_")
	name = strings.TrimPrefix(name, "OXM_OF_")
	name = strings.TrimPrefix(name, "OXM_PACKET_")
	name = strings.TrimPrefix(name, "OXM_FIELD_")
	name = strings.ToLower(name)
	if strings.HasPrefix(name, "ip_") && name != "ip_dscp" {
		name = strings.Replace(name, "ip_", "nw_", 1)
	}
	if strings.HasPrefix(name, "ipv4_") && name != "ip_dscp" {
		name = strings.Replace(name, "ipv4_", "nw_", 1)
	}
	if strings.HasPrefix(name, "icmpv6_") {
		name = strings.Replace(name, "icmpv6_", "icmp_", 1)
	}
	if strings.HasPrefix(name, "tun_ipv4_") {
		name = strings.Replace(name, "tun_ipv4_", "tun_", 1)
	}
	if strings.HasPrefix(name, "eth_") {
		name = strings.Replace(name, "eth_", "dl_", 1)
	}
	if name == "tcp_dst" || name == "tcp_src" {
		name = strings.Replace(name, "tcp_", "tp_", 1)
	}
	if name == "udp_dst" || name == "udp_src" {
		name = strings.Replace(name, "udp_", "tp_", 1)
	}
	if name == "sctp_dst" || name == "sctp_src" {
		name = strings.Replace(name, "sctp_", "tp_", 1)
	}
	if name == "vlan_vid" {
		name = "dl_vlan"
	}
	if name == "tunnel_id" {
		name = "tun_id"
	}
	return name
}

func (m *fieldMetadata) getActionNickname() string {
	name := strings.TrimPrefix(m.name, "NXM_OF_")
	name = strings.TrimPrefix(name, "NXM_NX_")
	name = strings.TrimPrefix(name, "OXM_OF_")
	name = strings.TrimPrefix(name, "OXM_PACKET_")
	name = strings.TrimPrefix(name, "OXM_FIELD_")
	name = strings.ToLower(name)
	if strings.HasPrefix(name, "ip_") && name != "ip_dscp" {
		name = strings.Replace(name, "ip_", "nw_", 1)
	}
	if strings.HasPrefix(name, "ipv4_") {
		name = strings.Replace(name, "ipv4_", "ip_", 1)
	}
	if strings.HasPrefix(name, "tun_ipv4_") {
		name = strings.Replace(name, "tun_ipv4_", "tun_", 1)
	}

	return name
}

var oxxFieldMetadataMap = map[uint16]map[uint8]*fieldMetadata{
	openflow15.OXM_CLASS_NXM_0: {
		openflow15.NXM_OF_IN_PORT:   &fieldMetadata{"NXM_OF_IN_PORT", 2},
		openflow15.NXM_OF_ETH_DST:   &fieldMetadata{"NXM_OF_ETH_DST", 6},
		openflow15.NXM_OF_ETH_SRC:   &fieldMetadata{"NXM_OF_ETH_SRC", 6},
		openflow15.NXM_OF_ETH_TYPE:  &fieldMetadata{"NXM_OF_ETH_TYPE", 2},
		openflow15.NXM_OF_VLAN_TCI:  &fieldMetadata{"NXM_OF_VLAN_TCI", 2},
		openflow15.NXM_OF_IP_TOS:    &fieldMetadata{"NXM_OF_IP_TOS", 1},
		openflow15.NXM_OF_IP_PROTO:  &fieldMetadata{"NXM_OF_IP_PROTO", 1},
		openflow15.NXM_OF_IP_SRC:    &fieldMetadata{"NXM_OF_IP_SRC", 4},
		openflow15.NXM_OF_IP_DST:    &fieldMetadata{"NXM_OF_IP_DST", 4},
		openflow15.NXM_OF_TCP_SRC:   &fieldMetadata{"NXM_OF_TCP_SRC", 2},
		openflow15.NXM_OF_TCP_DST:   &fieldMetadata{"NXM_OF_TCP_DST", 2},
		openflow15.NXM_OF_UDP_SRC:   &fieldMetadata{"NXM_OF_UDP_SRC", 2},
		openflow15.NXM_OF_UDP_DST:   &fieldMetadata{"NXM_OF_UDP_DST", 2},
		openflow15.NXM_OF_ICMP_TYPE: &fieldMetadata{"NXM_OF_ICMP_TYPE", 1},
		openflow15.NXM_OF_ICMP_CODE: &fieldMetadata{"NXM_OF_ICMP_CODE", 1},
		openflow15.NXM_OF_ARP_OP:    &fieldMetadata{"NXM_OF_ARP_OP", 2},
		openflow15.NXM_OF_ARP_SPA:   &fieldMetadata{"NXM_OF_ARP_SPA", 4},
		openflow15.NXM_OF_ARP_TPA:   &fieldMetadata{"NXM_OF_ARP_TPA", 4},
	},
	openflow15.OXM_CLASS_NXM_1: {
		openflow15.NXM_NX_REG0:          &fieldMetadata{"NXM_NX_REG0", 4},
		openflow15.NXM_NX_REG1:          &fieldMetadata{"NXM_NX_REG1", 4},
		openflow15.NXM_NX_REG2:          &fieldMetadata{"NXM_NX_REG2", 4},
		openflow15.NXM_NX_REG3:          &fieldMetadata{"NXM_NX_REG3", 4},
		openflow15.NXM_NX_REG4:          &fieldMetadata{"NXM_NX_REG4", 4},
		openflow15.NXM_NX_REG5:          &fieldMetadata{"NXM_NX_REG5", 4},
		openflow15.NXM_NX_REG6:          &fieldMetadata{"NXM_NX_REG6", 4},
		openflow15.NXM_NX_REG7:          &fieldMetadata{"NXM_NX_REG7", 4},
		openflow15.NXM_NX_REG8:          &fieldMetadata{"NXM_NX_REG8", 4},
		openflow15.NXM_NX_REG9:          &fieldMetadata{"NXM_NX_REG9", 4},
		openflow15.NXM_NX_REG10:         &fieldMetadata{"NXM_NX_REG10", 4},
		openflow15.NXM_NX_REG11:         &fieldMetadata{"NXM_NX_REG11", 4},
		openflow15.NXM_NX_REG12:         &fieldMetadata{"NXM_NX_REG12", 4},
		openflow15.NXM_NX_REG13:         &fieldMetadata{"NXM_NX_REG13", 4},
		openflow15.NXM_NX_REG14:         &fieldMetadata{"NXM_NX_REG14", 4},
		openflow15.NXM_NX_REG15:         &fieldMetadata{"NXM_NX_REG15", 4},
		openflow15.NXM_NX_TUN_ID:        &fieldMetadata{"NXM_NX_TUN_ID", 8},
		openflow15.NXM_NX_ARP_SHA:       &fieldMetadata{"NXM_NX_ARP_SHA", 6},
		openflow15.NXM_NX_ARP_THA:       &fieldMetadata{"NXM_NX_ARP_THA", 6},
		openflow15.NXM_NX_IPV6_SRC:      &fieldMetadata{"NXM_NX_IPV6_SRC", 16},
		openflow15.NXM_NX_IPV6_DST:      &fieldMetadata{"NXM_NX_IPV6_DST", 16},
		openflow15.NXM_NX_ICMPV6_TYPE:   &fieldMetadata{"NXM_NX_ICMPV6_TYPE", 1},
		openflow15.NXM_NX_ICMPV6_CODE:   &fieldMetadata{"NXM_NX_ICMPV6_CODE", 1},
		openflow15.NXM_NX_ND_TARGET:     &fieldMetadata{"NXM_NX_ND_TARGET", 16},
		openflow15.NXM_NX_ND_SLL:        &fieldMetadata{"NXM_NX_ND_SLL", 6},
		openflow15.NXM_NX_ND_TLL:        &fieldMetadata{"NXM_NX_ND_TLL", 6},
		openflow15.NXM_NX_IP_FRAG:       &fieldMetadata{"NXM_NX_IP_FRAG", 1},
		openflow15.NXM_NX_IPV6_LABEL:    &fieldMetadata{"NXM_NX_IPV6_LABEL", 1},
		openflow15.NXM_NX_IP_ECN:        &fieldMetadata{"NXM_NX_IP_ECN", 1},
		openflow15.NXM_NX_IP_TTL:        &fieldMetadata{"NXM_NX_IP_TTL", 1},
		openflow15.NXM_NX_MPLS_TTL:      &fieldMetadata{"NXM_NX_MPLS_TTL", 1},
		openflow15.NXM_NX_TUN_IPV4_SRC:  &fieldMetadata{"NXM_NX_TUN_IPV4_SRC", 4},
		openflow15.NXM_NX_TUN_IPV4_DST:  &fieldMetadata{"NXM_NX_TUN_IPV4_DST", 4},
		openflow15.NXM_NX_PKT_MARK:      &fieldMetadata{"NXM_NX_PKT_MARK", 4},
		openflow15.NXM_NX_TCP_FLAGS:     &fieldMetadata{"NXM_NX_TCP_FLAGS", 2},
		openflow15.NXM_NX_CONJ_ID:       &fieldMetadata{"NXM_NX_CONJ_ID", 4},
		openflow15.NXM_NX_TUN_GBP_ID:    &fieldMetadata{"NXM_NX_TUN_GBP_ID", 2},
		openflow15.NXM_NX_TUN_GBP_FLAGS: &fieldMetadata{"NXM_NX_TUN_GBP_FLAGS", 1},
		openflow15.NXM_NX_TUN_FLAGS:     &fieldMetadata{"NXM_NX_TUN_FLAGS", 2},
		openflow15.NXM_NX_CT_STATE:      &fieldMetadata{"NXM_NX_CT_STATE", 4},
		openflow15.NXM_NX_CT_ZONE:       &fieldMetadata{"NXM_NX_CT_ZONE", 2},
		openflow15.NXM_NX_CT_MARK:       &fieldMetadata{"NXM_NX_CT_MARK", 4},
		openflow15.NXM_NX_CT_LABEL:      &fieldMetadata{"NXM_NX_CT_LABEL", 16},
		openflow15.NXM_NX_TUN_IPV6_SRC:  &fieldMetadata{"NXM_NX_TUN_IPV6_SRC", 16},
		openflow15.NXM_NX_TUN_IPV6_DST:  &fieldMetadata{"NXM_NX_TUN_IPV6_DST", 16},
		openflow15.NXM_NX_CT_NW_PROTO:   &fieldMetadata{"NXM_NX_CT_NW_PROTO", 1},
		openflow15.NXM_NX_CT_NW_SRC:     &fieldMetadata{"NXM_NX_CT_NW_SRC", 4},
		openflow15.NXM_NX_CT_NW_DST:     &fieldMetadata{"NXM_NX_CT_NW_DST", 4},
		openflow15.NXM_NX_CT_IPV6_SRC:   &fieldMetadata{"NXM_NX_CT_IPV6_SRC", 16},
		openflow15.NXM_NX_CT_IPV6_DST:   &fieldMetadata{"NXM_NX_CT_IPV6_DST", 16},
		openflow15.NXM_NX_CT_TP_SRC:     &fieldMetadata{"NXM_NX_CT_TP_SRC", 2},
		openflow15.NXM_NX_CT_TP_DST:     &fieldMetadata{"NXM_NX_CT_TP_DST", 2},
		openflow15.NXM_NX_TUN_METADATA0: &fieldMetadata{"NXM_NX_TUN_METADATA0", 128},
		openflow15.NXM_NX_TUN_METADATA1: &fieldMetadata{"NXM_NX_TUN_METADATA1", 128},
		openflow15.NXM_NX_TUN_METADATA2: &fieldMetadata{"NXM_NX_TUN_METADATA2", 128},
		openflow15.NXM_NX_TUN_METADATA3: &fieldMetadata{"NXM_NX_TUN_METADATA3", 128},
		openflow15.NXM_NX_TUN_METADATA4: &fieldMetadata{"NXM_NX_TUN_METADATA4", 128},
		openflow15.NXM_NX_TUN_METADATA5: &fieldMetadata{"NXM_NX_TUN_METADATA5", 128},
		openflow15.NXM_NX_TUN_METADATA6: &fieldMetadata{"NXM_NX_TUN_METADATA6", 128},
		openflow15.NXM_NX_TUN_METADATA7: &fieldMetadata{"NXM_NX_TUN_METADATA7", 128},
		openflow15.NXM_NX_XXREG0:        &fieldMetadata{"NXM_NX_XXREG0", 16},
		openflow15.NXM_NX_XXREG1:        &fieldMetadata{"NXM_NX_XXREG1", 16},
		openflow15.NXM_NX_XXREG2:        &fieldMetadata{"NXM_NX_XXREG2", 16},
		openflow15.NXM_NX_XXREG3:        &fieldMetadata{"NXM_NX_XXREG3", 16},
	},
	openflow15.OXM_CLASS_OPENFLOW_BASIC: {
		openflow15.OXM_FIELD_IN_PORT:        &fieldMetadata{"OXM_OF_IN_PORT", 4},
		openflow15.OXM_FIELD_IN_PHY_PORT:    &fieldMetadata{"OXM_OF_IN_PHY_PORT", 4},
		openflow15.OXM_FIELD_METADATA:       &fieldMetadata{"OXM_OF_METADATA", 8},
		openflow15.OXM_FIELD_ETH_DST:        &fieldMetadata{"OXM_OF_ETH_DST", 6},
		openflow15.OXM_FIELD_ETH_SRC:        &fieldMetadata{"OXM_OF_ETH_SRC", 6},
		openflow15.OXM_FIELD_ETH_TYPE:       &fieldMetadata{"OXM_OF_ETH_TYPE", 2},
		openflow15.OXM_FIELD_VLAN_VID:       &fieldMetadata{"OXM_OF_VLAN_VID", 2},
		openflow15.OXM_FIELD_VLAN_PCP:       &fieldMetadata{"OXM_OF_VLAN_PCP", 1},
		openflow15.OXM_FIELD_IP_DSCP:        &fieldMetadata{"OXM_OF_IP_DSCP", 1},
		openflow15.OXM_FIELD_IP_ECN:         &fieldMetadata{"OXM_OF_IP_ECN", 1},
		openflow15.OXM_FIELD_IP_PROTO:       &fieldMetadata{"OXM_OF_IP_PROTO", 1},
		openflow15.OXM_FIELD_IPV4_SRC:       &fieldMetadata{"OXM_OF_IPV4_SRC", 4},
		openflow15.OXM_FIELD_IPV4_DST:       &fieldMetadata{"OXM_OF_IPV4_DST", 4},
		openflow15.OXM_FIELD_TCP_SRC:        &fieldMetadata{"OXM_OF_TCP_SRC", 2},
		openflow15.OXM_FIELD_TCP_DST:        &fieldMetadata{"OXM_OF_TCP_DST", 2},
		openflow15.OXM_FIELD_UDP_SRC:        &fieldMetadata{"OXM_OF_UDP_SRC", 2},
		openflow15.OXM_FIELD_UDP_DST:        &fieldMetadata{"OXM_OF_UDP_DST", 2},
		openflow15.OXM_FIELD_SCTP_SRC:       &fieldMetadata{"OXM_OF_SCTP_SRC", 2},
		openflow15.OXM_FIELD_SCTP_DST:       &fieldMetadata{"OXM_OF_SCTP_DST", 2},
		openflow15.OXM_FIELD_ICMPV4_TYPE:    &fieldMetadata{"OXM_OF_ICMPV4_TYPE", 1},
		openflow15.OXM_FIELD_ICMPV4_CODE:    &fieldMetadata{"OXM_OF_ICMPV4_CODE", 1},
		openflow15.OXM_FIELD_ARP_OP:         &fieldMetadata{"OXM_OF_ARP_OP", 2},
		openflow15.OXM_FIELD_ARP_SPA:        &fieldMetadata{"OXM_OF_ARP_SPA", 4},
		openflow15.OXM_FIELD_ARP_TPA:        &fieldMetadata{"OXM_OF_ARP_TPA", 4},
		openflow15.OXM_FIELD_ARP_SHA:        &fieldMetadata{"OXM_OF_ARP_SHA", 6},
		openflow15.OXM_FIELD_ARP_THA:        &fieldMetadata{"OXM_OF_ARP_THA", 6},
		openflow15.OXM_FIELD_IPV6_SRC:       &fieldMetadata{"OXM_OF_IPV6_SRC", 16},
		openflow15.OXM_FIELD_IPV6_DST:       &fieldMetadata{"OXM_OF_IPV6_DST", 16},
		openflow15.OXM_FIELD_IPV6_FLABEL:    &fieldMetadata{"OXM_OF_IPV6_FLABEL", 4},
		openflow15.OXM_FIELD_ICMPV6_TYPE:    &fieldMetadata{"OXM_OF_ICMPV6_TYPE", 1},
		openflow15.OXM_FIELD_ICMPV6_CODE:    &fieldMetadata{"OXM_OF_ICMPV6_CODE", 1},
		openflow15.OXM_FIELD_IPV6_ND_TARGET: &fieldMetadata{"OXM_OF_IPV6_ND_TARGET", 16},
		openflow15.OXM_FIELD_IPV6_ND_SLL:    &fieldMetadata{"OXM_OF_IPV6_ND_SLL", 6},
		openflow15.OXM_FIELD_IPV6_ND_TLL:    &fieldMetadata{"OXM_OF_IPV6_ND_TLL", 6},
		openflow15.OXM_FIELD_MPLS_LABEL:     &fieldMetadata{"OXM_OF_MPLS_LABEL", 4},
		openflow15.OXM_FIELD_MPLS_TC:        &fieldMetadata{"OXM_OF_MPLS_TC", 1},
		openflow15.OXM_FIELD_MPLS_BOS:       &fieldMetadata{"OXM_OF_MPLS_BOS", 1},
		openflow15.OXM_FIELD_PBB_ISID:       &fieldMetadata{"OXM_OF_PBB_ISID", 3},
		openflow15.OXM_FIELD_TUNNEL_ID:      &fieldMetadata{"OXM_OF_TUNNEL_ID", 8},
		openflow15.OXM_FIELD_IPV6_EXTHDR:    &fieldMetadata{"OXM_OF_IPV6_EXTHDR", 2},
		openflow15.OXM_FIELD_TCP_FLAGS:      &fieldMetadata{"OXM_FIELD_TCP_FLAGS", 2},
	},
}

func getFieldNameString(class uint16, field uint8, offset, length uint16, nickName bool, usedForMatching bool) string {
	fieldInfo := oxxFieldMetadataMap[class][field]
	if nickName {
		if usedForMatching {
			return fieldInfo.getMatchNickname()
		} else {
			return fieldInfo.getActionNickname()
		}
	}

	if offset == 0 && (length == 0 || length == uint16(fieldInfo.length)*8) {
		return fmt.Sprintf("%s[]", fieldInfo.name)
	} else if length > 1 && length < uint16(fieldInfo.length)*8 {
		return fmt.Sprintf("%s[%d..%d]", fieldInfo.name, offset, offset+length-1)
	} else if length == 1 {
		return fmt.Sprintf("%s[%d]", fieldInfo.name, offset)
	} else {
		return ""
	}
}

func matchPktMarkToString(field *openflow15.MatchField) string {
	return fmt.Sprintf("pkt_mark=%s", getFieldDataString(field))
}

func matchConjIdToString(field *openflow15.MatchField) string {
	return fmt.Sprintf("conj_id=%d", field.Value.(*openflow15.Uint32Message).Data)
}

func matchCtStateToString(field *openflow15.MatchField) string {
	data := field.Value.(*openflow15.Uint32Message).Data
	mask := field.Mask.(*openflow15.Uint32Message).Data
	allCtStates := map[int]string{
		0: "new",
		1: "est",
		2: "rel",
		3: "rpl",
		4: "inv",
		5: "trk",
		6: "snat",
		7: "dnat",
	}
	var ctStateStrs []string
	for offset := 0; offset <= 7; offset++ {
		v := uint32(1) << offset
		if mask&v == v {
			if data&v == v {
				ctStateStrs = append(ctStateStrs, "+"+allCtStates[offset])
			} else {
				ctStateStrs = append(ctStateStrs, "-"+allCtStates[offset])
			}
		}
	}
	return fmt.Sprintf("ct_state=%s", strings.Join(ctStateStrs, ""))
}

func matchCtMarkToString(field *openflow15.MatchField) string {
	return fmt.Sprintf("ct_mark=%s", getFieldDataString(field))
}

func matchCtLabelToString(field *openflow15.MatchField) string {
	return fmt.Sprintf("ct_label=%s", getFieldDataString(field))
}

func matchCtNwProtoToString(field *openflow15.MatchField) string {
	return fmt.Sprintf("ct_nw_proto=%s", getFieldDataString(field))
}

func matchProtoToString(etherType, ipProto *openflow15.MatchField) string {
	etherTypeValue := etherType.Value.(*openflow15.EthTypeField).EthType
	var ipProtoValue uint8
	if ipProto != nil {
		ipProtoValue = ipProto.Value.(*openflow15.IpProtoField).Protocol
	}

	var str string
	switch ipProtoValue {
	case 0:
		switch etherTypeValue {
		case 0x0800:
			str = "ip"
		case 0x86dd:
			str = "ipv6"
		case 0x0806:
			str = "arp"
		}
	case 6:
		switch etherTypeValue {
		case 0x0800:
			str = "tcp"
		case 0x86dd:
			str = "tcp6"
		}
	case 17:
		switch etherTypeValue {
		case 0x0800:
			str = "udp"
		case 0x86dd:
			str = "udp6"
		}
	case 132:
		switch etherTypeValue {
		case 0x0800:
			str = "sctp"
		case 0x86dd:
			str = "sctp6"
		}
	case 1:
		switch etherTypeValue {
		case 0x0800:
			str = "icmp"
		}
	case 58:
		switch etherTypeValue {
		case 0x86dd:
			str = "icmp6"
		}
	case 2:
		switch etherTypeValue {
		case 0x0800:
			str = "igmp"
		}
	}
	return str
}

func matchRegToString(idx int, field *openflow15.MatchField) string {
	return fmt.Sprintf("reg%d=%s", idx, getFieldDataString(field))
}

func matchXXRegToString(idx int, field *openflow15.MatchField) string {
	return fmt.Sprintf("xxreg%d=%s", idx, getFieldDataString(field))
}

func matchInPortToString(field *openflow15.MatchField) string {
	return fmt.Sprintf("in_port=%s", getFieldDataString(field))
}

func matchVlanToString(field *openflow15.MatchField) string {
	value := field.Value.(*openflow15.VlanIdField).VlanId
	mask := uint16(openflow15.OFPVID_PRESENT)
	if field.HasMask {
		mask |= field.Mask.(*openflow15.VlanIdField).VlanId
	}
	if mask == (protocol.VID_MASK | openflow15.OFPVID_PRESENT) {
		return fmt.Sprintf("dl_vlan=%d", value&protocol.VID_MASK)
	}
	return fmt.Sprintf("vlan_tci=0x%04x/0x%04x", value&openflow15.OFPVID_PRESENT, mask&openflow15.OFPVID_PRESENT)
}

func matchIpAddrToString(field *openflow15.MatchField, isCt, isSrc, isIPv6 bool) string {
	var matchKey string
	if isCt {
		matchKey = "ct_"
	}
	if isIPv6 {
		matchKey += "ipv6_"
	} else {
		matchKey += "nw_"
	}
	if isSrc {
		matchKey += "src"
	} else {
		matchKey += "dst"
	}
	return fmt.Sprintf("%s=%s", matchKey, getFieldDataString(field))
}

func matchTunDstToString(field *openflow15.MatchField, isIPv6 bool) string {
	matchKey := "tun_dst"
	if isIPv6 {
		matchKey = "tun_ipv6_dst"
	}
	return fmt.Sprintf("%s=%s", matchKey, getFieldDataString(field))
}

func matchTunIDToString(field *openflow15.MatchField) string {
	return fmt.Sprintf("tun_id=%s", getFieldDataString(field))
}

func matchNwTosToString(field *openflow15.MatchField) string {
	return fmt.Sprintf("nw_tos=%s", getFieldDataString(field))
}

func matchIpDscpToString(field *openflow15.MatchField) string {
	return fmt.Sprintf("ip_dscp=%d", field.Value.(*openflow15.IpDscpField).Dscp)
}

func matchTpPortToString(field *openflow15.MatchField, isCt, isSrc bool) string {
	var matchKey string
	if isCt {
		matchKey = "ct_"
	}
	matchKey += "tp_"
	if isSrc {
		matchKey += "src"
	} else {
		matchKey += "dst"
	}
	return fmt.Sprintf("%s=%s", matchKey, getFieldDataString(field))
}

func matchEtherAddrToString(field *openflow15.MatchField, isSrc bool) string {
	var matchKey string
	if isSrc {
		matchKey = "dl_src"
	} else {
		matchKey = "dl_dst"
	}
	return fmt.Sprintf("%s=%s", matchKey, getFieldDataString(field))
}

func matchArpPaAddrToString(field *openflow15.MatchField, isSrc bool) string {
	var matchKey string
	if isSrc {
		matchKey = "arp_spa"
	} else {
		matchKey = "arp_tpa"
	}
	return fmt.Sprintf("%s=%s", matchKey, getFieldDataString(field))
}

func matchArpHaAddrToString(field *openflow15.MatchField, isSrc bool) string {
	var matchKey string
	if isSrc {
		matchKey = "arp_sha"
	} else {
		matchKey = "arp_tha"
	}
	return fmt.Sprintf("%s=%s", matchKey, getFieldDataString(field))
}

func matchArpOpToString(field *openflow15.MatchField) string {
	return fmt.Sprintf("arp_op=%s", getFieldDataString(field))
}

func matchIcmpTypeToString(field *openflow15.MatchField) string {
	return fmt.Sprintf("icmp_type=%s", getFieldDataString(field))
}

func matchIcmpCodeToString(field *openflow15.MatchField) string {
	return fmt.Sprintf("icmp_code=%s", getFieldDataString(field))
}

func trimLeadingZero(s string) string {
	str := strings.TrimLeft(s, "0")
	if str == "" {
		return "0"
	}
	return str
}

func getFieldDataString(field *openflow15.MatchField) string {
	value, mask := field.Value, field.Mask
	var fieldStr string
	switch value.(type) {
	case *util.Buffer:
		fieldStr = fmt.Sprintf("0x%s", trimLeadingZero(fmt.Sprintf("%x", value.(*util.Buffer).Bytes())))
		if mask != nil {
			fieldStr = fmt.Sprintf("%s/0x%s", fieldStr, trimLeadingZero(fmt.Sprintf("%x", mask.(*util.Buffer).Bytes())))
		}
	case *openflow15.ByteArrayField:
		fieldStr = fmt.Sprintf("0x%s", trimLeadingZero(fmt.Sprintf("%x", value.(*openflow15.ByteArrayField).Data)))
		if mask != nil {
			fieldStr = fmt.Sprintf("%s/0x%s", fieldStr, trimLeadingZero(fmt.Sprintf("%x", mask.(*openflow15.ByteArrayField).Data)))
		}
	case *openflow15.Uint32Message:
		fieldStr = fmt.Sprintf("0x%x", value.(*openflow15.Uint32Message).Data)
		if mask != nil && mask.(*openflow15.Uint32Message).Data != 0xffffffff {
			fieldStr = fmt.Sprintf("%s/0x%x", fieldStr, mask.(*openflow15.Uint32Message).Data)
		}
	case *openflow15.CTLabel:
		fieldStr = fmt.Sprintf("0x%s", trimLeadingZero(fmt.Sprintf("%x", value.(*openflow15.CTLabel).Data)))
		if mask != nil && mask.(*openflow15.CTLabel).Data != [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff} {
			fieldStr = fmt.Sprintf("%s/0x%s", fieldStr, trimLeadingZero(fmt.Sprintf("%x", mask.(*openflow15.CTLabel).Data)))
		}
	case *openflow15.PortField:
		fieldStr = fmt.Sprintf("%d", value.(*openflow15.PortField).Port)
		if mask != nil && mask.(*openflow15.PortField).Port != 0xffff {
			fieldStr = fmt.Sprintf("0x%x/0x%x", value.(*openflow15.PortField).Port, mask.(*openflow15.PortField).Port)
		}
	case *ofctrl.PortField:
		fieldStr = fmt.Sprintf("%d", value.(*ofctrl.PortField).Port)
		if mask != nil && mask.(*ofctrl.PortField).Port != 0xffff {
			fieldStr = fmt.Sprintf("0x%x/0x%x", value.(*ofctrl.PortField).Port, mask.(*ofctrl.PortField).Port)
		}
	case *ofctrl.ProtocolField:
		fieldStr = fmt.Sprintf("%d", value.(*ofctrl.ProtocolField).Protocol)
	case *openflow15.IpDscpField:
		fieldStr = fmt.Sprintf("%d", value.(*openflow15.IpDscpField).Dscp)
	case *openflow15.EthSrcField:
		fieldStr = value.(*openflow15.EthSrcField).EthSrc.String()
	case *openflow15.EthDstField:
		fieldStr = value.(*openflow15.EthDstField).EthDst.String()
	case *openflow15.ArpXHaField:
		fieldStr = value.(*openflow15.ArpXHaField).ArpHa.String()
	case *openflow15.ArpXPaField:
		fieldStr = value.(*openflow15.ArpXPaField).ArpPa.String()
	case *openflow15.Ipv4SrcField:
		fieldStr = value.(*openflow15.Ipv4SrcField).Ipv4Src.String()
		if mask != nil {
			prefix, _ := net.IPMask(mask.(*openflow15.Ipv4SrcField).Ipv4Src).Size()
			if prefix < 32 {
				fieldStr = fmt.Sprintf("%s/%d", fieldStr, prefix)
			}
		}
	case *openflow15.Ipv4DstField:
		fieldStr = value.(*openflow15.Ipv4DstField).Ipv4Dst.String()
		if mask != nil {
			prefix, _ := net.IPMask(mask.(*openflow15.Ipv4DstField).Ipv4Dst).Size()
			if prefix < 32 {
				fieldStr = fmt.Sprintf("%s/%d", fieldStr, prefix)
			}
		}
	case *openflow15.Ipv6SrcField:
		fieldStr = value.(*openflow15.Ipv6SrcField).Ipv6Src.String()
		if mask != nil {
			prefix, _ := net.IPMask(mask.(*openflow15.Ipv6SrcField).Ipv6Src).Size()
			if prefix < 128 {
				fieldStr = fmt.Sprintf("%s/%d", fieldStr, prefix)
			}
		}
	case *openflow15.Ipv6DstField:
		fieldStr = value.(*openflow15.Ipv6DstField).Ipv6Dst.String()
		if mask != nil {
			prefix, _ := net.IPMask(mask.(*openflow15.Ipv6DstField).Ipv6Dst).Size()
			if prefix < 128 {
				fieldStr = fmt.Sprintf("%s/%d", fieldStr, prefix)
			}
		}
	case *openflow15.TunnelIpv4DstField:
		fieldStr = value.(*openflow15.TunnelIpv4DstField).TunnelIpv4Dst.String()
	case *openflow15.TunnelIdField:
		fieldStr = fmt.Sprintf("%d", value.(*openflow15.TunnelIdField).TunnelId)
	case *openflow15.VlanIdField:
		fieldStr = fmt.Sprintf("%d", value.(*openflow15.VlanIdField).VlanId)
	case *openflow15.ArpOperField:
		fieldStr = fmt.Sprintf("%d", value.(*openflow15.ArpOperField).ArpOper)
	case *openflow15.MatchField:
		fieldStr = fmt.Sprintf("0x%x", value.(*openflow15.MatchField).Value)
		if mask != nil {
			fieldStr = fmt.Sprintf("%s/0x%x", fieldStr, mask.(*openflow15.MatchField).Value)
		}
	case *openflow15.InPortField:
		fieldStr = fmt.Sprintf("%d", value.(*openflow15.InPortField).InPort)
	case *openflow15.IcmpTypeField:
		fieldStr = fmt.Sprintf("%d", value.(*openflow15.IcmpTypeField).Type)
	case *openflow15.IcmpCodeField:
		fieldStr = fmt.Sprintf("%d", value.(*openflow15.IcmpCodeField).Code)
	}
	return fieldStr
}

func actionOutputToString(action openflow15.Action) string {
	a := action.(*openflow15.ActionOutput)
	var actionStr string
	switch a.Port {
	case openflow15.P_IN_PORT:
		actionStr = "IN_PORT"
	case openflow15.P_NORMAL:
		actionStr = "NORMAL"
	default:
		actionStr = fmt.Sprintf("output:%d", a.Port)
	}
	return actionStr
}

func actionPopVlanToString(action openflow15.Action) string {
	return "pop_vlan"
}

func actionPushToString(action openflow15.Action) string {
	return fmt.Sprintf("push_vlan:0x%x", action.(*openflow15.ActionPush).EtherType)
}

func actionCopyFieldToString(action openflow15.Action) string {
	a := action.(*openflow15.ActionCopyField)
	srcFieldStr := getFieldNameString(a.OxmIdSrc.Class, a.OxmIdSrc.Field, a.SrcOffset, a.NBits, false, false)
	dstFieldStr := getFieldNameString(a.OxmIdDst.Class, a.OxmIdDst.Field, a.DstOffset, a.NBits, false, false)
	actionStr := fmt.Sprintf("move:%s->%s", srcFieldStr, dstFieldStr)
	return actionStr
}

func actionSetFieldToString(action openflow15.Action) string {
	a := action.(*openflow15.ActionSetField)
	fieldNameStr := getFieldNameString(a.Field.Class, a.Field.Field, 0, 0, true, false)
	fieldDataStr := getFieldDataString(&a.Field)
	actionStr := fmt.Sprintf("set_field:%s->%s", fieldDataStr, fieldNameStr)
	return actionStr
}

func actionMeterToString(action openflow15.Action) string {
	a := action.(*openflow15.ActionMeter)
	actionStr := fmt.Sprintf("meter:%d", a.MeterId)
	return actionStr
}

func nxActionOutputRegToString(action openflow15.Action) string {
	a := action.(*openflow15.NXActionOutputReg)
	offset := a.OfsNbits >> 6
	length := a.OfsNbits&0x3f + 1
	actionStr := fmt.Sprintf("output:%s", getFieldNameString(a.SrcField.Class, a.SrcField.Field, offset, length, false, false))
	return actionStr
}

func nxActionConnTrackToString(action openflow15.Action) string {
	a := action.(*openflow15.NXActionConnTrack)
	var parts []string
	if a.Flags&openflow15.NX_CT_F_FORCE == openflow15.NX_CT_F_FORCE {
		parts = append(parts, "commit")
	}
	if a.Flags&openflow15.NX_CT_F_COMMIT == openflow15.NX_CT_F_COMMIT {
		parts = append(parts, "commit")
	}
	if a.RecircTable != 0 {
		if tableName, ok := TableNameCache[a.RecircTable]; ok {
			parts = append(parts, fmt.Sprintf("table=%s", tableName))
		} else {
			parts = append(parts, fmt.Sprintf("table=%d", a.RecircTable))
		}
	}
	if a.ZoneSrc == 0 {
		parts = append(parts, fmt.Sprintf("zone=%d", a.ZoneOfsNbits))
	} else {
		class := uint16(a.ZoneSrc >> 16)
		field := uint8(a.ZoneSrc & 0xffff >> 9)
		offset := a.ZoneOfsNbits >> 6
		length := a.ZoneOfsNbits&0x3f + 1
		fieldStr := getFieldNameString(class, field, offset, length, false, false)
		parts = append(parts, fmt.Sprintf("zone=%s", fieldStr))
	}

	var ctExecActionStrs []string
	for _, ctAction := range a.Actions {
		switch ctAction.(type) {
		case *openflow15.ActionSetField:
			ctExecActionStrs = append(ctExecActionStrs, actionSetFieldToString(ctAction))
		case *openflow15.ActionCopyField:
			ctExecActionStrs = append(ctExecActionStrs, actionCopyFieldToString(ctAction))
		case *openflow15.NXActionCTNAT:
			parts = append(parts, nxActionCTNATToString(ctAction))
		}
	}
	if len(ctExecActionStrs) != 0 {
		parts = append(parts, fmt.Sprintf("exec(%s)", strings.Join(ctExecActionStrs, ",")))
	}
	return fmt.Sprintf("ct(%s)", strings.Join(parts, ","))
}

func nxActionCTNATToString(action openflow15.Action) string {
	a := action.(*openflow15.NXActionCTNAT)
	var parts []string
	var ipRange []net.IP
	if a.RangeIPv4Min != nil {
		ipRange = append(ipRange, a.RangeIPv4Min)
		if a.RangeIPv4Max != nil {
			ipRange = append(ipRange, a.RangeIPv4Max)
		}
	} else if a.RangeIPv6Min != nil {
		ipRange = append(ipRange, a.RangeIPv6Min)
		if a.RangeIPv6Max != nil {
			ipRange = append(ipRange, a.RangeIPv6Max)
		}
	}
	hasPortRange := a.RangeProtoMin != nil || a.RangeProtoMax != nil

	var ipRangeStr string
	if len(ipRange) > 0 {
		if len(ipRange) == 1 || len(ipRange) == 2 && ipRange[0].Equal(ipRange[1]) {
			ipRangeStr = ipRange[0].String()
		} else {
			ipRangeStr = fmt.Sprintf("%s-%s", ipRange[0], ipRange[1])
		}
		if ipRange[0].To4() == nil && hasPortRange {
			ipRangeStr = fmt.Sprintf("[%s]", ipRangeStr)
		}
	}
	var portRangeStr string
	if a.RangeProtoMin != nil || a.RangeProtoMax != nil {
		if a.RangeProtoMin != nil && a.RangeIPv4Max == nil ||
			a.RangeProtoMin != nil && a.RangeIPv4Max != nil && *a.RangeProtoMin == *a.RangeProtoMax {
			portRangeStr = fmt.Sprintf(":%d", *a.RangeProtoMin)
		} else {
			portRangeStr = fmt.Sprintf(":%d-%d", *a.RangeProtoMin, *a.RangeProtoMax)
		}
	}
	if a.Flags&openflow15.NX_NAT_F_SRC == openflow15.NX_NAT_F_SRC {
		parts = append(parts, fmt.Sprintf("src=%s%s", ipRangeStr, portRangeStr))
	} else if a.Flags&openflow15.NX_NAT_F_DST == openflow15.NX_NAT_F_DST {
		parts = append(parts, fmt.Sprintf("dst=%s%s", ipRangeStr, portRangeStr))
	}

	if a.Flags&openflow15.NX_NAT_F_PERSISTENT == openflow15.NX_NAT_F_PERSISTENT {
		parts = append(parts, "persistent")
	}
	if a.Flags&openflow15.NX_NAT_F_PROTO_RANDOM == openflow15.NX_NAT_F_PROTO_RANDOM {
		parts = append(parts, "random")
	} else if a.Flags&openflow15.NX_NAT_F_PROTO_HASH == openflow15.NX_NAT_F_PROTO_HASH {
		parts = append(parts, "hash")
	}

	actionStr := "nat"
	if len(parts) != 0 {
		actionStr = fmt.Sprintf("%s(%s)", actionStr, strings.Join(parts, ","))
	}
	return actionStr
}

func nxActionResubmitTableToString(action openflow15.Action) string {
	a := action.(*openflow15.NXActionResubmitTable)
	if tableName, ok := TableNameCache[a.TableID]; ok {
		return fmt.Sprintf("resubmit:%s", tableName)
	} else {
		return fmt.Sprintf("resubmit:%d", a.TableID)
	}
}

func nxActionDecTTLToString(action openflow15.Action) string {
	return "dec_ttl"
}

func nxActionConjunctionToString(action openflow15.Action) string {
	a := action.(*openflow15.NXActionConjunction)
	actionStr := fmt.Sprintf("conjunction(%d,%d/%d)", a.ID, a.Clause+1, a.NClause)
	return actionStr
}

func nxActionGroupToString(action openflow15.Action) string {
	a := action.(*openflow15.ActionGroup)
	actionStr := fmt.Sprintf("group:%d", a.GroupId)
	return actionStr
}

func nxActionNoteToString(action openflow15.Action) string {
	a := action.(*openflow15.NXActionNote)
	data := make([]byte, 12)

	for i := 0; i < len(a.Note); i++ {
		data[11-i] = a.Note[len(a.Note)-1-i]
	}
	for i := 0; i < 12-len(a.Note); i++ {
		data[i] = '0'
	}
	var parts []string
	for i := 0; i < 12; i += 2 {
		parts = append(parts, string(data[i:i+2]))
	}

	actionStr := fmt.Sprintf("note:%s", strings.Join(parts, ":"))
	return actionStr
}

func nxActionControllerToString(action openflow15.Action) string {
	a := action.(*openflow15.NXActionController)
	reasonMap := map[uint8]string{
		0: "no_match",
		1: "action",
		2: "invalid_ttl",
		3: "action_set",
		4: "group",
		5: "packet_out",
	}
	parts := []string{fmt.Sprintf("reason=%s", reasonMap[a.Reason]),
		fmt.Sprintf("max_len=%d", a.MaxLen),
		fmt.Sprintf("id=%d", a.ControllerID)}

	actionStr := fmt.Sprintf("controller(%s)", strings.Join(parts, ","))
	return actionStr
}

func nxActionController2ToString(action openflow15.Action) string {
	a := action.(*openflow15.NXActionController2)
	reasonMap := map[uint8]string{
		0: "no_match",
		1: "action",
		2: "invalid_ttl",
		3: "action_set",
		4: "group",
		5: "packet_out",
	}
	var parts []string
	actionBytes, _ := a.MarshalBinary()
	n := openflow15.NxActionHeaderLength + 6 // Add padding
	for n < int(a.Length) {
		p, err := openflow15.DecodeController2Prop(actionBytes[n:])
		if err != nil {
			return ""
		}
		switch v := p.(type) {
		case *openflow15.NXActionController2PropReason:
			parts = append(parts, fmt.Sprintf("reason=%s", reasonMap[v.Reason]))
		case *openflow15.NXActionController2PropMaxLen:
			parts = append(parts, fmt.Sprintf("max_len=%d", v.MaxLen))
		case *openflow15.NXActionController2PropControllerID:
			parts = append(parts, fmt.Sprintf("id=%d", v.ControllerID))
		case *openflow15.NXActionController2PropUserdata:
			convert := func(bytes []byte) string {
				s := make([]string, len(bytes))
				for i, b := range bytes {
					s[i] = fmt.Sprintf("%.2x", b)
				}
				return strings.Join(s, ".")
			}
			parts = append(parts, fmt.Sprintf("userdata=%s", convert(v.Userdata)))
		}
		n += int(p.Len())
	}
	actionStr := fmt.Sprintf("controller(%s)", strings.Join(parts, ","))
	return actionStr
}

func nxActionLearnToString(action openflow15.Action) string {
	a := action.(*openflow15.NXActionLearn)
	var parts []string
	if tableName, ok := TableNameCache[a.TableID]; ok {
		parts = append(parts, fmt.Sprintf("table=%s", tableName))
	} else {
		parts = append(parts, fmt.Sprintf("table=%d", a.TableID))
	}
	if a.IdleTimeout != 0 {
		parts = append(parts, fmt.Sprintf("idle_timeout=%d", a.IdleTimeout))
	}
	if a.HardTimeout != 0 {
		parts = append(parts, fmt.Sprintf("hard_timeout=%d", a.HardTimeout))
	}
	if a.FinIdleTimeout != 0 {
		parts = append(parts, fmt.Sprintf("fin_idle_timeout=%d", a.FinIdleTimeout))
	}
	if a.FinHardTimeout != 0 {
		parts = append(parts, fmt.Sprintf("fin_hard_timeout=%d", a.FinHardTimeout))
	}
	parts = append(parts, fmt.Sprintf("priority=%d", a.Priority))
	if a.Flags&openflow15.NX_LEARN_F_DELETE_LEARNED == openflow15.NX_LEARN_F_DELETE_LEARNED {
		parts = append(parts, "delete_learned")
	}
	if a.Cookie != 0 {
		parts = append(parts, fmt.Sprintf("cookie=0x%x", a.Cookie))
	}
	if len(a.LearnSpecs) != 0 {
		for _, spec := range a.LearnSpecs {
			nBits := spec.Header.NBits
			isLoad := spec.Header.Dst == true
			isMatch := spec.Header.Dst == false
			//TODO: add isOutput

			if spec.SrcValue != nil {
				srcValueStr := strings.TrimLeft(fmt.Sprintf("%x", spec.SrcValue), "0")
				if isMatch {
					var dstFieldStr string
					if spec.DstField.Field.Class == openflow15.OXM_CLASS_NXM_1 {
						dstFieldStr = getFieldNameString(spec.DstField.Field.Class, spec.DstField.Field.Field, spec.DstField.Ofs, nBits, false, true)
					} else {
						dstFieldStr = getFieldNameString(spec.DstField.Field.Class, spec.DstField.Field.Field, spec.DstField.Ofs, nBits, true, false)
					}
					parts = append(parts, fmt.Sprintf("%s=0x%s", dstFieldStr, srcValueStr))
				} else if isLoad {
					dstFieldStr := getFieldNameString(spec.DstField.Field.Class, spec.DstField.Field.Field, spec.DstField.Ofs, nBits, false, false)
					parts = append(parts, fmt.Sprintf("load:0x%s->%s", srcValueStr, dstFieldStr))
				}
			} else {
				srcFieldStr := getFieldNameString(spec.SrcField.Field.Class, spec.SrcField.Field.Field, spec.SrcField.Ofs, nBits, false, false)
				dstFieldStr := getFieldNameString(spec.DstField.Field.Class, spec.DstField.Field.Field, spec.DstField.Ofs, nBits, false, false)
				if isMatch {
					if srcFieldStr == dstFieldStr {
						parts = append(parts, dstFieldStr)
					} else {
						parts = append(parts, fmt.Sprintf("%s=%s", srcFieldStr, dstFieldStr))
					}
				} else if isLoad {
					parts = append(parts, fmt.Sprintf("load:%s->%s", srcFieldStr, dstFieldStr))
				}
			}
		}
	}
	return fmt.Sprintf("learn(%s)", strings.Join(parts, ","))
}

func getFlowModBaseString(flowMod *openflow15.FlowMod) string {
	var parts []string

	// cookie
	if flowMod.Cookie != 0 {
		if flowMod.CookieMask != 0 {
			parts = append(parts, fmt.Sprintf("cookie=0x%x/0x%x", flowMod.Cookie, flowMod.CookieMask))
		} else {
			parts = append(parts, fmt.Sprintf("cookie=0x%x", flowMod.Cookie))
		}
	}

	// table
	if tableName, ok := TableNameCache[flowMod.TableId]; ok {
		parts = append(parts, fmt.Sprintf("table=%s", tableName))
	} else {
		parts = append(parts, fmt.Sprintf("table=%d", flowMod.TableId))
	}

	// idle_timeout
	if flowMod.IdleTimeout != 0 {
		parts = append(parts, fmt.Sprintf("idle_timeout=%d", flowMod.IdleTimeout))
	}

	// hard_timeout
	if flowMod.HardTimeout != 0 {
		parts = append(parts, fmt.Sprintf("hard_timeout=%d", flowMod.HardTimeout))
	}

	return strings.Join(parts, ", ")
}

func getFlowModMatch(flowMod *openflow15.FlowMod) string {
	parts := []string{fmt.Sprintf("priority=%d", flowMod.Priority)}
	matchMap := map[string]*openflow15.MatchField{}
	for i := 0; i < len(flowMod.Match.Fields); i++ {
		fieldStr := getFieldNameString(flowMod.Match.Fields[i].Class, flowMod.Match.Fields[i].Field, 0, 0, true, true)
		matchMap[fieldStr] = &flowMod.Match.Fields[i]
	}

	if field, ok := matchMap["pkt_mark"]; ok {
		parts = append(parts, matchPktMarkToString(field))
	}

	// TODO: add support for field "recirc_id"

	// TODO: add support for field "dp_hash"

	if field, ok := matchMap["conj_id"]; ok {
		parts = append(parts, matchConjIdToString(field))
	}

	// TODO: add support for field "skb_priority"

	// TODO: add support for field "actset_output"

	if field, ok := matchMap["ct_state"]; ok {
		parts = append(parts, matchCtStateToString(field))
	}

	// TODO: add support for field "ct_zone"

	if field, ok := matchMap["ct_mark"]; ok {
		parts = append(parts, matchCtMarkToString(field))
	}

	if field, ok := matchMap["ct_label"]; ok {
		parts = append(parts, matchCtLabelToString(field))
	}

	if field, ok := matchMap["ct_nw_src"]; ok {
		parts = append(parts, matchIpAddrToString(field, true, true, false))
	}
	if field, ok := matchMap["ct_nw_dst"]; ok {
		parts = append(parts, matchIpAddrToString(field, true, false, false))
	}
	if field, ok := matchMap["ct_ipv6_src"]; ok {
		parts = append(parts, matchIpAddrToString(field, true, true, true))
	}
	if field, ok := matchMap["ct_ipv6_dst"]; ok {
		parts = append(parts, matchIpAddrToString(field, true, false, true))
	}

	if field, ok := matchMap["ct_nw_proto"]; ok {
		parts = append(parts, matchCtNwProtoToString(field))
	}

	if field, ok := matchMap["ct_tp_src"]; ok {
		parts = append(parts, matchTpPortToString(field, true, true))
	}
	if field, ok := matchMap["ct_tp_dst"]; ok {
		parts = append(parts, matchTpPortToString(field, true, false))
	}

	if field, ok := matchMap["dl_type"]; ok {
		parts = append(parts, matchProtoToString(field, matchMap["nw_proto"]))
	}

	for i := 0; i < 16; i++ {
		if field, ok := matchMap[fmt.Sprintf("reg%d", i)]; ok {
			parts = append(parts, matchRegToString(i, field))
		}
	}

	for i := 0; i < 4; i++ {
		if field, ok := matchMap[fmt.Sprintf("xxreg%d", i)]; ok {
			parts = append(parts, matchXXRegToString(i, field))
		}
	}

	// TODO: add other match conditions about tun
	if field, ok := matchMap["tun_dst"]; ok {
		parts = append(parts, matchTunDstToString(field, false))
	}
	if field, ok := matchMap["tun_ipv6_dst"]; ok {
		parts = append(parts, matchTunDstToString(field, true))
	}
	if field, ok := matchMap["tun_id"]; ok {
		parts = append(parts, matchTunIDToString(field))
	}

	// TODO: add support for field "metadata"

	if field, ok := matchMap["in_port"]; ok {
		parts = append(parts, matchInPortToString(field))
	}

	if field, ok := matchMap["dl_vlan"]; ok {
		parts = append(parts, matchVlanToString(field))
	}

	if field, ok := matchMap["dl_src"]; ok {
		parts = append(parts, matchEtherAddrToString(field, true))
	}
	if field, ok := matchMap["dl_dst"]; ok {
		parts = append(parts, matchEtherAddrToString(field, false))
	}

	if field, ok := matchMap["nw_src"]; ok {
		parts = append(parts, matchIpAddrToString(field, false, true, false))
	}
	if field, ok := matchMap["nw_dst"]; ok {
		parts = append(parts, matchIpAddrToString(field, false, false, false))
	}
	if field, ok := matchMap["ipv6_src"]; ok {
		parts = append(parts, matchIpAddrToString(field, false, true, true))
	}
	if field, ok := matchMap["ipv6_dst"]; ok {
		parts = append(parts, matchIpAddrToString(field, false, false, true))
	}

	if field, ok := matchMap["arp_spa"]; ok {
		parts = append(parts, matchArpPaAddrToString(field, true))
	}
	if field, ok := matchMap["arp_tpa"]; ok {
		parts = append(parts, matchArpPaAddrToString(field, false))
	}

	if field, ok := matchMap["arp_op"]; ok {
		parts = append(parts, matchArpOpToString(field))
	}

	// TODO: add support for field "nw_proto"

	if field, ok := matchMap["arp_sha"]; ok {
		parts = append(parts, matchArpHaAddrToString(field, true))
	}
	if field, ok := matchMap["arp_tha"]; ok {
		parts = append(parts, matchArpHaAddrToString(field, false))
	}

	if field, ok := matchMap["nw_tos"]; ok {
		parts = append(parts, matchNwTosToString(field))
	}
	if field, ok := matchMap["ip_dscp"]; ok {
		parts = append(parts, matchIpDscpToString(field))
	}

	// TODO: add support for field "nw_ecn", "nw_ttl", other match conditions about MPLS, and "nw_frag"

	if field, ok := matchMap["icmp_type"]; ok {
		parts = append(parts, matchIcmpTypeToString(field))
	}

	if field, ok := matchMap["icmp_code"]; ok {
		parts = append(parts, matchIcmpCodeToString(field))
	}

	if field, ok := matchMap["tp_src"]; ok {
		parts = append(parts, matchTpPortToString(field, false, true))
	}
	if field, ok := matchMap["tp_dst"]; ok {
		parts = append(parts, matchTpPortToString(field, false, false))
	}

	if field, ok := matchMap["tcp_flags"]; ok {
		parts = append(parts, matchTCPFlagsToString(field))
	}

	return strings.Join(parts, ",")
}

func matchTCPFlagsToString(field *openflow15.MatchField) string {
	data := field.Value.(*openflow15.TcpFlagsField).TcpFlags
	mask := field.Mask.(*openflow15.TcpFlagsField).TcpFlags
	allTCPFlags := map[int]string{
		0:  "fin",
		1:  "syn",
		2:  "rst",
		3:  "psh",
		4:  "ack",
		5:  "urg",
		6:  "ece",
		7:  "cwr",
		8:  "ns",
		9:  "[200]",
		10: "[400]",
		11: "[800]",
	}
	var tcpFlagStrs []string
	for offset := 0; offset <= 11; offset++ {
		v := uint16(1) << offset
		if mask&v == v {
			if data&v == v {
				tcpFlagStrs = append(tcpFlagStrs, "+"+allTCPFlags[offset])
			} else {
				tcpFlagStrs = append(tcpFlagStrs, "-"+allTCPFlags[offset])
			}
		}
	}
	return fmt.Sprintf("tcp_flags=%s", strings.Join(tcpFlagStrs, ""))
}

func getActionString(action openflow15.Action) (string, error) {
	var actionToStringFunc func(action openflow15.Action) string
	switch action.(type) {
	case *openflow15.ActionOutput:
		actionToStringFunc = actionOutputToString
	case *openflow15.ActionGroup:
		actionToStringFunc = nxActionGroupToString
	case *openflow15.ActionDecNwTtl:
		actionToStringFunc = nxActionDecTTLToString
	case *openflow15.ActionPush:
		actionToStringFunc = actionPushToString
	case *openflow15.ActionPopVlan:
		actionToStringFunc = actionPopVlanToString
	case *openflow15.ActionSetField:
		actionToStringFunc = actionSetFieldToString
	case *openflow15.ActionCopyField:
		actionToStringFunc = actionCopyFieldToString
	case *openflow15.ActionMeter:
		actionToStringFunc = actionMeterToString
	case *openflow15.NXActionConjunction:
		actionToStringFunc = nxActionConjunctionToString
	case *openflow15.NXActionConnTrack:
		actionToStringFunc = nxActionConnTrackToString
	case *openflow15.NXActionResubmitTable:
		actionToStringFunc = nxActionResubmitTableToString
	case *openflow15.NXActionOutputReg:
		actionToStringFunc = nxActionOutputRegToString
	case *openflow15.NXActionLearn:
		actionToStringFunc = nxActionLearnToString
	case *openflow15.NXActionNote:
		actionToStringFunc = nxActionNoteToString
	case *openflow15.NXActionController:
		actionToStringFunc = nxActionControllerToString
	case *openflow15.NXActionController2:
		actionToStringFunc = nxActionController2ToString
	case *openflow15.ActionMplsTtl:
	case *openflow15.ActionSetqueue:
	case *openflow15.ActionPopMpls:
	case *openflow15.ActionNwTtl:
	case *openflow15.NXActionRegLoad:
	case *openflow15.NXActionRegMove:
	case *openflow15.NXActionResubmit:
	case *openflow15.NXActionCTNAT:
	case *openflow15.NXActionDecTTL:
	case *openflow15.NXActionDecTTLCntIDs:
	}
	if actionToStringFunc != nil {
		return actionToStringFunc(action), nil
	} else {
		return "", fmt.Errorf("function to string is not implemented")
	}
}

func getFlowModAction(flowMod *openflow15.FlowMod) string {
	var parts []string

	for _, instruction := range flowMod.Instructions {
		switch instr := instruction.(type) {
		case *openflow15.InstrGotoTable:
			if tableName, ok := TableNameCache[instr.TableId]; ok {
				parts = append(parts, fmt.Sprintf("goto_table:%s", tableName))
			} else {
				parts = append(parts, fmt.Sprintf("goto_table:%d", instr.TableId))
			}
		case *openflow15.InstrActions:
			for _, action := range instr.Actions {
				actionStr, err := getActionString(action)
				if err != nil {
					klog.ErrorS(err, "Function to string for action is not implemented")
				} else {
					parts = append(parts, actionStr)
				}
			}
		}
	}

	if len(parts) == 0 {
		parts = append(parts, "drop")
	}
	return fmt.Sprintf("actions=%s", strings.Join(parts, ","))
}

func FlowModToString(flowMod *openflow15.FlowMod) string {
	return fmt.Sprintf("%s, %s %s", getFlowModBaseString(flowMod), getFlowModMatch(flowMod), getFlowModAction(flowMod))
}

func FlowModMatchString(flowMod *openflow15.FlowMod) string {
	return fmt.Sprintf("table=%d,%s", flowMod.TableId, getFlowModMatch(flowMod))
}

func GroupModToString(groupMod *openflow15.GroupMod) string {
	parts := []string{fmt.Sprintf("group_id=%d", groupMod.GroupId)}
	switch groupMod.Type {
	case openflow15.GT_ALL:
		parts = append(parts, "type=all")
	case openflow15.GT_SELECT:
		parts = append(parts, "type=select")
	}
	if len(groupMod.Buckets) != 0 {
		for _, bucket := range groupMod.Buckets {
			bucketStr := fmt.Sprintf("bucket=bucket_id:%d", bucket.BucketId)

			for _, property := range bucket.Properties {
				switch p := property.(type) {
				case *openflow15.GroupBucketPropWeight:
					bucketStr = fmt.Sprintf("%s,weight:%d", bucketStr, p.Weight)
				}
			}

			var actionStrs []string
			for _, action := range bucket.Actions {
				actionStr, err := getActionString(action)
				if err != nil {
					klog.ErrorS(err, "Function to string for action is not implemented")
				} else {
					actionStrs = append(actionStrs, actionStr)
				}
			}
			if len(actionStrs) != 0 {
				bucketStr = fmt.Sprintf("%s,actions=%s", bucketStr, strings.Join(actionStrs, ","))
			}
			parts = append(parts, bucketStr)
		}
	}
	return strings.Join(parts, ",")
}
