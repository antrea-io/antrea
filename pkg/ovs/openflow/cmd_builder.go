// Copyright 2019 Antrea Authors
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
)

type commandBuilder struct {
	commandFlow
}

func (b *commandBuilder) Done() Flow {
	return &b.commandFlow
}

func (b *commandBuilder) MatchField(name, value string) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("%s=%s", name, value))
	return b
}

func (b *commandBuilder) MatchFieldRange(name, value string, rng Range) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("%s[%d..%d]=%s", name, rng[0], rng[1], value))
	return b
}

func (b *commandBuilder) MatchReg(regID int, data uint32) FlowBuilder {
	return b.MatchField(fmt.Sprintf("reg%d", regID), fmt.Sprintf("0x%x", data))
}

func (b *commandBuilder) MatchRegRange(regID int, data uint32, rng Range) FlowBuilder {
	return b.MatchFieldRange(fmt.Sprintf("reg%d", regID), fmt.Sprintf("0x%x", data), rng)
}

func (b *commandBuilder) addCTStateString(value string) {
	for i, matcher := range b.matchers {
		if strings.HasPrefix(matcher, "ct_state=") {
			b.matchers[i] = fmt.Sprintf("%s%s", matcher, value)
			return
		}
	}
	b.matchers = append(b.matchers, fmt.Sprintf("ct_state=%s", value))
}

func (b *commandBuilder) MatchCTStateNew() FlowBuilder {
	b.addCTStateString("+new")
	return b
}

func (b *commandBuilder) MatchCTStateUnNew() FlowBuilder {
	b.addCTStateString("-new")
	return b
}

func (b *commandBuilder) MatchCTStateRel() FlowBuilder {
	b.addCTStateString("+rel")
	return b
}

func (b *commandBuilder) MatchCTStateUnRel() FlowBuilder {
	b.addCTStateString("-new")
	return b
}

func (b *commandBuilder) MatchCTStateRpl() FlowBuilder {
	b.addCTStateString("+rpl")
	return b
}

func (b *commandBuilder) MatchCTStateUnRpl() FlowBuilder {
	b.addCTStateString("-rpl")
	return b
}

func (b *commandBuilder) MatchCTStateEst() FlowBuilder {
	b.addCTStateString("+est")
	return b
}

func (b *commandBuilder) MatchCTStateUnEst() FlowBuilder {
	b.addCTStateString("-est")
	return b
}
func (b *commandBuilder) MatchCTStateTrk() FlowBuilder {
	b.addCTStateString("+trk")
	return b
}

func (b *commandBuilder) MatchCTStateUnTrk() FlowBuilder {
	b.addCTStateString("-trk")
	return b
}

func (b *commandBuilder) MatchCTStateInv() FlowBuilder {
	b.addCTStateString("+inv")
	return b
}

func (b *commandBuilder) MatchCTStateUnInv() FlowBuilder {
	b.addCTStateString("-inv")
	return b
}

func (b *commandBuilder) MatchCTMark(value uint32) FlowBuilder {
	b.matchers = append(b.matchers, fmt.Sprintf("ct_mark=0x%x", value))
	return b
}

func (b *commandBuilder) MatchCTMarkMask(mask uint32) FlowBuilder {
	for i, data := range b.matchers {
		if strings.HasPrefix(data, "ct_mark=") {
			b.matchers[i] = fmt.Sprintf("%s/0x%x", data, mask)
			break
		}
	}
	return b
}

func (b *commandBuilder) MatchInPort(inPort uint32) FlowBuilder {
	return b.MatchField("in_port", fmt.Sprint(inPort))
}

func (b *commandBuilder) MatchDstIP(ip net.IP) FlowBuilder {
	return b.MatchField("nw_dst", ip.String())
}

func (b *commandBuilder) MatchDstIPNet(ipNet net.IPNet) FlowBuilder {
	return b.MatchField("nw_dst", ipNet.String())
}

func (b *commandBuilder) MatchSrcIP(ip net.IP) FlowBuilder {
	return b.MatchField("nw_src", ip.String())
}

func (b *commandBuilder) MatchSrcIPNet(ipNet net.IPNet) FlowBuilder {
	return b.MatchField("nw_src", ipNet.String())
}

func (b *commandBuilder) MatchDstMAC(mac net.HardwareAddr) FlowBuilder {
	return b.MatchField("dl_dst", mac.String())
}

func (b *commandBuilder) MatchSrcMAC(mac net.HardwareAddr) FlowBuilder {
	return b.MatchField("dl_src", mac.String())
}

func (b *commandBuilder) MatchARPSha(mac net.HardwareAddr) FlowBuilder {
	return b.MatchField("arp_sha", mac.String())
}

func (b *commandBuilder) MatchARPTha(mac net.HardwareAddr) FlowBuilder {
	return b.MatchField("arp_tha", mac.String())
}

func (b *commandBuilder) MatchARPSpa(ip net.IP) FlowBuilder {
	return b.MatchField("arp_spa", ip.String())
}

func (b *commandBuilder) MatchARPTpa(ip net.IP) FlowBuilder {
	return b.MatchField("arp_tpa", ip.String())
}

func (b *commandBuilder) MatchARPOp(op uint16) FlowBuilder {
	return b.MatchField("arp_op", fmt.Sprintf("%d", op))
}

func (b *commandBuilder) MatchConjID(value uint32) FlowBuilder {
	return b.MatchField("conj_id", fmt.Sprintf("%d", value))
}

func (b *commandBuilder) Priority(priority uint32) FlowBuilder {
	b.priority = priority
	return b
}

func (b *commandBuilder) MatchTCPDstPort(port uint16) FlowBuilder {
	return b.MatchField("tcp_dst", fmt.Sprintf("%d", port))
}

func (b *commandBuilder) MatchUDPDstPort(port uint16) FlowBuilder {
	return b.MatchField("udp_dst", fmt.Sprintf("%d", port))
}

func (b *commandBuilder) MatchSCTPDstPort(port uint16) FlowBuilder {
	return b.MatchField("sct_dst", fmt.Sprintf("%d", port))
}

func (b *commandBuilder) MatchProtocol(protocol protocol) FlowBuilder {
	b.matchers = append(b.matchers, strings.ToLower(protocol))
	return b
}

func (b *commandBuilder) Cookie(cookieID uint64) FlowBuilder {
	return b.MatchField("cookie", fmt.Sprintf("%d", cookieID))
}

func (b *commandBuilder) Action() Action {
	return &commandAction{b}
}
