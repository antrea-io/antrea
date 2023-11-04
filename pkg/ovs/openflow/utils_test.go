// Copyright 2023 Antrea Authors
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
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

var (
	ipSrc, ipSrcNet, _ = net.ParseCIDR("192.168.10.2/24")
	ipDst, ipDstNet, _ = net.ParseCIDR("192.168.20.3/24")
	ip6Src, ip6Dst     = net.ParseIP("fe::ca8:a02"), net.ParseIP("fe::ca8:a03")
	tunDst, tun6Dst    = net.ParseIP("192.10.20.30"), net.ParseIP("fe::c0a:141e")
	ethSrc, _          = net.ParseMAC("10:1a:1b:1c:1d:1f")
	ethDst, _          = net.ParseMAC("20:2a:2b:2c:2d:2f")
)

func TestFlowModToString(t *testing.T) {
	b := NewOFBridge("test-br", GetMgmtAddress(ovsconfig.DefaultOVSRunDir, "test-br"))
	sw := newFakeOFSwitch(b)
	table := &ofTable{Table: &ofctrl.Table{TableId: 1, Switch: sw}, next: 2}
	rf := NewRegField(1, 0, 31)
	basicFB := table.BuildFlow(100).(*ofFlowBuilder)
	basicFB.Cookie(0x12345678).
		MatchInPort(3).
		MatchDstMAC(ethDst).
		MatchSrcMAC(ethSrc)
	for _, tt := range []struct {
		name         string
		flowFunc     func(fb *ofFlowBuilder) Flow
		expectedFlow string
	}{
		{
			name: "ARP responder",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchProtocol(ProtocolARP).
					SetIdleTimeout(3600).
					SetHardTimeout(3600).
					Action().LoadARPOperation(1).
					Action().SetARPSha(ethSrc).
					Action().SetARPTha(ethDst).
					Action().SetARPSpa(ipSrc).
					Action().SetARPTpa(ipDst).
					Action().OutputInPort().
					Done()
			},
			expectedFlow: "cookie=0x12345678, table=1, idle_timeout=3600, hard_timeout=3600, priority=100,arp,in_port=3,dl_src=10:1a:1b:1c:1d:1f,dl_dst=20:2a:2b:2c:2d:2f actions=set_field:1->arp_op,set_field:10:1a:1b:1c:1d:1f->arp_sha,set_field:20:2a:2b:2c:2d:2f->arp_tha,set_field:192.168.10.2->arp_spa,set_field:192.168.20.3->arp_tpa,IN_PORT",
		}, {
			name: "Modify IP and MAC",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchProtocol(ProtocolIP).
					SetIdleTimeout(3600).
					SetHardTimeout(3600).
					Action().SetDstMAC(ethDst).
					Action().SetSrcMAC(ethSrc).
					Action().SetDstIP(ipDst).
					Action().SetSrcIP(ipSrc).
					Action().Output(4).
					Done()
			},
			expectedFlow: "cookie=0x12345678, table=1, idle_timeout=3600, hard_timeout=3600, priority=100,ip,in_port=3,dl_src=10:1a:1b:1c:1d:1f,dl_dst=20:2a:2b:2c:2d:2f actions=set_field:20:2a:2b:2c:2d:2f->eth_dst,set_field:10:1a:1b:1c:1d:1f->eth_src,set_field:192.168.20.3->ip_dst,set_field:192.168.10.2->ip_src,output:4",
		}, {
			name: "Decrease ttl and set tunnel",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchProtocol(ProtocolIP).
					SetIdleTimeout(3600).
					SetHardTimeout(3600).
					Action().DecTTL().
					Action().SetTunnelDst(tunDst).
					Action().SetTunnelID(0x123456).
					Action().NextTable().
					Done()
			},
			expectedFlow: "cookie=0x12345678, table=1, idle_timeout=3600, hard_timeout=3600, priority=100,ip,in_port=3,dl_src=10:1a:1b:1c:1d:1f,dl_dst=20:2a:2b:2c:2d:2f actions=dec_ttl,set_field:192.10.20.30->tun_dst,set_field:1193046->tunnel_id,goto_table:2",
		}, {
			name: "Set VLAN",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchProtocol(ProtocolIP).
					SetIdleTimeout(3600).
					SetHardTimeout(3600).
					Action().PushVLAN(0x0800).
					Action().SetVLAN(102).
					Action().GotoTable(3).
					Done()
			},
			expectedFlow: "cookie=0x12345678, table=1, idle_timeout=3600, hard_timeout=3600, priority=100,ip,in_port=3,dl_src=10:1a:1b:1c:1d:1f,dl_dst=20:2a:2b:2c:2d:2f actions=push_vlan:0x800,set_field:4198->vlan_vid,goto_table:3",
		}, {
			name: "Pop VLAN",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchProtocol(ProtocolIP).
					SetIdleTimeout(3600).
					SetHardTimeout(3600).
					Action().PopVLAN().
					Action().OutputToRegField(rf).
					Done()
			},
			expectedFlow: "cookie=0x12345678, table=1, idle_timeout=3600, hard_timeout=3600, priority=100,ip,in_port=3,dl_src=10:1a:1b:1c:1d:1f,dl_dst=20:2a:2b:2c:2d:2f actions=pop_vlan,output:NXM_NX_REG1[]",
		}, {
			name: "conjunction",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchProtocol(ProtocolIP).
					SetIdleTimeout(3600).
					SetHardTimeout(3600).
					Action().Conjunction(10, 1, 2).
					Done()
			},
			expectedFlow: "cookie=0x12345678, table=1, idle_timeout=3600, hard_timeout=3600, priority=100,ip,in_port=3,dl_src=10:1a:1b:1c:1d:1f,dl_dst=20:2a:2b:2c:2d:2f actions=conjunction(10,1/2)",
		}, {
			name: "Move eth header, group and controller",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchProtocol(ProtocolIP).
					SetIdleTimeout(3600).
					SetHardTimeout(3600).
					Action().Move(NxmFieldSrcMAC, NxmFieldDstMAC).
					Action().Group(1).
					Action().SendToController([]byte{1}, false).
					Done()
			},
			expectedFlow: "cookie=0x12345678, table=1, idle_timeout=3600, hard_timeout=3600, priority=100,ip,in_port=3,dl_src=10:1a:1b:1c:1d:1f,dl_dst=20:2a:2b:2c:2d:2f actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],group:1,controller(id=100,reason=no_match,userdata=01,max_len=65535)",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			newFb := *(basicFB.CopyToBuilder(basicFB.FlowPriority(), false).(*ofFlowBuilder))
			f := tt.flowFunc(&newFb)
			messages, err := f.GetBundleMessages(AddMessage)
			assert.NoError(t, err)
			require.Equal(t, 1, len(messages))
			fm, ok := messages[0].GetMessage().(*openflow15.FlowMod)
			assert.True(t, ok)
			matchStr := FlowModToString(fm)
			assert.Equal(t, tt.expectedFlow, matchStr)
		})
	}
}

func TestFlowModMatchString(t *testing.T) {
	rm := &RegMark{field: NewRegField(0, 0, 3), value: 2}
	ctm := NewOneBitCTMark(4)
	pktm := uint32(1 << 31)
	table := &ofTable{Table: &ofctrl.Table{TableId: 1}}
	basicFB := table.BuildFlow(100).(*ofFlowBuilder)
	basicFB.Cookie(0x12345678).MatchInPort(3)
	for _, tt := range []struct {
		name          string
		flowFunc      func(fb *ofFlowBuilder) Flow
		expectedMatch string
	}{
		{
			name: "reg mark flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchRegMark(rm).
					MatchXXReg(1, ip6Dst).
					Done()
			},
			expectedMatch: "table=1,priority=100,reg0=0x2/0xf,xxreg1=0xfe000000000000000000000ca80a03,in_port=3",
		}, {
			name: "packet mark flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchPktMark(10, &pktm).Done()
			},
			expectedMatch: "table=1,priority=100,pkt_mark=0xa/0x80000000,in_port=3",
		}, {
			name: "L2 flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchDstMAC(ethDst).MatchSrcMAC(ethSrc).Done()
			},
			expectedMatch: "table=1,priority=100,in_port=3,dl_src=10:1a:1b:1c:1d:1f,dl_dst=20:2a:2b:2c:2d:2f",
		},
		{
			name: "VLAN flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchVLAN(false, 1000, nil).Done()
			},
			expectedMatch: "table=1,priority=100,in_port=3,dl_vlan=1000",
		}, {
			name: "IPv4 flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchDstMAC(ethDst).MatchSrcMAC(ethSrc).MatchDstIP(ipDst).MatchSrcIP(ipSrc).Done()
			},
			expectedMatch: "table=1,priority=100,in_port=3,dl_src=10:1a:1b:1c:1d:1f,dl_dst=20:2a:2b:2c:2d:2f,nw_src=192.168.10.2,nw_dst=192.168.20.3",
		}, {
			name: "IPv4 net flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchSrcIPNet(*ipSrcNet).MatchDstIPNet(*ipDstNet).Done()
			},
			expectedMatch: "table=1,priority=100,in_port=3,nw_src=192.168.10.0/24,nw_dst=192.168.20.0/24",
		}, {
			name: "IPv6 flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchDstIP(ip6Dst).MatchSrcIP(ip6Src).Done()
			},
			expectedMatch: "table=1,priority=100,in_port=3,ipv6_src=fe::ca8:a02,ipv6_dst=fe::ca8:a03",
		}, {
			name: "ARP flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchARPOp(2).MatchARPTha(ethDst).MatchARPSha(ethSrc).MatchARPTpa(ipDst).MatchARPSpa(ipSrc).Done()
			},
			expectedMatch: "table=1,priority=100,in_port=3,arp_spa=192.168.10.2,arp_tpa=192.168.20.3,arp_op=2,arp_sha=10:1a:1b:1c:1d:1f,arp_tha=20:2a:2b:2c:2d:2f",
		}, {
			name: "IP DSCP flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchProtocol(ProtocolIP).MatchIPDSCP(12).Done()
			},
			expectedMatch: "table=1,priority=100,ip,in_port=3,ip_dscp=12",
		}, {
			name: "IPv6 TCP flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchIPProtocolValue(true, 6).
					MatchDstPort(8080, nil).
					MatchSrcPort(23423, nil).
					MatchTCPFlags(0b010010, 0b010010).
					Done()
			},
			expectedMatch: "table=1,priority=100,tcp6,in_port=3,tp_src=23423,tp_dst=8080,tcp_flags=+syn+ack",
		}, {
			name: "IPv4 UDP flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchIPProtocolValue(false, 17).MatchDstPort(8080, nil).Done()
			},
			expectedMatch: "table=1,priority=100,udp,in_port=3,tp_dst=8080",
		}, {
			name: "IPv4 ICMP flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchProtocol(ProtocolICMP).MatchICMPCode(0).MatchICMPType(8).Done()
			},
			expectedMatch: "table=1,priority=100,icmp,in_port=3,icmp_type=8,icmp_code=0",
		}, {
			name: "IPv4 tunnel flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchProtocol(ProtocolIP).
					MatchTunnelDst(tunDst).
					MatchTunnelID(62346).
					Done()
			},
			expectedMatch: "table=1,priority=100,ip,tun_dst=192.10.20.30,tun_id=62346,in_port=3",
		}, {
			name: "IPv6 tunnel flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchProtocol(ProtocolIPv6).
					MatchTunnelDst(tun6Dst).
					MatchTunnelID(62346).
					Done()
			},
			expectedMatch: "table=1,priority=100,ipv6,tun_ipv6_dst=fe::c0a:141e,tun_id=62346,in_port=3",
		}, {
			name: "ct state flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchProtocol(ProtocolIP).
					MatchCTStateNew(true).
					MatchCTStateTrk(true).
					MatchCTStateEst(false).
					MatchCTStateRel(false).
					MatchCTStateRpl(false).
					MatchCTStateInv(false).
					MatchCTStateDNAT(true).
					MatchCTStateSNAT(true).
					Done()
			},
			expectedMatch: "table=1,priority=100,ct_state=+new-est-rel-rpl-inv+trk+snat+dnat,ip,in_port=3",
		}, {
			name: "ct mark flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchProtocol(ProtocolTCP).
					MatchCTMark(ctm).
					MatchCTLabelField(0, 32, NewCTLabel(0, 31)).
					MatchCTSrcIP(ipSrc).
					MatchCTDstIP(ipDst).
					MatchCTSrcPort(1230).
					MatchCTDstPort(80).
					MatchCTProtocol(ProtocolTCP).
					Done()
			},
			expectedMatch: "table=1,priority=100,ct_mark=0x10/0x10,ct_label=0x20/0xffffffff,ct_nw_src=192.168.10.2,ct_nw_dst=192.168.20.3,ct_nw_proto=6,ct_tp_src=1230,ct_tp_dst=80,tcp,in_port=3",
		}, {
			name: "conjunction flow",
			flowFunc: func(fb *ofFlowBuilder) Flow {
				return fb.MatchProtocol(ProtocolIP).MatchConjID(101).Done()
			},
			expectedMatch: "table=1,priority=100,conj_id=101,ip,in_port=3",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			newFb := *(basicFB.CopyToBuilder(basicFB.FlowPriority(), false).(*ofFlowBuilder))
			f := tt.flowFunc(&newFb)
			messages, err := f.GetBundleMessages(AddMessage)
			assert.NoError(t, err)
			require.Equal(t, 1, len(messages))
			fm, ok := messages[0].GetMessage().(*openflow15.FlowMod)
			assert.True(t, ok)
			fmStr := FlowModMatchString(fm)
			assert.Equal(t, tt.expectedMatch, fmStr)
		})
	}
}

func TestGroupModToString(t *testing.T) {
	rf := NewRegField(1, 0, 31)
	for _, tt := range []struct {
		name          string
		groupFunc     func() Group
		expectedGroup string
	}{
		{
			name: "type all group",
			groupFunc: func() Group {
				grp := &ofGroup{ofctrl: &ofctrl.Group{ID: 2, GroupType: ofctrl.GroupAll}}
				return grp.Bucket().
					LoadToRegField(rf, 10).
					SetTunnelDst(tunDst).
					ResubmitToTable(10).Done().
					Bucket().
					LoadToRegField(rf, 20).
					SetTunnelDst(tunDst).
					ResubmitToTable(10).Done()
			},
			expectedGroup: "group_id=2,type=all,bucket=bucket_id:0,actions=set_field:0xa->reg1,set_field:192.10.20.30->tun_dst,resubmit:10,bucket=bucket_id:1,actions=set_field:0x14->reg1,set_field:192.10.20.30->tun_dst,resubmit:10",
		}, {
			name: "type select group",
			groupFunc: func() Group {
				grp := &ofGroup{ofctrl: &ofctrl.Group{ID: 2, GroupType: ofctrl.GroupSelect}}
				return grp.Bucket().Weight(100).
					LoadToRegField(rf, 10).
					SetTunnelDst(tunDst).
					ResubmitToTable(10).Done().
					Bucket().Weight(100).
					LoadXXReg(1, ip6Dst).
					SetTunnelDst(tunDst).
					ResubmitToTable(10).Done()
			},
			expectedGroup: "group_id=2,type=select,bucket=bucket_id:0,weight:100,actions=set_field:0xa->reg1,set_field:192.10.20.30->tun_dst,resubmit:10,bucket=bucket_id:1,weight:100,actions=set_field:0xfe000000000000000000000ca80a03->xxreg1,set_field:192.10.20.30->tun_dst,resubmit:10",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			group := tt.groupFunc()
			messages, err := group.GetBundleMessages(AddMessage)
			require.NoError(t, err)
			require.Equal(t, 1, len(messages))
			gm := messages[0].GetMessage().(*openflow15.GroupMod)
			groupStr := GroupModToString(gm)
			assert.Equal(t, tt.expectedGroup, groupStr)
		})
	}
}
