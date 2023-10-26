// Copyright 2023 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openflow

import (
	"encoding/binary"
	"net"
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	tableID1   = uint8(100)
	tableID2   = uint8(200)
	tableName  = "testTable"
	stageID    = StageID(0)
	pipelineID = PipelineID(0)
	missAction = TableMissActionNext
)

func checkNXActionOutputReg(t *testing.T, expected *openflow15.NXActionOutputReg, action openflow15.Action) {
	require.IsType(t, &openflow15.NXActionOutputReg{}, action)
	a := action.(*openflow15.NXActionOutputReg)
	assert.Equal(t, expected.SrcField.Class, a.SrcField.Class)
	assert.Equal(t, expected.SrcField.Field, a.SrcField.Field)
	assert.Equal(t, expected.OfsNbits, a.OfsNbits)
}

func checkActionSetField(t *testing.T, expected *openflow15.ActionSetField, got openflow15.Action) {
	action := got.(*openflow15.ActionSetField)
	assert.Equal(t, expected.Field.Class, action.Field.Class)
	assert.Equal(t, expected.Field.Field, action.Field.Field)

	switch v := action.Field.Value.(type) {
	case *openflow15.EthSrcField,
		*openflow15.EthDstField,
		*openflow15.ArpXHaField,
		*openflow15.ArpXPaField,
		*openflow15.Ipv4SrcField,
		*openflow15.Ipv4DstField,
		*openflow15.Ipv6SrcField,
		*openflow15.Ipv6DstField,
		*openflow15.TunnelIpv4DstField,
		*openflow15.VlanIdField,
		*openflow15.ArpOperField:
		assert.Equal(t, expected.Field.Value, v)
	case *openflow15.MatchField:
		assert.Equal(t, expected.Field.Value, v.Value)
		assert.Equal(t, expected.Field.Mask, v.Mask)
	case *util.Buffer:
		assert.Equal(t, expected.Field.Value, v)
		if expected.Field.Mask != nil {
			assert.Equal(t, expected.Field.Mask, action.Field.Mask.(*util.Buffer))
		}
	case *openflow15.Uint32Message,
		*openflow15.IpDscpField:
		assert.Equal(t, expected.Field.Value, v)
		assert.Equal(t, expected.Field.Mask, action.Field.Mask)
	case *openflow15.CTLabel:
		assert.Equal(t, expected.Field.Value, v)
		assert.Equal(t, expected.Field.Mask, action.Field.Mask.(*openflow15.CTLabel))
	default:
		t.Fatalf("Unknown type %v", action.Field.Value)
	}
}

func checkActionCopyField(t *testing.T, expected *openflow15.ActionCopyField, action openflow15.Action) {
	require.IsType(t, &openflow15.ActionCopyField{}, action)
	a := action.(*openflow15.ActionCopyField)
	assert.Equal(t, expected.OxmIdSrc.Class, a.OxmIdSrc.Class)
	assert.Equal(t, expected.OxmIdDst.Class, a.OxmIdDst.Class)
	assert.Equal(t, expected.OxmIdSrc.Field, a.OxmIdSrc.Field)
	assert.Equal(t, expected.OxmIdDst.Field, a.OxmIdDst.Field)
	assert.Equal(t, expected.NBits, a.NBits)
	assert.Equal(t, expected.SrcOffset, a.SrcOffset)
	assert.Equal(t, expected.DstOffset, a.DstOffset)
}

func checkNXActionConnTrack(t *testing.T, expected *openflow15.NXActionConnTrack, action openflow15.Action) {
	require.IsType(t, &openflow15.NXActionConnTrack{}, action)
	a := action.(*openflow15.NXActionConnTrack)
	assert.Equal(t, expected.Flags, a.Flags)
	assert.Equal(t, expected.ZoneSrc, a.ZoneSrc)
	assert.Equal(t, expected.ZoneOfsNbits, a.ZoneOfsNbits)
	assert.Equal(t, expected.RecircTable, a.RecircTable)
}

func checkNXActionCTNAT(t *testing.T, expected *openflow15.NXActionCTNAT, action openflow15.Action) {
	require.IsType(t, &openflow15.NXActionCTNAT{}, action)
	a := action.(*openflow15.NXActionCTNAT)
	assert.Equal(t, expected.Flags, a.Flags)
	assert.Equal(t, expected.RangeIPv4Min, a.RangeIPv4Min)
	assert.Equal(t, expected.RangeIPv4Max, a.RangeIPv4Max)
	assert.Equal(t, expected.RangeIPv6Min, a.RangeIPv6Min)
	assert.Equal(t, expected.RangeIPv6Max, a.RangeIPv6Max)
	assert.Equal(t, expected.RangeProtoMin, a.RangeProtoMin)
	assert.Equal(t, expected.RangeProtoMax, a.RangeProtoMax)
}

func getFlowMod(t *testing.T, f Flow) *openflow15.FlowMod {
	msgs, err := f.GetBundleMessages(AddMessage)
	assert.NoError(t, err)
	require.Equal(t, 1, len(msgs))
	return msgs[0].GetMessage().(*openflow15.FlowMod)
}

func putUint16ToBytes(a uint16) []byte {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, a)
	return bytes
}

func checkLearnSpecs(t *testing.T, expected []*openflow15.NXLearnSpec, got []*openflow15.NXLearnSpec) {
	require.Equal(t, len(expected), len(got))
	for i := 0; i < len(expected); i++ {
		if got[i].SrcField != nil {
			assert.Equal(t, expected[i].SrcField.Field.Class, got[i].SrcField.Field.Class)
			assert.Equal(t, expected[i].SrcField.Field.Field, got[i].SrcField.Field.Field)
			assert.Equal(t, expected[i].SrcField.Ofs, got[i].SrcField.Ofs)
		}
		if got[i].DstField != nil {
			assert.Equal(t, expected[i].DstField.Field.Class, got[i].DstField.Field.Class)
			assert.Equal(t, expected[i].DstField.Field.Field, got[i].DstField.Field.Field)
			assert.Equal(t, expected[i].DstField.Ofs, got[i].DstField.Ofs)
		}
		if got[i].SrcValue != nil {
			assert.Equal(t, expected[i].SrcValue, got[i].SrcValue)
		}
	}
}

func TestFlowActions(t *testing.T) {
	table := NewOFTable(tableID1, tableName, stageID, pipelineID, missAction)
	table.SetNext(tableID2)
	table.(*ofTable).Table = &ofctrl.Table{
		Switch: &ofctrl.OFSwitch{},
	}
	pipelineCache[pipelineID] = &ofPipeline{
		pipelineID: pipelineID,
		tableMap:   map[StageID][]Table{stageID: {table}},
	}

	testCases := []struct {
		name                string
		actionFn            func(Action) FlowBuilder
		expectedActionField openflow15.Action
		expectedActionStr   string
	}{
		{
			name: "drop",
			actionFn: func(b Action) FlowBuilder {
				return b.Drop()
			},
			expectedActionStr: "drop",
		},
		{
			name: "OutputFieldRange (part bits)",
			actionFn: func(b Action) FlowBuilder {
				return b.OutputFieldRange("NXM_NX_REG1", rng1)
			},
			expectedActionField: &openflow15.NXActionOutputReg{
				SrcField: &openflow15.MatchField{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_REG1,
				},
				OfsNbits: rng1.ToNXRange().ToOfsBits(),
			},
			expectedActionStr: "output:NXM_NX_REG1[16..31]",
		},
		{
			name: "OutputFieldRange (all bits)",
			actionFn: func(b Action) FlowBuilder {
				return b.OutputFieldRange("NXM_NX_REG1", rng2)
			},
			expectedActionField: &openflow15.NXActionOutputReg{
				SrcField: &openflow15.MatchField{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_REG1,
				},
				OfsNbits: rng2.ToNXRange().ToOfsBits(),
			},
			expectedActionStr: "output:NXM_NX_REG1[]",
		},
		{
			name: "OutputToRegField (part bits)",
			actionFn: func(b Action) FlowBuilder {
				return b.OutputToRegField(NewRegField(1, 16, 31))
			},
			expectedActionField: &openflow15.NXActionOutputReg{
				SrcField: &openflow15.MatchField{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_REG1,
				},
				OfsNbits: rng1.ToNXRange().ToOfsBits(),
			},
			expectedActionStr: "output:NXM_NX_REG1[16..31]",
		},
		{
			name: "OutputToRegField (all bits)",
			actionFn: func(b Action) FlowBuilder {
				return b.OutputToRegField(NewRegField(1, 0, 31))
			},
			expectedActionField: &openflow15.NXActionOutputReg{
				SrcField: &openflow15.MatchField{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_REG1,
				},
				OfsNbits: rng2.ToNXRange().ToOfsBits(),
			},
			expectedActionStr: "output:NXM_NX_REG1[]",
		},
		{
			name: "Output",
			actionFn: func(b Action) FlowBuilder {
				return b.Output(5)
			},
			expectedActionField: &openflow15.ActionOutput{
				Port: 5,
			},
			expectedActionStr: "output:5",
		},
		{
			name: "OutputInPort",
			actionFn: func(b Action) FlowBuilder {
				return b.OutputInPort()
			},
			expectedActionField: &openflow15.ActionOutput{
				Port: uint32(openflow15.P_IN_PORT),
			},
			expectedActionStr: "IN_PORT",
		},
		{
			name: "Normal",
			actionFn: func(b Action) FlowBuilder {
				return b.Normal()
			},
			expectedActionField: &openflow15.ActionOutput{
				Port: uint32(openflow15.P_NORMAL),
			},
			expectedActionStr: "NORMAL",
		},
		{
			name: "SetSrcMAC",
			actionFn: func(b Action) FlowBuilder {
				return b.SetSrcMAC(mac)
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_SRC,
					Value: &openflow15.EthSrcField{
						EthSrc: mac,
					},
				},
			},
			expectedActionStr: "set_field:aa:bb:cc:dd:ee:ff->eth_src",
		},
		{
			name: "SetDstMAC",
			actionFn: func(b Action) FlowBuilder {
				return b.SetDstMAC(mac)
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_DST,
					Value: &openflow15.EthDstField{
						EthDst: mac,
					},
				},
			},
			expectedActionStr: "set_field:aa:bb:cc:dd:ee:ff->eth_dst",
		},
		{
			name: "SetARPSha",
			actionFn: func(b Action) FlowBuilder {
				return b.SetARPSha(mac)
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ARP_SHA,
					Value: &openflow15.ArpXHaField{
						ArpHa: mac,
					},
				},
			},
			expectedActionStr: "set_field:aa:bb:cc:dd:ee:ff->arp_sha",
		},
		{
			name: "SetARPTha",
			actionFn: func(b Action) FlowBuilder {
				return b.SetARPTha(mac)
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ARP_THA,
					Value: &openflow15.ArpXHaField{
						ArpHa: mac,
					},
				},
			},
			expectedActionStr: "set_field:aa:bb:cc:dd:ee:ff->arp_tha",
		},
		{
			name: "SetARPSpa",
			actionFn: func(b Action) FlowBuilder {
				return b.SetARPSpa(ipv4Addr1)
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ARP_SPA,
					Value: &openflow15.ArpXPaField{
						ArpPa: ipv4Addr1,
					},
				},
			},
			expectedActionStr: "set_field:1.1.1.1->arp_spa",
		},
		{
			name: "SetARPTpa",
			actionFn: func(b Action) FlowBuilder {
				return b.SetARPTpa(ipv4Addr1)
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ARP_TPA,
					Value: &openflow15.ArpXPaField{
						ArpPa: ipv4Addr1,
					},
				},
			},
			expectedActionStr: "set_field:1.1.1.1->arp_tpa",
		},
		{
			name: "SetSrcIP (IPv4)",
			actionFn: func(b Action) FlowBuilder {
				return b.SetSrcIP(ipv4Addr1)
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IPV4_SRC,
					Value: &openflow15.Ipv4SrcField{
						Ipv4Src: ipv4Addr1,
					},
				},
			},
			expectedActionStr: "set_field:1.1.1.1->ip_src",
		},
		{
			name: "SetSrcIP (IPv6)",
			actionFn: func(b Action) FlowBuilder {
				return b.SetSrcIP(ipv6Addr1)
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IPV6_SRC,
					Value: &openflow15.Ipv6SrcField{
						Ipv6Src: ipv6Addr1,
					},
				},
			},
			expectedActionStr: "set_field:fec0::1111->ipv6_src",
		},
		{
			name: "SetDstIP (IPv4)",
			actionFn: func(b Action) FlowBuilder {
				return b.SetDstIP(ipv4Addr1)
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IPV4_DST,
					Value: &openflow15.Ipv4DstField{
						Ipv4Dst: ipv4Addr1,
					},
				},
			},
			expectedActionStr: "set_field:1.1.1.1->ip_dst",
		},
		{
			name: "SetDstIP (IPv6)",
			actionFn: func(b Action) FlowBuilder {
				return b.SetDstIP(ipv6Addr1)
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IPV6_DST,
					Value: &openflow15.Ipv6DstField{
						Ipv6Dst: ipv6Addr1,
					},
				},
			},
			expectedActionStr: "set_field:fec0::1111->ipv6_dst",
		},
		{
			name: "SetTunnelDst (IPv4)",
			actionFn: func(b Action) FlowBuilder {
				return b.SetTunnelDst(ipv4Addr1)
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_TUN_IPV4_DST,
					Value: &openflow15.TunnelIpv4DstField{
						TunnelIpv4Dst: ipv4Addr1,
					},
				},
			},
			expectedActionStr: "set_field:1.1.1.1->tun_dst",
		},
		{
			name: "SetTunnelDst (IPv6)",
			actionFn: func(b Action) FlowBuilder {
				return b.SetTunnelDst(ipv6Addr1)
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_TUN_IPV6_DST,
					Value: &openflow15.Ipv6DstField{
						Ipv6Dst: ipv6Addr1,
					},
				},
			},
			expectedActionStr: "set_field:fec0::1111->tun_ipv6_dst",
		},
		{
			name: "SetVLAN",
			actionFn: func(b Action) FlowBuilder {
				return b.SetVLAN(100)
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_VLAN_VID,
					Value: &openflow15.VlanIdField{
						VlanId: 100 | openflow15.OFPVID_PRESENT,
					},
				},
			},
			expectedActionStr: "set_field:4196->vlan_vid",
		},
		{
			name: "LoadARPOperation",
			actionFn: func(b Action) FlowBuilder {
				return b.LoadARPOperation(1)
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ARP_OP,
					Value: &openflow15.ArpOperField{
						ArpOper: 1,
					},
				},
			},
			expectedActionStr: "set_field:1->arp_op",
		},
		{
			name: "LoadRegMark",
			actionFn: func(b Action) FlowBuilder {
				return b.LoadRegMark(NewRegMark(NewRegField(1, 1, 17), uint32(0xfffe)))
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_REG1,
					Value: &openflow15.Uint32Message{Data: 0x1fffc},
					Mask:  &openflow15.Uint32Message{Data: 0x3fffe},
				},
			},
			expectedActionStr: "set_field:0x1fffc/0x3fffe->reg1",
		},
		{
			name: "LoadPktMarkRange",
			actionFn: func(b Action) FlowBuilder {
				return b.LoadPktMarkRange(uint32(0xaeef), rng1)
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_PKT_MARK,
					Value: util.NewBuffer([]byte{0xae, 0xef, 0x0, 0x0}),
					Mask:  util.NewBuffer([]byte{0xff, 0xff, 0x0, 0x0}),
				},
			},
			expectedActionStr: "set_field:0xaeef0000/0xffff0000->pkt_mark",
		},
		{
			name: "LoadIPDSCP",
			actionFn: func(b Action) FlowBuilder {
				return b.LoadIPDSCP(uint8(63))
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_NXM_0,
					Field: openflow15.NXM_OF_IP_TOS,
					Value: &openflow15.IpDscpField{Dscp: uint8(63) << IPDSCPToSRange.Offset()},
					Mask:  &openflow15.IpDscpField{Dscp: uint8(0xff) >> (8 - IPDSCPToSRange.Length()) << IPDSCPToSRange.Offset()},
				},
			},
			expectedActionStr: "set_field:252->nw_tos",
		},
		{
			name: "PopVLAN",
			actionFn: func(b Action) FlowBuilder {
				return b.PopVLAN()
			},
			expectedActionField: &openflow15.ActionPopVlan{},
			expectedActionStr:   "pop_vlan",
		},
		{
			name: "PushVLAN",
			actionFn: func(b Action) FlowBuilder {
				return b.PushVLAN(0x8100)
			},
			expectedActionField: &openflow15.ActionPush{
				EtherType: 0x8100,
			},
			expectedActionStr: "push_vlan:0x8100",
		},
		{
			name: "Move (NXM_NX_REG4[]->NXM_NX_REG5[])",
			actionFn: func(b Action) FlowBuilder {
				return b.Move("NXM_NX_REG4", "NXM_NX_REG5")
			},
			expectedActionField: &openflow15.ActionCopyField{
				OxmIdSrc: openflow15.OxmId{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_REG4,
				},
				OxmIdDst: openflow15.OxmId{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_REG5,
				},
				NBits: 32,
			},
			expectedActionStr: "move:NXM_NX_REG4[]->NXM_NX_REG5[]",
		},
		{
			name: "Move (NXM_NX_XXREG0[]->NXM_NX_XXREG1[])",
			actionFn: func(b Action) FlowBuilder {
				return b.Move("NXM_NX_XXREG0", "NXM_NX_XXREG1")
			},
			expectedActionField: &openflow15.ActionCopyField{
				OxmIdSrc: openflow15.OxmId{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_XXREG0,
				},
				OxmIdDst: openflow15.OxmId{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_XXREG1,
				},
				NBits: 128,
			},
			expectedActionStr: "move:NXM_NX_XXREG0[]->NXM_NX_XXREG1[]",
		},
		{
			name: "Move (OXM_OF_ETH_SRC[]->OXM_OF_ETH_DST[])",
			actionFn: func(b Action) FlowBuilder {
				return b.Move("OXM_OF_ETH_SRC", "OXM_OF_ETH_DST")
			},
			expectedActionField: &openflow15.ActionCopyField{
				OxmIdSrc: openflow15.OxmId{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_SRC,
				},
				OxmIdDst: openflow15.OxmId{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_DST,
				},
				NBits: 48,
			},
			expectedActionStr: "move:OXM_OF_ETH_SRC[]->OXM_OF_ETH_DST[]",
		},
		{
			name: "MoveRange (OXM_OF_ETH_SRC[16..31]->NXM_NX_REG6[1..16])",
			actionFn: func(b Action) FlowBuilder {
				return b.MoveRange("OXM_OF_ETH_SRC", "NXM_NX_REG6", Range{16, 31}, Range{1, 16})
			},
			expectedActionField: &openflow15.ActionCopyField{
				OxmIdSrc: openflow15.OxmId{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_SRC,
				},
				SrcOffset: 16,
				OxmIdDst: openflow15.OxmId{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_REG6,
				},
				DstOffset: 1,
				NBits:     16,
			},
			expectedActionStr: "move:OXM_OF_ETH_SRC[16..31]->NXM_NX_REG6[1..16]",
		},
		{
			name: "ResubmitToTables",
			actionFn: func(b Action) FlowBuilder {
				return b.ResubmitToTables(100)
			},
			expectedActionField: &openflow15.NXActionResubmitTable{
				TableID: 100,
			},
			expectedActionStr: "resubmit:100",
		},
		{
			name: "DecTTL",
			actionFn: func(b Action) FlowBuilder {
				return b.DecTTL()
			},
			expectedActionField: &openflow15.ActionDecNwTtl{},
			expectedActionStr:   "dec_ttl",
		},
		{
			name: "Conjunction",
			actionFn: func(b Action) FlowBuilder {
				return b.Conjunction(61, 2, 3)
			},
			expectedActionField: &openflow15.NXActionConjunction{
				Clause:  2,
				ID:      61,
				NClause: 3,
			},
			expectedActionStr: "conjunction(61,2/3)",
		},
		{
			name: "Group",
			actionFn: func(b Action) FlowBuilder {
				return b.Group(GroupIDType(100))
			},
			expectedActionField: &openflow15.ActionGroup{
				GroupId: 100,
			},
			expectedActionStr: "group:100",
		},
		{
			name: "Note",
			actionFn: func(b Action) FlowBuilder {
				return b.Note("aabbccdd5566")
			},
			expectedActionField: &openflow15.NXActionNote{
				Note: []byte("aabbccdd5566"),
			},
			expectedActionStr: "note:aa:bb:cc:dd:55:66",
		},
		{
			name: "SendToController",
			actionFn: func(b Action) FlowBuilder {
				return b.SendToController([]byte{0x1}, false)
			},
			expectedActionField: &openflow15.NXActionController2{},
			expectedActionStr:   "controller(id=0,reason=no_match,userdata=01,max_len=65535)",
		},
		{
			name: "SendToController",
			actionFn: func(b Action) FlowBuilder {
				return b.SendToController([]byte{0x1}, false)
			},
			expectedActionField: &openflow15.NXActionController2{},
			expectedActionStr:   "controller(id=0,reason=no_match,userdata=01,max_len=65535)",
		},
		{
			name: "Meter",
			actionFn: func(b Action) FlowBuilder {
				return b.Meter(100)
			},
			expectedActionField: &openflow15.ActionMeter{
				MeterId: 100,
			},
			expectedActionStr: "meter:100",
		},
		{
			name: "GotoTable",
			actionFn: func(b Action) FlowBuilder {
				return b.GotoTable(tableID1)
			},
			expectedActionStr: "goto_table:100",
		},
		{
			name: "GotoStage",
			actionFn: func(b Action) FlowBuilder {
				return b.GotoStage(stageID)
			},
			expectedActionStr: "goto_table:100",
		},
		{
			name: "CT (commit, immediate zone value)",
			actionFn: func(b Action) FlowBuilder {
				return b.CT(true, tableID1, 101, nil).CTDone()
			},
			expectedActionField: &openflow15.NXActionConnTrack{
				Flags:        1,
				ZoneSrc:      0,
				ZoneOfsNbits: 101,
				RecircTable:  100,
			},
			expectedActionStr: "ct(commit,table=100,zone=101)",
		},
		{
			name: "CT (without commit, immediate zone value)",
			actionFn: func(b Action) FlowBuilder {
				return b.CT(false, tableID1, 101, nil).CTDone()
			},
			expectedActionField: &openflow15.NXActionConnTrack{
				Flags:        0,
				ZoneSrc:      0,
				ZoneOfsNbits: 101,
				RecircTable:  100,
			},
			expectedActionStr: "ct(table=100,zone=101)",
		},
		{
			name: "CT (commit, register zone value)",
			actionFn: func(b Action) FlowBuilder {
				return b.CT(true, tableID1, 0, NewRegField(1, 0, 16)).CTDone()
			},
			expectedActionField: &openflow15.NXActionConnTrack{
				Flags:        1,
				ZoneSrc:      0x10308,
				ZoneOfsNbits: 0x10,
				RecircTable:  100,
			},
			expectedActionStr: "ct(commit,table=100,zone=NXM_NX_REG1[0..16])",
		},
		{
			name: "CT (without commit, register zone value)",
			actionFn: func(b Action) FlowBuilder {
				return b.CT(false, tableID1, 0, NewRegField(1, 0, 16)).CTDone()
			},
			expectedActionField: &openflow15.NXActionConnTrack{
				Flags:        0,
				ZoneSrc:      0x10308,
				ZoneOfsNbits: 0x10,
				RecircTable:  100,
			},
			expectedActionStr: "ct(table=100,zone=NXM_NX_REG1[0..16])",
		},
		{
			name: "Learn",
			actionFn: func(b Action) FlowBuilder {
				return b.Learn(tableID1, 100, 1800, 1800, 0, 0, 100).Done()
			},
			expectedActionField: &openflow15.NXActionLearn{
				IdleTimeout: 1800,
				HardTimeout: 1800,
				Priority:    100,
				Cookie:      100,
				TableID:     100,
			},
			expectedActionStr: "learn(table=100,idle_timeout=1800,hard_timeout=1800,priority=100,cookie=0x64)",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flowMod := getFlowMod(t, tc.actionFn(table.BuildFlow(1).Action()).Done())
			if len(flowMod.Instructions) == 1 {
				switch instr := flowMod.Instructions[0].(type) {
				case *openflow15.InstrActions:
					actions := instr.Actions
					require.Equal(t, 1, len(actions))
					switch expected := tc.expectedActionField.(type) {
					case *openflow15.ActionSetField:
						checkActionSetField(t, expected, actions[0])
					case *openflow15.NXActionOutputReg:
						checkNXActionOutputReg(t, expected, actions[0])
					case *openflow15.ActionOutput:
						assert.Equal(t, expected.Port, actions[0].(*openflow15.ActionOutput).Port)
					case *openflow15.ActionPopVlan:
					case *openflow15.ActionPush:
						assert.Equal(t, expected.EtherType, actions[0].(*openflow15.ActionPush).EtherType)
					case *openflow15.ActionCopyField:
						checkActionCopyField(t, expected, actions[0])
					case *openflow15.NXActionResubmitTable:
						assert.Equal(t, expected.TableID, actions[0].(*openflow15.NXActionResubmitTable).TableID)
					case *openflow15.ActionDecNwTtl:
					case *openflow15.NXActionConjunction:
						a := actions[0].(*openflow15.NXActionConjunction)
						assert.Equal(t, expected.ID, a.ID)
						assert.Equal(t, expected.NClause, a.NClause)
						assert.Equal(t, expected.Clause-1, a.Clause)
					case *openflow15.ActionGroup:
						assert.Equal(t, expected.GroupId, actions[0].(*openflow15.ActionGroup).GroupId)
					case *openflow15.NXActionNote:
						assert.Equal(t, expected.Note, actions[0].(*openflow15.NXActionNote).Note)
					case *openflow15.NXActionController2:
					case *openflow15.ActionMeter:
						assert.Equal(t, expected.MeterId, actions[0].(*openflow15.ActionMeter).MeterId)
					case *openflow15.NXActionConnTrack:
						checkNXActionConnTrack(t, expected, actions[0])
					case *openflow15.NXActionLearn:
						a := actions[0].(*openflow15.NXActionLearn)
						assert.Equal(t, expected.IdleTimeout, a.IdleTimeout)
						assert.Equal(t, expected.HardTimeout, a.HardTimeout)
						assert.Equal(t, expected.Priority, a.Priority)
						assert.Equal(t, expected.Cookie, a.Cookie)
						assert.Equal(t, expected.TableID, a.TableID)
					default:
						t.Fatalf("Unknown action type %v", expected)
					}
				case *openflow15.InstrGotoTable:
					assert.Equal(t, tableID1, flowMod.Instructions[0].(*openflow15.InstrGotoTable).TableId)
				default:
					t.Fatalf("Unknown instruction type %v", instr)
				}
			}
			assert.Contains(t, getFlowModAction(flowMod), tc.expectedActionStr)
		})
	}
}

func TestCTActions(t *testing.T) {
	table := NewOFTable(tableID1, tableName, stageID, pipelineID, missAction)
	table.(*ofTable).Table = new(ofctrl.Table)
	ipv4Min, ipv4Max := net.ParseIP("1.1.1.1"), net.ParseIP("1.1.1.2")
	ipv6Min, ipv6Max := net.ParseIP("1:1:1::1"), net.ParseIP("1:1:1::2")
	portMin, portMax := uint16(3333), uint16(4444)

	commit := true
	nextTable := uint8(100)
	zone := 100

	testCases := []struct {
		name                string
		ctActionFn          func(CTAction) CTAction
		expectedActionField openflow15.Action
		expectedActionStr   string
	}{
		{
			name: "LoadToCtMark",
			ctActionFn: func(b CTAction) CTAction {
				return b.LoadToCtMark(NewCTMark(NewCTMarkField(0, 15), uint32(0x1234)))
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_MARK,
					Value: &openflow15.Uint32Message{Data: 0x1234},
					Mask:  &openflow15.Uint32Message{Data: 0xffff},
				},
			},
			expectedActionStr: "ct(commit,table=100,zone=100,exec(set_field:0x1234/0xffff->ct_mark))",
		},
		{
			name: "LoadToLabelField",
			ctActionFn: func(b CTAction) CTAction {
				return b.LoadToLabelField(0xffff_1111_1111_ffff, NewCTLabel(64, 127))
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_LABEL,
					Value: &openflow15.CTLabel{Data: [16]uint8{0xff, 0xff, 0x11, 0x11, 0x11, 0x11, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}},
					Mask:  &openflow15.CTLabel{Data: [16]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}},
				},
			},
			expectedActionStr: "ct(commit,table=100,zone=100,exec(set_field:0xffff11111111ffff0000000000000000/0xffffffffffffffff0000000000000000->ct_label))",
		},
		{
			name: "MoveToLabel",
			ctActionFn: func(b CTAction) CTAction {
				return b.MoveToLabel("NXM_NX_REG4", &Range{4, 7}, &Range{0, 3})
			},
			expectedActionField: &openflow15.ActionCopyField{
				OxmIdSrc: openflow15.OxmId{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_REG4,
				},
				OxmIdDst: openflow15.OxmId{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_LABEL,
				},
				SrcOffset: 4,
				DstOffset: 0,
				NBits:     4,
			},
			expectedActionStr: "ct(commit,table=100,zone=100,exec(move:NXM_NX_REG4[4..7]->NXM_NX_CT_LABEL[0..3]))",
		},
		{
			name: "MoveToCtMarkField",
			ctActionFn: func(b CTAction) CTAction {
				return b.MoveToCtMarkField(NewRegField(1, 1, 16), NewCTMarkField(2, 17))
			},
			expectedActionField: &openflow15.ActionCopyField{
				OxmIdSrc: openflow15.OxmId{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_REG1,
				},
				OxmIdDst: openflow15.OxmId{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_MARK,
				},
				SrcOffset: 1,
				DstOffset: 2,
				NBits:     16,
			},
			expectedActionStr: "ct(commit,table=100,zone=100,exec(move:NXM_NX_REG1[1..16]->NXM_NX_CT_MARK[2..17]))",
		},
		{
			name: "SNAT (IPv4)",
			ctActionFn: func(b CTAction) CTAction {
				return b.SNAT(&IPRange{ipv4Min, ipv4Min}, &PortRange{portMin, portMin})
			},
			expectedActionField: &openflow15.NXActionCTNAT{
				Flags:         openflow15.NX_NAT_F_SRC,
				RangeIPv4Min:  ipv4Min,
				RangeIPv4Max:  ipv4Min,
				RangeProtoMin: &portMin,
				RangeProtoMax: &portMin,
			},
			expectedActionStr: "ct(commit,table=100,zone=100,nat(src=1.1.1.1:3333))",
		},
		{
			name: "SNAT (IPv6)",
			ctActionFn: func(b CTAction) CTAction {
				return b.SNAT(&IPRange{ipv6Min, ipv6Min}, &PortRange{portMin, portMin})
			},
			expectedActionField: &openflow15.NXActionCTNAT{
				Flags:         openflow15.NX_NAT_F_SRC,
				RangeIPv6Min:  ipv6Min,
				RangeIPv6Max:  ipv6Min,
				RangeProtoMin: &portMin,
				RangeProtoMax: &portMin,
			},
			expectedActionStr: "ct(commit,table=100,zone=100,nat(src=[1:1:1::1]:3333))",
		},
		{
			name: "DNAT (IPv4)",
			ctActionFn: func(b CTAction) CTAction {
				return b.DNAT(&IPRange{ipv4Min, ipv4Max}, &PortRange{portMin, portMax})
			},
			expectedActionField: &openflow15.NXActionCTNAT{
				Flags:         openflow15.NX_NAT_F_DST,
				RangeIPv4Min:  ipv4Min,
				RangeIPv4Max:  ipv4Max,
				RangeProtoMin: &portMin,
				RangeProtoMax: &portMax,
			},
			expectedActionStr: "ct(commit,table=100,zone=100,nat(dst=1.1.1.1-1.1.1.2:3333-4444))",
		},
		{
			name: "DNAT (IPv6)",
			ctActionFn: func(b CTAction) CTAction {
				return b.DNAT(&IPRange{ipv6Min, ipv6Max}, &PortRange{portMin, portMin})
			},
			expectedActionField: &openflow15.NXActionCTNAT{
				Flags:         openflow15.NX_NAT_F_DST,
				RangeIPv6Min:  ipv6Min,
				RangeIPv6Max:  ipv6Max,
				RangeProtoMin: &portMin,
				RangeProtoMax: &portMin,
			},
			expectedActionStr: "ct(commit,table=100,zone=100,nat(dst=[1:1:1::1-1:1:1::2]:3333))",
		},
		{
			name: "NAT",
			ctActionFn: func(b CTAction) CTAction {
				return b.NAT()
			},
			expectedActionField: &openflow15.NXActionCTNAT{},
			expectedActionStr:   "ct(commit,table=100,zone=100,nat",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctAction := tc.ctActionFn(table.BuildFlow(1).Action().CT(commit, nextTable, zone, nil))
			actions := ctAction.(*ofCTAction).actions
			require.Equal(t, 1, len(actions))
			switch expected := tc.expectedActionField.(type) {
			case *openflow15.ActionSetField:
				checkActionSetField(t, expected, actions[0])
			case *openflow15.ActionCopyField:
				checkActionCopyField(t, expected, actions[0])
			case *openflow15.NXActionCTNAT:
				checkNXActionCTNAT(t, expected, actions[0])
			default:
				t.Fatalf("Unknown action type %v", expected)
			}
			flowMod := getFlowMod(t, ctAction.CTDone().Done())
			assert.Contains(t, getFlowModAction(flowMod), tc.expectedActionStr)
		})
	}
}

func TestLearnActions(t *testing.T) {
	table := NewOFTable(tableID1, tableName, stageID, pipelineID, missAction)
	table.(*ofTable).Table = new(ofctrl.Table)
	targetTable := uint8(100)
	priority := uint16(101)
	idleTimeout := uint16(120)
	hardTimeout := uint16(3600)
	cookieID := uint64(0xffffffff)

	testCases := []struct {
		name                 string
		learnActionFn        func(LearnAction) LearnAction
		expectedActionFields []*openflow15.NXLearnSpec
		expectedActionStr    string
	}{
		{
			name: "MatchEthernetProtocol,MatchIPProtocol (ProtocolTCP,IPv4)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchEthernetProtocol(false).MatchIPProtocol(ProtocolTCP)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_0,
							Field: openflow15.NXM_OF_ETH_TYPE,
						},
					},
					SrcValue: putUint16ToBytes(0x800),
				},
				{
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_0,
							Field: openflow15.NXM_OF_IP_PROTO,
						},
					},
					SrcValue: putUint16ToBytes(0x6),
				},
			},
			expectedActionStr: "eth_type=0x800,nw_proto=0x6",
		},
		{
			name: "MatchEthernetProtocol,MatchIPProtocol (ProtocolTCP,IPv6)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchEthernetProtocol(true).MatchIPProtocol(ProtocolTCP)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_0,
							Field: openflow15.NXM_OF_ETH_TYPE,
						},
					},
					SrcValue: putUint16ToBytes(0x86dd),
				},
				{
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_0,
							Field: openflow15.NXM_OF_IP_PROTO,
						},
					},
					SrcValue: putUint16ToBytes(0x6),
				},
			},
			expectedActionStr: "eth_type=0x86dd,nw_proto=0x6",
		},
		{
			name: "MatchEthernetProtocol,MatchIPProtocol (ProtocolUDP,IPv4)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchEthernetProtocol(false).MatchIPProtocol(ProtocolUDP)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_0,
							Field: openflow15.NXM_OF_ETH_TYPE,
						},
					},
					SrcValue: putUint16ToBytes(0x800),
				},
				{
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_0,
							Field: openflow15.NXM_OF_IP_PROTO,
						},
					},
					SrcValue: putUint16ToBytes(0x11),
				},
			},
			expectedActionStr: "eth_type=0x800,nw_proto=0x11",
		},
		{
			name: "MatchEthernetProtocol,MatchIPProtocol (ProtocolUDP,IPv6)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchEthernetProtocol(true).MatchIPProtocol(ProtocolUDP)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_0,
							Field: openflow15.NXM_OF_ETH_TYPE,
						},
					},
					SrcValue: putUint16ToBytes(0x86dd),
				},
				{
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_0,
							Field: openflow15.NXM_OF_IP_PROTO,
						},
					},
					SrcValue: putUint16ToBytes(0x11),
				},
			},
			expectedActionStr: "eth_type=0x86dd,nw_proto=0x11",
		},
		{
			name: "MatchEthernetProtocol,MatchIPProtocol (ProtocolSCTP,IPv4)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchEthernetProtocol(false).MatchIPProtocol(ProtocolSCTP)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_0,
							Field: openflow15.NXM_OF_ETH_TYPE,
						},
					},
					SrcValue: putUint16ToBytes(0x800),
				},
				{
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_0,
							Field: openflow15.NXM_OF_IP_PROTO,
						},
					},
					SrcValue: putUint16ToBytes(0x84),
				},
			},
			expectedActionStr: "eth_type=0x800,nw_proto=0x84",
		},
		{
			name: "MatchEthernetProtocol,MatchIPProtocol (ProtocolSCTP,IPv6)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchEthernetProtocol(true).MatchIPProtocol(ProtocolSCTP)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_0,
							Field: openflow15.NXM_OF_ETH_TYPE,
						},
					},
					SrcValue: putUint16ToBytes(0x86dd),
				},
				{
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_0,
							Field: openflow15.NXM_OF_IP_PROTO,
						},
					},
					SrcValue: putUint16ToBytes(0x84),
				},
			},
			expectedActionStr: "eth_type=0x86dd,nw_proto=0x84",
		},
		{
			name: "MatchLearnedSrcIP (IPv4)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchLearnedSrcIP(false)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_0,
							Field: openflow15.NXM_OF_IP_SRC,
						},
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_0,
							Field: openflow15.NXM_OF_IP_SRC,
						},
					},
				},
			},
			expectedActionStr: "NXM_OF_IP_SRC[]",
		},
		{
			name: "MatchLearnedSrcIP (IPv6)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchLearnedSrcIP(true)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_1,
							Field: openflow15.NXM_NX_IPV6_SRC,
						},
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_1,
							Field: openflow15.NXM_NX_IPV6_SRC,
						},
					},
				},
			},
			expectedActionStr: "NXM_NX_IPV6_SRC[]",
		},
		{
			name: "MatchLearnedDstIP (IPv4)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchLearnedDstIP(false)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_0,
							Field: openflow15.NXM_OF_IP_DST,
						},
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_0,
							Field: openflow15.NXM_OF_IP_DST,
						},
					},
				},
			},
			expectedActionStr: "NXM_OF_IP_DST[]",
		},
		{
			name: "MatchLearnedDstIP (IPv6)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchLearnedDstIP(true)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_1,
							Field: openflow15.NXM_NX_IPV6_DST,
						},
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_1,
							Field: openflow15.NXM_NX_IPV6_DST,
						},
					},
				},
			},
			expectedActionStr: "NXM_NX_IPV6_DST[]",
		},
		{
			name: "MatchLearnedSrcPort (ProtocolTCP)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchLearnedSrcPort(ProtocolTCP)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_TCP_SRC,
						},
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_TCP_SRC,
						},
					},
				},
			},
			expectedActionStr: "OXM_OF_TCP_SRC[]",
		},
		{
			name: "MatchLearnedSrcPort (ProtocolTCPv6)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchLearnedSrcPort(ProtocolTCPv6)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_TCP_SRC,
						},
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_TCP_SRC,
						},
					},
				},
			},
			expectedActionStr: "OXM_OF_TCP_SRC[]",
		},
		{
			name: "MatchLearnedSrcPort (ProtocolUDP)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchLearnedSrcPort(ProtocolUDP)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_UDP_SRC,
						},
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_UDP_SRC,
						},
					},
				},
			},
			expectedActionStr: "OXM_OF_UDP_SRC[]",
		},
		{
			name: "MatchLearnedSrcPort (ProtocolUDPv6)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchLearnedSrcPort(ProtocolUDPv6)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_UDP_SRC,
						},
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_UDP_SRC,
						},
					},
				},
			},
			expectedActionStr: "OXM_OF_UDP_SRC[]",
		},
		{
			name: "MatchLearnedSrcPort (ProtocolSCTP)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchLearnedSrcPort(ProtocolSCTP)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_SCTP_SRC,
						},
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_SCTP_SRC,
						},
					},
				},
			},
			expectedActionStr: "OXM_OF_SCTP_SRC[]",
		},
		{
			name: "MatchLearnedSrcPort (ProtocolSCTPv6)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchLearnedSrcPort(ProtocolSCTPv6)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_SCTP_SRC,
						},
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_SCTP_SRC,
						},
					},
				},
			},
			expectedActionStr: "OXM_OF_SCTP_SRC[]",
		},
		{
			name: "MatchLearnedDstPort (ProtocolTCP)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchLearnedDstPort(ProtocolTCP)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_TCP_DST,
						},
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_TCP_DST,
						},
					},
				},
			},
			expectedActionStr: "OXM_OF_TCP_DST[]",
		},
		{
			name: "MatchLearnedDstPort (ProtocolTCPv6)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchLearnedDstPort(ProtocolTCPv6)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_TCP_DST,
						},
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_TCP_DST,
						},
					},
				},
			},
			expectedActionStr: "OXM_OF_TCP_DST[]",
		},
		{
			name: "MatchLearnedDstPort (ProtocolUDP)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchLearnedDstPort(ProtocolUDP)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_UDP_DST,
						},
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_UDP_DST,
						},
					},
				},
			},
			expectedActionStr: "OXM_OF_UDP_DST[]",
		},
		{
			name: "MatchLearnedDstPort (ProtocolUDPv6)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchLearnedDstPort(ProtocolUDPv6)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_UDP_DST,
						},
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_UDP_DST,
						},
					},
				},
			},
			expectedActionStr: "OXM_OF_UDP_DST[]",
		},
		{
			name: "MatchLearnedDstPort (ProtocolSCTP)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchLearnedDstPort(ProtocolSCTP)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_SCTP_DST,
						},
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_SCTP_DST,
						},
					},
				},
			},
			expectedActionStr: "OXM_OF_SCTP_DST[]",
		},
		{
			name: "MatchLearnedDstPort (ProtocolSCTPv6)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchLearnedDstPort(ProtocolSCTPv6)
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_SCTP_DST,
						},
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
							Field: openflow15.OXM_FIELD_SCTP_DST,
						},
					},
				},
			},
			expectedActionStr: "OXM_OF_SCTP_DST[]",
		},
		{
			name: "MatchRegMark (part bits)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchRegMark(NewRegMark(NewRegField(11, 1, 4), 0xf))
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_1,
							Field: openflow15.NXM_NX_REG11,
						},
						Ofs: 1,
					},
					SrcValue: []uint8{0x0, 0xf},
				},
			},
			expectedActionStr: "NXM_NX_REG11[1..4]=0xf",
		},
		{
			name: "MatchRegMark (all bits)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.MatchRegMark(NewRegMark(NewRegField(1, 0, 31), 0xffffffff))
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_1,
							Field: openflow15.NXM_NX_REG1,
						},
						Ofs: 0,
					},
					SrcValue: []uint8{0xff, 0xff, 0xff, 0xff},
				},
			},
			expectedActionStr: "NXM_NX_REG1[]=0xffffffff",
		},
		{
			name: "LoadFieldToField (part bits)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.LoadFieldToField(NewRegField(1, 1, 16), NewRegField(2, 2, 17))
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_1,
							Field: openflow15.NXM_NX_REG1,
						},
						Ofs: 1,
					},

					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_1,
							Field: openflow15.NXM_NX_REG2,
						},
						Ofs: 2,
					},
				},
			},
			expectedActionStr: "load:NXM_NX_REG1[1..16]->NXM_NX_REG2[2..17]",
		},
		{
			name: "LoadFieldToField (all bits)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.LoadFieldToField(NewRegField(3, 0, 31), NewRegField(4, 0, 31))
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_1,
							Field: openflow15.NXM_NX_REG3,
						},
						Ofs: 0,
					},

					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_1,
							Field: openflow15.NXM_NX_REG4,
						},
						Ofs: 0,
					},
				},
			},
			expectedActionStr: "load:NXM_NX_REG3[]->NXM_NX_REG4[]",
		},
		{
			name: "LoadXXRegToXXReg (part bits)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.LoadXXRegToXXReg(NewXXRegField(0, 1, 100), NewXXRegField(1, 2, 101))
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_1,
							Field: openflow15.NXM_NX_XXREG0,
						},
						Ofs: 1,
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_1,
							Field: openflow15.NXM_NX_XXREG1,
						},
						Ofs: 2,
					},
				},
			},
			expectedActionStr: "load:NXM_NX_XXREG0[1..100]->NXM_NX_XXREG1[2..101]",
		},
		{
			name: "LoadXXRegToXXReg (all bits)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.LoadXXRegToXXReg(NewXXRegField(2, 0, 127), NewXXRegField(3, 0, 127))
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					SrcField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_1,
							Field: openflow15.NXM_NX_XXREG2,
						},
						Ofs: 0,
					},
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_1,
							Field: openflow15.NXM_NX_XXREG3,
						},
						Ofs: 0,
					},
				},
			},
			expectedActionStr: "load:NXM_NX_XXREG2[]->NXM_NX_XXREG3[]",
		},
		{
			name: "LoadRegMark (part bits)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.LoadRegMark(NewRegMark(NewRegField(11, 1, 4), 0xf))
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_1,
							Field: openflow15.NXM_NX_REG11,
						},
						Ofs: 1,
					},
					SrcValue: []uint8{0x0, 0xf},
				},
			},
			expectedActionStr: "load:0xf->NXM_NX_REG11[1..4]",
		},
		{
			name: "LoadRegMark (all bits)",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.LoadRegMark(NewRegMark(NewRegField(1, 0, 31), 0xffffffff))
			},
			expectedActionFields: []*openflow15.NXLearnSpec{
				{
					DstField: &openflow15.NXLearnSpecField{
						Field: &openflow15.MatchField{
							Class: openflow15.OXM_CLASS_NXM_1,
							Field: openflow15.NXM_NX_REG1,
						},
						Ofs: 0,
					},
					SrcValue: []uint8{0xff, 0xff, 0xff, 0xff},
				},
			},
			expectedActionStr: "load:0xffffffff->NXM_NX_REG1[]",
		},
		{
			name: "DeleteLearned",
			learnActionFn: func(b LearnAction) LearnAction {
				return b.DeleteLearned()
			},
			expectedActionStr: "delete_learned",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			learnAction := tc.learnActionFn(table.BuildFlow(1).Action().Learn(targetTable, priority, idleTimeout, hardTimeout, 0, 0, cookieID))
			action := learnAction.(*ofLearnAction).nxLearn.GetActionMessage().(*openflow15.NXActionLearn)
			checkLearnSpecs(t, tc.expectedActionFields, action.LearnSpecs)
			flowMod := getFlowMod(t, learnAction.Done().Done())
			assert.Contains(t, getFlowModAction(flowMod), tc.expectedActionStr)
		})
	}
}
