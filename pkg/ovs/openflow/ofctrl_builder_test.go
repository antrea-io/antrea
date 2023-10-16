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
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	vlanMask1      = uint16(0x1fff)
	vlanMask2      = uint16(0x1000)
	regMark1       = NewRegMark(NewRegField(1, 0, 31), 0xeeeeffff)
	regMark2       = NewRegMark(NewRegField(2, 2, 5), 0xf)
	pkgMarkMask    = uint32(0xf)
	ipv4Addr1      = net.ParseIP("1.1.1.1")
	ipv6Addr1      = net.ParseIP("fec0::1111")
	_, ipv4Net1, _ = net.ParseCIDR("1.1.1.0/24")
	_, ipv4Net2, _ = net.ParseCIDR("1.1.1.1/32")
	_, ipv6Net1, _ = net.ParseCIDR("fec0::/64")
	_, ipv6Net2, _ = net.ParseCIDR("fec0::ffff/128")
	mac, _         = net.ParseMAC("aa:bb:cc:dd:ee:ff")
	portMask       = uint16(0xf000)
	rng1           = &Range{16, 31}
	rng2           = &Range{0, 31}
)

func checkMatchField(t *testing.T, expected, got *openflow15.MatchField) {
	assert.Equal(t, expected.Class, got.Class)
	assert.Equal(t, expected.Field, got.Field)
	assert.Equal(t, expected.HasMask, got.HasMask)
	assert.Equal(t, expected.Value, got.Value)
	assert.Equal(t, expected.Mask, got.Mask)
}

func TestFlowBuilder(t *testing.T) {
	table := NewOFTable(tableID1, tableName, stageID, pipelineID, missAction)
	table.SetNext(tableID2)
	table.(*ofTable).Table = new(ofctrl.Table)

	testCases := []struct {
		name                string
		matchFn             func(FlowBuilder) FlowBuilder
		expectedMatchFields []*openflow15.MatchField
		expectedMatchStr    string
	}{
		{
			name: "MatchVLAN (nonVlan without mask)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchVLAN(true, 0, nil)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_VLAN_VID,
					Value: &openflow15.VlanIdField{VlanId: 0},
				},
			},
			expectedMatchStr: "vlan_tci=0x0000/0x1000",
		},
		{
			name: "MatchVLAN (nonVlan with mask)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchVLAN(true, 0, &vlanMask2)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_VLAN_VID,
					Value: &openflow15.VlanIdField{VlanId: 0},
				},
			},
			expectedMatchStr: "vlan_tci=0x0000/0x1000",
		},
		{
			name: "MatchVLAN (Vlan with mask)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchVLAN(false, 1, &vlanMask1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field:   openflow15.OXM_FIELD_VLAN_VID,
					HasMask: true,
					Value:   &openflow15.VlanIdField{VlanId: 0x1001},
					Mask:    &openflow15.VlanIdField{VlanId: 0x1fff},
				},
			},
			expectedMatchStr: "dl_vlan=1",
		},
		{
			name: "MatchVLAN (Vlan without mask)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchVLAN(false, 1, &vlanMask1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field:   openflow15.OXM_FIELD_VLAN_VID,
					HasMask: true,
					Value:   &openflow15.VlanIdField{VlanId: 0x1001},
					Mask:    &openflow15.VlanIdField{VlanId: 0x1fff},
				},
			},
			expectedMatchStr: "dl_vlan=1",
		},
		{
			name: "Cookie",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.Cookie(uint64(6))
			},
			expectedMatchStr: "cookie=0x6",
		},
		{
			name: "SetHardTimeout",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.SetHardTimeout(uint16(3600))
			},
			expectedMatchStr: "hard_timeout=3600",
		},
		{
			name: "SetIdleTimeout",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.SetIdleTimeout(uint16(3600))
			},
			expectedMatchStr: "idle_timeout=3600",
		},
		{
			name: "MatchXXReg (value 0x123456)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchXXReg(0, []byte{0x12, 0x34, 0x56})
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_XXREG0,
					Value: &openflow15.ByteArrayField{Data: []byte{0x12, 0x34, 0x56}, Length: 3},
				},
			},
			expectedMatchStr: "xxreg0=0x123456",
		},
		{
			name: "MatchXXReg (value 0xffffffff)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchXXReg(2, []byte{0xff, 0xff, 0xff, 0xff})
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_XXREG2,
					Value: &openflow15.ByteArrayField{Data: []byte{0xff, 0xff, 0xff, 0xff}, Length: 4},
				},
			},
			expectedMatchStr: "xxreg2=0xffffffff",
		},
		{
			name: "MatchRegMark (reg1, value 0xeeeeffff)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchRegMark(regMark1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_REG1,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: regMark1.value << regMark1.field.rng[0]},
					Mask:    &openflow15.Uint32Message{Data: regMark1.field.GetRange().ToNXRange().ToUint32Mask()},
				},
			},
			expectedMatchStr: "reg1=0xeeeeffff",
		},
		{
			name: "MatchRegMark (reg2, value 0x3c/0x3c)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchRegMark(regMark2)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_REG2,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: regMark2.value << regMark2.field.rng[0]},
					Mask:    &openflow15.Uint32Message{Data: regMark2.field.GetRange().ToNXRange().ToUint32Mask()},
				},
			},
			expectedMatchStr: "reg2=0x3c/0x3c",
		},
		{
			name: "MatchCTState (+new)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTStateNew(true)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_STATE,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 1},
					Mask:    &openflow15.Uint32Message{Data: 1},
				},
			},
			expectedMatchStr: "ct_state=+new",
		},
		{
			name: "MatchCTState (-new)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTStateNew(false)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_STATE,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 0x0},
					Mask:    &openflow15.Uint32Message{Data: 0x1},
				},
			},
			expectedMatchStr: "ct_state=-new",
		},
		{
			name: "MatchCTState (+rel)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTStateRel(true)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_STATE,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 0x4},
					Mask:    &openflow15.Uint32Message{Data: 0x4},
				},
			},
			expectedMatchStr: "ct_state=+rel",
		},
		{
			name: "MatchCTState (-rel)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTStateRel(false)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_STATE,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 0x0},
					Mask:    &openflow15.Uint32Message{Data: 0x4},
				},
			},
			expectedMatchStr: "ct_state=-rel",
		},
		{
			name: "MatchCTState (+rpl)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTStateRpl(true)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_STATE,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 0x8},
					Mask:    &openflow15.Uint32Message{Data: 0x8},
				},
			},
			expectedMatchStr: "ct_state=+rpl",
		},
		{
			name: "MatchCTState (-rpl)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTStateRpl(false)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_STATE,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 0x0},
					Mask:    &openflow15.Uint32Message{Data: 0x8},
				},
			},
			expectedMatchStr: "ct_state=-rpl",
		},
		{
			name: "MatchCTState (+est)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTStateEst(true)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_STATE,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 0x2},
					Mask:    &openflow15.Uint32Message{Data: 0x2},
				},
			},
			expectedMatchStr: "ct_state=+est",
		},
		{
			name: "MatchCTState (-est)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTStateEst(false)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_STATE,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 0x0},
					Mask:    &openflow15.Uint32Message{Data: 0x2},
				},
			},
			expectedMatchStr: "ct_state=-est",
		},
		{
			name: "MatchCTState (+trk)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTStateTrk(true)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_STATE,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 0x20},
					Mask:    &openflow15.Uint32Message{Data: 0x20},
				},
			},
			expectedMatchStr: "ct_state=+trk",
		},
		{
			name: "MatchCTState (-trk)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTStateTrk(false)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_STATE,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 0x0},
					Mask:    &openflow15.Uint32Message{Data: 0x20},
				},
			},
			expectedMatchStr: "ct_state=-trk",
		},
		{
			name: "MatchCTState (+inv)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTStateInv(true)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_STATE,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 0x10},
					Mask:    &openflow15.Uint32Message{Data: 0x10},
				},
			},
			expectedMatchStr: "ct_state=+inv",
		},
		{
			name: "MatchCTState (-inv)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTStateInv(false)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_STATE,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 0x0},
					Mask:    &openflow15.Uint32Message{Data: 0x10},
				},
			},
			expectedMatchStr: "ct_state=-inv",
		},
		{
			name: "MatchCTState (+dnat)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTStateDNAT(true)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_STATE,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 0x80},
					Mask:    &openflow15.Uint32Message{Data: 0x80},
				},
			},
			expectedMatchStr: "ct_state=+dnat",
		},
		{
			name: "MatchCTState (-dnat)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTStateDNAT(false)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_STATE,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 0x0},
					Mask:    &openflow15.Uint32Message{Data: 0x80},
				},
			},
			expectedMatchStr: "ct_state=-dnat",
		},
		{
			name: "MatchCTState (+snat)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTStateSNAT(true)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_STATE,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 0x40},
					Mask:    &openflow15.Uint32Message{Data: 0x40},
				},
			},
			expectedMatchStr: "ct_state=+snat",
		},
		{
			name: "MatchCTState (-snat)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTStateSNAT(false)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_STATE,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 0x0},
					Mask:    &openflow15.Uint32Message{Data: 0x40},
				},
			},
			expectedMatchStr: "ct_state=-snat",
		},
		{
			name: "MatchPktMark (value 0x2/0xf with mask)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchPktMark(2, &pkgMarkMask)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_PKT_MARK,
					HasMask: true,
					Value:   &openflow15.Uint32Message{Data: 0x2},
					Mask:    &openflow15.Uint32Message{Data: 0xf},
				},
			},
			expectedMatchStr: "pkt_mark=0x2/0xf",
		},
		{
			name: "MatchPktMark (value 0x2 without mask)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchPktMark(2, nil)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_PKT_MARK,
					Value: &openflow15.Uint32Message{Data: 0x2},
				},
			},
			expectedMatchStr: "pkt_mark=0x2",
		},
		{
			name: "MatchTunnelDst (IPv4)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchTunnelDst(ipv4Addr1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_TUN_IPV4_DST,
					Value: &openflow15.TunnelIpv4DstField{TunnelIpv4Dst: ipv4Addr1.To4()},
				},
			},
			expectedMatchStr: "tun_dst=1.1.1.1",
		},
		{
			name: "MatchTunnelDst (IPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchTunnelDst(ipv6Addr1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_TUN_IPV6_DST,
					Value: &openflow15.Ipv6DstField{Ipv6Dst: ipv6Addr1},
				},
			},
			expectedMatchStr: "tun_ipv6_dst=fec0::1111",
		},
		{
			name: "MatchCTLabelField (bit 0)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTLabelField(0, 0x1, NewCTLabel(0, 0))
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_LABEL,
					HasMask: true,
					Value:   openflow15.NewCTLabelMatchField([16]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}, nil).Value,
					Mask:    openflow15.NewCTLabelMatchField([16]byte{}, &[16]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}).Mask,
				},
			},
			expectedMatchStr: "ct_label=0x1/0x1",
		},
		{
			name: "MatchCTLabelField (bit 127)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTLabelField(0x8000_0000_0000_0000, 0, NewCTLabel(127, 127))
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_LABEL,
					HasMask: true,
					Value:   openflow15.NewCTLabelMatchField([16]byte{0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, nil).Value,
					Mask:    openflow15.NewCTLabelMatchField([16]byte{}, &[16]byte{0x80, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}).Mask,
				},
			},
			expectedMatchStr: "ct_label=0x80000000000000000000000000000000/0x80000000000000000000000000000000",
		},
		{
			name: "MatchCTLabelField (bits 0-127)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTLabelField(0x8000_0000_0000_0001, 0xa000_0000_0000_0001, NewCTLabel(0, 127))
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_LABEL,
					HasMask: true,
					Value:   openflow15.NewCTLabelMatchField([16]byte{0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xa0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}, nil).Value,
					Mask:    openflow15.NewCTLabelMatchField([16]byte{}, &[16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}).Mask,
				},
			},
			expectedMatchStr: "ct_label=0x8000000000000001a000000000000001",
		},
		{
			name: "MatchCTLabelField (bits 32-95)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTLabelField(0x8000_0001, 0xa000_0001_0000_0000, NewCTLabel(32, 95))
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_LABEL,
					HasMask: true,
					Value:   openflow15.NewCTLabelMatchField([16]byte{0x0, 0x0, 0x0, 0x0, 0x80, 0x0, 0x0, 0x1, 0xa0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0}, nil).Value,
					Mask:    openflow15.NewCTLabelMatchField([16]byte{}, &[16]byte{0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0}).Mask,
				},
			},
			expectedMatchStr: "ct_label=0x80000001a000000100000000/0xffffffffffffffff00000000",
		},
		{
			name: "MatchCTLabelField (bits 0-64)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTLabelField(0x1, 0xa000_0000_0000_0001, NewCTLabel(0, 64))
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_LABEL,
					HasMask: true,
					Value:   openflow15.NewCTLabelMatchField([16]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xa0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}, nil).Value,
					Mask:    openflow15.NewCTLabelMatchField([16]byte{}, &[16]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}).Mask,
				},
			},
			expectedMatchStr: "ct_label=0x1a000000000000001/0x1ffffffffffffffff",
		},
		{
			name: "MatchCTLabelField (bits 0-63)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTLabelField(0, 0xa000_0000_0000_0001, NewCTLabel(0, 63))
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_LABEL,
					HasMask: true,
					Value:   openflow15.NewCTLabelMatchField([16]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}, nil).Value,
					Mask:    openflow15.NewCTLabelMatchField([16]byte{}, &[16]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}).Mask,
				},
			},
			expectedMatchStr: "ct_label=0xa000000000000001/0xffffffffffffffff",
		},
		{
			name: "MatchCTLabelField (bits 64-127)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTLabelField(0xa000_0000_0000_0001, 0, NewCTLabel(64, 127))
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_LABEL,
					HasMask: true,
					Value:   openflow15.NewCTLabelMatchField([16]byte{0xa0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, nil).Value,
					Mask:    openflow15.NewCTLabelMatchField([16]byte{}, &[16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}).Mask,
				},
			},
			expectedMatchStr: "ct_label=0xa0000000000000010000000000000000/0xffffffffffffffff0000000000000000",
		},
		{
			name: "MatchInPort",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchInPort(1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IN_PORT,
					Value: &openflow15.InPortField{InPort: 1},
				},
			},
			expectedMatchStr: "in_port=1",
		},
		{
			name: "MatchSrcIP (IPv4)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchSrcIP(ipv4Addr1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IPV4_SRC,
					Value: &openflow15.Ipv4SrcField{Ipv4Src: ipv4Addr1},
				},
			},
			expectedMatchStr: "nw_src=1.1.1.1",
		},
		{
			name: "MatchSrcIP (IPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchSrcIP(ipv6Addr1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IPV6_SRC,
					Value: &openflow15.Ipv6SrcField{Ipv6Src: ipv6Addr1},
				},
			},
			expectedMatchStr: "ipv6_src=fec0::1111",
		},
		{
			name: "MatchDstIP (IPv4)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchDstIP(ipv4Addr1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IPV4_DST,
					Value: &openflow15.Ipv4DstField{Ipv4Dst: ipv4Addr1},
				},
			},
			expectedMatchStr: "nw_dst=1.1.1.1",
		},
		{
			name: "MatchDstIP (IPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchDstIP(ipv6Addr1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IPV6_DST,
					Value: &openflow15.Ipv6DstField{Ipv6Dst: ipv6Addr1},
				},
			},
			expectedMatchStr: "ipv6_dst=fec0::1111",
		},
		{
			name: "MatchSrcIPNet (IPv4)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchSrcIPNet(*ipv4Net1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field:   openflow15.OXM_FIELD_IPV4_SRC,
					HasMask: true,
					Value:   &openflow15.Ipv4SrcField{Ipv4Src: ipv4Net1.IP},
					Mask:    &openflow15.Ipv4SrcField{Ipv4Src: net.IP(ipv4Net1.Mask)},
				},
			},
			expectedMatchStr: "nw_src=1.1.1.0/24",
		},
		{
			name: "MatchSrcIPNet (IPv4)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchSrcIPNet(*ipv4Net2)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field:   openflow15.OXM_FIELD_IPV4_SRC,
					HasMask: true,
					Value:   &openflow15.Ipv4SrcField{Ipv4Src: ipv4Net2.IP},
					Mask:    &openflow15.Ipv4SrcField{Ipv4Src: net.IP(ipv4Net2.Mask)},
				},
			},
			expectedMatchStr: "nw_src=1.1.1.1",
		},
		{
			name: "MatchSrcIPNet (IPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchSrcIPNet(*ipv6Net1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field:   openflow15.OXM_FIELD_IPV6_SRC,
					HasMask: true,
					Value:   &openflow15.Ipv6SrcField{Ipv6Src: ipv6Net1.IP},
					Mask:    &openflow15.Ipv6SrcField{Ipv6Src: net.IP(ipv6Net1.Mask)},
				},
			},
			expectedMatchStr: "ipv6_src=fec0::/64",
		},
		{
			name: "MatchSrcIPNet (IPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchSrcIPNet(*ipv6Net2)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field:   openflow15.OXM_FIELD_IPV6_SRC,
					HasMask: true,
					Value:   &openflow15.Ipv6SrcField{Ipv6Src: ipv6Net2.IP},
					Mask:    &openflow15.Ipv6SrcField{Ipv6Src: net.IP(ipv6Net2.Mask)},
				},
			},
			expectedMatchStr: "ipv6_src=fec0::ffff",
		},
		{
			name: "MatchDstIPNet (IPv4)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchDstIPNet(*ipv4Net1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field:   openflow15.OXM_FIELD_IPV4_DST,
					HasMask: true,
					Value:   &openflow15.Ipv4DstField{Ipv4Dst: ipv4Net1.IP},
					Mask:    &openflow15.Ipv4DstField{Ipv4Dst: net.IP(ipv4Net1.Mask)},
				},
			},
			expectedMatchStr: "nw_dst=1.1.1.0/24",
		},
		{
			name: "MatchDstIPNet (IPv4)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchDstIPNet(*ipv4Net2)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field:   openflow15.OXM_FIELD_IPV4_DST,
					HasMask: true,
					Value:   &openflow15.Ipv4DstField{Ipv4Dst: ipv4Net2.IP},
					Mask:    &openflow15.Ipv4DstField{Ipv4Dst: net.IP(ipv4Net2.Mask)},
				},
			},
			expectedMatchStr: "nw_dst=1.1.1.1",
		},
		{
			name: "MatchDstIPNet (IPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchDstIPNet(*ipv6Net1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field:   openflow15.OXM_FIELD_IPV6_DST,
					HasMask: true,
					Value:   &openflow15.Ipv6DstField{Ipv6Dst: ipv6Net1.IP},
					Mask:    &openflow15.Ipv6DstField{Ipv6Dst: net.IP(ipv6Net1.Mask)},
				},
			},
			expectedMatchStr: "ipv6_dst=fec0::/64",
		},
		{
			name: "MatchDstIPNet (IPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchDstIPNet(*ipv6Net2)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field:   openflow15.OXM_FIELD_IPV6_DST,
					HasMask: true,
					Value:   &openflow15.Ipv6DstField{Ipv6Dst: ipv6Net2.IP},
					Mask:    &openflow15.Ipv6DstField{Ipv6Dst: net.IP(ipv6Net2.Mask)},
				},
			},
			expectedMatchStr: "ipv6_dst=fec0::ffff",
		},
		{
			name: "MatchICMPv6Type",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchICMPv6Type(3)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_ICMPV6_TYPE,
					Value: &openflow15.IcmpTypeField{Type: 3},
				},
			},
			expectedMatchStr: "icmp_type=3",
		},
		{
			name: "MatchICMPType",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchICMPType(3)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_0,
					Field: openflow15.NXM_OF_ICMP_TYPE,
					Value: &openflow15.IcmpTypeField{Type: 3},
				},
			},
			expectedMatchStr: "icmp_type=3",
		},
		{
			name: "MatchICMPv6Code",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchICMPv6Code(10)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_ICMPV6_CODE,
					Value: &openflow15.IcmpCodeField{Code: 10},
				},
			},
			expectedMatchStr: "icmp_code=10",
		},
		{
			name: "MatchICMPCode",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchICMPCode(10)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_0,
					Field: openflow15.NXM_OF_ICMP_CODE,
					Value: &openflow15.IcmpCodeField{Code: 10},
				},
			},
			expectedMatchStr: "icmp_code=10",
		},
		{
			name: "MatchSrcMAC",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchSrcMAC(mac)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_SRC,
					Value: &openflow15.EthSrcField{EthSrc: mac},
				},
			},
			expectedMatchStr: "dl_src=aa:bb:cc:dd:ee:ff",
		},
		{
			name: "MatchDstMAC",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchDstMAC(mac)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_DST,
					Value: &openflow15.EthDstField{EthDst: mac},
				},
			},
			expectedMatchStr: "dl_dst=aa:bb:cc:dd:ee:ff",
		},
		{
			name: "MatchARPSha",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchARPSha(mac)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ARP_SHA,
					Value: &openflow15.ArpXHaField{ArpHa: mac},
				},
			},
			expectedMatchStr: "arp_sha=aa:bb:cc:dd:ee:ff",
		},
		{
			name: "MatchARPTha",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchARPTha(mac)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ARP_THA,
					Value: &openflow15.ArpXHaField{ArpHa: mac},
				},
			},
			expectedMatchStr: "arp_tha=aa:bb:cc:dd:ee:ff",
		},
		{
			name: "MatchARPSpa",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchARPSpa(ipv4Addr1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ARP_SPA,
					Value: &openflow15.ArpXPaField{ArpPa: ipv4Addr1},
				},
			},
			expectedMatchStr: "arp_spa=1.1.1.1",
		},
		{
			name: "MatchARPTpa",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchARPTpa(ipv4Addr1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ARP_TPA,
					Value: &openflow15.ArpXPaField{ArpPa: ipv4Addr1},
				},
			},
			expectedMatchStr: "arp_tpa=1.1.1.1",
		},
		{
			name: "MatchARPOp",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchARPOp(1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ARP_OP,
					Value: &openflow15.ArpOperField{ArpOper: 1},
				},
			},
			expectedMatchStr: "arp_op=1",
		},
		{
			name: "MatchIPDSCP",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchIPDSCP(1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IP_DSCP,
					Value: &openflow15.IpDscpField{Dscp: 1},
				},
			},
			expectedMatchStr: "ip_dscp=1",
		},
		{
			name: "MatchConjID",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchConjID(1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CONJ_ID,
					Value: &openflow15.Uint32Message{Data: 1},
				},
			},
			expectedMatchStr: "conj_id=1",
		},
		{
			name: "MatchProtocol (ProtocolIP)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchProtocol(ProtocolIP)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_TYPE,
					Value: &openflow15.EthTypeField{EthType: 0x0800},
				},
			},
			expectedMatchStr: "ip",
		},
		{
			name: "MatchProtocol (ProtocolIPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchProtocol(ProtocolIPv6)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_TYPE,
					Value: &openflow15.EthTypeField{EthType: 0x86dd},
				},
			},
			expectedMatchStr: "ipv6",
		},
		{
			name: "MatchProtocol (ProtocolARP)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchProtocol(ProtocolARP)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_TYPE,
					Value: &openflow15.EthTypeField{EthType: 0x0806},
				},
			},
			expectedMatchStr: "arp",
		},
		{
			name: "MatchProtocol (ProtocolTCP)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchProtocol(ProtocolTCP)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_TYPE,
					Value: &openflow15.EthTypeField{EthType: 0x0800},
				},
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IP_PROTO,
					Value: &openflow15.IpProtoField{Protocol: 6},
				},
			},
			expectedMatchStr: "tcp",
		},
		{
			name: "MatchProtocol (ProtocolTCPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchProtocol(ProtocolTCPv6)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_TYPE,
					Value: &openflow15.EthTypeField{EthType: 0x86dd},
				},
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IP_PROTO,
					Value: &openflow15.IpProtoField{Protocol: 6},
				},
			},
			expectedMatchStr: "tcp6",
		},
		{
			name: "MatchProtocol (ProtocolUDP)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchProtocol(ProtocolUDP)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_TYPE,
					Value: &openflow15.EthTypeField{EthType: 0x0800},
				},
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IP_PROTO,
					Value: &openflow15.IpProtoField{Protocol: 17},
				},
			},
			expectedMatchStr: "udp",
		},
		{
			name: "MatchProtocol (ProtocolUDPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchProtocol(ProtocolUDPv6)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_TYPE,
					Value: &openflow15.EthTypeField{EthType: 0x86dd},
				},
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IP_PROTO,
					Value: &openflow15.IpProtoField{Protocol: 17},
				},
			},
			expectedMatchStr: "udp6",
		},
		{
			name: "MatchProtocol (ProtocolSCTP)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchProtocol(ProtocolSCTP)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_TYPE,
					Value: &openflow15.EthTypeField{EthType: 0x800},
				},
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IP_PROTO,
					Value: &openflow15.IpProtoField{Protocol: 132},
				},
			},
			expectedMatchStr: "sctp",
		},
		{
			name: "MatchProtocol (ProtocolSCTPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchProtocol(ProtocolSCTPv6)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_TYPE,
					Value: &openflow15.EthTypeField{EthType: 0x86dd},
				},
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IP_PROTO,
					Value: &openflow15.IpProtoField{Protocol: 132},
				},
			},
			expectedMatchStr: "sctp6",
		},
		{
			name: "MatchProtocol (ProtocolICMP)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchProtocol(ProtocolICMP)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_TYPE,
					Value: &openflow15.EthTypeField{EthType: 0x0800},
				},
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IP_PROTO,
					Value: &openflow15.IpProtoField{Protocol: 1},
				},
			},
			expectedMatchStr: "icmp",
		},
		{
			name: "MatchProtocol (ProtocolICMPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchProtocol(ProtocolICMPv6)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_TYPE,
					Value: &openflow15.EthTypeField{EthType: 0x86dd},
				},
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IP_PROTO,
					Value: &openflow15.IpProtoField{Protocol: 58},
				},
			},
			expectedMatchStr: "icmp6",
		},
		{
			name: "MatchProtocol (ProtocolIGMP)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchProtocol(ProtocolIGMP)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_TYPE,
					Value: &openflow15.EthTypeField{EthType: 0x0800},
				},
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IP_PROTO,
					Value: &openflow15.IpProtoField{Protocol: 2},
				},
			},
			expectedMatchStr: "igmp",
		},
		{
			name: "MatchIPProtocolValue (IPv4 TCP)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchIPProtocolValue(false, protocol.Type_TCP)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_TYPE,
					Value: &openflow15.EthTypeField{EthType: 0x0800},
				},
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IP_PROTO,
					Value: &openflow15.IpProtoField{Protocol: 6},
				},
			},
			expectedMatchStr: "tcp",
		},
		{
			name: "MatchIPProtocolValue (IPv6 TCP)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchIPProtocolValue(true, protocol.Type_TCP)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_TYPE,
					Value: &openflow15.EthTypeField{EthType: 0x086dd},
				},
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IP_PROTO,
					Value: &openflow15.IpProtoField{Protocol: 6},
				},
			},
			expectedMatchStr: "tcp6",
		},
		{
			name: "MatchIPProtocolValue (IPv4 UDP)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchIPProtocolValue(true, protocol.Type_TCP)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_TYPE,
					Value: &openflow15.EthTypeField{EthType: 0x086dd},
				},
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IP_PROTO,
					Value: &openflow15.IpProtoField{Protocol: 6},
				},
			},
			expectedMatchStr: "tcp6",
		},
		{
			name: "MatchIPProtocolValue (IPv6 UDP)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchIPProtocolValue(true, protocol.Type_UDP)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_ETH_TYPE,
					Value: &openflow15.EthTypeField{EthType: 0x086dd},
				},
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_IP_PROTO,
					Value: &openflow15.IpProtoField{Protocol: 17},
				},
			},
			expectedMatchStr: "udp6",
		},
		{
			name: "MatchSrcPort (without mask)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchSrcPort(0xf001, nil)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_TCP_SRC,
					Value: &openflow15.PortField{Port: 0xf001},
				},
			},
			expectedMatchStr: "tp_src=61441",
		},
		{
			name: "MatchSrcPort (with mask)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchSrcPort(0xf001, &portMask)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field:   openflow15.OXM_FIELD_TCP_SRC,
					HasMask: true,
					Value:   &openflow15.PortField{Port: 0xf001},
					Mask:    &openflow15.PortField{Port: portMask},
				},
			},
			expectedMatchStr: "tp_src=0xf001/0xf000",
		},
		{
			name: "MatchDstPort (without mask)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchDstPort(0xf001, nil)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field: openflow15.OXM_FIELD_TCP_DST,
					Value: &openflow15.PortField{Port: 0xf001},
				},
			},
			expectedMatchStr: "tp_dst=61441",
		},
		{
			name: "MatchDstPort (with mask)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchDstPort(0xf001, &portMask)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_OPENFLOW_BASIC,
					Field:   openflow15.OXM_FIELD_TCP_DST,
					HasMask: true,
					Value:   &openflow15.PortField{Port: 0xf001},
					Mask:    &openflow15.PortField{Port: portMask},
				},
			},
			expectedMatchStr: "tp_dst=0xf001/0xf000",
		},
		{
			name: "MatchCTSrcIP (IPv4)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTSrcIP(ipv4Addr1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_NW_SRC,
					Value: &openflow15.Ipv4SrcField{Ipv4Src: ipv4Addr1},
				},
			},
			expectedMatchStr: "ct_nw_src=1.1.1.1",
		},
		{
			name: "MatchCTSrcIP (IPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTSrcIP(ipv6Addr1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_IPV6_SRC,
					Value: &openflow15.Ipv6SrcField{Ipv6Src: ipv6Addr1},
				},
			},
			expectedMatchStr: "ct_ipv6_src=fec0::1111",
		},
		{
			name: "MatchCTDstIP (IPv4)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTDstIP(ipv4Addr1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_NW_DST,
					Value: &openflow15.Ipv4DstField{Ipv4Dst: ipv4Addr1},
				},
			},
			expectedMatchStr: "ct_nw_dst=1.1.1.1",
		},
		{
			name: "MatchCTDstIP (IPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTDstIP(ipv6Addr1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_IPV6_DST,
					Value: &openflow15.Ipv6DstField{Ipv6Dst: ipv6Addr1},
				},
			},
			expectedMatchStr: "ct_ipv6_dst=fec0::1111",
		},
		{
			name: "MatchCTSrcIPNet (IPv4)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTSrcIPNet(*ipv4Net1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_NW_SRC,
					HasMask: true,
					Value:   &openflow15.Ipv4SrcField{Ipv4Src: ipv4Net1.IP},
					Mask:    &openflow15.Ipv4SrcField{Ipv4Src: net.IP(ipv4Net1.Mask)},
				},
			},
			expectedMatchStr: "ct_nw_src=1.1.1.0/24",
		},
		{
			name: "MatchCTSrcIPNet (IPv4)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTSrcIPNet(*ipv4Net2)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_NW_SRC,
					HasMask: true,
					Value:   &openflow15.Ipv4SrcField{Ipv4Src: ipv4Net2.IP},
					Mask:    &openflow15.Ipv4SrcField{Ipv4Src: net.IP(ipv4Net2.Mask)},
				},
			},
			expectedMatchStr: "ct_nw_src=1.1.1.1",
		},
		{
			name: "MatchCTSrcIPNet (IPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTSrcIPNet(*ipv6Net1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_IPV6_SRC,
					HasMask: true,
					Value:   &openflow15.Ipv6SrcField{Ipv6Src: ipv6Net1.IP},
					Mask:    &openflow15.Ipv6SrcField{Ipv6Src: net.IP(ipv6Net1.Mask)},
				},
			},
			expectedMatchStr: "ct_ipv6_src=fec0::/64",
		},
		{
			name: "MatchCTSrcIPNet (IPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTSrcIPNet(*ipv6Net2)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_IPV6_SRC,
					HasMask: true,
					Value:   &openflow15.Ipv6SrcField{Ipv6Src: ipv6Net2.IP},
					Mask:    &openflow15.Ipv6SrcField{Ipv6Src: net.IP(ipv6Net2.Mask)},
				},
			},
			expectedMatchStr: "ct_ipv6_src=fec0::ffff",
		},
		{
			name: "MatchCTDstIPNet (IPv4)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTDstIPNet(*ipv4Net1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_NW_DST,
					HasMask: true,
					Value:   &openflow15.Ipv4DstField{Ipv4Dst: ipv4Net1.IP},
					Mask:    &openflow15.Ipv4DstField{Ipv4Dst: net.IP(ipv4Net1.Mask)},
				},
			},
			expectedMatchStr: "ct_nw_dst=1.1.1.0/24",
		},
		{
			name: "MatchCTDstIPNet (IPv4)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTDstIPNet(*ipv4Net2)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_NW_DST,
					HasMask: true,
					Value:   &openflow15.Ipv4DstField{Ipv4Dst: ipv4Net2.IP},
					Mask:    &openflow15.Ipv4DstField{Ipv4Dst: net.IP(ipv4Net2.Mask)},
				},
			},
			expectedMatchStr: "ct_nw_dst=1.1.1.1",
		},
		{
			name: "MatchCTDstIPNet (IPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTDstIPNet(*ipv6Net1)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_IPV6_DST,
					HasMask: true,
					Value:   &openflow15.Ipv6DstField{Ipv6Dst: ipv6Net1.IP},
					Mask:    &openflow15.Ipv6DstField{Ipv6Dst: net.IP(ipv6Net1.Mask)},
				},
			},
			expectedMatchStr: "ct_ipv6_dst=fec0::/64",
		},
		{
			name: "MatchCTDstIPNet (IPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTDstIPNet(*ipv6Net2)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class:   openflow15.OXM_CLASS_NXM_1,
					Field:   openflow15.NXM_NX_CT_IPV6_DST,
					HasMask: true,
					Value:   &openflow15.Ipv6DstField{Ipv6Dst: ipv6Net2.IP},
					Mask:    &openflow15.Ipv6DstField{Ipv6Dst: net.IP(ipv6Net2.Mask)},
				},
			},
			expectedMatchStr: "ct_ipv6_dst=fec0::ffff",
		},
		{
			name: "MatchCTSrcPort",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTSrcPort(0xf001)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_TP_SRC,
					Value: &ofctrl.PortField{Port: 0xf001},
				},
			},
			expectedMatchStr: "ct_tp_src=61441",
		},
		{
			name: "MatchCTDstPort",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTDstPort(0xf001)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_TP_DST,
					Value: &ofctrl.PortField{Port: 0xf001},
				},
			},
			expectedMatchStr: "ct_tp_dst=61441",
		},
		{
			name: "MatchCTProtocol (ProtocolTCP)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTProtocol(ProtocolTCPv6)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_NW_PROTO,
					Value: &ofctrl.ProtocolField{Protocol: 0x6},
				},
			},
			expectedMatchStr: "ct_nw_proto=6",
		},
		{
			name: "MatchCTProtocol (ProtocolTCPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTProtocol(ProtocolTCPv6)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_NW_PROTO,
					Value: &ofctrl.ProtocolField{Protocol: 0x6},
				},
			},
			expectedMatchStr: "ct_nw_proto=6",
		},
		{
			name: "MatchCTProtocol (ProtocolUDP)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTProtocol(ProtocolUDP)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_NW_PROTO,
					Value: &ofctrl.ProtocolField{Protocol: 0x11},
				},
			},
			expectedMatchStr: "ct_nw_proto=17",
		},
		{
			name: "MatchCTProtocol (ProtocolUDPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTProtocol(ProtocolUDPv6)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_NW_PROTO,
					Value: &ofctrl.ProtocolField{Protocol: 0x11},
				},
			},
			expectedMatchStr: "ct_nw_proto=17",
		},
		{
			name: "MatchCTProtocol (ProtocolSCTP)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTProtocol(ProtocolSCTP)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_NW_PROTO,
					Value: &ofctrl.ProtocolField{Protocol: 0x84},
				},
			},
			expectedMatchStr: "ct_nw_proto=132",
		},
		{
			name: "MatchCTProtocol (ProtocolSCTPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTProtocol(ProtocolSCTPv6)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_NW_PROTO,
					Value: &ofctrl.ProtocolField{Protocol: 0x84},
				},
			},
			expectedMatchStr: "ct_nw_proto=132",
		},
		{
			name: "MatchCTProtocol (ProtocolICMP)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTProtocol(ProtocolICMP)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_NW_PROTO,
					Value: &ofctrl.ProtocolField{Protocol: 0x1},
				},
			},
			expectedMatchStr: "ct_nw_proto=1",
		},
		{
			name: "MatchCTProtocol (ProtocolICMPv6)",
			matchFn: func(fb FlowBuilder) FlowBuilder {
				return fb.MatchCTProtocol(ProtocolICMPv6)
			},
			expectedMatchFields: []*openflow15.MatchField{
				{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_CT_NW_PROTO,
					Value: &ofctrl.ProtocolField{Protocol: 0x3a},
				},
			},
			expectedMatchStr: "ct_nw_proto=58",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flowMod := getFlowMod(t, tc.matchFn(table.BuildFlow(1)).Done())
			require.Equal(t, len(tc.expectedMatchFields), len(flowMod.Match.Fields))
			for i, expectedMatchField := range tc.expectedMatchFields {
				checkMatchField(t, expectedMatchField, &flowMod.Match.Fields[i])
			}
			assert.Contains(t, FlowModToString(flowMod), tc.expectedMatchStr)
		})
	}
}
