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
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getGroupMod(t *testing.T, g Group) *openflow15.GroupMod {
	msgs, err := g.GetBundleMessages(AddMessage)
	assert.NoError(t, err)
	require.Equal(t, 1, len(msgs))
	return msgs[0].GetMessage().(*openflow15.GroupMod)
}

func TestBucketBuilder(t *testing.T) {
	testCases := []struct {
		name                string
		bucketFn            func(BucketBuilder) BucketBuilder
		expectedProperty    util.Message
		expectedActionField openflow15.Action
		expectedActionStr   string
	}{
		{
			name: "Weight",
			bucketFn: func(fb BucketBuilder) BucketBuilder {
				return fb.Weight(100)
			},
			expectedProperty: &openflow15.GroupBucketPropWeight{
				Weight: 100,
			},
			expectedActionStr: "weight:100",
		},
		{
			name: "LoadToRegField (all bits)",
			bucketFn: func(fb BucketBuilder) BucketBuilder {
				return fb.LoadToRegField(NewRegField(1, 0, 31), uint32(0xffff_ffff))
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_REG1,
					Value: &openflow15.Uint32Message{Data: uint32(0xffff_ffff)},
					Mask:  &openflow15.Uint32Message{Data: uint32(0xffff_ffff)},
				},
			},
			expectedActionStr: "set_field:0xffffffff->reg1",
		},
		{
			name: "LoadToRegField (part bits)",
			bucketFn: func(fb BucketBuilder) BucketBuilder {
				return fb.LoadToRegField(NewRegField(1, 4, 15), uint32(0xf))
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_REG1,
					Value: &openflow15.Uint32Message{Data: uint32(0xf0)},
					Mask:  &openflow15.Uint32Message{Data: uint32(0xfff0)},
				},
			},
			expectedActionStr: "set_field:0xf0/0xfff0->reg1",
		},
		{
			name: "LoadXXReg (all bits)",
			bucketFn: func(fb BucketBuilder) BucketBuilder {
				return fb.LoadXXReg(0, []byte{0x11, 0x22, 0x33, 0x44})
			},
			expectedActionField: &openflow15.ActionSetField{
				Field: openflow15.MatchField{
					Class: openflow15.OXM_CLASS_NXM_1,
					Field: openflow15.NXM_NX_XXREG0,
					Value: util.NewBuffer([]byte{0x11, 0x22, 0x33, 0x44}),
				},
			},
			expectedActionStr: "set_field:0x11223344->xxreg0",
		},
		{
			name: "SetTunnelDst (IPv4)",
			bucketFn: func(fb BucketBuilder) BucketBuilder {
				return fb.SetTunnelDst(ipv4Addr1)
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
			bucketFn: func(fb BucketBuilder) BucketBuilder {
				return fb.SetTunnelDst(ipv6Addr1)
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
			name: "ResubmitToTable",
			bucketFn: func(fb BucketBuilder) BucketBuilder {
				return fb.ResubmitToTable(tableID1)
			},
			expectedActionField: &openflow15.NXActionResubmitTable{
				TableID: tableID1,
			},
			expectedActionStr: "resubmit:100",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := &ofGroup{ofctrl: &ofctrl.Group{}}
			groupMod := getGroupMod(t, tc.bucketFn(g.Bucket()).Done())
			assert.Equal(t, 1, len(groupMod.Buckets))

			actions := groupMod.Buckets[0].Actions
			properties := groupMod.Buckets[0].Properties

			if tc.expectedProperty != nil {
				require.Equal(t, 1, len(properties))
				assert.Equal(t, tc.expectedProperty, properties[0])
			}
			if tc.expectedActionField != nil {
				require.Equal(t, 1, len(actions))
				action := actions[0]
				switch expected := tc.expectedActionField.(type) {
				case *openflow15.ActionSetField:
					checkActionSetField(t, expected, action)
				case *openflow15.NXActionResubmitTable:
					assert.Equal(t, expected.TableID, action.(*openflow15.NXActionResubmitTable).TableID)
				default:
					t.Fatalf("Unknown type %v", action)
				}
			}
			assert.Contains(t, GroupModToString(groupMod), tc.expectedActionStr)
		})
	}
}
