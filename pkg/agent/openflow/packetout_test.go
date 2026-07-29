// Copyright 2026 Antrea Authors
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

package openflow_test

import (
	"testing"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/agent/openflow"
	oftest "antrea.io/antrea/pkg/agent/openflow/testing"
)

// TestSendRejectPacketOutShortPacket exercises SendRejectPacketOut with short
// non-TCP IP packets whose marshaled IP header is smaller than ipHdrLen+8. On
// the unpatched code the ipHdr[:ipHdrLen+8] slice expression panics with
// "slice bounds out of range"; with the length clamp it must build a
// (truncated) ICMP reject packet without panicking.
func TestSendRejectPacketOutShortPacket(t *testing.T) {
	testCases := []struct {
		name     string
		isIPv6   bool
		proto    uint8
		ethernet *protocol.Ethernet
	}{
		{
			// 20-byte IPv4 packet with an unassigned protocol and no
			// payload: len(ipHdr)=20 < ipv4HdrLen(20)+8=28.
			name:   "IPv4 unassigned protocol, no payload",
			isIPv6: false,
			proto:  200,
			ethernet: &protocol.Ethernet{
				Ethertype: protocol.IPv4_MSG,
				Data:      &protocol.IPv4{Protocol: 200},
			},
		},
		{
			// 40-byte IPv6 packet with NextHeader=59 (no next header) and
			// zero payload: len(ipHdr)=40 < ipv6HdrLen(40)+8=48.
			name:   "IPv6 NextHeader=59, no payload",
			isIPv6: true,
			proto:  59,
			ethernet: &protocol.Ethernet{
				Ethertype: protocol.IPv6_MSG,
				Data:      &protocol.IPv6{NextHeader: 59, Data: util.NewBuffer([]byte{})},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockClient := oftest.NewMockClient(ctrl)
			mockClient.EXPECT().SendICMPPacketOut(
				gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
				gomock.Any(), gomock.Any(), tc.isIPv6, gomock.Any(),
				gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

			assert.NotPanics(t, func() {
				err := openflow.SendRejectPacketOut(mockClient,
					"00:11:22:33:44:55",
					"55:44:33:22:11:00",
					"10.0.0.1",
					"10.0.0.2",
					1,
					2,
					tc.isIPv6,
					tc.ethernet,
					tc.proto,
					nil)
				assert.NoError(t, err)
			})
		})
	}
}
