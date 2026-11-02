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

package openflow

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/v2/pkg/agent/config"
	opstest "antrea.io/antrea/v2/pkg/agent/openflow/operations/testing"
	"antrea.io/antrea/v2/pkg/agent/types"
)

func Test_client_InstallPodL2DispatchFlows(t *testing.T) {
	ofPort := uint32(100)
	// The actions which follow the pkt_mark actions of the flows.
	regActions := "set_field:0x20/0xf0->reg0,set_field:0x80000/0x80000->reg0,goto_table:L2ForwardingCalc"
	testCases := []struct {
		name                  string
		snatIP                net.IP
		peerIndex             uint32
		trafficShapingEnabled bool
		expectedFlows         []string
	}{
		{
			// pkt_mark gets the flag of the l2 dispatch, bit 29, and the index 3 in bits 16 to 27. Bit 28 is not changed.
			name:      "IPv4",
			snatIP:    net.ParseIP("192.168.77.101"),
			peerIndex: 3,
			expectedFlows: []string{
				"cookie=0x1040000000000, table=EgressMark, priority=200,ct_state=+trk,ip,in_port=100 " +
					"actions=set_field:0x20000000/0x20000000->pkt_mark,set_field:0x30000/0xfff0000->pkt_mark," + regActions,
			},
		},
		{
			name:      "IPv6 with the largest index",
			snatIP:    net.ParseIP("fd00::101"),
			peerIndex: types.MaxL2DispatchPeerIndex,
			expectedFlows: []string{
				"cookie=0x1040000000000, table=EgressMark, priority=200,ct_state=+trk,ipv6,in_port=100 " +
					"actions=set_field:0x20000000/0x20000000->pkt_mark,set_field:0xfff0000/0xfff0000->pkt_mark," + regActions,
			},
		},
		{
			// The bandwidth of an Egress applies on its Egress Node, so the flow does not use the meter table.
			name:                  "traffic shaping",
			snatIP:                net.ParseIP("192.168.77.101"),
			peerIndex:             3,
			trafficShapingEnabled: true,
			expectedFlows: []string{
				"cookie=0x1040000000000, table=EgressMark, priority=200,ct_state=+trk,ip,in_port=100 " +
					"actions=set_field:0x20000000/0x20000000->pkt_mark,set_field:0x30000/0xfff0000->pkt_mark," + regActions,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)
			fc := newFakeClient(m, true, true, config.K8sNode, config.TrafficEncapModeNoEncap,
				setEnableEgressTrafficShaping(tc.trafficShapingEnabled))
			defer resetPipelines()

			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
			m.EXPECT().DeleteAll(gomock.Any()).Return(nil).Times(1)
			cacheKey := fmt.Sprintf("p%x", ofPort)

			require.NoError(t, fc.InstallPodL2DispatchFlows(ofPort, tc.snatIP, tc.peerIndex))
			fCacheI, ok := fc.featureEgress.cachedFlows.Load(cacheKey)
			require.True(t, ok)
			assert.ElementsMatch(t, tc.expectedFlows, getFlowStrings(fCacheI))

			// UninstallPodSNATFlows removes the flows, like those of InstallPodSNATFlows.
			require.NoError(t, fc.UninstallPodSNATFlows(ofPort))
			_, ok = fc.featureEgress.cachedFlows.Load(cacheKey)
			assert.False(t, ok)
		})
	}
}
