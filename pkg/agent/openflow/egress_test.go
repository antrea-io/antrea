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
	"testing"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/agent/config"
)

func egressInitFlows(isIPv4 bool) []string {
	if isIPv4 {
		return []string{
			"cookie=0x1040000000000, table=L3Forwarding, priority=190,ct_state=-rpl+trk,ip,reg0=0x3/0xf,reg4=0x0/0x100000 actions=goto_table:EgressMark",
			"cookie=0x1040000000000, table=L3Forwarding, priority=190,ct_state=-rpl+trk,ip,reg0=0x1/0xf actions=set_field:0a:00:00:00:00:01->eth_dst,goto_table:EgressMark",
			"cookie=0x1040000000000, table=EgressMark, priority=210,ip,nw_dst=192.168.78.0/24 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
			"cookie=0x1040000000000, table=EgressMark, priority=210,ip,nw_dst=192.168.77.100 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
			"cookie=0x1040000000000, table=EgressMark, priority=190,ct_state=+new+trk,ip,reg0=0x1/0xf actions=drop",
			"cookie=0x1040000000000, table=EgressMark, priority=0 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
		}
	}
	return []string{
		"cookie=0x1040000000000, table=L3Forwarding, priority=190,ct_state=-rpl+trk,ipv6,reg0=0x3/0xf,reg4=0x0/0x100000 actions=goto_table:EgressMark",
		"cookie=0x1040000000000, table=L3Forwarding, priority=190,ct_state=-rpl+trk,ipv6,reg0=0x1/0xf actions=set_field:0a:00:00:00:00:01->eth_dst,goto_table:EgressMark",
		"cookie=0x1040000000000, table=EgressMark, priority=210,ipv6,ipv6_dst=fec0:192:168:78::/80 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
		"cookie=0x1040000000000, table=EgressMark, priority=210,ipv6,ipv6_dst=fec0:192:168:77::100 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
		"cookie=0x1040000000000, table=EgressMark, priority=190,ct_state=+new+trk,ipv6,reg0=0x1/0xf actions=drop",
		"cookie=0x1040000000000, table=EgressMark, priority=0 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
	}
}

func Test_featureEgress_initFlows(t *testing.T) {
	testCases := []struct {
		name          string
		enableIPv4    bool
		enableIPv6    bool
		expectedFlows []string
	}{
		{
			name:          "IPv4",
			enableIPv4:    true,
			expectedFlows: egressInitFlows(true),
		},
		{
			name:          "IPv6",
			enableIPv6:    true,
			expectedFlows: egressInitFlows(false),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fc := newFakeClient(nil, tc.enableIPv4, tc.enableIPv6, config.K8sNode, config.TrafficEncapModeEncap)
			defer resetPipelines()

			flows := getFlowStrings(fc.featureEgress.initFlows())
			assert.ElementsMatch(t, tc.expectedFlows, flows)
		})
	}
}
