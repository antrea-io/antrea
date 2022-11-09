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

func Test_featureMulticast_initFlows(t *testing.T) {
	testCases := []struct {
		name             string
		enableIPv4       bool
		enableIPv6       bool
		trafficEncapMode config.TrafficEncapModeType
		clientOptions    []clientOptionsFn
		expectedFlows    []string
	}{
		{
			name:             "IPv4,Encap",
			enableIPv4:       true,
			trafficEncapMode: config.TrafficEncapModeEncap,
			clientOptions:    []clientOptionsFn{enableMulticast},
			expectedFlows: []string{
				"cookie=0x1050000000000, table=MulticastEgressRule, priority=64990,igmp,reg0=0x3/0xf actions=goto_table:MulticastRouting",
				"cookie=0x1050000000000, table=MulticastEgressPodMetric, priority=210,igmp actions=goto_table:MulticastRouting",
				"cookie=0x1050000000000, table=MulticastRouting, priority=210,igmp,reg0=0x3/0xf actions=set_field:0x20000/0x3e000->reg0,controller:(reason=no_match,max_len=128,id=32776)",
				"cookie=0x1050000000000, table=MulticastRouting, priority=210,igmp,reg0=0x1/0xf actions=set_field:0x20000/0x3e000->reg0,controller:(reason=no_match,max_len=128,id=32776)",
				"cookie=0x1050000000000, table=MulticastRouting, priority=190,ip actions=set_field:0x100/0x100->reg0,set_field:0x2->reg1,goto_table:MulticastOutput",
				"cookie=0x1050000000000, table=MulticastIngressPodMetric, priority=210,igmp actions=goto_table:MulticastOutput",
				"cookie=0x1050000000000, table=MulticastOutput, priority=210,reg0=0x101/0x10f,reg1=0x2 actions=drop",
				"cookie=0x1050000000000, table=MulticastOutput, priority=210,reg0=0x102/0x10f,reg1=0x1 actions=drop",
				"cookie=0x1050000000000, table=MulticastOutput, priority=200,reg0=0x100/0x100 actions=output:NXM_NX_REG1[]",
			},
		},
		{
			name:             "IPv4,NoEncap",
			enableIPv4:       true,
			trafficEncapMode: config.TrafficEncapModeNoEncap,
			clientOptions:    []clientOptionsFn{enableMulticast},
			expectedFlows: []string{
				"cookie=0x1050000000000, table=MulticastIngressPodMetric, priority=210,igmp actions=goto_table:MulticastOutput",
				"cookie=0x1050000000000, table=MulticastRouting, priority=210,igmp,reg0=0x3/0xf actions=set_field:0x20000/0x3e000->reg0,controller:(reason=no_match,max_len=128,id=32776)",
				"cookie=0x1050000000000, table=MulticastRouting, priority=190,ip actions=set_field:0x100/0x100->reg0,set_field:0x2->reg1,goto_table:MulticastOutput",
				"cookie=0x1050000000000, table=MulticastEgressPodMetric, priority=210,igmp actions=goto_table:MulticastRouting",
				"cookie=0x1050000000000, table=MulticastEgressRule, priority=64990,igmp,reg0=0x3/0xf actions=goto_table:MulticastRouting",
				"cookie=0x1050000000000, table=MulticastOutput, priority=200,reg0=0x100/0x100 actions=output:NXM_NX_REG1[]",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fc := newFakeClient(nil, tc.enableIPv4, tc.enableIPv6, config.K8sNode, tc.trafficEncapMode, tc.clientOptions...)
			defer resetPipelines()

			flows := getFlowStrings(fc.featureMulticast.initFlows())
			assert.ElementsMatch(t, tc.expectedFlows, flows)
		})
	}
}
