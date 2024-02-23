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
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/agent/config"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	openflowtest "antrea.io/antrea/pkg/ovs/openflow/testing"
)

func multicastInitFlows(isEncap bool) []string {
	if isEncap {
		return []string{
			"cookie=0x1050000000000, table=MulticastEgressRule, priority=64990,igmp,reg0=0x3/0xf actions=goto_table:MulticastRouting",
			"cookie=0x1050000000000, table=MulticastEgressPodMetric, priority=210,igmp actions=goto_table:MulticastRouting",
			"cookie=0x1050000000000, table=MulticastRouting, priority=210,igmp,reg0=0x3/0xf actions=controller(id=32776,reason=no_match,userdata=03,max_len=65535)",
			"cookie=0x1050000000000, table=MulticastRouting, priority=210,igmp,reg0=0x1/0xf actions=controller(id=32776,reason=no_match,userdata=03,max_len=65535)",
			"cookie=0x1050000000000, table=MulticastRouting, priority=190,ip actions=output:2",
			"cookie=0x1050000000000, table=MulticastIngressPodMetric, priority=210,igmp actions=goto_table:MulticastOutput",
			"cookie=0x1050000000000, table=MulticastOutput, priority=210,reg0=0x200001/0x60000f,reg1=0x2 actions=drop",
			"cookie=0x1050000000000, table=MulticastOutput, priority=210,reg0=0x200002/0x60000f,reg1=0x1 actions=drop",
			"cookie=0x1050000000000, table=MulticastOutput, priority=200,reg0=0x200000/0x600000 actions=output:NXM_NX_REG1[]",
		}
	}
	return []string{
		"cookie=0x1050000000000, table=MulticastIngressPodMetric, priority=210,igmp actions=goto_table:MulticastOutput",
		"cookie=0x1050000000000, table=MulticastRouting, priority=210,igmp,reg0=0x3/0xf actions=controller(id=32776,reason=no_match,userdata=03,max_len=65535)",
		"cookie=0x1050000000000, table=MulticastRouting, priority=190,ip actions=output:2",
		"cookie=0x1050000000000, table=MulticastEgressPodMetric, priority=210,igmp actions=goto_table:MulticastRouting",
		"cookie=0x1050000000000, table=MulticastEgressRule, priority=64990,igmp,reg0=0x3/0xf actions=goto_table:MulticastRouting",
		"cookie=0x1050000000000, table=MulticastOutput, priority=200,reg0=0x200000/0x600000 actions=output:NXM_NX_REG1[]",
	}
}

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
			expectedFlows:    multicastInitFlows(true),
		},
		{
			name:             "IPv4,NoEncap",
			enableIPv4:       true,
			trafficEncapMode: config.TrafficEncapModeNoEncap,
			clientOptions:    []clientOptionsFn{enableMulticast},
			expectedFlows:    multicastInitFlows(false),
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

// If any test case fails, please consider setting binding.MaxBucketsPerMessage to a smaller value.
func TestMulticastReceiversGroupMaxBuckets(t *testing.T) {
	fm := &featureMulticast{
		bridge: binding.NewOFBridge(bridgeName, ""),
	}

	testCases := []struct {
		name         string
		ports        []uint32
		remoteIPs    []net.IP
		expectedCall func(*openflowtest.MockTable)
	}{
		{
			name: "Only ports",
			ports: func() []uint32 {
				var ports []uint32
				for i := 0; i < binding.MaxBucketsPerMessage; i++ {
					ports = append(ports, uint32(i))
				}
				return ports
			}(),
			expectedCall: func(table *openflowtest.MockTable) {},
		},
		{
			name: "Only remote IPs",
			remoteIPs: func() []net.IP {
				var remoteIPs []net.IP
				sampleIP := net.ParseIP("192.168.1.1")
				for i := 0; i < binding.MaxBucketsPerMessage; i++ {
					remoteIPs = append(remoteIPs, sampleIP)
				}
				return remoteIPs
			}(),
			expectedCall: func(table *openflowtest.MockTable) {
				table.EXPECT().GetID().Return(uint8(1)).Times(binding.MaxBucketsPerMessage)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			fakeOfTable := openflowtest.NewMockTable(ctrl)
			MulticastOutputTable.ofTable = fakeOfTable
			defer func() {
				MulticastOutputTable.ofTable = nil
			}()

			tc.expectedCall(fakeOfTable)
			group := fm.multicastReceiversGroup(binding.GroupIDType(100), 0, tc.ports, tc.remoteIPs)
			messages, err := group.GetBundleMessages(binding.AddMessage)
			require.NoError(t, err)
			require.Equal(t, 1, len(messages))
			groupMod := messages[0].GetMessage().(*openflow15.GroupMod)
			errorMsg := fmt.Sprintf("The GroupMod size with %d buckets exceeds the OpenFlow message's maximum allowable size, please consider setting binding.MaxBucketsPerMessage to a smaller value.", binding.MaxBucketsPerMessage)
			require.LessOrEqual(t, getGroupModLen(groupMod), uint32(openflow15.MSG_MAX_LEN), errorMsg)
		})
	}
}
