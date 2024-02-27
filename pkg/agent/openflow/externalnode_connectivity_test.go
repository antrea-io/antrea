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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/agent/config"
	opstest "antrea.io/antrea/pkg/agent/openflow/operations/testing"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

func Test_client_InstallVMUplinkFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := opstest.NewMockOFEntryOperations(ctrl)

	fc := newFakeClient(m, true, true, config.ExternalNode, config.TrafficEncapModeEncap)
	defer resetPipelines()

	hostIFName := "ens192"
	hostPort := int32(20)
	uplinkPort := int32(21)
	expectedFlows := []string{
		"cookie=0x1080000000000, table=L2ForwardingCalc, priority=200,ip,in_port=20 actions=set_field:0x200000/0x600000->reg0,set_field:0x15->reg1,goto_table:IngressSecurityClassifier",
		"cookie=0x1080000000000, table=L2ForwardingCalc, priority=200,ip,in_port=21 actions=set_field:0x200000/0x600000->reg0,set_field:0x14->reg1,goto_table:IngressSecurityClassifier",
		"cookie=0x1080000000000, table=NonIP, priority=200,in_port=20 actions=output:21",
		"cookie=0x1080000000000, table=NonIP, priority=200,in_port=21 actions=output:20",
	}

	m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)
	m.EXPECT().DeleteAll(gomock.Any()).Return(nil).Times(1)

	assert.NoError(t, fc.InstallVMUplinkFlows(hostIFName, hostPort, uplinkPort))
	fCacheI, ok := fc.featureExternalNodeConnectivity.uplinkFlowCache.Load(hostIFName)
	require.True(t, ok)
	assert.ElementsMatch(t, expectedFlows, getFlowStrings(fCacheI.(flowMessageCache)))

	assert.NoError(t, fc.UninstallVMUplinkFlows(hostIFName))
	_, ok = fc.featureExternalNodeConnectivity.uplinkFlowCache.Load(hostIFName)
	require.False(t, ok)
}

func Test_client_InstallPolicyBypassFlows(t *testing.T) {
	protocol := binding.ProtocolTCP
	_, ipNet, _ := net.ParseCIDR("10.10.10.0/30")
	port := uint16(30000)

	testCases := []struct {
		name          string
		isIngress     bool
		expectedFlows []string
	}{
		{
			name:      "Ingress",
			isIngress: true,
			expectedFlows: []string{
				"cookie=0x1080000000000, table=IngressSecurityClassifier, priority=200,ct_state=+new+trk,tcp,nw_src=10.10.10.0/30,tp_dst=30000 actions=goto_table:IngressMetric",
			},
		},
		{
			name: "Egress",
			expectedFlows: []string{
				"cookie=0x1080000000000, table=EgressSecurityClassifier, priority=200,ct_state=+new+trk,tcp,nw_dst=10.10.10.0/30,tp_dst=30000 actions=goto_table:EgressMetric",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)

			fc := newFakeClient(m, true, true, config.ExternalNode, config.TrafficEncapModeEncap)
			defer resetPipelines()

			m.EXPECT().AddAll(gomock.Any()).Return(nil).Times(1)

			assert.NoError(t, fc.InstallPolicyBypassFlows(protocol, ipNet, port, tc.isIngress))
			fCacheI, ok := fc.featureExternalNodeConnectivity.uplinkFlowCache.Load(policyBypassFlowsKey)
			require.True(t, ok)
			assert.ElementsMatch(t, tc.expectedFlows, getFlowStrings(fCacheI))
		})
	}
}

func Test_featureExternalInodeConnectivity_initFlows(t *testing.T) {
	fc := newFakeClient(nil, true, false, config.ExternalNode, config.TrafficEncapModeEncap)
	defer resetPipelines()

	expectedFlows := []string{
		"cookie=0x1080000000000, table=ConntrackZone, priority=200,ip actions=ct(table=ConntrackState,zone=65520)",
		"cookie=0x1080000000000, table=ConntrackState, priority=210,ct_state=+inv+trk,ip actions=drop",
		"cookie=0x1080000000000, table=ConntrackCommit, priority=200,ct_state=+new+trk,ip actions=ct(commit,table=Output,zone=65520)",
		"cookie=0x1080000000000, table=Output, priority=200,reg0=0x200000/0x600000 actions=output:NXM_NX_REG1[]",
	}

	flows := getFlowStrings(fc.featureExternalNodeConnectivity.initFlows())
	assert.ElementsMatch(t, expectedFlows, flows)
}
