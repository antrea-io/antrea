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
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/agent/config"
	opstest "antrea.io/antrea/pkg/agent/openflow/operations/testing"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

func TestTrafficControlMarkFlows(t *testing.T) {
	testCases := []struct {
		name          string
		sourceOFPorts []uint32
		targetOFPort  uint32
		direction     v1alpha2.Direction
		action        v1alpha2.TrafficControlAction
		expectedFlows []string
	}{
		{
			name:          "Ingress Redirect",
			sourceOFPorts: []uint32{10},
			targetOFPort:  100,
			direction:     v1alpha2.DirectionIngress,
			action:        v1alpha2.ActionRedirect,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=TrafficControl, priority=200,reg1=0xa actions=set_field:0x64->reg9,set_field:0x800000/0xc00000->reg0,goto_table:IngressSecurityClassifier",
			},
		},
		{
			name:          "Egress Redirect",
			sourceOFPorts: []uint32{10},
			targetOFPort:  100,
			direction:     v1alpha2.DirectionEgress,
			action:        v1alpha2.ActionRedirect,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=PipelineIPClassifier, priority=200,in_port=10 actions=output:100",
			},
		},
		{
			name:          "Egress Mirror",
			sourceOFPorts: []uint32{10},
			targetOFPort:  100,
			direction:     v1alpha2.DirectionEgress,
			action:        v1alpha2.ActionMirror,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=PipelineIPClassifier, priority=200,in_port=10 actions=set_field:0x64->reg9,set_field:0x400000/0xc00000->reg0,output:100,goto_table:ConntrackState",
			},
		},
		{
			name:          "Both Directions Redirect",
			sourceOFPorts: []uint32{10},
			targetOFPort:  100,
			direction:     v1alpha2.DirectionBoth,
			action:        v1alpha2.ActionRedirect,
			expectedFlows: []string{
				"cookie=0x1010000000000, table=TrafficControl, priority=200,reg1=0xa actions=set_field:0x64->reg9,set_field:0x800000/0xc00000->reg0,goto_table:IngressSecurityClassifier",
				"cookie=0x1010000000000, table=PipelineIPClassifier, priority=200,in_port=10 actions=output:100",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := opstest.NewMockOFEntryOperations(ctrl)
			fc := newFakeClient(m, true, false, config.K8sNode, config.TrafficEncapModeEncap, enableTrafficControl)
			defer resetPipelines()

			flows := tc.sourceOFPorts // not used directly, just to pass to method
			_ = flows

			actualFlows := fc.featurePodConnectivity.trafficControlMarkFlows(tc.sourceOFPorts, tc.targetOFPort, tc.direction, tc.action, priorityNormal)
			assert.ElementsMatch(t, tc.expectedFlows, getFlowStrings(actualFlows))
		})
	}
}

func TestTrafficControlReturnClassifierFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := opstest.NewMockOFEntryOperations(ctrl)
	fc := newFakeClient(m, true, false, config.K8sNode, config.TrafficEncapModeEncap, enableTrafficControl)
	defer resetPipelines()

	flow := fc.featurePodConnectivity.trafficControlReturnClassifierFlow(100)
	expectedFlow := "cookie=0x1010000000000, table=Classifier, priority=200,in_port=100 actions=set_field:0x3/0xf->reg0,goto_table:ConntrackState"

	assert.Equal(t, expectedFlow, getFlowStrings([]binding.Flow{flow})[0])
}
