// Copyright 2022 Antrea Authors.
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
	"sync"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	oftest "antrea.io/antrea/pkg/agent/openflow/testing"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	mocks "antrea.io/antrea/pkg/ovs/openflow/testing"
)

var (
	bakMulticastEgressRuleTable       binding.Table
	bakMulticastEgressPodMetricTable  binding.Table
	bakMulticastRoutingTable          binding.Table
	bakMulticastOutputTable           binding.Table
	bakMulticastIngressPodMetricTable binding.Table

	mockMulticastEgressRuleTable       *mocks.MockTable
	mockMulticastEgressPodMetricTable  *mocks.MockTable
	mockMulticastRoutingTable          *mocks.MockTable
	mockMulticastOutputTable           *mocks.MockTable
	mockMulticastIngressPodMetricTable *mocks.MockTable

	mockFeatureMulticast = featureMulticast{
		enableAntreaPolicy: true,
		cookieAllocator:    cookie.NewAllocator(0),
		category:           cookie.Multicast,
		cachedFlows:        newFlowCategoryCache(),
		groupCache:         sync.Map{},
	}
)

func newMockPktInFlowBuilder(ctrl *gomock.Controller) *mocks.MockFlowBuilder {
	pktInFlowBuilder := mocks.NewMockFlowBuilder(ctrl)
	pktInFlowBuilder.EXPECT().Cookie(gomock.Any()).Return(pktInFlowBuilder).AnyTimes()
	pktInFlowBuilder.EXPECT().MatchProtocol(gomock.Any()).Return(pktInFlowBuilder).AnyTimes()
	pktInFlowBuilder.EXPECT().MatchRegMark(gomock.Any()).Return(pktInFlowBuilder).AnyTimes()
	action := mocks.NewMockAction(ctrl)
	action.EXPECT().LoadRegMark(gomock.Any()).Return(pktInFlowBuilder).AnyTimes()
	pktInFlowBuilder.EXPECT().Action().Return(action).Times(1)
	action.EXPECT().SendToController(gomock.Any()).Return(pktInFlowBuilder).AnyTimes()
	pktInFlowBuilder.EXPECT().Action().Return(action).Times(1)

	pktInFlow := mocks.NewMockFlow(ctrl)
	pktInFlowBuilder.EXPECT().Done().Return(pktInFlow).Times(1)
	pktInFlow.EXPECT().MatchString().Return("").AnyTimes()

	return pktInFlowBuilder
}

func newMockExternalMulticastReceiver(ctrl *gomock.Controller) *mocks.MockFlowBuilder {
	externalMcastReceiverFlowBuilder := mocks.NewMockFlowBuilder(ctrl)

	externalMcastReceiverFlowBuilder.EXPECT().Cookie(gomock.Any()).Return(externalMcastReceiverFlowBuilder).AnyTimes()
	externalMcastReceiverFlowBuilder.EXPECT().MatchProtocol(gomock.Any()).Return(externalMcastReceiverFlowBuilder).AnyTimes()

	action := mocks.NewMockAction(ctrl)
	action.EXPECT().LoadRegMark(gomock.Any()).Return(externalMcastReceiverFlowBuilder).AnyTimes()
	externalMcastReceiverFlowBuilder.EXPECT().Action().Return(action).Times(1)
	action.EXPECT().LoadToRegField(gomock.Any(), gomock.Any()).Return(externalMcastReceiverFlowBuilder).AnyTimes()
	externalMcastReceiverFlowBuilder.EXPECT().Action().Return(action).Times(1)
	action.EXPECT().GotoStage(gomock.Any()).Return(externalMcastReceiverFlowBuilder).AnyTimes()
	externalMcastReceiverFlowBuilder.EXPECT().Action().Return(action).Times(1)

	externalMcastReceiverFlow := mocks.NewMockFlow(ctrl)
	externalMcastReceiverFlowBuilder.EXPECT().Done().Return(externalMcastReceiverFlow).Times(1)
	externalMcastReceiverFlow.EXPECT().MatchString().Return("").AnyTimes()

	return externalMcastReceiverFlowBuilder
}

func newMockMulticastSkipIGMPMetricFlows(ctrl *gomock.Controller) *mocks.MockFlowBuilder {
	mockFlowBuilder := mocks.NewMockFlowBuilder(ctrl)
	mockFlowBuilder.EXPECT().Cookie(gomock.Any()).Return(mockFlowBuilder).AnyTimes()
	mockFlowBuilder.EXPECT().MatchProtocol(gomock.Any()).Return(mockFlowBuilder).AnyTimes()
	action := mocks.NewMockAction(ctrl)
	action.EXPECT().NextTable().Return(mockFlowBuilder).AnyTimes()
	mockFlowBuilder.EXPECT().Action().Return(action).Times(1)
	mockFlow := mocks.NewMockFlow(ctrl)
	mockFlowBuilder.EXPECT().Done().Return(mockFlow).Times(1)
	mockFlow.EXPECT().MatchString().Return("").AnyTimes()
	return mockFlowBuilder
}

func newMockIGMPFlowBuilder(ctrl *gomock.Controller) *mocks.MockFlowBuilder {
	igmpFlowBuilder := mocks.NewMockFlowBuilder(ctrl)
	igmpFlowBuilder.EXPECT().Cookie(gomock.Any()).Return(igmpFlowBuilder).Times(1)
	igmpFlowBuilder.EXPECT().MatchProtocol(gomock.Any()).Return(igmpFlowBuilder).Times(1)
	igmpFlowBuilder.EXPECT().MatchRegMark(gomock.Any()).Return(igmpFlowBuilder).Times(1)
	action := mocks.NewMockAction(ctrl)
	action.EXPECT().GotoStage(gomock.Any()).Return(igmpFlowBuilder).Times(1)
	igmpFlowBuilder.EXPECT().Action().Return(action).Times(1)
	igmpFlow := mocks.NewMockFlow(ctrl)
	igmpFlowBuilder.EXPECT().Done().Return(igmpFlow).Times(1)
	igmpFlow.EXPECT().MatchString().Return("").AnyTimes()
	return igmpFlowBuilder
}

func initMockTables(ctrl *gomock.Controller) {
	mockMulticastEgressRuleTable = mocks.NewMockTable(ctrl)
	mockMulticastEgressPodMetricTable = mocks.NewMockTable(ctrl)
	mockMulticastRoutingTable = mocks.NewMockTable(ctrl)
	mockMulticastOutputTable = mocks.NewMockTable(ctrl)
	mockMulticastIngressPodMetricTable = mocks.NewMockTable(ctrl)

	bakMulticastEgressRuleTable = MulticastEgressRuleTable.ofTable
	bakMulticastEgressPodMetricTable = MulticastEgressPodMetricTable.ofTable
	bakMulticastRoutingTable = MulticastRoutingTable.ofTable
	bakMulticastOutputTable = MulticastOutputTable.ofTable
	bakMulticastIngressPodMetricTable = MulticastIngressPodMetricTable.ofTable

	MulticastEgressRuleTable.ofTable = mockMulticastEgressRuleTable
	MulticastEgressPodMetricTable.ofTable = mockMulticastEgressPodMetricTable
	MulticastRoutingTable.ofTable = mockMulticastRoutingTable
	MulticastOutputTable.ofTable = mockMulticastOutputTable
	MulticastIngressPodMetricTable.ofTable = mockMulticastIngressPodMetricTable
}

func resetMulticastTables() {
	MulticastEgressRuleTable.ofTable = bakMulticastEgressRuleTable
	MulticastEgressPodMetricTable.ofTable = bakMulticastEgressPodMetricTable
	MulticastRoutingTable.ofTable = bakMulticastRoutingTable
	MulticastOutputTable.ofTable = bakMulticastOutputTable
	MulticastIngressPodMetricTable.ofTable = bakMulticastIngressPodMetricTable
}

func newMcastClient(ctrl *gomock.Controller) *client {
	bridge := mocks.NewMockBridge(ctrl)
	bridge.EXPECT().AddFlowsInBundle(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	m := oftest.NewMockOFEntryOperations(ctrl)
	m.EXPECT().AddAll(gomock.Any()).Return(nil).AnyTimes()
	return &client{
		bridge:             bridge,
		ipProtocols:        []binding.Protocol{binding.ProtocolIP},
		cookieAllocator:    cookie.NewAllocator(0),
		ofEntryOperations:  m,
		featureMulticast:   &mockFeatureMulticast,
		enableMulticast:    true,
		enableAntreaPolicy: true,
	}
}

func TestInstallMulticastInitialFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c = newMcastClient(ctrl)
	initMockTables(ctrl)
	defer resetMulticastTables()

	c.enableMulticast = true
	c.enableAntreaPolicy = true
	c.featureMulticast = &mockFeatureMulticast
	mockMulticastRoutingTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockPktInFlowBuilder(ctrl)).Times(1)
	mockMulticastRoutingTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockExternalMulticastReceiver(ctrl)).Times(1)
	mockMulticastEgressPodMetricTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockMulticastSkipIGMPMetricFlows(ctrl)).Times(1)
	mockMulticastIngressPodMetricTable.EXPECT().BuildFlow(gomock.Any()).Return(newMockMulticastSkipIGMPMetricFlows(ctrl)).Times(1)
	mockMulticastEgressRuleTable.EXPECT().BuildFlow(priorityTopAntreaPolicy).Return(newMockIGMPFlowBuilder(ctrl)).Times(1)
	c.nodeConfig = &config.NodeConfig{PodIPv4CIDR: podIPv4CIDR, PodIPv6CIDR: nil}
	c.networkConfig = &config.NetworkConfig{}
	c.pipelines = pipelineMap

	err := c.InstallMulticastInitialFlows(uint8(PacketInReasonMC))
	require.NoErrorf(t, err, "Failed to install multicast initial flows")
}
