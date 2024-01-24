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

package flowrecord

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	ipfixentitiestesting "github.com/vmware/go-ipfix/pkg/entities/testing"
	"github.com/vmware/go-ipfix/pkg/registry"
	"go.uber.org/mock/gomock"

	flowaggregatortesting "antrea.io/antrea/pkg/flowaggregator/testing"
)

func init() {
	registry.LoadRegistry()
}

func TestGetFlowRecord(t *testing.T) {
	ctrl := gomock.NewController(t)
	testcases := []struct {
		isIPv4 bool
	}{
		{true},
		{false},
	}

	for _, tc := range testcases {
		mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)
		flowaggregatortesting.PrepareMockIpfixRecord(mockRecord, tc.isIPv4)

		flowRecord := GetFlowRecord(mockRecord)
		assert.Equal(t, time.Unix(int64(1637706961), 0), flowRecord.FlowStartSeconds)
		assert.Equal(t, time.Unix(int64(1637706973), 0), flowRecord.FlowEndSeconds)
		assert.Equal(t, time.Unix(int64(1637706974), 0), flowRecord.FlowEndSecondsFromSourceNode)
		assert.Equal(t, time.Unix(int64(1637706975), 0), flowRecord.FlowEndSecondsFromDestinationNode)
		assert.Equal(t, uint8(3), flowRecord.FlowEndReason)
		assert.Equal(t, uint16(44752), flowRecord.SourceTransportPort)
		assert.Equal(t, uint16(5201), flowRecord.DestinationTransportPort)
		assert.Equal(t, uint8(6), flowRecord.ProtocolIdentifier)
		assert.Equal(t, uint64(823188), flowRecord.PacketTotalCount)
		assert.Equal(t, uint64(30472817041), flowRecord.OctetTotalCount)
		assert.Equal(t, uint64(241333), flowRecord.PacketDeltaCount)
		assert.Equal(t, uint64(8982624938), flowRecord.OctetDeltaCount)
		assert.Equal(t, uint64(471111), flowRecord.ReversePacketTotalCount)
		assert.Equal(t, uint64(24500996), flowRecord.ReverseOctetTotalCount)
		assert.Equal(t, uint64(136211), flowRecord.ReversePacketDeltaCount)
		assert.Equal(t, uint64(7083284), flowRecord.ReverseOctetDeltaCount)
		assert.Equal(t, "perftest-a", flowRecord.SourcePodName)
		assert.Equal(t, "antrea-test", flowRecord.SourcePodNamespace)
		assert.Equal(t, "k8s-node-control-plane", flowRecord.SourceNodeName)
		assert.Equal(t, "perftest-b", flowRecord.DestinationPodName)
		assert.Equal(t, "antrea-test-b", flowRecord.DestinationPodNamespace)
		assert.Equal(t, "k8s-node-control-plane-b", flowRecord.DestinationNodeName)
		assert.Equal(t, uint16(5202), flowRecord.DestinationServicePort)
		assert.Equal(t, "perftest", flowRecord.DestinationServicePortName)
		assert.Equal(t, "test-flow-aggregator-networkpolicy-ingress-allow", flowRecord.IngressNetworkPolicyName)
		assert.Equal(t, "antrea-test-ns", flowRecord.IngressNetworkPolicyNamespace)
		assert.Equal(t, "test-flow-aggregator-networkpolicy-rule", flowRecord.IngressNetworkPolicyRuleName)
		assert.Equal(t, uint8(1), flowRecord.IngressNetworkPolicyType)
		assert.Equal(t, uint8(2), flowRecord.IngressNetworkPolicyRuleAction)
		assert.Equal(t, "test-flow-aggregator-networkpolicy-egress-allow", flowRecord.EgressNetworkPolicyName)
		assert.Equal(t, "antrea-test-ns-e", flowRecord.EgressNetworkPolicyNamespace)
		assert.Equal(t, "test-flow-aggregator-networkpolicy-rule-e", flowRecord.EgressNetworkPolicyRuleName)
		assert.Equal(t, uint8(4), flowRecord.EgressNetworkPolicyType)
		assert.Equal(t, uint8(5), flowRecord.EgressNetworkPolicyRuleAction)
		assert.Equal(t, "TIME_WAIT", flowRecord.TcpState)
		assert.Equal(t, uint8(11), flowRecord.FlowType)
		assert.Equal(t, "{\"antrea-e2e\":\"perftest-a\",\"app\":\"iperf\"}", flowRecord.SourcePodLabels)
		assert.Equal(t, "{\"antrea-e2e\":\"perftest-b\",\"app\":\"iperf\"}", flowRecord.DestinationPodLabels)
		assert.Equal(t, uint64(15902813472), flowRecord.Throughput)
		assert.Equal(t, uint64(12381344), flowRecord.ReverseThroughput)
		assert.Equal(t, uint64(15902813473), flowRecord.ThroughputFromSourceNode)
		assert.Equal(t, uint64(15902813474), flowRecord.ThroughputFromDestinationNode)
		assert.Equal(t, uint64(12381345), flowRecord.ReverseThroughputFromSourceNode)
		assert.Equal(t, uint64(12381346), flowRecord.ReverseThroughputFromDestinationNode)
		assert.Equal(t, "test-egress", flowRecord.EgressName)
		assert.Equal(t, "172.18.0.1", flowRecord.EgressIP)
		assert.Equal(t, "http", flowRecord.AppProtocolName)
		assert.Equal(t, "mockHttpString", flowRecord.HttpVals)

		if tc.isIPv4 {
			assert.Equal(t, "10.10.0.79", flowRecord.SourceIP)
			assert.Equal(t, "10.10.0.80", flowRecord.DestinationIP)
			assert.Equal(t, "10.10.1.10", flowRecord.DestinationClusterIP)
		} else {
			assert.Equal(t, "2001:0:3238:dfe1:63::fefb", flowRecord.SourceIP)
			assert.Equal(t, "2001:0:3238:dfe1:63::fefc", flowRecord.DestinationIP)
			assert.Equal(t, "2001:0:3238:dfe1:64::a", flowRecord.DestinationClusterIP)
		}
	}
}
