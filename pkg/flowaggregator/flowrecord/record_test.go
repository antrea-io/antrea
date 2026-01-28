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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowaggregatortesting "antrea.io/antrea/pkg/flowaggregator/testing"
)

func TestGetFlowRecord(t *testing.T) {
	runTest := func(t *testing.T, isIPv4 bool) {
		record := flowaggregatortesting.PrepareTestFlowRecord(isIPv4)

		flowRecord, err := GetFlowRecord(record)
		require.NoError(t, err)
		assert.Equal(t, time.Unix(int64(1637706961), 0).UTC(), flowRecord.FlowStartSeconds)
		assert.Equal(t, time.Unix(int64(1637706973), 0).UTC(), flowRecord.FlowEndSeconds)
		assert.Equal(t, time.Unix(int64(1637706974), 0).UTC(), flowRecord.FlowEndSecondsFromSourceNode)
		assert.Equal(t, time.Unix(int64(1637706975), 0).UTC(), flowRecord.FlowEndSecondsFromDestinationNode)
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
		assert.Equal(t, uint8(3), flowRecord.EgressNetworkPolicyType)
		assert.Equal(t, uint8(1), flowRecord.EgressNetworkPolicyRuleAction)
		assert.Equal(t, "TIME_WAIT", flowRecord.TcpState)
		assert.Equal(t, uint8(2), flowRecord.FlowType)
		assert.Equal(t, "{\"antrea-e2e\":\"perftest-a\",\"app\":\"iperf\"}", flowRecord.SourcePodLabels)
		assert.Equal(t, "{\"antrea-e2e\":\"perftest-b\",\"app\":\"iperf\"}", flowRecord.DestinationPodLabels)
		assert.Equal(t, uint64(15902813472), flowRecord.Throughput)
		assert.Equal(t, uint64(12381344), flowRecord.ReverseThroughput)
		assert.Equal(t, uint64(15902813473), flowRecord.ThroughputFromSourceNode)
		assert.Equal(t, uint64(15902813474), flowRecord.ThroughputFromDestinationNode)
		assert.Equal(t, uint64(12381345), flowRecord.ReverseThroughputFromSourceNode)
		assert.Equal(t, uint64(12381346), flowRecord.ReverseThroughputFromDestinationNode)
		assert.Equal(t, "test-egress", flowRecord.EgressName)

		if isIPv4 {
			assert.Equal(t, "10.10.0.79", flowRecord.SourceIP)
			assert.Equal(t, "10.10.0.80", flowRecord.DestinationIP)
			assert.Equal(t, "10.10.1.10", flowRecord.DestinationClusterIP)
			assert.Equal(t, "172.18.0.1", flowRecord.EgressIP)
		} else {
			assert.Equal(t, "2001:0:3238:dfe1:63::fefb", flowRecord.SourceIP)
			assert.Equal(t, "2001:0:3238:dfe1:63::fefc", flowRecord.DestinationIP)
			assert.Equal(t, "2001:0:3238:dfe1:64::a", flowRecord.DestinationClusterIP)
			assert.Equal(t, "2001:0:3238:dfe1::ac12:1", flowRecord.EgressIP)
		}
	}

	t.Run("ipv4", func(t *testing.T) { runTest(t, true) })
	t.Run("ipv6", func(t *testing.T) { runTest(t, false) })
}

func TestIpAddressAsString(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "IPv4",
			input:    net.ParseIP("192.168.1.1").To4(),
			expected: "192.168.1.1",
		},
		{
			name:     "IPv6",
			input:    net.ParseIP("2001:db8::1").To16(),
			expected: "2001:db8::1",
		},
		{
			name:     "IPv6_Full",
			input:    []byte{0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
			expected: "2001:db8:85a3::8a2e:370:7334",
		},
		{
			name:     "nil",
			input:    nil,
			expected: "",
		},
		{
			name:     "empty slice",
			input:    []byte{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := IpAddressAsString(tt.input)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
