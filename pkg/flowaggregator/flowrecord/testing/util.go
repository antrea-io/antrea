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

package testing

import (
	"time"

	"antrea.io/antrea/pkg/flowaggregator/flowrecord"
)

// used for unit testing
func PrepareTestFlowRecord() *flowrecord.FlowRecord {
	return &flowrecord.FlowRecord{
		FlowStartSeconds:                     time.Unix(int64(1637706961), 0),
		FlowEndSeconds:                       time.Unix(int64(1637706973), 0),
		FlowEndSecondsFromSourceNode:         time.Unix(int64(1637706974), 0),
		FlowEndSecondsFromDestinationNode:    time.Unix(int64(1637706975), 0),
		FlowEndReason:                        3,
		SourceIP:                             "10.10.0.79",
		DestinationIP:                        "10.10.0.80",
		SourceTransportPort:                  44752,
		DestinationTransportPort:             5201,
		ProtocolIdentifier:                   6,
		PacketTotalCount:                     823188,
		OctetTotalCount:                      30472817041,
		PacketDeltaCount:                     241333,
		OctetDeltaCount:                      8982624938,
		ReversePacketTotalCount:              471111,
		ReverseOctetTotalCount:               24500996,
		ReversePacketDeltaCount:              136211,
		ReverseOctetDeltaCount:               7083284,
		SourcePodName:                        "perftest-a",
		SourcePodNamespace:                   "antrea-test",
		SourceNodeName:                       "k8s-node-control-plane",
		DestinationPodName:                   "perftest-b",
		DestinationPodNamespace:              "antrea-test-b",
		DestinationNodeName:                  "k8s-node-control-plane-b",
		DestinationClusterIP:                 "10.10.1.10",
		DestinationServicePort:               5202,
		DestinationServicePortName:           "perftest",
		IngressNetworkPolicyName:             "test-flow-aggregator-networkpolicy-ingress-allow",
		IngressNetworkPolicyNamespace:        "antrea-test-ns",
		IngressNetworkPolicyRuleName:         "test-flow-aggregator-networkpolicy-rule",
		IngressNetworkPolicyRuleAction:       2,
		IngressNetworkPolicyType:             1,
		EgressNetworkPolicyName:              "test-flow-aggregator-networkpolicy-egress-allow",
		EgressNetworkPolicyNamespace:         "antrea-test-ns-e",
		EgressNetworkPolicyRuleName:          "test-flow-aggregator-networkpolicy-rule-e",
		EgressNetworkPolicyRuleAction:        5,
		EgressNetworkPolicyType:              4,
		TcpState:                             "TIME_WAIT",
		FlowType:                             11,
		SourcePodLabels:                      "{\"antrea-e2e\":\"perftest-a\",\"app\":\"iperf\"}",
		DestinationPodLabels:                 "{\"antrea-e2e\":\"perftest-b\",\"app\":\"iperf\"}",
		Throughput:                           15902813472,
		ReverseThroughput:                    12381344,
		ThroughputFromSourceNode:             15902813473,
		ThroughputFromDestinationNode:        15902813474,
		ReverseThroughputFromSourceNode:      12381345,
		ReverseThroughputFromDestinationNode: 12381346,
		EgressName:                           "test-egress",
		EgressIP:                             "172.18.0.1",
		AppProtocolName:                      "http",
		HttpVals:                             "mockHttpString",
		EgressNodeName:                       "test-egress-node",
	}
}
