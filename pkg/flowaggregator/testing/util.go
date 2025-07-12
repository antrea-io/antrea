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
	"net/netip"
	"google.golang.org/protobuf/types/known/timestamppb"
	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)
// used for unit testing
func PrepareTestFlowRecord(isIPv4 bool) *flowpb.Flow {
	ipVersion := flowpb.IPVersion_IP_VERSION_4
	source := netip.MustParseAddr("10.10.0.79")
	destination := netip.MustParseAddr("10.10.0.80")
	destinationClusterIP := netip.MustParseAddr("10.10.1.10")
	egressIP := netip.MustParseAddr("172.18.0.1")
	if !isIPv4 {
		ipVersion = flowpb.IPVersion_IP_VERSION_6
		source = netip.MustParseAddr("2001:0:3238:dfe1:63::fefb")
		destination = netip.MustParseAddr("2001:0:3238:dfe1:63::fefc")
		destinationClusterIP = netip.MustParseAddr("2001:0:3238:dfe1:64::a")
		egressIP = netip.MustParseAddr("2001:0:3238:dfe1::ac12:1")
	}
	return &flowpb.Flow{
		Ipfix: &flowpb.IPFIX{},
		StartTs: &timestamppb.Timestamp{
			Seconds: 1637706961,
		},
		EndTs: &timestamppb.Timestamp{
			Seconds: 1637706973,
		},
		EndReason: flowpb.FlowEndReason_FLOW_END_REASON_END_OF_FLOW,
		Ip: &flowpb.IP{
			Version:     ipVersion,
			Source:      source.AsSlice(),
			Destination: destination.AsSlice(),
		},
		Transport: &flowpb.Transport{
			SourcePort:      44752,
			DestinationPort: 5201,
			ProtocolNumber:  6,
			Protocol: &flowpb.Transport_TCP{
				TCP: &flowpb.TCP{
					StateName: "TIME_WAIT",
				},
			},
		},
		K8S: &flowpb.Kubernetes{
			FlowType:           flowpb.FlowType_FLOW_TYPE_INTER_NODE,
			SourcePodName:      "perftest-a",
			SourcePodNamespace: "antrea-test",
			SourcePodLabels: &flowpb.Labels{
				Labels: map[string]string{
					"antrea-e2e": "perftest-a",
					"app":        "iperf",
				},
			},
			SourceNodeName:          "k8s-node-control-plane",
			DestinationPodName:      "perftest-b",
			DestinationPodNamespace: "antrea-test-b",
			DestinationPodLabels: &flowpb.Labels{
				Labels: map[string]string{
					"antrea-e2e": "perftest-b",
					"app":        "iperf",
				},
			},
			DestinationNodeName:            "k8s-node-control-plane-b",
			DestinationClusterIp:           destinationClusterIP.AsSlice(),
			DestinationServicePort:         5202,
			DestinationServicePortName:     "perftest",
			IngressNetworkPolicyName:       "test-flow-aggregator-networkpolicy-ingress-allow",
			IngressNetworkPolicyNamespace:  "antrea-test-ns",
			IngressNetworkPolicyRuleName:   "test-flow-aggregator-networkpolicy-rule",
			IngressNetworkPolicyRuleAction: flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP,
			IngressNetworkPolicyType:       flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_K8S,
			EgressNetworkPolicyName:        "test-flow-aggregator-networkpolicy-egress-allow",
			EgressNetworkPolicyNamespace:   "antrea-test-ns-e",
			EgressNetworkPolicyRuleName:    "test-flow-aggregator-networkpolicy-rule-e",
			EgressNetworkPolicyRuleAction:  flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_ALLOW,
			EgressNetworkPolicyType:        flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_ACNP,
			EgressName:                     "test-egress",
			EgressIp:                       egressIP.AsSlice(),
			EgressNodeName:                 "test-egress-node",
		},
		Stats: &flowpb.Stats{
			PacketTotalCount: 823188,
			OctetTotalCount:  30472817041,
			PacketDeltaCount: 241333,
			OctetDeltaCount:  8982624938,
		},
		ReverseStats: &flowpb.Stats{
			PacketTotalCount: 471111,
			OctetTotalCount:  24500996,
			PacketDeltaCount: 136211,
			OctetDeltaCount:  7083284,
		},
		App: &flowpb.App{
			ProtocolName: "http",
			HttpVals:     []byte("mockHttpString"),
		},
		Aggregation: &flowpb.Aggregation{
			EndTsFromSource: &timestamppb.Timestamp{
				Seconds: 1637706974,
			},
			EndTsFromDestination: &timestamppb.Timestamp{
				Seconds: 1637706975,
			},
			StatsFromSource:                  &flowpb.Stats{},
			ReverseStatsFromSource:           &flowpb.Stats{},
			StatsFromDestination:             &flowpb.Stats{},
			ReverseStatsFromDestination:      &flowpb.Stats{},
			Throughput:                       15902813472,
			ReverseThroughput:                12381344,
			ThroughputFromSource:             15902813473,
			ThroughputFromDestination:        15902813474,
			ReverseThroughputFromSource:      12381345,
			ReverseThroughputFromDestination: 12381346,
		},
		FlowDirection: flowpb.FlowDirection_FLOW_DIRECTION_UNKNOWN,
	}
}
