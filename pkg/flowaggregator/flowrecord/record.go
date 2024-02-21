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
	"time"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
)

type FlowRecord struct {
	FlowStartSeconds                     time.Time
	FlowEndSeconds                       time.Time
	FlowEndSecondsFromSourceNode         time.Time
	FlowEndSecondsFromDestinationNode    time.Time
	FlowEndReason                        uint8
	SourceIP                             string
	DestinationIP                        string
	SourceTransportPort                  uint16
	DestinationTransportPort             uint16
	ProtocolIdentifier                   uint8
	PacketTotalCount                     uint64
	OctetTotalCount                      uint64
	PacketDeltaCount                     uint64
	OctetDeltaCount                      uint64
	ReversePacketTotalCount              uint64
	ReverseOctetTotalCount               uint64
	ReversePacketDeltaCount              uint64
	ReverseOctetDeltaCount               uint64
	SourcePodName                        string
	SourcePodNamespace                   string
	SourceNodeName                       string
	DestinationPodName                   string
	DestinationPodNamespace              string
	DestinationNodeName                  string
	DestinationClusterIP                 string
	DestinationServicePort               uint16
	DestinationServicePortName           string
	IngressNetworkPolicyName             string
	IngressNetworkPolicyNamespace        string
	IngressNetworkPolicyRuleName         string
	IngressNetworkPolicyRuleAction       uint8
	IngressNetworkPolicyType             uint8
	EgressNetworkPolicyName              string
	EgressNetworkPolicyNamespace         string
	EgressNetworkPolicyRuleName          string
	EgressNetworkPolicyRuleAction        uint8
	EgressNetworkPolicyType              uint8
	TcpState                             string
	FlowType                             uint8
	SourcePodLabels                      string
	DestinationPodLabels                 string
	Throughput                           uint64
	ReverseThroughput                    uint64
	ThroughputFromSourceNode             uint64
	ThroughputFromDestinationNode        uint64
	ReverseThroughputFromSourceNode      uint64
	ReverseThroughputFromDestinationNode uint64
	EgressName                           string
	EgressIP                             string
	AppProtocolName                      string
	HttpVals                             string
	EgressNodeName                       string
}

// GetFlowRecord converts ipfixentities.Record to FlowRecord
func GetFlowRecord(record ipfixentities.Record) *FlowRecord {
	r := &FlowRecord{}
	if flowStartSeconds, _, ok := record.GetInfoElementWithValue("flowStartSeconds"); ok {
		r.FlowStartSeconds = time.Unix(int64(flowStartSeconds.GetUnsigned32Value()), 0)
	}
	if flowEndSeconds, _, ok := record.GetInfoElementWithValue("flowEndSeconds"); ok {
		r.FlowEndSeconds = time.Unix(int64(flowEndSeconds.GetUnsigned32Value()), 0)
	}
	if flowEndSecFromSrcNode, _, ok := record.GetInfoElementWithValue("flowEndSecondsFromSourceNode"); ok {
		r.FlowEndSecondsFromSourceNode = time.Unix(int64(flowEndSecFromSrcNode.GetUnsigned32Value()), 0)
	}
	if flowEndSecFromDstNode, _, ok := record.GetInfoElementWithValue("flowEndSecondsFromDestinationNode"); ok {
		r.FlowEndSecondsFromDestinationNode = time.Unix(int64(flowEndSecFromDstNode.GetUnsigned32Value()), 0)
	}
	if flowEndReason, _, ok := record.GetInfoElementWithValue("flowEndReason"); ok {
		r.FlowEndReason = flowEndReason.GetUnsigned8Value()
	}
	if sourceIPv4, _, ok := record.GetInfoElementWithValue("sourceIPv4Address"); ok {
		r.SourceIP = sourceIPv4.GetIPAddressValue().String()
	} else if sourceIPv6, _, ok := record.GetInfoElementWithValue("sourceIPv6Address"); ok {
		r.SourceIP = sourceIPv6.GetIPAddressValue().String()
	}
	if destinationIPv4, _, ok := record.GetInfoElementWithValue("destinationIPv4Address"); ok {
		r.DestinationIP = destinationIPv4.GetIPAddressValue().String()
	} else if destinationIPv6, _, ok := record.GetInfoElementWithValue("destinationIPv6Address"); ok {
		r.DestinationIP = destinationIPv6.GetIPAddressValue().String()
	}
	if sourcePort, _, ok := record.GetInfoElementWithValue("sourceTransportPort"); ok {
		r.SourceTransportPort = sourcePort.GetUnsigned16Value()
	}
	if destinationPort, _, ok := record.GetInfoElementWithValue("destinationTransportPort"); ok {
		r.DestinationTransportPort = destinationPort.GetUnsigned16Value()
	}
	if protocolIdentifier, _, ok := record.GetInfoElementWithValue("protocolIdentifier"); ok {
		r.ProtocolIdentifier = protocolIdentifier.GetUnsigned8Value()
	}
	if packetTotalCount, _, ok := record.GetInfoElementWithValue("packetTotalCount"); ok {
		r.PacketTotalCount = packetTotalCount.GetUnsigned64Value()
	}
	if octetTotalCount, _, ok := record.GetInfoElementWithValue("octetTotalCount"); ok {
		r.OctetTotalCount = octetTotalCount.GetUnsigned64Value()
	}
	if packetDeltaCount, _, ok := record.GetInfoElementWithValue("packetDeltaCount"); ok {
		r.PacketDeltaCount = packetDeltaCount.GetUnsigned64Value()
	}
	if octetDeltaCount, _, ok := record.GetInfoElementWithValue("octetDeltaCount"); ok {
		r.OctetDeltaCount = octetDeltaCount.GetUnsigned64Value()
	}
	if reversePacketTotalCount, _, ok := record.GetInfoElementWithValue("reversePacketTotalCount"); ok {
		r.ReversePacketTotalCount = reversePacketTotalCount.GetUnsigned64Value()
	}
	if reverseOctetTotalCount, _, ok := record.GetInfoElementWithValue("reverseOctetTotalCount"); ok {
		r.ReverseOctetTotalCount = reverseOctetTotalCount.GetUnsigned64Value()
	}
	if reversePacketDeltaCount, _, ok := record.GetInfoElementWithValue("reversePacketDeltaCount"); ok {
		r.ReversePacketDeltaCount = reversePacketDeltaCount.GetUnsigned64Value()
	}
	if reverseOctetDeltaCount, _, ok := record.GetInfoElementWithValue("reverseOctetDeltaCount"); ok {
		r.ReverseOctetDeltaCount = reverseOctetDeltaCount.GetUnsigned64Value()
	}
	if sourcePodName, _, ok := record.GetInfoElementWithValue("sourcePodName"); ok {
		r.SourcePodName = sourcePodName.GetStringValue()
	}
	if sourcePodNamespace, _, ok := record.GetInfoElementWithValue("sourcePodNamespace"); ok {
		r.SourcePodNamespace = sourcePodNamespace.GetStringValue()
	}
	if sourceNodeName, _, ok := record.GetInfoElementWithValue("sourceNodeName"); ok {
		r.SourceNodeName = sourceNodeName.GetStringValue()
	}
	if destinationPodName, _, ok := record.GetInfoElementWithValue("destinationPodName"); ok {
		r.DestinationPodName = destinationPodName.GetStringValue()
	}
	if destinationPodNamespace, _, ok := record.GetInfoElementWithValue("destinationPodNamespace"); ok {
		r.DestinationPodNamespace = destinationPodNamespace.GetStringValue()
	}
	if destinationNodeName, _, ok := record.GetInfoElementWithValue("destinationNodeName"); ok {
		r.DestinationNodeName = destinationNodeName.GetStringValue()
	}
	if destinationClusterIPv4, _, ok := record.GetInfoElementWithValue("destinationClusterIPv4"); ok {
		r.DestinationClusterIP = destinationClusterIPv4.GetIPAddressValue().String()
	} else if destinationClusterIPv6, _, ok := record.GetInfoElementWithValue("destinationClusterIPv6"); ok {
		r.DestinationClusterIP = destinationClusterIPv6.GetIPAddressValue().String()
	}
	if destinationServicePort, _, ok := record.GetInfoElementWithValue("destinationServicePort"); ok {
		r.DestinationServicePort = destinationServicePort.GetUnsigned16Value()
	}
	if destinationServicePortName, _, ok := record.GetInfoElementWithValue("destinationServicePortName"); ok {
		r.DestinationServicePortName = destinationServicePortName.GetStringValue()
	}
	if ingressNPName, _, ok := record.GetInfoElementWithValue("ingressNetworkPolicyName"); ok {
		r.IngressNetworkPolicyName = ingressNPName.GetStringValue()
	}
	if ingressNPNamespace, _, ok := record.GetInfoElementWithValue("ingressNetworkPolicyNamespace"); ok {
		r.IngressNetworkPolicyNamespace = ingressNPNamespace.GetStringValue()
	}
	if ingressNPRuleName, _, ok := record.GetInfoElementWithValue("ingressNetworkPolicyRuleName"); ok {
		r.IngressNetworkPolicyRuleName = ingressNPRuleName.GetStringValue()
	}
	if ingressNPType, _, ok := record.GetInfoElementWithValue("ingressNetworkPolicyType"); ok {
		r.IngressNetworkPolicyType = ingressNPType.GetUnsigned8Value()
	}
	if ingressNPRuleAction, _, ok := record.GetInfoElementWithValue("ingressNetworkPolicyRuleAction"); ok {
		r.IngressNetworkPolicyRuleAction = ingressNPRuleAction.GetUnsigned8Value()
	}
	if egressNPName, _, ok := record.GetInfoElementWithValue("egressNetworkPolicyName"); ok {
		r.EgressNetworkPolicyName = egressNPName.GetStringValue()
	}
	if egressNPNamespace, _, ok := record.GetInfoElementWithValue("egressNetworkPolicyNamespace"); ok {
		r.EgressNetworkPolicyNamespace = egressNPNamespace.GetStringValue()
	}
	if egressNPRuleName, _, ok := record.GetInfoElementWithValue("egressNetworkPolicyRuleName"); ok {
		r.EgressNetworkPolicyRuleName = egressNPRuleName.GetStringValue()
	}
	if egressNPType, _, ok := record.GetInfoElementWithValue("egressNetworkPolicyType"); ok {
		r.EgressNetworkPolicyType = egressNPType.GetUnsigned8Value()
	}
	if egressNPRuleAction, _, ok := record.GetInfoElementWithValue("egressNetworkPolicyRuleAction"); ok {
		r.EgressNetworkPolicyRuleAction = egressNPRuleAction.GetUnsigned8Value()
	}
	if tcpState, _, ok := record.GetInfoElementWithValue("tcpState"); ok {
		r.TcpState = tcpState.GetStringValue()
	}
	if flowType, _, ok := record.GetInfoElementWithValue("flowType"); ok {
		r.FlowType = flowType.GetUnsigned8Value()
	}
	if sourcePodLabels, _, ok := record.GetInfoElementWithValue("sourcePodLabels"); ok {
		r.SourcePodLabels = sourcePodLabels.GetStringValue()
	}
	if destinationPodLabels, _, ok := record.GetInfoElementWithValue("destinationPodLabels"); ok {
		r.DestinationPodLabels = destinationPodLabels.GetStringValue()
	}
	if throughput, _, ok := record.GetInfoElementWithValue("throughput"); ok {
		r.Throughput = throughput.GetUnsigned64Value()
	}
	if reverseThroughput, _, ok := record.GetInfoElementWithValue("reverseThroughput"); ok {
		r.ReverseThroughput = reverseThroughput.GetUnsigned64Value()
	}
	if throughputFromSrcNode, _, ok := record.GetInfoElementWithValue("throughputFromSourceNode"); ok {
		r.ThroughputFromSourceNode = throughputFromSrcNode.GetUnsigned64Value()
	}
	if throughputFromDstNode, _, ok := record.GetInfoElementWithValue("throughputFromDestinationNode"); ok {
		r.ThroughputFromDestinationNode = throughputFromDstNode.GetUnsigned64Value()
	}
	if revTputFromSrcNode, _, ok := record.GetInfoElementWithValue("reverseThroughputFromSourceNode"); ok {
		r.ReverseThroughputFromSourceNode = revTputFromSrcNode.GetUnsigned64Value()
	}
	if revTputFromDstNode, _, ok := record.GetInfoElementWithValue("reverseThroughputFromDestinationNode"); ok {
		r.ReverseThroughputFromDestinationNode = revTputFromDstNode.GetUnsigned64Value()
	}
	if egressName, _, ok := record.GetInfoElementWithValue("egressName"); ok {
		r.EgressName = egressName.GetStringValue()
	}
	if egressIP, _, ok := record.GetInfoElementWithValue("egressIP"); ok {
		r.EgressIP = egressIP.GetStringValue()
	}
	if appProtocolName, _, ok := record.GetInfoElementWithValue("appProtocolName"); ok {
		r.AppProtocolName = appProtocolName.GetStringValue()
	}
	if httpVals, _, ok := record.GetInfoElementWithValue("httpVals"); ok {
		r.HttpVals = httpVals.GetStringValue()
	}
	if egressNodeName, _, ok := record.GetInfoElementWithValue("egressNodeName"); ok {
		r.EgressNodeName = egressNodeName.GetStringValue()
	}
	return r
}

func GetTestFlowRecord() *FlowRecord {
	return &FlowRecord{
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
	}
}
