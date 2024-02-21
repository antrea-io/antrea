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
	"net"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixentitiestesting "github.com/vmware/go-ipfix/pkg/entities/testing"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
)

// used for unit testing
func createElement(name string, enterpriseID uint32) ipfixentities.InfoElementWithValue {
	element, _ := ipfixregistry.GetInfoElement(name, enterpriseID)
	ieWithValue, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
	return ieWithValue
}

// used for unit testing
func PrepareMockIpfixRecord(mockRecord *ipfixentitiestesting.MockRecord, isIPv4 bool) {
	flowStartSecElem := createElement("flowStartSeconds", ipfixregistry.IANAEnterpriseID)
	flowStartSecElem.SetUnsigned32Value(uint32(1637706961))
	mockRecord.EXPECT().GetInfoElementWithValue("flowStartSeconds").Return(flowStartSecElem, 0, true)

	flowEndSecElem := createElement("flowEndSeconds", ipfixregistry.IANAEnterpriseID)
	flowEndSecElem.SetUnsigned32Value(uint32(1637706973))
	mockRecord.EXPECT().GetInfoElementWithValue("flowEndSeconds").Return(flowEndSecElem, 0, true)

	flowEndSecSrcNodeElem := createElement("flowEndSecondsFromSourceNode", ipfixregistry.AntreaEnterpriseID)
	flowEndSecSrcNodeElem.SetUnsigned32Value(uint32(1637706974))
	mockRecord.EXPECT().GetInfoElementWithValue("flowEndSecondsFromSourceNode").Return(flowEndSecSrcNodeElem, 0, true)

	flowEndSecDstNodeElem := createElement("flowEndSecondsFromDestinationNode", ipfixregistry.AntreaEnterpriseID)
	flowEndSecDstNodeElem.SetUnsigned32Value(uint32(1637706975))
	mockRecord.EXPECT().GetInfoElementWithValue("flowEndSecondsFromDestinationNode").Return(flowEndSecDstNodeElem, 0, true)

	flowEndReasonElem := createElement("flowEndReason", ipfixregistry.IANAEnterpriseID)
	flowEndReasonElem.SetUnsigned8Value(uint8(3))
	mockRecord.EXPECT().GetInfoElementWithValue("flowEndReason").Return(flowEndReasonElem, 0, true)

	srcPortElem := createElement("sourceTransportPort", ipfixregistry.IANAEnterpriseID)
	srcPortElem.SetUnsigned16Value(uint16(44752))
	mockRecord.EXPECT().GetInfoElementWithValue("sourceTransportPort").Return(srcPortElem, 0, true)

	dstPortElem := createElement("destinationTransportPort", ipfixregistry.IANAEnterpriseID)
	dstPortElem.SetUnsigned16Value(uint16(5201))
	mockRecord.EXPECT().GetInfoElementWithValue("destinationTransportPort").Return(dstPortElem, 0, true)

	protoIdentifierElem := createElement("protocolIdentifier", ipfixregistry.IANAEnterpriseID)
	protoIdentifierElem.SetUnsigned8Value(uint8(6))
	mockRecord.EXPECT().GetInfoElementWithValue("protocolIdentifier").Return(protoIdentifierElem, 0, true)

	packetTotalCountElem := createElement("packetTotalCount", ipfixregistry.IANAEnterpriseID)
	packetTotalCountElem.SetUnsigned64Value(uint64(823188))
	mockRecord.EXPECT().GetInfoElementWithValue("packetTotalCount").Return(packetTotalCountElem, 0, true)

	octetTotalCountElem := createElement("octetTotalCount", ipfixregistry.IANAEnterpriseID)
	octetTotalCountElem.SetUnsigned64Value(uint64(30472817041))
	mockRecord.EXPECT().GetInfoElementWithValue("octetTotalCount").Return(octetTotalCountElem, 0, true)

	packetDeltaCountElem := createElement("packetDeltaCount", ipfixregistry.IANAEnterpriseID)
	packetDeltaCountElem.SetUnsigned64Value(uint64(241333))
	mockRecord.EXPECT().GetInfoElementWithValue("packetDeltaCount").Return(packetDeltaCountElem, 0, true)

	octetDeltaCountElem := createElement("octetDeltaCount", ipfixregistry.IANAEnterpriseID)
	octetDeltaCountElem.SetUnsigned64Value(uint64(8982624938))
	mockRecord.EXPECT().GetInfoElementWithValue("octetDeltaCount").Return(octetDeltaCountElem, 0, true)

	reversePacketTotalCountElem := createElement("reversePacketTotalCount", ipfixregistry.IANAReversedEnterpriseID)
	reversePacketTotalCountElem.SetUnsigned64Value(uint64(471111))
	mockRecord.EXPECT().GetInfoElementWithValue("reversePacketTotalCount").Return(reversePacketTotalCountElem, 0, true)

	reverseOctetTotalCountElem := createElement("reverseOctetTotalCount", ipfixregistry.IANAReversedEnterpriseID)
	reverseOctetTotalCountElem.SetUnsigned64Value(uint64(24500996))
	mockRecord.EXPECT().GetInfoElementWithValue("reverseOctetTotalCount").Return(reverseOctetTotalCountElem, 0, true)

	reversePacketDeltaCountElem := createElement("reversePacketDeltaCount", ipfixregistry.IANAReversedEnterpriseID)
	reversePacketDeltaCountElem.SetUnsigned64Value(uint64(136211))
	mockRecord.EXPECT().GetInfoElementWithValue("reversePacketDeltaCount").Return(reversePacketDeltaCountElem, 0, true)

	reverseOctetDeltaCountElem := createElement("reverseOctetDeltaCount", ipfixregistry.IANAReversedEnterpriseID)
	reverseOctetDeltaCountElem.SetUnsigned64Value(uint64(7083284))
	mockRecord.EXPECT().GetInfoElementWithValue("reverseOctetDeltaCount").Return(reverseOctetDeltaCountElem, 0, true)

	sourcePodNameElem := createElement("sourcePodName", ipfixregistry.AntreaEnterpriseID)
	sourcePodNameElem.SetStringValue("perftest-a")
	mockRecord.EXPECT().GetInfoElementWithValue("sourcePodName").Return(sourcePodNameElem, 0, true)

	sourcePodNamespaceElem := createElement("sourcePodNamespace", ipfixregistry.AntreaEnterpriseID)
	sourcePodNamespaceElem.SetStringValue("antrea-test")
	mockRecord.EXPECT().GetInfoElementWithValue("sourcePodNamespace").Return(sourcePodNamespaceElem, 0, true)

	sourceNodeNameElem := createElement("sourceNodeName", ipfixregistry.AntreaEnterpriseID)
	sourceNodeNameElem.SetStringValue("k8s-node-control-plane")
	mockRecord.EXPECT().GetInfoElementWithValue("sourceNodeName").Return(sourceNodeNameElem, 0, true)

	destinationPodNameElem := createElement("destinationPodName", ipfixregistry.AntreaEnterpriseID)
	destinationPodNameElem.SetStringValue("perftest-b")
	mockRecord.EXPECT().GetInfoElementWithValue("destinationPodName").Return(destinationPodNameElem, 0, true)

	destinationPodNamespaceElem := createElement("destinationPodNamespace", ipfixregistry.AntreaEnterpriseID)
	destinationPodNamespaceElem.SetStringValue("antrea-test-b")
	mockRecord.EXPECT().GetInfoElementWithValue("destinationPodNamespace").Return(destinationPodNamespaceElem, 0, true)

	destinationNodeNameElem := createElement("destinationNodeName", ipfixregistry.AntreaEnterpriseID)
	destinationNodeNameElem.SetStringValue("k8s-node-control-plane-b")
	mockRecord.EXPECT().GetInfoElementWithValue("destinationNodeName").Return(destinationNodeNameElem, 0, true)

	destinationServicePortElem := createElement("destinationServicePort", ipfixregistry.AntreaEnterpriseID)
	destinationServicePortElem.SetUnsigned16Value(uint16(5202))
	mockRecord.EXPECT().GetInfoElementWithValue("destinationServicePort").Return(destinationServicePortElem, 0, true)

	destinationServicePortNameElem := createElement("destinationServicePortName", ipfixregistry.AntreaEnterpriseID)
	destinationServicePortNameElem.SetStringValue("perftest")
	mockRecord.EXPECT().GetInfoElementWithValue("destinationServicePortName").Return(destinationServicePortNameElem, 0, true)

	ingressNetworkPolicyNameElem := createElement("ingressNetworkPolicyName", ipfixregistry.AntreaEnterpriseID)
	ingressNetworkPolicyNameElem.SetStringValue("test-flow-aggregator-networkpolicy-ingress-allow")
	mockRecord.EXPECT().GetInfoElementWithValue("ingressNetworkPolicyName").Return(ingressNetworkPolicyNameElem, 0, true)

	ingressNetworkPolicyNamespaceElem := createElement("ingressNetworkPolicyNamespace", ipfixregistry.AntreaEnterpriseID)
	ingressNetworkPolicyNamespaceElem.SetStringValue("antrea-test-ns")
	mockRecord.EXPECT().GetInfoElementWithValue("ingressNetworkPolicyNamespace").Return(ingressNetworkPolicyNamespaceElem, 0, true)

	ingressNetworkPolicyRuleNameElem := createElement("ingressNetworkPolicyRuleName", ipfixregistry.AntreaEnterpriseID)
	ingressNetworkPolicyRuleNameElem.SetStringValue("test-flow-aggregator-networkpolicy-rule")
	mockRecord.EXPECT().GetInfoElementWithValue("ingressNetworkPolicyRuleName").Return(ingressNetworkPolicyRuleNameElem, 0, true)

	ingressNetworkPolicyTypeElem := createElement("ingressNetworkPolicyType", ipfixregistry.AntreaEnterpriseID)
	ingressNetworkPolicyTypeElem.SetUnsigned8Value(uint8(1))
	mockRecord.EXPECT().GetInfoElementWithValue("ingressNetworkPolicyType").Return(ingressNetworkPolicyTypeElem, 0, true)

	ingressNetworkPolicyRuleActionElem := createElement("ingressNetworkPolicyRuleAction", ipfixregistry.AntreaEnterpriseID)
	ingressNetworkPolicyRuleActionElem.SetUnsigned8Value(uint8(2))
	mockRecord.EXPECT().GetInfoElementWithValue("ingressNetworkPolicyRuleAction").Return(ingressNetworkPolicyRuleActionElem, 0, true)

	egressNetworkPolicyNameElem := createElement("egressNetworkPolicyName", ipfixregistry.AntreaEnterpriseID)
	egressNetworkPolicyNameElem.SetStringValue("test-flow-aggregator-networkpolicy-egress-allow")
	mockRecord.EXPECT().GetInfoElementWithValue("egressNetworkPolicyName").Return(egressNetworkPolicyNameElem, 0, true)

	egressNetworkPolicyNamespaceElem := createElement("egressNetworkPolicyNamespace", ipfixregistry.AntreaEnterpriseID)
	egressNetworkPolicyNamespaceElem.SetStringValue("antrea-test-ns-e")
	mockRecord.EXPECT().GetInfoElementWithValue("egressNetworkPolicyNamespace").Return(egressNetworkPolicyNamespaceElem, 0, true)

	egressNetworkPolicyRuleNameElem := createElement("egressNetworkPolicyRuleName", ipfixregistry.AntreaEnterpriseID)
	egressNetworkPolicyRuleNameElem.SetStringValue("test-flow-aggregator-networkpolicy-rule-e")
	mockRecord.EXPECT().GetInfoElementWithValue("egressNetworkPolicyRuleName").Return(egressNetworkPolicyRuleNameElem, 0, true)

	egressNetworkPolicyTypeElem := createElement("egressNetworkPolicyType", ipfixregistry.AntreaEnterpriseID)
	egressNetworkPolicyTypeElem.SetUnsigned8Value(uint8(4))
	mockRecord.EXPECT().GetInfoElementWithValue("egressNetworkPolicyType").Return(egressNetworkPolicyTypeElem, 0, true)

	egressNetworkPolicyRuleActionElem := createElement("egressNetworkPolicyRuleAction", ipfixregistry.AntreaEnterpriseID)
	egressNetworkPolicyRuleActionElem.SetUnsigned8Value(uint8(5))
	mockRecord.EXPECT().GetInfoElementWithValue("egressNetworkPolicyRuleAction").Return(egressNetworkPolicyRuleActionElem, 0, true)

	tcpStateElem := createElement("tcpState", ipfixregistry.AntreaEnterpriseID)
	tcpStateElem.SetStringValue("TIME_WAIT")
	mockRecord.EXPECT().GetInfoElementWithValue("tcpState").Return(tcpStateElem, 0, true)

	flowTypeElem := createElement("flowType", ipfixregistry.AntreaEnterpriseID)
	flowTypeElem.SetUnsigned8Value(uint8(11))
	mockRecord.EXPECT().GetInfoElementWithValue("flowType").Return(flowTypeElem, 0, true)

	sourcePodLabelsElem := createElement("sourcePodLabels", ipfixregistry.AntreaEnterpriseID)
	sourcePodLabelsElem.SetStringValue("{\"antrea-e2e\":\"perftest-a\",\"app\":\"iperf\"}")
	mockRecord.EXPECT().GetInfoElementWithValue("sourcePodLabels").Return(sourcePodLabelsElem, 0, true)

	destinationPodLabelsElem := createElement("destinationPodLabels", ipfixregistry.AntreaEnterpriseID)
	destinationPodLabelsElem.SetStringValue("{\"antrea-e2e\":\"perftest-b\",\"app\":\"iperf\"}")
	mockRecord.EXPECT().GetInfoElementWithValue("destinationPodLabels").Return(destinationPodLabelsElem, 0, true)

	throughputElem := createElement("throughput", ipfixregistry.AntreaEnterpriseID)
	throughputElem.SetUnsigned64Value(uint64(15902813472))
	mockRecord.EXPECT().GetInfoElementWithValue("throughput").Return(throughputElem, 0, true)

	reverseThroughputElem := createElement("reverseThroughput", ipfixregistry.AntreaEnterpriseID)
	reverseThroughputElem.SetUnsigned64Value(uint64(12381344))
	mockRecord.EXPECT().GetInfoElementWithValue("reverseThroughput").Return(reverseThroughputElem, 0, true)

	throughputFromSourceNodeElem := createElement("throughputFromSourceNode", ipfixregistry.AntreaEnterpriseID)
	throughputFromSourceNodeElem.SetUnsigned64Value(uint64(15902813473))
	mockRecord.EXPECT().GetInfoElementWithValue("throughputFromSourceNode").Return(throughputFromSourceNodeElem, 0, true)

	throughputFromDestinationNodeElem := createElement("throughputFromDestinationNode", ipfixregistry.AntreaEnterpriseID)
	throughputFromDestinationNodeElem.SetUnsigned64Value(uint64(15902813474))
	mockRecord.EXPECT().GetInfoElementWithValue("throughputFromDestinationNode").Return(throughputFromDestinationNodeElem, 0, true)

	reverseThroughputFromSourceNodeElem := createElement("reverseThroughputFromSourceNode", ipfixregistry.AntreaEnterpriseID)
	reverseThroughputFromSourceNodeElem.SetUnsigned64Value(uint64(12381345))
	mockRecord.EXPECT().GetInfoElementWithValue("reverseThroughputFromSourceNode").Return(reverseThroughputFromSourceNodeElem, 0, true)

	reverseThroughputFromDestinationNodeElem := createElement("reverseThroughputFromDestinationNode", ipfixregistry.AntreaEnterpriseID)
	reverseThroughputFromDestinationNodeElem.SetUnsigned64Value(uint64(12381346))
	mockRecord.EXPECT().GetInfoElementWithValue("reverseThroughputFromDestinationNode").Return(reverseThroughputFromDestinationNodeElem, 0, true)

	egressNameElem := createElement("egressName", ipfixregistry.AntreaEnterpriseID)
	egressNameElem.SetStringValue("test-egress")
	mockRecord.EXPECT().GetInfoElementWithValue("egressName").Return(egressNameElem, 0, true)

	egressIPElem := createElement("egressIP", ipfixregistry.AntreaEnterpriseID)
	egressIPElem.SetStringValue("172.18.0.1")
	mockRecord.EXPECT().GetInfoElementWithValue("egressIP").Return(egressIPElem, 0, true)

	appProtocolNameElem := createElement("appProtocolName", ipfixregistry.AntreaEnterpriseID)
	appProtocolNameElem.SetStringValue("http")
	mockRecord.EXPECT().GetInfoElementWithValue("appProtocolName").Return(appProtocolNameElem, 0, true)

	httpValsElem := createElement("httpVals", ipfixregistry.AntreaEnterpriseID)
	httpValsElem.SetStringValue("mockHttpString")
	mockRecord.EXPECT().GetInfoElementWithValue("httpVals").Return(httpValsElem, 0, true)

	egressNodeNameElem := createElement("egressNodeName", ipfixregistry.AntreaEnterpriseID)
	egressNodeNameElem.SetStringValue("test-egress-node")
	mockRecord.EXPECT().GetInfoElementWithValue("egressNodeName").Return(egressNodeNameElem, 0, true)

	if isIPv4 {
		sourceIPv4Elem := createElement("sourceIPv4Address", ipfixregistry.IANAEnterpriseID)
		sourceIPv4Elem.SetIPAddressValue(net.ParseIP("10.10.0.79"))
		mockRecord.EXPECT().GetInfoElementWithValue("sourceIPv4Address").Return(sourceIPv4Elem, 0, true).AnyTimes()
		mockRecord.EXPECT().GetInfoElementWithValue("sourceIPv6Address").Return(nil, 0, false).AnyTimes()

		destinationIPv4Elem := createElement("destinationIPv4Address", ipfixregistry.IANAEnterpriseID)
		destinationIPv4Elem.SetIPAddressValue(net.ParseIP("10.10.0.80"))
		mockRecord.EXPECT().GetInfoElementWithValue("destinationIPv4Address").Return(destinationIPv4Elem, 0, true).AnyTimes()
		mockRecord.EXPECT().GetInfoElementWithValue("destinationIPv6Address").Return(nil, 0, false).AnyTimes()

		destinationClusterIPv4Elem := createElement("destinationClusterIPv4", ipfixregistry.AntreaEnterpriseID)
		destinationClusterIPv4Elem.SetIPAddressValue(net.ParseIP("10.10.1.10"))
		mockRecord.EXPECT().GetInfoElementWithValue("destinationClusterIPv4").Return(destinationClusterIPv4Elem, 0, true).AnyTimes()
		mockRecord.EXPECT().GetInfoElementWithValue("destinationClusterIPv6").Return(nil, 0, false).AnyTimes()
	} else {
		sourceIPv6Elem := createElement("sourceIPv6Address", ipfixregistry.IANAEnterpriseID)
		sourceIPv6Elem.SetIPAddressValue(net.ParseIP("2001:0:3238:dfe1:63::fefb"))
		mockRecord.EXPECT().GetInfoElementWithValue("sourceIPv6Address").Return(sourceIPv6Elem, 0, true).AnyTimes()
		mockRecord.EXPECT().GetInfoElementWithValue("sourceIPv4Address").Return(nil, 0, false).AnyTimes()

		destinationIPv6Elem := createElement("destinationIPv6Address", ipfixregistry.IANAEnterpriseID)
		destinationIPv6Elem.SetIPAddressValue(net.ParseIP("2001:0:3238:dfe1:63::fefc"))
		mockRecord.EXPECT().GetInfoElementWithValue("destinationIPv6Address").Return(destinationIPv6Elem, 0, true).AnyTimes()
		mockRecord.EXPECT().GetInfoElementWithValue("destinationIPv4Address").Return(nil, 0, false).AnyTimes()

		destinationClusterIPv6Elem := createElement("destinationClusterIPv6", ipfixregistry.AntreaEnterpriseID)
		destinationClusterIPv6Elem.SetIPAddressValue(net.ParseIP("2001:0:3238:dfe1:64::a"))
		mockRecord.EXPECT().GetInfoElementWithValue("destinationClusterIPv6").Return(destinationClusterIPv6Elem, 0, true).AnyTimes()
		mockRecord.EXPECT().GetInfoElementWithValue("destinationClusterIPv4").Return(nil, 0, false).AnyTimes()
	}
}
