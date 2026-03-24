// Copyright 2024 Antrea Authors
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

package collector

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

func init() {
	ipfixregistry.LoadRegistry()
}

func createTestElement(name string, enterpriseID uint32) ipfixentities.InfoElementWithValue {
	element, _ := ipfixregistry.GetInfoElement(name, enterpriseID)
	ieWithValue, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
	return ieWithValue
}

func createTestElements(isIPv4 bool) []ipfixentities.InfoElementWithValue {
	elements := make([]ipfixentities.InfoElementWithValue, 0)

	flowStartSecElem := createTestElement("flowStartSeconds", ipfixregistry.IANAEnterpriseID)
	flowStartSecElem.SetUnsigned32Value(uint32(1637706961))
	elements = append(elements, flowStartSecElem)

	flowEndSecElem := createTestElement("flowEndSeconds", ipfixregistry.IANAEnterpriseID)
	flowEndSecElem.SetUnsigned32Value(uint32(1637706973))
	elements = append(elements, flowEndSecElem)

	flowEndReasonElem := createTestElement("flowEndReason", ipfixregistry.IANAEnterpriseID)
	flowEndReasonElem.SetUnsigned8Value(uint8(3))
	elements = append(elements, flowEndReasonElem)

	srcPortElem := createTestElement("sourceTransportPort", ipfixregistry.IANAEnterpriseID)
	srcPortElem.SetUnsigned16Value(uint16(44752))
	elements = append(elements, srcPortElem)

	dstPortElem := createTestElement("destinationTransportPort", ipfixregistry.IANAEnterpriseID)
	dstPortElem.SetUnsigned16Value(uint16(5201))
	elements = append(elements, dstPortElem)

	protoIdentifierElem := createTestElement("protocolIdentifier", ipfixregistry.IANAEnterpriseID)
	protoIdentifierElem.SetUnsigned8Value(uint8(6))
	elements = append(elements, protoIdentifierElem)

	packetTotalCountElem := createTestElement("packetTotalCount", ipfixregistry.IANAEnterpriseID)
	packetTotalCountElem.SetUnsigned64Value(uint64(823188))
	elements = append(elements, packetTotalCountElem)

	octetTotalCountElem := createTestElement("octetTotalCount", ipfixregistry.IANAEnterpriseID)
	octetTotalCountElem.SetUnsigned64Value(uint64(30472817041))
	elements = append(elements, octetTotalCountElem)

	packetDeltaCountElem := createTestElement("packetDeltaCount", ipfixregistry.IANAEnterpriseID)
	packetDeltaCountElem.SetUnsigned64Value(uint64(241333))
	elements = append(elements, packetDeltaCountElem)

	octetDeltaCountElem := createTestElement("octetDeltaCount", ipfixregistry.IANAEnterpriseID)
	octetDeltaCountElem.SetUnsigned64Value(uint64(8982624938))
	elements = append(elements, octetDeltaCountElem)

	reversePacketTotalCountElem := createTestElement("reversePacketTotalCount", ipfixregistry.IANAReversedEnterpriseID)
	reversePacketTotalCountElem.SetUnsigned64Value(uint64(471111))
	elements = append(elements, reversePacketTotalCountElem)

	reverseOctetTotalCountElem := createTestElement("reverseOctetTotalCount", ipfixregistry.IANAReversedEnterpriseID)
	reverseOctetTotalCountElem.SetUnsigned64Value(uint64(24500996))
	elements = append(elements, reverseOctetTotalCountElem)

	reversePacketDeltaCountElem := createTestElement("reversePacketDeltaCount", ipfixregistry.IANAReversedEnterpriseID)
	reversePacketDeltaCountElem.SetUnsigned64Value(uint64(136211))
	elements = append(elements, reversePacketDeltaCountElem)

	reverseOctetDeltaCountElem := createTestElement("reverseOctetDeltaCount", ipfixregistry.IANAReversedEnterpriseID)
	reverseOctetDeltaCountElem.SetUnsigned64Value(uint64(7083284))
	elements = append(elements, reverseOctetDeltaCountElem)

	sourcePodNameElem := createTestElement("sourcePodName", ipfixregistry.AntreaEnterpriseID)
	sourcePodNameElem.SetStringValue("perftest-a")
	elements = append(elements, sourcePodNameElem)

	sourcePodNamespaceElem := createTestElement("sourcePodNamespace", ipfixregistry.AntreaEnterpriseID)
	sourcePodNamespaceElem.SetStringValue("antrea-test")
	elements = append(elements, sourcePodNamespaceElem)

	sourceNodeNameElem := createTestElement("sourceNodeName", ipfixregistry.AntreaEnterpriseID)
	sourceNodeNameElem.SetStringValue("k8s-node-control-plane")
	elements = append(elements, sourceNodeNameElem)

	destinationPodNameElem := createTestElement("destinationPodName", ipfixregistry.AntreaEnterpriseID)
	destinationPodNameElem.SetStringValue("perftest-b")
	elements = append(elements, destinationPodNameElem)

	destinationPodNamespaceElem := createTestElement("destinationPodNamespace", ipfixregistry.AntreaEnterpriseID)
	destinationPodNamespaceElem.SetStringValue("antrea-test-b")
	elements = append(elements, destinationPodNamespaceElem)

	destinationNodeNameElem := createTestElement("destinationNodeName", ipfixregistry.AntreaEnterpriseID)
	destinationNodeNameElem.SetStringValue("k8s-node-control-plane-b")
	elements = append(elements, destinationNodeNameElem)

	destinationServicePortElem := createTestElement("destinationServicePort", ipfixregistry.AntreaEnterpriseID)
	destinationServicePortElem.SetUnsigned16Value(uint16(5202))
	elements = append(elements, destinationServicePortElem)

	destinationServicePortNameElem := createTestElement("destinationServicePortName", ipfixregistry.AntreaEnterpriseID)
	destinationServicePortNameElem.SetStringValue("perftest")
	elements = append(elements, destinationServicePortNameElem)

	ingressNetworkPolicyNameElem := createTestElement("ingressNetworkPolicyName", ipfixregistry.AntreaEnterpriseID)
	ingressNetworkPolicyNameElem.SetStringValue("test-flow-aggregator-networkpolicy-ingress-allow")
	elements = append(elements, ingressNetworkPolicyNameElem)

	ingressNetworkPolicyNamespaceElem := createTestElement("ingressNetworkPolicyNamespace", ipfixregistry.AntreaEnterpriseID)
	ingressNetworkPolicyNamespaceElem.SetStringValue("antrea-test-ns")
	elements = append(elements, ingressNetworkPolicyNamespaceElem)

	ingressNetworkPolicyRuleNameElem := createTestElement("ingressNetworkPolicyRuleName", ipfixregistry.AntreaEnterpriseID)
	ingressNetworkPolicyRuleNameElem.SetStringValue("test-flow-aggregator-networkpolicy-rule")
	elements = append(elements, ingressNetworkPolicyRuleNameElem)

	ingressNetworkPolicyTypeElem := createTestElement("ingressNetworkPolicyType", ipfixregistry.AntreaEnterpriseID)
	ingressNetworkPolicyTypeElem.SetUnsigned8Value(uint8(1))
	elements = append(elements, ingressNetworkPolicyTypeElem)

	ingressNetworkPolicyRuleActionElem := createTestElement("ingressNetworkPolicyRuleAction", ipfixregistry.AntreaEnterpriseID)
	ingressNetworkPolicyRuleActionElem.SetUnsigned8Value(uint8(2))
	elements = append(elements, ingressNetworkPolicyRuleActionElem)

	egressNetworkPolicyNameElem := createTestElement("egressNetworkPolicyName", ipfixregistry.AntreaEnterpriseID)
	egressNetworkPolicyNameElem.SetStringValue("test-flow-aggregator-networkpolicy-egress-allow")
	elements = append(elements, egressNetworkPolicyNameElem)

	egressNetworkPolicyNamespaceElem := createTestElement("egressNetworkPolicyNamespace", ipfixregistry.AntreaEnterpriseID)
	egressNetworkPolicyNamespaceElem.SetStringValue("antrea-test-ns-e")
	elements = append(elements, egressNetworkPolicyNamespaceElem)

	egressNetworkPolicyRuleNameElem := createTestElement("egressNetworkPolicyRuleName", ipfixregistry.AntreaEnterpriseID)
	egressNetworkPolicyRuleNameElem.SetStringValue("test-flow-aggregator-networkpolicy-rule-e")
	elements = append(elements, egressNetworkPolicyRuleNameElem)

	egressNetworkPolicyTypeElem := createTestElement("egressNetworkPolicyType", ipfixregistry.AntreaEnterpriseID)
	egressNetworkPolicyTypeElem.SetUnsigned8Value(uint8(3))
	elements = append(elements, egressNetworkPolicyTypeElem)

	egressNetworkPolicyRuleActionElem := createTestElement("egressNetworkPolicyRuleAction", ipfixregistry.AntreaEnterpriseID)
	egressNetworkPolicyRuleActionElem.SetUnsigned8Value(uint8(1))
	elements = append(elements, egressNetworkPolicyRuleActionElem)

	tcpStateElem := createTestElement("tcpState", ipfixregistry.AntreaEnterpriseID)
	tcpStateElem.SetStringValue("TIME_WAIT")
	elements = append(elements, tcpStateElem)

	flowTypeElem := createTestElement("flowType", ipfixregistry.AntreaEnterpriseID)
	flowTypeElem.SetUnsigned8Value(uint8(2))
	elements = append(elements, flowTypeElem)

	egressNameElem := createTestElement("egressName", ipfixregistry.AntreaEnterpriseID)
	egressNameElem.SetStringValue("test-egress")
	elements = append(elements, egressNameElem)

	egressNodeNameElem := createTestElement("egressNodeName", ipfixregistry.AntreaEnterpriseID)
	egressNodeNameElem.SetStringValue("test-egress-node")
	elements = append(elements, egressNodeNameElem)

	// These IEs don't come at the end in the IPFIX records sent by the Flow Exporter, but the
	// order doesn't matter for the preprocessor's conversion logic.
	if isIPv4 {
		sourceIPv4Elem := createTestElement("sourceIPv4Address", ipfixregistry.IANAEnterpriseID)
		sourceIPv4Elem.SetIPAddressValue(netip.MustParseAddr("10.10.0.79").AsSlice())
		elements = append(elements, sourceIPv4Elem)

		destinationIPv4Elem := createTestElement("destinationIPv4Address", ipfixregistry.IANAEnterpriseID)
		destinationIPv4Elem.SetIPAddressValue(netip.MustParseAddr("10.10.0.80").AsSlice())
		elements = append(elements, destinationIPv4Elem)

		destinationClusterIPv4Elem := createTestElement("destinationClusterIPv4", ipfixregistry.AntreaEnterpriseID)
		destinationClusterIPv4Elem.SetIPAddressValue(netip.MustParseAddr("10.10.1.10").AsSlice())
		elements = append(elements, destinationClusterIPv4Elem)

		egressIPElem := createTestElement("egressIP", ipfixregistry.AntreaEnterpriseID)
		egressIPElem.SetStringValue("172.18.0.1")
		elements = append(elements, egressIPElem)
	} else {
		sourceIPv6Elem := createTestElement("sourceIPv6Address", ipfixregistry.IANAEnterpriseID)
		sourceIPv6Elem.SetIPAddressValue(netip.MustParseAddr("2001:0:3238:dfe1:63::fefb").AsSlice())
		elements = append(elements, sourceIPv6Elem)

		destinationIPv6Elem := createTestElement("destinationIPv6Address", ipfixregistry.IANAEnterpriseID)
		destinationIPv6Elem.SetIPAddressValue(netip.MustParseAddr("2001:0:3238:dfe1:63::fefc").AsSlice())
		elements = append(elements, destinationIPv6Elem)

		destinationClusterIPv6Elem := createTestElement("destinationClusterIPv6", ipfixregistry.AntreaEnterpriseID)
		destinationClusterIPv6Elem.SetIPAddressValue(netip.MustParseAddr("2001:0:3238:dfe1:64::a").AsSlice())
		elements = append(elements, destinationClusterIPv6Elem)

		egressIPElem := createTestElement("egressIP", ipfixregistry.AntreaEnterpriseID)
		egressIPElem.SetStringValue("2001:0:3238:dfe1::ac12:1")
		elements = append(elements, egressIPElem)
	}

	return elements
}

func createExpectedFlowRecord(isIPv4 bool) *flowpb.Flow {
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
			FlowType:                       flowpb.FlowType_FLOW_TYPE_INTER_NODE,
			SourcePodName:                  "perftest-a",
			SourcePodNamespace:             "antrea-test",
			SourceNodeName:                 "k8s-node-control-plane",
			DestinationPodName:             "perftest-b",
			DestinationPodNamespace:        "antrea-test-b",
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
	}
}

func TestPreprocessorProcessMsg(t *testing.T) {
	// For the sake of this test, we can use the same value for IPv4 and IPv6.
	const testTemplateID = 256

	exportTime := time.Now().Unix()
	const (
		sequenceNum = 10
		obsDomainID = 0xabcd
		exportAddr  = "1.2.3.4"
	)

	getTestMsg := func(iesWithValue []ipfixentities.InfoElementWithValue) *ipfixentities.Message {
		s, err := ipfixentities.MakeDataSet(testTemplateID, iesWithValue)
		require.NoError(t, err)
		msg := ipfixentities.NewMessage(true)
		msg.AddSet(s)
		msg.SetExportTime(uint32(exportTime))
		msg.SetSequenceNum(sequenceNum)
		msg.SetObsDomainID(obsDomainID)
		msg.SetExportAddress(exportAddr)
		return msg
	}

	testIPFamily := func(t *testing.T, isIPv4 bool) {
		iesWithValue := createTestElements(isIPv4)
		// Buffered channel with capacity 1 to hold the output message generated by processMsg.
		outCh := make(chan *flowpb.Flow, 1)
		p, err := newPreprocessor(nil, outCh)
		require.NoError(t, err)
		msg := getTestMsg(iesWithValue)
		p.processMsg(msg)
		var record *flowpb.Flow
		select {
		case record = <-outCh:
		default:
		}
		require.NotNil(t, record, "No record written to channel")
		expected := createExpectedFlowRecord(isIPv4)
		expected.Ipfix = &flowpb.IPFIX{
			ExportTime: &timestamppb.Timestamp{
				Seconds: exportTime,
			},
			SequenceNumber:      sequenceNum,
			ObservationDomainId: obsDomainID,
			ExporterIp:          exportAddr,
		}
		assert.Empty(t, cmp.Diff(expected, record, protocmp.Transform()))
	}

	t.Run("ipv4", func(t *testing.T) {
		testIPFamily(t, true)
	})
	t.Run("ipv6", func(t *testing.T) {
		testIPFamily(t, false)
	})
}
