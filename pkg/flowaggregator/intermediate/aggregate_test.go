// Copyright 2025 Antrea Authors
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

package intermediate

import (
	"container/heap"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

var (
	fields = []string{
		"sourcePodName",
		"sourcePodNamespace",
		"sourceNodeName",
		"destinationPodName",
		"destinationPodNamespace",
		"destinationNodeName",
		"destinationClusterIPv4",
		"destinationClusterIPv6",
		"destinationServicePort",
		"ingressNetworkPolicyRuleAction",
		"egressNetworkPolicyRuleAction",
		"ingressNetworkPolicyRulePriority",
	}
	nonStatsElementList = []string{
		"flowEndSeconds",
		"flowEndReason",
		"tcpState",
		"httpVals",
	}
	statsElementList = []string{
		"packetTotalCount",
		"packetDeltaCount",
		"octetTotalCount",
		"reversePacketTotalCount",
		"reversePacketDeltaCount",
		"reverseOctetTotalCount",
	}
	antreaSourceStatsElementList = []string{
		"packetTotalCountFromSourceNode",
		"packetDeltaCountFromSourceNode",
		"octetTotalCountFromSourceNode",
		"reversePacketTotalCountFromSourceNode",
		"reversePacketDeltaCountFromSourceNode",
		"reverseOctetTotalCountFromSourceNode",
	}
	antreaDestinationStatsElementList = []string{
		"packetTotalCountFromDestinationNode",
		"packetDeltaCountFromDestinationNode",
		"octetTotalCountFromDestinationNode",
		"reversePacketTotalCountFromDestinationNode",
		"reversePacketDeltaCountFromDestinationNode",
		"reverseOctetTotalCountFromDestinationNode",
	}
	antreaFlowEndSecondsElementList = []string{
		"flowEndSecondsFromSourceNode",
		"flowEndSecondsFromDestinationNode",
	}
	antreaThroughputElementList = []string{
		"throughput",
		"reverseThroughput",
	}
	antreaSourceThroughputElementList = []string{
		"throughputFromSourceNode",
		"reverseThroughputFromSourceNode",
	}
	antreaDestinationThroughputElementList = []string{
		"throughputFromDestinationNode",
		"reverseThroughputFromDestinationNode",
	}
)

func init() {
	registry.LoadRegistry()
	MaxRetries = 1
	MinExpiryTime = 0
}

const (
	testTemplateID     = uint16(256)
	testActiveExpiry   = 100 * time.Millisecond
	testInactiveExpiry = 150 * time.Millisecond
	testMaxRetries     = 2
)

func createMsgwithTemplateSet(isIPv6 bool) *entities.Message {
	set := entities.NewSet(true)
	set.PrepareSet(entities.Template, testTemplateID)
	elements := make([]entities.InfoElementWithValue, 0)
	ie3 := entities.NewUnsigned16InfoElement(entities.NewInfoElement("sourceTransportPort", 7, 2, 0, 2), 0)
	ie4 := entities.NewUnsigned16InfoElement(entities.NewInfoElement("destinationTransportPort", 11, 2, 0, 2), 0)
	ie5 := entities.NewUnsigned8InfoElement(entities.NewInfoElement("protocolIdentifier", 4, 1, 0, 1), 0)
	ie6 := entities.NewStringInfoElement(entities.NewInfoElement("sourcePodName", 101, 13, registry.AntreaEnterpriseID, 65535), "")
	ie7 := entities.NewStringInfoElement(entities.NewInfoElement("destinationPodName", 103, 13, registry.AntreaEnterpriseID, 65535), "")
	ie9 := entities.NewUnsigned16InfoElement(entities.NewInfoElement("destinationServicePort", 107, 2, registry.AntreaEnterpriseID, 2), 0)
	var ie1, ie2, ie8 entities.InfoElementWithValue
	if !isIPv6 {
		ie1 = entities.NewIPAddressInfoElement(entities.NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
		ie2 = entities.NewIPAddressInfoElement(entities.NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), nil)
		ie8 = entities.NewIPAddressInfoElement(entities.NewInfoElement("destinationClusterIPv4", 106, 18, registry.AntreaEnterpriseID, 4), nil)
	} else {
		ie1 = entities.NewIPAddressInfoElement(entities.NewInfoElement("sourceIPv6Address", 8, 19, 0, 16), nil)
		ie2 = entities.NewIPAddressInfoElement(entities.NewInfoElement("destinationIPv6Address", 12, 19, 0, 16), nil)
		ie8 = entities.NewIPAddressInfoElement(entities.NewInfoElement("destinationClusterIPv6", 106, 19, registry.AntreaEnterpriseID, 16), nil)
	}
	ie10 := entities.NewDateTimeSecondsInfoElement(entities.NewInfoElement("flowEndSeconds", 151, 14, 0, 4), 0)
	ie11 := entities.NewUnsigned8InfoElement(entities.NewInfoElement("flowType", 137, 1, registry.AntreaEnterpriseID, 1), 0)
	ie12 := entities.NewUnsigned8InfoElement(entities.NewInfoElement("ingressNetworkPolicyRuleAction", 139, 1, registry.AntreaEnterpriseID, 1), 0)
	ie13 := entities.NewUnsigned8InfoElement(entities.NewInfoElement("egressNetworkPolicyRuleAction", 140, 1, registry.AntreaEnterpriseID, 1), 0)
	ie14 := entities.NewSigned32InfoElement(entities.NewInfoElement("ingressNetworkPolicyRulePriority", 116, 7, registry.AntreaEnterpriseID, 4), 0)

	elements = append(elements, ie1, ie2, ie3, ie4, ie5, ie6, ie7, ie8, ie9, ie10, ie11, ie12, ie13, ie14)
	set.AddRecord(elements, 256)

	message := entities.NewMessage(true)
	message.SetVersion(10)
	message.SetMessageLen(40)
	message.SetSequenceNum(1)
	message.SetObsDomainID(5678)
	message.SetExportTime(0)
	if isIPv6 {
		message.SetExportAddress("::1")
	} else {
		message.SetExportAddress("127.0.0.1")
	}
	message.AddSet(set)
	return message
}

// TODO:Cleanup this function using a loop, to make it easy to add elements for testing.
func createDataMsgForSrc(t testing.TB, isIPv6 bool, isIntraNode bool, isUpdatedRecord bool, isToExternal bool, isEgressDeny bool) *entities.Message {
	set := entities.NewSet(true)
	set.PrepareSet(entities.Data, testTemplateID)
	elements := make([]entities.InfoElementWithValue, 0)
	var srcPod, dstPod string
	srcPod = "pod1"
	if !isIntraNode {
		dstPod = ""
	} else {
		dstPod = "pod2"
	}
	ie3 := entities.NewUnsigned16InfoElement(entities.NewInfoElement("sourceTransportPort", 7, 2, 0, 2), uint16(1234))
	ie4 := entities.NewUnsigned16InfoElement(entities.NewInfoElement("destinationTransportPort", 11, 2, 0, 2), uint16(5678))
	ie5 := entities.NewUnsigned8InfoElement(entities.NewInfoElement("protocolIdentifier", 4, 1, 0, 1), uint8(6))
	ie6 := entities.NewStringInfoElement(entities.NewInfoElement("sourcePodName", 101, 13, registry.AntreaEnterpriseID, 65535), srcPod)
	ie7 := entities.NewStringInfoElement(entities.NewInfoElement("destinationPodName", 103, 13, registry.AntreaEnterpriseID, 65535), dstPod)
	ie9 := entities.NewUnsigned16InfoElement(entities.NewInfoElement("destinationServicePort", 107, 2, registry.AntreaEnterpriseID, 2), uint16(4739))
	var ie1, ie2, ie8, ie10, ie11, ie12, ie13, ie14, ie15, ie16, ie17, ie18 entities.InfoElementWithValue
	if !isIPv6 {
		ie1 = entities.NewIPAddressInfoElement(entities.NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), net.ParseIP("10.0.0.1").To4())
		ie2 = entities.NewIPAddressInfoElement(entities.NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), net.ParseIP("10.0.0.2").To4())
		ie8 = entities.NewIPAddressInfoElement(entities.NewInfoElement("destinationClusterIPv4", 106, 18, registry.AntreaEnterpriseID, 4), net.ParseIP("192.168.0.1").To4())
	} else {
		ie1 = entities.NewIPAddressInfoElement(entities.NewInfoElement("sourceIPv6Address", 8, 19, 0, 16), net.ParseIP("2001:0:3238:DFE1:63::FEFB"))
		ie2 = entities.NewIPAddressInfoElement(entities.NewInfoElement("destinationIPv6Address", 12, 19, 0, 16), net.ParseIP("2001:0:3238:DFE1:63::FEFC"))
		ie8 = entities.NewIPAddressInfoElement(entities.NewInfoElement("destinationClusterIPv6", 106, 19, registry.AntreaEnterpriseID, 16), net.ParseIP("2001:0:3238:BBBB:63::AAAA"))
	}
	tmpFlowStartSecs, _ := registry.GetInfoElement("flowStartSeconds", registry.IANAEnterpriseID)
	tmpFlowEndSecs, _ := registry.GetInfoElement("flowEndSeconds", registry.IANAEnterpriseID)
	tmpFlowEndReason, _ := registry.GetInfoElement("flowEndReason", registry.IANAEnterpriseID)
	tmpTCPState, _ := registry.GetInfoElement("tcpState", registry.AntreaEnterpriseID)
	tmpHttpVals, _ := registry.GetInfoElement("httpVals", registry.AntreaEnterpriseID)

	if !isUpdatedRecord {
		ie10 = entities.NewDateTimeSecondsInfoElement(tmpFlowEndSecs, uint32(1))
		ie12 = entities.NewUnsigned8InfoElement(tmpFlowEndReason, registry.ActiveTimeoutReason)
		ie13 = entities.NewStringInfoElement(tmpTCPState, "ESTABLISHED")
		ie18 = entities.NewStringInfoElement(tmpHttpVals, "{\"0\":\"{hostname:10.10.0.1,url:/public/,http_user_agent:curl/7.74.0,http_content_type:text/html,http_method:GET,protocol:HTTP/1.1,status:200,length:153}\"}")
	} else {
		ie10 = entities.NewDateTimeSecondsInfoElement(tmpFlowEndSecs, uint32(10))
		ie12 = entities.NewUnsigned8InfoElement(tmpFlowEndReason, registry.EndOfFlowReason)
		ie13 = entities.NewStringInfoElement(tmpTCPState, "TIME_WAIT")
		ie18 = entities.NewStringInfoElement(tmpHttpVals, "{\"0\":\"{hostname:10.10.0.1,url:/public/,http_user_agent:curl/7.74.0,http_content_type:text/html,http_method:GET,protocol:HTTP/1.1,status:200,length:153}\"}")
	}

	if isToExternal {
		ie11 = entities.NewUnsigned8InfoElement(entities.NewInfoElement("flowType", 137, 1, registry.AntreaEnterpriseID, 1), registry.FlowTypeToExternal)
		ie16 = entities.NewSigned32InfoElement(entities.NewInfoElement("ingressNetworkPolicyRulePriority", 116, 7, registry.AntreaEnterpriseID, 4), int32(50000))
	} else if !isIntraNode {
		ie11 = entities.NewUnsigned8InfoElement(entities.NewInfoElement("flowType", 137, 1, registry.AntreaEnterpriseID, 1), registry.FlowTypeInterNode)
		ie16 = entities.NewSigned32InfoElement(entities.NewInfoElement("ingressNetworkPolicyRulePriority", 116, 7, registry.AntreaEnterpriseID, 4), int32(0))
	} else {
		ie11 = entities.NewUnsigned8InfoElement(entities.NewInfoElement("flowType", 137, 1, registry.AntreaEnterpriseID, 1), registry.FlowTypeIntraNode)
		ie16 = entities.NewSigned32InfoElement(entities.NewInfoElement("ingressNetworkPolicyRulePriority", 116, 7, registry.AntreaEnterpriseID, 4), int32(50000))
	}
	ie14 = entities.NewUnsigned8InfoElement(entities.NewInfoElement("ingressNetworkPolicyRuleAction", 139, 1, registry.AntreaEnterpriseID, 1), registry.NetworkPolicyRuleActionNoAction)

	if isEgressDeny {
		ie15 = entities.NewUnsigned8InfoElement(entities.NewInfoElement("egressNetworkPolicyRuleAction", 140, 1, registry.AntreaEnterpriseID, 1), registry.NetworkPolicyRuleActionDrop)
	} else {
		ie15 = entities.NewUnsigned8InfoElement(entities.NewInfoElement("egressNetworkPolicyRuleAction", 140, 1, registry.AntreaEnterpriseID, 1), registry.NetworkPolicyRuleActionNoAction)
	}
	ie17 = entities.NewDateTimeSecondsInfoElement(tmpFlowStartSecs, uint32(0))

	elements = append(elements, ie1, ie2, ie3, ie4, ie5, ie6, ie7, ie8, ie9, ie10, ie11, ie12, ie13, ie14, ie15, ie16, ie17, ie18)
	// Add all elements in statsElements.
	for _, element := range statsElementList {
		var e *entities.InfoElement
		if !strings.Contains(element, "reverse") {
			e, _ = registry.GetInfoElement(element, registry.IANAEnterpriseID)
		} else {
			e, _ = registry.GetInfoElement(element, registry.IANAReversedEnterpriseID)
		}

		var ieWithValue entities.InfoElementWithValue
		switch element {
		case "packetTotalCount", "reversePacketTotalCount":
			if !isUpdatedRecord {
				ieWithValue = entities.NewUnsigned64InfoElement(e, uint64(500))
			} else {
				ieWithValue = entities.NewUnsigned64InfoElement(e, uint64(1000))
			}
		case "packetDeltaCount", "reversePacketDeltaCount":
			if !isUpdatedRecord {
				ieWithValue = entities.NewUnsigned64InfoElement(e, uint64(0))
			} else {
				ieWithValue = entities.NewUnsigned64InfoElement(e, uint64(500))
			}
		case "octetTotalCount", "reverseOctetTotalCount":
			if !isUpdatedRecord {
				ieWithValue = entities.NewUnsigned64InfoElement(e, uint64(1000))
			} else {
				ieWithValue = entities.NewUnsigned64InfoElement(e, uint64(2000))
			}
		}
		elements = append(elements, ieWithValue)
	}

	err := set.AddRecord(elements, 256)
	assert.NoError(t, err)

	message := entities.NewMessage(true)
	message.SetVersion(10)
	message.SetMessageLen(32)
	message.SetSequenceNum(1)
	message.SetObsDomainID(1234)
	message.SetExportTime(0)
	if isIPv6 {
		message.SetExportAddress("::1")
	} else {
		message.SetExportAddress("127.0.0.1")
	}
	message.AddSet(set)

	return message
}

func createDataMsgForDst(t testing.TB, isIPv6 bool, isIntraNode bool, isUpdatedRecord bool, isIngressReject bool, isIngressDrop bool) *entities.Message {
	set := entities.NewSet(true)
	set.PrepareSet(entities.Data, testTemplateID)
	elements := make([]entities.InfoElementWithValue, 0)
	var srcAddr, dstAddr, svcAddr []byte
	var flowStartTime, flowEndTime uint32
	var flowEndReason, ingressNetworkPolicyRuleAction, antreaFlowType uint8
	var srcPod, dstPod, tcpState, httpVals string
	var svcPort uint16
	srcPort := uint16(1234)
	dstPort := uint16(5678)
	proto := uint8(6)
	if isIngressReject {
		ingressNetworkPolicyRuleAction = registry.NetworkPolicyRuleActionReject
	} else if isIngressDrop {
		ingressNetworkPolicyRuleAction = registry.NetworkPolicyRuleActionDrop
	} else {
		ingressNetworkPolicyRuleAction = registry.NetworkPolicyRuleActionNoAction
	}
	egressNetworkPolicyRuleAction := registry.NetworkPolicyRuleActionNoAction
	ingressNetworkPolicyRulePriority := int32(50000)
	if !isIntraNode {
		svcPort = uint16(0)
		srcPod = ""
	} else {
		svcPort = uint16(4739)
		srcPod = "pod1"
	}
	dstPod = "pod2"

	ie3 := entities.NewUnsigned16InfoElement(entities.NewInfoElement("sourceTransportPort", 7, 2, 0, 2), srcPort)
	ie4 := entities.NewUnsigned16InfoElement(entities.NewInfoElement("destinationTransportPort", 11, 2, 0, 2), dstPort)
	ie5 := entities.NewUnsigned8InfoElement(entities.NewInfoElement("protocolIdentifier", 4, 1, 0, 1), proto)
	ie6 := entities.NewStringInfoElement(entities.NewInfoElement("sourcePodName", 101, 13, registry.AntreaEnterpriseID, 65535), srcPod)
	ie7 := entities.NewStringInfoElement(entities.NewInfoElement("destinationPodName", 103, 13, registry.AntreaEnterpriseID, 65535), dstPod)
	ie9 := entities.NewUnsigned16InfoElement(entities.NewInfoElement("destinationServicePort", 107, 2, registry.AntreaEnterpriseID, 2), svcPort)
	var ie1, ie2, ie8, ie11 entities.InfoElementWithValue
	if !isIPv6 {
		srcAddr = net.ParseIP("10.0.0.1").To4()
		dstAddr = net.ParseIP("10.0.0.2").To4()
		svcAddr = net.ParseIP("0.0.0.0").To4()
		ie1 = entities.NewIPAddressInfoElement(entities.NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), srcAddr)
		ie2 = entities.NewIPAddressInfoElement(entities.NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), dstAddr)
		ie8 = entities.NewIPAddressInfoElement(entities.NewInfoElement("destinationClusterIPv4", 106, 18, registry.AntreaEnterpriseID, 4), svcAddr)
	} else {
		srcAddr = net.ParseIP("2001:0:3238:DFE1:63::FEFB")
		dstAddr = net.ParseIP("2001:0:3238:DFE1:63::FEFC")
		if !isIntraNode {
			svcAddr = net.ParseIP("::0")
		} else {
			svcAddr = net.ParseIP("2001:0:3238:BBBB:63::AAAA")
		}
		ie1 = entities.NewIPAddressInfoElement(entities.NewInfoElement("sourceIPv6Address", 8, 19, 0, 16), srcAddr)
		ie2 = entities.NewIPAddressInfoElement(entities.NewInfoElement("destinationIPv6Address", 12, 19, 0, 16), dstAddr)
		ie8 = entities.NewIPAddressInfoElement(entities.NewInfoElement("destinationClusterIPv6", 106, 19, registry.AntreaEnterpriseID, 16), svcAddr)
	}
	flowStartTime = uint32(0)
	if !isUpdatedRecord {
		flowEndTime = uint32(1)
		flowEndReason = registry.ActiveTimeoutReason
		tcpState = "ESTABLISHED"
		httpVals = "{\"0\":\"{hostname:10.10.0.1,url:/public/,http_user_agent:curl/7.74.0,http_content_type:text/html,http_method:GET,protocol:HTTP/1.1,status:200,length:153}\"}"
	} else {
		flowEndTime = uint32(10)
		flowEndReason = registry.EndOfFlowReason
		tcpState = "TIME_WAIT"
		httpVals = "{\"0\":\"{hostname:10.10.0.1,url:/public/,http_user_agent:curl/7.74.0,http_content_type:text/html,http_method:GET,protocol:HTTP/1.1,status:200,length:153}\"}"
	}
	tmpElement, _ := registry.GetInfoElement("flowStartSeconds", registry.IANAEnterpriseID)
	ie17 := entities.NewDateTimeSecondsInfoElement(tmpElement, flowStartTime)
	tmpElement, _ = registry.GetInfoElement("flowEndSeconds", registry.IANAEnterpriseID)
	ie10 := entities.NewDateTimeSecondsInfoElement(tmpElement, flowEndTime)
	if !isIntraNode {
		antreaFlowType = registry.FlowTypeInterNode
	} else {
		antreaFlowType = registry.FlowTypeIntraNode
	}
	ie11 = entities.NewUnsigned8InfoElement(entities.NewInfoElement("flowType", 137, 1, registry.AntreaEnterpriseID, 1), antreaFlowType)
	tmpElement, _ = registry.GetInfoElement("flowEndReason", registry.IANAEnterpriseID)
	ie12 := entities.NewUnsigned8InfoElement(tmpElement, flowEndReason)
	tmpElement, _ = registry.GetInfoElement("tcpState", registry.AntreaEnterpriseID)
	ie13 := entities.NewStringInfoElement(tmpElement, tcpState)
	ie14 := entities.NewUnsigned8InfoElement(entities.NewInfoElement("ingressNetworkPolicyRuleAction", 139, 1, registry.AntreaEnterpriseID, 1), ingressNetworkPolicyRuleAction)
	ie15 := entities.NewUnsigned8InfoElement(entities.NewInfoElement("egressNetworkPolicyRuleAction", 140, 1, registry.AntreaEnterpriseID, 1), egressNetworkPolicyRuleAction)
	ie16 := entities.NewSigned32InfoElement(entities.NewInfoElement("ingressNetworkPolicyRulePriority", 116, 7, registry.AntreaEnterpriseID, 4), ingressNetworkPolicyRulePriority)
	tmpElement, _ = registry.GetInfoElement("httpVals", registry.AntreaEnterpriseID)
	ie18 := entities.NewStringInfoElement(tmpElement, httpVals)

	elements = append(elements, ie1, ie2, ie3, ie4, ie5, ie6, ie7, ie8, ie9, ie10, ie11, ie12, ie13, ie14, ie15, ie16, ie17, ie18)
	// Add all elements in statsElements.
	for _, element := range statsElementList {
		var e *entities.InfoElement
		if !strings.Contains(element, "reverse") {
			e, _ = registry.GetInfoElement(element, registry.IANAEnterpriseID)
		} else {
			e, _ = registry.GetInfoElement(element, registry.IANAReversedEnterpriseID)
		}
		var ieWithValue entities.InfoElementWithValue
		switch element {
		case "packetTotalCount", "reversePacketTotalCount":
			if !isUpdatedRecord {
				ieWithValue = entities.NewUnsigned64InfoElement(e, uint64(502))
			} else {
				ieWithValue = entities.NewUnsigned64InfoElement(e, uint64(1005))
			}
		case "packetDeltaCount", "reversePacketDeltaCount":
			if !isUpdatedRecord {
				ieWithValue = entities.NewUnsigned64InfoElement(e, uint64(0))
			} else {
				ieWithValue = entities.NewUnsigned64InfoElement(e, uint64(503))
			}
		case "octetTotalCount", "reverseOctetTotalCount":
			if !isUpdatedRecord {
				ieWithValue = entities.NewUnsigned64InfoElement(e, uint64(1020))
			} else {
				ieWithValue = entities.NewUnsigned64InfoElement(e, uint64(2050))
			}
		}
		elements = append(elements, ieWithValue)
	}
	err := set.AddRecord(elements, 256)
	assert.NoError(t, err)

	message := entities.NewMessage(true)
	message.SetVersion(10)
	message.SetMessageLen(32)
	message.SetSequenceNum(1)
	message.SetObsDomainID(1234)
	message.SetExportTime(0)
	if isIPv6 {
		message.SetExportAddress("::1")
	} else {
		message.SetExportAddress("127.0.0.1")
	}
	message.AddSet(set)

	return message
}

func TestInitAggregationProcess(t *testing.T) {
	t.Run("no input channel", func(t *testing.T) {
		_, err := InitAggregationProcess(AggregationInput{
			WorkerNum:       2,
			CorrelateFields: fields,
		})
		assert.Error(t, err)
	})
	t.Run("both input channels", func(t *testing.T) {
		_, err := InitAggregationProcess(AggregationInput{
			MessageChan:     make(chan *entities.Message),
			RecordChan:      make(chan entities.Record),
			WorkerNum:       2,
			CorrelateFields: fields,
		})
		assert.Error(t, err)
	})
	t.Run("message input channel", func(t *testing.T) {
		aggregationProcess, err := InitAggregationProcess(AggregationInput{
			MessageChan:     make(chan *entities.Message),
			WorkerNum:       2,
			CorrelateFields: fields,
		})
		require.NoError(t, err)
		assert.Equal(t, 2, aggregationProcess.workerNum)
	})
	t.Run("record input channel", func(t *testing.T) {
		aggregationProcess, err := InitAggregationProcess(AggregationInput{
			RecordChan:      make(chan entities.Record),
			WorkerNum:       2,
			CorrelateFields: fields,
		})
		require.NoError(t, err)
		assert.Equal(t, 2, aggregationProcess.workerNum)
	})
}

func TestGetTupleRecordMap(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:     messageChan,
		WorkerNum:       2,
		CorrelateFields: fields,
	}
	aggregationProcess, _ := InitAggregationProcess(input)
	assert.Equal(t, aggregationProcess.flowKeyRecordMap, aggregationProcess.flowKeyRecordMap)
}

func TestAggregateMsgByFlowKey(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:           messageChan,
		WorkerNum:             2,
		CorrelateFields:       fields,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	aggregationProcess, _ := InitAggregationProcess(input)
	// Template records with IPv4 fields should be ignored
	message := createMsgwithTemplateSet(false)
	err := aggregationProcess.AggregateMsgByFlowKey(message)
	assert.NoError(t, err)
	assert.Empty(t, aggregationProcess.flowKeyRecordMap)
	assert.Empty(t, aggregationProcess.expirePriorityQueue.Len())
	// Data records should be processed and stored with corresponding flow key
	message = createDataMsgForSrc(t, false, false, false, false, false)
	err = aggregationProcess.AggregateMsgByFlowKey(message)
	assert.NoError(t, err)
	assert.NotZero(t, uint64(1), aggregationProcess.GetNumFlows())
	assert.NotZero(t, aggregationProcess.expirePriorityQueue.Len())
	flowKey := FlowKey{"10.0.0.1", "10.0.0.2", 6, 1234, 5678}
	aggRecord := aggregationProcess.flowKeyRecordMap[flowKey]
	assert.NotNil(t, aggregationProcess.flowKeyRecordMap[flowKey])
	item := aggregationProcess.expirePriorityQueue.Peek()
	assert.NotNil(t, item)
	ieWithValue, _, exist := aggRecord.Record.GetInfoElementWithValue("sourceIPv4Address")
	assert.Equal(t, true, exist)
	assert.Equal(t, net.IP{0xa, 0x0, 0x0, 0x1}, ieWithValue.GetIPAddressValue())
	assert.Equal(t, message.GetSet().GetRecords()[0], aggRecord.Record)

	// Template records with IPv6 fields should be ignored
	message = createMsgwithTemplateSet(true)
	err = aggregationProcess.AggregateMsgByFlowKey(message)
	assert.NoError(t, err)
	// It should have only data record with IPv4 fields that is added before.
	assert.Equal(t, int64(1), aggregationProcess.GetNumFlows())
	assert.Equal(t, 1, aggregationProcess.expirePriorityQueue.Len())
	// Data record with IPv6 addresses should be processed and stored correctly
	message = createDataMsgForSrc(t, true, false, false, false, false)
	err = aggregationProcess.AggregateMsgByFlowKey(message)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), aggregationProcess.GetNumFlows())
	assert.Equal(t, 2, aggregationProcess.expirePriorityQueue.Len())
	flowKey = FlowKey{"2001:0:3238:dfe1:63::fefb", "2001:0:3238:dfe1:63::fefc", 6, 1234, 5678}
	assert.NotNil(t, aggregationProcess.flowKeyRecordMap[flowKey])
	aggRecord = aggregationProcess.flowKeyRecordMap[flowKey]
	ieWithValue, _, exist = aggRecord.Record.GetInfoElementWithValue("sourceIPv6Address")
	assert.Equal(t, true, exist)
	assert.Equal(t, net.IP{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xdf, 0xe1, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xfe, 0xfb}, ieWithValue.GetIPAddressValue())
	assert.Equal(t, message.GetSet().GetRecords()[0], aggRecord.Record)

	// Test data record with invalid "flowEndSeconds" field
	element, _, exists := message.GetSet().GetRecords()[0].GetInfoElementWithValue("flowEndSeconds")
	assert.True(t, exists)
	element.ResetValue()
	err = aggregationProcess.AggregateMsgByFlowKey(message)
	assert.NoError(t, err)
}

func TestAggregationProcess(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:     messageChan,
		WorkerNum:       2,
		CorrelateFields: fields,
	}
	aggregationProcess, _ := InitAggregationProcess(input)
	dataMsg := createDataMsgForSrc(t, false, false, false, false, false)
	go func() {
		messageChan <- createMsgwithTemplateSet(false)
		time.Sleep(time.Second)
		messageChan <- dataMsg
		time.Sleep(time.Second)
		close(messageChan)
		aggregationProcess.Stop()
	}()
	// the Start() function is blocking until above goroutine with Stop() finishes
	// Proper usage of aggregation process is to have Start() in a goroutine with external channel
	aggregationProcess.Start()
	flowKey := FlowKey{
		"10.0.0.1", "10.0.0.2", 6, 1234, 5678,
	}
	aggRecord := aggregationProcess.flowKeyRecordMap[flowKey]
	assert.Equalf(t, aggRecord.Record, dataMsg.GetSet().GetRecords()[0], "records should be equal")
}

func BenchmarkAggregateMsgByFlowKey(b *testing.B) {
	bench := func(b *testing.B, isIPv6 bool) {
		messageChan := make(chan *entities.Message)
		input := AggregationInput{
			MessageChan:     messageChan,
			WorkerNum:       1, // not relevant for this benchmark (not calling Start)
			CorrelateFields: fields,
		}
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			ap, err := InitAggregationProcess(input)
			require.NoError(b, err)
			msg1 := createDataMsgForSrc(b, isIPv6, false, false, false, false)
			msg2 := createDataMsgForDst(b, isIPv6, false, false, false, false)
			b.StartTimer()
			require.NoError(b, ap.AggregateMsgByFlowKey(msg1))
			require.NoError(b, ap.AggregateMsgByFlowKey(msg2))
			assert.EqualValues(b, 1, ap.GetNumFlows())
		}
	}

	b.Run("ipv4", func(b *testing.B) { bench(b, false) })
	b.Run("ipv6", func(b *testing.B) { bench(b, true) })
}

func TestCorrelateRecordsForInterNodeFlow(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:           messageChan,
		WorkerNum:             2,
		CorrelateFields:       fields,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	clock := clocktesting.NewFakeClock(time.Now())
	ap, _ := initAggregationProcessWithClock(input, clock)
	// Test IPv4 fields.
	// Test the scenario, where record1 is added first and then record2.
	record1 := createDataMsgForSrc(t, false, false, false, false, false).GetSet().GetRecords()[0]
	record2 := createDataMsgForDst(t, false, false, false, false, false).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, clock, record1, record2, false, false, true)
	// Cleanup the flowKeyMap in aggregation process.
	flowKey1, _, _ := getFlowKeyFromRecord(record1)
	err := ap.deleteFlowKeyFromMap(*flowKey1)
	assert.NoError(t, err)
	heap.Pop(&ap.expirePriorityQueue)
	// Test the scenario, where record2 is added first and then record1.
	record1 = createDataMsgForSrc(t, false, false, false, false, false).GetSet().GetRecords()[0]
	record2 = createDataMsgForDst(t, false, false, false, false, false).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, clock, record2, record1, false, false, true)
	// Cleanup the flowKeyMap in aggregation process.
	err = ap.deleteFlowKeyFromMap(*flowKey1)
	assert.NoError(t, err)
	heap.Pop(&ap.expirePriorityQueue)
	// Test IPv6 fields.
	// Test the scenario, where record1 is added first and then record2.
	record1 = createDataMsgForSrc(t, true, false, false, false, false).GetSet().GetRecords()[0]
	record2 = createDataMsgForDst(t, true, false, false, false, false).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, clock, record1, record2, true, false, true)
	// Cleanup the flowKeyMap in aggregation process.
	flowKey1, _, _ = getFlowKeyFromRecord(record1)
	err = ap.deleteFlowKeyFromMap(*flowKey1)
	assert.NoError(t, err)
	heap.Pop(&ap.expirePriorityQueue)
	// Test the scenario, where record2 is added first and then record1.
	record1 = createDataMsgForSrc(t, true, false, false, false, false).GetSet().GetRecords()[0]
	record2 = createDataMsgForDst(t, true, false, false, false, false).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, clock, record2, record1, true, false, true)
}

func TestCorrelateRecordsForInterNodeDenyFlow(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:     messageChan,
		WorkerNum:       2,
		CorrelateFields: fields,
	}
	clock := clocktesting.NewFakeClock(time.Now())
	ap, _ := initAggregationProcessWithClock(input, clock)
	// Test the scenario, where src record has egress deny rule
	record1 := createDataMsgForSrc(t, false, false, false, false, true).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, clock, record1, nil, false, false, false)
	// Cleanup the flowKeyMap in aggregation process.
	flowKey1, _, _ := getFlowKeyFromRecord(record1)
	ap.deleteFlowKeyFromMap(*flowKey1)
	heap.Pop(&ap.expirePriorityQueue)
	// Test the scenario, where dst record has ingress reject rule
	record2 := createDataMsgForDst(t, false, false, false, true, false).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, clock, record2, nil, false, false, false)
	// Cleanup the flowKeyMap in aggregation process.
	ap.deleteFlowKeyFromMap(*flowKey1)
	heap.Pop(&ap.expirePriorityQueue)
	// Test the scenario, where dst record has ingress drop rule
	record1 = createDataMsgForSrc(t, false, false, false, false, false).GetSet().GetRecords()[0]
	record2 = createDataMsgForDst(t, false, false, false, false, true).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, clock, record1, record2, false, false, true)
	// Cleanup the flowKeyMap in aggregation process.
	ap.deleteFlowKeyFromMap(*flowKey1)

}

func TestCorrelateRecordsForIntraNodeFlow(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:           messageChan,
		WorkerNum:             2,
		CorrelateFields:       fields,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	clock := clocktesting.NewFakeClock(time.Now())
	ap, _ := initAggregationProcessWithClock(input, clock)
	// Test IPv4 fields.
	record1 := createDataMsgForSrc(t, false, true, false, false, false).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, clock, record1, nil, false, true, false)
	// Cleanup the flowKeyMap in aggregation process.
	flowKey1, _, _ := getFlowKeyFromRecord(record1)
	err := ap.deleteFlowKeyFromMap(*flowKey1)
	assert.NoError(t, err)
	heap.Pop(&ap.expirePriorityQueue)
	// Test IPv6 fields.
	record1 = createDataMsgForSrc(t, true, true, false, false, false).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, clock, record1, nil, true, true, false)
}

func TestCorrelateRecordsForToExternalFlow(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:           messageChan,
		WorkerNum:             2,
		CorrelateFields:       fields,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	clock := clocktesting.NewFakeClock(time.Now())
	ap, _ := initAggregationProcessWithClock(input, clock)
	// Test IPv4 fields.
	record1 := createDataMsgForSrc(t, false, true, false, true, false).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, clock, record1, nil, false, true, false)
	// Cleanup the flowKeyMap in aggregation process.
	flowKey1, _, _ := getFlowKeyFromRecord(record1)
	err := ap.deleteFlowKeyFromMap(*flowKey1)
	assert.NoError(t, err)
	heap.Pop(&ap.expirePriorityQueue)
	// Test IPv6 fields.
	record1 = createDataMsgForSrc(t, true, true, false, true, false).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, clock, record1, nil, true, true, false)
}

func TestAggregateRecordsForInterNodeFlow(t *testing.T) {
	messageChan := make(chan *entities.Message)
	aggElements := &AggregationElements{
		NonStatsElements:                   nonStatsElementList,
		StatsElements:                      statsElementList,
		AggregatedSourceStatsElements:      antreaSourceStatsElementList,
		AggregatedDestinationStatsElements: antreaDestinationStatsElementList,
		AntreaFlowEndSecondsElements:       antreaFlowEndSecondsElementList,
		ThroughputElements:                 antreaThroughputElementList,
		SourceThroughputElements:           antreaSourceThroughputElementList,
		DestinationThroughputElements:      antreaDestinationThroughputElementList,
	}
	input := AggregationInput{
		MessageChan:           messageChan,
		WorkerNum:             2,
		CorrelateFields:       fields,
		AggregateElements:     aggElements,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	clock := clocktesting.NewFakeClock(time.Now())
	ap, _ := initAggregationProcessWithClock(input, clock)

	// Test the scenario (added in order): srcRecord, dstRecord, record1_updated, record2_updated
	srcRecord := createDataMsgForSrc(t, false, false, false, false, false).GetSet().GetRecords()[0]
	dstRecord := createDataMsgForDst(t, false, false, false, false, false).GetSet().GetRecords()[0]
	latestSrcRecord := createDataMsgForSrc(t, false, false, true, false, false).GetSet().GetRecords()[0]
	latestDstRecord := createDataMsgForDst(t, false, false, true, false, false).GetSet().GetRecords()[0]
	runAggregationAndCheckResult(t, ap, clock, srcRecord, dstRecord, latestSrcRecord, latestDstRecord, false)
}

func TestDeleteFlowKeyFromMapWithLock(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:     messageChan,
		WorkerNum:       2,
		CorrelateFields: fields,
	}
	aggregationProcess, _ := InitAggregationProcess(input)
	message := createDataMsgForSrc(t, false, false, false, false, false)
	flowKey1 := FlowKey{"10.0.0.1", "10.0.0.2", 6, 1234, 5678}
	flowKey2 := FlowKey{"2001:0:3238:dfe1:63::fefb", "2001:0:3238:dfe1:63::fefc", 6, 1234, 5678}
	aggFlowRecord := &AggregationFlowRecord{
		Record:                    message.GetSet().GetRecords()[0],
		PriorityQueueItem:         &ItemToExpire{},
		ReadyToSend:               true,
		waitForReadyToSendRetries: 0,
		areCorrelatedFieldsFilled: false,
		areExternalFieldsFilled:   false,
	}
	aggregationProcess.flowKeyRecordMap[flowKey1] = aggFlowRecord
	assert.Equal(t, int64(1), aggregationProcess.GetNumFlows())
	err := aggregationProcess.deleteFlowKeyFromMap(flowKey2)
	assert.Error(t, err)
	assert.Equal(t, int64(1), aggregationProcess.GetNumFlows())
	err = aggregationProcess.deleteFlowKeyFromMap(flowKey1)
	assert.NoError(t, err)
	assert.Empty(t, aggregationProcess.flowKeyRecordMap)
}

func TestGetExpiryFromExpirePriorityQueue(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:           messageChan,
		WorkerNum:             2,
		CorrelateFields:       fields,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	ap, _ := InitAggregationProcess(input)
	// Add records with IPv4 fields.
	recordIPv4Src := createDataMsgForSrc(t, false, false, false, false, false).GetSet().GetRecords()[0]
	recordIPv4Dst := createDataMsgForDst(t, false, false, false, false, false).GetSet().GetRecords()[0]
	// Add records with IPv6 fields.
	recordIPv6Src := createDataMsgForSrc(t, true, false, false, false, false).GetSet().GetRecords()[0]
	recordIPv6Dst := createDataMsgForDst(t, true, false, false, false, false).GetSet().GetRecords()[0]
	testCases := []struct {
		name    string
		records []entities.Record
	}{
		{
			"empty queue",
			nil,
		},
		{
			"One aggregation record",
			[]entities.Record{recordIPv4Src, recordIPv4Dst},
		},
		{
			"Two aggregation records",
			[]entities.Record{recordIPv4Src, recordIPv4Dst, recordIPv6Src, recordIPv6Dst},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, record := range tc.records {
				flowKey, isIPv4, _ := getFlowKeyFromRecord(record)
				err := ap.addOrUpdateRecordInMap(flowKey, record, isIPv4)
				assert.NoError(t, err)
			}
			expiryTime := ap.GetExpiryFromExpirePriorityQueue()
			assert.LessOrEqualf(t, expiryTime.Nanoseconds(), testActiveExpiry.Nanoseconds(), "incorrect expiry time")
		})
	}
}

func assertElementMap(t *testing.T, record map[string]interface{}, ipv6 bool) {
	if ipv6 {
		assert.Equal(t, net.ParseIP("2001:0:3238:dfe1:63::fefb"), record["sourceIPv6Address"])
		assert.Equal(t, net.ParseIP("2001:0:3238:dfe1:63::fefc"), record["destinationIPv6Address"])
		assert.Equal(t, net.ParseIP("2001:0:3238:bbbb:63::aaaa"), record["destinationClusterIPv6"])
	} else {
		assert.Equal(t, net.ParseIP("10.0.0.1").To4(), record["sourceIPv4Address"])
		assert.Equal(t, net.ParseIP("10.0.0.2").To4(), record["destinationIPv4Address"])
		assert.Equal(t, net.ParseIP("192.168.0.1").To4(), record["destinationClusterIPv4"])
	}
	assert.Equal(t, uint16(1234), record["sourceTransportPort"])
	assert.Equal(t, uint16(5678), record["destinationTransportPort"])
	assert.Equal(t, uint8(6), record["protocolIdentifier"])
	assert.Equal(t, "pod1", record["sourcePodName"])
	assert.Equal(t, "pod2", record["destinationPodName"])
	assert.Equal(t, uint16(4739), record["destinationServicePort"])
	assert.Equal(t, uint32(0), record["flowStartSeconds"])
	assert.Equal(t, uint32(1), record["flowEndSeconds"])
	assert.Equal(t, uint32(1), record["flowEndSecondsFromSourceNode"])
	assert.Equal(t, uint32(1), record["flowEndSecondsFromDestinationNode"])
	assert.Equal(t, uint8(2), record["flowType"])
	assert.Equal(t, uint8(2), record["flowEndReason"])
	assert.Equal(t, "ESTABLISHED", record["tcpState"])
	assert.Equal(t, uint8(0), record["ingressNetworkPolicyRuleAction"])
	assert.Equal(t, uint8(0), record["egressNetworkPolicyRuleAction"])
	assert.Equal(t, int32(50000), record["ingressNetworkPolicyRulePriority"])
	assert.Equal(t, uint64(502), record["packetTotalCount"])
	assert.Equal(t, uint64(502), record["reversePacketTotalCount"])
	assert.Equal(t, uint64(1020), record["octetTotalCount"])
	assert.Equal(t, uint64(1020), record["reverseOctetTotalCount"])
	assert.Equal(t, uint64(1020*8), record["throughput"])
	assert.Equal(t, uint64(1020*8), record["reverseThroughput"])
	assert.Equal(t, uint64(1000*8), record["throughputFromSourceNode"])
	assert.Equal(t, uint64(1000*8), record["reverseThroughputFromSourceNode"])
	assert.Equal(t, uint64(1020*8), record["throughputFromDestinationNode"])
	assert.Equal(t, uint64(1020*8), record["reverseThroughputFromDestinationNode"])
	assert.Equal(t, uint64(0), record["packetDeltaCount"])
	assert.Equal(t, uint64(502), record["reversePacketTotalCount"])
	assert.Equal(t, uint64(0), record["reversePacketDeltaCount"])
	assert.Equal(t, "{\"0\":\"{hostname:10.10.0.1,url:/public/,http_user_agent:curl/7.74.0,http_content_type:text/html,http_method:GET,protocol:HTTP/1.1,status:200,length:153}\"}", record["httpVals"])
}

func TestGetRecords(t *testing.T) {
	messageChan := make(chan *entities.Message)
	aggElements := &AggregationElements{
		NonStatsElements:                   nonStatsElementList,
		StatsElements:                      statsElementList,
		AggregatedSourceStatsElements:      antreaSourceStatsElementList,
		AggregatedDestinationStatsElements: antreaDestinationStatsElementList,
		AntreaFlowEndSecondsElements:       antreaFlowEndSecondsElementList,
		ThroughputElements:                 antreaThroughputElementList,
		SourceThroughputElements:           antreaSourceThroughputElementList,
		DestinationThroughputElements:      antreaDestinationThroughputElementList,
	}
	input := AggregationInput{
		MessageChan:           messageChan,
		WorkerNum:             2,
		CorrelateFields:       fields,
		AggregateElements:     aggElements,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	ap, _ := InitAggregationProcess(input)

	// Add records with IPv4 fields.
	recordIPv4Src := createDataMsgForSrc(t, false, false, false, false, false).GetSet().GetRecords()[0]
	recordIPv4Dst := createDataMsgForDst(t, false, false, false, false, false).GetSet().GetRecords()[0]
	// Add records with IPv6 fields.
	recordIPv6Src := createDataMsgForSrc(t, true, false, false, false, false).GetSet().GetRecords()[0]
	recordIPv6Dst := createDataMsgForDst(t, true, false, false, false, false).GetSet().GetRecords()[0]

	records := []entities.Record{recordIPv4Src, recordIPv4Dst, recordIPv6Src, recordIPv6Dst}
	for _, record := range records {
		flowKey, isIPv4, _ := getFlowKeyFromRecord(record)
		err := ap.addOrUpdateRecordInMap(flowKey, record, isIPv4)
		assert.NoError(t, err)
	}

	flowKeyIPv4, _, _ := getFlowKeyFromRecord(recordIPv4Src)
	partialFlowKeyIPv6 := &FlowKey{
		SourceAddress: "2001:0:3238:dfe1:63::fefb",
	}
	testCases := []struct {
		name        string
		flowKey     *FlowKey
		expectedLen int
	}{
		{
			"Empty flowkey",
			nil,
			2,
		},
		{
			"IPv4 flowkey",
			flowKeyIPv4,
			1,
		},
		{
			"IPv6 flowkey",
			partialFlowKeyIPv6,
			1,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			records := ap.GetRecords(tc.flowKey)
			assert.Equalf(t, tc.expectedLen, len(records), "%s: Number of records string is incorrect, expected %d got %d", tc.name, tc.expectedLen, len(records))
			if tc.flowKey != nil {
				assertElementMap(t, records[0], tc.name == "IPv6 flowkey")
			} else {
				if _, ok := records[0]["sourceIPv6Address"]; ok {
					assertElementMap(t, records[0], true)
					assertElementMap(t, records[1], false)
				} else {
					assertElementMap(t, records[0], false)
					assertElementMap(t, records[1], true)
				}
			}
		})
	}
}

func TestForAllExpiredFlowRecordsDo(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:           messageChan,
		WorkerNum:             2,
		CorrelateFields:       fields,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	ap, _ := InitAggregationProcess(input)
	// Add records with IPv4 fields.
	recordIPv4Src := createDataMsgForSrc(t, false, false, false, false, false).GetSet().GetRecords()[0]
	recordIPv4Dst := createDataMsgForDst(t, false, false, false, false, false).GetSet().GetRecords()[0]
	// Add records with IPv6 fields.
	recordIPv6Src := createDataMsgForSrc(t, true, false, false, false, false).GetSet().GetRecords()[0]
	recordIPv6Dst := createDataMsgForDst(t, true, false, false, false, false).GetSet().GetRecords()[0]
	numExecutions := 0
	testCallback := func(key FlowKey, record *AggregationFlowRecord) error {
		numExecutions = numExecutions + 1
		return nil
	}

	testCases := []struct {
		name               string
		records            []entities.Record
		expectedExecutions int
		expectedPQLen      int
	}{
		{
			"empty queue",
			nil,
			0,
			0,
		},
		{
			"One aggregation record and none expired",
			[]entities.Record{recordIPv4Src, recordIPv4Dst},
			0,
			1,
		},
		{
			"One aggregation record and one expired",
			[]entities.Record{recordIPv4Src, recordIPv4Dst},
			1,
			1,
		},
		{
			"Two aggregation records and one expired",
			[]entities.Record{recordIPv4Src, recordIPv4Dst, recordIPv6Src, recordIPv6Dst},
			1,
			2,
		},
		{
			"Two aggregation records and two expired",
			[]entities.Record{recordIPv4Src, recordIPv4Dst, recordIPv6Src, recordIPv6Dst},
			2,
			0,
		},
		{
			"One aggregation record and waitForReadyToSendRetries reach maximum",
			[]entities.Record{recordIPv4Src},
			0,
			0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			numExecutions = 0
			for _, record := range tc.records {
				flowKey, isIPv4, _ := getFlowKeyFromRecord(record)
				err := ap.addOrUpdateRecordInMap(flowKey, record, isIPv4)
				assert.NoError(t, err)
			}
			switch tc.name {
			case "One aggregation record and one expired":
				time.Sleep(testActiveExpiry)
				err := ap.ForAllExpiredFlowRecordsDo(testCallback)
				assert.NoError(t, err)
			case "Two aggregation records and one expired":
				time.Sleep(testActiveExpiry)
				secondAggRec := ap.expirePriorityQueue[1]
				ap.expirePriorityQueue.Update(secondAggRec, secondAggRec.flowKey,
					secondAggRec.flowRecord, secondAggRec.activeExpireTime.Add(testActiveExpiry), secondAggRec.inactiveExpireTime.Add(testInactiveExpiry))
				err := ap.ForAllExpiredFlowRecordsDo(testCallback)
				assert.NoError(t, err)
			case "Two aggregation records and two expired":
				time.Sleep(2 * testActiveExpiry)
				err := ap.ForAllExpiredFlowRecordsDo(testCallback)
				assert.NoError(t, err)
			case "One aggregation record and waitForReadyToSendRetries reach maximum":
				for i := 0; i < testMaxRetries; i++ {
					time.Sleep(testActiveExpiry)
					err := ap.ForAllExpiredFlowRecordsDo(testCallback)
					assert.NoError(t, err)
				}
			default:
				break
			}
			assert.Equalf(t, tc.expectedExecutions, numExecutions, "number of callback executions are incorrect")
			assert.Equalf(t, tc.expectedPQLen, ap.expirePriorityQueue.Len(), "expected pq length not correct")
		})
	}
}

func runCorrelationAndCheckResult(t *testing.T, ap *aggregationProcess, clock *clocktesting.FakeClock, record1, record2 entities.Record, isIPv6, isIntraNode, needsCorrelation bool) {
	flowKey1, isIPv4, _ := getFlowKeyFromRecord(record1)
	err := ap.addOrUpdateRecordInMap(flowKey1, record1, isIPv4)
	assert.NoError(t, err)
	item := ap.expirePriorityQueue.Peek()
	oldActiveExpiryTime := item.activeExpireTime
	oldInactiveExpiryTime := item.inactiveExpireTime
	if !isIntraNode && needsCorrelation {
		clock.Step(10 * time.Millisecond)
		flowKey2, isIPv4, _ := getFlowKeyFromRecord(record2)
		assert.Equalf(t, *flowKey1, *flowKey2, "flow keys should be equal.")
		err = ap.addOrUpdateRecordInMap(flowKey2, record2, isIPv4)
		assert.NoError(t, err)
	}
	assert.Equal(t, int64(1), ap.GetNumFlows())
	assert.Equal(t, 1, ap.expirePriorityQueue.Len())
	aggRecord := ap.flowKeyRecordMap[*flowKey1]
	item = ap.expirePriorityQueue.Peek()
	assert.Equal(t, *aggRecord, *item.flowRecord)
	assert.Equal(t, oldActiveExpiryTime, item.activeExpireTime)
	if !isIntraNode && needsCorrelation {
		assert.Equal(t, oldInactiveExpiryTime.Add(10*time.Millisecond), item.inactiveExpireTime)
		assert.True(t, ap.AreCorrelatedFieldsFilled(*aggRecord))
	}
	if !isIntraNode && !needsCorrelation {
		// for inter-Node deny connections, either src or dst Pod info will be resolved.
		sourcePodName, _, _ := aggRecord.Record.GetInfoElementWithValue("sourcePodName")
		destinationPodName, _, _ := aggRecord.Record.GetInfoElementWithValue("destinationPodName")
		assert.True(t, sourcePodName.GetStringValue() == "" || destinationPodName.GetStringValue() == "")
		egress, _, _ := aggRecord.Record.GetInfoElementWithValue("egressNetworkPolicyRuleAction")
		ingress, _, _ := aggRecord.Record.GetInfoElementWithValue("ingressNetworkPolicyRuleAction")
		assert.True(t, egress.GetUnsigned8Value() != 0 || ingress.GetUnsigned8Value() != 0)
		assert.False(t, ap.AreCorrelatedFieldsFilled(*aggRecord))
	} else {
		ieWithValue, _, _ := aggRecord.Record.GetInfoElementWithValue("sourcePodName")
		assert.Equal(t, "pod1", ieWithValue.GetStringValue())
		ieWithValue, _, _ = aggRecord.Record.GetInfoElementWithValue("destinationPodName")
		assert.Equal(t, "pod2", ieWithValue.GetStringValue())
		if !isIPv6 {
			ieWithValue, _, _ = aggRecord.Record.GetInfoElementWithValue("destinationClusterIPv4")
			assert.Equal(t, net.ParseIP("192.168.0.1").To4(), ieWithValue.GetIPAddressValue())
		} else {
			ieWithValue, _, _ = aggRecord.Record.GetInfoElementWithValue("destinationClusterIPv6")
			assert.Equal(t, net.ParseIP("2001:0:3238:BBBB:63::AAAA"), ieWithValue.GetIPAddressValue())
		}
		ieWithValue, _, _ = aggRecord.Record.GetInfoElementWithValue("destinationServicePort")
		assert.Equal(t, uint16(4739), ieWithValue.GetUnsigned16Value())
		ingressPriority, _, _ := aggRecord.Record.GetInfoElementWithValue("ingressNetworkPolicyRulePriority")
		assert.Equal(t, ingressPriority.GetSigned32Value(), int32(50000))
		assert.True(t, ap.AreCorrelatedFieldsFilled(*aggRecord))
	}
}

func runAggregationAndCheckResult(t *testing.T, ap *aggregationProcess, clock *clocktesting.FakeClock, srcRecord, dstRecord, srcRecordLatest, dstRecordLatest entities.Record, isIntraNode bool) {
	flowKey, isIPv4, _ := getFlowKeyFromRecord(srcRecord)
	addOrUpdateRecordInMap := func(record entities.Record) error {
		err := ap.addOrUpdateRecordInMap(flowKey, record, isIPv4)
		clock.Step(10 * time.Millisecond)
		return err
	}

	assert.NoError(t, addOrUpdateRecordInMap(srcRecord))
	item := ap.expirePriorityQueue.Peek()
	oldActiveExpiryTime := item.activeExpireTime
	oldInactiveExpiryTime := item.inactiveExpireTime

	if !isIntraNode {
		assert.NoError(t, addOrUpdateRecordInMap(dstRecord))
	}
	assert.NoError(t, addOrUpdateRecordInMap(srcRecordLatest))
	if !isIntraNode {
		assert.NoError(t, addOrUpdateRecordInMap(dstRecordLatest))
	}
	assert.Equal(t, int64(1), ap.GetNumFlows())
	assert.Equal(t, 1, ap.expirePriorityQueue.Len())
	aggRecord := ap.flowKeyRecordMap[*flowKey]
	item = ap.expirePriorityQueue.Peek()
	assert.Equal(t, *aggRecord, *item.flowRecord)
	assert.Equal(t, oldActiveExpiryTime, item.activeExpireTime)
	if !isIntraNode {
		assert.NotEqual(t, oldInactiveExpiryTime, item.inactiveExpireTime)
	}
	ieWithValue, _, _ := aggRecord.Record.GetInfoElementWithValue("sourcePodName")
	assert.Equal(t, "pod1", ieWithValue.GetStringValue())
	ieWithValue, _, _ = aggRecord.Record.GetInfoElementWithValue("destinationPodName")
	assert.Equal(t, "pod2", ieWithValue.GetStringValue())
	ieWithValue, _, _ = aggRecord.Record.GetInfoElementWithValue("destinationClusterIPv4")
	assert.Equal(t, net.ParseIP("192.168.0.1").To4(), ieWithValue.GetIPAddressValue())
	ieWithValue, _, _ = aggRecord.Record.GetInfoElementWithValue("destinationServicePort")
	assert.Equal(t, uint16(4739), ieWithValue.GetUnsigned16Value())
	ieWithValue, _, _ = aggRecord.Record.GetInfoElementWithValue("ingressNetworkPolicyRuleAction")
	assert.Equal(t, registry.NetworkPolicyRuleActionNoAction, ieWithValue.GetUnsigned8Value())
	for _, e := range nonStatsElementList {
		ieWithValue, _, _ = aggRecord.Record.GetInfoElementWithValue(e)
		expectedIE, _, _ := dstRecordLatest.GetInfoElementWithValue(e)
		switch ieWithValue.GetDataType() {
		case entities.Unsigned8:
			assert.Equal(t, ieWithValue.GetUnsigned8Value(), expectedIE.GetUnsigned8Value())
		case entities.String:
			assert.Equal(t, ieWithValue.GetStringValue(), expectedIE.GetStringValue())
		case entities.Signed32:
			assert.Equal(t, ieWithValue.GetSigned32Value(), expectedIE.GetSigned32Value())
		}
	}
	for _, e := range statsElementList {
		ieWithValue, _, _ = aggRecord.Record.GetInfoElementWithValue(e)
		aggVal := ieWithValue.GetUnsigned64Value()
		latestRecord, _, _ := dstRecordLatest.GetInfoElementWithValue(e)
		latestVal := latestRecord.GetUnsigned64Value()
		if !strings.Contains(e, "Delta") {
			assert.Equalf(t, latestVal, aggVal, "values should be equal for element %v", e)
		} else {
			assert.Equalf(t, latestVal, aggVal, "values should be equal for element %v", e)
		}
	}
	for i, e := range antreaSourceStatsElementList {
		ieWithValue, _, _ = aggRecord.Record.GetInfoElementWithValue(e)
		latestRecord, _, _ := srcRecordLatest.GetInfoElementWithValue(statsElementList[i])
		assert.Equalf(t, latestRecord.GetUnsigned64Value(), ieWithValue.GetUnsigned64Value(), "values should be equal for element %v", e)
	}
	for i, e := range antreaDestinationStatsElementList {
		ieWithValue, _, _ = aggRecord.Record.GetInfoElementWithValue(e)
		latestRecord, _, _ := dstRecordLatest.GetInfoElementWithValue(statsElementList[i])
		assert.Equalf(t, latestRecord.GetUnsigned64Value(), ieWithValue.GetUnsigned64Value(), "values should be equal for element %v", e)
	}
	for _, e := range antreaThroughputElementList {
		ieWithValue, _, _ = aggRecord.Record.GetInfoElementWithValue(e)
		expectedVal := 915
		assert.Equalf(t, uint64(expectedVal), ieWithValue.GetUnsigned64Value(), "values should be equal for element %v", e)
	}
	for _, e := range antreaSourceThroughputElementList {
		ieWithValue, _, _ = aggRecord.Record.GetInfoElementWithValue(e)
		expectedVal := 888
		assert.Equalf(t, uint64(expectedVal), ieWithValue.GetUnsigned64Value(), "values should be equal for element %v", e)
	}
	for _, e := range antreaDestinationThroughputElementList {
		ieWithValue, _, _ = aggRecord.Record.GetInfoElementWithValue(e)
		expectedVal := 915
		assert.Equalf(t, uint64(expectedVal), ieWithValue.GetUnsigned64Value(), "values should be equal for element %v", e)
	}
}

func TestFillHttpVals(t *testing.T) {
	testCases := []struct {
		name             string
		incomingHttpVals string
		existingHttpVals string
		updatedHttpVals  string
	}{
		{
			name:             "Normal case",
			incomingHttpVals: "{\"1\":\"{hostname:10.10.0.1,url:/public/,http_user_agent:curl/7.74.0,http_content_type:text/html,http_method:GET,protocol:HTTP/1.1,status:200,length:153}\"}",
			existingHttpVals: "{\"0\":\"{hostname:10.10.0.1,url:/public/,http_user_agent:curl/7.74.0,http_content_type:text/html,http_method:GET,protocol:HTTP/1.1,status:200,length:153}\"}",
			updatedHttpVals:  "{\"0\":\"{hostname:10.10.0.1,url:/public/,http_user_agent:curl/7.74.0,http_content_type:text/html,http_method:GET,protocol:HTTP/1.1,status:200,length:153}\",\"1\":\"{hostname:10.10.0.1,url:/public/,http_user_agent:curl/7.74.0,http_content_type:text/html,http_method:GET,protocol:HTTP/1.1,status:200,length:153}\"}",
		}, {
			name:             "Existing httpVals empty",
			incomingHttpVals: "{\"1\":\"{hostname:10.10.0.1,url:/public/,http_user_agent:curl/7.74.0,http_content_type:text/html,http_method:GET,protocol:HTTP/1.1,status:200,length:153}\"}",
			existingHttpVals: "",
			updatedHttpVals:  "{\"1\":\"{hostname:10.10.0.1,url:/public/,http_user_agent:curl/7.74.0,http_content_type:text/html,http_method:GET,protocol:HTTP/1.1,status:200,length:153}\"}",
		}, {
			name:             "Overlapping httpVals",
			incomingHttpVals: "{\"1\":\"{hostname:10.10.0.1,url:/public/,http_user_agent:curl/7.74.0,http_content_type:text/html,http_method:GET,protocol:HTTP/1.1,status:200,length:153}\"}",
			existingHttpVals: "{\"1\":\"{hostname:10.10.0.1,url:/public/,http_user_agent:curl/7.74.0,http_content_type:text/html,http_method:GET,protocol:HTTP/1.1,status:200,length:153}\"}",
			updatedHttpVals:  "{\"1\":\"{hostname:10.10.0.1,url:/public/,http_user_agent:curl/7.74.0,http_content_type:text/html,http_method:GET,protocol:HTTP/1.1,status:200,length:153}\"}",
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			retVals, _ := fillHttpVals(tt.incomingHttpVals, tt.existingHttpVals)
			assert.Equal(t, tt.updatedHttpVals, retVals)
		})
	}
}
