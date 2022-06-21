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

package clickhouseclient

import (
	"database/sql/driver"
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gammazero/deque"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixentitiestesting "github.com/vmware/go-ipfix/pkg/entities/testing"
	"github.com/vmware/go-ipfix/pkg/registry"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
)

func init() {
	registry.LoadRegistry()
}

func TestGetDataSourceName(t *testing.T) {
	chInput := ClickHouseInput{
		Username:       "username",
		Password:       "password",
		Database:       "default",
		DatabaseURL:    "tcp://click-house-svc:9000",
		Debug:          true,
		Compress:       new(bool),
		CommitInterval: 1 * time.Second,
	}
	*chInput.Compress = true
	dsn := "tcp://click-house-svc:9000?username=username&password=password&database=default&debug=true&compress=true"

	chInputInvalid := ClickHouseInput{}

	testcases := []struct {
		input       ClickHouseInput
		expectedDSN string
		expectedErr bool
	}{
		{chInput, dsn, false},
		{chInputInvalid, "", true},
	}

	for _, tc := range testcases {
		dsn, err := tc.input.getDataSourceName()
		if tc.expectedErr && err == nil {
			t.Errorf("ClickHouseInput %v unexpectedly returns no error when getting DSN", tc.input)
		}
		assert.Equal(t, tc.expectedDSN, dsn)
	}
}

func TestGetClickHouseFlowRow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testcases := []struct {
		isIPv4 bool
	}{
		{true},
		{false},
	}

	for _, tc := range testcases {
		mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)
		prepareMockRecord(mockRecord, tc.isIPv4)

		chClient := &ClickHouseExportProcess{}
		flowRow := chClient.getClickHouseFlowRow(mockRecord)
		assert.Equal(t, time.Unix(int64(1637706961), 0), flowRow.flowStartSeconds)
		assert.Equal(t, time.Unix(int64(1637706973), 0), flowRow.flowEndSeconds)
		assert.Equal(t, time.Unix(int64(1637706974), 0), flowRow.flowEndSecondsFromSourceNode)
		assert.Equal(t, time.Unix(int64(1637706975), 0), flowRow.flowEndSecondsFromDestinationNode)
		assert.Equal(t, uint8(3), flowRow.flowEndReason)
		assert.Equal(t, uint16(44752), flowRow.sourceTransportPort)
		assert.Equal(t, uint16(5201), flowRow.destinationTransportPort)
		assert.Equal(t, uint8(6), flowRow.protocolIdentifier)
		assert.Equal(t, uint64(823188), flowRow.packetTotalCount)
		assert.Equal(t, uint64(30472817041), flowRow.octetTotalCount)
		assert.Equal(t, uint64(241333), flowRow.packetDeltaCount)
		assert.Equal(t, uint64(8982624938), flowRow.octetDeltaCount)
		assert.Equal(t, uint64(471111), flowRow.reversePacketTotalCount)
		assert.Equal(t, uint64(24500996), flowRow.reverseOctetTotalCount)
		assert.Equal(t, uint64(136211), flowRow.reversePacketDeltaCount)
		assert.Equal(t, uint64(7083284), flowRow.reverseOctetDeltaCount)
		assert.Equal(t, "perftest-a", flowRow.sourcePodName)
		assert.Equal(t, "antrea-test", flowRow.sourcePodNamespace)
		assert.Equal(t, "k8s-node-control-plane", flowRow.sourceNodeName)
		assert.Equal(t, "perftest-b", flowRow.destinationPodName)
		assert.Equal(t, "antrea-test-b", flowRow.destinationPodNamespace)
		assert.Equal(t, "k8s-node-control-plane-b", flowRow.destinationNodeName)
		assert.Equal(t, uint16(5202), flowRow.destinationServicePort)
		assert.Equal(t, "perftest", flowRow.destinationServicePortName)
		assert.Equal(t, "test-flow-aggregator-networkpolicy-ingress-allow", flowRow.ingressNetworkPolicyName)
		assert.Equal(t, "antrea-test-ns", flowRow.ingressNetworkPolicyNamespace)
		assert.Equal(t, "test-flow-aggregator-networkpolicy-rule", flowRow.ingressNetworkPolicyRuleName)
		assert.Equal(t, uint8(1), flowRow.ingressNetworkPolicyType)
		assert.Equal(t, uint8(2), flowRow.ingressNetworkPolicyRuleAction)
		assert.Equal(t, "test-flow-aggregator-networkpolicy-egress-allow", flowRow.egressNetworkPolicyName)
		assert.Equal(t, "antrea-test-ns-e", flowRow.egressNetworkPolicyNamespace)
		assert.Equal(t, "test-flow-aggregator-networkpolicy-rule-e", flowRow.egressNetworkPolicyRuleName)
		assert.Equal(t, uint8(4), flowRow.egressNetworkPolicyType)
		assert.Equal(t, uint8(5), flowRow.egressNetworkPolicyRuleAction)
		assert.Equal(t, "TIME_WAIT", flowRow.tcpState)
		assert.Equal(t, uint8(11), flowRow.flowType)
		assert.Equal(t, "{\"antrea-e2e\":\"perftest-a\",\"app\":\"perftool\"}", flowRow.sourcePodLabels)
		assert.Equal(t, "{\"antrea-e2e\":\"perftest-b\",\"app\":\"perftool\"}", flowRow.destinationPodLabels)
		assert.Equal(t, uint64(15902813472), flowRow.throughput)
		assert.Equal(t, uint64(12381344), flowRow.reverseThroughput)
		assert.Equal(t, uint64(15902813473), flowRow.throughputFromSourceNode)
		assert.Equal(t, uint64(15902813474), flowRow.throughputFromDestinationNode)
		assert.Equal(t, uint64(12381345), flowRow.reverseThroughputFromSourceNode)
		assert.Equal(t, uint64(12381346), flowRow.reverseThroughputFromDestinationNode)

		if tc.isIPv4 {
			assert.Equal(t, "10.10.0.79", flowRow.sourceIP)
			assert.Equal(t, "10.10.0.80", flowRow.destinationIP)
			assert.Equal(t, "10.10.1.10", flowRow.destinationClusterIP)
		} else {
			assert.Equal(t, "2001:0:3238:dfe1:63::fefb", flowRow.sourceIP)
			assert.Equal(t, "2001:0:3238:dfe1:63::fefc", flowRow.destinationIP)
			assert.Equal(t, "2001:0:3238:dfe1:64::a", flowRow.destinationClusterIP)
		}
	}
}

func createElement(name string, enterpriseID uint32) ipfixentities.InfoElementWithValue {
	element, _ := ipfixregistry.GetInfoElement(name, enterpriseID)
	ieWithValue, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
	return ieWithValue
}

func prepareMockRecord(mockRecord *ipfixentitiestesting.MockRecord, isIPv4 bool) {
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
	sourcePodLabelsElem.SetStringValue("{\"antrea-e2e\":\"perftest-a\",\"app\":\"perftool\"}")
	mockRecord.EXPECT().GetInfoElementWithValue("sourcePodLabels").Return(sourcePodLabelsElem, 0, true)

	destinationPodLabelsElem := createElement("destinationPodLabels", ipfixregistry.AntreaEnterpriseID)
	destinationPodLabelsElem.SetStringValue("{\"antrea-e2e\":\"perftest-b\",\"app\":\"perftool\"}")
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

func TestCacheSet(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	chExportProc := ClickHouseExportProcess{
		deque: deque.New(),
		mutex: sync.RWMutex{},
	}

	chExportProc.queueSize = 1
	// First call. only populate row.
	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)
	prepareMockRecord(mockRecord, true)
	mockSet := ipfixentitiestesting.NewMockSet(ctrl)
	mockSet.EXPECT().GetRecords().Return([]ipfixentities.Record{mockRecord}).AnyTimes()
	chExportProc.CacheSet(mockSet)
	assert.Equal(t, 1, chExportProc.deque.Len())
	assert.Equal(t, "10.10.0.79", chExportProc.deque.At(0).(*ClickHouseFlowRow).sourceIP)

	// Second call. discard prev row and add new row.
	mockRecord = ipfixentitiestesting.NewMockRecord(ctrl)
	prepareMockRecord(mockRecord, false)
	mockSet = ipfixentitiestesting.NewMockSet(ctrl)
	mockSet.EXPECT().GetRecords().Return([]ipfixentities.Record{mockRecord}).AnyTimes()
	chExportProc.CacheSet(mockSet)
	assert.Equal(t, 1, chExportProc.deque.Len())
	assert.Equal(t, "2001:0:3238:dfe1:63::fefb", chExportProc.deque.At(0).(*ClickHouseFlowRow).sourceIP)
}

func TestBatchCommitAll(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	chExportProc := ClickHouseExportProcess{
		db:    db,
		deque: deque.New(),
		mutex: sync.RWMutex{},
	}

	recordRow := ClickHouseFlowRow{
		flowStartSeconds:                     time.Unix(int64(1637706961), 0),
		flowEndSeconds:                       time.Unix(int64(1637706973), 0),
		flowEndSecondsFromSourceNode:         time.Unix(int64(1637706974), 0),
		flowEndSecondsFromDestinationNode:    time.Unix(int64(1637706975), 0),
		flowEndReason:                        3,
		sourceIP:                             "10.10.0.79",
		destinationIP:                        "10.10.0.80",
		sourceTransportPort:                  44752,
		destinationTransportPort:             5201,
		protocolIdentifier:                   6,
		packetTotalCount:                     823188,
		octetTotalCount:                      30472817041,
		packetDeltaCount:                     241333,
		octetDeltaCount:                      8982624938,
		reversePacketTotalCount:              471111,
		reverseOctetTotalCount:               24500996,
		reversePacketDeltaCount:              136211,
		reverseOctetDeltaCount:               7083284,
		sourcePodName:                        "perftest-a",
		sourcePodNamespace:                   "antrea-test",
		sourceNodeName:                       "k8s-node-control-plane",
		destinationPodName:                   "perftest-b",
		destinationPodNamespace:              "antrea-test-b",
		destinationNodeName:                  "k8s-node-control-plane-b",
		destinationClusterIP:                 "10.10.1.10",
		destinationServicePort:               5202,
		destinationServicePortName:           "perftest",
		ingressNetworkPolicyName:             "test-flow-aggregator-networkpolicy-ingress-allow",
		ingressNetworkPolicyNamespace:        "antrea-test-ns",
		ingressNetworkPolicyRuleName:         "test-flow-aggregator-networkpolicy-rule",
		ingressNetworkPolicyRuleAction:       2,
		ingressNetworkPolicyType:             1,
		egressNetworkPolicyName:              "test-flow-aggregator-networkpolicy-egress-allow",
		egressNetworkPolicyNamespace:         "antrea-test-ns-e",
		egressNetworkPolicyRuleName:          "test-flow-aggregator-networkpolicy-rule-e",
		egressNetworkPolicyRuleAction:        5,
		egressNetworkPolicyType:              4,
		tcpState:                             "TIME_WAIT",
		flowType:                             11,
		sourcePodLabels:                      "{\"antrea-e2e\":\"perftest-a\",\"app\":\"perftool\"}",
		destinationPodLabels:                 "{\"antrea-e2e\":\"perftest-b\",\"app\":\"perftool\"}",
		throughput:                           15902813472,
		reverseThroughput:                    12381344,
		throughputFromSourceNode:             15902813473,
		throughputFromDestinationNode:        15902813474,
		reverseThroughputFromSourceNode:      12381345,
		reverseThroughputFromDestinationNode: 12381346,
	}

	chExportProc.deque.PushBack(&recordRow)

	mock.ExpectBegin()
	mock.ExpectPrepare(insertQuery).ExpectExec().
		WithArgs(
			time.Unix(int64(1637706961), 0),
			time.Unix(int64(1637706973), 0),
			time.Unix(int64(1637706974), 0),
			time.Unix(int64(1637706975), 0),
			3,
			"10.10.0.79",
			"10.10.0.80",
			44752,
			5201,
			6,
			823188,
			30472817041,
			241333,
			8982624938,
			471111,
			24500996,
			136211,
			7083284,
			"perftest-a",
			"antrea-test",
			"k8s-node-control-plane",
			"perftest-b",
			"antrea-test-b",
			"k8s-node-control-plane-b",
			"10.10.1.10",
			5202,
			"perftest",
			"test-flow-aggregator-networkpolicy-ingress-allow",
			"antrea-test-ns",
			"test-flow-aggregator-networkpolicy-rule",
			2,
			1,
			"test-flow-aggregator-networkpolicy-egress-allow",
			"antrea-test-ns-e",
			"test-flow-aggregator-networkpolicy-rule-e",
			5,
			4,
			"TIME_WAIT",
			11,
			"{\"antrea-e2e\":\"perftest-a\",\"app\":\"perftool\"}",
			"{\"antrea-e2e\":\"perftest-b\",\"app\":\"perftool\"}",
			15902813472,
			12381344,
			15902813473,
			15902813474,
			12381345,
			12381346).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	count, err := chExportProc.batchCommitAll()
	if err != nil {
		t.Errorf("Error occurred when committing record with mock sql db: %s", err)
	}
	assert.Equal(t, 1, count)
	assert.Equal(t, 0, chExportProc.deque.Len())
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Exists unfulfilled expectations for db sql operation: %s", err)
	}
}

func TestBatchCommitAllMultiRecord(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	chExportProc := ClickHouseExportProcess{
		db:    db,
		deque: deque.New(),
		mutex: sync.RWMutex{},
	}
	recordRow := ClickHouseFlowRow{}
	fieldCount := reflect.TypeOf(recordRow).NumField()
	argList := make([]driver.Value, fieldCount)
	for i := 0; i < len(argList); i++ {
		argList[i] = sqlmock.AnyArg()
	}

	mock.ExpectBegin()
	expected := mock.ExpectPrepare(insertQuery)
	for i := 0; i < 10; i++ {
		chExportProc.deque.PushBack(&recordRow)
		expected.ExpectExec().WithArgs(argList...).WillReturnResult(sqlmock.NewResult(int64(i), 1))
	}
	mock.ExpectCommit()

	count, err := chExportProc.batchCommitAll()
	if err != nil {
		t.Errorf("Error occurred when committing record with mock sql db: %s", err)
	}
	assert.Equal(t, 10, count)
	assert.Equal(t, 0, chExportProc.deque.Len())
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Exists unfulfilled expectations for db sql operation: %s", err)
	}
}

func TestBatchCommitAllError(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatalf("Error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	chExportProc := ClickHouseExportProcess{
		db:    db,
		deque: deque.New(),
		mutex: sync.RWMutex{},
	}
	recordRow := ClickHouseFlowRow{}
	chExportProc.deque.PushBack(&recordRow)
	fieldCount := reflect.TypeOf(recordRow).NumField()
	argList := make([]driver.Value, fieldCount)
	for i := 0; i < len(argList); i++ {
		argList[i] = sqlmock.AnyArg()
	}

	mock.ExpectBegin()
	mock.ExpectPrepare(insertQuery).ExpectExec().WithArgs(argList...).WillReturnError(
		fmt.Errorf("mock error for sql stmt exec"))
	mock.ExpectRollback()

	count, err := chExportProc.batchCommitAll()
	if err == nil {
		t.Errorf("Expect error when if encounter issue when committing reocrds")
	}
	assert.Equal(t, 0, count)
	assert.Equal(t, 1, chExportProc.deque.Len())
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Exists unfulfilled expectations for db sql operation: %s", err)
	}
}
