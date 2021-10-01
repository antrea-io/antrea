// Copyright 2020 Antrea Authors
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

package exporter

import (
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixentitiestesting "github.com/vmware/go-ipfix/pkg/entities/testing"
	"github.com/vmware/go-ipfix/pkg/registry"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"

	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	connectionstest "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	ipfixtest "antrea.io/antrea/pkg/ipfix/testing"
)

const (
	testTemplateIDv4      = uint16(256)
	testTemplateIDv6      = uint16(257)
	testActiveFlowTimeout = 3 * time.Second
	testIdleFlowTimeout   = 1 * time.Second
)

func init() {
	registry.LoadRegistry()
}

func TestFlowExporter_sendTemplateSet(t *testing.T) {
	for _, tc := range []struct {
		v4Enabled bool
		v6Enabled bool
	}{
		{true, false},
		{false, true},
		{true, true},
	} {
		testSendTemplateSet(t, tc.v4Enabled, tc.v6Enabled)
	}
}

func testSendTemplateSet(t *testing.T, v4Enabled bool, v6Enabled bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockIPFIXRegistry := ipfixtest.NewMockIPFIXRegistry(ctrl)
	flowExp := &flowExporter{
		process:      mockIPFIXExpProc,
		templateIDv4: testTemplateIDv4,
		templateIDv6: testTemplateIDv6,
		registry:     mockIPFIXRegistry,
		v4Enabled:    v4Enabled,
		v6Enabled:    v6Enabled,
	}

	if v4Enabled {
		sendTemplateSet(t, ctrl, mockIPFIXExpProc, mockIPFIXRegistry, flowExp, false)
	}
	if v6Enabled {
		sendTemplateSet(t, ctrl, mockIPFIXExpProc, mockIPFIXRegistry, flowExp, true)
	}
}

func sendTemplateSet(t *testing.T, ctrl *gomock.Controller, mockIPFIXExpProc *ipfixtest.MockIPFIXExportingProcess, mockIPFIXRegistry *ipfixtest.MockIPFIXRegistry, flowExp *flowExporter, isIPv6 bool) {
	var mockTempSet *ipfixentitiestesting.MockSet
	mockTempSet = ipfixentitiestesting.NewMockSet(ctrl)
	flowExp.ipfixSet = mockTempSet
	// Following consists of all elements that are in IANAInfoElements and AntreaInfoElements (globals)
	// Only the element name is needed, other arguments have dummy values.
	elemList := getElementList(isIPv6)
	ianaIE := IANAInfoElementsIPv4
	antreaIE := AntreaInfoElementsIPv4
	if isIPv6 {
		ianaIE = IANAInfoElementsIPv6
		antreaIE = AntreaInfoElementsIPv6
	}
	for i, ie := range ianaIE {
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAEnterpriseID).Return(elemList[i].GetInfoElement(), nil)
	}
	for i, ie := range IANAReverseInfoElements {
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAReversedEnterpriseID).Return(elemList[i+len(ianaIE)].GetInfoElement(), nil)
	}
	for i, ie := range antreaIE {
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[i+len(ianaIE)+len(IANAReverseInfoElements)].GetInfoElement(), nil)
	}
	if !isIPv6 {
		mockTempSet.EXPECT().AddRecord(elemList, testTemplateIDv4).Return(nil)
	} else {
		mockTempSet.EXPECT().AddRecord(elemList, testTemplateIDv6).Return(nil)
	}
	// Passing 0 for sentBytes as it is not used anywhere in the test. If this not a call to mock, the actual sentBytes
	// above elements: IANAInfoElements, IANAReverseInfoElements and AntreaInfoElements.
	mockTempSet.EXPECT().ResetSet()
	if !isIPv6 {
		mockTempSet.EXPECT().PrepareSet(ipfixentities.Template, testTemplateIDv4).Return(nil)
	} else {
		mockTempSet.EXPECT().PrepareSet(ipfixentities.Template, testTemplateIDv6).Return(nil)
	}
	mockIPFIXExpProc.EXPECT().SendSet(mockTempSet).Return(0, nil)
	_, err := flowExp.sendTemplateSet(isIPv6)
	assert.NoError(t, err, "Error in sending template set")

	eL := flowExp.elementsListv4
	if isIPv6 {
		eL = flowExp.elementsListv6
	}
	assert.Len(t, eL, len(ianaIE)+len(IANAReverseInfoElements)+len(antreaIE), "flowExp.elementsList and template record should have same number of elements")
}

func getElementList(isIPv6 bool) []ipfixentities.InfoElementWithValue {
	elemList := make([]ipfixentities.InfoElementWithValue, 0)
	ianaIE := IANAInfoElementsIPv4
	antreaIE := AntreaInfoElementsIPv4
	if isIPv6 {
		ianaIE = IANAInfoElementsIPv6
		antreaIE = AntreaInfoElementsIPv6
	}
	for _, ie := range ianaIE {
		elemList = append(elemList, createElement(ie, ipfixregistry.IANAEnterpriseID))
	}
	for _, ie := range IANAReverseInfoElements {
		elemList = append(elemList, createElement(ie, ipfixregistry.IANAReversedEnterpriseID))
	}
	for _, ie := range antreaIE {
		elemList = append(elemList, createElement(ie, ipfixregistry.AntreaEnterpriseID))
	}
	return elemList
}

type elementListMatcher struct {
	elements []ipfixentities.InfoElementWithValue
}

func ElementListMatcher(elementList []ipfixentities.InfoElementWithValue) gomock.Matcher {
	return elementListMatcher{elementList}
}

func (em elementListMatcher) Matches(arg interface{}) bool {
	elements, _ := arg.([]ipfixentities.InfoElementWithValue)
	for i, ieWithValue := range elements {
		if ieWithValue.GetInfoElement().Name != em.elements[i].GetInfoElement().Name {
			return false
		}
		switch elements[i].GetInfoElement().DataType {
		case ipfixentities.Unsigned8:
			if ieWithValue.GetUnsigned8Value() != em.elements[i].GetUnsigned8Value() {
				return false
			}
		case ipfixentities.Unsigned16:
			if ieWithValue.GetUnsigned16Value() != em.elements[i].GetUnsigned16Value() {
				return false
			}
		case ipfixentities.Unsigned32:
			if ieWithValue.GetUnsigned32Value() != em.elements[i].GetUnsigned32Value() {
				return false
			}
		case ipfixentities.Unsigned64:
			if ieWithValue.GetUnsigned64Value() != em.elements[i].GetUnsigned64Value() {
				return false
			}
		case ipfixentities.String:
			if ieWithValue.GetStringValue() != em.elements[i].GetStringValue() {
				return false
			}
		case ipfixentities.Ipv4Address, ipfixentities.Ipv6Address:
			if ieWithValue.GetIPAddressValue().String() != em.elements[i].GetIPAddressValue().String() {
				return false
			}
		}
	}
	return true
}
func (em elementListMatcher) String() string {
	return ""
}

// TestFlowExporter_sendDataRecord tests essentially if element names in the switch-case matches globals
// IANAInfoElements and AntreaInfoElements.
func TestFlowExporter_sendDataSet(t *testing.T) {
	for _, tc := range []struct {
		v4Enabled bool
		v6Enabled bool
	}{
		{true, false},
		{false, true},
		{true, true},
	} {
		testSendDataSet(t, tc.v4Enabled, tc.v6Enabled)
	}
}

func testSendDataSet(t *testing.T, v4Enabled bool, v6Enabled bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockDataSet := ipfixentitiestesting.NewMockSet(ctrl)
	mockIPFIXRegistry := ipfixtest.NewMockIPFIXRegistry(ctrl)

	var connv4, connv6 *flowexporter.Connection
	var elemListv4, elemListv6 []ipfixentities.InfoElementWithValue
	if v4Enabled {
		connv4 = getConnection(false, true, 302, 6, "ESTABLISHED")
		elemListv4 = getElemList(IANAInfoElementsIPv4, AntreaInfoElementsIPv4)
	}
	if v6Enabled {
		connv6 = getConnection(true, true, 302, 6, "ESTABLISHED")
		elemListv6 = getElemList(IANAInfoElementsIPv6, AntreaInfoElementsIPv6)
	}
	flowExp := &flowExporter{
		process:        mockIPFIXExpProc,
		elementsListv4: elemListv4,
		elementsListv6: elemListv6,
		templateIDv4:   testTemplateIDv4,
		templateIDv6:   testTemplateIDv6,
		registry:       mockIPFIXRegistry,
		v4Enabled:      v4Enabled,
		v6Enabled:      v6Enabled,
		ipfixSet:       mockDataSet,
	}

	sendDataSet := func(elemList []ipfixentities.InfoElementWithValue, templateID uint16, conn flowexporter.Connection) {
		mockDataSet.EXPECT().ResetSet()
		mockDataSet.EXPECT().PrepareSet(ipfixentities.Data, templateID).Return(nil)
		mockDataSet.EXPECT().AddRecord(ElementListMatcher(elemList), templateID).Return(nil)
		mockIPFIXExpProc.EXPECT().SendSet(mockDataSet).Return(0, nil)

		err := flowExp.addConnToSet(&conn)
		assert.NoError(t, err, "Error when adding record to data set")
		_, err = flowExp.sendDataSet()
		assert.NoError(t, err, "Error in sending data set")
	}

	if v4Enabled {
		sendDataSet(elemListv4, testTemplateIDv4, *connv4)
	}
	if v6Enabled {
		sendDataSet(elemListv6, testTemplateIDv6, *connv6)
	}
}

func getElemList(ianaIE []string, antreaIE []string) []ipfixentities.InfoElementWithValue {
	// Following consists of all elements that are in IANAInfoElements and AntreaInfoElements (globals)
	// Need only element name and other fields are set to dummy values
	elemList := make([]ipfixentities.InfoElementWithValue, len(ianaIE)+len(IANAReverseInfoElements)+len(antreaIE))
	for i, ie := range ianaIE {
		elemList[i] = createElement(ie, ipfixregistry.IANAEnterpriseID)
	}
	for i, ie := range IANAReverseInfoElements {
		elemList[i+len(ianaIE)] = createElement(ie, ipfixregistry.IANAReversedEnterpriseID)
	}
	for i, ie := range antreaIE {
		elemList[i+len(ianaIE)+len(IANAReverseInfoElements)] = createElement(ie, ipfixregistry.AntreaEnterpriseID)
	}

	for i, ie := range elemList {
		switch ieName := ie.GetInfoElement().Name; ieName {
		case "flowStartSeconds":
			ie.SetUnsigned32Value(uint32(time.Time{}.Unix()))
		case "flowEndSeconds":
			ie.SetUnsigned32Value(uint32(time.Now().Unix()))
		case "flowEndReason":
			ie.SetUnsigned8Value(uint8(0))
		case "sourceIPv4Address", "destinationIPv4Address", "sourceIPv6Address", "destinationIPv6Address":
			ie.SetIPAddressValue(net.ParseIP(""))
		case "destinationClusterIPv4":
			ie.SetIPAddressValue(net.IP{0, 0, 0, 0})
		case "destinationClusterIPv6":
			ie.SetIPAddressValue(net.ParseIP("::"))
		case "sourceTransportPort", "destinationTransportPort", "destinationServicePort":
			ie.SetUnsigned16Value(uint16(0))
		case "protocolIdentifier":
			ie.SetUnsigned8Value(uint8(0))
		case "packetTotalCount", "octetTotalCount", "packetDeltaCount", "octetDeltaCount", "reversePacketTotalCount", "reverseOctetTotalCount", "reversePacketDeltaCount", "reverseOctetDeltaCount":
			ie.SetUnsigned64Value(uint64(0))
		case "sourcePodName", "sourcePodNamespace", "sourceNodeName", "destinationPodName", "destinationPodNamespace", "destinationNodeName", "destinationServicePortName":
			ie.SetStringValue("")
		case "ingressNetworkPolicyName", "ingressNetworkPolicyNamespace", "egressNetworkPolicyName", "egressNetworkPolicyNamespace":
			ie.SetStringValue("")
		case "ingressNetworkPolicyRuleName", "egressNetworkPolicyRuleName":
			ie.SetStringValue("")
		case "ingressNetworkPolicyType", "egressNetworkPolicyType", "ingressNetworkPolicyRuleAction", "egressNetworkPolicyRuleAction":
			ie.SetUnsigned8Value(uint8(0))
		}
		elemList[i] = ie
	}
	return elemList
}

func getConnection(isIPv6 bool, isPresent bool, statusFlag uint32, protoID uint8, tcpState string) *flowexporter.Connection {
	var tuple flowexporter.Tuple
	if !isIPv6 {
		tuple = flowexporter.Tuple{SourceAddress: net.IP{1, 2, 3, 4}, DestinationAddress: net.IP{4, 3, 2, 1}, Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	} else {
		srcIP := net.ParseIP("2001:0:3238:dfe1:63::fefb")
		dstIP := net.ParseIP("2001:0:3238:dfe1:63::fefc")
		tuple = flowexporter.Tuple{SourceAddress: srcIP, DestinationAddress: dstIP, Protocol: protoID, SourcePort: 65280, DestinationPort: 255}
	}
	conn := &flowexporter.Connection{
		StartTime:                     time.Time{},
		StopTime:                      time.Time{},
		StatusFlag:                    statusFlag,
		OriginalPackets:               0xab,
		OriginalBytes:                 0xabcd,
		ReversePackets:                0xa,
		ReverseBytes:                  0xab,
		FlowKey:                       tuple,
		IsPresent:                     isPresent,
		SourcePodNamespace:            "ns",
		SourcePodName:                 "pod",
		DestinationPodNamespace:       "",
		DestinationPodName:            "",
		IngressNetworkPolicyName:      "",
		IngressNetworkPolicyNamespace: "",
		IngressNetworkPolicyType:      registry.PolicyTypeK8sNetworkPolicy,
		IngressNetworkPolicyRuleName:  "",
		EgressNetworkPolicyName:       "np",
		EgressNetworkPolicyNamespace:  "np-ns",
		EgressNetworkPolicyType:       registry.PolicyTypeK8sNetworkPolicy,
		EgressNetworkPolicyRuleName:   "",
		DestinationServicePortName:    "service",
		TCPState:                      tcpState,
	}
	return conn
}

func getDenyConnection(isIPv6 bool, protoID uint8) *flowexporter.Connection {
	var tuple, _ flowexporter.Tuple
	if !isIPv6 {
		tuple = flowexporter.Tuple{SourceAddress: net.IP{1, 2, 3, 4}, DestinationAddress: net.IP{4, 3, 2, 1}, Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	} else {
		srcIP := net.ParseIP("2001:0:3238:dfe1:63::fefb")
		dstIP := net.ParseIP("2001:0:3238:dfe1:63::fefc")
		tuple = flowexporter.Tuple{SourceAddress: srcIP, DestinationAddress: dstIP, Protocol: protoID, SourcePort: 65280, DestinationPort: 255}
	}
	conn := &flowexporter.Connection{
		FlowKey: tuple,
	}
	return conn
}

func TestFlowExporter_sendFlowRecords(t *testing.T) {
	for _, tc := range []struct {
		v4Enabled bool
		v6Enabled bool
	}{
		{true, false},
		{false, true},
		{true, true},
	} {
		testSendFlowRecords(t, tc.v4Enabled, tc.v6Enabled)
	}
}

func testSendFlowRecords(t *testing.T, v4Enabled bool, v6Enabled bool) {
	var elemListv4, elemListv6 []ipfixentities.InfoElementWithValue
	if v4Enabled {
		elemListv4 = getElemList(IANAInfoElementsIPv4, AntreaInfoElementsIPv4)
	}
	if v6Enabled {
		elemListv6 = getElemList(IANAInfoElementsIPv6, AntreaInfoElementsIPv6)
	}

	flowExp := &flowExporter{
		elementsListv4: elemListv4,
		elementsListv6: elemListv6,
		templateIDv4:   testTemplateIDv4,
		templateIDv6:   testTemplateIDv6,
		v4Enabled:      true}

	if v4Enabled {
		runSendFlowRecordTests(t, flowExp, false)
	}
	if v6Enabled {
		runSendFlowRecordTests(t, flowExp, true)
	}
}

func runSendFlowRecordTests(t *testing.T, flowExp *flowExporter, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockDataSet := ipfixentitiestesting.NewMockSet(ctrl)
	flowExp.process = mockIPFIXExpProc
	flowExp.ipfixSet = mockDataSet
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	startTime := time.Now()

	tests := []struct {
		name               string
		isDenyConn         bool
		isConnPresent      bool
		tcpState           string
		statusFlag         uint32
		protoID            uint8
		originalPackets    uint64
		reversePackets     uint64
		prevPackets        uint64
		prevReversePackets uint64
		activeExpireTime   time.Time
		idleExpireTime     time.Time
	}{
		{
			"conntrack connection being active time out",
			false,
			true,
			"SYN_SENT",
			4,
			6,
			1,
			1,
			0,
			0,
			startTime.Add(-testActiveFlowTimeout),
			startTime.Add(10 * testIdleFlowTimeout),
		},
		{
			"conntrack connection being idle time out and becoming inactive",
			false,
			true,
			"SYN_SENT",
			4,
			6,
			0,
			0,
			0,
			0,
			startTime.Add(10 * testActiveFlowTimeout),
			startTime.Add(-testIdleFlowTimeout),
		},
		{
			"conntrack connection with deleted connection",
			false,
			false,
			"TIME_WAIT",
			204,
			6,
			0,
			0,
			0,
			0,
			startTime.Add(-testActiveFlowTimeout),
			startTime.Add(-testIdleFlowTimeout),
		},
		{
			"deny connection being active time out",
			true,
			false,
			"TIME_WAIT",
			204,
			6,
			1,
			0,
			0,
			0,
			startTime.Add(-testActiveFlowTimeout),
			startTime.Add(10 * testIdleFlowTimeout),
		},
		{
			"deny connection being active time out and becoming inactive",
			true,
			false,
			"TIME_WAIT",
			204,
			6,
			1,
			0,
			1,
			0,
			startTime.Add(-testActiveFlowTimeout),
			startTime.Add(10 * testIdleFlowTimeout),
		},
		{
			"deny connection being idle time out",
			true,
			false,
			"TIME_WAIT",
			204,
			6,
			0,
			0,
			0,
			0,
			startTime.Add(10 * testActiveFlowTimeout),
			startTime.Add(-testIdleFlowTimeout),
		},
	}
	for id, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conntrackPQ := priorityqueue.NewExpirePriorityQueue(testActiveFlowTimeout, testIdleFlowTimeout)
			denyPQ := priorityqueue.NewExpirePriorityQueue(testActiveFlowTimeout, testIdleFlowTimeout)
			flowExp.conntrackPriorityQueue = conntrackPQ
			flowExp.denyPriorityQueue = denyPQ
			flowExp.conntrackConnStore = connections.NewConntrackConnectionStore(mockConnDumper, nil, !isIPv6, isIPv6, nil, nil, 1, conntrackPQ, 1)
			flowExp.denyConnStore = connections.NewDenyConnectionStore(nil, nil, denyPQ, 0)
			flowExp.numDataSetsSent = 0
			var conn, denyConn *flowexporter.Connection
			var connKey flowexporter.ConnectionKey
			var pqItem *flowexporter.ItemToExpire

			if !tt.isDenyConn {
				// Prepare connection map
				conn = getConnection(isIPv6, tt.isConnPresent, tt.statusFlag, tt.protoID, tt.tcpState)
				connKey = flowexporter.NewConnectionKey(conn)
				conn.OriginalPackets = tt.originalPackets
				conn.ReversePackets = tt.reversePackets
				flowExp.conntrackConnStore.AddOrUpdateConn(conn)
				assert.Equalf(t, getNumOfConntrackConns(flowExp.conntrackConnStore), 1, "connection is expected to be in the connection map")
				assert.Equalf(t, flowExp.conntrackPriorityQueue.Len(), 1, "pqItem is expected to be in the expire priority queue")
				conn.PrevPackets = tt.prevPackets
				conn.PrevReversePackets = tt.prevReversePackets
				pqItem = flowExp.conntrackPriorityQueue.KeyToItem[connKey]
				pqItem.ActiveExpireTime = tt.activeExpireTime
				pqItem.IdleExpireTime = tt.idleExpireTime
			} else {
				// Prepare deny connection map
				denyConn = getDenyConnection(isIPv6, tt.protoID)
				connKey = flowexporter.NewConnectionKey(denyConn)
				flowExp.denyConnStore.AddOrUpdateConn(denyConn, time.Now(), uint64(60))
				assert.Equalf(t, getNumOfDenyConns(flowExp.denyConnStore), 1, "deny connection is expected to be in the connection map")
				assert.Equalf(t, flowExp.denyPriorityQueue.Len(), 1, "pqItem is expected to be in the expire priority queue")
				denyConn.PrevPackets = tt.prevPackets
				pqItem = flowExp.denyPriorityQueue.KeyToItem[connKey]
				pqItem.ActiveExpireTime = tt.activeExpireTime
				pqItem.IdleExpireTime = tt.idleExpireTime
			}

			mockDataSet.EXPECT().ResetSet()
			if !isIPv6 {
				mockDataSet.EXPECT().PrepareSet(ipfixentities.Data, flowExp.templateIDv4).Return(nil)
				mockDataSet.EXPECT().AddRecord(flowExp.elementsListv4, flowExp.templateIDv4).Return(nil)
			} else {
				mockDataSet.EXPECT().PrepareSet(ipfixentities.Data, flowExp.templateIDv6).Return(nil)
				mockDataSet.EXPECT().AddRecord(flowExp.elementsListv6, flowExp.templateIDv6).Return(nil)
			}
			mockIPFIXExpProc.EXPECT().SendSet(mockDataSet).Return(0, nil)
			_, err := flowExp.sendFlowRecords()
			assert.NoError(t, err)
			assert.Equalf(t, uint64(1), flowExp.numDataSetsSent, "1 data set should have been sent.")

			switch id {
			case 0: // conntrack connection being active time out
				assert.True(t, pqItem.ActiveExpireTime.After(startTime))
				assert.Equal(t, conn.OriginalPackets, conn.PrevPackets)
				assert.Equalf(t, 1, flowExp.conntrackPriorityQueue.Len(), "Length of expire priority queue should be 1")
			case 1: // conntrack connection being idle time out and becoming inactive
				assert.False(t, conn.IsActive)
				assert.Equalf(t, 0, flowExp.conntrackPriorityQueue.Len(), "Length of expire priority queue should be 0")
			case 2: // conntrack connection with deleted connection
				assert.True(t, conn.ReadyToDelete)
				assert.Equalf(t, 0, flowExp.conntrackPriorityQueue.Len(), "Length of expire priority queue should be 0")
			case 3: // deny connection being active time out
				assert.True(t, pqItem.ActiveExpireTime.After(startTime))
				assert.Equal(t, denyConn.OriginalPackets, denyConn.PrevPackets)
				assert.Equalf(t, 1, flowExp.denyPriorityQueue.Len(), "Length of expire priority queue should be 1")
			case 4: // deny connection being active time out and becoming inactive
				assert.False(t, denyConn.IsActive)
				assert.Equalf(t, 0, flowExp.denyPriorityQueue.Len(), "Length of expire priority queue should be 0")
			case 5: // deny connection being idle time out
				assert.Equal(t, true, denyConn.ReadyToDelete)
				assert.Equalf(t, 0, flowExp.denyPriorityQueue.Len(), "Length of expire priority queue should be 0")
			}
		})
	}
}

func getNumOfConntrackConns(connStore *connections.ConntrackConnectionStore) int {
	count := 0
	countNumOfConns := func(key flowexporter.ConnectionKey, conn *flowexporter.Connection) error {
		count++
		return nil
	}
	connStore.ForAllConnectionsDo(countNumOfConns)
	return count
}

func getNumOfDenyConns(connStore *connections.DenyConnectionStore) int {
	count := 0
	countNumOfConns := func(key flowexporter.ConnectionKey, conn *flowexporter.Connection) error {
		count++
		return nil
	}
	connStore.ForAllConnectionsDo(countNumOfConns)
	return count
}

func createElement(name string, enterpriseID uint32) ipfixentities.InfoElementWithValue {
	element, _ := ipfixregistry.GetInfoElement(name, enterpriseID)
	ieWithValue, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
	return ieWithValue
}
