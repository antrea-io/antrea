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
	"antrea.io/antrea/pkg/agent/flowexporter/flowrecords"
	ipfixtest "antrea.io/antrea/pkg/ipfix/testing"
)

const (
	testTemplateIDv4      = uint16(256)
	testTemplateIDv6      = uint16(257)
	testActiveFlowTimeout = 3 * time.Second
	testIdleFlowTimeout   = 1 * time.Second
)

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
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAEnterpriseID).Return(elemList[i].Element, nil)
	}
	for i, ie := range IANAReverseInfoElements {
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAReversedEnterpriseID).Return(elemList[i+len(ianaIE)].Element, nil)
	}
	for i, ie := range antreaIE {
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[i+len(ianaIE)+len(IANAReverseInfoElements)].Element, nil)
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

func getElementList(isIPv6 bool) []*ipfixentities.InfoElementWithValue {
	elemList := make([]*ipfixentities.InfoElementWithValue, 0)
	ianaIE := IANAInfoElementsIPv4
	antreaIE := AntreaInfoElementsIPv4
	if isIPv6 {
		ianaIE = IANAInfoElementsIPv6
		antreaIE = AntreaInfoElementsIPv6
	}
	for _, ie := range ianaIE {
		elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.IANAEnterpriseID, 0), nil))
	}
	for _, ie := range IANAReverseInfoElements {
		elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.IANAReversedEnterpriseID, 0), nil))
	}
	for _, ie := range antreaIE {
		elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.AntreaEnterpriseID, 0), nil))
	}
	return elemList
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

	var recordv4, recordv6 flowexporter.FlowRecord
	var elemListv4, elemListv6 []*ipfixentities.InfoElementWithValue
	if v4Enabled {
		recordv4 = getFlowRecord(getConnection(false, true, 302, 6, "ESTABLISHED"), false, true)
		elemListv4 = getElemList(IANAInfoElementsIPv4, AntreaInfoElementsIPv4)
	}
	if v6Enabled {
		recordv6 = getFlowRecord(getConnection(true, true, 302, 6, "ESTABLISHED"), true, true)
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

	sendDataSet := func(elemList []*ipfixentities.InfoElementWithValue, templateID uint16, record flowexporter.FlowRecord) {
		mockDataSet.EXPECT().AddRecord(gomock.AssignableToTypeOf(elemList), templateID).DoAndReturn(
			func(elements []*ipfixentities.InfoElementWithValue, templateID uint16) interface{} {
				for i, ieWithValue := range elements {
					assert.Equal(t, ieWithValue.Element.Name, elemList[i].Element.Name)
					assert.Equal(t, ieWithValue.Value, elemList[i].Value)
				}
				return nil
			},
		)
		mockIPFIXExpProc.EXPECT().SendSet(mockDataSet).Return(0, nil)
		err := flowExp.addRecordToSet(record)
		assert.NoError(t, err, "Error when adding record to data set")
		_, err = flowExp.sendDataSet()
		assert.NoError(t, err, "Error in sending data set")
	}

	if v4Enabled {
		sendDataSet(elemListv4, testTemplateIDv4, recordv4)
	}
	if v6Enabled {
		sendDataSet(elemListv6, testTemplateIDv6, recordv6)
	}
}

func getElemList(ianaIE []string, antreaIE []string) []*ipfixentities.InfoElementWithValue {
	// Following consists of all elements that are in IANAInfoElements and AntreaInfoElements (globals)
	// Need only element name and other fields are set to dummy values
	elemList := make([]*ipfixentities.InfoElementWithValue, len(ianaIE)+len(IANAReverseInfoElements)+len(antreaIE))
	for i, ie := range ianaIE {
		elemList[i] = ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, 0, 0), nil)
	}
	for i, ie := range IANAReverseInfoElements {
		elemList[i+len(ianaIE)] = ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.IANAReversedEnterpriseID, 0), nil)
	}
	for i, ie := range antreaIE {
		elemList[i+len(ianaIE)+len(IANAReverseInfoElements)] = ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, 0, 0), nil)
	}

	for i, ie := range elemList {
		switch ieName := ie.Element.Name; ieName {
		case "flowStartSeconds":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, uint32(time.Time{}.Unix()))
		case "flowEndSeconds":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, uint32(time.Now().Unix()))
		case "flowEndReason":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, uint8(0))
		case "sourceIPv4Address", "destinationIPv4Address", "sourceIPv6Address", "destinationIPv6Address":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, net.ParseIP(""))
		case "destinationClusterIPv4":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, net.IP{0, 0, 0, 0})
		case "destinationClusterIPv6":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, net.ParseIP("::"))
		case "sourceTransportPort", "destinationTransportPort", "destinationServicePort":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, uint16(0))
		case "protocolIdentifier":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, uint8(0))
		case "packetTotalCount", "octetTotalCount", "packetDeltaCount", "octetDeltaCount", "reversePacketTotalCount", "reverseOctetTotalCount", "reversePacketDeltaCount", "reverseOctetDeltaCount":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, uint64(0))
		case "sourcePodName", "sourcePodNamespace", "sourceNodeName", "destinationPodName", "destinationPodNamespace", "destinationNodeName", "destinationServicePortName":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, "")
		case "ingressNetworkPolicyName", "ingressNetworkPolicyNamespace", "egressNetworkPolicyName", "egressNetworkPolicyNamespace":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, "")
		case "ingressNetworkPolicyRuleName", "egressNetworkPolicyRuleName":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, "")
		case "ingressNetworkPolicyType", "egressNetworkPolicyType", "ingressNetworkPolicyRuleAction", "egressNetworkPolicyRuleAction":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, uint8(0))
		}
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

func getDenyConnection(isIPv6 bool, isActive bool, protoID uint8) *flowexporter.Connection {
	var tuple, _ flowexporter.Tuple
	if !isIPv6 {
		tuple = flowexporter.Tuple{SourceAddress: net.IP{1, 2, 3, 4}, DestinationAddress: net.IP{4, 3, 2, 1}, Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	} else {
		srcIP := net.ParseIP("2001:0:3238:dfe1:63::fefb")
		dstIP := net.ParseIP("2001:0:3238:dfe1:63::fefc")
		tuple = flowexporter.Tuple{SourceAddress: srcIP, DestinationAddress: dstIP, Protocol: protoID, SourcePort: 65280, DestinationPort: 255}
	}
	conn := &flowexporter.Connection{
		FlowKey:        tuple,
		LastExportTime: time.Now().Add(-testIdleFlowTimeout),
	}
	if isActive {
		conn.LastExportTime = time.Now().Add(-testActiveFlowTimeout)
		conn.DeltaPackets = uint64(1)
	}
	return conn
}

func getFlowRecord(conn *flowexporter.Connection, isIPv6 bool, isActive bool) flowexporter.FlowRecord {
	flowRecord := &flowexporter.FlowRecord{
		Conn:               *conn,
		PrevPackets:        0,
		PrevBytes:          0,
		PrevReversePackets: 0,
		PrevReverseBytes:   0,
		IsIPv6:             isIPv6,
		IsActive:           isActive,
	}
	return *flowRecord
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
	var elemListv4, elemListv6 []*ipfixentities.InfoElementWithValue
	if v4Enabled {
		elemListv4 = getElemList(IANAInfoElementsIPv4, AntreaInfoElementsIPv4)
	}
	if v6Enabled {
		elemListv6 = getElemList(IANAInfoElementsIPv6, AntreaInfoElementsIPv6)
	}
	flowExp := &flowExporter{
		elementsListv4:    elemListv4,
		elementsListv6:    elemListv6,
		templateIDv4:      testTemplateIDv4,
		templateIDv6:      testTemplateIDv6,
		v4Enabled:         true,
		activeFlowTimeout: testActiveFlowTimeout,
		idleFlowTimeout:   testIdleFlowTimeout,
	}

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
	flowExp.conntrackConnStore = connections.NewConntrackConnectionStore(mockConnDumper, flowrecords.NewFlowRecords(), nil, !isIPv6, isIPv6, nil, nil, 1)

	tests := []struct {
		name               string
		isConnPresent      bool
		isRecordActive     bool
		packetDifference   uint64
		lastExportTimeDiff time.Duration
		tcpState           string
		statusFlag         uint32
		protoID            uint8
		isDenyConnActive   bool
	}{
		{
			"active flow record",
			true,
			true,
			0x2, // non-zero number for active records
			testActiveFlowTimeout,
			"SYN_SENT",
			0x4,
			6,
			true,
		},
		{
			"idle flow record",
			true,
			true,
			0x0, // zero for idle records
			testIdleFlowTimeout,
			"ESTABLISHED",
			302,
			6,
			false,
		},
		{
			"idle flow record that is still inactive",
			true,
			false,
			0x0,
			testIdleFlowTimeout,
			"",
			0x204,
			17,
			false,
		},
		{
			"idle flow record becomes active",
			true,
			true,
			0x0,
			testActiveFlowTimeout,
			"SYN_SENT",
			302,
			6,
			true,
		},
		{
			"idle flow record for deleted connection",
			false,
			true,
			0x1,
			testIdleFlowTimeout,
			"TIME_WAIT",
			0x204,
			6,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := getConnection(isIPv6, tt.isConnPresent, tt.statusFlag, tt.protoID, tt.tcpState)
			connKey := flowexporter.NewConnectionKey(conn)
			flowExp.conntrackConnStore.AddOrUpdateConn(conn)
			flowExp.flowRecords = flowrecords.NewFlowRecords()
			err := flowExp.conntrackConnStore.ForAllConnectionsDo(flowExp.flowRecords.AddOrUpdateFlowRecord)
			assert.NoError(t, err)
			flowExp.numDataSetsSent = 0

			denyConn := getDenyConnection(isIPv6, tt.isDenyConnActive, tt.protoID)
			flowExp.denyConnStore = connections.NewDenyConnectionStore(nil, nil)
			flowExp.denyConnStore.AddOrUpdateConn(denyConn, denyConn.LastExportTime, denyConn.DeltaBytes)
			assert.Equal(t, getNumOfConnections(flowExp.denyConnStore), 1)

			// Get the flow record and update it.
			flowRec, exists := flowExp.flowRecords.GetFlowRecordFromMap(&connKey)
			if !exists {
				t.Fatal("flow record is expected to be in the record map")
			}
			flowRec.IsActive = tt.isRecordActive
			flowRec.PrevPackets = flowRec.Conn.OriginalPackets - tt.packetDifference
			flowRec.PrevReversePackets = flowRec.Conn.ReversePackets - tt.packetDifference
			flowRec.LastExportTime = time.Now().Add(-tt.lastExportTimeDiff)
			flowExp.flowRecords.AddFlowRecordToMap(&connKey, flowRec)

			count := 1
			if tt.isRecordActive {
				count += 1
			}
			if !isIPv6 {
				mockDataSet.EXPECT().PrepareSet(ipfixentities.Data, flowExp.templateIDv4).Times(count).Return(nil)
				mockDataSet.EXPECT().AddRecord(flowExp.elementsListv4, flowExp.templateIDv4).Times(count).Return(nil)
			} else {
				mockDataSet.EXPECT().PrepareSet(ipfixentities.Data, flowExp.templateIDv6).Times(count).Return(nil)
				mockDataSet.EXPECT().AddRecord(flowExp.elementsListv6, flowExp.templateIDv6).Times(count).Return(nil)
			}
			mockIPFIXExpProc.EXPECT().SendSet(mockDataSet).Times(count).Return(0, nil)
			mockDataSet.EXPECT().ResetSet().Times(count)

			err = flowExp.sendFlowRecords()
			assert.NoError(t, err)
			assert.Equalf(t, uint64(count), flowExp.numDataSetsSent, "%v data sets should have been sent.", count)
			if tt.isDenyConnActive {
				connection, exist := flowExp.denyConnStore.GetConnByKey(connKey)
				assert.True(t, exist)
				assert.Equal(t, uint64(0), connection.DeltaPackets)
				assert.Equal(t, uint64(0), connection.DeltaBytes)
			} else {
				assert.Equal(t, getNumOfConnections(flowExp.denyConnStore), 0)
			}
			if tt.isRecordActive && flowexporter.IsConnectionDying(conn) {
				err = flowExp.conntrackConnStore.ForAllConnectionsDo(flowExp.flowRecords.AddOrUpdateFlowRecord)
				assert.NoError(t, err)
				_, recPresent := flowExp.flowRecords.GetFlowRecordFromMap(&connKey)
				assert.Falsef(t, recPresent, "record should not be in the map")
				connection, _ := flowExp.conntrackConnStore.GetConnByKey(connKey)
				assert.True(t, connection.DyingAndDoneExport)
			}
		})
	}
}

func getNumOfConnections(connStore *connections.DenyConnectionStore) int {
	count := 0
	countNumOfConns := func(key flowexporter.ConnectionKey, conn *flowexporter.Connection) error {
		count++
		return nil
	}
	connStore.ForAllConnectionsDo(countNumOfConns)
	return count
}
