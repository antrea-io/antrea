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
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"

	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	connectionstest "github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/connections/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/flowrecords"
	ipfixtest "github.com/vmware-tanzu/antrea/pkg/ipfix/testing"
)

const (
	testTemplateIDv4      = uint16(256)
	testTemplateIDv6      = uint16(257)
	testActiveFlowTimeout = 3 * time.Second
	testIdleFlowTimeout   = 1 * time.Second
)

func makeTuple(srcIP *net.IP, dstIP *net.IP, protoID uint8, srcPort uint16, dstPort uint16) (flowexporter.Tuple, flowexporter.Tuple) {
	tuple := flowexporter.Tuple{
		SourceAddress:      *srcIP,
		DestinationAddress: *dstIP,
		Protocol:           protoID,
		SourcePort:         srcPort,
		DestinationPort:    dstPort,
	}
	revTuple := flowexporter.Tuple{
		SourceAddress:      *dstIP,
		DestinationAddress: *srcIP,
		Protocol:           protoID,
		SourcePort:         dstPort,
		DestinationPort:    srcPort,
	}
	return tuple, revTuple
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
	var mockTempSet *ipfixtest.MockIPFIXSet
	mockTempSet = ipfixtest.NewMockIPFIXSet(ctrl)

	// Following consists of all elements that are in IANAInfoElements and AntreaInfoElements (globals)
	// Only the element name is needed, other arguments have dummy values.
	var elemList = make([]*ipfixentities.InfoElementWithValue, 0)
	ianaIE := IANAInfoElementsIPv4
	antreaIE := AntreaInfoElementsIPv4
	if isIPv6 {
		ianaIE = IANAInfoElementsIPv6
		antreaIE = AntreaInfoElementsIPv6
	}
	for i, ie := range ianaIE {
		elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.IANAEnterpriseID, 0), nil))
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAEnterpriseID).Return(elemList[i].Element, nil)
	}
	for i, ie := range IANAReverseInfoElements {
		elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.IANAReversedEnterpriseID, 0), nil))
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAReversedEnterpriseID).Return(elemList[i+len(ianaIE)].Element, nil)
	}
	for i, ie := range antreaIE {
		elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.AntreaEnterpriseID, 0), nil))
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[i+len(ianaIE)+len(IANAReverseInfoElements)].Element, nil)
	}
	if !isIPv6 {
		mockTempSet.EXPECT().AddRecord(elemList, testTemplateIDv4).Return(nil)
	} else {
		mockTempSet.EXPECT().AddRecord(elemList, testTemplateIDv6).Return(nil)
	}
	// Passing 0 for sentBytes as it is not used anywhere in the test. If this not a call to mock, the actual sentBytes
	// above elements: IANAInfoElements, IANAReverseInfoElements and AntreaInfoElements.
	mockIPFIXExpProc.EXPECT().SendSet(mockTempSet).Return(0, nil)
	_, err := flowExp.sendTemplateSet(mockTempSet, isIPv6)
	assert.NoError(t, err, "Error in sending template set")

	eL := flowExp.elementsListv4
	if isIPv6 {
		eL = flowExp.elementsListv6
	}
	assert.Len(t, eL, len(ianaIE)+len(IANAReverseInfoElements)+len(antreaIE), "flowExp.elementsList and template record should have same number of elements")
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
	mockDataSet := ipfixtest.NewMockIPFIXSet(ctrl)
	mockIPFIXRegistry := ipfixtest.NewMockIPFIXRegistry(ctrl)

	var recordv4, recordv6 flowexporter.FlowRecord
	var elemListv4, elemListv6 []*ipfixentities.InfoElementWithValue
	if v4Enabled {
		recordv4 = getFlowRecord(getConnection(false, true), false, true)
		elemListv4 = getElemList(IANAInfoElementsIPv4, AntreaInfoElementsIPv4)
	}
	if v6Enabled {
		recordv6 = getFlowRecord(getConnection(true, true), true, true)
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
		}
	}
	return elemList
}

func getConnection(isIPv6 bool, isPresent bool) *flowexporter.Connection {
	var tuple, revTuple flowexporter.Tuple
	if !isIPv6 {
		tuple, revTuple = makeTuple(&net.IP{1, 2, 3, 4}, &net.IP{4, 3, 2, 1}, 6, 65280, 255)
	} else {
		srcIP := net.IP([]byte{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xdf, 0xe1, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xfe, 0xfb})
		dstIP := net.IP([]byte{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xdf, 0xe1, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xfe, 0xfc})
		tuple, revTuple = makeTuple(&srcIP, &dstIP, 6, 65280, 255)
	}
	conn := &flowexporter.Connection{
		StartTime:                     time.Time{},
		StopTime:                      time.Time{},
		OriginalPackets:               0xab,
		OriginalBytes:                 0xabcd,
		ReversePackets:                0xa,
		ReverseBytes:                  0xab,
		TupleOrig:                     tuple,
		TupleReply:                    revTuple,
		IsPresent:                     isPresent,
		SourcePodNamespace:            "ns",
		SourcePodName:                 "pod",
		DestinationPodNamespace:       "",
		DestinationPodName:            "",
		IngressNetworkPolicyName:      "",
		IngressNetworkPolicyNamespace: "",
		EgressNetworkPolicyName:       "np",
		EgressNetworkPolicyNamespace:  "np-ns",
		DestinationServicePortName:    "service",
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
	mockDataSet := ipfixtest.NewMockIPFIXSet(ctrl)
	mockConnStore := connectionstest.NewMockConnectionStore(ctrl)
	flowExp.process = mockIPFIXExpProc
	flowExp.ipfixSet = mockDataSet
	flowExp.connStore = mockConnStore

	tests := []struct {
		name               string
		isConnPresent      bool
		isRecordActive     bool
		packetDifference   uint64
		lastExportTimeDiff time.Duration
	}{
		{
			"active flow record",
			true,
			true,
			0x2, // non-zero number for active records
			testActiveFlowTimeout,
		},
		{
			"idle flow record",
			true,
			true,
			0x0, // zero for idle records
			testIdleFlowTimeout,
		},
		{
			"idle flow record that is still inactive",
			true,
			false,
			0x0,
			testIdleFlowTimeout,
		},
		{
			"idle flow record becomes active",
			true,
			true,
			0x0,
			testActiveFlowTimeout,
		},
		{
			"idle flow record for deleted connection",
			false,
			true,
			0x1,
			testIdleFlowTimeout,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := getConnection(isIPv6, tt.isConnPresent)
			connKey := flowexporter.NewConnectionKey(conn)
			flowExp.flowRecords = flowrecords.NewFlowRecords()
			err := flowExp.flowRecords.AddOrUpdateFlowRecord(connKey, *conn)
			assert.NoError(t, err)
			flowExp.numDataSetsSent = 0

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

			if tt.isRecordActive {
				if !isIPv6 {
					mockDataSet.EXPECT().PrepareSet(ipfixentities.Data, flowExp.templateIDv4).Return(nil)
					mockDataSet.EXPECT().AddRecord(flowExp.elementsListv4, flowExp.templateIDv4).Return(nil)
				} else {
					mockDataSet.EXPECT().PrepareSet(ipfixentities.Data, flowExp.templateIDv6).Return(nil)
					mockDataSet.EXPECT().AddRecord(flowExp.elementsListv6, flowExp.templateIDv6).Return(nil)
				}
				mockIPFIXExpProc.EXPECT().SendSet(mockDataSet).Return(0, nil)
				mockDataSet.EXPECT().ResetSet()
				if !tt.isConnPresent {
					mockConnStore.EXPECT().DeleteConnectionByKey(connKey).Return(nil)
				}
				err = flowExp.sendFlowRecords()
				assert.NoError(t, err)
				assert.Equalf(t, uint64(1), flowExp.numDataSetsSent, "data set should have been sent.")
				if !tt.isConnPresent {
					_, recPresent := flowExp.flowRecords.GetFlowRecordFromMap(&connKey)
					assert.Falsef(t, recPresent, "record should not be in the map")
				}
			} else {
				err = flowExp.sendFlowRecords()
				assert.NoError(t, err)
				assert.Equalf(t, uint64(0), flowExp.numDataSetsSent, "data set should not have been sent.")
			}

		})
	}
}
