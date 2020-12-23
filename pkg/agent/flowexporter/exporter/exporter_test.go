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
	ipfixtest "github.com/vmware-tanzu/antrea/pkg/ipfix/testing"
)

const (
	testTemplateIDv4        = uint16(256)
	testTemplateIDv6        = uint16(257)
	testFlowExportFrequency = 12
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
		testFlowExporter_sendTemplateSet(t, tc.v4Enabled, tc.v6Enabled)
	}
}

func testFlowExporter_sendTemplateSet(t *testing.T, v4Enabled bool, v6Enabled bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockIPFIXRegistry := ipfixtest.NewMockIPFIXRegistry(ctrl)
	flowExp := &flowExporter{
		nil,
		mockIPFIXExpProc,
		nil,
		nil,
		testFlowExportFrequency,
		0,
		testTemplateIDv4,
		testTemplateIDv6,
		mockIPFIXRegistry,
		v4Enabled,
		v6Enabled,
		nil,
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

	var tempSet ipfixentities.Set
	if !isIPv6 {
		mockTempSet.EXPECT().AddRecord(elemList, testTemplateIDv4).Return(nil)
		mockTempSet.EXPECT().GetSet().Return(tempSet)
	} else {
		mockTempSet.EXPECT().AddRecord(elemList, testTemplateIDv6).Return(nil)
		mockTempSet.EXPECT().GetSet().Return(tempSet)
	}

	// Passing 0 for sentBytes as it is not used anywhere in the test. If this not a call to mock, the actual sentBytes
	// above elements: IANAInfoElements, IANAReverseInfoElements and AntreaInfoElements.
	mockIPFIXExpProc.EXPECT().SendSet(tempSet).Return(0, nil)

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
		testFlowExporter_sendDataSet(t, tc.v4Enabled, tc.v6Enabled)
	}
}

func testFlowExporter_sendDataSet(t *testing.T, v4Enabled bool, v6Enabled bool) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockDataSet := ipfixtest.NewMockIPFIXSet(ctrl)
	mockIPFIXRegistry := ipfixtest.NewMockIPFIXRegistry(ctrl)

	var recordv4, recordv6 flowexporter.FlowRecord
	var elemListv4, elemListv6 []*ipfixentities.InfoElementWithValue
	if v4Enabled {
		recordv4 = getFlowRecord(false)
		elemListv4 = getElemList(IANAInfoElementsIPv4, AntreaInfoElementsIPv4)
	}
	if v6Enabled {
		recordv6 = getFlowRecord(true)
		elemListv6 = getElemList(IANAInfoElementsIPv6, AntreaInfoElementsIPv6)
	}
	flowExp := &flowExporter{
		nil,
		mockIPFIXExpProc,
		elemListv4,
		elemListv6,
		testFlowExportFrequency,
		0,
		testTemplateIDv4,
		testTemplateIDv6,
		mockIPFIXRegistry,
		v4Enabled,
		v6Enabled,
		nil,
	}

	sendDataSet := func(elemList []*ipfixentities.InfoElementWithValue, templateID uint16, record flowexporter.FlowRecord) {
		var dataSet ipfixentities.Set
		mockDataSet.EXPECT().AddRecord(gomock.AssignableToTypeOf(elemList), templateID).DoAndReturn(
			func(elements []*ipfixentities.InfoElementWithValue, templateID uint16) interface{} {
				for i, ieWithValue := range elements {
					assert.Equal(t, ieWithValue.Element.Name, elemList[i].Element.Name)
					assert.Equal(t, ieWithValue.Value, elemList[i].Value)
				}
				return nil
			},
		)
		mockDataSet.EXPECT().GetSet().Return(dataSet)
		mockIPFIXExpProc.EXPECT().SendSet(dataSet).Return(0, nil)
		err := flowExp.addRecordToSet(mockDataSet, record)
		assert.NoError(t, err, "Error when adding record to data set")
		_, err = flowExp.sendDataSet(mockDataSet)
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

func getFlowRecord(isIPv6 bool) flowexporter.FlowRecord {
	// Values in the connection are not important. Initializing with 0s.
	return flowexporter.FlowRecord{
		Conn: &flowexporter.Connection{
			StartTime:       time.Time{},
			StopTime:        time.Time{},
			OriginalPackets: 0,
			OriginalBytes:   0,
			ReversePackets:  0,
			ReverseBytes:    0,
			TupleOrig: flowexporter.Tuple{
				SourceAddress:      nil,
				DestinationAddress: nil,
				Protocol:           0,
				SourcePort:         0,
				DestinationPort:    0,
			},
			TupleReply: flowexporter.Tuple{
				SourceAddress:      nil,
				DestinationAddress: nil,
				Protocol:           0,
				SourcePort:         0,
				DestinationPort:    0,
			},
			SourcePodNamespace:            "",
			SourcePodName:                 "",
			DestinationPodNamespace:       "",
			DestinationPodName:            "",
			IngressNetworkPolicyName:      "",
			IngressNetworkPolicyNamespace: "",
			EgressNetworkPolicyName:       "",
			EgressNetworkPolicyNamespace:  "",
		},
		PrevPackets:        0,
		PrevBytes:          0,
		PrevReversePackets: 0,
		PrevReverseBytes:   0,
		IsIPv6:             isIPv6,
	}
}
