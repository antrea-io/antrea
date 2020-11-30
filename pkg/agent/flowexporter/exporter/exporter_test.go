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

	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	ipfixtest "github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/ipfix/testing"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
)

const (
	testTemplateID          = uint16(256)
	testFlowExportFrequency = 12
)

func TestFlowExporter_sendTemplateSet(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockTempSet := ipfixtest.NewMockIPFIXSet(ctrl)
	mockIPFIXRegistry := ipfixtest.NewMockIPFIXRegistry(ctrl)
	flowExp := &flowExporter{
		nil,
		mockIPFIXExpProc,
		nil,
		testFlowExportFrequency,
		0,
		testTemplateID,
		mockIPFIXRegistry,
	}
	// Following consists of all elements that are in IANAInfoElements and AntreaInfoElements (globals)
	// Only the element name is needed, other arguments have dummy values.
	elemList := make([]*ipfixentities.InfoElementWithValue, 0)
	for i, ie := range IANAInfoElements {
		elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.IANAEnterpriseID, 0), nil))
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAEnterpriseID).Return(elemList[i].Element, nil)
	}
	for i, ie := range IANAReverseInfoElements {
		elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.IANAReversedEnterpriseID, 0), nil))
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAReversedEnterpriseID).Return(elemList[i+len(IANAInfoElements)].Element, nil)
	}
	for i, ie := range AntreaInfoElements {
		elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.AntreaEnterpriseID, 0), nil))
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[i+len(IANAInfoElements)+len(IANAReverseInfoElements)].Element, nil)
	}

	var tempSet ipfixentities.Set
	mockTempSet.EXPECT().AddRecord(elemList, testTemplateID).Return(nil)
	mockTempSet.EXPECT().GetSet().Return(tempSet)

	// Passing 0 for sentBytes as it is not used anywhere in the test. If this not a call to mock, the actual sentBytes
	// above elements: IANAInfoElements, IANAReverseInfoElements and AntreaInfoElements.
	mockIPFIXExpProc.EXPECT().AddSetAndSendMsg(ipfixentities.Template, tempSet).Return(0, nil)

	_, err := flowExp.sendTemplateSet(mockTempSet, testTemplateID)
	if err != nil {
		t.Errorf("Error in sending templated record: %v", err)
	}

	assert.Equal(t, len(IANAInfoElements)+len(IANAReverseInfoElements)+len(AntreaInfoElements), len(flowExp.elementsList), flowExp.elementsList, "flowExp.elementsList and template record should have same number of elements")
}

// TestFlowExporter_sendDataRecord tests essentially if element names in the switch-case matches globals
// IANAInfoElements and AntreaInfoElements.
func TestFlowExporter_sendDataSet(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Values in the connection are not important. Initializing with 0s.
	flow1 := flowexporter.Connection{
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
	}
	record1 := flowexporter.FlowRecord{
		Conn:               &flow1,
		PrevPackets:        0,
		PrevBytes:          0,
		PrevReversePackets: 0,
		PrevReverseBytes:   0,
	}
	// Following consists of all elements that are in IANAInfoElements and AntreaInfoElements (globals)
	// Need only element name and other are dummys
	elemList := make([]*ipfixentities.InfoElementWithValue, len(IANAInfoElements)+len(IANAReverseInfoElements)+len(AntreaInfoElements))
	for i, ie := range IANAInfoElements {
		elemList[i] = ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, 0, 0), nil)
	}
	for i, ie := range IANAReverseInfoElements {
		elemList[i+len(IANAInfoElements)] = ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.IANAReversedEnterpriseID, 0), nil)
	}
	for i, ie := range AntreaInfoElements {
		elemList[i+len(IANAInfoElements)+len(IANAReverseInfoElements)] = ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, 0, 0), nil)
	}

	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockDataSet := ipfixtest.NewMockIPFIXSet(ctrl)
	mockIPFIXRegistry := ipfixtest.NewMockIPFIXRegistry(ctrl)
	flowExp := &flowExporter{
		nil,
		mockIPFIXExpProc,
		elemList,
		testFlowExportFrequency,
		0,
		testTemplateID,
		mockIPFIXRegistry,
	}

	for i, ie := range flowExp.elementsList {
		switch ieName := ie.Element.Name; ieName {
		case "flowStartSeconds":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, uint32(time.Time{}.Unix()))
		case "flowEndSeconds":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, uint32(time.Now().Unix()))
		case "sourceIPv4Address", "destinationIPv4Address":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, net.ParseIP(""))
		case "destinationClusterIPv4":
			elemList[i] = ipfixentities.NewInfoElementWithValue(ie.Element, net.IP{0, 0, 0, 0})
		case "sourceTransportPort", "destinationTransportPort":
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

	// TODO: add tests for data fields
	var dataSet ipfixentities.Set
	mockDataSet.EXPECT().AddRecord(gomock.AssignableToTypeOf(elemList), testTemplateID).DoAndReturn(
		func(elements []*ipfixentities.InfoElementWithValue, templateID uint16) interface{} {
			for i, ieWithValue := range elements {
				assert.Equal(t, ieWithValue.Element.Name, elemList[i].Element.Name)
				assert.Equal(t, ieWithValue.Value, elemList[i].Value)
			}
			return nil
		},
	)
	mockDataSet.EXPECT().GetSet().Return(dataSet)
	mockIPFIXExpProc.EXPECT().AddSetAndSendMsg(ipfixentities.Data, dataSet).Return(0, nil)

	err := flowExp.sendDataSet(mockDataSet, record1, testTemplateID)
	if err != nil {
		t.Errorf("Error in sending data set: %v", err)
	}
}
