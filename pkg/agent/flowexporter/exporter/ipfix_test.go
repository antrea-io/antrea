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

package exporter

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixentitiestesting "github.com/vmware/go-ipfix/pkg/entities/testing"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	flowexportertesting "antrea.io/antrea/pkg/agent/flowexporter/testing"
	ipfixtest "antrea.io/antrea/pkg/ipfix/testing"
)

const (
	testTemplateIDv4      = uint16(256)
	testTemplateIDv6      = uint16(257)
	testActiveFlowTimeout = 3 * time.Second
	testIdleFlowTimeout   = 1 * time.Second
)

func init() {
	ipfixregistry.LoadRegistry()
}

func TestIPFIXExporter_sendTemplateSet(t *testing.T) {
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
	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockIPFIXRegistry := ipfixtest.NewMockIPFIXRegistry(ctrl)
	flowExp := &ipfixExporter{
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

func sendTemplateSet(t *testing.T, ctrl *gomock.Controller, mockIPFIXExpProc *ipfixtest.MockIPFIXExportingProcess, mockIPFIXRegistry *ipfixtest.MockIPFIXRegistry, flowExp *ipfixExporter, isIPv6 bool) {
	var mockTempSet = ipfixentitiestesting.NewMockSet(ctrl)
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
		mockTempSet.EXPECT().AddRecordV2(elemList, testTemplateIDv4).Return(nil)
	} else {
		mockTempSet.EXPECT().AddRecordV2(elemList, testTemplateIDv6).Return(nil)
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
	assert.NoError(t, err, "Error when sending template set")

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

// TestIPFIXExporter_sendDataRecord tests essentially if element names in the switch-case matches globals
// IANAInfoElements and AntreaInfoElements.
func TestIPFIXExporter_sendDataSet(t *testing.T) {
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
	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockDataSet := ipfixentitiestesting.NewMockSet(ctrl)
	mockIPFIXRegistry := ipfixtest.NewMockIPFIXRegistry(ctrl)

	var connv4, connv6 *connection.Connection
	var elemListv4, elemListv6 []ipfixentities.InfoElementWithValue
	if v4Enabled {
		connv4 = flowexportertesting.GetConnection(false, true, 302, 6, "ESTABLISHED")
		elemListv4 = getElemList(IANAInfoElementsIPv4, AntreaInfoElementsIPv4)
	}
	if v6Enabled {
		connv6 = flowexportertesting.GetConnection(true, true, 302, 6, "ESTABLISHED")
		elemListv6 = getElemList(IANAInfoElementsIPv6, AntreaInfoElementsIPv6)
	}
	flowExp := &ipfixExporter{
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

	sendDataSet := func(elemList []ipfixentities.InfoElementWithValue, templateID uint16, conn connection.Connection) {
		mockDataSet.EXPECT().ResetSet()
		mockDataSet.EXPECT().PrepareSet(ipfixentities.Data, templateID).Return(nil)
		mockDataSet.EXPECT().AddRecordV2(ElementListMatcher(elemList), templateID).Return(nil)
		mockIPFIXExpProc.EXPECT().SendSet(mockDataSet).Return(0, nil)

		err := flowExp.addConnToSet(&conn)
		assert.NoError(t, err, "Error when adding record to data set")
		_, err = flowExp.sendDataSet()
		assert.NoError(t, err, "Error when sending data set")
	}

	if v4Enabled {
		sendDataSet(elemListv4, testTemplateIDv4, *connv4)
	}
	if v6Enabled {
		sendDataSet(elemListv6, testTemplateIDv6, *connv6)
	}
}

func createElement(name string, enterpriseID uint32) ipfixentities.InfoElementWithValue {
	element, _ := ipfixregistry.GetInfoElement(name, enterpriseID)
	ieWithValue, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
	return ieWithValue
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
