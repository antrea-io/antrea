// Copyright 2020 Antrea Authors
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

package flowaggregator

import (
	"bytes"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixentitiestesting "github.com/vmware/go-ipfix/pkg/entities/testing"
	ipfixintermediate "github.com/vmware/go-ipfix/pkg/intermediate"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	ipfixtest "antrea.io/antrea/pkg/ipfix/testing"
)

const (
	testActiveTimeout       = 60 * time.Second
	testInactiveTimeout     = 180 * time.Second
	testObservationDomainID = 0xabcd
	informerDefaultResync   = 12 * time.Hour
)

var testTemplateIDv4 = map[uint8]map[uint8]uint16{
	uint8(1): {
		uint8(1): uint16(0),
		uint8(2): uint16(1)},
	uint8(2): {
		uint8(1): uint16(2),
		uint8(2): uint16(3)},
	uint8(3): {
		uint8(1): uint16(4),
		uint8(2): uint16(5),
	},
}
var testTemplateIDv6 = map[uint8]map[uint8]uint16{
	uint8(1): {
		uint8(1): uint16(6),
		uint8(2): uint16(7)},
	uint8(2): {
		uint8(1): uint16(8),
		uint8(2): uint16(9)},
	uint8(3): {
		uint8(1): uint16(10),
		uint8(2): uint16(11),
	},
}

func init() {
	ipfixregistry.LoadRegistry()
}

func TestFlowAggregator_sendFlowKeyRecord(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockIPFIXRegistry := ipfixtest.NewMockIPFIXRegistry(ctrl)
	mockDataSet := ipfixentitiestesting.NewMockSet(ctrl)
	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)
	mockAggregationProcess := ipfixtest.NewMockIPFIXAggregationProcess(ctrl)

	client := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)

	newFlowAggregator := func(includePodLabels bool) *flowAggregator {
		return &flowAggregator{
			externalFlowCollectorAddr:   "",
			externalFlowCollectorProto:  "",
			aggregatorTransportProtocol: "tcp",
			aggregationProcess:          mockAggregationProcess,
			activeFlowRecordTimeout:     testActiveTimeout,
			inactiveFlowRecordTimeout:   testInactiveTimeout,
			exportingProcess:            mockIPFIXExpProc,
			templateIDv4:                testTemplateIDv4,
			templateIDv6:                testTemplateIDv6,
			registry:                    mockIPFIXRegistry,
			set:                         mockDataSet,
			flowAggregatorAddress:       "",
			includePodLabels:            includePodLabels,
			observationDomainID:         testObservationDomainID,
			podInformer:                 informerFactory.Core().V1().Pods(),
		}
	}

	ipv4Key := ipfixintermediate.FlowKey{
		SourceAddress:      "10.0.0.1",
		DestinationAddress: "10.0.0.2",
		Protocol:           6,
		SourcePort:         1234,
		DestinationPort:    5678,
	}

	ipv6Key := ipfixintermediate.FlowKey{
		SourceAddress:      "2001:0:3238:dfe1:63::fefb",
		DestinationAddress: "2001:0:3238:dfe1:63::fefc",
		Protocol:           6,
		SourcePort:         1234,
		DestinationPort:    5678,
	}

	readyRecord := &ipfixintermediate.AggregationFlowRecord{
		Record:      mockRecord,
		ReadyToSend: true,
	}

	testcases := []struct {
		name             string
		isIPv6           bool
		flowKey          ipfixintermediate.FlowKey
		flowRecord       *ipfixintermediate.AggregationFlowRecord
		includePodLabels bool
	}{
		{
			"IPv4_ready_to_send_with_pod_labels",
			false,
			ipv4Key,
			readyRecord,
			true,
		},
		{
			"IPv6_ready_to_send_with_pod_labels",
			true,
			ipv6Key,
			readyRecord,
			true,
		},
		{
			"IPv4_ready_to_send_without_pod_labels",
			false,
			ipv4Key,
			readyRecord,
			false,
		},
		{
			"IPv6_ready_to_send_without_pod_labels",
			true,
			ipv6Key,
			readyRecord,
			false,
		},
	}

	for _, tc := range testcases {
		for _, flowType := range flowtypeArray {
			for _, connectType := range connectTypeArray {
				fa := newFlowAggregator(tc.includePodLabels)
				mockDataSet.EXPECT().ResetSet()
				mockDataSet.EXPECT().PrepareSet(ipfixentities.Data, gomock.Any()).Return(nil).AnyTimes()
				elementList := make([]ipfixentities.InfoElementWithValue, 0)
				mockRecord.EXPECT().GetOrderedElementList().Return(elementList).AnyTimes()
				mockDataSet.EXPECT().AddRecord(elementList, gomock.Any()).Return(nil).AnyTimes()
				mockIPFIXExpProc.EXPECT().SendSet(mockDataSet).Return(0, nil)
				mockAggregationProcess.EXPECT().ResetStatAndThroughputElementsInRecord(mockRecord).Return(nil)
				mockAggregationProcess.EXPECT().AreCorrelatedFieldsFilled(*tc.flowRecord).Return(false).AnyTimes()
				emptyStr := make([]byte, 8)
				sourcePodNameElem, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(ipfixentities.NewInfoElement("sourcePodName", 0, 0, ipfixregistry.AntreaEnterpriseID, 0), emptyStr)
				mockRecord.EXPECT().GetInfoElementWithValue("sourcePodName").Return(sourcePodNameElem, 0, false).AnyTimes()
				destPodNameElem, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(ipfixentities.NewInfoElement("destinationPodName", 0, 0, ipfixregistry.AntreaEnterpriseID, 0), emptyStr)
				mockRecord.EXPECT().GetInfoElementWithValue("destinationPodName").Return(destPodNameElem, 0, false).AnyTimes()
				flowTypeElem, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(ipfixentities.NewInfoElement("flowtype", 0, ipfixentities.Unsigned8, ipfixregistry.AntreaEnterpriseID, 0), emptyStr)
				flowTypeElem.SetUnsigned8Value(flowType)
				mockRecord.EXPECT().GetInfoElementWithValue("flowType").Return(flowTypeElem, 0, true)
				ingressNetworkPolicyRuleActionElem, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(ipfixentities.NewInfoElement("ingressNetworkPolicyRuleActionElem", 0, ipfixentities.Unsigned8, ipfixregistry.AntreaEnterpriseID, 0), emptyStr)
				EgressNetworkPolicyRuleActionElem, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(ipfixentities.NewInfoElement("EgressNetworkPolicyRuleAction", 0, ipfixentities.Unsigned8, ipfixregistry.AntreaEnterpriseID, 0), emptyStr)
				EgressNetworkPolicyRuleActionElem.SetUnsigned8Value(ipfixregistry.NetworkPolicyRuleActionAllow)
				if connectType == DeniedConnection {
					ingressNetworkPolicyRuleActionElem.SetUnsigned8Value(ipfixregistry.NetworkPolicyRuleActionDrop)
				} else {
					ingressNetworkPolicyRuleActionElem.SetUnsigned8Value(ipfixregistry.NetworkPolicyRuleActionAllow)
				}
				mockRecord.EXPECT().GetInfoElementWithValue("ingressNetworkPolicyRuleAction").Return(ingressNetworkPolicyRuleActionElem, 0, true)
				mockRecord.EXPECT().GetInfoElementWithValue("EgressNetworkPolicyRuleAction").Return(ingressNetworkPolicyRuleActionElem, 0, true).AnyTimes()
				mockAggregationProcess.EXPECT().SetCorrelatedFieldsFilled(tc.flowRecord)
				if tc.includePodLabels {
					mockAggregationProcess.EXPECT().AreExternalFieldsFilled(*tc.flowRecord).Return(false)
					sourcePodLabelsElement := ipfixentities.NewInfoElement("sourcePodLabels", 0, 0, ipfixregistry.AntreaEnterpriseID, 0)
					mockIPFIXRegistry.EXPECT().GetInfoElement("sourcePodLabels", ipfixregistry.AntreaEnterpriseID).Return(sourcePodLabelsElement, nil)
					sourcePodLabelsIE, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(sourcePodLabelsElement, bytes.NewBufferString("").Bytes())
					mockRecord.EXPECT().AddInfoElement(sourcePodLabelsIE).Return(nil).AnyTimes()
					destinationPodLabelsElement := ipfixentities.NewInfoElement("destinationPodLabels", 0, 0, ipfixregistry.AntreaEnterpriseID, 0)
					mockIPFIXRegistry.EXPECT().GetInfoElement("destinationPodLabels", ipfixregistry.AntreaEnterpriseID).Return(ipfixentities.NewInfoElement("destinationPodLabels", 0, 0, ipfixregistry.AntreaEnterpriseID, 0), nil)
					destinationPodLabelsIE, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(destinationPodLabelsElement, bytes.NewBufferString("").Bytes())
					mockRecord.EXPECT().AddInfoElement(destinationPodLabelsIE).Return(nil).AnyTimes()
					mockAggregationProcess.EXPECT().SetExternalFieldsFilled(tc.flowRecord)
				}
				mockAggregationProcess.EXPECT().IsAggregatedRecordIPv4(*tc.flowRecord).Return(!tc.isIPv6)
				err := fa.sendFlowKeyRecord(tc.flowKey, tc.flowRecord)
				assert.NoError(t, err, "Error in sending flow key record: %v, key: %v, record: %v", err, tc.flowKey, tc.flowRecord)
			}
		}

	}
}

func TestFlowAggregator_sendTemplateSet(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockIPFIXRegistry := ipfixtest.NewMockIPFIXRegistry(ctrl)
	mockTempSet := ipfixentitiestesting.NewMockSet(ctrl)

	newFlowAggregator := func(includePodLabels bool) *flowAggregator {
		return &flowAggregator{
			externalFlowCollectorAddr:   "",
			externalFlowCollectorProto:  "",
			aggregatorTransportProtocol: "tcp",
			collectingProcess:           nil,
			aggregationProcess:          nil,
			activeFlowRecordTimeout:     testActiveTimeout,
			exportingProcess:            mockIPFIXExpProc,
			templateIDv4:                testTemplateIDv4,
			templateIDv6:                testTemplateIDv6,
			registry:                    mockIPFIXRegistry,
			set:                         mockTempSet,
			flowAggregatorAddress:       "",
			includePodLabels:            includePodLabels,
			k8sClient:                   nil,
			observationDomainID:         testObservationDomainID,
		}
	}

	testcases := []struct {
		isIPv6           bool
		includePodLabels bool
	}{
		{false, true},
		{true, true},
		{false, false},
		{true, false},
	}

	for _, tc := range testcases {
		fa := newFlowAggregator(tc.includePodLabels)
		ianaInfoElements := ianaInfoElementsIPv4
		antreaInfoElements := antreaInfoElementsIPv4
		if tc.isIPv6 {
			ianaInfoElements = ianaInfoElementsIPv6
			antreaInfoElements = antreaInfoElementsIPv6
		}
		for _, flowType := range flowtypeArray {
			for _, connectType := range connectTypeArray {
				// Following consists of all elements that are in ianaInfoElements and antreaInfoElements (globals)
				// Only the element name is needed, other arguments have dummy values.
				elemList := make([]ipfixentities.InfoElementWithValue, 0)
				for _, ie := range ianaInfoElements {
					elemList = append(elemList, createElement(ie, ipfixregistry.IANAEnterpriseID))
					mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
				}
				for _, ie := range ianaReverseInfoElements {
					elemList = append(elemList, createElement(ie, ipfixregistry.IANAReversedEnterpriseID))
					mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAReversedEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
				}
				for _, ie := range antreaInfoElements {
					elemList = append(elemList, createElement(ie, ipfixregistry.AntreaEnterpriseID))
					mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
				}
				for i := range statsElementList {
					elemList = append(elemList, createElement(antreaSourceStatsElementList[i], ipfixregistry.AntreaEnterpriseID))
					mockIPFIXRegistry.EXPECT().GetInfoElement(antreaSourceStatsElementList[i], ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
					elemList = append(elemList, createElement(antreaDestinationStatsElementList[i], ipfixregistry.AntreaEnterpriseID))
					mockIPFIXRegistry.EXPECT().GetInfoElement(antreaDestinationStatsElementList[i], ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
				}
				for _, ie := range antreaFlowEndSecondsElementList {
					elemList = append(elemList, createElement(ie, ipfixregistry.AntreaEnterpriseID))
					mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
				}
				for i := range antreaThroughputElementList {
					elemList = append(elemList, createElement(antreaThroughputElementList[i], ipfixregistry.AntreaEnterpriseID))
					mockIPFIXRegistry.EXPECT().GetInfoElement(antreaThroughputElementList[i], ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
					elemList = append(elemList, createElement(antreaSourceThroughputElementList[i], ipfixregistry.AntreaEnterpriseID))
					mockIPFIXRegistry.EXPECT().GetInfoElement(antreaSourceThroughputElementList[i], ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
					elemList = append(elemList, createElement(antreaDestinationThroughputElementList[i], ipfixregistry.AntreaEnterpriseID))
					mockIPFIXRegistry.EXPECT().GetInfoElement(antreaDestinationThroughputElementList[i], ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
				}
				if tc.includePodLabels {
					for _, ie := range antreaLabelsElementList {
						elemList = append(elemList, createElement(ie, ipfixregistry.AntreaEnterpriseID))
						mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
					}
				}
				filteredElements := fa.filterField(fieldFilterMap[flowType], elemList)
				if connectType == DeniedConnection {
					filteredElements = fa.filterField(fieldFilterDeniedConnection, filteredElements)
				}
				mockTempSet.EXPECT().ResetSet()
				mockTempSet.EXPECT().PrepareSet(ipfixentities.Template, gomock.Any()).Return(nil)
				mockTempSet.EXPECT().AddRecord(filteredElements, gomock.Any()).Return(nil)
				// Passing 0 for sentBytes as it is not used anywhere in the test. If this not a call to mock, the actual sentBytes
				// above elements: ianaInfoElements, ianaReverseInfoElements and antreaInfoElements.
				mockIPFIXExpProc.EXPECT().SendSet(mockTempSet).Return(0, nil)

				_, err := fa.sendTemplateSet(tc.isIPv6, flowType, connectType)
				assert.NoErrorf(t, err, "Error in sending template record: %v, isIPv6: %v", err, tc.isIPv6)
			}
		}

	}
}

func createElement(name string, enterpriseID uint32) ipfixentities.InfoElementWithValue {
	element, _ := ipfixregistry.GetInfoElement(name, enterpriseID)
	ieWithValue, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
	return ieWithValue
}
