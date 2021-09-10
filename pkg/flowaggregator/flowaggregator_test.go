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
	testTemplateIDv4        = uint16(256)
	testTemplateIDv6        = uint16(257)
	testActiveTimeout       = 60 * time.Second
	testInactiveTimeout     = 180 * time.Second
	testObservationDomainID = 0xabcd
	informerDefaultResync   = 12 * time.Hour
)

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

	fa := &flowAggregator{
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
		observationDomainID:         testObservationDomainID,
		podInformer:                 informerFactory.Core().V1().Pods(),
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
		name       string
		isIPv6     bool
		flowKey    ipfixintermediate.FlowKey
		flowRecord *ipfixintermediate.AggregationFlowRecord
	}{
		{
			"IPv4_ready_to_send",
			false,
			ipv4Key,
			readyRecord,
		},
		{
			"IPv6_ready_to_send",
			true,
			ipv6Key,
			readyRecord,
		},
	}

	for _, tc := range testcases {
		templateID := fa.templateIDv4
		if tc.isIPv6 {
			templateID = fa.templateIDv6
		}
		mockDataSet.EXPECT().ResetSet()
		mockDataSet.EXPECT().PrepareSet(ipfixentities.Data, templateID).Return(nil)
		elementList := make([]ipfixentities.InfoElementWithValue, 0)
		mockRecord.EXPECT().GetOrderedElementList().Return(elementList)
		mockDataSet.EXPECT().AddRecord(elementList, templateID).Return(nil)
		mockIPFIXExpProc.EXPECT().SendSet(mockDataSet).Return(0, nil)
		mockAggregationProcess.EXPECT().ResetStatElementsInRecord(mockRecord).Return(nil)
		mockAggregationProcess.EXPECT().AreCorrelatedFieldsFilled(*tc.flowRecord).Return(false)
		sourcePodNameElem := ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement("sourcePodName", 0, 0, ipfixregistry.AntreaEnterpriseID, 0), "")
		mockRecord.EXPECT().GetInfoElementWithValue("sourcePodName").Return(&sourcePodNameElem, 0, false)
		destPodNameElem := ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement("destinationPodName", 0, 0, ipfixregistry.AntreaEnterpriseID, 0), "")
		mockRecord.EXPECT().GetInfoElementWithValue("destinationPodName").Return(&destPodNameElem, 0, false)
		mockAggregationProcess.EXPECT().SetCorrelatedFieldsFilled(tc.flowRecord)
		mockAggregationProcess.EXPECT().AreExternalFieldsFilled(*tc.flowRecord).Return(false)
		sourcePodLabelsElement := ipfixentities.NewInfoElement("sourcePodLabels", 0, 0, ipfixregistry.AntreaEnterpriseID, 0)
		mockIPFIXRegistry.EXPECT().GetInfoElement("sourcePodLabels", ipfixregistry.AntreaEnterpriseID).Return(sourcePodLabelsElement, nil)
		sourcePodLabelsIE := ipfixentities.NewInfoElementWithValue(sourcePodLabelsElement, bytes.NewBufferString("").Bytes())
		mockRecord.EXPECT().AddInfoElement(&sourcePodLabelsIE).Return(nil)
		destinationPodLabelsElement := ipfixentities.NewInfoElement("destinationPodLabels", 0, 0, ipfixregistry.AntreaEnterpriseID, 0)
		mockIPFIXRegistry.EXPECT().GetInfoElement("destinationPodLabels", ipfixregistry.AntreaEnterpriseID).Return(ipfixentities.NewInfoElement("destinationPodLabels", 0, 0, ipfixregistry.AntreaEnterpriseID, 0), nil)
		destinationPodLabelsIE := ipfixentities.NewInfoElementWithValue(destinationPodLabelsElement, bytes.NewBufferString("").Bytes())
		mockRecord.EXPECT().AddInfoElement(&destinationPodLabelsIE).Return(nil)
		mockAggregationProcess.EXPECT().SetExternalFieldsFilled(tc.flowRecord)
		mockAggregationProcess.EXPECT().IsAggregatedRecordIPv4(*tc.flowRecord).Return(!tc.isIPv6)

		err := fa.sendFlowKeyRecord(tc.flowKey, tc.flowRecord)
		assert.NoError(t, err, "Error in sending flow key record: %v, key: %v, record: %v", err, tc.flowKey, tc.flowRecord)
	}
}

func TestFlowAggregator_sendTemplateSet(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockIPFIXRegistry := ipfixtest.NewMockIPFIXRegistry(ctrl)
	mockTempSet := ipfixentitiestesting.NewMockSet(ctrl)

	fa := &flowAggregator{
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
		k8sClient:                   nil,
		observationDomainID:         testObservationDomainID,
	}

	for _, isIPv6 := range []bool{false, true} {
		ianaInfoElements := ianaInfoElementsIPv4
		antreaInfoElements := antreaInfoElementsIPv4
		testTemplateID := fa.templateIDv4
		if isIPv6 {
			ianaInfoElements = ianaInfoElementsIPv6
			antreaInfoElements = antreaInfoElementsIPv6
			testTemplateID = fa.templateIDv6
		}
		// Following consists of all elements that are in ianaInfoElements and antreaInfoElements (globals)
		// Only the element name is needed, other arguments have dummy values.
		elemList := make([]ipfixentities.InfoElementWithValue, 0)
		for i, ie := range ianaInfoElements {
			elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.IANAEnterpriseID, 0), nil))
			mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAEnterpriseID).Return(elemList[i].Element, nil)
		}
		for i, ie := range ianaReverseInfoElements {
			elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.IANAReversedEnterpriseID, 0), nil))
			mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAReversedEnterpriseID).Return(elemList[i+len(ianaInfoElements)].Element, nil)
		}
		for i, ie := range antreaInfoElements {
			elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.AntreaEnterpriseID, 0), nil))
			mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[i+len(ianaInfoElements)+len(ianaReverseInfoElements)].Element, nil)
		}
		for i, ie := range antreaSourceStatsElementList {
			elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.AntreaEnterpriseID, 0), nil))
			mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[i+len(ianaInfoElements)+len(ianaReverseInfoElements)+len(antreaInfoElements)].Element, nil)
		}
		for i, ie := range antreaDestinationStatsElementList {
			elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.AntreaEnterpriseID, 0), nil))
			mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[i+len(ianaInfoElements)+len(ianaReverseInfoElements)+len(antreaInfoElements)+len(antreaSourceStatsElementList)].Element, nil)
		}
		for i, ie := range antreaLabelsElementList {
			elemList = append(elemList, ipfixentities.NewInfoElementWithValue(ipfixentities.NewInfoElement(ie, 0, 0, ipfixregistry.AntreaEnterpriseID, 0), nil))
			mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[i+len(ianaInfoElements)+len(ianaReverseInfoElements)+len(antreaInfoElements)+len(antreaSourceStatsElementList)+len(antreaDestinationStatsElementList)].Element, nil)
		}
		mockTempSet.EXPECT().ResetSet()
		mockTempSet.EXPECT().PrepareSet(ipfixentities.Template, testTemplateID).Return(nil)
		mockTempSet.EXPECT().AddRecord(elemList, testTemplateID).Return(nil)
		// Passing 0 for sentBytes as it is not used anywhere in the test. If this not a call to mock, the actual sentBytes
		// above elements: ianaInfoElements, ianaReverseInfoElements and antreaInfoElements.
		mockIPFIXExpProc.EXPECT().SendSet(mockTempSet).Return(0, nil)

		_, err := fa.sendTemplateSet(isIPv6)
		assert.NoErrorf(t, err, "Error in sending template record: %v, isIPv6: %v", err, isIPv6)
	}
}
