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

package exporter

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/gammazero/deque"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixentitiestesting "github.com/vmware/go-ipfix/pkg/entities/testing"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/pkg/flowaggregator/infoelements"
	"antrea.io/antrea/pkg/flowaggregator/options"
	ipfixtesting "antrea.io/antrea/pkg/ipfix/testing"
)

const (
	testTemplateIDv4        = uint16(256)
	testTemplateIDv6        = uint16(257)
	testObservationDomainID = 0xabcd
)

func init() {
	ipfixregistry.LoadRegistry()
}

func createElement(name string, enterpriseID uint32) ipfixentities.InfoElementWithValue {
	element, _ := ipfixregistry.GetInfoElement(name, enterpriseID)
	ieWithValue, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
	return ieWithValue
}

func TestFlowAggregator_sendTemplateSet(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIPFIXExpProc := ipfixtesting.NewMockIPFIXExportingProcess(ctrl)
	mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
	mockTempSet := ipfixentitiestesting.NewMockSet(ctrl)

	newIPFIXExporter := func(includePodLabels bool) *IPFIXExporter {
		return &IPFIXExporter{
			externalFlowCollectorAddr:  "",
			externalFlowCollectorProto: "",
			exportingProcess:           mockIPFIXExpProc,
			templateIDv4:               testTemplateIDv4,
			templateIDv6:               testTemplateIDv6,
			registry:                   mockIPFIXRegistry,
			set:                        mockTempSet,
			includePodLabels:           includePodLabels,
			observationDomainID:        testObservationDomainID,
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
		exporter := newIPFIXExporter(tc.includePodLabels)
		ianaInfoElements := infoelements.IANAInfoElementsIPv4
		antreaInfoElements := infoelements.AntreaInfoElementsIPv4
		testTemplateID := exporter.templateIDv4
		if tc.isIPv6 {
			ianaInfoElements = infoelements.IANAInfoElementsIPv6
			antreaInfoElements = infoelements.AntreaInfoElementsIPv6
			testTemplateID = exporter.templateIDv6
		}
		// Following consists of all elements that are in ianaInfoElements and antreaInfoElements (globals)
		// Only the element name is needed, other arguments have dummy values.
		elemList := make([]ipfixentities.InfoElementWithValue, 0)
		for _, ie := range ianaInfoElements {
			elemList = append(elemList, createElement(ie, ipfixregistry.IANAEnterpriseID))
			mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
		}
		for _, ie := range infoelements.IANAReverseInfoElements {
			elemList = append(elemList, createElement(ie, ipfixregistry.IANAReversedEnterpriseID))
			mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAReversedEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
		}
		for _, ie := range antreaInfoElements {
			elemList = append(elemList, createElement(ie, ipfixregistry.AntreaEnterpriseID))
			mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
		}
		for i := range infoelements.StatsElementList {
			elemList = append(elemList, createElement(infoelements.AntreaSourceStatsElementList[i], ipfixregistry.AntreaEnterpriseID))
			mockIPFIXRegistry.EXPECT().GetInfoElement(infoelements.AntreaSourceStatsElementList[i], ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
			elemList = append(elemList, createElement(infoelements.AntreaDestinationStatsElementList[i], ipfixregistry.AntreaEnterpriseID))
			mockIPFIXRegistry.EXPECT().GetInfoElement(infoelements.AntreaDestinationStatsElementList[i], ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
		}
		for _, ie := range infoelements.AntreaFlowEndSecondsElementList {
			elemList = append(elemList, createElement(ie, ipfixregistry.AntreaEnterpriseID))
			mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
		}
		for i := range infoelements.AntreaThroughputElementList {
			elemList = append(elemList, createElement(infoelements.AntreaThroughputElementList[i], ipfixregistry.AntreaEnterpriseID))
			mockIPFIXRegistry.EXPECT().GetInfoElement(infoelements.AntreaThroughputElementList[i], ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
			elemList = append(elemList, createElement(infoelements.AntreaSourceThroughputElementList[i], ipfixregistry.AntreaEnterpriseID))
			mockIPFIXRegistry.EXPECT().GetInfoElement(infoelements.AntreaSourceThroughputElementList[i], ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
			elemList = append(elemList, createElement(infoelements.AntreaDestinationThroughputElementList[i], ipfixregistry.AntreaEnterpriseID))
			mockIPFIXRegistry.EXPECT().GetInfoElement(infoelements.AntreaDestinationThroughputElementList[i], ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
		}
		if tc.includePodLabels {
			for _, ie := range infoelements.AntreaLabelsElementList {
				elemList = append(elemList, createElement(ie, ipfixregistry.AntreaEnterpriseID))
				mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
			}
		}
		mockTempSet.EXPECT().ResetSet()
		mockTempSet.EXPECT().PrepareSet(ipfixentities.Template, testTemplateID).Return(nil)
		mockTempSet.EXPECT().AddRecord(elemList, testTemplateID).Return(nil)
		// Passing 0 for sentBytes as it is not used anywhere in the test. If this not a call to mock, the actual sentBytes
		// above elements: ianaInfoElements, ianaReverseInfoElements and antreaInfoElements.
		mockIPFIXExpProc.EXPECT().SendSet(mockTempSet).Return(0, nil)

		_, err := exporter.sendTemplateSet(tc.isIPv6)
		assert.NoErrorf(t, err, "Error in sending template record: %v, isIPv6: %v", err, tc.isIPv6)
	}
}

func TestFlushQueueOnStop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIPFIXExpProc := ipfixtesting.NewMockIPFIXExportingProcess(ctrl)
	mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
	mockTempSet := ipfixentitiestesting.NewMockSet(ctrl)
	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)

	ipfixExporter := IPFIXExporter{
		externalFlowCollectorAddr:  "",
		externalFlowCollectorProto: "",
		exportingProcess:           mockIPFIXExpProc,
		templateIDv4:               testTemplateIDv4,
		templateIDv6:               testTemplateIDv6,
		registry:                   mockIPFIXRegistry,
		set:                        mockTempSet,
		observationDomainID:        testObservationDomainID,
		deque:                      deque.New(),
		queueSize:                  maxQueueSize,
		// something arbitrarily large
		sendInterval: time.Hour,
	}
	testTemplateID := testTemplateIDv4

	qRecord := queuedRecord{
		record:       mockRecord,
		isRecordIPv6: false,
	}

	ipfixExporter.deque.PushBack(qRecord)

	sendCompleted := false
	mockTempSet.EXPECT().ResetSet()
	mockTempSet.EXPECT().PrepareSet(gomock.Any(), testTemplateID).Return(nil)
	mockRecord.EXPECT().GetOrderedElementList().Return(nil)
	mockTempSet.EXPECT().AddRecord(gomock.Any(), testTemplateID).Return(nil)
	mockIPFIXExpProc.EXPECT().SendSet(mockTempSet).Do(func(set interface{}) {
		time.Sleep(time.Second)
		// this is not technically thread-safe, but we don't really care
		// for the sake of this test. If the IPFIXExporter
		// implementation is correct, there will not actually be any
		// concurrent access to sendCompleted.
		sendCompleted = true
	}).Return(0, nil)
	mockIPFIXExpProc.EXPECT().CloseConnToCollector()

	ipfixExporter.Start()
	// this should bock for about 1 second, which is the duration by which
	// we delay the SendSet call above.
	ipfixExporter.Stop()
	assert.True(t, sendCompleted, "queue not flushed on stop")
}

func TestUpdateOptions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIPFIXExpProc := ipfixtesting.NewMockIPFIXExportingProcess(ctrl)
	mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
	mockTempSet := ipfixentitiestesting.NewMockSet(ctrl)
	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)

	// we override the initIPFIXExportingProcess var function: it will
	// simply set the exportingProcess member field of the ipfixExporter to
	// our mock instance.
	// note that even though we "update" the external flow collector address
	// as part of the test, we still use the same mock for simplicity's sake.
	initIPFIXExportingProcessSaved := initIPFIXExportingProcess
	initIPFIXExportingProcess = func(exporter *IPFIXExporter) error {
		exporter.exportingProcess = mockIPFIXExpProc
		return nil
	}
	defer func() {
		initIPFIXExportingProcess = initIPFIXExportingProcessSaved
	}()

	ipfixExporter := IPFIXExporter{
		externalFlowCollectorAddr:  "",
		externalFlowCollectorProto: "",
		templateIDv4:               testTemplateIDv4,
		templateIDv6:               testTemplateIDv6,
		registry:                   mockIPFIXRegistry,
		set:                        mockTempSet,
		observationDomainID:        testObservationDomainID,
		deque:                      deque.New(),
		queueSize:                  maxQueueSize,
		// something small for the test
		sendInterval: 100 * time.Millisecond,
	}
	testTemplateID := testTemplateIDv4

	qRecord := queuedRecord{
		record:       mockRecord,
		isRecordIPv6: false,
	}

	var setCount int32
	mockTempSet.EXPECT().ResetSet().Times(2)
	mockTempSet.EXPECT().PrepareSet(gomock.Any(), testTemplateID).Return(nil).Times(2)
	mockRecord.EXPECT().GetOrderedElementList().Return(nil).Times(2)
	mockTempSet.EXPECT().AddRecord(gomock.Any(), testTemplateID).Return(nil).Times(2)
	mockIPFIXExpProc.EXPECT().SendSet(mockTempSet).Do(func(set interface{}) {
		atomic.AddInt32(&setCount, 1)
	}).Return(0, nil).Times(2)
	mockIPFIXExpProc.EXPECT().CloseConnToCollector().Times(2)

	func() {
		ipfixExporter.dequeMutex.Lock()
		defer ipfixExporter.dequeMutex.Unlock()
		ipfixExporter.deque.PushBack(qRecord)
	}()

	ipfixExporter.Start()
	defer ipfixExporter.Stop()

	require.NoError(t, wait.Poll(ipfixExporter.sendInterval, time.Second, func() (bool, error) {
		return (atomic.LoadInt32(&setCount) >= 1), nil
	}), "timeout while waiting for first flow record to be sent (before options update)")

	const newAddr = "newAddr"
	const newProto = "newProto"

	ipfixExporter.UpdateOptions(&options.Options{
		ExternalFlowCollectorAddr:  newAddr,
		ExternalFlowCollectorProto: newProto,
	})

	func() {
		ipfixExporter.dequeMutex.Lock()
		defer ipfixExporter.dequeMutex.Unlock()
		ipfixExporter.deque.PushBack(qRecord)
	}()

	require.NoError(t, wait.Poll(ipfixExporter.sendInterval, time.Second, func() (bool, error) {
		return (atomic.LoadInt32(&setCount) >= 2), nil
	}), "timeout while waiting for second flow record to be sent (after options update)")

	assert.Equal(t, newAddr, ipfixExporter.externalFlowCollectorAddr)
	assert.Equal(t, newProto, ipfixExporter.externalFlowCollectorProto)

	assert.EqualValues(t, 2, setCount, "Invalid number of flow sets sent by exporter")
}
