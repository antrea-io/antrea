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
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixentitiestesting "github.com/vmware/go-ipfix/pkg/entities/testing"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"go.uber.org/mock/gomock"
	"k8s.io/utils/ptr"

	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
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

func TestIPFIXExporter_sendTemplateSet(t *testing.T) {
	runTest := func(t *testing.T, isIPv6 bool) {
		ctrl := gomock.NewController(t)

		mockIPFIXExpProc := ipfixtesting.NewMockIPFIXExportingProcess(ctrl)
		mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
		mockTempSet := ipfixentitiestesting.NewMockSet(ctrl)

		exporter := &IPFIXExporter{
			externalFlowCollectorAddr:  "",
			externalFlowCollectorProto: "",
			exportingProcess:           mockIPFIXExpProc,
			templateIDv4:               testTemplateIDv4,
			templateIDv6:               testTemplateIDv6,
			registry:                   mockIPFIXRegistry,
			set:                        mockTempSet,
			observationDomainID:        testObservationDomainID,
		}
		elemList := createElementList(isIPv6, mockIPFIXRegistry)
		testTemplateID := exporter.templateIDv4
		if isIPv6 {
			testTemplateID = exporter.templateIDv6
		}
		mockTempSet.EXPECT().ResetSet()
		mockTempSet.EXPECT().PrepareSet(ipfixentities.Template, testTemplateID).Return(nil)
		mockTempSet.EXPECT().AddRecordV2(elemList, testTemplateID).Return(nil)
		// Passing 0 for sentBytes as it is not used anywhere in the test. If this not a call to mock, the actual sentBytes
		// above elements: ianaInfoElements, ianaReverseInfoElements and antreaInfoElements.
		mockIPFIXExpProc.EXPECT().SendSet(mockTempSet).Return(0, nil)

		_, err := exporter.sendTemplateSet(isIPv6)
		assert.NoErrorf(t, err, "Error when sending template record")
	}

	t.Run("IPv4", func(t *testing.T) { runTest(t, false) })
	t.Run("IPv6", func(t *testing.T) { runTest(t, true) })
}

func TestIPFIXExporter_UpdateOptions(t *testing.T) {
	ctrl := gomock.NewController(t)

	mockIPFIXExpProc := ipfixtesting.NewMockIPFIXExportingProcess(ctrl)
	mockSet := ipfixentitiestesting.NewMockSet(ctrl)
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

	config := &flowaggregatorconfig.FlowAggregatorConfig{
		FlowCollector: flowaggregatorconfig.FlowCollectorConfig{
			Enable:              true,
			Address:             "",
			ObservationDomainID: ptr.To[uint32](testObservationDomainID),
			RecordFormat:        "IPFIX",
		},
	}
	ipfixExporter := IPFIXExporter{
		config:                     config.FlowCollector,
		externalFlowCollectorAddr:  "",
		externalFlowCollectorProto: "",
		templateIDv4:               testTemplateIDv4,
		templateIDv6:               testTemplateIDv6,
		set:                        mockSet,
		observationDomainID:        testObservationDomainID,
	}
	testTemplateID := testTemplateIDv4

	setCount := 0
	mockSet.EXPECT().ResetSet().Times(2)
	mockSet.EXPECT().PrepareSet(gomock.Any(), testTemplateID).Return(nil).Times(2)
	mockRecord.EXPECT().GetOrderedElementList().Return(nil).Times(2)
	mockSet.EXPECT().AddRecordV2(gomock.Any(), testTemplateID).Return(nil).Times(2)
	mockIPFIXExpProc.EXPECT().SendSet(mockSet).Do(func(set interface{}) {
		setCount += 1
	}).Return(0, nil).Times(2)
	// connection will be closed when updating the external flow collector address
	mockIPFIXExpProc.EXPECT().CloseConnToCollector()

	require.NoError(t, ipfixExporter.AddRecord(mockRecord, false))
	assert.Equal(t, 1, setCount, "Invalid number of flow sets sent by exporter")

	const newAddr = "newAddr"
	const newProto = "newProto"
	const newTemplateRefreshTimeout = 1200 * time.Second
	config.FlowCollector.Address = fmt.Sprintf("%s:%s", newAddr, newProto)
	config.FlowCollector.RecordFormat = "JSON"
	config.FlowCollector.TemplateRefreshTimeout = newTemplateRefreshTimeout.String()

	ipfixExporter.UpdateOptions(&options.Options{
		Config:                     config,
		ExternalFlowCollectorAddr:  newAddr,
		ExternalFlowCollectorProto: newProto,
		TemplateRefreshTimeout:     newTemplateRefreshTimeout,
	})

	assert.Equal(t, newAddr, ipfixExporter.externalFlowCollectorAddr)
	assert.Equal(t, newProto, ipfixExporter.externalFlowCollectorProto)
	assert.True(t, ipfixExporter.sendJSONRecord)
	assert.Equal(t, newTemplateRefreshTimeout, ipfixExporter.templateRefreshTimeout)

	require.NoError(t, ipfixExporter.AddRecord(mockRecord, false))
	assert.Equal(t, 2, setCount, "Invalid number of flow sets sent by exporter")
}

func TestIPFIXExporter_AddRecord(t *testing.T) {
	ctrl := gomock.NewController(t)

	mockIPFIXExpProc := ipfixtesting.NewMockIPFIXExportingProcess(ctrl)
	mockSet := ipfixentitiestesting.NewMockSet(ctrl)
	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)

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
		set:                        mockSet,
		observationDomainID:        testObservationDomainID,
	}
	testTemplateID := testTemplateIDv4

	mockSet.EXPECT().ResetSet()
	mockSet.EXPECT().PrepareSet(gomock.Any(), testTemplateID).Return(nil)
	mockRecord.EXPECT().GetOrderedElementList().Return(nil)
	mockSet.EXPECT().AddRecordV2(gomock.Any(), testTemplateID).Return(nil)
	mockIPFIXExpProc.EXPECT().SendSet(mockSet).Return(0, nil)

	assert.NoError(t, ipfixExporter.AddRecord(mockRecord, false))
}

func TestIPFIXExporter_initIPFIXExportingProcess_Error(t *testing.T) {
	ctrl := gomock.NewController(t)

	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)

	// we override the initIPFIXExportingProcess var function: it will
	// simply return an error.
	initIPFIXExportingProcessSaved := initIPFIXExportingProcess
	initIPFIXExportingProcess = func(exporter *IPFIXExporter) error {
		return fmt.Errorf("error when initializing IPFIX exporting process")
	}
	defer func() {
		initIPFIXExportingProcess = initIPFIXExportingProcessSaved
	}()

	ipfixExporter := IPFIXExporter{
		externalFlowCollectorAddr:  "",
		externalFlowCollectorProto: "",
	}

	assert.Error(t, ipfixExporter.AddRecord(mockRecord, false))
}

func TestIPFIXExporter_sendRecord_Error(t *testing.T) {
	ctrl := gomock.NewController(t)

	mockIPFIXExpProc := ipfixtesting.NewMockIPFIXExportingProcess(ctrl)
	mockSet := ipfixentitiestesting.NewMockSet(ctrl)
	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)

	ipfixExporter := IPFIXExporter{
		externalFlowCollectorAddr:  "",
		externalFlowCollectorProto: "",
		exportingProcess:           mockIPFIXExpProc,
		templateIDv4:               testTemplateIDv4,
		templateIDv6:               testTemplateIDv6,
		set:                        mockSet,
		observationDomainID:        testObservationDomainID,
	}
	testTemplateID := testTemplateIDv4

	mockSet.EXPECT().ResetSet()
	mockSet.EXPECT().PrepareSet(gomock.Any(), testTemplateID).Return(nil)
	mockRecord.EXPECT().GetOrderedElementList().Return(nil)
	mockSet.EXPECT().AddRecordV2(gomock.Any(), testTemplateID).Return(nil)
	mockIPFIXExpProc.EXPECT().SendSet(mockSet).Return(0, fmt.Errorf("send error"))
	mockIPFIXExpProc.EXPECT().CloseConnToCollector()

	assert.Error(t, ipfixExporter.AddRecord(mockRecord, false))
}

func createElementList(isIPv6 bool, mockIPFIXRegistry *ipfixtesting.MockIPFIXRegistry) []ipfixentities.InfoElementWithValue {
	ianaInfoElements := infoelements.IANAInfoElementsIPv4
	antreaInfoElements := infoelements.AntreaInfoElementsIPv4
	if isIPv6 {
		ianaInfoElements = infoelements.IANAInfoElementsIPv6
		antreaInfoElements = infoelements.AntreaInfoElementsIPv6
	}
	// Following consists of all elements that are in ianaInfoElements and antreaInfoElements (globals)
	// Only the element name is needed, other arguments have dummy values
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
	for _, ie := range infoelements.AntreaLabelsElementList {
		elemList = append(elemList, createElement(ie, ipfixregistry.AntreaEnterpriseID))
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
	}
	elemList = append(elemList, createElement("clusterId", ipfixregistry.AntreaEnterpriseID))
	mockIPFIXRegistry.EXPECT().GetInfoElement("clusterId", ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)

	return elemList
}

func TestInitExportingProcess(t *testing.T) {
	clusterUUID := uuid.New()

	t.Run("tcp success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
		opt := &options.Options{}
		opt.Config = &flowaggregatorconfig.FlowAggregatorConfig{}
		flowaggregatorconfig.SetConfigDefaults(opt.Config)
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer listener.Close()
		opt.ExternalFlowCollectorAddr = listener.Addr().String()
		opt.ExternalFlowCollectorProto = listener.Addr().Network()
		opt.Config.FlowCollector.RecordFormat = "JSON"
		createElementList(false, mockIPFIXRegistry)
		createElementList(true, mockIPFIXRegistry)
		exp := NewIPFIXExporter(clusterUUID, opt, mockIPFIXRegistry)
		err = exp.initExportingProcess()
		assert.NoError(t, err)
	})
	t.Run("udp success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
		opt := &options.Options{}
		opt.Config = &flowaggregatorconfig.FlowAggregatorConfig{}
		flowaggregatorconfig.SetConfigDefaults(opt.Config)
		udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		require.NoError(t, err)
		listener, err := net.ListenUDP("udp", udpAddr)
		require.NoError(t, err)
		defer listener.Close()
		opt.ExternalFlowCollectorAddr = listener.LocalAddr().String()
		opt.ExternalFlowCollectorProto = listener.LocalAddr().Network()
		opt.Config.FlowCollector.RecordFormat = "JSON"
		createElementList(false, mockIPFIXRegistry)
		createElementList(true, mockIPFIXRegistry)
		exp := NewIPFIXExporter(clusterUUID, opt, mockIPFIXRegistry)
		err = exp.initExportingProcess()
		assert.NoError(t, err)
	})
	t.Run("tcp failure", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
		opt := &options.Options{}
		opt.Config = &flowaggregatorconfig.FlowAggregatorConfig{}
		flowaggregatorconfig.SetConfigDefaults(opt.Config)
		// dialing this address is guaranteed to fail (we use 0 as the port number)
		opt.ExternalFlowCollectorAddr = "127.0.0.1:0"
		opt.ExternalFlowCollectorProto = "tcp"
		exp := NewIPFIXExporter(clusterUUID, opt, mockIPFIXRegistry)
		err := exp.initExportingProcess()
		assert.ErrorContains(t, err, "got error when initializing IPFIX exporting process: dial tcp 127.0.0.1:0:")
	})
}

func TestNewIPFIXExporterObservationDomainID(t *testing.T) {
	clusterUUID := uuid.New()
	testCases := []struct {
		name                        string
		userObservationDomainID     *uint32
		expectedObservationDomainID uint32
	}{
		{"user-provided", ptr.To[uint32](testObservationDomainID), testObservationDomainID},
		{"generated from clusterUUID", nil, genObservationDomainID(clusterUUID)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
			opt := &options.Options{}
			opt.Config = &flowaggregatorconfig.FlowAggregatorConfig{}
			flowaggregatorconfig.SetConfigDefaults(opt.Config)
			opt.Config.FlowCollector.ObservationDomainID = tc.userObservationDomainID
			exp := NewIPFIXExporter(clusterUUID, opt, mockIPFIXRegistry)
			assert.Equal(t, clusterUUID, exp.clusterUUID)
			assert.Equal(t, tc.expectedObservationDomainID, exp.observationDomainID)
		})
	}
}
