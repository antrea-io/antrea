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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"
	"github.com/google/uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"go.uber.org/mock/gomock"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	flowaggregatorconfig "antrea.io/antrea/v2/pkg/config/flowaggregator"
	"antrea.io/antrea/v2/pkg/flowaggregator/infoelements"
	"antrea.io/antrea/v2/pkg/flowaggregator/options"
	flowaggregatortesting "antrea.io/antrea/v2/pkg/flowaggregator/testing"
	ipfixtesting "antrea.io/antrea/v2/pkg/ipfix/testing"
	"antrea.io/antrea/v2/pkg/util/tlstest"
	flowaggregatorconfig "antrea.io/antrea/v2/pkg/config/flowaggregator"
	"antrea.io/antrea/v2/pkg/flowaggregator/infoelements"
	"antrea.io/antrea/v2/pkg/flowaggregator/options"
	flowaggregatortesting "antrea.io/antrea/v2/pkg/flowaggregator/testing"
	ipfixtesting "antrea.io/antrea/v2/pkg/ipfix/testing"
	"antrea.io/antrea/v2/pkg/util/tlstest"
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
func TestIPFIXExporter_createAndSendTemplate(t *testing.T) {
	runTest := func(t *testing.T, isIPv6 bool) {
		ctrl := gomock.NewController(t)
		mockIPFIXExpProc := ipfixtesting.NewMockIPFIXExportingProcess(ctrl)
		mockIPFIXBufferedExp := ipfixtesting.NewMockIPFIXBufferedExporter(ctrl)
		mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
		testTemplateID := testTemplateIDv4
		if isIPv6 {
			testTemplateID = testTemplateIDv6
		}
		mockIPFIXExpProc.EXPECT().NewTemplateID().Return(testTemplateID)
		exporter := &IPFIXExporter{
			externalFlowCollectorAddr:  "",
			externalFlowCollectorProto: "",
			exportingProcess:           mockIPFIXExpProc,
			bufferedExporter:           mockIPFIXBufferedExp,
			registry:                   mockIPFIXRegistry,
			aggregatorMode:             flowaggregatorconfig.AggregatorModeAggregate,
			observationDomainID:        testObservationDomainID,
			clock:                      clock.RealClock{},
		}
		elemList := createElementList(flowaggregatorconfig.AggregatorModeAggregate, isIPv6, mockIPFIXRegistry)
		mockIPFIXBufferedExp.EXPECT().AddRecord(gomock.Cond(func(record ipfixentities.Record) bool {
			return record.GetTemplateID() == testTemplateID && reflect.DeepEqual(record.GetOrderedElementList(), elemList)
		})).Return(nil)
		assert.NoErrorf(t, exporter.createAndSendTemplate(isIPv6), "Error when sending template record")
	}
	t.Run("IPv4", func(t *testing.T) { runTest(t, false) })
	t.Run("IPv6", func(t *testing.T) { runTest(t, true) })
}
func TestIPFIXExporter_UpdateOptions(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockIPFIXExpProc := ipfixtesting.NewMockIPFIXExportingProcess(ctrl)
	mockIPFIXBufferedExp := ipfixtesting.NewMockIPFIXBufferedExporter(ctrl)
	mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
	record := flowaggregatortesting.PrepareTestFlowRecord(true)
	// we override the initIPFIXExportingProcess var function: it will
	// simply set the exportingProcess and bufferedExporter member fields of
	// the ipfixExporter to our mocks.
	// note that even though we "update" the external flow collector address
	// as part of the test, we still use the same mocks for simplicity's sake.
	initIPFIXExportingProcessSaved := initIPFIXExportingProcess
	initIPFIXExportingProcess = func(exporter *IPFIXExporter) error {
		exporter.exportingProcess = mockIPFIXExpProc
		exporter.bufferedExporter = mockIPFIXBufferedExp
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
	ipfixExporter := &IPFIXExporter{
		config:                     config.FlowCollector,
		externalFlowCollectorAddr:  "",
		externalFlowCollectorProto: "",
		templateIDv4:               testTemplateIDv4,
		templateIDv6:               testTemplateIDv6,
		registry:                   mockIPFIXRegistry,
		aggregatorMode:             flowaggregatorconfig.AggregatorModeAggregate,
		observationDomainID:        testObservationDomainID,
		clock:                      clock.RealClock{},
	}
	createElementList(flowaggregatorconfig.AggregatorModeAggregate, false, mockIPFIXRegistry)
	ipfixExporter.elementsV4, _ = ipfixExporter.prepareElements(false)
	setCount := 0
	mockIPFIXBufferedExp.EXPECT().AddRecord(gomock.Cond(func(record ipfixentities.Record) bool {
		return record.GetTemplateID() == testTemplateIDv4
	})).Do(func(record ipfixentities.Record) {
		setCount += 1
	}).Return(nil).Times(2)
	// connection will be closed when updating the external flow collector address
	mockIPFIXBufferedExp.EXPECT().Flush()
	mockIPFIXExpProc.EXPECT().CloseConnToCollector()
	require.NoError(t, ipfixExporter.AddRecord(record, false))
	assert.Equal(t, 1, setCount, "Invalid number of flow sets sent by exporter")
	const newAddr = "newAddr"
	const newProto = "newProto"
	const newTemplateRefreshTimeout = 1200 * time.Second
	config.FlowCollector.Address = fmt.Sprintf("%s:%s", newAddr, newProto)
	config.FlowCollector.RecordFormat = "JSON"
	config.FlowCollector.TemplateRefreshTimeout = newTemplateRefreshTimeout.String()
	config.FlowCollector.TLS.Enable = true
	config.FlowCollector.TLS.MinVersion = "VersionTLS13"
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
	assert.True(t, ipfixExporter.tls.enable)
	assert.Equal(t, uint16(tls.VersionTLS13), ipfixExporter.tls.minVersion)
	require.NoError(t, ipfixExporter.AddRecord(record, false))
	assert.Equal(t, 2, setCount, "Invalid number of flow sets sent by exporter")
}
func TestIPFIXExporter_Stop(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockIPFIXExpProc := ipfixtesting.NewMockIPFIXExportingProcess(ctrl)
	mockIPFIXBufferedExp := ipfixtesting.NewMockIPFIXBufferedExporter(ctrl)
	mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
	record := flowaggregatortesting.PrepareTestFlowRecord(true)
	initIPFIXExportingProcessSaved := initIPFIXExportingProcess
	initIPFIXExportingProcess = func(exporter *IPFIXExporter) error {
		exporter.exportingProcess = mockIPFIXExpProc
		exporter.bufferedExporter = mockIPFIXBufferedExp
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
	ipfixExporter := &IPFIXExporter{
		config:                     config.FlowCollector,
		externalFlowCollectorAddr:  "",
		externalFlowCollectorProto: "",
		templateIDv4:               testTemplateIDv4,
		templateIDv6:               testTemplateIDv6,
		registry:                   mockIPFIXRegistry,
		aggregatorMode:             flowaggregatorconfig.AggregatorModeAggregate,
		observationDomainID:        testObservationDomainID,
		clock:                      clock.RealClock{},
	}
	createElementList(flowaggregatorconfig.AggregatorModeAggregate, false, mockIPFIXRegistry)
	ipfixExporter.elementsV4, _ = ipfixExporter.prepareElements(false)
	mockIPFIXBufferedExp.EXPECT().AddRecord(gomock.Cond(func(record ipfixentities.Record) bool {
		return record.GetTemplateID() == testTemplateIDv4
	})).Return(nil)
	mockIPFIXBufferedExp.EXPECT().Flush()
	mockIPFIXExpProc.EXPECT().CloseConnToCollector()
	require.NoError(t, ipfixExporter.AddRecord(record, false))
	ipfixExporter.Stop()
	assert.Nil(t, ipfixExporter.exportingProcess)
}
func TestIPFIXExporter_AddRecord(t *testing.T) {
	testCases := []struct {
		aggregatorMode flowaggregatorconfig.AggregatorMode
		isIPv6         bool
	}{
		{flowaggregatorconfig.AggregatorModeAggregate, false},
		{flowaggregatorconfig.AggregatorModeAggregate, true},
		{flowaggregatorconfig.AggregatorModeProxy, false},
		{flowaggregatorconfig.AggregatorModeProxy, true},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s-%t", tc.aggregatorMode, tc.isIPv6), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIPFIXBufferedExp := ipfixtesting.NewMockIPFIXBufferedExporter(ctrl)
			mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
			record := flowaggregatortesting.PrepareTestFlowRecord(true)
			initIPFIXExportingProcessSaved := initIPFIXExportingProcess
			initIPFIXExportingProcess = func(exporter *IPFIXExporter) error {
				exporter.bufferedExporter = mockIPFIXBufferedExp
				return nil
			}
			defer func() {
				initIPFIXExportingProcess = initIPFIXExportingProcessSaved
			}()
			ipfixExporter := &IPFIXExporter{
				externalFlowCollectorAddr:  "",
				externalFlowCollectorProto: "",
				templateIDv4:               testTemplateIDv4,
				templateIDv6:               testTemplateIDv6,
				registry:                   mockIPFIXRegistry,
				aggregatorMode:             tc.aggregatorMode,
				observationDomainID:        testObservationDomainID,
				clusterID:                  "foobar",
				clock:                      clock.RealClock{},
			}
			createElementList(tc.aggregatorMode, false, mockIPFIXRegistry)
			ipfixExporter.elementsV4, _ = ipfixExporter.prepareElements(false)
			createElementList(tc.aggregatorMode, true, mockIPFIXRegistry)
			ipfixExporter.elementsV6, _ = ipfixExporter.prepareElements(true)
			testTemplateID := testTemplateIDv4
			if tc.isIPv6 {
				testTemplateID = testTemplateIDv6
			}
			mockIPFIXBufferedExp.EXPECT().AddRecord(gomock.Cond(func(record ipfixentities.Record) bool {
				elems := record.GetOrderedElementList()
				// We make sure that all elements have been set by checking the last element.
				// TODO: also validate record contents?
				return record.GetTemplateID() == testTemplateID && !elems[len(elems)-1].IsValueEmpty()
			})).Return(nil)
			assert.NoError(t, ipfixExporter.AddRecord(record, tc.isIPv6))
		})
	}
}
func TestIPFIXExporter_initIPFIXExportingProcess_Error(t *testing.T) {
	record := flowaggregatortesting.PrepareTestFlowRecord(true)
	// we override the initIPFIXExportingProcess var function: it will
	// simply return an error.
	initIPFIXExportingProcessSaved := initIPFIXExportingProcess
	initIPFIXExportingProcess = func(exporter *IPFIXExporter) error {
		return fmt.Errorf("error when initializing IPFIX exporting process")
	}
	defer func() {
		initIPFIXExportingProcess = initIPFIXExportingProcessSaved
	}()
	ipfixExporter := &IPFIXExporter{
		externalFlowCollectorAddr:  "",
		externalFlowCollectorProto: "",
		aggregatorMode:             flowaggregatorconfig.AggregatorModeAggregate,
		clock:                      clock.RealClock{},
	}
	assert.Error(t, ipfixExporter.AddRecord(record, false))
}
func TestIPFIXExporter_sendRecord_Error(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockIPFIXExpProc := ipfixtesting.NewMockIPFIXExportingProcess(ctrl)
	mockIPFIXBufferedExp := ipfixtesting.NewMockIPFIXBufferedExporter(ctrl)
	mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
	record := flowaggregatortesting.PrepareTestFlowRecord(true)
	ipfixExporter := &IPFIXExporter{
		externalFlowCollectorAddr:  "",
		externalFlowCollectorProto: "",
		exportingProcess:           mockIPFIXExpProc,
		bufferedExporter:           mockIPFIXBufferedExp,
		templateIDv4:               testTemplateIDv4,
		templateIDv6:               testTemplateIDv6,
		registry:                   mockIPFIXRegistry,
		aggregatorMode:             flowaggregatorconfig.AggregatorModeAggregate,
		observationDomainID:        testObservationDomainID,
		clock:                      clock.RealClock{},
	}
	createElementList(flowaggregatorconfig.AggregatorModeAggregate, false, mockIPFIXRegistry)
	ipfixExporter.elementsV4, _ = ipfixExporter.prepareElements(false)
	mockIPFIXBufferedExp.EXPECT().AddRecord(gomock.Cond(func(record ipfixentities.Record) bool {
		return record.GetTemplateID() == testTemplateIDv4
	})).Return(fmt.Errorf("send error"))
	mockIPFIXExpProc.EXPECT().CloseConnToCollector()
	assert.Error(t, ipfixExporter.AddRecord(record, false))
}
func createElementList(mode flowaggregatorconfig.AggregatorMode, isIPv6 bool, mockIPFIXRegistry *ipfixtesting.MockIPFIXRegistry) []ipfixentities.InfoElementWithValue {
	ianaInfoElements := infoelements.IANAInfoElementsIPv4
	antreaInfoElements := infoelements.AntreaInfoElementsIPv4
	if isIPv6 {
		ianaInfoElements = infoelements.IANAInfoElementsIPv6
		antreaInfoElements = infoelements.AntreaInfoElementsIPv6
	}
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
	if mode == flowaggregatorconfig.AggregatorModeAggregate {
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
	}
	for _, ie := range infoelements.AntreaLabelsElementList {
		elemList = append(elemList, createElement(ie, ipfixregistry.AntreaEnterpriseID))
		mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
	}
	elemList = append(elemList, createElement("clusterId", ipfixregistry.AntreaEnterpriseID))
	mockIPFIXRegistry.EXPECT().GetInfoElement("clusterId", ipfixregistry.AntreaEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
	if mode == flowaggregatorconfig.AggregatorModeProxy {
		for _, ie := range infoelements.IANAProxyModeElementList {
			elemList = append(elemList, createElement(ie, ipfixregistry.IANAEnterpriseID))
			mockIPFIXRegistry.EXPECT().GetInfoElement(ie, ipfixregistry.IANAEnterpriseID).Return(elemList[len(elemList)-1].GetInfoElement(), nil)
		}
	}
	return elemList
}
func generateLocalhostCert(t *testing.T, isClient bool) ([]byte, []byte) {
	certPEM, keyPEM, err := tlstest.GenerateCert(
		[]string{"localhost", "127.0.0.1"},
		time.Unix(0, 0),
		100*365*24*time.Hour,
		true,
		isClient,
		0,
		"P256",
		false,
	)
	require.NoError(t, err)
	return certPEM, keyPEM
}
// runTestTLSServer starts a test TLS server using the provided config. The server will be closed
// (alongside all active connections) when t.Context() is cancelled. All the data received across
// all connections will be sent on the recvCh channel.
// If any unexpected error is encountered, the test will be marked as failed.
func runTestTLSServer(t *testing.T, tlsConfig *tls.Config, recvCh chan<- []byte) (string, string) {
	ctx := t.Context()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	handleConnection := func(conn net.Conn) {
		defer conn.Close()
		go func() {
			for {
				b := make([]byte, 1024)
				// Note that if the client certificate is invalid, we will not see
				// an error until the first Read.
				_, err := conn.Read(b)
				if err == io.EOF {
					return
				}
				// ignore error if context is cancelled
				select {
				case <-ctx.Done():
					return
				default:
					break
				}
				if !assert.NoError(t, err) {
					return
				}
				recvCh <- b
			}
		}()
		<-ctx.Done()
	}
	go func() {
		for {
			conn, err := listener.Accept()
			// ignore error if context is cancelled
			select {
			case <-ctx.Done():
				return
			default:
				break
			}
			if !assert.NoError(t, err) {
				return
			}
			go handleConnection(conn)
		}
	}()
	return listener.Addr().Network(), listener.Addr().String()
}
func TestInitExportingProcess(t *testing.T) {
	clusterUUID := uuid.New()
	t.Run("tcp success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
		opt := &options.Options{
			AggregatorMode: flowaggregatorconfig.AggregatorModeAggregate,
		}
		opt.Config = &flowaggregatorconfig.FlowAggregatorConfig{}
		flowaggregatorconfig.SetConfigDefaults(opt.Config)
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer listener.Close()
		opt.ExternalFlowCollectorAddr = listener.Addr().String()
		opt.ExternalFlowCollectorProto = listener.Addr().Network()
		opt.Config.FlowCollector.RecordFormat = "JSON"
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, false, mockIPFIXRegistry)
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, mockIPFIXRegistry)
		exp := NewIPFIXExporter(clusterUUID, clusterUUID.String(), opt, mockIPFIXRegistry)
		err = exp.initExportingProcess()
		assert.NoError(t, err)
	})
	t.Run("udp success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
		opt := &options.Options{
			AggregatorMode: flowaggregatorconfig.AggregatorModeAggregate,
		}
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
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, false, mockIPFIXRegistry)
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, mockIPFIXRegistry)
		exp := NewIPFIXExporter(clusterUUID, clusterUUID.String(), opt, mockIPFIXRegistry)
		err = exp.initExportingProcess()
		assert.NoError(t, err)
	})
	t.Run("tcp failure", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
		opt := &options.Options{
			AggregatorMode: flowaggregatorconfig.AggregatorModeAggregate,
		}
		opt.Config = &flowaggregatorconfig.FlowAggregatorConfig{}
		flowaggregatorconfig.SetConfigDefaults(opt.Config)
		// dialing this address is guaranteed to fail (we use 0 as the port number)
		opt.ExternalFlowCollectorAddr = "127.0.0.1:0"
		opt.ExternalFlowCollectorProto = "tcp"
		exp := NewIPFIXExporter(clusterUUID, clusterUUID.String(), opt, mockIPFIXRegistry)
		err := exp.initExportingProcess()
		assert.ErrorContains(t, err, "got error when initializing IPFIX exporting process: dial tcp 127.0.0.1:0:")
	})
	t.Run("tls success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
		serverCertPEM, serverKeyPEM := generateLocalhostCert(t, false)
		serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
		require.NoError(t, err)
		defaultFS = afero.NewMemMapFs()
		t.Cleanup(func() { defaultFS = afero.NewOsFs() })
		// the certificate is used as the CA
		require.NoError(t, afero.WriteFile(defaultFS, filepath.Join(flowCollectorCertDir, "ca.crt"), serverCertPEM, 0644))
		opt := &options.Options{
			AggregatorMode: flowaggregatorconfig.AggregatorModeAggregate,
		}
		opt.Config = &flowaggregatorconfig.FlowAggregatorConfig{}
		flowaggregatorconfig.SetConfigDefaults(opt.Config)
		opt.Config.FlowCollector.TLS.Enable = true
		opt.Config.FlowCollector.TLS.CASecretName = "server-ca"
		// It seems that (m)TLS testing requires an actual server. Using a listener which
		// never calls Accept (what we have for the tests above) does not work and causes
		// the test to hang.
		// TODO: it would be more convenient to use the actual collector from the go-ipfix
		// library, but some changes are necessary in the library first (e.g., the ability
		// to provide a net.Listener instead of an address).
		recvCh := make(chan []byte, 10)
		opt.ExternalFlowCollectorProto, opt.ExternalFlowCollectorAddr = runTestTLSServer(t, &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			MinVersion:   tls.VersionTLS12,
		}, recvCh)
		// Use IPFIX to guarantee that data is sent (and should be received by the server):
		// in this case the data is the template records.
		opt.Config.FlowCollector.RecordFormat = "IPFIX"
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, false, mockIPFIXRegistry)
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, mockIPFIXRegistry)
		exp := NewIPFIXExporter(clusterUUID, clusterUUID.String(), opt, mockIPFIXRegistry)
		defer exp.Stop()
		err = exp.initExportingProcess()
		assert.NoError(t, err)
		select {
		case <-recvCh:
			break
		case <-time.After(1 * time.Second):
			assert.Fail(t, "No data received by server")
		}
	})
	t.Run("mtls success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
		serverCertPEM, serverKeyPEM := generateLocalhostCert(t, false)
		serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
		clientCertPEM, clientKeyPEM := generateLocalhostCert(t, true)
		require.NoError(t, err)
		defaultFS = afero.NewMemMapFs()
		t.Cleanup(func() { defaultFS = afero.NewOsFs() })
		// the certificate is used as the CA
		require.NoError(t, afero.WriteFile(defaultFS, filepath.Join(flowCollectorCertDir, "ca.crt"), serverCertPEM, 0644))
		require.NoError(t, afero.WriteFile(defaultFS, filepath.Join(flowCollectorCertDir, "tls.crt"), clientCertPEM, 0644))
		require.NoError(t, afero.WriteFile(defaultFS, filepath.Join(flowCollectorCertDir, "tls.key"), clientKeyPEM, 0644))
		opt := &options.Options{
			AggregatorMode: flowaggregatorconfig.AggregatorModeAggregate,
		}
		opt.Config = &flowaggregatorconfig.FlowAggregatorConfig{}
		flowaggregatorconfig.SetConfigDefaults(opt.Config)
		opt.Config.FlowCollector.TLS.Enable = true
		opt.Config.FlowCollector.TLS.CASecretName = "server-ca"
		opt.Config.FlowCollector.TLS.ClientSecretName = "client-tls"
		clientCAs := x509.NewCertPool()
		// the certificate is used as the CA
		require.True(t, clientCAs.AppendCertsFromPEM(clientCertPEM))
		recvCh := make(chan []byte, 10)
		opt.ExternalFlowCollectorProto, opt.ExternalFlowCollectorAddr = runTestTLSServer(t, &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    clientCAs,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS12,
		}, recvCh)
		opt.Config.FlowCollector.RecordFormat = "IPFIX"
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, false, mockIPFIXRegistry)
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, mockIPFIXRegistry)
		exp := NewIPFIXExporter(clusterUUID, clusterUUID.String(), opt, mockIPFIXRegistry)
		defer exp.Stop()
		err = exp.initExportingProcess()
		assert.NoError(t, err)
		select {
		case <-recvCh:
			break
		case <-time.After(1 * time.Second):
			assert.Fail(t, "No data received by server")
		}
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
			exp := NewIPFIXExporter(clusterUUID, clusterUUID.String(), opt, mockIPFIXRegistry)
			assert.Equal(t, clusterUUID, exp.clusterUUID)
			assert.Equal(t, tc.expectedObservationDomainID, exp.observationDomainID)
		})
	}
}
func TestInitExportingProcessWithBackoff(t *testing.T) {
	errCh := make(chan error, 1)
	initIPFIXExportingProcessSaved := initIPFIXExportingProcess
	initIPFIXExportingProcess = func(exporter *IPFIXExporter) error {
		select {
		case err := <-errCh:
			return err
		default:
			return fmt.Errorf("no available error in channel")
		}
	}
	defer func() {
		initIPFIXExportingProcess = initIPFIXExportingProcessSaved
	}()
	clusterUUID := uuid.New()
	opt := &options.Options{
		AggregatorMode: flowaggregatorconfig.AggregatorModeProxy,
		Config:         &flowaggregatorconfig.FlowAggregatorConfig{},
	}
	flowaggregatorconfig.SetConfigDefaults(opt.Config)
	clock := clocktesting.NewFakeClock(time.Now())
	exp := newIPFIXExporterWithClock(clusterUUID, clusterUUID.String(), opt, nil, clock)
	require.NotNil(t, exp)
	setError := func(err error) {
		select {
		case errCh <- err:
			break
		default:
			require.Fail(t, "channel write should not block")
		}
	}
	setError(nil)
	require.NoError(t, exp.initExportingProcessWithBackoff())
	connectionErr := fmt.Errorf("connection error")
	setError(connectionErr)
	require.ErrorIs(t, exp.initExportingProcessWithBackoff(), connectionErr)
	// Connection error starts the backoff, first step is 1s (no jitter).
	require.ErrorIs(t, exp.initExportingProcessWithBackoff(), ErrIPFIXExporterBackoff)
	require.Equal(t, clock.Now().Add(1*time.Second), exp.initNextAttempt)
	require.ErrorIs(t, exp.initExportingProcessWithBackoff(), ErrIPFIXExporterBackoff)
	// A second error will cause a 2s backoff.
	setError(connectionErr)
	clock.SetTime(exp.initNextAttempt)
	require.ErrorIs(t, exp.initExportingProcessWithBackoff(), connectionErr)
	require.Equal(t, clock.Now().Add(2*time.Second), exp.initNextAttempt)
	require.ErrorIs(t, exp.initExportingProcessWithBackoff(), ErrIPFIXExporterBackoff)
	setError(nil)
	clock.SetTime(exp.initNextAttempt)
	require.NoError(t, exp.initExportingProcessWithBackoff())
	// After a successful initialization, backoff should be reset.
	setError(connectionErr)
	require.ErrorIs(t, exp.initExportingProcessWithBackoff(), connectionErr)
	require.Equal(t, clock.Now().Add(1*time.Second), exp.initNextAttempt)
}
