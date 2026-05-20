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
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"go.uber.org/mock/gomock"
	"k8s.io/utils/ptr"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	flowaggregatorconfig "antrea.io/antrea/v2/pkg/config/flowaggregator"
	"antrea.io/antrea/v2/pkg/flowaggregator/infoelements"
	"antrea.io/antrea/v2/pkg/flowaggregator/options"
	"antrea.io/antrea/v2/pkg/flowaggregator/ringbuffer"
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

func TestIPFIXExporter_Run(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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

		ipfixExporter := &IPFIXExporter{
			externalFlowCollectorAddr:  "",
			externalFlowCollectorProto: "",
			includeK8sNames:            true,
			templateIDv4:               testTemplateIDv4,
			templateIDv6:               testTemplateIDv6,
			registry:                   mockIPFIXRegistry,
			aggregatorMode:             flowaggregatorconfig.AggregatorModeAggregate,
			observationDomainID:        testObservationDomainID,
		}
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, false, false, mockIPFIXRegistry)
		ipfixExporter.elementsV4, _ = ipfixExporter.prepareElements(false)
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, false, true, mockIPFIXRegistry)
		ipfixExporter.elementsV6, _ = ipfixExporter.prepareElements(true)

		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](8)
		defer buf.Shutdown()

		mockIPFIXBufferedExp.EXPECT().AddRecord(gomock.Cond(func(record ipfixentities.Record) bool {
			return record.GetTemplateID() == testTemplateIDv4
		})).Return(nil)
		// Expect flush on periodic tick and/or shutdown.
		mockIPFIXBufferedExp.EXPECT().Flush().Return(nil).AnyTimes()
		mockIPFIXExpProc.EXPECT().CloseConnToCollector().AnyTimes()

		ctx, cancel := context.WithCancel(t.Context())
		go ipfixExporter.Run(ctx, buf)

		// Wait until Run's goroutine is blocked in consumer.ConsumeMultiple() — this
		// guarantees the consumer has been created and will see the next Produce.
		synctest.Wait()
		buf.Produce(record)
		// Wait for the Run goroutine to process the record (calls AddRecord).
		synctest.Wait()

		// Trigger the periodic flush by advancing fake time past flushInterval.
		time.Sleep(flushInterval)
		synctest.Wait()

		cancel()
	})
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
			includeK8sNames:            true,
			registry:                   mockIPFIXRegistry,
			aggregatorMode:             flowaggregatorconfig.AggregatorModeAggregate,
			observationDomainID:        testObservationDomainID,
		}
		elemList := createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, false, isIPv6, mockIPFIXRegistry)
		mockIPFIXBufferedExp.EXPECT().AddRecord(gomock.Cond(func(record ipfixentities.Record) bool {
			return record.GetTemplateID() == testTemplateID && reflect.DeepEqual(record.GetOrderedElementList(), elemList)
		})).Return(nil)

		assert.NoErrorf(t, exporter.createAndSendTemplate(isIPv6), "Error when sending template record")
	}

	t.Run("IPv4", func(t *testing.T) { runTest(t, false) })
	t.Run("IPv6", func(t *testing.T) { runTest(t, true) })
}

func TestIPFIXExporter_flush(t *testing.T) {
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
		includeK8sNames:            true,
		templateIDv4:               testTemplateIDv4,
		templateIDv6:               testTemplateIDv6,
		registry:                   mockIPFIXRegistry,
		aggregatorMode:             flowaggregatorconfig.AggregatorModeAggregate,
		observationDomainID:        testObservationDomainID,
	}
	createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, false, false, mockIPFIXRegistry)
	ipfixExporter.elementsV4, _ = ipfixExporter.prepareElements(false)

	mockIPFIXBufferedExp.EXPECT().AddRecord(gomock.Cond(func(record ipfixentities.Record) bool {
		return record.GetTemplateID() == testTemplateIDv4
	})).Return(nil)
	mockIPFIXBufferedExp.EXPECT().Flush().Return(nil)

	require.NoError(t, ipfixExporter.sendRecord(record, false))
	require.NoError(t, ipfixExporter.flush())
}

func TestIPFIXExporter_sendRecord(t *testing.T) {
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

			mockIPFIXExpProc := ipfixtesting.NewMockIPFIXExportingProcess(ctrl)
			mockIPFIXBufferedExp := ipfixtesting.NewMockIPFIXBufferedExporter(ctrl)
			mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
			record := flowaggregatortesting.PrepareTestFlowRecord(true)

			ipfixExporter := &IPFIXExporter{
				externalFlowCollectorAddr:  "",
				externalFlowCollectorProto: "",
				exportingProcess:           mockIPFIXExpProc,
				bufferedExporter:           mockIPFIXBufferedExp,
				includeK8sNames:            true,
				templateIDv4:               testTemplateIDv4,
				templateIDv6:               testTemplateIDv6,
				registry:                   mockIPFIXRegistry,
				aggregatorMode:             tc.aggregatorMode,
				observationDomainID:        testObservationDomainID,
				clusterID:                  "foobar",
			}
			createElementList(tc.aggregatorMode, true, false, false, mockIPFIXRegistry)
			ipfixExporter.elementsV4, _ = ipfixExporter.prepareElements(false)
			createElementList(tc.aggregatorMode, true, false, true, mockIPFIXRegistry)
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
			assert.NoError(t, ipfixExporter.sendRecord(record, tc.isIPv6))
		})
	}
}

func TestIPFIXExporter_sendRecord_NoExportingProcess(t *testing.T) {
	record := flowaggregatortesting.PrepareTestFlowRecord(true)

	ipfixExporter := &IPFIXExporter{
		externalFlowCollectorAddr:  "",
		externalFlowCollectorProto: "",
		includeK8sNames:            true,
		aggregatorMode:             flowaggregatorconfig.AggregatorModeAggregate,
	}

	assert.Error(t, ipfixExporter.sendRecord(record, false))
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
		includeK8sNames:            true,
		templateIDv4:               testTemplateIDv4,
		templateIDv6:               testTemplateIDv6,
		registry:                   mockIPFIXRegistry,
		aggregatorMode:             flowaggregatorconfig.AggregatorModeAggregate,
		observationDomainID:        testObservationDomainID,
	}
	createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, false, false, mockIPFIXRegistry)
	ipfixExporter.elementsV4, _ = ipfixExporter.prepareElements(false)

	mockIPFIXBufferedExp.EXPECT().AddRecord(gomock.Cond(func(record ipfixentities.Record) bool {
		return record.GetTemplateID() == testTemplateIDv4
	})).Return(fmt.Errorf("send error"))

	assert.Error(t, ipfixExporter.sendRecord(record, false))
}

func createElementList(mode flowaggregatorconfig.AggregatorMode, includeK8sNames, includeK8sUIDs, isIPv6 bool, mockIPFIXRegistry *ipfixtesting.MockIPFIXRegistry) []ipfixentities.InfoElementWithValue {
	ianaInfoElements := infoelements.IANAInfoElements(isIPv6)
	antreaInfoElements := infoelements.AntreaInfoElements(includeK8sNames, includeK8sUIDs, isIPv6)
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
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, false, false, mockIPFIXRegistry)
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, false, true, mockIPFIXRegistry)
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
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, false, false, mockIPFIXRegistry)
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, false, true, mockIPFIXRegistry)
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
		assert.ErrorContains(t, err, "got error when initializing IPFIX exporting process: cannot create the connection to the Collector")
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
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, false, false, mockIPFIXRegistry)
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, false, true, mockIPFIXRegistry)
		exp := NewIPFIXExporter(clusterUUID, clusterUUID.String(), opt, mockIPFIXRegistry)
		defer exp.reset()
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
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, false, false, mockIPFIXRegistry)
		createElementList(flowaggregatorconfig.AggregatorModeAggregate, true, false, true, mockIPFIXRegistry)
		exp := NewIPFIXExporter(clusterUUID, clusterUUID.String(), opt, mockIPFIXRegistry)
		defer exp.reset()
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

// TestInitBackoffInRun verifies the backoff logic in the Run loop: after a
// failed initialization attempt, the loop waits for the backoff duration
// before retrying; the backoff doubles on successive failures and resets after
// a successful initialization.
func TestInitBackoffInRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// initErrCh controls what initIPFIXExportingProcess returns.
		// Send nil for success, a non-nil error for failure.
		// The default (empty channel) returns a "no error queued" sentinel so
		// that we can detect unexpected extra calls.
		initErrCh := make(chan error, 1)

		ctrl := gomock.NewController(t)
		mockIPFIXExpProc := ipfixtesting.NewMockIPFIXExportingProcess(ctrl)
		mockIPFIXBufferedExp := ipfixtesting.NewMockIPFIXBufferedExporter(ctrl)
		mockIPFIXExpProc.EXPECT().CloseConnToCollector().AnyTimes()
		mockIPFIXBufferedExp.EXPECT().Flush().Return(nil).AnyTimes()

		initIPFIXExportingProcessSaved := initIPFIXExportingProcess
		initIPFIXExportingProcess = func(exporter *IPFIXExporter) error {
			select {
			case err := <-initErrCh:
				if err == nil {
					exporter.exportingProcess = mockIPFIXExpProc
					exporter.bufferedExporter = mockIPFIXBufferedExp
				}
				return err
			default:
				// t.Errorf is safe to call from any goroutine, unlike require.Fail.
				t.Errorf("unexpected extra call to initExportingProcess")
				return fmt.Errorf("unexpected extra call to initExportingProcess")
			}
		}
		defer func() { initIPFIXExportingProcess = initIPFIXExportingProcessSaved }()

		clusterUUID := uuid.New()
		opt := &options.Options{
			AggregatorMode: flowaggregatorconfig.AggregatorModeProxy,
			Config:         &flowaggregatorconfig.FlowAggregatorConfig{},
		}
		flowaggregatorconfig.SetConfigDefaults(opt.Config)

		exp := NewIPFIXExporter(clusterUUID, clusterUUID.String(), opt, nil)
		require.NotNil(t, exp)

		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](8)
		defer buf.Shutdown()

		connectionErr := fmt.Errorf("connection error")

		// First attempt: fails with connectionErr → backoff step 1 = 1s.
		// Note that we need to ensure that we write to initErrCh before calling Run.
		initErrCh <- connectionErr

		go exp.Run(t.Context(), buf)

		synctest.Wait()
		require.Nil(t, exp.exportingProcess, "exporting process should not be set after failed init")

		// The loop is now waiting on waitCh for 1s. A second init call must
		// not happen yet; verify by advancing less than the full backoff.
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		require.Nil(t, exp.exportingProcess, "exporting process should not be set before backoff expires")

		// Advance past the 1s backoff. Second attempt also fails → backoff
		// step 2 = 2s.
		initErrCh <- connectionErr
		time.Sleep(500 * time.Millisecond) // total: 1s from first attempt
		synctest.Wait()
		require.Nil(t, exp.exportingProcess, "exporting process should not be set after second failed init")

		// Now waiting for 2s. Advance past it. Third attempt succeeds.
		initErrCh <- nil
		time.Sleep(2 * time.Second)
		synctest.Wait()
		require.NotNil(t, exp.exportingProcess, "exporting process should be initialized after successful init")
	})
}
