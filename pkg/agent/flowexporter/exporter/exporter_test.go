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
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixentitiestesting "github.com/vmware/go-ipfix/pkg/entities/testing"
	"github.com/vmware/go-ipfix/pkg/exporter"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/component-base/metrics/legacyregistry"

	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	connectionstest "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	"antrea.io/antrea/pkg/agent/metrics"
	ipfixtest "antrea.io/antrea/pkg/ipfix/testing"
	queriertest "antrea.io/antrea/pkg/querier/testing"
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
	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockIPFIXRegistry := ipfixtest.NewMockIPFIXRegistry(ctrl)
	flowExp := &FlowExporter{
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

func sendTemplateSet(t *testing.T, ctrl *gomock.Controller, mockIPFIXExpProc *ipfixtest.MockIPFIXExportingProcess, mockIPFIXRegistry *ipfixtest.MockIPFIXRegistry, flowExp *FlowExporter, isIPv6 bool) {
	var mockTempSet *ipfixentitiestesting.MockSet
	mockTempSet = ipfixentitiestesting.NewMockSet(ctrl)
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
		mockTempSet.EXPECT().AddRecord(elemList, testTemplateIDv4).Return(nil)
	} else {
		mockTempSet.EXPECT().AddRecord(elemList, testTemplateIDv6).Return(nil)
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
	assert.NoError(t, err, "Error in sending template set")

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
	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockDataSet := ipfixentitiestesting.NewMockSet(ctrl)
	mockIPFIXRegistry := ipfixtest.NewMockIPFIXRegistry(ctrl)

	var connv4, connv6 *flowexporter.Connection
	var elemListv4, elemListv6 []ipfixentities.InfoElementWithValue
	if v4Enabled {
		connv4 = getConnection(false, true, 302, 6, "ESTABLISHED")
		elemListv4 = getElemList(IANAInfoElementsIPv4, AntreaInfoElementsIPv4)
	}
	if v6Enabled {
		connv6 = getConnection(true, true, 302, 6, "ESTABLISHED")
		elemListv6 = getElemList(IANAInfoElementsIPv6, AntreaInfoElementsIPv6)
	}
	flowExp := &FlowExporter{
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

	sendDataSet := func(elemList []ipfixentities.InfoElementWithValue, templateID uint16, conn flowexporter.Connection) {
		mockDataSet.EXPECT().ResetSet()
		mockDataSet.EXPECT().PrepareSet(ipfixentities.Data, templateID).Return(nil)
		mockDataSet.EXPECT().AddRecord(ElementListMatcher(elemList), templateID).Return(nil)
		mockIPFIXExpProc.EXPECT().SendSet(mockDataSet).Return(0, nil)

		err := flowExp.addConnToSet(&conn)
		assert.NoError(t, err, "Error when adding record to data set")
		_, err = flowExp.sendDataSet()
		assert.NoError(t, err, "Error in sending data set")
	}

	if v4Enabled {
		sendDataSet(elemListv4, testTemplateIDv4, *connv4)
	}
	if v6Enabled {
		sendDataSet(elemListv6, testTemplateIDv6, *connv6)
	}
}

func TestFlowExporter_resolveCollectorAddress(t *testing.T) {
	ctx := context.Background()

	k8sClient := fake.NewSimpleClientset(
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "svc1",
				Namespace: "ns",
			},
			Spec: corev1.ServiceSpec{
				Type:       corev1.ServiceTypeClusterIP,
				ClusterIP:  "10.96.1.201",
				ClusterIPs: []string{"10.96.1.201"},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "svc2",
				Namespace: "ns",
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeClusterIP,
				// missing ClusterIP
			},
		},
	)

	testCases := []struct {
		name               string
		inputAddr          string
		withTLS            bool
		expectedAddr       string
		expectedServerName string
		expectedErr        string
	}{
		{
			name:         "IP address",
			inputAddr:    "10.96.1.100:4739",
			expectedAddr: "10.96.1.100:4739",
		},
		{
			name:         "Service name",
			inputAddr:    "ns/svc1:4739",
			expectedAddr: "10.96.1.201:4739",
		},
		{
			name:               "Service name with TLS",
			inputAddr:          "ns/svc1:4739",
			withTLS:            true,
			expectedAddr:       "10.96.1.201:4739",
			expectedServerName: "svc1.ns.svc",
		},
		{
			name:        "Service without ClusterIP",
			inputAddr:   "ns/svc2:4739",
			expectedErr: "ClusterIP is not available for FlowAggregator Service",
		},
		{
			name:        "Missing Service",
			inputAddr:   "ns/svc3:4739",
			expectedErr: "failed to resolve FlowAggregator Service",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			exp := &FlowExporter{
				collectorAddr: tc.inputAddr,
				exporterInput: exporter.ExporterInput{
					CollectorProtocol: "tcp",
				},
				k8sClient: k8sClient,
			}
			if tc.withTLS {
				exp.exporterInput.TLSClientConfig = &exporter.ExporterTLSClientConfig{}
			}

			err := exp.resolveCollectorAddress(ctx)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedAddr, exp.exporterInput.CollectorAddress)
				if tc.withTLS {
					assert.Equal(t, tc.expectedServerName, exp.exporterInput.TLSClientConfig.ServerName)
				} else {
					// should stay nil
					assert.Nil(t, exp.exporterInput.TLSClientConfig)
				}
			}
		})
	}
}

func TestFlowExporter_initFlowExporter(t *testing.T) {
	metrics.InitializeConnectionMetrics()
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err, "Error when resolving UDP address")
	conn1, err := net.ListenUDP("udp", udpAddr)
	require.NoError(t, err, "Error when creating a local UDP server")
	defer conn1.Close()
	tcpAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	require.NoError(t, err, "Error when resolving TCP address")
	conn2, err := net.ListenTCP("tcp", tcpAddr)
	require.NoError(t, err, "Error when creating a local TCP server")
	defer conn2.Close()

	for _, tc := range []struct {
		protocol               string
		address                string
		expectedTempRefTimeout uint32
	}{
		{conn1.LocalAddr().Network(), conn1.LocalAddr().String(), uint32(1800)},
		{conn2.Addr().Network(), conn2.Addr().String(), uint32(0)},
	} {
		exp := &FlowExporter{
			collectorAddr: tc.address,
			process:       nil,
			exporterInput: exporter.ExporterInput{
				CollectorProtocol: tc.protocol,
			},
		}
		err = exp.initFlowExporter(context.Background())
		require.NoError(t, err)
		assert.Equal(t, tc.address, exp.exporterInput.CollectorAddress)
		assert.Equal(t, tc.expectedTempRefTimeout, exp.exporterInput.TempRefTimeout)
		checkTotalReconnectionsMetric(t)
		metrics.ReconnectionsToFlowCollector.Dec()
	}
}

func checkTotalReconnectionsMetric(t *testing.T) {
	expected := `
	# HELP antrea_agent_flow_collector_reconnection_count [ALPHA] Number of re-connections between Flow Exporter and flow collector. This metric gets updated whenever the connection is re-established between the Flow Exporter and the flow collector (e.g. the Flow Aggregator).
	# TYPE antrea_agent_flow_collector_reconnection_count gauge
	antrea_agent_flow_collector_reconnection_count 1
	`
	err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expected), "antrea_agent_flow_collector_reconnection_count")
	assert.NoError(t, err)
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

func getConnection(isIPv6 bool, isPresent bool, statusFlag uint32, protoID uint8, tcpState string) *flowexporter.Connection {
	var tuple flowexporter.Tuple
	if !isIPv6 {
		tuple = flowexporter.Tuple{SourceAddress: netip.MustParseAddr("1.2.3.4"), DestinationAddress: netip.MustParseAddr("4.3.2.1"), Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	} else {
		srcIP := netip.MustParseAddr("2001:0:3238:dfe1:63::fefb")
		dstIP := netip.MustParseAddr("2001:0:3238:dfe1:63::fefc")
		tuple = flowexporter.Tuple{SourceAddress: srcIP, DestinationAddress: dstIP, Protocol: protoID, SourcePort: 65280, DestinationPort: 255}
	}
	conn := &flowexporter.Connection{
		StartTime:                     time.Time{},
		StopTime:                      time.Time{},
		StatusFlag:                    statusFlag,
		OriginalPackets:               0xab,
		OriginalBytes:                 0xabcd,
		ReversePackets:                0xa,
		ReverseBytes:                  0xab,
		FlowKey:                       tuple,
		IsPresent:                     isPresent,
		SourcePodNamespace:            "ns",
		SourcePodName:                 "pod",
		DestinationPodNamespace:       "",
		DestinationPodName:            "",
		IngressNetworkPolicyName:      "",
		IngressNetworkPolicyNamespace: "",
		IngressNetworkPolicyType:      ipfixregistry.PolicyTypeK8sNetworkPolicy,
		IngressNetworkPolicyRuleName:  "",
		EgressNetworkPolicyName:       "np",
		EgressNetworkPolicyNamespace:  "np-ns",
		EgressNetworkPolicyType:       ipfixregistry.PolicyTypeK8sNetworkPolicy,
		EgressNetworkPolicyRuleName:   "",
		DestinationServicePortName:    "service",
		TCPState:                      tcpState,
	}
	return conn
}

func getDenyConnection(isIPv6 bool, protoID uint8) *flowexporter.Connection {
	var tuple, _ flowexporter.Tuple
	if !isIPv6 {
		tuple = flowexporter.Tuple{SourceAddress: netip.MustParseAddr("1.2.3.4"), DestinationAddress: netip.MustParseAddr("4.3.2.1"), Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	} else {
		srcIP := netip.MustParseAddr("2001:0:3238:dfe1:63::fefb")
		dstIP := netip.MustParseAddr("2001:0:3238:dfe1:63::fefc")
		tuple = flowexporter.Tuple{SourceAddress: srcIP, DestinationAddress: dstIP, Protocol: protoID, SourcePort: 65280, DestinationPort: 255}
	}
	conn := &flowexporter.Connection{
		FlowKey:       tuple,
		SourcePodName: "pod",
	}
	return conn
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
	var elemListv4, elemListv6 []ipfixentities.InfoElementWithValue
	if v4Enabled {
		elemListv4 = getElemList(IANAInfoElementsIPv4, AntreaInfoElementsIPv4)
	}
	if v6Enabled {
		elemListv6 = getElemList(IANAInfoElementsIPv6, AntreaInfoElementsIPv6)
	}

	flowExp := &FlowExporter{
		elementsListv4: elemListv4,
		elementsListv6: elemListv6,
		templateIDv4:   testTemplateIDv4,
		templateIDv6:   testTemplateIDv6,
		v4Enabled:      v4Enabled,
		v6Enabled:      v6Enabled}

	if v4Enabled {
		runSendFlowRecordTests(t, flowExp, false)
	}
	if v6Enabled {
		runSendFlowRecordTests(t, flowExp, true)
	}
}

func runSendFlowRecordTests(t *testing.T, flowExp *FlowExporter, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	mockIPFIXExpProc := ipfixtest.NewMockIPFIXExportingProcess(ctrl)
	mockDataSet := ipfixentitiestesting.NewMockSet(ctrl)
	flowExp.process = mockIPFIXExpProc
	flowExp.ipfixSet = mockDataSet
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	startTime := time.Now()

	tests := []struct {
		name               string
		isDenyConn         bool
		isConnPresent      bool
		tcpState           string
		statusFlag         uint32
		protoID            uint8
		originalPackets    uint64
		reversePackets     uint64
		prevPackets        uint64
		prevReversePackets uint64
		activeExpireTime   time.Time
		idleExpireTime     time.Time
	}{
		{
			"conntrack connection being active time out",
			false,
			true,
			"SYN_SENT",
			4,
			6,
			1,
			1,
			0,
			0,
			startTime.Add(-testActiveFlowTimeout),
			startTime.Add(10 * testIdleFlowTimeout),
		},
		{
			"conntrack connection being idle time out and becoming inactive",
			false,
			true,
			"SYN_SENT",
			4,
			6,
			0,
			0,
			0,
			0,
			startTime.Add(10 * testActiveFlowTimeout),
			startTime.Add(-testIdleFlowTimeout),
		},
		{
			"conntrack connection with deleted connection",
			false,
			false,
			"TIME_WAIT",
			204,
			6,
			0,
			0,
			0,
			0,
			startTime.Add(-testActiveFlowTimeout),
			startTime.Add(-testIdleFlowTimeout),
		},
		{
			"deny connection being active time out",
			true,
			false,
			"TIME_WAIT",
			204,
			6,
			1,
			0,
			0,
			0,
			startTime.Add(-testActiveFlowTimeout),
			startTime.Add(10 * testIdleFlowTimeout),
		},
		{
			"deny connection being active time out and becoming inactive",
			true,
			false,
			"TIME_WAIT",
			204,
			6,
			1,
			0,
			1,
			0,
			startTime.Add(-testActiveFlowTimeout),
			startTime.Add(10 * testIdleFlowTimeout),
		},
		{
			"deny connection being idle time out",
			true,
			false,
			"TIME_WAIT",
			204,
			6,
			0,
			0,
			0,
			0,
			startTime.Add(10 * testActiveFlowTimeout),
			startTime.Add(-testIdleFlowTimeout),
		},
	}
	for id, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &flowexporter.FlowExporterOptions{
				FlowCollectorAddr:      "",
				FlowCollectorProto:     "",
				ActiveFlowTimeout:      testActiveFlowTimeout,
				IdleFlowTimeout:        testIdleFlowTimeout,
				StaleConnectionTimeout: 1,
				PollInterval:           1}
			flowExp.conntrackConnStore = connections.NewConntrackConnectionStore(mockConnDumper, !isIPv6, isIPv6, nil, nil, nil, nil, o)
			flowExp.denyConnStore = connections.NewDenyConnectionStore(nil, nil, o)
			flowExp.conntrackPriorityQueue = flowExp.conntrackConnStore.GetPriorityQueue()
			flowExp.denyPriorityQueue = flowExp.denyConnStore.GetPriorityQueue()
			flowExp.numDataSetsSent = 0
			var conn, denyConn *flowexporter.Connection
			var connKey flowexporter.ConnectionKey
			var pqItem *flowexporter.ItemToExpire

			if !tt.isDenyConn {
				// Prepare connection map
				conn = getConnection(isIPv6, tt.isConnPresent, tt.statusFlag, tt.protoID, tt.tcpState)
				connKey = flowexporter.NewConnectionKey(conn)
				conn.OriginalPackets = tt.originalPackets
				conn.ReversePackets = tt.reversePackets
				flowExp.conntrackConnStore.AddOrUpdateConn(conn)
				assert.Equalf(t, getNumOfConntrackConns(flowExp.conntrackConnStore), 1, "connection is expected to be in the connection map")
				assert.Equalf(t, flowExp.conntrackPriorityQueue.Len(), 1, "pqItem is expected to be in the expire priority queue")
				conn.PrevPackets = tt.prevPackets
				conn.PrevReversePackets = tt.prevReversePackets
				pqItem = flowExp.conntrackPriorityQueue.KeyToItem[connKey]
				pqItem.ActiveExpireTime = tt.activeExpireTime
				pqItem.IdleExpireTime = tt.idleExpireTime
			} else {
				// Prepare deny connection map
				denyConn = getDenyConnection(isIPv6, tt.protoID)
				connKey = flowexporter.NewConnectionKey(denyConn)
				flowExp.denyConnStore.AddOrUpdateConn(denyConn, time.Now(), uint64(60))
				assert.Equalf(t, getNumOfDenyConns(flowExp.denyConnStore), 1, "deny connection is expected to be in the connection map")
				assert.Equalf(t, flowExp.denyPriorityQueue.Len(), 1, "pqItem is expected to be in the expire priority queue")
				denyConn.PrevPackets = tt.prevPackets
				pqItem = flowExp.denyPriorityQueue.KeyToItem[connKey]
				pqItem.ActiveExpireTime = tt.activeExpireTime
				pqItem.IdleExpireTime = tt.idleExpireTime
			}

			mockDataSet.EXPECT().ResetSet()
			if !isIPv6 {
				mockDataSet.EXPECT().PrepareSet(ipfixentities.Data, flowExp.templateIDv4).Return(nil)
				mockDataSet.EXPECT().AddRecord(flowExp.elementsListv4, flowExp.templateIDv4).Return(nil)
			} else {
				mockDataSet.EXPECT().PrepareSet(ipfixentities.Data, flowExp.templateIDv6).Return(nil)
				mockDataSet.EXPECT().AddRecord(flowExp.elementsListv6, flowExp.templateIDv6).Return(nil)
			}
			mockIPFIXExpProc.EXPECT().SendSet(mockDataSet).Return(0, nil)
			_, err := flowExp.sendFlowRecords()
			assert.NoError(t, err)
			assert.Equalf(t, uint64(1), flowExp.numDataSetsSent, "1 data set should have been sent.")

			switch id {
			case 0: // conntrack connection being active time out
				assert.True(t, pqItem.ActiveExpireTime.After(startTime))
				assert.Equal(t, conn.OriginalPackets, conn.PrevPackets)
				assert.Equalf(t, 1, flowExp.conntrackPriorityQueue.Len(), "Length of expire priority queue should be 1")
			case 1: // conntrack connection being idle time out and becoming inactive
				assert.False(t, conn.IsActive)
				assert.Equalf(t, 0, flowExp.conntrackPriorityQueue.Len(), "Length of expire priority queue should be 0")
			case 2: // conntrack connection with deleted connection
				assert.True(t, conn.ReadyToDelete)
				assert.Equalf(t, 0, flowExp.conntrackPriorityQueue.Len(), "Length of expire priority queue should be 0")
			case 3: // deny connection being active time out
				assert.True(t, pqItem.ActiveExpireTime.After(startTime))
				assert.Equal(t, denyConn.OriginalPackets, denyConn.PrevPackets)
				assert.Equalf(t, 1, flowExp.denyPriorityQueue.Len(), "Length of expire priority queue should be 1")
			case 4: // deny connection being active time out and becoming inactive
				assert.False(t, denyConn.IsActive)
				assert.Equalf(t, 0, flowExp.denyPriorityQueue.Len(), "Length of expire priority queue should be 0")
			case 5: // deny connection being idle time out
				assert.Equal(t, true, denyConn.ReadyToDelete)
				assert.Equalf(t, 0, flowExp.denyPriorityQueue.Len(), "Length of expire priority queue should be 0")
			}
		})
	}
}

func getNumOfConntrackConns(connStore *connections.ConntrackConnectionStore) int {
	count := 0
	countNumOfConns := func(key flowexporter.ConnectionKey, conn *flowexporter.Connection) error {
		count++
		return nil
	}
	connStore.ForAllConnectionsDo(countNumOfConns)
	return count
}

func getNumOfDenyConns(connStore *connections.DenyConnectionStore) int {
	count := 0
	countNumOfConns := func(key flowexporter.ConnectionKey, conn *flowexporter.Connection) error {
		count++
		return nil
	}
	connStore.ForAllConnectionsDo(countNumOfConns)
	return count
}

func createElement(name string, enterpriseID uint32) ipfixentities.InfoElementWithValue {
	element, _ := ipfixregistry.GetInfoElement(name, enterpriseID)
	ieWithValue, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
	return ieWithValue
}

func TestFlowExporter_prepareExporterInputArgs(t *testing.T) {
	for _, tc := range []struct {
		collectorProto              string
		nodeName                    string
		expectedObservationDomainID uint32
		expectedIsEncrypted         bool
		expectedProto               string
	}{
		{"tls", "kind-worker", 801257890, true, "tcp"},
		{"tcp", "kind-worker", 801257890, false, "tcp"},
		{"udp", "kind-worker", 801257890, false, "udp"},
	} {
		expInput := prepareExporterInputArgs(tc.collectorProto, tc.nodeName)
		assert.Equal(t, tc.expectedObservationDomainID, expInput.ObservationDomainID)
		assert.Equal(t, tc.expectedIsEncrypted, expInput.TLSClientConfig != nil)
		assert.Equal(t, tc.expectedProto, expInput.CollectorProtocol)
	}
}

func TestFlowExporter_findFlowType(t *testing.T) {
	conn1 := flowexporter.Connection{SourcePodName: "podA", DestinationPodName: "podB"}
	conn2 := flowexporter.Connection{SourcePodName: "podA", DestinationPodName: ""}
	for _, tc := range []struct {
		isNetworkPolicyOnly bool
		conn                flowexporter.Connection
		expectedFlowType    uint8
	}{
		{true, conn1, 1},
		{true, conn2, 2},
		{false, conn1, 0},
	} {
		flowExp := &FlowExporter{
			isNetworkPolicyOnly: tc.isNetworkPolicyOnly,
		}
		flowType := flowExp.findFlowType(tc.conn)
		assert.Equal(t, tc.expectedFlowType, flowType)
	}
}

func TestFlowExporter_fillEgressInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	testCases := []struct {
		name               string
		sourcePodNamespace string
		sourcePodName      string
		expectedEgressName string
		expectedEgressIP   string
		expectedErr        string
	}{
		{
			name:               "Both EgressName and EgressIP filled",
			sourcePodNamespace: "namespaceA",
			sourcePodName:      "podA",
			expectedEgressName: "test-egress",
			expectedEgressIP:   "172.18.0.1",
		},
		{
			name:               "No Egress Information filled",
			sourcePodNamespace: "namespaceA",
			sourcePodName:      "podC",
			expectedEgressName: "",
			expectedEgressIP:   "",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			egressQuerier := queriertest.NewMockEgressQuerier(ctrl)
			exp := &FlowExporter{
				egressQuerier: egressQuerier,
			}
			conn := flowexporter.Connection{
				SourcePodNamespace: tc.sourcePodNamespace,
				SourcePodName:      tc.sourcePodName,
			}
			if tc.expectedEgressName != "" {
				egressQuerier.EXPECT().GetEgress(conn.SourcePodNamespace, conn.SourcePodName).Return(tc.expectedEgressName, tc.expectedEgressIP, "", nil)
			} else {
				egressQuerier.EXPECT().GetEgress(conn.SourcePodNamespace, conn.SourcePodName).Return("", "", "", fmt.Errorf("no Egress applied to Pod %s", conn.SourcePodName))
			}
			exp.fillEgressInfo(&conn)
			assert.Equal(t, tc.expectedEgressName, conn.EgressName)
			assert.Equal(t, tc.expectedEgressIP, conn.EgressIP)
		})
	}
}
