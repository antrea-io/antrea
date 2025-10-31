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

package flowexporter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/component-base/metrics/legacyregistry"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	connectionstesting "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	exportertesting "antrea.io/antrea/pkg/agent/flowexporter/exporter/testing"
	"antrea.io/antrea/pkg/agent/flowexporter/filter"
	"antrea.io/antrea/pkg/agent/flowexporter/options"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	flowexportertesting "antrea.io/antrea/pkg/agent/flowexporter/testing"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/agent/metrics"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	queriertest "antrea.io/antrea/pkg/querier/testing"
)

const (
	testActiveFlowTimeout = 3 * time.Second
	testIdleFlowTimeout   = 1 * time.Second
)

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
			name:               "Service name",
			inputAddr:          "ns/svc1:4739",
			expectedAddr:       "10.96.1.201:4739",
			expectedServerName: "svc1.ns.svc",
		},
		{
			name:        "Service without ClusterIP",
			inputAddr:   "ns/svc2:4739",
			expectedErr: "ClusterIP is not available for Service",
		},
		{
			name:        "Missing Service",
			inputAddr:   "ns/svc3:4739",
			expectedErr: "failed to resolve Service",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			exp := &FlowExporter{
				collectorAddr: tc.inputAddr,
				k8sClient:     k8sClient,
			}

			addr, name, err := exp.resolveCollectorAddress(ctx)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedAddr, addr)
				assert.Equal(t, tc.expectedServerName, name)
			}
		})
	}
}

func TestFlowExporter_initFlowExporter(t *testing.T) {
	metrics.InitializeConnectionMetrics()
	ctrl := gomock.NewController(t)
	mockExporter := exportertesting.NewMockInterface(ctrl)
	collectorAddr := "127.0.0.1:4739"
	exp := &FlowExporter{
		collectorAddr: collectorAddr,
		exporter:      mockExporter,
	}
	// TODO: test the TLS case (requires certificates)
	mockExporter.EXPECT().ConnectToCollector(collectorAddr, nil)
	require.NoError(t, exp.initFlowExporter(context.Background()))
	assert.True(t, exp.exporterConnected)
	checkTotalReconnectionsMetric(t)
	metrics.ReconnectionsToFlowCollector.Dec()
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
	flowExp := &FlowExporter{
		v4Enabled: v4Enabled,
		v6Enabled: v6Enabled,
	}

	if v4Enabled {
		runSendFlowRecordTests(t, flowExp, false)
	}
	if v6Enabled {
		runSendFlowRecordTests(t, flowExp, true)
	}
}

// TODO: This test needs to be fixed
// - It used subtests but they depend on each other, which is not a good pattern
// - The subtests should not share a gomock Controller
// - The expectation for Export should not use gomock.Any()
func runSendFlowRecordTests(t *testing.T, flowExp *FlowExporter, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	mockExporter := exportertesting.NewMockInterface(ctrl)
	flowExp.exporter = mockExporter
	mockConnDumper := connectionstesting.NewMockConnTrackDumper(ctrl)
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
			o := &options.FlowExporterOptions{
				FlowCollectorAddr:      "",
				FlowCollectorProto:     "",
				ActiveFlowTimeout:      testActiveFlowTimeout,
				IdleFlowTimeout:        testIdleFlowTimeout,
				StaleConnectionTimeout: 1,
				PollInterval:           1,
			}
			flowExp.conntrackConnStore = connections.NewConntrackConnectionStore(mockConnDumper, !isIPv6, isIPv6, nil, nil, nil, nil, nil, o)
			flowExp.denyConnStore = connections.NewDenyConnectionStore(nil, nil, nil, o, filter.NewProtocolFilter(nil))
			flowExp.conntrackPriorityQueue = flowExp.conntrackConnStore.GetPriorityQueue()
			flowExp.denyPriorityQueue = flowExp.denyConnStore.GetPriorityQueue()
			flowExp.numConnsExported = 0
			var conn, denyConn *connection.Connection
			var pqItem *priorityqueue.ItemToExpire

			if !tt.isDenyConn {
				// Prepare connection map
				conn = flowexportertesting.GetConnection(isIPv6, tt.isConnPresent, tt.statusFlag, tt.protoID, tt.tcpState)
				connKey := connection.NewConnectionKey(conn)
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
				denyConn = flowexportertesting.GetDenyConnection(isIPv6, tt.protoID)
				connKey := connection.NewConnectionKey(denyConn)
				flowExp.denyConnStore.AddOrUpdateConn(denyConn, time.Now(), uint64(60))
				assert.Equalf(t, getNumOfDenyConns(flowExp.denyConnStore), 1, "deny connection is expected to be in the connection map")
				assert.Equalf(t, flowExp.denyPriorityQueue.Len(), 1, "pqItem is expected to be in the expire priority queue")
				denyConn.PrevPackets = tt.prevPackets
				pqItem = flowExp.denyPriorityQueue.KeyToItem[connKey]
				pqItem.ActiveExpireTime = tt.activeExpireTime
				pqItem.IdleExpireTime = tt.idleExpireTime
			}

			mockExporter.EXPECT().Export(gomock.Any())

			_, err := flowExp.sendFlowRecords()
			assert.NoError(t, err)
			assert.Equalf(t, uint64(1), flowExp.numConnsExported, "1 data set should have been sent.")

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
	countNumOfConns := func(key connection.ConnectionKey, conn *connection.Connection) error {
		count++
		return nil
	}
	connStore.ForAllConnectionsDo(countNumOfConns)
	return count
}

func getNumOfDenyConns(connStore *connections.DenyConnectionStore) int {
	count := 0
	countNumOfConns := func(key connection.ConnectionKey, conn *connection.Connection) error {
		count++
		return nil
	}
	connStore.ForAllConnectionsDo(countNumOfConns)
	return count
}

var (
	isGateway, _ = netip.AddrFromSlice([]byte{9, 9, 9, 9})
	isNotPod, _  = netip.AddrFromSlice([]byte{8, 8, 8, 8})
	isPod, _     = netip.AddrFromSlice([]byte{7, 7, 7, 7})
)

type mockNodeRouteController struct{}

func (m mockNodeRouteController) LookupIPInPodSubnets(ip netip.Addr) (bool, bool) {
	if ip == isGateway {
		return true, true
	}
	if ip == isPod {
		return true, false
	}
	if ip == isNotPod {
		return false, false
	}
	return false, false
}

func (m mockNodeRouteController) IsNil() bool {
	return false
}

type mockServiceLookUp struct{}

func (m mockServiceLookUp) IsNil() bool {
	return false
}

func (m mockServiceLookUp) FillServiceInfo(conn *connection.Connection) error {
	return nil
}

type mockServiceLookUpErrors struct{}

func (m mockServiceLookUpErrors) IsNil() bool {
	return false
}

func (m mockServiceLookUpErrors) FillServiceInfo(conn *connection.Connection) error {
	return errors.New("error")
}

func TestFlowExporter_findFlowType(t *testing.T) {
	conn1 := connection.Connection{SourcePodName: "podA", DestinationPodName: "podB"}
	conn2 := connection.Connection{SourcePodName: "podA", DestinationPodName: ""}
	conn3 := connection.Connection{FlowKey: connection.Tuple{SourceAddress: isGateway, DestinationAddress: isPod}, DestinationPodNamespace: "not-empty"}
	conn55 := connection.Connection{FlowKey: connection.Tuple{SourceAddress: isGateway, DestinationAddress: isPod},
		DestinationPodNamespace: ""}
	conn4 := connection.Connection{FlowKey: connection.Tuple{DestinationAddress: isGateway}}
	conn6 := connection.Connection{FlowKey: connection.Tuple{DestinationAddress: isNotPod, SourceAddress: isPod}}
	conn7 := connection.Connection{FlowKey: connection.Tuple{DestinationAddress: isPod, SourceAddress: isPod}}
	conn8 := connection.Connection{SourcePodName: "source-pod-name", DestinationPodName: "destination-pod-name", FlowKey: connection.Tuple{DestinationAddress: isPod, SourceAddress: isPod}}
	conn10 := connection.Connection{FlowKey: connection.Tuple{SourceAddress: isNotPod, DestinationAddress: isPod}}
	conn11 := connection.Connection{FlowKey: connection.Tuple{SourceAddress: isNotPod, DestinationAddress: isNotPod}}
	mockController := mockNodeRouteController{}
	mockServiceLookUp := mockServiceLookUp{}
	//mockServiceLookUpErrors := mockServiceLookUpErrors{} TODO  - this is not tested
	//var nilFlowExporter *FlowExporter = nil // todo - should this be used?
	//var nilServiceLookUp serviceLookUpInterface = nilFlowExporter // TODO this is not tested
	for _, tc := range []struct {
		name                              string
		isNetworkPolicyOnly               bool
		conn                              connection.Connection
		expectedFlowType                  uint8
		nodeRouteControllerImplementation nodeRouteControllerInterface
		serviceLookUpImplementation       serviceLookUpInterface
	}{

		{"isNetworkPolicy and pod names exist", true, conn1, utils.FlowTypeIntraNode, nil, nil},
		{"isNetworkPolicy and pod names are missing", true, conn2, utils.FlowTypeInterNode, nil, nil},
		{"unspecified flow type", false, conn1, utils.FlowTypeUnspecified, nil, nil},
		{"source is gateway and destinoation pod namespace is not flow aggregator", false, conn3, utils.FlowTypeFromExternal, mockController, nil},
		{"source is gateway and destinoation pod namesapce is empty", false, conn55, utils.FlowTypeUnsupported, mockController, nil},
		{"destination is gateway", false, conn4, utils.FlowTypeUnsupported, mockController, nil},
		{"source is pod, but destination is not", false, conn6, utils.FlowTypeToExternal, mockController, nil},
		{"pod names missing", false, conn7, utils.FlowTypeInterNode, mockController, nil},
		{"pod names not missing", false, conn8, utils.FlowTypeIntraNode, mockController, nil},
		{"source is not pod but destination is", false, conn10, utils.FlowTypeFromExternal, mockController, mockServiceLookUp},
		{"source and destination are not pods", false, conn11, utils.FlowTypeUnsupported, mockController, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flowExp := &FlowExporter{
				isNetworkPolicyOnly: tc.isNetworkPolicyOnly,
			}
			var serviceLookUpImplementation serviceLookUpInterface
			if tc.serviceLookUpImplementation == nil {
				serviceLookUpImplementation = flowExp
			} else {
				serviceLookUpImplementation = tc.serviceLookUpImplementation
			}
			flowType := flowExp.findFlowType(tc.conn, tc.nodeRouteControllerImplementation, serviceLookUpImplementation)
			assert.Equal(t, tc.expectedFlowType, flowType)
		})
	}
}

func TestFlowExporter_fillEgressInfo(t *testing.T) {
	testCases := []struct {
		name                   string
		sourcePodNamespace     string
		sourcePodName          string
		expectedEgressName     string
		expectedEgressUID      string
		expectedEgressIP       string
		expectedEgressNodeName string
		expectedErr            string
	}{
		{
			name:                   "EgressName, EgressIP and EgressNodeName filled",
			sourcePodNamespace:     "namespaceA",
			sourcePodName:          "podA",
			expectedEgressName:     "test-egress",
			expectedEgressUID:      "test-egress-uid",
			expectedEgressIP:       "172.18.0.1",
			expectedEgressNodeName: "test-egress-node",
		},
		{
			name:               "No Egress Information filled",
			sourcePodNamespace: "namespaceA",
			sourcePodName:      "podC",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			egressQuerier := queriertest.NewMockEgressQuerier(ctrl)
			exp := &FlowExporter{
				egressQuerier: egressQuerier,
			}
			conn := connection.Connection{
				SourcePodNamespace: tc.sourcePodNamespace,
				SourcePodName:      tc.sourcePodName,
			}
			if tc.expectedEgressName != "" {
				egressQuerier.EXPECT().GetEgress(conn.SourcePodNamespace, conn.SourcePodName).Return(agenttypes.EgressConfig{
					Name:       tc.expectedEgressName,
					UID:        types.UID(tc.expectedEgressUID),
					EgressIP:   tc.expectedEgressIP,
					EgressNode: tc.expectedEgressNodeName,
				}, nil)
			} else {
				egressQuerier.EXPECT().GetEgress(conn.SourcePodNamespace, conn.SourcePodName).Return(agenttypes.EgressConfig{}, fmt.Errorf("no Egress applied to Pod %s", conn.SourcePodName))
			}
			exp.fillEgressInfo(&conn)
			assert.Equal(t, tc.expectedEgressName, conn.EgressName)
			assert.Equal(t, tc.expectedEgressUID, conn.EgressUID)
			assert.Equal(t, tc.expectedEgressIP, conn.EgressIP)
			assert.Equal(t, tc.expectedEgressNodeName, conn.EgressNodeName)
		})
	}
}
