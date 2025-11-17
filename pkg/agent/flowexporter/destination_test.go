// Copyright 2025 Antrea Authors.
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

package flowexporter

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/component-base/metrics/legacyregistry"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/exporter"
	exportertesting "antrea.io/antrea/pkg/agent/flowexporter/exporter/testing"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	flowexportertesting "antrea.io/antrea/pkg/agent/flowexporter/testing"
	"antrea.io/antrea/pkg/agent/metrics"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	queriertest "antrea.io/antrea/pkg/querier/testing"
)

const (
	testActiveFlowTimeout = 3 * time.Second
	testIdleFlowTimeout   = 1 * time.Second
)

// TODO: This test needs to be fixed
// - It used subtests but they depend on each other, which is not a good pattern
// - The subtests should not share a gomock Controller
// - The expectation for Export should not use gomock.Any()
func runSendFlowRecordTests(t *testing.T, destination *Destination, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	mockExporter := exportertesting.NewMockInterface(ctrl)
	destination.exp = mockExporter
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
			name:               "conntrack connection being active time out",
			isDenyConn:         false,
			isConnPresent:      true,
			tcpState:           "SYN_SENT",
			statusFlag:         4,
			protoID:            6,
			originalPackets:    1,
			reversePackets:     1,
			prevPackets:        0,
			prevReversePackets: 0,
			activeExpireTime:   startTime.Add(-testActiveFlowTimeout),
			idleExpireTime:     startTime.Add(10 * testIdleFlowTimeout),
		},
		{
			name:               "conntrack connection being idle time out and becoming inactive",
			isDenyConn:         false,
			isConnPresent:      true,
			tcpState:           "SYN_SENT",
			statusFlag:         4,
			protoID:            6,
			originalPackets:    0,
			reversePackets:     0,
			prevPackets:        0,
			prevReversePackets: 0,
			activeExpireTime:   startTime.Add(10 * testActiveFlowTimeout),
			idleExpireTime:     startTime.Add(-testIdleFlowTimeout),
		},
		{
			name:               "conntrack connection with deleted connection",
			isDenyConn:         false,
			isConnPresent:      false,
			tcpState:           "TIME_WAIT",
			statusFlag:         204,
			protoID:            6,
			originalPackets:    0,
			reversePackets:     0,
			prevPackets:        0,
			prevReversePackets: 0,
			activeExpireTime:   startTime.Add(-testActiveFlowTimeout),
			idleExpireTime:     startTime.Add(-testIdleFlowTimeout),
		},
		{
			name:               "deny connection being active time out",
			isDenyConn:         true,
			isConnPresent:      false,
			tcpState:           "TIME_WAIT",
			statusFlag:         204,
			protoID:            6,
			originalPackets:    1,
			reversePackets:     0,
			prevPackets:        0,
			prevReversePackets: 0,
			activeExpireTime:   startTime.Add(-testActiveFlowTimeout),
			idleExpireTime:     startTime.Add(10 * testIdleFlowTimeout),
		},
		{
			name:               "deny connection being active time out and becoming inactive",
			isDenyConn:         true,
			isConnPresent:      false,
			tcpState:           "TIME_WAIT",
			statusFlag:         204,
			protoID:            6,
			originalPackets:    1,
			reversePackets:     0,
			prevPackets:        1,
			prevReversePackets: 0,
			activeExpireTime:   startTime.Add(-testActiveFlowTimeout),
			idleExpireTime:     startTime.Add(10 * testIdleFlowTimeout),
		},
		{
			name:               "deny connection being idle time out",
			isDenyConn:         true,
			isConnPresent:      false,
			tcpState:           "TIME_WAIT",
			statusFlag:         204,
			protoID:            6,
			originalPackets:    0,
			reversePackets:     0,
			prevPackets:        0,
			prevReversePackets: 0,
			activeExpireTime:   startTime.Add(10 * testActiveFlowTimeout),
			idleExpireTime:     startTime.Add(-testIdleFlowTimeout),
		},
	}
	for id, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := connections.ConnectionStoreConfig{
				ActiveFlowTimeout:      testActiveFlowTimeout,
				IdleFlowTimeout:        testIdleFlowTimeout,
				StaleConnectionTimeout: 1,
			}

			destination.conntrackConnStore = connections.NewConntrackConnectionStore(nil, nil, nil, config)
			destination.denyConnStore = connections.NewDenyConnectionStore(nil, nil, nil, config)
			destination.conntrackPriorityQueue = destination.conntrackConnStore.GetPriorityQueue()
			destination.denyPriorityQueue = destination.denyConnStore.GetPriorityQueue()
			destination.numConnsExported = 0
			var conn, denyConn *connection.Connection
			var pqItem *priorityqueue.ItemToExpire

			if !tt.isDenyConn {
				// Prepare connection map
				conn = flowexportertesting.GetConnection(isIPv6, tt.isConnPresent, tt.statusFlag, tt.protoID, tt.tcpState)
				connKey := connection.NewConnectionKey(conn)
				conn.OriginalPackets = tt.originalPackets
				conn.ReversePackets = tt.reversePackets
				destination.conntrackConnStore.AddOrUpdateConn(conn)
				conn, _ = destination.conntrackConnStore.GetConnByKey(connKey)
				require.NotNil(t, conn)
				assert.Equalf(t, getNumOfConntrackConns(destination.conntrackConnStore), 1, "connection is expected to be in the connection map")
				assert.Equalf(t, destination.conntrackPriorityQueue.Len(), 1, "pqItem is expected to be in the expire priority queue")
				conn.PrevPackets = tt.prevPackets
				conn.PrevReversePackets = tt.prevReversePackets
				pqItem = destination.conntrackPriorityQueue.KeyToItem[connKey]
				pqItem.ActiveExpireTime = tt.activeExpireTime
				pqItem.IdleExpireTime = tt.idleExpireTime
			} else {
				// Prepare deny connection map
				denyConn = flowexportertesting.GetDenyConnection(isIPv6, tt.protoID)
				connKey := connection.NewConnectionKey(denyConn)
				destination.denyConnStore.AddOrUpdateConn(denyConn)
				denyConn, _ = destination.denyConnStore.GetConnByKey(connKey)
				require.NotNil(t, denyConn)
				assert.Equalf(t, getNumOfDenyConns(destination.denyConnStore), 1, "deny connection is expected to be in the connection map")
				assert.Equalf(t, destination.denyPriorityQueue.Len(), 1, "pqItem is expected to be in the expire priority queue")
				denyConn.PrevPackets = tt.prevPackets
				pqItem = destination.denyPriorityQueue.KeyToItem[connKey]
				pqItem.ActiveExpireTime = tt.activeExpireTime
				pqItem.IdleExpireTime = tt.idleExpireTime
			}

			mockExporter.EXPECT().Export(gomock.Any())

			_, err := destination.sendFlowRecords()
			assert.NoError(t, err)
			assert.Equalf(t, uint64(1), destination.numConnsExported, "1 data set should have been sent.")

			switch id {
			case 0: // conntrack connection being active time out
				assert.True(t, pqItem.ActiveExpireTime.After(startTime))
				assert.Equal(t, conn.OriginalPackets, conn.PrevPackets)
				assert.Equalf(t, 1, destination.conntrackPriorityQueue.Len(), "Length of expire priority queue should be 1")
			case 1: // conntrack connection being idle time out and becoming inactive
				assert.False(t, conn.IsActive)
				assert.Equalf(t, 0, destination.conntrackPriorityQueue.Len(), "Length of expire priority queue should be 0")
			case 2: // conntrack connection with deleted connection
				assert.True(t, conn.ReadyToDelete)
				assert.Equalf(t, 0, destination.conntrackPriorityQueue.Len(), "Length of expire priority queue should be 0")
			case 3: // deny connection being active time out
				assert.True(t, pqItem.ActiveExpireTime.After(startTime))
				assert.Equal(t, denyConn.OriginalPackets, denyConn.PrevPackets)
				assert.Equalf(t, 1, destination.denyPriorityQueue.Len(), "Length of expire priority queue should be 1")
			case 4: // deny connection being active time out and becoming inactive
				assert.False(t, denyConn.IsActive)
				assert.Equalf(t, 0, destination.denyPriorityQueue.Len(), "Length of expire priority queue should be 0")
			case 5: // deny connection being idle time out
				assert.Equal(t, true, denyConn.ReadyToDelete)
				assert.Equalf(t, 0, destination.denyPriorityQueue.Len(), "Length of expire priority queue should be 0")
			}
		})
	}
}

func TestDestination_sendFlowRecords(t *testing.T) {
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

func TestDestination_fillEgressInfo(t *testing.T) {
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
			dest := &Destination{
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
			dest.fillEgressInfo(&conn)
			assert.Equal(t, tc.expectedEgressName, conn.EgressName)
			assert.Equal(t, tc.expectedEgressUID, conn.EgressUID)
			assert.Equal(t, tc.expectedEgressIP, conn.EgressIP)
			assert.Equal(t, tc.expectedEgressNodeName, conn.EgressNodeName)
		})
	}
}

func testSendFlowRecords(t *testing.T, v4Enabled bool, v6Enabled bool) {
	destination := &Destination{}

	if v4Enabled {
		runSendFlowRecordTests(t, destination, false)
	}
	if v6Enabled {
		runSendFlowRecordTests(t, destination, true)
	}
}

func TestDestination_findFlowType(t *testing.T) {
	conn1 := connection.Connection{SourcePodName: "podA", DestinationPodName: "podB"}
	conn2 := connection.Connection{SourcePodName: "podA", DestinationPodName: ""}
	for _, tc := range []struct {
		isNetworkPolicyOnly bool
		conn                connection.Connection
		expectedFlowType    uint8
	}{
		{true, conn1, 1},
		{true, conn2, 2},
		{false, conn1, 0},
	} {
		flowExp := &Destination{
			DestinationConfig: DestinationConfig{
				isNetworkPolicyOnly: tc.isNetworkPolicyOnly,
			},
		}
		flowType := flowExp.findFlowType(tc.conn)
		assert.Equal(t, tc.expectedFlowType, flowType)
	}
}

func TestDestination_Connect(t *testing.T) {
	metrics.InitializeConnectionMetrics()
	ctrl := gomock.NewController(t)
	mockExporter := exportertesting.NewMockInterface(ctrl)
	collectorAddr := "127.0.0.1:4739"
	exp := &Destination{
		DestinationConfig: DestinationConfig{
			address: collectorAddr,
		},
		exp: mockExporter,
	}
	// TODO: test the TLS case (requires certificates)
	mockExporter.EXPECT().ConnectToCollector(collectorAddr, nil)
	require.NoError(t, exp.Connect(context.Background()))
	assert.True(t, exp.connected)
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

func TestDestination_getExporterTLSConfig(t *testing.T) {
	caConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-cm",
			Namespace: "test-ns",
		},
		Data: map[string]string{
			"ca.crt": "ca data",
		},
	}
	badCAConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bad-ca-cm",
			Namespace: "test-ns",
		},
		Data: map[string]string{},
	}
	clientTLSSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "client-tls",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"tls.crt": []byte("client-cert"),
			"tls.key": []byte("client-key"),
		},
	}
	badClientTLSSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bad-client-tls",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"tls.crt": []byte("client-cert"),
			"tls.key": []byte("client-key"),
		},
	}
	destinationHost := "foo.example.com"
	destinationPort := "4739"
	destinationAddr := destinationHost + ":" + destinationPort

	tests := []struct {
		name              string
		tlsConfig         *v1alpha1.FlowExporterTLSConfig
		expectedTLSConfig *exporter.TLSConfig
		expectErr         bool
	}{
		{
			name:              "no tls configuration",
			expectedTLSConfig: nil,
			expectErr:         false,
		}, {
			name: "ca configmap defined",
			tlsConfig: &v1alpha1.FlowExporterTLSConfig{
				ServerName: "foobar",
				CAConfigMap: v1alpha1.NamespacedName{
					Name:      caConfigMap.Name,
					Namespace: caConfigMap.Namespace,
				},
			},
			expectedTLSConfig: &exporter.TLSConfig{
				ServerName: "foobar",
				CAData:     []byte(caConfigMap.Data["ca.crt"]),
			},
		}, {
			name: "ca configmap errors - does not exist",
			tlsConfig: &v1alpha1.FlowExporterTLSConfig{
				ServerName: "foobar",
				CAConfigMap: v1alpha1.NamespacedName{
					Name:      "unknown",
					Namespace: "unknown",
				},
			},
			expectErr: true,
		}, {
			name: "ca configmap errors - bad data",
			tlsConfig: &v1alpha1.FlowExporterTLSConfig{
				ServerName: "foobar",
				CAConfigMap: v1alpha1.NamespacedName{
					Name:      badCAConfigMap.Name,
					Namespace: badCAConfigMap.Namespace,
				},
			},
			expectErr: true,
		}, {
			name:      "ca configmap not defined",
			tlsConfig: &v1alpha1.FlowExporterTLSConfig{},
			expectErr: true,
		}, {
			name: "client secret defined",
			tlsConfig: &v1alpha1.FlowExporterTLSConfig{
				CAConfigMap: v1alpha1.NamespacedName{
					Name:      caConfigMap.Name,
					Namespace: caConfigMap.Namespace,
				},
				ClientSecret: &v1alpha1.NamespacedName{
					Name:      clientTLSSecret.Name,
					Namespace: clientTLSSecret.Namespace,
				},
			},
			expectedTLSConfig: &exporter.TLSConfig{
				ServerName: destinationHost,
				CAData:     []byte(caConfigMap.Data["ca.crt"]),
				CertData:   clientTLSSecret.Data["tls.crt"],
				KeyData:    clientTLSSecret.Data["tls.key"],
			},
		}, {
			name: "client secret errors - bad data",
			tlsConfig: &v1alpha1.FlowExporterTLSConfig{
				CAConfigMap: v1alpha1.NamespacedName{
					Name:      caConfigMap.Name,
					Namespace: caConfigMap.Namespace,
				},
				ClientSecret: &v1alpha1.NamespacedName{
					Name:      badClientTLSSecret.Name,
					Namespace: badClientTLSSecret.Namespace,
				},
			},
			expectErr: true,
		}, {
			name: "client secret errors - does not exist",
			tlsConfig: &v1alpha1.FlowExporterTLSConfig{
				CAConfigMap: v1alpha1.NamespacedName{
					Name:      caConfigMap.Name,
					Namespace: caConfigMap.Namespace,
				},
				ClientSecret: &v1alpha1.NamespacedName{
					Name:      "unknown",
					Namespace: "unknown",
				},
			},
			expectErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientset(caConfigMap, clientTLSSecret)
			d := &Destination{
				k8sClient: fakeClient,
				DestinationConfig: DestinationConfig{
					address:   destinationAddr,
					tlsConfig: tt.tlsConfig,
				},
			}
			tlsConfig, err := d.getExporterTLSConfig(context.Background())
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectedTLSConfig, tlsConfig)
		})
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
			addr, err := resolveCollectorAddress(ctx, k8sClient, tc.inputAddr)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedAddr, addr)
			}
		})
	}
}
