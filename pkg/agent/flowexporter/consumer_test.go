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
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/exporter"
	exportertesting "antrea.io/antrea/pkg/agent/flowexporter/exporter/testing"
	"antrea.io/antrea/pkg/agent/flowexporter/filter"
	"antrea.io/antrea/pkg/agent/flowexporter/options"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	. "antrea.io/antrea/pkg/agent/flowexporter/testing"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

const (
	testActiveFlowTimeout = 3 * time.Second
	testIdleFlowTimeout   = 1 * time.Second
)

func TestConsumer_resolveAddress(t *testing.T) {
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
		t.Run(tc.name, func(t *testing.T) {
			consumer := &Consumer{
				ConsumerConfig: &ConsumerConfig{
					address: tc.inputAddr,
				},
				k8sClient: k8sClient,
			}

			addr, name, err := consumer.resolveAddress(ctx)
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

func TestConsumer_handleUpdatedConns(t *testing.T) {
	tcpConn := GenerateConnectionFn(IncrementStats)
	udpConn := GenerateConnectionFn(AsUDPConnection)

	tests := []struct {
		name             string
		conns            []*connection.Connection
		existingL7Events map[connection.ConnectionKey]connections.L7ProtocolFields
		l7Events         map[connection.ConnectionKey]connections.L7ProtocolFields
		filter           []string
		existingStates   map[connection.ConnectionKey]prevState
		existingConns    []*connection.Connection
		expectedConns    []*connection.Connection
	}{
		{
			name: "no conns",
		}, {
			name:          "filtered connections",
			conns:         []*connection.Connection{tcpConn(), udpConn()},
			filter:        []string{"TCP"},
			expectedConns: []*connection.Connection{tcpConn()},
		}, {
			name:  "has old stats - active",
			conns: []*connection.Connection{tcpConn(IncrementStats)},
			existingStates: map[connection.ConnectionKey]prevState{tcpConn.ConnectionKey(): {
				stats:    tcpConn.OriginalStats(),
				tcpState: tcpConn.TCPState(),
			}},
			expectedConns: []*connection.Connection{tcpConn(IncrementStats)},
		}, {
			name:  "has old stats - inactive",
			conns: []*connection.Connection{tcpConn()},
			existingStates: map[connection.ConnectionKey]prevState{tcpConn.ConnectionKey(): {
				stats:    tcpConn.OriginalStats(),
				tcpState: tcpConn.TCPState(),
			}},
			expectedConns: []*connection.Connection{},
		},
		// TODO Andrew: Add case for PQ idle time update
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prevStates := tt.existingStates
			if prevStates == nil {
				prevStates = make(map[connection.ConnectionKey]prevState)
			}
			c := &Consumer{
				ConsumerConfig: &ConsumerConfig{
					idleFlowTimeout: 15 * time.Minute,
				},
				l7Events:            make(map[connection.ConnectionKey]connections.L7ProtocolFields, len(tt.l7Events)),
				prevStates:          prevStates,
				expirePriorityQueue: priorityqueue.NewExpirePriorityQueue(15*time.Minute, 30*time.Minute),
				protocolFilter:      filter.NewProtocolFilter(tt.filter),
			}

			c.handleUpdatedConns(tt.conns, tt.l7Events)

			assert.Len(t, c.expirePriorityQueue.KeyToItem, len(tt.expectedConns))
			pqConns := []*connection.Connection{}
			for _, item := range c.expirePriorityQueue.KeyToItem {
				pqConns = append(pqConns, item.Conn)
			}

			if !cmp.Equal(tt.expectedConns, pqConns, DefaultCmpOptions) {
				t.Errorf("pq items did not match (-want,+got):\n%s", cmp.Diff(tt.expectedConns, pqConns, DefaultCmpOptions))
			}
			assert.Len(t, c.l7Events, len(tt.l7Events))
		})
	}
}

func TestConsumer_sendFlowRecords(t *testing.T) {
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
	flowExp := CreateConsumer(nil, nil, ConsumerConfig{
		activeFlowTimeout: testActiveFlowTimeout,
		idleFlowTimeout:   testIdleFlowTimeout,
	})

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
func runSendFlowRecordTests(t *testing.T, flowExp *Consumer, isIPv6 bool) {
	ctrl := gomock.NewController(t)
	mockExporter := exportertesting.NewMockInterface(ctrl)
	flowExp.exp = mockExporter
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
			name:             "conntrack connection being active time out",
			isDenyConn:       false,
			isConnPresent:    true,
			tcpState:         "SYN_SENT",
			statusFlag:       4,
			protoID:          6,
			originalPackets:  1,
			reversePackets:   1,
			activeExpireTime: startTime.Add(-testActiveFlowTimeout),
			idleExpireTime:   startTime.Add(10 * testIdleFlowTimeout),
		},
		{
			name:             "conntrack connection being idle time out and becoming inactive",
			isDenyConn:       false,
			isConnPresent:    true,
			tcpState:         "SYN_SENT",
			statusFlag:       4,
			protoID:          6,
			activeExpireTime: startTime.Add(10 * testActiveFlowTimeout),
			idleExpireTime:   startTime.Add(-testIdleFlowTimeout),
		},
		{
			name:       "deny connection being active time out",
			isDenyConn: true,
			protoID:    6,
			// We increase the number of packets because these tests are building on each other.
			// A new denied connection would have increases the original packet amount
			originalPackets:  2,
			prevPackets:      1,
			activeExpireTime: startTime.Add(-testActiveFlowTimeout),
			idleExpireTime:   startTime.Add(10 * testIdleFlowTimeout),
		},
		{
			name:             "deny connection being idle time out",
			isDenyConn:       true,
			protoID:          6,
			originalPackets:  3,
			activeExpireTime: startTime.Add(10 * testActiveFlowTimeout),
			idleExpireTime:   startTime.Add(-testIdleFlowTimeout),
		},
	}
	for id, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var conn *connection.Connection
			var pqItem *priorityqueue.ItemToExpire

			if tt.isDenyConn {
				conn = GetDenyConnection(isIPv6, tt.protoID)
			} else {
				conn = GetConnection(isIPv6, tt.isConnPresent, tt.statusFlag, tt.protoID, tt.tcpState)
			}

			connKey := connection.NewConnectionKey(conn)
			conn.OriginalStats.Packets = tt.originalPackets
			conn.OriginalStats.ReversePackets = tt.reversePackets
			flowExp.handleUpdatedConns([]*connection.Connection{conn}, nil)
			assert.Equalf(t, flowExp.expirePriorityQueue.Len(), 1, "connection is expected to be in the connection map")
			pqItem = flowExp.expirePriorityQueue.KeyToItem[connKey]
			pqItem.ActiveExpireTime = tt.activeExpireTime
			pqItem.IdleExpireTime = tt.idleExpireTime

			var exportedConn *connection.Connection
			mockExporter.EXPECT().Export(gomock.Any()).Do(func(c *connection.Connection) {
				exportedConn = c
			})

			_, err := flowExp.sendFlowRecords()
			assert.NoError(t, err)

			switch id {
			case 0: // conntrack connection being active time out
				assert.True(t, pqItem.ActiveExpireTime.After(startTime))
				assert.Equal(t, tt.prevPackets, exportedConn.PreviousStats.Packets)
				assert.Equal(t, tt.prevReversePackets, exportedConn.PreviousStats.ReversePackets)
				assert.Equalf(t, 1, flowExp.expirePriorityQueue.Len(), "Length of expire priority queue should be 1")
			case 1: // conntrack connection being idle time out and becoming inactive
				assert.False(t, conn.IsActive)
				assert.Equalf(t, 0, flowExp.expirePriorityQueue.Len(), "Length of expire priority queue should be 0")
			case 2: // deny connection being active time out
				assert.True(t, pqItem.ActiveExpireTime.After(startTime))
				assert.Equal(t, tt.prevPackets, exportedConn.PreviousStats.Packets)
				assert.Equalf(t, 1, flowExp.expirePriorityQueue.Len(), "Length of expire priority queue should be 1")
			case 3: // deny connection being idle time out
				assert.False(t, conn.IsActive)
				assert.Equalf(t, 0, flowExp.expirePriorityQueue.Len(), "Length of expire priority queue should be 0")
			}
		})
	}
}

func TestConsumer_Connect(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockExporter := exportertesting.NewMockInterface(ctrl)

	k8sClient := fake.NewClientset(
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
		}, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "flow-aggregator-ca",
				Namespace: "ns",
			},
			Data: map[string]string{
				"ca.crt": "certdata",
			},
		}, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "flow-aggregator-client-tls",
				Namespace: "ns",
			},
			Data: map[string][]byte{
				"tls.crt": []byte("tlscert"),
				"tls.key": []byte("tlskey"),
			},
		},
	)

	tests := []struct {
		name             string
		store            connections.StoreSubscriber
		addrOverride     string
		exporterOverride exporter.Interface
		connected        bool
		protocol         v1alpha1.FlowExporterProtocol

		wantErr       bool
		exporterType  exporter.Interface
		wantConnected bool
	}{
		{
			name:      "already connected",
			connected: true,
		}, {
			name: "grpc exporter type",
			protocol: v1alpha1.FlowExporterProtocol{
				GRPC: &v1alpha1.FlowExporterGRPCConfig{},
			},
			addrOverride: "unknown/invalid:4739",
			wantErr:      true, // Error because the service doesn't exist
			exporterType: exporter.NewGRPCExporter("", "", 0),
		}, {
			name: "ipfix exporter type",
			protocol: v1alpha1.FlowExporterProtocol{
				IPFIX: &v1alpha1.FlowExporterIPFIXConfig{},
			},
			addrOverride: "unknown/invalid:4739",
			wantErr:      true, // Error because the service doesn't exist
			exporterType: exporter.NewIPFIXExporter("", "", 0, false, false),
		}, {
			name: "exporter connects",
			protocol: v1alpha1.FlowExporterProtocol{
				IPFIX: &v1alpha1.FlowExporterIPFIXConfig{},
			}, exporterOverride: mockExporter,
			addrOverride:  "ns/svc1:4739",
			wantConnected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantConnected {
				mockExporter.EXPECT().ConnectToCollector(gomock.Any(), gomock.Any())
			}

			cfg := ConsumerConfig{
				address:     "ns/svc1:4739",
				nodeName:    "X",
				nodeUID:     "UID1",
				obsDomainID: 100,
				v4Enabled:   true,
				v6Enabled:   true,
				protocol:    getExporterProtocol(tt.protocol),
			}
			if tt.addrOverride != "" {
				cfg.address = tt.addrOverride
			}
			c := CreateConsumer(k8sClient, nil, cfg)
			c.connected = tt.connected
			if tt.exporterOverride != nil {
				c.exp = tt.exporterOverride
			}

			gotErr := c.Connect(context.Background())
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Connect() failed: %v", gotErr)
					return
				}
			} else if tt.wantErr {
				t.Fatal("Connect() succeeded unexpectedly")
			}

			if tt.exporterType != nil {
				assert.IsType(t, tt.exporterType, c.exp)
			}

			if tt.wantConnected {
				assert.True(t, c.connected)
			}
		})
	}
}

func TestConsumer_getExporterTLSConfig(t *testing.T) {
	k8sClient := fake.NewClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "flow-aggregator-ca",
				Namespace: "ns",
			},
			Data: map[string]string{
				"ca.crt": "certdata",
			},
		}, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "flow-aggregator-client-tls",
				Namespace: "ns",
			},
			Data: map[string][]byte{
				"tls.crt": []byte("tlscert"),
				"tls.key": []byte("tlskey"),
			},
		},
	)

	tests := []struct {
		name string

		dnsName           string
		expectedTLSConfig *exporter.TLSConfig
		wantErr           bool
	}{
		{
			name:    "has certs",
			dnsName: "svc1.ns",
			expectedTLSConfig: &exporter.TLSConfig{
				ServerName: "svc1.ns",
				CAData:     []byte("certdata"),
				CertData:   []byte("tlscert"),
				KeyData:    []byte("tlskey"),
			},
		}, {
			name:              "not found",
			dnsName:           "x.y",
			expectedTLSConfig: nil,
			wantErr:           true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := CreateConsumer(k8sClient, nil, ConsumerConfig{protocol: &v1alpha1.FlowExporterGRPCConfig{}})

			tlsConfig, gotErr := c.getExporterTLSConfig(context.Background(), tt.dnsName)
			if tt.wantErr {
				require.Error(t, gotErr)
			} else {
				require.NoError(t, gotErr)
			}

			assert.Equal(t, tt.expectedTLSConfig, tlsConfig)
		})
	}
}

func TestConsumer_handleDeleteConns(t *testing.T) {
	c := CreateConsumer(nil, nil, ConsumerConfig{})

	require.Empty(t, c.expirePriorityQueue.KeyToItem)
	require.Empty(t, c.prevStates)
	require.Empty(t, c.l7Events)

	conn := GenerateConnectionFn()
	c.expirePriorityQueue.WriteItemToQueue(conn.ConnectionKey(), conn())
	c.prevStates[conn.ConnectionKey()] = prevState{}
	c.l7Events[conn.ConnectionKey()] = connections.L7ProtocolFields{}

	require.Len(t, c.expirePriorityQueue.KeyToItem, 1)
	require.Len(t, c.prevStates, 1)
	require.Len(t, c.l7Events, 1)

	c.handleDeletedConns([]*connection.Connection{conn()})

	require.Empty(t, c.expirePriorityQueue.KeyToItem)
	require.Empty(t, c.prevStates)
	require.Empty(t, c.l7Events)
}

func TestConsumer_Run(t *testing.T) {
	c := CreateConsumer(nil, nil, ConsumerConfig{activeFlowTimeout: 1 * time.Hour})
	c.store = connections.NewConnStore(nil, true, false, nil, nil, nil, nil, nil, nil, nil, false, &options.FlowExporterOptions{
		StaleConnectionTimeout: 10 * time.Minute,
		PollInterval:           10 * time.Minute,
		ConnectUplinkToBridge:  false,
	})

	gracefulShutdownCh := make(chan struct{})
	stopCh := make(chan struct{})
	go func() {
		defer close(gracefulShutdownCh)
		c.Run(stopCh)
	}()

	time.Sleep(1 * time.Second)
	close(stopCh)

	select {
	case <-gracefulShutdownCh:
		// All good
	case <-time.After(1 * time.Second):
		require.Fail(t, "expected a graceful and quick shutdown")
	}
}
