// Copyright 2021 Antrea Authors
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

package connections

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	connectionstest "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	"antrea.io/antrea/pkg/agent/flowexporter/options"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
	proxytest "antrea.io/antrea/pkg/agent/proxy/testing"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	secv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	queriertest "antrea.io/antrea/pkg/querier/testing"
	objectstoretest "antrea.io/antrea/pkg/util/objectstore/testing"
	utilwait "antrea.io/antrea/pkg/util/wait"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

var (
	pod1 = &v1.Pod{
		Status: v1.PodStatus{
			PodIPs: []v1.PodIP{
				{
					IP: "8.7.6.5",
				},
				{
					IP: "4.3.2.1",
				},
			},
			Phase: v1.PodRunning,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod1",
			Namespace: "ns1",
		},
	}
	servicePortName = k8sproxy.ServicePortName{
		NamespacedName: types.NamespacedName{
			Namespace: "serviceNS1",
			Name:      "service1",
		},
		Port:     "255",
		Protocol: v1.ProtocolTCP,
	}
	np1 = cpv1beta.NetworkPolicyReference{
		Type:      cpv1beta.K8sNetworkPolicy,
		Namespace: "foo",
		Name:      "bar",
		UID:       "uid1",
	}
	action = secv1beta1.RuleActionAllow
	rule1  = agenttypes.PolicyRule{
		Direction: cpv1beta.DirectionIn,
		From:      []agenttypes.Address{},
		To:        []agenttypes.Address{},
		Service:   []cpv1beta.Service{},
		Action:    &action,
		Priority:  nil,
		Name:      "",
		FlowID:    uint32(0),
		TableID:   uint8(10),
		PolicyRef: &np1,
	}
)

func TestConntrackConnectionStore_AddOrUpdateConn(t *testing.T) {
	refTime := time.Now()
	networkPolicyReadyTime := refTime.Add(-time.Hour)

	tuple := connection.Tuple{SourceAddress: netip.MustParseAddr("5.6.7.8"), DestinationAddress: netip.MustParseAddr("8.7.6.5"), Protocol: 6, SourcePort: 60001, DestinationPort: 200}

	tc := []struct {
		name                             string
		oldConn                          *connection.Connection
		newConn                          connection.Connection
		expectedConn                     connection.Connection
		expectNetworkPolicyMetadataAdded bool
	}{
		{
			name:                             "addNewConn",
			oldConn:                          nil,
			expectNetworkPolicyMetadataAdded: true,
			newConn: connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey:   tuple,
				Labels:    []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
				Mark:      openflow.ServiceCTMark.GetValue(),
				Zone:      65520,
			},
			expectedConn: connection.Connection{
				StartTime:                      refTime,
				StopTime:                       refTime,
				LastExportTime:                 refTime,
				FlowKey:                        tuple,
				Labels:                         []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
				Mark:                           openflow.ServiceCTMark.GetValue(),
				IsPresent:                      true,
				IsActive:                       true,
				DestinationPodName:             "pod1",
				DestinationPodNamespace:        "ns1",
				DestinationServicePortName:     servicePortName.String(),
				IngressNetworkPolicyName:       np1.Name,
				IngressNetworkPolicyNamespace:  np1.Namespace,
				IngressNetworkPolicyUID:        string(np1.UID),
				IngressNetworkPolicyType:       utils.PolicyTypeToUint8(np1.Type),
				IngressNetworkPolicyRuleName:   rule1.Name,
				IngressNetworkPolicyRuleAction: utils.RuleActionToUint8(string(*rule1.Action)),
				Zone:                           65520,
			},
		},
		{
			name:                             "updateActiveConn",
			expectNetworkPolicyMetadataAdded: false, // Update case doesn't add NetworkPolicy metadata
			oldConn: &connection.Connection{
				StartTime:       refTime.Add(-(time.Second * 50)),
				StopTime:        refTime.Add(-(time.Second * 30)),
				LastExportTime:  refTime.Add(-(time.Second * 50)),
				OriginalPackets: 0xfff,
				OriginalBytes:   0xbaaaaa00000000,
				ReversePackets:  0xf,
				ReverseBytes:    0xbaa,
				FlowKey:         tuple,
				IsPresent:       true,
				Zone:            65520,
			},
			newConn: connection.Connection{
				StartTime:       refTime.Add(-(time.Second * 50)),
				StopTime:        refTime,
				OriginalPackets: 0xffff,
				OriginalBytes:   0xbaaaaa0000000000,
				ReversePackets:  0xff,
				ReverseBytes:    0xbaaa,
				FlowKey:         tuple,
				IsPresent:       true,
				Zone:            65520,
			},
			expectedConn: connection.Connection{
				StartTime:       refTime.Add(-(time.Second * 50)),
				StopTime:        refTime,
				LastExportTime:  refTime.Add(-(time.Second * 50)),
				OriginalPackets: 0xffff,
				OriginalBytes:   0xbaaaaa0000000000,
				ReversePackets:  0xff,
				ReverseBytes:    0xbaaa,
				FlowKey:         tuple,
				IsPresent:       true,
				IsActive:        true,
				Zone:            65520,
			},
		},
		{
			// If the polled new connection is dying, the old connection present
			// in connection store will not be updated.
			name:                             "updateDyingConn",
			expectNetworkPolicyMetadataAdded: false, // Update case doesn't add NetworkPolicy metadata
			oldConn: &connection.Connection{
				StartTime:       refTime.Add(-(time.Second * 50)),
				StopTime:        refTime.Add(-(time.Second * 30)),
				LastExportTime:  refTime.Add(-(time.Second * 50)),
				OriginalPackets: 0xfff,
				OriginalBytes:   0xbaaaaa00000000,
				ReversePackets:  0xf,
				ReverseBytes:    0xba,
				FlowKey:         tuple,
				TCPState:        "TIME_WAIT",
				IsPresent:       true,
			},
			newConn: connection.Connection{
				StartTime:       refTime.Add(-(time.Second * 50)),
				StopTime:        refTime,
				OriginalPackets: 0xffff,
				OriginalBytes:   0xbaaaaa0000000000,
				ReversePackets:  0xff,
				ReverseBytes:    0xbaaa,
				FlowKey:         tuple,
				TCPState:        "TIME_WAIT",
				IsPresent:       true,
			},
			expectedConn: connection.Connection{
				StartTime:       refTime.Add(-(time.Second * 50)),
				StopTime:        refTime.Add(-(time.Second * 30)),
				LastExportTime:  refTime.Add(-(time.Second * 50)),
				OriginalPackets: 0xfff,
				OriginalBytes:   0xbaaaaa00000000,
				ReversePackets:  0xf,
				ReverseBytes:    0xba,
				FlowKey:         tuple,
				TCPState:        "TIME_WAIT",
				IsPresent:       true,
			},
		},
		{
			name:                             "addConnWithOldTimestamp_NoNetworkPolicyMetadata",
			oldConn:                          nil,
			expectNetworkPolicyMetadataAdded: false,
			newConn: connection.Connection{
				StartTime: networkPolicyReadyTime.Add(-time.Minute), // Before NetworkPolicy ready
				StopTime:  refTime,
				FlowKey:   tuple,
				Labels:    []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
				Mark:      openflow.ServiceCTMark.GetValue(),
				Zone:      65520,
			},
			expectedConn: connection.Connection{
				StartTime:                  networkPolicyReadyTime.Add(-time.Minute),
				StopTime:                   refTime,
				LastExportTime:             networkPolicyReadyTime.Add(-time.Minute),
				FlowKey:                    tuple,
				Labels:                     []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
				Mark:                       openflow.ServiceCTMark.GetValue(),
				IsPresent:                  true,
				IsActive:                   true,
				DestinationPodName:         "pod1",
				DestinationPodNamespace:    "ns1",
				DestinationServicePortName: servicePortName.String(),
				Zone:                       65520,
				// NetworkPolicy fields should be empty for old connections
			},
		},
	}

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			mockProxier := proxytest.NewMockProxyQuerier(ctrl)
			mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
			npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)

			conntrackConnStore := NewConntrackConnectionStore(mockConnDumper, true, false, npQuerier, mockPodStore, mockProxier, nil, testFlowExporterOptions)
			// Set the networkPolicyReadyTime to simulate that NetworkPolicies are ready
			conntrackConnStore.networkPolicyReadyTime = networkPolicyReadyTime

			// Add the existing connection to the connection store.
			if c.oldConn != nil {
				addConnToStore(conntrackConnStore, c.oldConn)
			} else {
				testAddNewConn(mockPodStore, mockProxier, npQuerier, c.newConn, c.expectNetworkPolicyMetadataAdded)
			}
			conntrackConnStore.AddOrUpdateConn(&c.newConn)
			actualConn, exist := conntrackConnStore.GetConnByKey(connection.NewConnectionKey(&c.newConn))
			require.Equal(t, exist, true, "The connection should exist in the connection store")
			assert.Equal(t, c.expectedConn, *actualConn, "Connections should be equal")
			require.Equal(t, 1, conntrackConnStore.connectionStore.expirePriorityQueue.Len(), "Length of the expire priority queue should be 1")
			conntrackConnStore.connectionStore.expirePriorityQueue.Pop() // empty the PQ
		})
	}
}

func TestConntrackConnectionStore_AddOrUpdateConn_FromExternalConns(t *testing.T) {
	refTime := time.Now()
	networkPolicyReadyTime := refTime.Add(-time.Hour)

	tc := []struct {
		name                             string
		oldConn                          *connection.Connection
		newConn                          connection.Connection
		expectedConn                     connection.Connection
		updatedConn                      connection.Connection
		expectedUpdatedConn              connection.Connection
		expectNetworkPolicyMetadataAdded bool
	}{
		{
			name:                             "correlateConn",
			expectNetworkPolicyMetadataAdded: true,
			oldConn: &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("172.18.0.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         52142,
					DestinationPort:    80},
				Mark:          openflow.ServiceCTMark.GetValue(),
				ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
				ProxySnatPort: uint16(28392),
			},
			newConn: connection.Connection{
				StartTime:      refTime.Add(-(time.Second * 50)),
				StopTime:       refTime.Add(-(time.Second * 30)),
				LastExportTime: refTime.Add(-(time.Second * 50)),
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("10.244.2.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         28392,
					DestinationPort:    80},
				Mark:            openflow.ServiceCTMark.GetValue(),
				Labels:          []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
				ProxySnatIP:     netip.MustParseAddr("10.244.2.1"),
				ProxySnatPort:   uint16(28392),
				Zone:            65520,
				OriginalPackets: 0xfff,
			},
			updatedConn: connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("10.244.2.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         28392,
					DestinationPort:    80},
				Mark:            openflow.ServiceCTMark.GetValue(),
				Labels:          []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
				ProxySnatIP:     netip.MustParseAddr("10.244.2.1"),
				ProxySnatPort:   uint16(28392),
				Zone:            65520,
				OriginalPackets: 0xffff,
			},
			expectedConn: connection.Connection{
				StartTime:      refTime.Add(-(time.Second * 50)),
				StopTime:       refTime.Add(-(time.Second * 30)),
				LastExportTime: refTime.Add(-(time.Second * 50)),
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("172.18.0.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         52142,
					DestinationPort:    80},
				Mark:                           openflow.ServiceCTMark.GetValue(),
				Labels:                         []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
				IsPresent:                      true,
				IsActive:                       true,
				DestinationPodName:             "pod1",
				DestinationPodNamespace:        "ns1",
				DestinationServicePortName:     servicePortName.String(),
				IngressNetworkPolicyName:       np1.Name,
				IngressNetworkPolicyNamespace:  np1.Namespace,
				IngressNetworkPolicyUID:        string(np1.UID),
				IngressNetworkPolicyType:       utils.PolicyTypeToUint8(np1.Type),
				IngressNetworkPolicyRuleName:   rule1.Name,
				IngressNetworkPolicyRuleAction: utils.RuleActionToUint8(string(*rule1.Action)),
				Zone:                           65520,
				OriginalPackets:                0xfff,
				ProxySnatIP:                    netip.MustParseAddr("172.18.0.2"),
				ProxySnatPort:                  uint16(28392),
			},
			expectedUpdatedConn: connection.Connection{
				StartTime:      refTime.Add(-(time.Second * 50)),
				StopTime:       refTime,
				LastExportTime: refTime.Add(-(time.Second * 50)),
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("172.18.0.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         52142,
					DestinationPort:    80},
				Mark:                           openflow.ServiceCTMark.GetValue(),
				Labels:                         []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
				IsPresent:                      true,
				IsActive:                       true,
				DestinationPodName:             "pod1",
				DestinationPodNamespace:        "ns1",
				DestinationServicePortName:     servicePortName.String(),
				IngressNetworkPolicyName:       np1.Name,
				IngressNetworkPolicyNamespace:  np1.Namespace,
				IngressNetworkPolicyUID:        string(np1.UID),
				IngressNetworkPolicyType:       utils.PolicyTypeToUint8(np1.Type),
				IngressNetworkPolicyRuleName:   rule1.Name,
				IngressNetworkPolicyRuleAction: utils.RuleActionToUint8(string(*rule1.Action)),
				Zone:                           65520,
				OriginalPackets:                0xffff,
				ProxySnatIP:                    netip.MustParseAddr("172.18.0.2"),
				ProxySnatPort:                  uint16(28392),
			},
		},
	}

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			mockProxier := proxytest.NewMockProxyQuerier(ctrl)
			mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
			npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
			conntrackConnStore := NewConntrackConnectionStore(mockConnDumper, true, false, npQuerier, mockPodStore, mockProxier, nil, nil, testFlowExporterOptions)
			// Set the networkPolicyReadyTime to simulate that NetworkPolicies are ready
			conntrackConnStore.networkPolicyReadyTime = networkPolicyReadyTime

			// Add Zone Zero
			conntrackConnStore.AddOrUpdateConn(c.oldConn)

			// Add Antrea Zone
			mockPodStore.EXPECT().GetPodByIPAndTime(c.expectedConn.FlowKey.SourceAddress.String(), gomock.Any()).Return(nil, false)
			mockPodStore.EXPECT().GetPodByIPAndTime(c.expectedConn.FlowKey.DestinationAddress.String(), gomock.Any()).Return(pod1, true)
			protocol, _ := lookupServiceProtocol(c.expectedConn.FlowKey.Protocol)
			serviceStr := fmt.Sprintf("%s:%d/%s", c.expectedConn.OriginalDestinationAddress.String(), c.newConn.OriginalDestinationPort, protocol)
			mockProxier.EXPECT().GetServiceByIP(serviceStr).Return(servicePortName, true)
			ingressOfID := binary.BigEndian.Uint32(c.expectedConn.Labels[12:16])
			npQuerier.EXPECT().GetRuleByFlowID(ingressOfID).Return(&rule1)
			conntrackConnStore.AddOrUpdateConn(&c.newConn)

			actualConn, exist := conntrackConnStore.GetConnByKey(c.expectedConn.FlowKey)
			require.Equal(t, exist, true, "The connection should exist in the connection store")
			assert.Equal(t, c.expectedConn, *actualConn, "Connections should be equal")

			// Re-add Antrea zone
			conntrackConnStore.AddOrUpdateConn(&c.updatedConn)
			actualConn, exist = conntrackConnStore.GetConnByKey(c.expectedConn.FlowKey)
			require.Equal(t, exist, true, "The connection should exist in the connection store")
			assert.Equal(t, c.expectedUpdatedConn, *actualConn, "Connections should be equal")
		})
	}
}

// testAddNewConn tests podInfo, Services, network policy mapping.
func testAddNewConn(mockPodStore *objectstoretest.MockPodStore, mockProxier *proxytest.MockProxyQuerier, npQuerier *queriertest.MockAgentNetworkPolicyInfoQuerier, conn connection.Connection, expectNetworkPolicyMetadataAdded bool) {
	mockPodStore.EXPECT().GetPodByIPAndTime(conn.FlowKey.SourceAddress.String(), gomock.Any()).Return(nil, false)
	mockPodStore.EXPECT().GetPodByIPAndTime(conn.FlowKey.DestinationAddress.String(), gomock.Any()).Return(pod1, true)

	protocol, _ := lookupServiceProtocol(conn.FlowKey.Protocol)
	serviceStr := fmt.Sprintf("%s:%d/%s", conn.OriginalDestinationAddress.String(), conn.OriginalDestinationPort, protocol)
	mockProxier.EXPECT().GetServiceByIP(serviceStr).Return(servicePortName, true)

	if expectNetworkPolicyMetadataAdded {
		ingressOfID := binary.BigEndian.Uint32(conn.Labels[12:16])
		npQuerier.EXPECT().GetRuleByFlowID(ingressOfID).Return(&rule1)
	}
}

// addConntrackConnToMap adds a conntrack connection to the connection map and
// increment the metric.
func addConnToStore(cs *ConntrackConnectionStore, conn *connection.Connection) {
	connKey := connection.NewConnectionKey(conn)
	cs.AddConnToMap(&connKey, conn)
	cs.expirePriorityQueue.WriteItemToQueue(connKey, conn)
	metrics.TotalAntreaConnectionsInConnTrackTable.Inc()
}

func TestConnectionStore_DeleteConnectionByKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	// Create two flows; one is already in connectionStore and other one is new
	testFlows := make([]*connection.Connection, 2)
	testFlowKeys := make([]*connection.ConnectionKey, 2)
	refTime := time.Now()
	// Flow-1, which is already in connectionStore
	tuple1 := connection.Tuple{SourceAddress: netip.MustParseAddr("1.2.3.4"), DestinationAddress: netip.MustParseAddr("4.3.2.1"), Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	testFlows[0] = &connection.Connection{
		StartTime:       refTime.Add(-(time.Second * 50)),
		StopTime:        refTime,
		OriginalPackets: 0xffff,
		OriginalBytes:   0xbaaaaa0000000000,
		ReversePackets:  0xff,
		ReverseBytes:    0xbaaa,
		FlowKey:         tuple1,
		IsPresent:       true,
	}
	// Flow-2, which is not in connectionStore
	tuple2 := connection.Tuple{SourceAddress: netip.MustParseAddr("5.6.7.8"), DestinationAddress: netip.MustParseAddr("8.7.6.5"), Protocol: 6, SourcePort: 60001, DestinationPort: 200}
	testFlows[1] = &connection.Connection{
		StartTime:       refTime.Add(-(time.Second * 20)),
		StopTime:        refTime,
		OriginalPackets: 0xbb,
		OriginalBytes:   0xcbbb,
		ReversePackets:  0xbbbb,
		ReverseBytes:    0xcbbbb0000000000,
		FlowKey:         tuple2,
		IsPresent:       true,
	}
	for i, flow := range testFlows {
		connKey := connection.NewConnectionKey(flow)
		testFlowKeys[i] = &connKey
	}
	// For testing purposes, set the metric
	metrics.TotalAntreaConnectionsInConnTrackTable.Set(float64(len(testFlows)))
	// Create connectionStore
	mockPodStore := objectstoretest.NewMockPodStore(ctrl)
	connStore := NewConntrackConnectionStore(nil, true, false, nil, mockPodStore, nil, nil, testFlowExporterOptions)
	// Add flows to the connection store.
	for i, flow := range testFlows {
		connStore.connections[*testFlowKeys[i]] = flow
	}
	// Delete the connections in connection store.
	for i := 0; i < len(testFlows); i++ {
		err := connStore.deleteConnWithoutLock(*testFlowKeys[i])
		assert.Nil(t, err, "DeleteConnectionByKey should return nil")
		_, exists := connStore.GetConnByKey(*testFlowKeys[i])
		assert.Equal(t, exists, false, "connection should be deleted in connection store")
		checkAntreaConnectionMetrics(t, len(connStore.connections))
	}
}

func TestZoneZeroCache_Delete(t *testing.T) {
	refTime := time.Now()
	networkPolicyReadyTime := refTime.Add(-time.Hour)

	oldConn := connection.Connection{
		StartTime: refTime,
		StopTime:  refTime,
		FlowKey: connection.Tuple{
			SourceAddress:      netip.MustParseAddr("172.18.0.1"),
			DestinationAddress: netip.MustParseAddr("10.244.2.2"),
			Protocol:           6,
			SourcePort:         52142,
			DestinationPort:    80},
		Mark:          openflow.ServiceCTMark.GetValue(),
		ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
		ProxySnatPort: uint16(28392),
	}
	newConn := connection.Connection{
		StartTime:      refTime.Add(-(time.Second * 50)),
		StopTime:       refTime.Add(-(time.Second * 30)),
		LastExportTime: refTime.Add(-(time.Second * 50)),
		FlowKey: connection.Tuple{
			SourceAddress:      netip.MustParseAddr("10.244.2.1"),
			DestinationAddress: netip.MustParseAddr("10.244.2.2"),
			Protocol:           6,
			SourcePort:         28392,
			DestinationPort:    80},
		Mark:            openflow.ServiceCTMark.GetValue(),
		Labels:          []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
		ProxySnatIP:     netip.MustParseAddr("10.244.2.1"),
		ProxySnatPort:   uint16(28392),
		Zone:            65520,
		OriginalPackets: 0xfff,
	}
	expectedConn := connection.Connection{
		StartTime:      refTime.Add(-(time.Second * 50)),
		StopTime:       refTime.Add(-(time.Second * 30)),
		LastExportTime: refTime.Add(-(time.Second * 50)),
		FlowKey: connection.Tuple{
			SourceAddress:      netip.MustParseAddr("172.18.0.1"),
			DestinationAddress: netip.MustParseAddr("10.244.2.2"),
			Protocol:           6,
			SourcePort:         52142,
			DestinationPort:    80},
		Mark:                           openflow.ServiceCTMark.GetValue(),
		Labels:                         []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
		IsPresent:                      true,
		IsActive:                       true,
		DestinationPodName:             "pod1",
		DestinationPodNamespace:        "ns1",
		DestinationServicePortName:     servicePortName.String(),
		IngressNetworkPolicyName:       np1.Name,
		IngressNetworkPolicyNamespace:  np1.Namespace,
		IngressNetworkPolicyUID:        string(np1.UID),
		IngressNetworkPolicyType:       utils.PolicyTypeToUint8(np1.Type),
		IngressNetworkPolicyRuleName:   rule1.Name,
		IngressNetworkPolicyRuleAction: utils.RuleActionToUint8(string(*rule1.Action)),
		Zone:                           65520,
		OriginalPackets:                0xfff,
		ProxySnatIP:                    netip.MustParseAddr("172.18.0.2"),
		ProxySnatPort:                  uint16(28392),
	}

	ctrl := gomock.NewController(t)
	mockPodStore := objectstoretest.NewMockPodStore(ctrl)
	mockProxier := proxytest.NewMockProxyQuerier(ctrl)
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
	conntrackConnStore := NewConntrackConnectionStore(mockConnDumper, true, false, npQuerier, mockPodStore, mockProxier, nil, nil, testFlowExporterOptions)
	// Set the networkPolicyReadyTime to simulate that NetworkPolicies are ready
	conntrackConnStore.networkPolicyReadyTime = networkPolicyReadyTime

	// Add Zone Zero
	conntrackConnStore.AddOrUpdateConn(&oldConn)

	// Add Antrea Zone
	mockPodStore.EXPECT().GetPodByIPAndTime(expectedConn.FlowKey.SourceAddress.String(), gomock.Any()).Return(nil, false)
	mockPodStore.EXPECT().GetPodByIPAndTime(expectedConn.FlowKey.DestinationAddress.String(), gomock.Any()).Return(pod1, true)
	protocol, _ := lookupServiceProtocol(expectedConn.FlowKey.Protocol)
	serviceStr := fmt.Sprintf("%s:%d/%s", expectedConn.OriginalDestinationAddress.String(), newConn.OriginalDestinationPort, protocol)
	mockProxier.EXPECT().GetServiceByIP(serviceStr).Return(servicePortName, true)
	ingressOfID := binary.BigEndian.Uint32(expectedConn.Labels[12:16])
	npQuerier.EXPECT().GetRuleByFlowID(ingressOfID).Return(&rule1)
	newConnCopy := newConn
	conntrackConnStore.AddOrUpdateConn(&newConn)

	_, exist := conntrackConnStore.GetConnByKey(expectedConn.FlowKey)
	assert.True(t, exist)

	actualConn, _ := conntrackConnStore.GetConnByKey(expectedConn.FlowKey)
	assert.Equal(t, expectedConn, *actualConn, "Connections should be equal")

	conntrackConnStore.zoneZeroCache.Delete(actualConn)

	matchingConn := conntrackConnStore.zoneZeroCache.GetMatching(&newConnCopy)
	assert.Nil(t, matchingConn, "The connection should be deleted from the ZoneZeroCache")
}

func TestConnectionStore_MetricSettingInPoll(t *testing.T) {
	ctrl := gomock.NewController(t)

	testFlows := make([]*connection.Connection, 0)
	// Create connectionStore
	mockPodStore := objectstoretest.NewMockPodStore(ctrl)
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	conntrackConnStore := NewConntrackConnectionStore(mockConnDumper, true, false, nil, mockPodStore, nil, nil, testFlowExporterOptions)
	// Hard-coded conntrack occupancy metrics for test
	TotalConnections := 0
	MaxConnections := 300000
	mockConnDumper.EXPECT().DumpFlows(uint16(0)).Return(testFlows, TotalConnections, nil)
	mockConnDumper.EXPECT().DumpFlows(uint16(openflow.CtZone)).Return(testFlows, TotalConnections, nil)
	mockConnDumper.EXPECT().GetMaxConnections().Return(MaxConnections, nil)
	connsLens, err := conntrackConnStore.Poll()
	require.Nil(t, err, fmt.Sprintf("Failed to add connections to connection store: %v", err))
	assert.Equal(t, 2, len(connsLens), "length of connsLens is expected to be 2")
	assert.Equal(t, len(testFlows), connsLens[0], "expected connections should be equal to number of testFlows")
	checkTotalConnectionsMetric(t, TotalConnections)
	checkMaxConnectionsMetric(t, MaxConnections)
}

func TestConntrackConnectionStore_Run_NetworkPolicyWait(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)

	// Create a utilwait.Group and increment it to simulate waiting for NetworkPolicies
	networkPolicyWait := utilwait.NewGroup()
	networkPolicyWait.Increment()

	testOptions := &options.FlowExporterOptions{
		ActiveFlowTimeout:      testActiveFlowTimeout,
		IdleFlowTimeout:        testIdleFlowTimeout,
		StaleConnectionTimeout: testStaleConnectionTimeout,
		PollInterval:           100 * time.Millisecond, // Valid but small poll interval
	}
	conntrackConnStore := NewConntrackConnectionStore(mockConnDumper, true, false, nil, nil, nil, networkPolicyWait, testOptions)

	// Create a signal channel that will be closed on the final DumpFlows call
	firstPollDoneCh := make(chan struct{})

	// Set up mock expectations - close signal channel on final DumpFlows call, then return normally
	mockConnDumper.EXPECT().DumpFlows(uint16(0)).DoAndReturn(func(uint16) ([]*connection.Connection, int, error) {
		return []*connection.Connection{}, 0, nil
	}).Times(1)
	mockConnDumper.EXPECT().DumpFlows(uint16(openflow.CtZone)).DoAndReturn(func(uint16) ([]*connection.Connection, int, error) {
		defer close(firstPollDoneCh)
		return []*connection.Connection{}, 0, nil
	}).Times(1)
	mockConnDumper.EXPECT().DumpFlows(uint16(openflow.CtZone)).Return([]*connection.Connection{}, 0, nil).AnyTimes()
	mockConnDumper.EXPECT().GetMaxConnections().Return(0, nil).AnyTimes()

	// Record the time before starting Run
	beforeRunTime := time.Now()

	// Verify that networkPolicyReadyTime is initially zero
	require.Zero(t, conntrackConnStore.networkPolicyReadyTime)

	// Start the connection store in a goroutine
	stopCh := make(chan struct{})
	closeStopCh := sync.OnceFunc(func() { close(stopCh) })
	defer closeStopCh()
	runFinishedCh := make(chan struct{})
	go func() {
		defer close(runFinishedCh)
		conntrackConnStore.Run(stopCh)
	}()

	// Signal that NetworkPolicies are ready
	networkPolicyWait.Done()

	// Wait for the first poll to happen (which means Run has proceeded past the wait)
	select {
	case <-firstPollDoneCh:
		// Expected: Run has started polling
	case <-time.After(1 * time.Second):
		require.Fail(t, "Run should have started polling within 1 second")
	}

	// Stop the connection store
	closeStopCh()

	// Wait for Run to finish
	select {
	case <-runFinishedCh:
		// Expected: Run finished cleanly
	case <-time.After(1 * time.Second):
		require.Fail(t, "Run should have finished within 1 second after stopCh was closed")
	}

	// Verify that networkPolicyReadyTime has been set and is after we started the test
	require.NotZero(t, conntrackConnStore.networkPolicyReadyTime)
	assert.True(t, conntrackConnStore.networkPolicyReadyTime.After(beforeRunTime))
}

func TestGetZones(t *testing.T) {
	t.Run("IP v4 enabled", func(t *testing.T) {
		t.Run("connectUplinkToBridge", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
			mockProxier := proxytest.NewMockProxyQuerier(ctrl)
			npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			testFlowExporterOptions.ConnectUplinkToBridge = true
			conntrackConnStore := NewConntrackConnectionStore(mockConnDumper, true, false, npQuerier, mockPodStore, mockProxier, nil, nil, testFlowExporterOptions)
			zones := conntrackConnStore.getZones()
			assert.Equal(t, 2, len(zones))
			assert.Contains(t, zones, uint16(openflow.IPCtZoneTypeRegMark.GetValue()<<12))
		})
		t.Run("no connectUplinkToBridge", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
			mockProxier := proxytest.NewMockProxyQuerier(ctrl)
			npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			testFlowExporterOptions.ConnectUplinkToBridge = false
			conntrackConnStore := NewConntrackConnectionStore(mockConnDumper, true, false, npQuerier, mockPodStore, mockProxier, nil, nil, testFlowExporterOptions)
			zones := conntrackConnStore.getZones()
			assert.Equal(t, 2, len(zones))
			assert.Contains(t, zones, uint16(openflow.CtZone))
		})
	})
	t.Run("IP v6 enabled", func(t *testing.T) {
		t.Run("connectUplinkToBridge", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
			mockProxier := proxytest.NewMockProxyQuerier(ctrl)
			npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			testFlowExporterOptions.ConnectUplinkToBridge = true
			conntrackConnStore := NewConntrackConnectionStore(mockConnDumper, false, true, npQuerier, mockPodStore, mockProxier, nil, nil, testFlowExporterOptions)
			zones := conntrackConnStore.getZones()
			assert.Equal(t, 2, len(zones))
			assert.Contains(t, zones, uint16(openflow.IPv6CtZoneTypeRegMark.GetValue()<<12))
		})
		t.Run("no connectUplinkToBridge", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
			mockProxier := proxytest.NewMockProxyQuerier(ctrl)
			npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			testFlowExporterOptions.ConnectUplinkToBridge = false
			conntrackConnStore := NewConntrackConnectionStore(mockConnDumper, false, true, npQuerier, mockPodStore, mockProxier, nil, nil, testFlowExporterOptions)
			zones := conntrackConnStore.getZones()
			assert.Equal(t, 2, len(zones))
			assert.Contains(t, zones, uint16(openflow.CtZoneV6))
		})
	})
}

func TestZoneZeroCache(t *testing.T) {
	t.Run("Add", func(t *testing.T) {
		t.Run("Adding a zone zero record", func(t *testing.T) {
			cache := NewZoneZeroCache()
			refTime := time.Now()
			zoneZeroConn := &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("172.18.0.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         52142,
					DestinationPort:    80},
				Mark:          openflow.ServiceCTMark.GetValue(),
				ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
				ProxySnatPort: uint16(28392),
			}
			err := cache.Add(zoneZeroConn)
			assert.Nil(t, err, "Expected adding zone 0 connection to not error")
			assert.Equal(t, 1, len(cache.cache), "Expected cache to contain newly added connection")
		})
		t.Run("Adding a record not from zone zero", func(t *testing.T) {
			cache := NewZoneZeroCache()
			refTime := time.Now()
			zoneZeroConn := &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("172.18.0.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         52142,
					DestinationPort:    80},
				Mark:          openflow.ServiceCTMark.GetValue(),
				ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
				ProxySnatPort: uint16(28392),
				Zone:          123,
			}
			assert.Error(t, cache.Add(zoneZeroConn), "Expected an error adding connection with zone 123")
		})
	})
	t.Run("GetMatching", func(t *testing.T) {
		t.Run("Has Match", func(t *testing.T) {
			cache := NewZoneZeroCache()
			refTime := time.Now()
			zoneZeroConn := &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("172.18.0.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         52142,
					DestinationPort:    80},
				Mark:          openflow.ServiceCTMark.GetValue(),
				ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
				ProxySnatPort: uint16(28392),
			}
			antreaZeroConn := &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("10.244.2.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         28392,
					DestinationPort:    80},
				Mark:          openflow.ServiceCTMark.GetValue(),
				ProxySnatIP:   netip.MustParseAddr("10.244.2.1"),
				ProxySnatPort: uint16(28392),
			}
			cache.Add(zoneZeroConn)
			match := cache.GetMatching(antreaZeroConn)
			assert.NotNil(t, match, "Expected a matching zone zero connection to have been cached")
			assert.Equal(t, zoneZeroConn, match)
		})
		t.Run("Does Not Have Match", func(t *testing.T) {
			cache := NewZoneZeroCache()
			refTime := time.Now()
			zoneZeroConn := &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("172.18.0.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         52142,
					DestinationPort:    80},
				Mark:          openflow.ServiceCTMark.GetValue(),
				ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
				ProxySnatPort: uint16(28392),
			}
			antreaZeroConn := &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("10.244.2.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         55555,
					DestinationPort:    80},
				Mark:          openflow.ServiceCTMark.GetValue(),
				ProxySnatIP:   netip.MustParseAddr("10.244.2.1"),
				ProxySnatPort: uint16(28392),
			}
			cache.Add(zoneZeroConn)
			match := cache.GetMatching(antreaZeroConn)
			assert.Nil(t, match, "Expected cache to return a nil match")
		})
	})
	t.Run("Contains", func(t *testing.T) {
		t.Run("After adding connection", func(t *testing.T) {
			cache := NewZoneZeroCache()
			refTime := time.Now()
			zoneZeroConn := &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("172.18.0.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         52142,
					DestinationPort:    80},
				Mark:          openflow.ServiceCTMark.GetValue(),
				ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
				ProxySnatPort: uint16(28392),
			}
			cache.Add(zoneZeroConn)
			assert.True(t, cache.Contains(zoneZeroConn), "Expected cache to contain previously added connection")
		})
		t.Run("On an empty cache", func(t *testing.T) {
			cache := NewZoneZeroCache()
			refTime := time.Now()
			zoneZeroConn := &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("172.18.0.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         52142,
					DestinationPort:    80},
				Mark:          openflow.ServiceCTMark.GetValue(),
				ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
				ProxySnatPort: uint16(28392),
			}
			assert.False(t, cache.Contains(zoneZeroConn), "Expected cache to not contain any connections")
		})
	})
}

func TestCorrelateExternal(t *testing.T) {
	refTime := time.Now()
	zoneZero := connection.Connection{
		StartTime: refTime,
		StopTime:  refTime,
		FlowKey: connection.Tuple{
			SourceAddress:      netip.MustParseAddr("172.18.0.1"),
			DestinationAddress: netip.MustParseAddr("10.244.2.2"),
			Protocol:           6,
			SourcePort:         52142,
			DestinationPort:    80},
		Mark:          openflow.ServiceCTMark.GetValue(),
		ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
		ProxySnatPort: uint16(28392),
	}
	antreaZone := connection.Connection{
		StartTime: refTime,
		StopTime:  refTime,
		FlowKey: connection.Tuple{
			SourceAddress:      netip.MustParseAddr("10.244.2.1"),
			DestinationAddress: netip.MustParseAddr("10.244.2.2"),
			Protocol:           6,
			SourcePort:         55555,
			DestinationPort:    80},
		Mark:          openflow.ServiceCTMark.GetValue(),
		ProxySnatIP:   netip.MustParseAddr("10.244.2.1"),
		ProxySnatPort: uint16(28392),
	}
	expected := connection.Connection{
		StartTime: refTime,
		StopTime:  refTime,
		FlowKey: connection.Tuple{
			SourceAddress:      netip.MustParseAddr("172.18.0.1"),
			DestinationAddress: netip.MustParseAddr("10.244.2.2"),
			Protocol:           6,
			SourcePort:         52142,
			DestinationPort:    80},
		Mark:          openflow.ServiceCTMark.GetValue(),
		ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
		ProxySnatPort: uint16(28392),
	}
	CorrelateExternal(&zoneZero, &antreaZone)
	assert.Equal(t, expected, antreaZone)
}
