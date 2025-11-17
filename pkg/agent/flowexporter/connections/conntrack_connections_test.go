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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
	proxytest "antrea.io/antrea/pkg/agent/proxy/testing"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	secv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	queriertest "antrea.io/antrea/pkg/querier/testing"
	objectstoretest "antrea.io/antrea/pkg/util/objectstore/testing"
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
				// NetworkPolicy fields should be empty for old connections
			},
		},
	}

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			mockProxier := proxytest.NewMockProxyQuerier(ctrl)
			npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)

			conntrackConnStore := NewConntrackConnectionStore(npQuerier, mockPodStore, mockProxier, testFlowExporterOptions)
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
	connStore := NewConntrackConnectionStore(nil, mockPodStore, nil, testFlowExporterOptions)
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

func TestConntrackConnectionStore_AddOrUpdateConns(t *testing.T) {
	refTime := time.Now()
	tuple1 := connection.Tuple{SourceAddress: netip.MustParseAddr("1.1.1.1"), DestinationAddress: netip.MustParseAddr("2.2.2.2"), Protocol: 6, SourcePort: 50000, DestinationPort: 100}
	tuple2 := connection.Tuple{SourceAddress: netip.MustParseAddr("3.3.3.3"), DestinationAddress: netip.MustParseAddr("4.4.4.4"), Protocol: 6, SourcePort: 60000, DestinationPort: 200}

	tests := []struct {
		name            string
		oldConn         *connection.Connection
		resubmitOldConn bool
		expectPresent   bool
		expectDeleted   bool
	}{
		{
			name: "old connection is marked as not present",
			oldConn: &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey:   tuple1,
				IsPresent: true,
			},
		}, {
			name: "old connection which is not present is deleted",
			oldConn: &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey:   tuple1,
				IsPresent: false,
			},
			expectDeleted: true,
		}, {
			name: "old connection which is still active will remain present",
			oldConn: &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey:   tuple1,
				IsPresent: true,
			},
			resubmitOldConn: true,
			expectPresent:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := NewConntrackConnectionStore(nil, nil, nil, testFlowExporterOptions)

			require.NotNil(t, tt.oldConn)
			addConnToStore(cs, tt.oldConn)

			if tt.resubmitOldConn {
				require.NoError(t, cs.AddOrUpdateConns([]*connection.Connection{tt.oldConn}))
			} else {
				newConn := &connection.Connection{
					StartTime:     refTime,
					StopTime:      refTime,
					FlowKey:       tuple2,
					IsPresent:     true,
					SourcePodName: "test",
				}
				require.NoError(t, cs.AddOrUpdateConns([]*connection.Connection{newConn}))
				assert.Contains(t, cs.connections, tuple2)
			}

			assert.Equal(t, tt.expectPresent, tt.oldConn.IsPresent)
			if tt.expectDeleted {
				assert.NotContains(t, cs.connections, tt.oldConn.FlowKey)
			} else {
				assert.Contains(t, cs.connections, tt.oldConn.FlowKey)
			}
		})
	}
}
