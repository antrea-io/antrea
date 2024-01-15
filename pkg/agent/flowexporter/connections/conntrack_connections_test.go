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

	"antrea.io/antrea/pkg/agent/flowexporter"
	connectionstest "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
	proxytest "antrea.io/antrea/pkg/agent/proxy/testing"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	secv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	queriertest "antrea.io/antrea/pkg/querier/testing"
	podstoretest "antrea.io/antrea/pkg/util/podstore/testing"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

var (
	tuple1 = flowexporter.Tuple{SourceAddress: netip.MustParseAddr("5.6.7.8"), DestinationAddress: netip.MustParseAddr("8.7.6.5"), Protocol: 6, SourcePort: 60001, DestinationPort: 200}
	tuple2 = flowexporter.Tuple{SourceAddress: netip.MustParseAddr("1.2.3.4"), DestinationAddress: netip.MustParseAddr("4.3.2.1"), Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	tuple3 = flowexporter.Tuple{SourceAddress: netip.MustParseAddr("10.10.10.10"), DestinationAddress: netip.MustParseAddr("4.3.2.1"), Protocol: 6, SourcePort: 60000, DestinationPort: 100}
	pod1   = &v1.Pod{
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

type fakeL7Listener struct{}

func (fll *fakeL7Listener) ConsumeL7EventMap() map[flowexporter.ConnectionKey]L7ProtocolFields {
	l7EventsMap := make(map[flowexporter.ConnectionKey]L7ProtocolFields)
	return l7EventsMap
}

func TestConntrackConnectionStore_AddOrUpdateConn(t *testing.T) {
	ctrl := gomock.NewController(t)
	refTime := time.Now()

	tc := []struct {
		name         string
		flowKey      flowexporter.Tuple
		oldConn      *flowexporter.Connection
		newConn      flowexporter.Connection
		expectedConn flowexporter.Connection
	}{
		{
			name:    "addNewConn",
			flowKey: tuple1,
			oldConn: nil,
			newConn: flowexporter.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey:   tuple1,
				Labels:    []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0},
				Mark:      openflow.ServiceCTMark.GetValue(),
			},
			expectedConn: flowexporter.Connection{
				StartTime:                      refTime,
				StopTime:                       refTime,
				LastExportTime:                 refTime,
				FlowKey:                        tuple1,
				Labels:                         []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0},
				Mark:                           openflow.ServiceCTMark.GetValue(),
				IsPresent:                      true,
				IsActive:                       true,
				DestinationPodName:             "pod1",
				DestinationPodNamespace:        "ns1",
				DestinationServicePortName:     servicePortName.String(),
				IngressNetworkPolicyName:       np1.Name,
				IngressNetworkPolicyNamespace:  np1.Namespace,
				IngressNetworkPolicyType:       flowexporter.PolicyTypeToUint8(np1.Type),
				IngressNetworkPolicyRuleName:   rule1.Name,
				IngressNetworkPolicyRuleAction: flowexporter.RuleActionToUint8(string(*rule1.Action)),
			},
		},
		{
			name:    "updateActiveConn",
			flowKey: tuple2,
			oldConn: &flowexporter.Connection{
				StartTime:       refTime.Add(-(time.Second * 50)),
				StopTime:        refTime.Add(-(time.Second * 30)),
				LastExportTime:  refTime.Add(-(time.Second * 50)),
				OriginalPackets: 0xfff,
				OriginalBytes:   0xbaaaaa00000000,
				ReversePackets:  0xf,
				ReverseBytes:    0xbaa,
				FlowKey:         tuple2,
				IsPresent:       true,
			},
			newConn: flowexporter.Connection{
				StartTime:       refTime.Add(-(time.Second * 50)),
				StopTime:        refTime,
				OriginalPackets: 0xffff,
				OriginalBytes:   0xbaaaaa0000000000,
				ReversePackets:  0xff,
				ReverseBytes:    0xbaaa,
				FlowKey:         tuple2,
				IsPresent:       true,
			},
			expectedConn: flowexporter.Connection{
				StartTime:       refTime.Add(-(time.Second * 50)),
				StopTime:        refTime,
				LastExportTime:  refTime.Add(-(time.Second * 50)),
				OriginalPackets: 0xffff,
				OriginalBytes:   0xbaaaaa0000000000,
				ReversePackets:  0xff,
				ReverseBytes:    0xbaaa,
				FlowKey:         tuple2,
				IsPresent:       true,
				IsActive:        true,
			},
		},
		{
			// If the polled new connection is dying, the old connection present
			// in connection store will not be updated.
			name:    "updateDyingConn",
			flowKey: tuple3,
			oldConn: &flowexporter.Connection{
				StartTime:       refTime.Add(-(time.Second * 50)),
				StopTime:        refTime.Add(-(time.Second * 30)),
				LastExportTime:  refTime.Add(-(time.Second * 50)),
				OriginalPackets: 0xfff,
				OriginalBytes:   0xbaaaaa00000000,
				ReversePackets:  0xf,
				ReverseBytes:    0xba,
				FlowKey:         tuple3,
				TCPState:        "TIME_WAIT",
				IsPresent:       true,
			},
			newConn: flowexporter.Connection{
				StartTime:       refTime.Add(-(time.Second * 50)),
				StopTime:        refTime,
				OriginalPackets: 0xffff,
				OriginalBytes:   0xbaaaaa0000000000,
				ReversePackets:  0xff,
				ReverseBytes:    0xbaaa,
				FlowKey:         tuple3,
				TCPState:        "TIME_WAIT",
				IsPresent:       true,
			},
			expectedConn: flowexporter.Connection{
				StartTime:       refTime.Add(-(time.Second * 50)),
				StopTime:        refTime.Add(-(time.Second * 30)),
				LastExportTime:  refTime.Add(-(time.Second * 50)),
				OriginalPackets: 0xfff,
				OriginalBytes:   0xbaaaaa00000000,
				ReversePackets:  0xf,
				ReverseBytes:    0xba,
				FlowKey:         tuple3,
				TCPState:        "TIME_WAIT",
				IsPresent:       true,
			},
		},
	}

	mockPodStore := podstoretest.NewMockInterface(ctrl)
	mockProxier := proxytest.NewMockProxier(ctrl)
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
	conntrackConnStore := NewConntrackConnectionStore(mockConnDumper, true, false, npQuerier, mockPodStore, mockProxier, nil, testFlowExporterOptions)

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			// Add the existing connection to the connection store.
			if c.oldConn != nil {
				addConnToStore(conntrackConnStore, c.oldConn)
			} else {
				testAddNewConn(mockPodStore, mockProxier, npQuerier, c.newConn)
			}
			conntrackConnStore.AddOrUpdateConn(&c.newConn)
			actualConn, exist := conntrackConnStore.GetConnByKey(flowexporter.NewConnectionKey(&c.newConn))
			require.Equal(t, exist, true, "The connection should exist in the connection store")
			assert.Equal(t, c.expectedConn, *actualConn, "Connections should be equal")
			assert.Equalf(t, 1, conntrackConnStore.connectionStore.expirePriorityQueue.Len(), "Length of the expire priority queue should be 1")
			conntrackConnStore.connectionStore.expirePriorityQueue.Pop() // empty the PQ
		})
	}
}

// testAddNewConn tests podInfo, Services, network policy mapping.
func testAddNewConn(mockPodStore *podstoretest.MockInterface, mockProxier *proxytest.MockProxier, npQuerier *queriertest.MockAgentNetworkPolicyInfoQuerier, conn flowexporter.Connection) {
	mockPodStore.EXPECT().GetPodByIPAndTime(conn.FlowKey.SourceAddress.String(), gomock.Any()).Return(nil, false)
	mockPodStore.EXPECT().GetPodByIPAndTime(conn.FlowKey.DestinationAddress.String(), gomock.Any()).Return(pod1, true)

	protocol, _ := lookupServiceProtocol(conn.FlowKey.Protocol)
	serviceStr := fmt.Sprintf("%s:%d/%s", conn.OriginalDestinationAddress.String(), conn.OriginalDestinationPort, protocol)
	mockProxier.EXPECT().GetServiceByIP(serviceStr).Return(servicePortName, true)

	ingressOfID := binary.LittleEndian.Uint32(conn.Labels[:4])
	npQuerier.EXPECT().GetNetworkPolicyByRuleFlowID(ingressOfID).Return(&np1)
	npQuerier.EXPECT().GetRuleByFlowID(ingressOfID).Return(&rule1)
}

// addConntrackConnToMap adds a conntrack connection to the connection map and
// increment the metric.
func addConnToStore(cs *ConntrackConnectionStore, conn *flowexporter.Connection) {
	connKey := flowexporter.NewConnectionKey(conn)
	cs.AddConnToMap(&connKey, conn)
	cs.expirePriorityQueue.WriteItemToQueue(connKey, conn)
	metrics.TotalAntreaConnectionsInConnTrackTable.Inc()
}

func TestConnectionStore_DeleteConnectionByKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	// Create two flows; one is already in connectionStore and other one is new
	testFlows := make([]*flowexporter.Connection, 2)
	testFlowKeys := make([]*flowexporter.ConnectionKey, 2)
	refTime := time.Now()
	// Flow-1, which is already in connectionStore
	tuple1 := flowexporter.Tuple{SourceAddress: netip.MustParseAddr("1.2.3.4"), DestinationAddress: netip.MustParseAddr("4.3.2.1"), Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	testFlows[0] = &flowexporter.Connection{
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
	tuple2 := flowexporter.Tuple{SourceAddress: netip.MustParseAddr("5.6.7.8"), DestinationAddress: netip.MustParseAddr("8.7.6.5"), Protocol: 6, SourcePort: 60001, DestinationPort: 200}
	testFlows[1] = &flowexporter.Connection{
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
		connKey := flowexporter.NewConnectionKey(flow)
		testFlowKeys[i] = &connKey
	}
	// For testing purposes, set the metric
	metrics.TotalAntreaConnectionsInConnTrackTable.Set(float64(len(testFlows)))
	// Create connectionStore
	mockPodStore := podstoretest.NewMockInterface(ctrl)
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

func TestConnectionStore_MetricSettingInPoll(t *testing.T) {
	ctrl := gomock.NewController(t)

	testFlows := make([]*flowexporter.Connection, 0)
	// Create connectionStore
	mockPodStore := podstoretest.NewMockInterface(ctrl)
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	conntrackConnStore := NewConntrackConnectionStore(mockConnDumper, true, false, nil, mockPodStore, nil, &fakeL7Listener{}, testFlowExporterOptions)
	// Hard-coded conntrack occupancy metrics for test
	TotalConnections := 0
	MaxConnections := 300000
	mockConnDumper.EXPECT().DumpFlows(uint16(openflow.CtZone)).Return(testFlows, TotalConnections, nil)
	mockConnDumper.EXPECT().GetMaxConnections().Return(MaxConnections, nil)
	connsLens, err := conntrackConnStore.Poll()
	require.Nil(t, err, fmt.Sprintf("Failed to add connections to connection store: %v", err))
	assert.Equal(t, len(connsLens), 1, "length of connsLens is expected to be 1")
	assert.Equal(t, connsLens[0], len(testFlows), "expected connections should be equal to number of testFlows")
	checkTotalConnectionsMetric(t, TotalConnections)
	checkMaxConnectionsMetric(t, MaxConnections)
}
