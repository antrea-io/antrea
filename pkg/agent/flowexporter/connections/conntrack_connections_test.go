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
	"net"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/component-base/metrics/legacyregistry"

	"antrea.io/antrea/pkg/agent/flowexporter"
	connectionstest "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	"antrea.io/antrea/pkg/agent/interfacestore"
	interfacestoretest "antrea.io/antrea/pkg/agent/interfacestore/testing"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
	ofclient "antrea.io/antrea/pkg/agent/openflow"
	proxytest "antrea.io/antrea/pkg/agent/proxy/testing"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	secv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	queriertest "antrea.io/antrea/pkg/querier/testing"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

var (
	tuple1         = flowexporter.Tuple{SourceAddress: net.IP{5, 6, 7, 8}, DestinationAddress: net.IP{8, 7, 6, 5}, Protocol: 6, SourcePort: 60001, DestinationPort: 200}
	tuple2         = flowexporter.Tuple{SourceAddress: net.IP{1, 2, 3, 4}, DestinationAddress: net.IP{4, 3, 2, 1}, Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	tuple3         = flowexporter.Tuple{SourceAddress: net.IP{10, 10, 10, 10}, DestinationAddress: net.IP{4, 3, 2, 1}, Protocol: 6, SourcePort: 60000, DestinationPort: 100}
	podConfigFlow1 = &interfacestore.ContainerInterfaceConfig{
		ContainerID:  "1",
		PodName:      "pod1",
		PodNamespace: "ns1",
	}
	interfaceFlow1 = &interfacestore.InterfaceConfig{
		InterfaceName:            "interface1",
		IPs:                      []net.IP{{8, 7, 6, 5}},
		ContainerInterfaceConfig: podConfigFlow1,
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
	action = secv1alpha1.RuleActionAllow
	rule1  = agenttypes.PolicyRule{
		Direction:     cpv1beta.DirectionIn,
		From:          []agenttypes.Address{},
		To:            []agenttypes.Address{},
		Service:       []cpv1beta.Service{},
		Action:        &action,
		Priority:      nil,
		Name:          "",
		FlowID:        uint32(0),
		TableID:       ofclient.IngressRuleTable.GetID(),
		PolicyRef:     &np1,
		EnableLogging: false,
	}
)

func TestConntrackConnectionStore_AddOrUpdateConn(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	metrics.InitializeConnectionMetrics()
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
				FlowKey:                        tuple1,
				Labels:                         []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0},
				Mark:                           openflow.ServiceCTMark.GetValue(),
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
	// Mock interface store with one of the couple of IPs correspond to Pods
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(ctrl)
	mockProxier := proxytest.NewMockProxier(ctrl)
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
	pq := priorityqueue.NewExpirePriorityQueue(testActiveFlowTimeout, testIdleFlowTimeout)
	conntrackConnStore := NewConntrackConnectionStore(mockConnDumper, mockIfaceStore, true, false,
		mockProxier, npQuerier, testPollInterval, pq, testStaleConnectionTimeout)

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			// Add the existing connection to the connection store.
			if c.oldConn != nil {
				addConnToStore(conntrackConnStore, c.oldConn)
			} else {
				testAddNewConn(mockIfaceStore, mockProxier, npQuerier, c.newConn)
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
func testAddNewConn(mockIfaceStore *interfacestoretest.MockInterfaceStore, mockProxier *proxytest.MockProxier, npQuerier *queriertest.MockAgentNetworkPolicyInfoQuerier, conn flowexporter.Connection) {
	mockIfaceStore.EXPECT().GetInterfaceByIP(conn.FlowKey.SourceAddress.String()).Return(nil, false)
	mockIfaceStore.EXPECT().GetInterfaceByIP(conn.FlowKey.DestinationAddress.String()).Return(interfaceFlow1, true)

	protocol, _ := lookupServiceProtocol(conn.FlowKey.Protocol)
	serviceStr := fmt.Sprintf("%s:%d/%s", conn.DestinationServiceAddress.String(), conn.DestinationServicePort, protocol)
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
	cs.expirePriorityQueue.AddItemToQueue(connKey, conn)
	metrics.TotalAntreaConnectionsInConnTrackTable.Inc()
}

func TestConnectionStore_DeleteConnectionByKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	metrics.InitializeConnectionMetrics()
	// Create two flows; one is already in connectionStore and other one is new
	testFlows := make([]*flowexporter.Connection, 2)
	testFlowKeys := make([]*flowexporter.ConnectionKey, 2)
	refTime := time.Now()
	// Flow-1, which is already in connectionStore
	tuple1 := flowexporter.Tuple{SourceAddress: net.IP{1, 2, 3, 4}, DestinationAddress: net.IP{4, 3, 2, 1}, Protocol: 6, SourcePort: 65280, DestinationPort: 255}
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
	tuple2 := flowexporter.Tuple{SourceAddress: net.IP{5, 6, 7, 8}, DestinationAddress: net.IP{8, 7, 6, 5}, Protocol: 6, SourcePort: 60001, DestinationPort: 200}
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
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(ctrl)
	connStore := NewConntrackConnectionStore(nil, mockIfaceStore, true, false, nil, nil, testPollInterval, nil, testStaleConnectionTimeout)
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
	defer ctrl.Finish()
	metrics.InitializeConnectionMetrics()

	testFlows := make([]*flowexporter.Connection, 0)
	// Create connectionStore
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(ctrl)
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	conntrackConnStore := NewConntrackConnectionStore(mockConnDumper, mockIfaceStore, true, false, nil, nil, testPollInterval, nil, testStaleConnectionTimeout)
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

func checkAntreaConnectionMetrics(t *testing.T, numConns int) {
	expectedAntreaConnectionCount := `
	# HELP antrea_agent_conntrack_antrea_connection_count [ALPHA] Number of connections in the Antrea ZoneID of the conntrack table. This metric gets updated at an interval specified by flowPollInterval, a configuration parameter for the Agent.
	# TYPE antrea_agent_conntrack_antrea_connection_count gauge
	`
	expectedAntreaConnectionCount = expectedAntreaConnectionCount + fmt.Sprintf("antrea_agent_conntrack_antrea_connection_count %d\n", numConns)
	err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedAntreaConnectionCount), "antrea_agent_conntrack_antrea_connection_count")
	assert.NoError(t, err)
}

func checkTotalConnectionsMetric(t *testing.T, numConns int) {
	expectedConnectionCount := `
	# HELP antrea_agent_conntrack_total_connection_count [ALPHA] Number of connections in the conntrack table. This metric gets updated at an interval specified by flowPollInterval, a configuration parameter for the Agent.
	# TYPE antrea_agent_conntrack_total_connection_count gauge
	`
	expectedConnectionCount = expectedConnectionCount + fmt.Sprintf("antrea_agent_conntrack_total_connection_count %d\n", numConns)
	err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedConnectionCount), "antrea_agent_conntrack_total_connection_count")
	assert.NoError(t, err)
}

func checkMaxConnectionsMetric(t *testing.T, maxConns int) {
	expectedMaxConnectionsCount := `
	# HELP antrea_agent_conntrack_max_connection_count [ALPHA] Size of the conntrack table. This metric gets updated at an interval specified by flowPollInterval, a configuration parameter for the Agent.
	# TYPE antrea_agent_conntrack_max_connection_count gauge
	`
	expectedMaxConnectionsCount = expectedMaxConnectionsCount + fmt.Sprintf("antrea_agent_conntrack_max_connection_count %d\n", maxConns)
	err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedMaxConnectionsCount), "antrea_agent_conntrack_max_connection_count")
	assert.NoError(t, err)
}
