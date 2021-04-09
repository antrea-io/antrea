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

package connections

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/component-base/metrics/testutil"

	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	connectionstest "github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/connections/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/flowrecords"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	interfacestoretest "github.com/vmware-tanzu/antrea/pkg/agent/interfacestore/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/metrics"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	proxytest "github.com/vmware-tanzu/antrea/pkg/agent/proxy/testing"
	cpv1beta "github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
	queriertest "github.com/vmware-tanzu/antrea/pkg/querier/testing"
	k8sproxy "github.com/vmware-tanzu/antrea/third_party/proxy"
)

var (
	np1 = cpv1beta.NetworkPolicyReference{
		Type:      cpv1beta.K8sNetworkPolicy,
		Namespace: "foo",
		Name:      "bar",
		UID:       "uid1",
	}
	np2 = cpv1beta.NetworkPolicyReference{
		Type:      cpv1beta.K8sNetworkPolicy,
		Namespace: "foo",
		Name:      "baz",
		UID:       "uid2",
	}
)

const testPollInterval = 0 // Not used in these tests, hence 0.

func makeTuple(srcIP *net.IP, dstIP *net.IP, protoID uint8, srcPort uint16, dstPort uint16) (flowexporter.Tuple, flowexporter.Tuple) {
	tuple := flowexporter.Tuple{
		SourceAddress:      *srcIP,
		DestinationAddress: *dstIP,
		Protocol:           protoID,
		SourcePort:         srcPort,
		DestinationPort:    dstPort,
	}
	revTuple := flowexporter.Tuple{
		SourceAddress:      *dstIP,
		DestinationAddress: *srcIP,
		Protocol:           protoID,
		SourcePort:         dstPort,
		DestinationPort:    srcPort,
	}
	return tuple, revTuple
}

func TestConnectionStore_addAndUpdateConn(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	metrics.InitializeConnectionMetrics()
	// Create three flows; two are already in connectionStore and another one is new
	refTime := time.Now()
	// Flow-1, which is already in connectionStore
	tuple1, revTuple1 := makeTuple(&net.IP{1, 2, 3, 4}, &net.IP{4, 3, 2, 1}, 6, 65280, 255)
	testFlow1 := flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 50)),
		StopTime:        refTime,
		OriginalPackets: 0xffff,
		OriginalBytes:   0xbaaaaa0000000000,
		ReversePackets:  0xff,
		ReverseBytes:    0xbaaa,
		TupleOrig:       tuple1,
		TupleReply:      revTuple1,
		IsPresent:       true,
	}
	// Flow-2, which is not in connectionStore
	tuple2, revTuple2 := makeTuple(&net.IP{5, 6, 7, 8}, &net.IP{8, 7, 6, 5}, 6, 60001, 200)
	testFlow2 := flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 20)),
		StopTime:        refTime,
		OriginalPackets: 0xbb,
		OriginalBytes:   0xcbbb,
		ReversePackets:  0xbbbb,
		ReverseBytes:    0xcbbbb0000000000,
		TupleOrig:       tuple2,
		TupleReply:      revTuple2,
		IsPresent:       true,
	}
	// Flow-3 , which is already in connectionStore
	tuple3, revTuple3 := makeTuple(&net.IP{10, 10, 10, 10}, &net.IP{4, 3, 2, 1}, 6, 60000, 100)
	testFlow3 := flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 50)),
		StopTime:        refTime,
		OriginalPackets: 0xffff,
		OriginalBytes:   0xbaaaaa,
		ReversePackets:  0xff,
		ReverseBytes:    0xbaaa,
		TupleOrig:       tuple3,
		TupleReply:      revTuple3,
		TCPState:        "TIME_WAIT",
		IsPresent:       true,
	}
	// To test service name mapping.
	tuple4, revTuple4 := makeTuple(&net.IP{10, 10, 10, 10}, &net.IP{20, 20, 20, 20}, 6, 5000, 80)
	testFlow4 := flowexporter.Connection{
		TupleOrig:  tuple4,
		TupleReply: revTuple4,
		Mark:       openflow.ServiceCTMark,
		IsPresent:  true,
	}
	// To test NetworkPolicy mapping.
	tuple5, revTuple5 := makeTuple(&net.IP{30, 30, 30, 30}, &net.IP{20, 20, 20, 20}, 6, 5000, 80)
	testFlow5 := flowexporter.Connection{
		TupleOrig:  tuple5,
		TupleReply: revTuple5,
		Labels:     []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2},
		IsPresent:  true,
	}
	// Create copy of old conntrack flow for testing purposes.
	// These two flows are already in connection store.
	oldTestFlow1 := flowexporter.Connection{
		StartTime:               testFlow1.StartTime,
		StopTime:                testFlow1.StopTime.Add(-(time.Second * 30)),
		OriginalPackets:         0xfff,
		OriginalBytes:           0xbaaaaa00000000,
		ReversePackets:          0xf,
		ReverseBytes:            0xba,
		TupleOrig:               tuple1,
		TupleReply:              revTuple1,
		SourcePodNamespace:      "ns1",
		SourcePodName:           "pod1",
		DestinationPodNamespace: "",
		DestinationPodName:      "",
		IsPresent:               true,
		TCPState:                "",
	}
	oldTestFlow3 := flowexporter.Connection{
		StartTime:               testFlow3.StartTime,
		StopTime:                testFlow3.StopTime.Add(-(time.Second * 30)),
		OriginalPackets:         0xffff,
		OriginalBytes:           0xbaaaaa,
		ReversePackets:          0xff,
		ReverseBytes:            0xbaaa,
		TupleOrig:               tuple3,
		TupleReply:              revTuple3,
		SourcePodNamespace:      "ns3",
		SourcePodName:           "pod3",
		DestinationPodNamespace: "",
		DestinationPodName:      "",
		IsPresent:               true,
		TCPState:                "TIME_WAIT",
	}
	podConfigFlow2 := &interfacestore.ContainerInterfaceConfig{
		ContainerID:  "2",
		PodName:      "pod2",
		PodNamespace: "ns2",
	}
	interfaceFlow2 := &interfacestore.InterfaceConfig{
		InterfaceName:            "interface2",
		IPs:                      []net.IP{{8, 7, 6, 5}},
		ContainerInterfaceConfig: podConfigFlow2,
	}
	servicePortName := k8sproxy.ServicePortName{
		NamespacedName: types.NamespacedName{
			Namespace: "serviceNS1",
			Name:      "service1",
		},
		Port:     "255",
		Protocol: v1.ProtocolTCP,
	}
	// Mock interface store with one of the couple of IPs correspond to Pods
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(ctrl)
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	mockProxier := proxytest.NewMockProxier(ctrl)
	npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
	connStore := NewConnectionStore(mockConnDumper, flowrecords.NewFlowRecords(), mockIfaceStore, true, false, mockProxier, npQuerier, testPollInterval)

	// Add flow1conn and flow3conn to the Connection map
	testFlow1Tuple := flowexporter.NewConnectionKey(&testFlow1)
	connStore.connections[testFlow1Tuple] = &oldTestFlow1
	testFlow3Tuple := flowexporter.NewConnectionKey(&testFlow3)
	connStore.connections[testFlow3Tuple] = &oldTestFlow3
	// For testing purposes, increment the metric
	metrics.TotalAntreaConnectionsInConnTrackTable.Inc()
	metrics.TotalAntreaConnectionsInConnTrackTable.Inc()

	addOrUpdateConnTests := []struct {
		flow flowexporter.Connection
	}{
		{testFlow1}, // To test update part of function.
		{testFlow2}, // To test add part of function.
		{testFlow3}, // To test update part of function for dying connection.
		{testFlow4}, // To test service name mapping.
		{testFlow5}, // To test NetworkPolicy mapping.
	}
	for i, test := range addOrUpdateConnTests {
		flowTuple := flowexporter.NewConnectionKey(&test.flow)
		expConn := test.flow
		switch i {
		case 0:
			// Tests update part of the function.
			expConn.SourcePodNamespace = "ns1"
			expConn.SourcePodName = "pod1"
		case 1:
			// Tests add part of the function.
			mockIfaceStore.EXPECT().GetInterfaceByIP(test.flow.TupleOrig.SourceAddress.String()).Return(nil, false)
			mockIfaceStore.EXPECT().GetInterfaceByIP(test.flow.TupleReply.SourceAddress.String()).Return(interfaceFlow2, true)

			expConn.DestinationPodNamespace = "ns2"
			expConn.DestinationPodName = "pod2"
		case 2:
			// Tests update part of the function for dying connection.

			expConn.SourcePodNamespace = "ns3"
			expConn.SourcePodName = "pod3"
			expConn.TCPState = "TIME_WAIT"
			expConn.StopTime = refTime.Add(-(time.Second * 30))
		case 3:
			// Tests service name mapping.
			mockIfaceStore.EXPECT().GetInterfaceByIP(expConn.TupleOrig.SourceAddress.String()).Return(nil, false)
			mockIfaceStore.EXPECT().GetInterfaceByIP(expConn.TupleReply.SourceAddress.String()).Return(nil, false)

			protocol, _ := lookupServiceProtocol(expConn.TupleOrig.Protocol)
			serviceStr := fmt.Sprintf("%s:%d/%s", expConn.TupleOrig.DestinationAddress.String(), expConn.TupleOrig.DestinationPort, protocol)
			mockProxier.EXPECT().GetServiceByIP(serviceStr).Return(servicePortName, true)
			expConn.DestinationServicePortName = servicePortName.String()
		case 4:
			// Tests NetworkPolicy mapping.
			mockIfaceStore.EXPECT().GetInterfaceByIP(expConn.TupleOrig.SourceAddress.String()).Return(nil, false)
			mockIfaceStore.EXPECT().GetInterfaceByIP(expConn.TupleReply.SourceAddress.String()).Return(nil, false)

			ingressOfID := binary.LittleEndian.Uint32(test.flow.Labels[:4])
			npQuerier.EXPECT().GetNetworkPolicyByRuleFlowID(ingressOfID).Return(&np1)
			expConn.IngressNetworkPolicyName = np1.Name
			expConn.IngressNetworkPolicyNamespace = np1.Namespace

			egressOfID := binary.LittleEndian.Uint32(test.flow.Labels[4:8])
			npQuerier.EXPECT().GetNetworkPolicyByRuleFlowID(egressOfID).Return(&np2)
			expConn.EgressNetworkPolicyName = np2.Name
			expConn.EgressNetworkPolicyNamespace = np2.Namespace
		}
		connStore.addOrUpdateConn(&test.flow)
		actualConn, ok := connStore.GetConnByKey(flowTuple)
		assert.Equal(t, ok, true, "connection should be there in connection store")
		assert.Equal(t, expConn, *actualConn, "Connections should be equal")
		checkAntreaConnectionMetrics(t, len(connStore.connections))
	}
}

func TestConnectionStore_ForAllConnectionsDo(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	// Create two flows; one is already in connectionStore and other one is new
	testFlows := make([]*flowexporter.Connection, 2)
	testFlowKeys := make([]*flowexporter.ConnectionKey, 2)
	refTime := time.Now()
	// Flow-1, which is already in connectionStore
	tuple1, revTuple1 := makeTuple(&net.IP{1, 2, 3, 4}, &net.IP{4, 3, 2, 1}, 6, 65280, 255)
	testFlows[0] = &flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 50)),
		StopTime:        refTime,
		OriginalPackets: 0xffff,
		OriginalBytes:   0xbaaaaa0000000000,
		ReversePackets:  0xff,
		ReverseBytes:    0xbaaa,
		TupleOrig:       tuple1,
		TupleReply:      revTuple1,
		IsPresent:       true,
	}
	// Flow-2, which is not in connectionStore
	tuple2, revTuple2 := makeTuple(&net.IP{5, 6, 7, 8}, &net.IP{8, 7, 6, 5}, 6, 60001, 200)
	testFlows[1] = &flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 20)),
		StopTime:        refTime,
		OriginalPackets: 0xbb,
		OriginalBytes:   0xcbbb,
		ReversePackets:  0xbbbb,
		ReverseBytes:    0xcbbbb0000000000,
		TupleOrig:       tuple2,
		TupleReply:      revTuple2,
		IsPresent:       true,
	}
	for i, flow := range testFlows {
		connKey := flowexporter.NewConnectionKey(flow)
		testFlowKeys[i] = &connKey
	}
	// Create connectionStore
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(ctrl)
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	connStore := NewConnectionStore(mockConnDumper, flowrecords.NewFlowRecords(), mockIfaceStore, true, false, nil, nil, testPollInterval)
	// Add flows to the Connection store
	for i, flow := range testFlows {
		connStore.connections[*testFlowKeys[i]] = flow
	}

	resetTwoFields := func(key flowexporter.ConnectionKey, conn *flowexporter.Connection) error {
		conn.IsPresent = false
		conn.OriginalPackets = 0
		return nil
	}
	connStore.ForAllConnectionsDo(resetTwoFields)
	// Check isActive and OriginalPackets, if they are reset or not.
	for i := 0; i < len(testFlows); i++ {
		conn, ok := connStore.GetConnByKey(*testFlowKeys[i])
		assert.Equal(t, ok, true, "connection should be there in connection store")
		assert.Equal(t, conn.IsPresent, false, "isActive flag should be reset")
		assert.Equal(t, conn.OriginalPackets, uint64(0), "OriginalPackets should be reset")
	}
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
	tuple1, revTuple1 := makeTuple(&net.IP{1, 2, 3, 4}, &net.IP{4, 3, 2, 1}, 6, 65280, 255)
	testFlows[0] = &flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 50)),
		StopTime:        refTime,
		OriginalPackets: 0xffff,
		OriginalBytes:   0xbaaaaa0000000000,
		ReversePackets:  0xff,
		ReverseBytes:    0xbaaa,
		TupleOrig:       tuple1,
		TupleReply:      revTuple1,
		IsPresent:       true,
	}
	// Flow-2, which is not in connectionStore
	tuple2, revTuple2 := makeTuple(&net.IP{5, 6, 7, 8}, &net.IP{8, 7, 6, 5}, 6, 60001, 200)
	testFlows[1] = &flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 20)),
		StopTime:        refTime,
		OriginalPackets: 0xbb,
		OriginalBytes:   0xcbbb,
		ReversePackets:  0xbbbb,
		ReverseBytes:    0xcbbbb0000000000,
		TupleOrig:       tuple2,
		TupleReply:      revTuple2,
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
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	connStore := NewConnectionStore(mockConnDumper, flowrecords.NewFlowRecords(), mockIfaceStore, true, false, nil, nil, testPollInterval)
	// Add flows to the connection store.
	for i, flow := range testFlows {
		connStore.connections[*testFlowKeys[i]] = flow
	}
	// Delete the connections in connection store.
	for i := 0; i < len(testFlows); i++ {
		err := connStore.deleteConnectionByKeyWithoutLock(*testFlowKeys[i])
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
	connStore := NewConnectionStore(mockConnDumper, flowrecords.NewFlowRecords(), mockIfaceStore, true, false, nil, nil, testPollInterval)
	// Hard-coded conntrack occupancy metrics for test
	TotalConnections := 0
	MaxConnections := 300000
	mockConnDumper.EXPECT().DumpFlows(uint16(openflow.CtZone)).Return(testFlows, TotalConnections, nil)
	mockConnDumper.EXPECT().GetMaxConnections().Return(MaxConnections, nil)
	connsLens, err := connStore.Poll()
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
