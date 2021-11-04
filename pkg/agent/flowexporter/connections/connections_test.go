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
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/agent/flowexporter"
	connectionstest "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	interfacestoretest "antrea.io/antrea/pkg/agent/interfacestore/testing"
	"antrea.io/antrea/pkg/agent/metrics"
)

const (
	testActiveFlowTimeout      = 3 * time.Second
	testIdleFlowTimeout        = 1 * time.Second
	testPollInterval           = 0 // Not used in these tests, hence 0.
	testStaleConnectionTimeout = 5 * time.Minute
)

var testFlowExporterOptions = &flowexporter.FlowExporterOptions{
	FlowCollectorAddr:      "",
	FlowCollectorProto:     "",
	ActiveFlowTimeout:      testActiveFlowTimeout,
	IdleFlowTimeout:        testIdleFlowTimeout,
	StaleConnectionTimeout: testStaleConnectionTimeout,
	PollInterval:           testPollInterval,
}

func TestConnectionStore_ForAllConnectionsDo(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
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
	// Create connectionStore
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(ctrl)
	connStore := NewConnectionStore(mockIfaceStore, nil, testFlowExporterOptions)
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

func TestConnectionStore_DeleteConnWithoutLock(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	metrics.InitializeConnectionMetrics()
	// test on deny connection store
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(ctrl)
	denyConnStore := NewDenyConnectionStore(mockIfaceStore, nil, testFlowExporterOptions)
	tuple := flowexporter.Tuple{SourceAddress: net.IP{1, 2, 3, 4}, DestinationAddress: net.IP{4, 3, 2, 1}, Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	conn := &flowexporter.Connection{
		FlowKey: tuple,
	}
	connKey := flowexporter.NewConnectionKey(conn)
	denyConnStore.connections[connKey] = conn

	// For testing purposes, set the metric
	metrics.TotalDenyConnections.Set(1)
	denyConnStore.deleteConnWithoutLock(connKey)
	_, exists := denyConnStore.GetConnByKey(connKey)
	assert.Equal(t, false, exists, "connection should be deleted in connection store")
	checkDenyConnectionMetrics(t, len(denyConnStore.connections))

	// test on conntrack connection store
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	conntrackConnStore := NewConntrackConnectionStore(mockConnDumper, true, false, nil, mockIfaceStore, nil, testFlowExporterOptions)
	conntrackConnStore.connections[connKey] = conn

	metrics.TotalAntreaConnectionsInConnTrackTable.Set(1)
	conntrackConnStore.deleteConnWithoutLock(connKey)
	_, exists = conntrackConnStore.GetConnByKey(connKey)
	assert.Equal(t, false, exists, "connection should be deleted in connection store")
	checkAntreaConnectionMetrics(t, len(conntrackConnStore.connections))
}
