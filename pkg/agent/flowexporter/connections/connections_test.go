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

	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	connectionstest "github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/connections/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	interfacestoretest "github.com/vmware-tanzu/antrea/pkg/agent/interfacestore/testing"
)

const testPollInterval = 0 // Not used in these tests, hence 0.

func makeTuple(srcIP *net.IP, dstIP *net.IP, protoID uint8, srcPort uint16, dstPort uint16) (*flowexporter.Tuple, *flowexporter.Tuple) {
	tuple := &flowexporter.Tuple{
		SourceAddress:      *srcIP,
		DestinationAddress: *dstIP,
		Protocol:           protoID,
		SourcePort:         srcPort,
		DestinationPort:    dstPort,
	}
	revTuple := &flowexporter.Tuple{
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
	// Create two flows; one is already in ConnectionStore and other one is new
	refTime := time.Now()
	// Flow-1, which is already in ConnectionStore
	tuple1, revTuple1 := makeTuple(&net.IP{1, 2, 3, 4}, &net.IP{4, 3, 2, 1}, 6, 65280, 255)
	testFlow1 := flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 50)),
		StopTime:        refTime,
		OriginalPackets: 0xffff,
		OriginalBytes:   0xbaaaaa0000000000,
		ReversePackets:  0xff,
		ReverseBytes:    0xbaaa,
		TupleOrig:       *tuple1,
		TupleReply:      *revTuple1,
		IsActive:        true,
	}
	// Flow-2, which is not in ConnectionStore
	tuple2, revTuple2 := makeTuple(&net.IP{5, 6, 7, 8}, &net.IP{8, 7, 6, 5}, 6, 60001, 200)
	testFlow2 := flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 20)),
		StopTime:        refTime,
		OriginalPackets: 0xbb,
		OriginalBytes:   0xcbbb,
		ReversePackets:  0xbbbb,
		ReverseBytes:    0xcbbbb0000000000,
		TupleOrig:       *tuple2,
		TupleReply:      *revTuple2,
		IsActive:        true,
	}
	// Create copy of old conntrack flow for testing purposes.
	// This flow is already in connection store.
	oldTestFlow1 := flowexporter.Connection{
		StartTime:               testFlow1.StartTime,
		StopTime:                testFlow1.StopTime.Add(-(time.Second * 30)),
		OriginalPackets:         0xfff,
		OriginalBytes:           0xbaaaaa00000000,
		ReversePackets:          0xf,
		ReverseBytes:            0xba,
		TupleOrig:               *tuple1,
		TupleReply:              *revTuple1,
		SourcePodNamespace:      "ns1",
		SourcePodName:           "pod1",
		DestinationPodNamespace: "",
		DestinationPodName:      "",
		IsActive:                true,
	}
	podConfigFlow2 := &interfacestore.ContainerInterfaceConfig{
		ContainerID:  "2",
		PodName:      "pod2",
		PodNamespace: "ns2",
	}
	interfaceFlow2 := &interfacestore.InterfaceConfig{
		InterfaceName:            "interface2",
		IP:                       net.IP{8, 7, 6, 5},
		ContainerInterfaceConfig: podConfigFlow2,
	}
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(ctrl)
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	connStore := NewConnectionStore(mockConnDumper, mockIfaceStore, testPollInterval)
	// Add flow1conn to the Connection map
	testFlow1Tuple := flowexporter.NewConnectionKey(&testFlow1)
	connStore.connections[testFlow1Tuple] = oldTestFlow1

	addOrUpdateConnTests := []struct {
		flow flowexporter.Connection
	}{
		{testFlow1}, // To test update part of function
		{testFlow2}, // To test add part of function
	}
	for i, test := range addOrUpdateConnTests {
		flowTuple := flowexporter.NewConnectionKey(&test.flow)
		var expConn flowexporter.Connection
		if i == 0 {
			expConn = test.flow
			expConn.SourcePodNamespace = "ns1"
			expConn.SourcePodName = "pod1"
		} else {
			expConn = test.flow
			expConn.DestinationPodNamespace = "ns2"
			expConn.DestinationPodName = "pod2"
			mockIfaceStore.EXPECT().GetInterfaceByIP(test.flow.TupleOrig.SourceAddress.String()).Return(nil, false)
			mockIfaceStore.EXPECT().GetInterfaceByIP(test.flow.TupleReply.SourceAddress.String()).Return(interfaceFlow2, true)
		}
		connStore.addOrUpdateConn(&test.flow)
		actualConn, ok := connStore.GetConnByKey(flowTuple)
		assert.Equal(t, ok, true, "connection should be there in connection store")
		assert.Equal(t, expConn, *actualConn, "Connections should be equal")
	}
}

func TestConnectionStore_ForAllConnectionsDo(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	// Create two flows; one is already in ConnectionStore and other one is new
	testFlows := make([]*flowexporter.Connection, 2)
	testFlowKeys := make([]*flowexporter.ConnectionKey, 2)
	refTime := time.Now()
	// Flow-1, which is already in ConnectionStore
	tuple1, revTuple1 := makeTuple(&net.IP{1, 2, 3, 4}, &net.IP{4, 3, 2, 1}, 6, 65280, 255)
	testFlows[0] = &flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 50)),
		StopTime:        refTime,
		OriginalPackets: 0xffff,
		OriginalBytes:   0xbaaaaa0000000000,
		ReversePackets:  0xff,
		ReverseBytes:    0xbaaa,
		TupleOrig:       *tuple1,
		TupleReply:      *revTuple1,
		IsActive:        true,
	}
	// Flow-2, which is not in ConnectionStore
	tuple2, revTuple2 := makeTuple(&net.IP{5, 6, 7, 8}, &net.IP{8, 7, 6, 5}, 6, 60001, 200)
	testFlows[1] = &flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 20)),
		StopTime:        refTime,
		OriginalPackets: 0xbb,
		OriginalBytes:   0xcbbb,
		ReversePackets:  0xbbbb,
		ReverseBytes:    0xcbbbb0000000000,
		TupleOrig:       *tuple2,
		TupleReply:      *revTuple2,
		IsActive:        true,
	}
	for i, flow := range testFlows {
		connKey := flowexporter.NewConnectionKey(flow)
		testFlowKeys[i] = &connKey
	}
	// Create ConnectionStore
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(ctrl)
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	connStore := NewConnectionStore(mockConnDumper, mockIfaceStore, testPollInterval)
	// Add flows to the Connection store
	for i, flow := range testFlows {
		connStore.connections[*testFlowKeys[i]] = *flow
	}

	resetTwoFields := func(key flowexporter.ConnectionKey, conn flowexporter.Connection) error {
		conn.IsActive = false
		conn.OriginalPackets = 0
		connStore.connections[key] = conn
		return nil
	}
	connStore.ForAllConnectionsDo(resetTwoFields)
	// Check isActive and OriginalPackets, if they are reset or not.
	for i := 0; i < len(testFlows); i++ {
		conn, ok := connStore.GetConnByKey(*testFlowKeys[i])
		assert.Equal(t, ok, true, "connection should be there in connection store")
		assert.Equal(t, conn.IsActive, false, "isActive flag should be reset")
		assert.Equal(t, conn.OriginalPackets, uint64(0), "OriginalPackets should be reset")
	}
}

func TestConnectionStore_DeleteConnectionByKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	// Create two flows; one is already in ConnectionStore and other one is new
	testFlows := make([]*flowexporter.Connection, 2)
	testFlowKeys := make([]*flowexporter.ConnectionKey, 2)
	refTime := time.Now()
	// Flow-1, which is already in ConnectionStore
	tuple1, revTuple1 := makeTuple(&net.IP{1, 2, 3, 4}, &net.IP{4, 3, 2, 1}, 6, 65280, 255)
	testFlows[0] = &flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 50)),
		StopTime:        refTime,
		OriginalPackets: 0xffff,
		OriginalBytes:   0xbaaaaa0000000000,
		ReversePackets:  0xff,
		ReverseBytes:    0xbaaa,
		TupleOrig:       *tuple1,
		TupleReply:      *revTuple1,
		IsActive:        true,
	}
	// Flow-2, which is not in ConnectionStore
	tuple2, revTuple2 := makeTuple(&net.IP{5, 6, 7, 8}, &net.IP{8, 7, 6, 5}, 6, 60001, 200)
	testFlows[1] = &flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 20)),
		StopTime:        refTime,
		OriginalPackets: 0xbb,
		OriginalBytes:   0xcbbb,
		ReversePackets:  0xbbbb,
		ReverseBytes:    0xcbbbb0000000000,
		TupleOrig:       *tuple2,
		TupleReply:      *revTuple2,
		IsActive:        true,
	}
	for i, flow := range testFlows {
		connKey := flowexporter.NewConnectionKey(flow)
		testFlowKeys[i] = &connKey
	}
	// Create ConnectionStore
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(ctrl)
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	connStore := NewConnectionStore(mockConnDumper, mockIfaceStore, testPollInterval)
	// Add flows to the connection store.
	for i, flow := range testFlows {
		connStore.connections[*testFlowKeys[i]] = *flow
	}
	// Delete the connections in connection store.
	for i := 0; i < len(testFlows); i++ {
		err := connStore.DeleteConnectionByKey(*testFlowKeys[i])
		assert.Nil(t, err, "DeleteConnectionByKey should return nil")
		_, exists := connStore.GetConnByKey(*testFlowKeys[i])
		assert.Equal(t, exists, false, "connection should be deleted in connection store")
	}
}
