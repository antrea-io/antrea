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

var (
	refTime = time.Now()
	tuple1  = flowexporter.Tuple{
		SourceAddress:      net.IP{1, 2, 3, 4},
		DestinationAddress: net.IP{4, 3, 2, 1},
		Protocol:           6,
		SourcePort:         65280,
		DestinationPort:    255,
	}
	revTuple1 = flowexporter.Tuple{
		SourceAddress:      net.IP{4, 3, 2, 1},
		DestinationAddress: net.IP{1, 2, 3, 4},
		Protocol:           6,
		SourcePort:         255,
		DestinationPort:    65280,
	}
	flow1 = flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 50)),
		StopTime:        refTime,
		OriginalPackets: 0xffff,
		OriginalBytes:   0xbaaaaa0000000000,
		ReversePackets:  0xff,
		ReverseBytes:    0xbaaa,
		TupleOrig:       tuple1,
		TupleReply:      revTuple1,
	}

	tuple2 = flowexporter.Tuple{
		SourceAddress:      net.IP{5, 6, 7, 8},
		DestinationAddress: net.IP{8, 7, 6, 5},
		Protocol:           6,
		SourcePort:         60001,
		DestinationPort:    200,
	}
	revTuple2 = flowexporter.Tuple{
		SourceAddress:      net.IP{8, 7, 6, 5},
		DestinationAddress: net.IP{5, 6, 7, 8},
		Protocol:           6,
		SourcePort:         200,
		DestinationPort:    60001,
	}
	flow2 = flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 20)),
		StopTime:        refTime,
		OriginalPackets: 0xbb,
		OriginalBytes:   0xcbbb,
		ReversePackets:  0xbbbb,
		ReverseBytes:    0xcbbbb0000000000,
		TupleOrig:       tuple2,
		TupleReply:      revTuple2,
	}
)

func TestConnectionStore_addAndUpdateConn(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	// Two flows; one is already in connectionStore and other one is new
	testFlow1 := flow1
	testFlow2 := flow2

	// Create old conntrack flow for testing purposes.
	// This flow is already in connection map.
	oldTestFlow1 := flowexporter.Connection{
		StartTime:               flow1.StartTime,
		StopTime:                flow1.StopTime.Add(-(time.Second * 30)),
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
	// Mock interface store with one of the couple of IPs correspond to Pods
	iStore := interfacestoretest.NewMockInterfaceStore(ctrl)
	mockCT := connectionstest.NewMockConnTrackDumper(ctrl)
	// Create connectionStore
	connStore := &connectionStore{
		connections: make(map[flowexporter.ConnectionKey]flowexporter.Connection),
		connDumper:  mockCT,
		ifaceStore:  iStore,
	}
	// Add flow1conn to the Connection map
	testFlow1Tuple := flowexporter.NewConnectionKey(&testFlow1)
	connStore.connections[testFlow1Tuple] = oldTestFlow1

	updateConnTests := []struct {
		flow flowexporter.Connection
	}{
		{testFlow1}, // To test update part of function
		{testFlow2}, // To test add part of function
	}
	for i, test := range updateConnTests {
		flowTuple := flowexporter.NewConnectionKey(&test.flow)
		var expConn flowexporter.Connection
		if i == 0 {
			expConn = flow1
			expConn.SourcePodNamespace = "ns1"
			expConn.SourcePodName = "pod1"
		} else {
			expConn = flow2
			expConn.DestinationPodNamespace = "ns2"
			expConn.DestinationPodName = "pod2"
			iStore.EXPECT().GetInterfaceByIP(test.flow.TupleOrig.SourceAddress.String()).Return(nil, false)
			iStore.EXPECT().GetInterfaceByIP(test.flow.TupleReply.SourceAddress.String()).Return(interfaceFlow2, true)
		}
		connStore.addOrUpdateConn(&test.flow)
		actualConn, _ := connStore.getConnByKey(flowTuple)
		assert.Equal(t, expConn, *actualConn, "Connections should be equal")
	}
}
