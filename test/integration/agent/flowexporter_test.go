//go:build !windows
// +build !windows

// Copyright 2020 Antrea Authors
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

package agent

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mock "go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	connectionstest "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/util/sysctl"
	queriertest "antrea.io/antrea/pkg/querier/testing"
	podstoretest "antrea.io/antrea/pkg/util/podstore/testing"
)

const (
	testPollInterval           = 0 // Not used in the test, hence 0.
	testActiveFlowTimeout      = 2 * time.Second
	testIdleFlowTimeout        = 1 * time.Second
	testStaleConnectionTimeout = 5 * time.Minute
)

type fakel7EventMapGetter struct{}

func (fll *fakel7EventMapGetter) ConsumeL7EventMap() map[flowexporter.ConnectionKey]connections.L7ProtocolFields {
	l7EventsMap := make(map[flowexporter.ConnectionKey]connections.L7ProtocolFields)
	return l7EventsMap
}

func createConnsForTest() ([]*flowexporter.Connection, []*flowexporter.ConnectionKey) {
	// Reference for flow timestamp
	refTime := time.Now()

	testConns := make([]*flowexporter.Connection, 2)
	testConnKeys := make([]*flowexporter.ConnectionKey, 2)
	// Flow-1
	tuple1 := flowexporter.Tuple{SourceAddress: netip.MustParseAddr("1.2.3.4"), DestinationAddress: netip.MustParseAddr("4.3.2.1"), Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	testConn1 := &flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 50)),
		StopTime:        refTime,
		OriginalPackets: 0xffff,
		OriginalBytes:   0xbaaaaa0000000000,
		ReversePackets:  0xff,
		ReverseBytes:    0xbaaa,
		FlowKey:         tuple1,
	}
	testConnKey1 := flowexporter.NewConnectionKey(testConn1)
	testConns[0] = testConn1
	testConnKeys[0] = &testConnKey1
	// Flow-2
	tuple2 := flowexporter.Tuple{SourceAddress: netip.MustParseAddr("5.6.7.8"), DestinationAddress: netip.MustParseAddr("8.7.6.5"), Protocol: 6, SourcePort: 60001, DestinationPort: 200}
	testConn2 := &flowexporter.Connection{
		StartTime:       refTime.Add(-(time.Second * 20)),
		StopTime:        refTime,
		OriginalPackets: 0xbb,
		OriginalBytes:   0xcbbb,
		ReversePackets:  0xbbbb,
		ReverseBytes:    0xcbbbb0000000000,
		FlowKey:         tuple2,
	}
	testConnKey2 := flowexporter.NewConnectionKey(testConn2)
	testConns[1] = testConn2
	testConnKeys[1] = &testConnKey2

	return testConns, testConnKeys
}

func preparePodInformation(podName string, podNS string, ip netip.Addr) *v1.Pod {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: podNS,
			Name:      podName,
			UID:       types.UID(podName),
		},
		Status: v1.PodStatus{
			Phase: v1.PodPending,
			PodIPs: []v1.PodIP{
				{
					IP: ip.String(),
				},
			},
		},
	}
	return pod
}

// TestConnectionStoreAndFlowRecords covers two scenarios: (i.) Add connections to connection store through connectionStore.Poll
// execution and build flow records. (ii.) Flush the connections and check records are sti:w
func TestConnectionStoreAndFlowRecords(t *testing.T) {
	// Test setup
	ctrl := mock.NewController(t)

	// Prepare connections and pod store for test
	testConns, testConnKeys := createConnsForTest()
	testPods := make([]*v1.Pod, 2)
	testPods[0] = preparePodInformation("pod1", "ns1", testConns[0].FlowKey.SourceAddress)
	testPods[1] = preparePodInformation("pod2", "ns2", testConns[1].FlowKey.DestinationAddress)

	// Create connectionStore, FlowRecords and associated mocks
	connDumperMock := connectionstest.NewMockConnTrackDumper(ctrl)
	mockPodStore := podstoretest.NewMockInterface(ctrl)
	npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
	// TODO: Enhance the integration test by testing service.
	o := &flowexporter.FlowExporterOptions{
		ActiveFlowTimeout:      testActiveFlowTimeout,
		IdleFlowTimeout:        testIdleFlowTimeout,
		StaleConnectionTimeout: testStaleConnectionTimeout,
		PollInterval:           testPollInterval}
	conntrackConnStore := connections.NewConntrackConnectionStore(connDumperMock, true, false, npQuerier, mockPodStore, nil, &fakel7EventMapGetter{}, o)
	// Expect calls for connStore.poll and other callees
	connDumperMock.EXPECT().DumpFlows(uint16(openflow.CtZone)).Return(testConns, 0, nil)
	connDumperMock.EXPECT().GetMaxConnections().Return(0, nil)
	for i, testConn := range testConns {
		if i == 0 {
			mockPodStore.EXPECT().GetPodByIPAndTime(testConn.FlowKey.SourceAddress.String(), mock.Any()).Return(testPods[i], true)
			mockPodStore.EXPECT().GetPodByIPAndTime(testConn.FlowKey.DestinationAddress.String(), mock.Any()).Return(nil, false)
		} else {
			mockPodStore.EXPECT().GetPodByIPAndTime(testConn.FlowKey.SourceAddress.String(), mock.Any()).Return(nil, false)
			mockPodStore.EXPECT().GetPodByIPAndTime(testConn.FlowKey.DestinationAddress.String(), mock.Any()).Return(testPods[i], true)
		}
	}
	// Execute connStore.Poll
	connsLens, err := conntrackConnStore.Poll()
	require.Nil(t, err, fmt.Sprintf("Failed to add connections to connection store: %v", err))
	assert.Len(t, connsLens, 1, "length of connsLens is expected to be 1")
	assert.Len(t, testConns, connsLens[0], "expected connections should be equal to number of testConns")

	// Check if connections in connectionStore are same as testConns or not
	for i, expConn := range testConns {
		if i == 0 {
			expConn.SourcePodName = testPods[i].ObjectMeta.Name
			expConn.SourcePodNamespace = testPods[i].ObjectMeta.Namespace
		} else {
			expConn.DestinationPodName = testPods[i].ObjectMeta.Name
			expConn.DestinationPodNamespace = testPods[i].ObjectMeta.Name
		}
		actualConn, found := conntrackConnStore.GetConnByKey(*testConnKeys[i])
		assert.Equal(t, found, true, "testConn should be present in connection store")
		assert.Equal(t, expConn, actualConn, "testConn and connection in connection store should be equal")
	}
}

func TestSetupConnTrackParameters(t *testing.T) {
	err := connections.SetupConntrackParameters()
	require.NoError(t, err, "Cannot Setup conntrack parameters")
	conntrackAcct, err := sysctl.GetSysctlNet("netfilter/nf_conntrack_acct")
	require.NoError(t, err, "Cannot read nf_conntrack_acct")
	assert.Equal(t, 1, conntrackAcct, "net.netfilter.nf_conntrack_acct value should be 1")
	conntrackTimestamping, err := sysctl.GetSysctlNet("netfilter/nf_conntrack_timestamp")
	require.NoError(t, err, "Cannot read nf_conntrack_timestamp")
	assert.Equal(t, 1, conntrackTimestamping, "net.netfilter.nf_conntrack_timestamp value should be 1")
}
