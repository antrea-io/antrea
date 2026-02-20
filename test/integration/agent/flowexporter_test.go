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
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ti-mo/conntrack"
	mock "go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	types "k8s.io/apimachinery/pkg/types"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	connectionstest "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	"antrea.io/antrea/pkg/agent/flowexporter/filter"
	"antrea.io/antrea/pkg/agent/flowexporter/options"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/util/sysctl"
	queriertest "antrea.io/antrea/pkg/querier/testing"
	"antrea.io/antrea/pkg/util/k8s"
	"antrea.io/antrea/pkg/util/objectstore"
	objectstoretest "antrea.io/antrea/pkg/util/objectstore/testing"
)

const (
	testPollInterval           = 0 // Not used in the test, hence 0.
	testActiveFlowTimeout      = 2 * time.Second
	testIdleFlowTimeout        = 1 * time.Second
	testStaleConnectionTimeout = 5 * time.Minute
)

func createConnsForTest() ([]*connection.Connection, []*connection.ConnectionKey) {
	// Reference for flow timestamp
	refTime := time.Now()

	testConns := make([]*connection.Connection, 2)
	testConnKeys := make([]*connection.ConnectionKey, 2)
	// Flow-1
	tuple1 := connection.Tuple{SourceAddress: netip.MustParseAddr("1.2.3.4"), DestinationAddress: netip.MustParseAddr("4.3.2.1"), Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	testConn1 := &connection.Connection{
		StartTime:       refTime.Add(-(time.Second * 50)),
		StopTime:        refTime,
		OriginalPackets: 0xffff,
		OriginalBytes:   0xbaaaaa0000000000,
		ReversePackets:  0xff,
		ReverseBytes:    0xbaaa,
		FlowKey:         tuple1,
		Zone:            65520,
	}
	testConnKey1 := connection.NewConnectionKey(testConn1)
	testConns[0] = testConn1
	testConnKeys[0] = &testConnKey1
	// Flow-2
	tuple2 := connection.Tuple{SourceAddress: netip.MustParseAddr("5.6.7.8"), DestinationAddress: netip.MustParseAddr("8.7.6.5"), Protocol: 6, SourcePort: 60001, DestinationPort: 200}
	testConn2 := &connection.Connection{
		StartTime:       refTime.Add(-(time.Second * 20)),
		StopTime:        refTime,
		OriginalPackets: 0xbb,
		OriginalBytes:   0xcbbb,
		ReversePackets:  0xbbbb,
		ReverseBytes:    0xcbbbb0000000000,
		FlowKey:         tuple2,
		Zone:            65520,
	}
	testConnKey2 := connection.NewConnectionKey(testConn2)
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
	mockPodStore := objectstoretest.NewMockPodStore(ctrl)
	npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
	// TODO: Enhance the integration test by testing service.
	o := &options.FlowExporterOptions{
		ActiveFlowTimeout:      testActiveFlowTimeout,
		IdleFlowTimeout:        testIdleFlowTimeout,
		StaleConnectionTimeout: testStaleConnectionTimeout,
		PollInterval:           testPollInterval}
	conntrackConnStore := connections.NewConntrackConnectionStore(connDumperMock, true, false, npQuerier, mockPodStore, nil, nil, o)
	// Expect calls for connStore.poll and other callees
	connDumperMock.EXPECT().DumpFlows(uint16(0)).Return(nil, 0, nil)
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
	assert.Len(t, connsLens, 2, "length of connsLens is expected to be 2")
	assert.Len(t, testConns, connsLens[1], "expected connections should be equal to number of testConns")

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

// BenchmarkConntrackConnectionStorePoll is a benchmark for the poll function of the
// ConntrackConnectionStore, which periodically dumps all connections from conntrack and updates its
// internal store. This benchmark only evaluates connection "add", and not connection "update",
// which is achieved by clearing the connection store after each benchmark loop iteration. Note that
// connection "add" is more expensive than connection "update". However, it seems that dumping the
// connections from conntrack is what is using the most CPU time.
func BenchmarkConntrackConnectionStorePoll(b *testing.B) {
	// 32K is not such a high number (we could go to 128K or even more), but it seems reasonable
	// for the purpose of the benchmark. The polling operation should be O(N) for time, and the
	// connection store should use O(N) memory, where N is the number of connections in
	// conntrack, so we can extrapolate easily.
	const numConnections = 32768
	const ctZone = openflow.CtZone
	const otherCtZone = 100
	require.NotEqual(b, ctZone, otherCtZone)
	// Set the ConnSourceCTMarkField to localVal (3) to mark as from local Pods
	// This ensures the connection passes the policyAllowed check
	const ctMark = 0x3
	const baseSrcPort = 20000
	const baseDstIPOctet = 100
	const numDstIPs = 100
	require.Less(b, baseDstIPOctet+numDstIPs-1, 255, "numDstIPs is too large")

	// Create a conntrack connection to manage entries
	conn, err := conntrack.Dial(nil)
	require.NoError(b, err, "Failed to create conntrack connection")
	defer conn.Close()

	// We want to ensure that there are no conntrack entries in the Antrea zone
	// before we start the benchmark, as that would skew the results.
	flows, err := conn.Dump(nil)
	require.NoError(b, err, "Failed to dump conntrack entries")
	for _, flow := range flows {
		require.NotEqualValues(b, ctZone, flow.Zone, "Expected no conntrack entries in Antrea zone")
	}

	getConnection := func(srcAddr, dstAddr netip.Addr, srcPort uint16, zone uint16, mark uint32) conntrack.Flow {
		flow := conntrack.NewFlow(
			6, // TCP protocol
			0,
			srcAddr,
			dstAddr,
			srcPort,
			80,   // destination port
			3600, // timeout
			mark,
		)
		flow.Zone = zone
		return flow
	}

	createdFlows := make([]conntrack.Flow, 0, 2*numConnections)

	// Cleanup function to delete all created entries
	cleanup := func() {
		b.Logf("Cleaning up %d conntrack entries...", len(createdFlows))
		for i, flow := range createdFlows {
			if err := conn.Delete(flow); err != nil {
				b.Logf("Warning: Failed to delete conntrack entry %d: %v", i, err)
			}
		}
	}
	defer cleanup()

	srcAddr := netip.MustParseAddr("10.0.0.2")
	// Create conntrack entries spread across multiple destination addresses and ports
	createConnections := func(num int, zone uint16, mark uint32) {
		b.Logf("Creating %d conntrack entries across multiple destination addresses in zone %d with mark %x...", num, zone, mark)
		for i := range num {
			// Calculate destination address: cycle through 10.0.0.100 through 10.0.0.199
			// For 100 destinations (100-199), we cycle through them first
			dstOctet := baseDstIPOctet + (i % numDstIPs)
			dstAddr := netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", dstOctet))

			// Calculate source port: increment after cycling through all destinations
			srcPort := uint16(baseSrcPort + (i / numDstIPs))
			if srcPort < baseSrcPort { // Overflow check
				require.Fail(b, "Too many connections created")
			}

			flow := getConnection(
				srcAddr,
				dstAddr,
				srcPort, // varying source port
				zone,
				mark,
			)
			require.NoError(b, conn.Create(flow), "Failed to create conntrack entry %d")
			createdFlows = append(createdFlows, flow)
		}
	}

	b.Logf("Creating target conntrack entries")
	createConnections(numConnections, ctZone, ctMark) // mark - ConnSourceCTMarkField set to localVal
	b.Logf("Creating other conntrack entries")
	// These connections are not relevant to the FlowExporter, but are created to check how
	// efficient we are at filtering out other connections.
	createConnections(numConnections, otherCtZone, 0)

	// Create fake Kubernetes client and PodStore
	var fakePods []runtime.Object

	// Create source pod
	srcPod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "src-pod",
			UID:               types.UID("src-pod-uid"),
			CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour)},
		},
		Status: v1.PodStatus{
			PodIPs: []v1.PodIP{
				{IP: "10.0.0.2"},
			},
			Phase: v1.PodRunning,
		},
	}
	fakePods = append(fakePods, srcPod)

	// Create destination pods
	for offset := range numDstIPs {
		dstOctet := baseDstIPOctet + offset
		dstIP := fmt.Sprintf("10.0.0.%d", dstOctet)
		podName := fmt.Sprintf("dst-pod-%d", dstOctet)
		podUID := fmt.Sprintf("dst-pod-%d-uid", dstOctet)

		dstPod := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:         "default",
				Name:              podName,
				UID:               types.UID(podUID),
				CreationTimestamp: metav1.Time{Time: time.Now().Add(-time.Hour)},
			},
			Status: v1.PodStatus{
				PodIPs: []v1.PodIP{
					{IP: dstIP},
				},
				Phase: v1.PodRunning,
			},
		}
		fakePods = append(fakePods, dstPod)
	}

	// Create fake client with all pods provided upfront
	k8sClient := fake.NewSimpleClientset(fakePods...)

	// Create PodStore with the fake client
	stopCh := make(chan struct{})
	defer close(stopCh)

	podInformer := coreinformers.NewPodInformer(k8sClient, metav1.NamespaceAll, 0, cache.Indexers{})
	podInformer.SetTransform(k8s.NewTrimmer(k8s.TrimPod))
	podStore := objectstore.NewPodStore(podInformer)

	go podInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, podInformer.HasSynced, podStore.HasSynced)

	// Create a real conntrack dumper that will read from the actual conntrack table
	nodeConfig := &config.NodeConfig{
		GatewayConfig: &config.GatewayConfig{
			IPv4: net.ParseIP("10.0.0.1"),
		},
	}
	serviceCIDRv4 := netip.MustParsePrefix("10.96.0.0/12")
	connDumper := connections.NewConnTrackSystem(nodeConfig, serviceCIDRv4, netip.Prefix{}, false, filter.NewProtocolFilter(nil))

	ctrl := mock.NewController(b)
	npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)

	o := &options.FlowExporterOptions{
		ActiveFlowTimeout:      testActiveFlowTimeout,
		IdleFlowTimeout:        testIdleFlowTimeout,
		StaleConnectionTimeout: testStaleConnectionTimeout,
		PollInterval:           testPollInterval,
	}

	conntrackConnStore := connections.NewConntrackConnectionStore(
		connDumper,
		true,  // v4Enabled
		false, // v6Enabled
		npQuerier,
		podStore,
		nil,
		nil,
		o,
	)

	for b.Loop() {
		connsLens, err := conntrackConnStore.Poll()
		require.NoError(b, err, "Poll() should not return error")
		require.Len(b, connsLens, 1, "Poll() should return slice of length 1")
		assert.Equal(b, numConnections, connsLens[0], "Poll() should return %d connections", numConnections)
		assert.Equal(b, numConnections, conntrackConnStore.NumConnections(), "NumConnections() should return %d connections", numConnections)
		// Delete all connections, so that we only benchmark the performance of adding new connections.
		assert.Equal(b, numConnections, conntrackConnStore.DeleteAllConnections(), "DeleteAllConnections() should return %d connections", numConnections)
	}
}
