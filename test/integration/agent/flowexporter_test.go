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
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/filter"
	"antrea.io/antrea/pkg/agent/flowexporter/options"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/util/sysctl"
	queriertest "antrea.io/antrea/pkg/querier/testing"
	"antrea.io/antrea/pkg/util/k8s"
	"antrea.io/antrea/pkg/util/objectstore"
)

const (
	testPollInterval           = 0 // Not used in the test, hence 0.
	testActiveFlowTimeout      = 2 * time.Second
	testIdleFlowTimeout        = 1 * time.Second
	testStaleConnectionTimeout = 5 * time.Minute
)

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

	store := connections.NewConnStore(connDumper, true, false, podStore, nil, npQuerier, nil, nil, nil, nil, false, o)

	for b.Loop() {
		connsLens, err := store.PollConntrackAndStore()
		require.NoError(b, err, "Poll() should not return error")
		require.Len(b, connsLens, 1, "Poll() should return slice of length 1")
		assert.Equal(b, numConnections, connsLens[0], "Poll() should return %d connections", numConnections)
		assert.Equal(b, numConnections, store.NumConnections(), "NumConnections() should return %d connections", numConnections)
		// Delete all connections, so that we only benchmark the performance of adding new connections.
		assert.Equal(b, numConnections, store.DeleteAllConnections(), "DeleteAllConnections() should return %d connections", numConnections)
	}
}
