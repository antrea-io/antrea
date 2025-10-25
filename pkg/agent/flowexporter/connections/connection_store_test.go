// Copyright 2025 Antrea Authors.
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

package connections

import (
	"container/heap"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	connectionstest "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	"antrea.io/antrea/pkg/agent/flowexporter/options"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
	proxytest "antrea.io/antrea/pkg/agent/proxy/testing"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	secv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	queriertest "antrea.io/antrea/pkg/querier/testing"
	objectstoretest "antrea.io/antrea/pkg/util/objectstore/testing"
	utilwait "antrea.io/antrea/pkg/util/wait"
	k8sproxy "antrea.io/antrea/third_party/proxy"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	. "antrea.io/antrea/pkg/agent/flowexporter/testing"
)

const (
	testActiveFlowTimeout      = 3 * time.Second
	testIdleFlowTimeout        = 1 * time.Second
	testPollInterval           = 0 // Not used in these tests, hence 0.
	testStaleConnectionTimeout = 5 * time.Minute
)

var testFlowExporterOptions = &options.FlowExporterOptions{
	FlowCollectorAddr:      "",
	FlowCollectorProto:     "",
	ActiveFlowTimeout:      testActiveFlowTimeout,
	IdleFlowTimeout:        testIdleFlowTimeout,
	StaleConnectionTimeout: testStaleConnectionTimeout,
	PollInterval:           testPollInterval,
}

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
)

func Test_ctConnMerge(t *testing.T) {
	conn := GenerateConnectionFn()

	tests := []struct {
		name     string
		existing *connection.Connection
		incoming *connection.Connection
		want     *connection.Connection
	}{
		{
			name:     "no existing connection",
			existing: nil,
			incoming: conn(),
			want:     conn(MarkCTConn),
		}, {
			name:     "existing conn is denied connection",
			existing: conn(MarkDenyConn),
			incoming: conn(),
			want:     conn(MarkDenyConn),
		}, {
			name:     "activity on connection (packet stats)",
			existing: conn(WithStats(connection.Stats{Packets: 1})),
			incoming: conn(UpdatedAfter(30*time.Second), WithStats(connection.Stats{Packets: 4})),
			want:     conn(UpdatedAfter(30*time.Second), WithStats(connection.Stats{Packets: 4})),
		}, {
			name:     "activity on connection (reverse packet stats)",
			existing: conn(WithStats(connection.Stats{ReversePackets: 1})),
			incoming: conn(UpdatedAfter(30*time.Second), WithStats(connection.Stats{ReversePackets: 4})),
			want:     conn(UpdatedAfter(30*time.Second), WithStats(connection.Stats{ReversePackets: 4})),
		}, {
			name:     "activity on tcp state",
			existing: conn(WithSYNSentState()),
			incoming: conn(UpdatedAfter(30*time.Second), WithCloseState()),
			want:     conn(UpdatedAfter(30*time.Second), WithCloseState()),
		}, {
			name:     "StopTime is merged",
			existing: conn(),
			incoming: conn(StoppedAfter(1 * time.Second)),
			want:     conn(StoppedAfter(1 * time.Second)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ctConnMerge(tt.existing, tt.incoming)
			if !cmp.Equal(tt.want, got, DefaultCmpOptions) {
				t.Errorf("ctConnMerge() did not match (-want,+got):\n%s", cmp.Diff(tt.want, got, DefaultCmpOptions))
			}
		})
	}
}

func Test_denyConnMerge(t *testing.T) {
	conn1 := GenerateConnectionFn(MarkDenyConn)

	tests := []struct {
		name     string
		existing *connection.Connection
		incoming *connection.Connection
		want     *connection.Connection
	}{
		{
			name:     "no existing connection",
			existing: nil,
			incoming: conn1(),
			want:     conn1(),
		}, {
			name:     "existing conn is denied connection",
			existing: conn1(MarkDenyConn),
			incoming: conn1(),
			want:     conn1(MarkDenyConn),
		}, {
			name:     "stats are accumulated",
			existing: conn1(WithStats(connection.Stats{Packets: 1, Bytes: 10})),
			incoming: conn1(UpdatedAfter(30*time.Second), WithStats(connection.Stats{Packets: 10, Bytes: 100})),
			want:     conn1(UpdatedAfter(30*time.Second), WithStats(connection.Stats{Packets: 11, Bytes: 110})),
		}, {
			name:     "StopTime is merged",
			existing: conn1(),
			incoming: conn1(StoppedAfter(1 * time.Second)),
			want:     conn1(StoppedAfter(1 * time.Second)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := denyConnMerge(tt.existing, tt.incoming)
			if !cmp.Equal(tt.want, got, DefaultCmpOptions) {
				t.Errorf("denyConnMerge() did not match (-want,+got):\n%s", cmp.Diff(tt.want, got, DefaultCmpOptions))
			}
		})
	}
}

func Test_acceptConnection(t *testing.T) {
	conn := GenerateConnectionFn()

	tests := []struct {
		name string
		conn *connection.Connection
		want bool
	}{
		{
			name: "Has all expected fields",
			conn: conn(WithFlowType(utils.FlowTypeIntraNode), WithPodInfo("ns1", "pod1", "ns2", "pod2")),
			want: true,
		}, {
			name: "missing src pod",
			conn: conn(WithFlowType(utils.FlowTypeIntraNode), WithPodInfo("", "", "ns2", "pod2")),
			want: true,
		}, {
			name: "missing dst pod",
			conn: conn(WithFlowType(utils.FlowTypeIntraNode), WithPodInfo("ns1", "pod1", "", "")),
			want: true,
		}, {
			name: "missing both src and dst pod",
			conn: conn(WithFlowType(utils.FlowTypeIntraNode)),
			want: false,
		}, {
			name: "flow type unsupported",
			conn: conn(WithFlowType(utils.FlowTypeUnsupported), WithPodInfo("ns1", "pod1", "ns2", "pod2")),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := acceptConnection(tt.conn)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConnStore_updateConns(t *testing.T) {
	now := time.Now()
	clock := clocktesting.NewFakeClock(now)
	resetClock := func() {
		clock.SetTime(now)
	}
	basicConn := GenerateConnectionFnWithClock(clock)
	acceptableConn := GenerateConnectionFnWithClock(clock, MarkCTConn, WithPodInfo("ns1", "pod1", "ns2", "pod2"), WithFlowType(utils.FlowTypeIntraNode))

	noopAugment := func(conn *connection.Connection) *connection.Connection { return conn }
	noopMerge := func(e, n *connection.Connection) *connection.Connection {
		if e == nil {
			return n
		}
		return e
	}

	tests := []struct {
		name             string
		existingConns    []*connection.Connection
		newConns         []*connection.Connection
		l7Events         map[connection.ConnectionKey]L7ProtocolFields
		mergeFn          func(t *testing.T) MergeFunc
		notifier         chan UpdateMsg
		expectedConns    map[connection.ConnectionKey]*connection.Connection
		expectedSubConns []*connection.Connection
	}{
		{
			name:     "no conns",
			newConns: []*connection.Connection{},
		}, {
			name:     "conn without any pod info is rejected",
			newConns: []*connection.Connection{basicConn()},
		}, {
			name:     "conn with unsupported flowtype is rejected",
			newConns: []*connection.Connection{basicConn(WithFlowType(utils.FlowTypeUnsupported))},
		}, {
			name:     "accepted connection",
			newConns: []*connection.Connection{acceptableConn()},
			expectedConns: map[connection.ConnectionKey]*connection.Connection{
				connection.NewConnectionKey(acceptableConn()): acceptableConn(UpdatedAfter(2 * time.Minute)),
			},
			mergeFn: func(t *testing.T) MergeFunc {
				return func(existing, incoming *connection.Connection) *connection.Connection {
					require.Empty(t, existing)
					require.Equal(t, acceptableConn(UpdatedAfter(2*time.Minute)), incoming)
					return incoming
				}
			},
		}, {
			name:          "accepted connection with existing",
			existingConns: []*connection.Connection{acceptableConn()},
			newConns:      []*connection.Connection{acceptableConn(IncrementStats)},
			expectedConns: map[connection.ConnectionKey]*connection.Connection{
				connection.NewConnectionKey(acceptableConn()): acceptableConn(IncrementStats, UpdatedAfter(2*time.Minute)),
			},
			mergeFn:  func(_ *testing.T) MergeFunc { return ctConnMerge },
			notifier: make(chan UpdateMsg, 1),
		}, {
			name: "handle L7 existing",
			l7Events: map[connection.ConnectionKey]L7ProtocolFields{
				acceptableConn().FlowKey: {Http: map[int32]*Http{}},
			},
			existingConns: []*connection.Connection{acceptableConn()},
			newConns:      []*connection.Connection{acceptableConn(IncrementStats)},
			expectedConns: map[connection.ConnectionKey]*connection.Connection{
				connection.NewConnectionKey(acceptableConn()): acceptableConn(),
			},
			notifier: make(chan UpdateMsg, 1),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer resetClock()
			s := newStoreWithClock(clock)
			for _, conn := range tt.existingConns {
				key := connection.NewConnectionKey(conn)
				s.entries[key] = conn
			}

			var sub *subscription
			if tt.notifier != nil {
				sub = s.Subscribe()
				sub.ch = tt.notifier
			}

			mergeFn := noopMerge
			if tt.mergeFn != nil {
				mergeFn = tt.mergeFn(t)
			}

			clock.Step(2 * time.Minute)
			s.updateConns(tt.newConns, tt.l7Events, noopAugment, mergeFn)

			if sub != nil {
				select {
				case msg := <-sub.ch:
					require.Len(t, msg.L7Events, len(tt.l7Events))
					if !cmp.Equal(tt.l7Events, msg.L7Events, DefaultCmpOptions) {
						t.Errorf("l7 events did not match (-want,+got):\n%s", cmp.Diff(tt.l7Events, msg.L7Events, DefaultCmpOptions))
					}
				case <-time.After(100 * time.Millisecond):
					t.Error("no notification received for subscription")
				}
			}

			if !cmp.Equal(tt.expectedConns, s.entries, DefaultCmpOptions) {
				t.Errorf("updated conns did not match (-want,+got):\n%s", cmp.Diff(tt.expectedConns, s.entries, DefaultCmpOptions))
			}
		})
	}
}

func newStoreWithClock(clock clock.WithTicker) *ConnStore {
	store := &ConnStore{
		staleConnectionTimeout: testStaleConnectionTimeout,
		subs:                   make(map[*subscription]struct{}, 5),
		entries:                make(map[connection.ConnectionKey]*connection.Connection, 100),
		denyConnUpdates:        make(chan *connection.Connection),
		gc: gcHeap{
			keyToItem: make(map[connection.ConnectionKey]*gcItem),
		},
		clock: clock,
		zones: []uint16{openflow.CtZone},
	}
	return store
}

func TestConnStore_Run_NetworkPolicyWait(t *testing.T) {
	ctrl := gomock.NewController(t)
	// Create a utilwait.Group and increment it to simulate waiting for NetworkPolicies
	networkPolicyWait := utilwait.NewGroup()
	networkPolicyWait.Increment()

	firstPollDoneCh := make(chan struct{})
	store := newStoreWithClock(clock.RealClock{})
	store.pollInterval = 100 * time.Millisecond
	store.networkPolicyWait = networkPolicyWait

	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	mockConnDumper.EXPECT().GetMaxConnections().Return(0, nil).AnyTimes()
	mockConnDumper.EXPECT().DumpFlows(uint16(openflow.CtZone)).DoAndReturn(func(uint16) ([]*connection.Connection, int, error) {
		close(firstPollDoneCh)
		return []*connection.Connection{}, 0, nil
	}).Times(1)
	mockConnDumper.EXPECT().DumpFlows(uint16(openflow.CtZone)).Return([]*connection.Connection{}, 0, nil).AnyTimes()

	store.connDumper = mockConnDumper
	// Record the time before starting Run
	beforeRunTime := time.Now()

	// Verify that networkPolicyReadyTime is initially zero
	require.Zero(t, store.networkPolicyReadyTime)

	// Start the connection store in a goroutine
	stopCh := make(chan struct{})
	closeStopCh := sync.OnceFunc(func() { close(stopCh) })
	defer closeStopCh()
	runFinishedCh := make(chan struct{})
	go func() {
		defer close(runFinishedCh)
		store.Run(stopCh)
	}()

	// Signal that NetworkPolicies are ready
	networkPolicyWait.Done()

	select {
	case <-firstPollDoneCh:
		// Expected: DumpFlows to be triggered
	case <-time.After(1 * time.Second):
		require.Fail(t, "DumpFlows was not triggered")
	}

	assert.True(t, store.networkPolicyReadyTime.After(beforeRunTime))

	// Stop the connection store
	closeStopCh()

	// Wait for Run to finish
	select {
	case <-runFinishedCh:
		// Expected: Run finished cleanly
	case <-time.After(1 * time.Second):
		require.Fail(t, "Run should have finished within 1 second after stopCh was closed")
	}
}

func TestConnStore_removeStaleConnections(t *testing.T) {
	now := time.Now()
	clock := clocktesting.NewFakeClock(now)
	resetClock := func() {
		clock.SetTime(now)
	}
	expiredConn := GenerateConnectionFnWithClock(clock, UpdatedAfter(0))
	validConn := GenerateConnectionFnWithClock(clock, UpdatedAfter(2*time.Hour))

	tests := []struct {
		name            string
		existingConns   []*connection.Connection
		expectedEntries []*connection.Connection
	}{
		{
			name:            "no conns",
			existingConns:   []*connection.Connection{},
			expectedEntries: []*connection.Connection{},
		}, {
			name:            "has expired connection",
			existingConns:   []*connection.Connection{expiredConn()},
			expectedEntries: []*connection.Connection{},
		}, {
			name:            "has non-expired connection",
			existingConns:   []*connection.Connection{validConn()},
			expectedEntries: []*connection.Connection{validConn()},
		},
		{
			name:            "has non-expired connection",
			existingConns:   []*connection.Connection{expiredConn(), validConn()},
			expectedEntries: []*connection.Connection{validConn()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer resetClock()

			s := newStoreWithClock(clock)
			for _, conn := range tt.existingConns {
				heap.Push(&s.gc, &gcItem{
					conn:       conn,
					expiryNano: conn.LastUpdateTime.UnixNano() + s.staleConnectionTimeout.Nanoseconds(),
				})
			}

			require.Len(t, s.gc.items, len(tt.existingConns))
			clock.Step(10 * time.Minute)
			s.removeStaleConnections()

			collectedConns := make([]*connection.Connection, 0, len(s.gc.items))
			for _, item := range s.gc.items {
				collectedConns = append(collectedConns, item.conn)
			}
			assert.ElementsMatch(t, tt.expectedEntries, collectedConns)
		})
	}
}

func TestConnStore_HandleCTConnection(t *testing.T) {
	refTime := time.Now()
	clock := clocktesting.NewFakeClock(refTime)
	resetClock := func() {
		clock.SetTime(refTime)
	}
	conn := GenerateConnectionFnWithClock(clock)

	servicePortName := k8sproxy.ServicePortName{
		NamespacedName: types.NamespacedName{
			Namespace: "serviceNS1",
			Name:      "service1",
		},
		Port:     "255",
		Protocol: v1.ProtocolTCP,
	}

	var ingressOfID uint32 = 1000
	var egressOfID uint32 = 2000
	np1 := cpv1beta.NetworkPolicyReference{
		Type:      cpv1beta.K8sNetworkPolicy,
		Namespace: "foo",
		Name:      "bar",
		UID:       "uid1",
	}
	rule1 := agenttypes.PolicyRule{
		Direction: cpv1beta.DirectionIn,
		From:      []agenttypes.Address{},
		To:        []agenttypes.Address{},
		Service:   []cpv1beta.Service{},
		Action:    ptr.To(secv1beta1.RuleActionAllow),
		Priority:  nil,
		Name:      "rule1",
		FlowID:    uint32(0),
		TableID:   uint8(10),
		PolicyRef: &np1,
	}

	rule2 := agenttypes.PolicyRule{
		Direction: cpv1beta.DirectionIn,
		From:      []agenttypes.Address{},
		To:        []agenttypes.Address{},
		Service:   []cpv1beta.Service{},
		Action:    ptr.To(secv1beta1.RuleActionAllow),
		Priority:  nil,
		Name:      "rule2",
		FlowID:    uint32(0),
		TableID:   uint8(10),
		PolicyRef: &np1,
	}

	tc := []struct {
		name string
		// flow for testing adding and updating
		testFlow                *connection.Connection
		oldConn                 *connection.Connection
		hasSrcPod               bool
		hasDstPod               bool
		hasSvc                  bool
		hasIngressNetworkPolicy bool
		hasEgressNetworkPolicy  bool
		expectedConn            *connection.Connection
	}{
		{
			name:     "bad flow, no pod for src or dst",
			testFlow: conn(),
		}, {
			name:         "has src pod",
			testFlow:     conn(),
			hasSrcPod:    true,
			expectedConn: conn(MarkCTConn, WithPodInfoFromPod(pod1, nil), UpdatedAfter(0)),
		}, {
			name:         "has dst pod",
			testFlow:     conn(),
			hasDstPod:    true,
			expectedConn: conn(MarkCTConn, WithPodInfoFromPod(nil, pod1), UpdatedAfter(0)),
		}, {
			name:         "has both pod",
			testFlow:     conn(),
			hasSrcPod:    true,
			hasDstPod:    true,
			expectedConn: conn(MarkCTConn, WithPodInfoFromPod(pod1, pod1), UpdatedAfter(0)),
		}, {
			name:         "has svc",
			testFlow:     conn(WithServiceMark),
			hasSrcPod:    true,
			hasDstPod:    true,
			hasSvc:       true,
			expectedConn: conn(MarkCTConn, WithPodInfoFromPod(pod1, pod1), UpdatedAfter(0), WithServiceMark, WithServicePortName(servicePortName.Namespace, servicePortName.Name, servicePortName.Port)),
		}, {
			name:                    "has ingress network policy",
			testFlow:                conn(WithIngressOpenflowID(ingressOfID)),
			hasSrcPod:               true,
			hasDstPod:               true,
			hasIngressNetworkPolicy: true,
			expectedConn:            conn(MarkCTConn, WithPodInfoFromPod(pod1, pod1), UpdatedAfter(0), WithIngressOpenflowID(ingressOfID), IngressNPMetadataOpt(np1.Namespace, np1.Name, string(np1.UID), rule1.Name, np1.Type)),
		}, {
			name:                   "has egress network policy",
			testFlow:               conn(WithEgressOpenflowID(egressOfID)),
			hasSrcPod:              true,
			hasDstPod:              true,
			hasEgressNetworkPolicy: true,
			expectedConn:           conn(MarkCTConn, WithPodInfoFromPod(pod1, pod1), UpdatedAfter(0), WithEgressOpenflowID(egressOfID), EgressNPMetadataOpt(np1.Namespace, np1.Name, string(np1.UID), rule2.Name, np1.Type)),
			// }, {
			// 	name: "update active connection",
			// }, {
			// 	name: "update dying connection",
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			defer resetClock()
			ctrl := gomock.NewController(t)

			flow := tt.testFlow
			key := connection.NewConnectionKey(flow)

			// Reset the metrics.
			metrics.TotalDenyConnections.Set(0)
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			mockProxier := proxytest.NewMockProxier(ctrl)
			mockNPQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
			egressQuerier := queriertest.NewMockEgressQuerier(ctrl)

			if tt.hasSrcPod {
				mockPodStore.EXPECT().GetPodByIPAndTime(key.SourceAddress.String(), gomock.Any()).Return(pod1, true)
			} else {
				mockPodStore.EXPECT().GetPodByIPAndTime(key.SourceAddress.String(), gomock.Any()).Return(nil, false)
			}

			if tt.hasDstPod {
				mockPodStore.EXPECT().GetPodByIPAndTime(key.DestinationAddress.String(), gomock.Any()).Return(pod1, true)
			} else {
				mockPodStore.EXPECT().GetPodByIPAndTime(key.DestinationAddress.String(), gomock.Any()).Return(nil, false)
			}

			if tt.hasSvc {
				protocol, _ := lookupServiceProtocol(key.Protocol)
				serviceStr := fmt.Sprintf("%s:%d/%s", flow.OriginalDestinationAddress.String(), flow.OriginalDestinationPort, protocol)
				mockProxier.EXPECT().GetServiceByIP(serviceStr).Return(servicePortName, true)
			}

			if tt.hasIngressNetworkPolicy {
				mockNPQuerier.EXPECT().GetNetworkPolicyByRuleFlowID(ingressOfID).Return(&np1)
				mockNPQuerier.EXPECT().GetRuleByFlowID(ingressOfID).Return(&rule1)
			}

			if tt.hasEgressNetworkPolicy {
				mockNPQuerier.EXPECT().GetNetworkPolicyByRuleFlowID(egressOfID).Return(&np1)
				mockNPQuerier.EXPECT().GetRuleByFlowID(egressOfID).Return(&rule2)
			}

			store := NewConnStore(nil, true, false, mockPodStore, mockProxier, mockNPQuerier, egressQuerier, nil, nil, nil, false, testFlowExporterOptions)
			store.clock = clock

			store.updateConns([]*connection.Connection{flow}, nil, store.ctConnectionAugment, ctConnMerge)

			assert.Equal(t, tt.expectedConn, store.entries[key])
		})
	}
}

func TestConnStore_HandleDenyConnection(t *testing.T) {
	ctrl := gomock.NewController(t)
	// Create flow for testing adding and updating of same connection.
	refTime := time.Now()
	clock := clocktesting.NewFakeClock(refTime)
	resetClock := func() {
		clock.SetTime(refTime)
	}
	deniedConn := GenerateConnectionFnWithClock(clock, MarkDenyConn, WithStats(connection.Stats{Packets: 1, Bytes: 60}), WithRandomOriginalDestinationV4())

	servicePortName := k8sproxy.ServicePortName{
		NamespacedName: types.NamespacedName{
			Namespace: "serviceNS1",
			Name:      "service1",
		},
		Port:     "255",
		Protocol: v1.ProtocolTCP,
	}

	processingTime := 10 * time.Second

	tc := []struct {
		name string
		// flow for testing adding and updating
		testFlow *connection.Connection
		isSvc    bool
	}{
		{
			name:     "Flow not through service",
			testFlow: deniedConn(),
			isSvc:    false,
		}, {
			name:     "Flow through service",
			testFlow: deniedConn(WithServiceMark),
			isSvc:    true,
		},
	}
	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			defer resetClock()

			// Reset the metrics.
			metrics.TotalDenyConnections.Set(0)
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			mockProxier := proxytest.NewMockProxier(ctrl)

			if c.isSvc {
				protocol, _ := lookupServiceProtocol(c.testFlow.FlowKey.Protocol)
				serviceStr := fmt.Sprintf("%s:%d/%s", c.testFlow.OriginalDestinationAddress.String(), c.testFlow.OriginalDestinationPort, protocol)
				mockProxier.EXPECT().GetServiceByIP(serviceStr).Return(servicePortName, true)
			}
			mockPodStore.EXPECT().GetPodByIPAndTime(c.testFlow.FlowKey.SourceAddress.String(), gomock.Any()).Return(pod1, true)
			mockPodStore.EXPECT().GetPodByIPAndTime(c.testFlow.FlowKey.DestinationAddress.String(), gomock.Any()).Return(pod1, true)

			store := NewConnStore(nil, true, false, mockPodStore, mockProxier, nil, nil, nil, nil, nil, false, testFlowExporterOptions)

			store.clock = clock

			clock.Step(processingTime)

			copy := *c.testFlow
			expectedConn := &copy
			expectedConn.LastUpdateTime = clock.Now()
			expectedConn.DestinationPodName = pod1.Name
			expectedConn.DestinationPodNamespace = pod1.Namespace
			expectedConn.SourcePodName = pod1.Name
			expectedConn.SourcePodNamespace = pod1.Namespace

			if c.isSvc {
				expectedConn.DestinationServicePortName = servicePortName.String()
			}

			store.handleDenyConnection(c.testFlow)

			key := connection.NewConnectionKey(c.testFlow)
			ok := store.HasConn(key)
			require.True(t, ok, "deny connection should be there in connection store")
			actualConn := store.entries[key]
			assert.Equal(t, expectedConn, actualConn, "connection should be updated and filled")
			assert.Len(t, store.gc.items, 1, "Length of the stale queue should be 1")
			checkDenyConnectionMetrics(t, len(store.entries))

			clock.Step(processingTime)
			expectedConn.OriginalStats.Bytes += c.testFlow.OriginalStats.Bytes
			expectedConn.OriginalStats.Packets += 1
			expectedConn.LastUpdateTime = clock.Now()

			store.handleDenyConnection(c.testFlow)
			actualConn = store.entries[key]

			assert.Equal(t, expectedConn, actualConn, "deny connections should be equal")
			checkDenyConnectionMetrics(t, len(store.entries))
		})
	}
}

func TestConnStore_SubmitDenyConn(t *testing.T) {
	conn := GenerateConnectionFn(MarkDenyConn)
	store := &ConnStore{
		denyConnUpdates: make(chan *connection.Connection, 1),
	}

	store.SubmitDenyConn(conn())

	select {
	case got := <-store.denyConnUpdates:
		assert.Equal(t, conn(), got)
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "did not receive submitted connection")
	}
}
