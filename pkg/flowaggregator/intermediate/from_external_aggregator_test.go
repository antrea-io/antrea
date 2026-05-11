// Copyright 2026 Antrea Authors
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

package intermediate

import (
	"container/heap"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	clocktesting "k8s.io/utils/clock/testing"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

func TestCorrelateRecordsForToExternalFlow(t *testing.T) {
	recordChan := make(chan *flowpb.Flow)
	input := AggregationInput{
		RecordChan:            recordChan,
		WorkerNum:             2,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	clock := clocktesting.NewFakeClock(time.Now())
	ap, _ := initAggregationProcessWithClock(input, clock)
	// Test IPv4 fields.
	record1 := createFlowRecordForSrc(false, flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	runCorrelationAndCheckResult(t, ap, clock, record1, nil, false, flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL, false)
	// Cleanup the flowKeyMap in aggregation process.
	flowKey1, _ := getFlowKeyFromRecord(record1)
	err := ap.deleteFlowKeyFromMap(*flowKey1)
	assert.NoError(t, err)
	heap.Pop(&ap.expirePriorityQueue)
	// Test IPv6 fields.
	record1 = createFlowRecordForSrc(true, flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	runCorrelationAndCheckResult(t, ap, clock, record1, nil, true, flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL, false)
}

var (
	currTime                   = time.Now()
	externalIP                 = []byte{0xac, 0x12, 0x00, 0x01} // 172.18.0.1
	podIP                      = []byte{0x0a, 0xf4, 0x01, 0x03} // 10.244.1.3
	gatewayIP                  = []byte{0x0a, 0xf4, 0x02, 0x01} // 10.244.2.1
	nodeIP                     = []byte{0xac, 0x12, 0x00, 0x02} // 172.18.0.2
	containerPort              = uint32(82)
	destinationServicePortName = "namespace/service-name:serviceportname"
)

var sourceNodeIP = &flowpb.IP{
	Source:      externalIP,
	Destination: podIP,
}

// generateSourceNodeFlowAndFlowKey returns a FROM_EXTERNAL source-node flow. It has ProxySnatIp
// set (the source node's gateway masqueraded the external client) and no DestinationPodName (the
// pod is on the destination node).
func generateSourceNodeFlowAndFlowKey() (*flowpb.Flow, *FlowKey) {
	sourceNodeRecord := &flowpb.Flow{
		K8S: &flowpb.Kubernetes{
			FlowType:                   flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL,
			DestinationServicePortName: destinationServicePortName,
			DestinationServiceIp:       nodeIP,
			DestinationClusterIp:       nodeIP,
			DestinationServicePort:     containerPort,
		},
		Ip: sourceNodeIP,
		Transport: &flowpb.Transport{
			ProtocolNumber:  6,
			SourcePort:      38746,
			DestinationPort: 80,
		},
		ReverseStats:  &flowpb.Stats{},
		StartTs:       timestamppb.New(currTime),
		EndTs:         timestamppb.New(currTime.Add(time.Minute)),
		ProxySnatIp:   gatewayIP,
		ProxySnatPort: uint32(52391),
	}
	sourceNodeFlowKey, _ := getFlowKeyFromRecord(sourceNodeRecord)
	return sourceNodeRecord, sourceNodeFlowKey
}

// generateDestinationNodeFlowAndFlowKey returns the destination-node half of an inter-node
// FROM_EXTERNAL connection. The agent exports it with FlowType=INTER_NODE (srcIsGw branch).
// ProxySnatIp is absent because conntrack is symmetric at the destination node (no SNAT here).
func generateDestinationNodeFlowAndFlowKey() (*flowpb.Flow, *FlowKey) {
	destinationNodeRecord := &flowpb.Flow{
		K8S: &flowpb.Kubernetes{
			DestinationPodName:      "nginx-deployment-HASH",
			DestinationPodNamespace: "some-namespace",
			FlowType:                flowpb.FlowType_FLOW_TYPE_INTER_NODE,
		},
		Ip: &flowpb.IP{
			Source:      gatewayIP,
			Destination: podIP,
		},
		Transport: &flowpb.Transport{
			ProtocolNumber:  6,
			SourcePort:      52391,
			DestinationPort: 80,
		},
		Stats:        &flowpb.Stats{},
		ReverseStats: &flowpb.Stats{},
		StartTs:      timestamppb.New(currTime),
		EndTs:        timestamppb.New(currTime.Add(2 * time.Minute)),
	}
	destinationNodeFlowKey, _ := getFlowKeyFromRecord(destinationNodeRecord)
	return destinationNodeRecord, destinationNodeFlowKey
}

func newAggregationProcess() *aggregationProcess {
	recordChan := make(chan *flowpb.Flow)
	input := AggregationInput{
		RecordChan:            recordChan,
		WorkerNum:             2,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	clock := clocktesting.NewFakeClock(time.Now())
	ap, _ := initAggregationProcessWithClock(input, clock)
	return ap
}

func TestIsSourceNodeFromExternalFlow(t *testing.T) {
	sourceNodeFlow, _ := generateSourceNodeFlowAndFlowKey()
	destinationNodeFlow, _ := generateDestinationNodeFlowAndFlowKey()
	testCases := []struct {
		name     string
		flow     *flowpb.Flow
		expected bool
	}{
		{
			"k8s nil flow",
			&flowpb.Flow{},
			false,
		},
		{
			"FROM_EXTERNAL with destination pod (single-node, not source-node)",
			&flowpb.Flow{
				K8S: &flowpb.Kubernetes{
					FlowType:                flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL,
					DestinationPodName:      "pod",
					DestinationPodNamespace: "ns",
				},
			},
			false,
		},
		{
			"TO_EXTERNAL flow",
			&flowpb.Flow{
				K8S: &flowpb.Kubernetes{
					FlowType: flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL,
				},
			},
			false,
		},
		{
			"destination-node INTER_NODE flow",
			destinationNodeFlow,
			false,
		},
		{
			"source-node FROM_EXTERNAL flow",
			sourceNodeFlow,
			true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.expected {
				assert.True(t, isSourceNodeFromExternalFlow(tc.flow))
			} else {
				assert.False(t, isSourceNodeFromExternalFlow(tc.flow))
			}
		})
	}
}

func TestIsDestinationNodeFromExternalFlow(t *testing.T) {
	sourceNodeFlow, _ := generateSourceNodeFlowAndFlowKey()
	destinationNodeFlow, _ := generateDestinationNodeFlowAndFlowKey()
	testCases := []struct {
		name     string
		flow     *flowpb.Flow
		expected bool
	}{
		{
			"k8s nil flow",
			&flowpb.Flow{},
			false,
		},
		{
			"FROM_EXTERNAL source-node flow",
			sourceNodeFlow,
			false,
		},
		{
			"INTER_NODE with SourcePodName set (regular inter-node)",
			&flowpb.Flow{
				K8S: &flowpb.Kubernetes{
					FlowType:           flowpb.FlowType_FLOW_TYPE_INTER_NODE,
					SourcePodName:      "source-pod",
					DestinationPodName: "dst-pod",
				},
			},
			false,
		},
		{
			"INTER_NODE with ProxySnatIp set",
			&flowpb.Flow{
				K8S: &flowpb.Kubernetes{
					FlowType:           flowpb.FlowType_FLOW_TYPE_INTER_NODE,
					DestinationPodName: "pod",
				},
				ProxySnatIp: gatewayIP,
			},
			false,
		},
		{
			"destination-node INTER_NODE flow (from srcIsGw branch)",
			destinationNodeFlow,
			true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.expected {
				assert.True(t, isDestinationNodeFromExternalFlow(tc.flow))
			} else {
				assert.False(t, isDestinationNodeFromExternalFlow(tc.flow))
			}
		})
	}
}

func contains(a *fromExternalAggregator, key string) bool {
	a.lock.Lock()
	defer a.lock.Unlock()
	_, exists := a.fromExternalStore[key]
	return exists
}

func TestCorrelateOrStore_SourceNodeFlow(t *testing.T) {
	t.Run("stores source-node flow and returns nil", func(t *testing.T) {
		a := newFromExternalAggregator()
		sourceNodeFlow, sourceNodeFlowKey := generateSourceNodeFlowAndFlowKey()
		gotFlowKey, gotRecord := a.correlateOrStore(sourceNodeFlowKey, sourceNodeFlow)
		assert.Nil(t, gotFlowKey, "Expected nil flowKey: source-node flow should be stored")
		assert.Nil(t, gotRecord, "Expected nil record: source-node flow should be stored")

		key := generateFromExternalStoreKey(sourceNodeFlow)
		assert.True(t, contains(a, key), "Expected source-node flow to be stored in fromExternalStore")
	})
	t.Run("stored flow can be popped by cross-key", func(t *testing.T) {
		a := newFromExternalAggregator()
		sourceNodeFlow, sourceNodeFlowKey := generateSourceNodeFlowAndFlowKey()
		a.correlateOrStore(sourceNodeFlowKey, sourceNodeFlow)

		key := generateFromExternalStoreKey(sourceNodeFlow)
		popped := a.popSourceNodeFlow(key)
		assert.Equal(t, sourceNodeFlow, popped, "Expected popSourceNodeFlow to return the stored flow")
		assert.False(t, contains(a, key), "Expected store to be empty after pop")
	})
}

func TestExpiresStaleFlows(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := newFromExternalAggregator()
		stopCh := make(chan struct{})
		t.Cleanup(func() { close(stopCh) })
		go a.Run(stopCh)

		sourceNodeFlow, sourceNodeFlowKey := generateSourceNodeFlowAndFlowKey()
		a.correlateOrStore(sourceNodeFlowKey, sourceNodeFlow)

		key := generateFromExternalStoreKey(sourceNodeFlow)
		assert.True(t, contains(a, key), "expected entry before expiry")

		time.Sleep(defaultTTL + 2*defaultCleanUpInterval)
		synctest.Wait()

		assert.False(t, contains(a, key), "expected flow to have been cleaned up")
	})
}

// TestCorrelateOrStore verifies the correlateOrStore contract at the fromExternalAggregator
// level. End-to-end correlation (including the cross-key merge in flowKeyRecordMap) is tested
// in TestCorrelateRecordsForFromExternalFlow in aggregate_test.go.
func TestCorrelateOrStore(t *testing.T) {
	t.Run("single-node FROM_EXTERNAL passes through unchanged", func(t *testing.T) {
		a := newFromExternalAggregator()
		singleNodeRecord := &flowpb.Flow{
			K8S: &flowpb.Kubernetes{
				FlowType:                flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL,
				DestinationPodName:      "nginx",
				DestinationPodNamespace: "default",
			},
			Ip:        sourceNodeIP,
			Transport: &flowpb.Transport{ProtocolNumber: 6, SourcePort: 12345, DestinationPort: 80},
			StartTs:   timestamppb.New(currTime),
			EndTs:     timestamppb.New(currTime.Add(time.Minute)),
		}
		flowKey, _ := getFlowKeyFromRecord(singleNodeRecord)
		originalFlowKey := *flowKey
		gotFlowKey, gotRecord := a.correlateOrStore(flowKey, singleNodeRecord)
		require.NotNil(t, gotFlowKey)
		assert.Equal(t, originalFlowKey, *gotFlowKey)
		assert.Same(t, singleNodeRecord, gotRecord)
		assert.Empty(t, a.fromExternalStore, "single-node flow must not be stored")
	})
	t.Run("destination-node INTER_NODE passes through unchanged, nothing stored", func(t *testing.T) {
		a := newFromExternalAggregator()
		destinationNodeRecord, destinationNodeFlowKey := generateDestinationNodeFlowAndFlowKey()
		originalFlowKey := *destinationNodeFlowKey
		gotFlowKey, gotRecord := a.correlateOrStore(destinationNodeFlowKey, destinationNodeRecord)
		require.NotNil(t, gotFlowKey)
		assert.Equal(t, originalFlowKey, *gotFlowKey)
		assert.Same(t, destinationNodeRecord, gotRecord)
		assert.Empty(t, a.fromExternalStore, "destination-node flow must not be stored here")
	})
	t.Run("regular INTER_NODE destination flow passes through unchanged, nothing stored", func(t *testing.T) {
		a := newFromExternalAggregator()
		regularInterNodeDst := &flowpb.Flow{
			K8S: &flowpb.Kubernetes{
				FlowType:                flowpb.FlowType_FLOW_TYPE_INTER_NODE,
				DestinationPodName:      "dst-pod",
				DestinationPodNamespace: "default",
			},
			Ip:        &flowpb.IP{Source: []byte{10, 244, 1, 5}, Destination: podIP},
			Transport: &flowpb.Transport{ProtocolNumber: 6, SourcePort: 40000, DestinationPort: 80},
			StartTs:   timestamppb.New(currTime),
			EndTs:     timestamppb.New(currTime.Add(time.Minute)),
		}
		flowKey, _ := getFlowKeyFromRecord(regularInterNodeDst)
		originalFlowKey := *flowKey
		gotFlowKey, gotRecord := a.correlateOrStore(flowKey, regularInterNodeDst)
		require.NotNil(t, gotFlowKey)
		assert.Equal(t, originalFlowKey, *gotFlowKey)
		assert.Same(t, regularInterNodeDst, gotRecord)
		assert.Empty(t, a.fromExternalStore)
	})
	t.Run("FROM_EXTERNAL source-node flow stored; returns nil to signal cross-key merge", func(t *testing.T) {
		a := newFromExternalAggregator()
		sourceNodeRecord, sourceNodeFlowKey := generateSourceNodeFlowAndFlowKey()
		gotFlowKey, gotRecord := a.correlateOrStore(sourceNodeFlowKey, sourceNodeRecord)
		assert.Nil(t, gotFlowKey, "Expected nil: source-node flow stored, addOrUpdateRecordInMap will merge")
		assert.Nil(t, gotRecord)
		key := generateFromExternalStoreKey(sourceNodeRecord)
		assert.True(t, contains(a, key), "Expected source-node flow in fromExternalStore")
	})
}
