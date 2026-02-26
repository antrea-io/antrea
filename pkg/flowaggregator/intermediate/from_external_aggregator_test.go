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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	flowpb "antrea.io/antrea/pkg/apis/flow/v1alpha1"
)

type mockIndexer struct {
	cache.Indexer
	mockByIndex func(indexName, indexedValue string) ([]interface{}, error)
}

func (m *mockIndexer) ByIndex(indexName, indexedValue string) ([]interface{}, error) {
	if m.mockByIndex != nil {
		return m.mockByIndex(indexName, indexedValue)
	}
	return nil, nil
}

func TestCorrelateRecordsForToExternalFlow(t *testing.T) {
	recordChan := make(chan *flowpb.Flow)
	input := AggregationInput{
		RecordChan:            recordChan,
		WorkerNum:             2,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	clock := clocktesting.NewFakeClock(time.Now())
	ap, _ := initAggregationProcessWithClock(input, clock, nil)
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

var currTime = time.Now()
var externalIP = []byte{0xac, 0x12, 0x00, 0x01} // 172.12.18.01
var podIP = []byte{0x0e, 0xec, 0x01, 0x03}      // 10.244.1.3
var gatewayIP = []byte{0x0a, 0xf4, 0x02, 0x01}  // 10.244.2.1
var nodeIP = []byte{0xac, 0x12, 0x00, 0x02}     // 172.12.18.02
var containerPort = uint32(82)
var sourceNodeIP = &flowpb.IP{
	Source:      externalIP,
	Destination: podIP,
}
var destinationServicePortName = "namespace/service-name:serviceportname"

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

func generateDestinationNodeFlowAndFlowKey() (*flowpb.Flow, *FlowKey) {
	destinationNodeRecord := &flowpb.Flow{
		K8S: &flowpb.Kubernetes{
			DestinationPodName:      "nginx-deployment-HASH",
			DestinationPodNamespace: "some-namespace",
			FlowType:                flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL,
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
		Stats:         &flowpb.Stats{},
		ReverseStats:  &flowpb.Stats{},
		StartTs:       timestamppb.New(currTime),
		EndTs:         timestamppb.New(currTime.Add(2 * time.Minute)),
		ProxySnatIp:   gatewayIP,
		ProxySnatPort: uint32(52391),
	}
	destinationNodeFlowKey, _ := getFlowKeyFromRecord(destinationNodeRecord)
	return destinationNodeRecord, destinationNodeFlowKey
}

var mockIndexerA = &mockIndexer{
	mockByIndex: func(indexName, indexedValue string) ([]interface{}, error) {
		if indexedValue == "10.244.2.1" {
			return []interface{}{"found"}, nil
		}
		return []interface{}{}, nil
	},
}

func newAggregationProcess() *aggregationProcess { // todo - can delete maybe?
	recordChan := make(chan *flowpb.Flow)
	input := AggregationInput{
		RecordChan:            recordChan,
		WorkerNum:             2,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	clock := clocktesting.NewFakeClock(time.Now())
	ap, _ := initAggregationProcessWithClock(input, clock, mockIndexerA)
	return ap
}

func TestIsGateway(t *testing.T) {
	testCases := []struct {
		name         string
		ip           []byte
		setupIndexer func() cache.Indexer
		want         bool
	}{
		{
			name: "Invalid IP",
			ip:   []byte{},
			setupIndexer: func() cache.Indexer {
				return &mockIndexer{}
			},
			want: false,
		},
		{
			name: "nodeIndexer errors",
			ip:   podIP,
			setupIndexer: func() cache.Indexer {
				return &mockIndexer{
					mockByIndex: func(indexName, indexedValue string) ([]interface{}, error) {
						return nil, fmt.Errorf("error")
					},
				}
			},
			want: false,
		},
		{
			name: "nodeIndexer returns no matches",
			ip:   podIP,
			setupIndexer: func() cache.Indexer {
				return &mockIndexer{
					mockByIndex: func(indexName, indexedValue string) ([]interface{}, error) {
						return []interface{}{}, nil
					},
				}
			},
			want: false,
		},
		{
			name: "Valid Gateway",
			ip:   gatewayIP,
			setupIndexer: func() cache.Indexer {
				return &mockIndexer{
					mockByIndex: func(indexName, indexedValue string) ([]interface{}, error) {
						return []interface{}{""}, nil
					},
				}
			},
			want: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := newFromExternalAggregator(tc.setupIndexer())
			if tc.want {
				assert.True(t, a.isGateway(tc.ip))
			} else {
				assert.False(t, a.isGateway(tc.ip))
			}
		})
	}
}

func TestFromExternalCorrelationRequired(t *testing.T) {
	destinationNodeFlow, _ := generateDestinationNodeFlowAndFlowKey()
	sourceNodeFlow, _ := generateSourceNodeFlowAndFlowKey()
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
			"nil IP",
			&flowpb.Flow{
				K8S: &flowpb.Kubernetes{
					FlowType: flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL,
				},
			},
			false,
		},
		{
			"non FromExternal flow",
			&flowpb.Flow{
				K8S: &flowpb.Kubernetes{
					FlowType: flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL,
				},
			},
			false,
		},
		{
			"destinationNode flow",
			destinationNodeFlow,
			true,
		},
		{
			"sourceNode flow",
			sourceNodeFlow,
			true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := newFromExternalAggregator(mockIndexerA)
			if tc.expected {
				assert.True(t, a.FromExternalCorrelationRequired(tc.flow))
			} else {
				assert.False(t, a.FromExternalCorrelationRequired(tc.flow))
			}
		})
	}
}

func contains(a *fromExternalAggregator, key string) bool {
	a.lock.Lock()
	defer a.lock.Unlock()
	_, exists := a.FromExternalStore[key]
	return exists
}

func TestStoreIfNew(t *testing.T) {
	t.Run("storing first flow", func(t *testing.T) {
		a := newFromExternalAggregator(mockIndexerA)
		sourceNodeFlow, _ := generateSourceNodeFlowAndFlowKey()
		exists := a.StoreIfNew(sourceNodeFlow)
		assert.True(t, exists, "Expected not to find flow in an empty store")

		key := a.generateFromExternalStoreKey(sourceNodeFlow)
		assert.True(t, contains(a, key), "Expected flow to have been stored")
	})
	t.Run("flow is in store", func(t *testing.T) {
		a := newFromExternalAggregator(mockIndexerA)
		sourceNodeFlow, _ := generateSourceNodeFlowAndFlowKey()
		destinationNodeFlow, _ := generateDestinationNodeFlowAndFlowKey()
		a.StoreIfNew(sourceNodeFlow)
		exists := a.StoreIfNew(destinationNodeFlow)
		assert.False(t, exists, "Expected other half of flow to have been stored")
	})
}

// withTTL overrides the default flow expiration TTL.
func withTTL(ttl time.Duration) option {
	return func(a *fromExternalAggregator) {
		a.ttl = ttl
	}
}

// withCleanupInterval overrides the default background loop interval.
func withCleanupInterval(interval time.Duration) option {
	return func(a *fromExternalAggregator) {
		a.cleanUpInterval = interval
	}
}

func TestExpiresStaleFlows(t *testing.T) {
	a := newFromExternalAggregator(mockIndexerA, withTTL(time.Millisecond), withCleanupInterval(time.Millisecond))
	sourceNodeFlow, _ := generateSourceNodeFlowAndFlowKey()
	exists := a.StoreIfNew(sourceNodeFlow)
	assert.True(t, exists, "Expected not to find flow in an empty store")
	time.Sleep(3 * time.Millisecond)

	key := a.generateFromExternalStoreKey(sourceNodeFlow)
	assert.False(t, contains(a, key), "Expected flow to have been cleaned up")
}

func TestStopIsThreadSafe(t *testing.T) {
	a := newFromExternalAggregator(mockIndexerA)

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.stop()
		}()
	}
	wg.Wait()

	select {
	case <-a.stopCh:
	default:
		t.Fatal("Expected stopCh to be closed, but it was still open")
	}
}

// correlatedFieldSnapshot collects the set of fields that are modified during correlation.
type correlatedFieldSnapshot struct {
	DestinationServiceIp       []byte
	DestinationServicePortName string
	DestinationServicePort     uint32
	DestinationClusterIp       []byte
}

// captureCorrelatedFields return a snapshot of fields relevant for correlation in lieu of a full copy
// of Flow which includes a mutex.
func captureCorrelatedFields(flow *flowpb.Flow) correlatedFieldSnapshot {
	// Protect against nil panics if the test passes an empty flow
	if flow == nil || flow.K8S == nil {
		return correlatedFieldSnapshot{}
	}

	return correlatedFieldSnapshot{
		DestinationServiceIp:       flow.K8S.DestinationServiceIp,
		DestinationServicePortName: flow.K8S.DestinationServicePortName,
		DestinationServicePort:     flow.K8S.DestinationServicePort,
		DestinationClusterIp:       flow.K8S.DestinationClusterIp,
	}
}

func TestCorrelateOrStore(t *testing.T) {
	t.Run("correlation not required", func(t *testing.T) {
		a := newFromExternalAggregator(mockIndexerA)

		// Build a correlated record
		destinationNodeRecord, _ := generateDestinationNodeFlowAndFlowKey()
		destinationNodeRecord.Ip = sourceNodeIP
		flowKey, _ := getFlowKeyFromRecord(destinationNodeRecord)

		originalFlowKey := *flowKey
		recordSnapshot := captureCorrelatedFields(destinationNodeRecord)
		gotFlowKey, gotRecord := a.correlateOrStore(flowKey, destinationNodeRecord)
		assert.Equal(t, originalFlowKey, *gotFlowKey, "Expected flowKey for a correlated record to remain unchanged")
		assert.Equal(t, recordSnapshot, captureCorrelatedFields(gotRecord), "Expected a correlated record to remain unchanged")
	})
	t.Run("correlation is required", func(t *testing.T) {
		t.Run("source node flow arrives first", func(t *testing.T) {
			a := newFromExternalAggregator(mockIndexerA)

			// Add the sourceNodeFlow
			sourceNodeRecord, sourceNodeRecordFlowKey := generateSourceNodeFlowAndFlowKey()
			gotFlowKey, gotRecord := a.correlateOrStore(sourceNodeRecordFlowKey, sourceNodeRecord)
			assert.Nil(t, gotFlowKey, "Expected nil when flows are stored")
			assert.Nil(t, gotRecord, "Expected nil when flows are stored")
			key := a.generateFromExternalStoreKey(sourceNodeRecord)
			assert.True(t, contains(a, key), "Expected flow to have been stored")

			// Add the destinationNodeFlow
			destinationNodeRecord, destinationNodeRecordFlowKey := generateDestinationNodeFlowAndFlowKey()
			_, gotRecord = a.correlateOrStore(destinationNodeRecordFlowKey, destinationNodeRecord)

			require.NotNil(t, gotRecord, "Expected flow to be correlated")
			require.NotNil(t, gotRecord.Ip, "Expected correlated flow's IP not to be nil")
			assert.Equal(t, externalIP, gotRecord.Ip.Source, "Expected correlated flow to have original source IP")
			require.NotNil(t, gotRecord.K8S, "Expected correlated flow's K8S data not to be nil")
			assert.Equal(t, nodeIP, gotRecord.K8S.DestinationServiceIp, "Expected correlated flow to have node IP")
			assert.Equal(t, nodeIP, gotRecord.K8S.DestinationClusterIp, "Expected correlated flow to have node IP")
			assert.Equal(t, containerPort, gotRecord.K8S.DestinationServicePort, "Expected correlated flow to have the container port")
			assert.Equal(t, destinationServicePortName, gotRecord.K8S.DestinationServicePortName, "Expected correlated flow to have DestinationServicePortName")

			assert.False(t, contains(a, key), "Expected stored flow to be removed")
		})
		t.Run("destination node flow arrives first", func(t *testing.T) {
			a := newFromExternalAggregator(mockIndexerA)

			// Add the destinationNodeFlow
			destinationNodeRecord, destinationNodeRecordFlowKey := generateDestinationNodeFlowAndFlowKey()
			gotFlowKey, gotRecord := a.correlateOrStore(destinationNodeRecordFlowKey, destinationNodeRecord)
			assert.Nil(t, gotFlowKey, "Expected nil when flows are stored")
			assert.Nil(t, gotRecord, "Expected nil when flows are stored")

			// Add the sourceNodeFlow
			sourceNodeRecord, sourceNodeRecordFlowKey := generateSourceNodeFlowAndFlowKey()
			_, gotRecord = a.correlateOrStore(sourceNodeRecordFlowKey, sourceNodeRecord)

			require.NotNil(t, gotRecord, "Expected flow to be correlated")
			require.NotNil(t, gotRecord.Ip, "Expected correlated flow's IP not to be nil")
			assert.Equal(t, externalIP, gotRecord.Ip.Source, "Expected correlated flow to have original source IP")
			require.NotNil(t, gotRecord.K8S, "Expected correlated flow's K8S data not to be nil")
			assert.Equal(t, nodeIP, gotRecord.K8S.DestinationServiceIp, "Expected correlated flow to have node IP")
			assert.Equal(t, nodeIP, gotRecord.K8S.DestinationClusterIp, "Expected correlated flow to have node IP")
			assert.Equal(t, containerPort, gotRecord.K8S.DestinationServicePort, "Expected correlated flow to have the container port")
			assert.Equal(t, destinationServicePortName, gotRecord.K8S.DestinationServicePortName, "Expected correlated flow to have DestinationServicePortName")

			key := a.generateFromExternalStoreKey(destinationNodeRecord)
			assert.False(t, contains(a, key), "Expected stored to have been removed")
		})
	})
}
