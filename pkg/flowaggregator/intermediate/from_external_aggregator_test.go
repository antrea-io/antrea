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
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	flowpb "antrea.io/antrea/pkg/apis/flow/v1alpha1"
	"antrea.io/antrea/pkg/flowaggregator/flowrecord"
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

var mockIndexerA = &mockIndexer{ // todo - fold into newAggregationProcess?
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

// TestCorrelateRecordsForFromExternalFlow validates flows received by the FlowAggregator
// are correctly correlated as they come from the source node and destination node
func TestCorrelateRecordsForFromExternalFlow(t *testing.T) {
	t.Run("correlation not required", func(t *testing.T) {
		ap := newAggregationProcess()

		// Build a correlated record
		destinationNodeRecord, _ := generateDestinationNodeFlowAndFlowKey()
		destinationNodeRecord.Ip = sourceNodeIP
		flowKey, _ := getFlowKeyFromRecord(destinationNodeRecord)

		ap.addOrUpdateRecordInMap(flowKey, destinationNodeRecord, false)
		got := ap.expirePriorityQueue.Peek().flowKey
		assert.Equal(t, flowKey, got, "Expected previously correlated flow to be added to queue")
	})
	t.Run("source node flow arrives first", func(t *testing.T) {
		ap := newAggregationProcess()

		// Add the sourceNodeFlow
		sourceNodeRecord, sourceNodeRecordFlowKey := generateSourceNodeFlowAndFlowKey()
		ap.addOrUpdateRecordInMap(sourceNodeRecordFlowKey, sourceNodeRecord, false)
		key := ap.fromExternalAggregator.generateFromExternalStoreKey(sourceNodeRecord)
		_, exists := ap.fromExternalAggregator.FromExternalStore[key]
		assert.True(t, exists, "Expected flow to have been stored")

		// Add the destinationNodeFlow
		destinationNodeRecord, destinationNodeRecordFlowKey := generateDestinationNodeFlowAndFlowKey()
		ap.addOrUpdateRecordInMap(destinationNodeRecordFlowKey, destinationNodeRecord, false)

		flowKey := destinationNodeRecordFlowKey
		flowKey.SourceAddress = flowrecord.IpAddressAsString(sourceNodeRecord.Ip.Source)
		assert.Equal(t, 1, ap.expirePriorityQueue.Len(), "Expected flow to be correlated and added to queue")
		item := ap.expirePriorityQueue.Peek()
		got := item.flowKey
		assert.Equal(t, flowKey, got, "Expected flow to be correlated and added to queue")

		record, exists := ap.flowKeyRecordMap[*flowKey]
		assert.True(t, exists, "Expected correlated flow to be added to flowKeyRecordMap")
		assert.True(t, item.flowRecord.ReadyToSend, "Expected correlated flow to be marked ready to send for export")
		correlatedFlow := record.Record
		assert.NotNil(t, correlatedFlow, "Expected stored flow to not be nil")
		assert.Equal(t, externalIP, correlatedFlow.Ip.Source, "Expected correlated flow to have original source IP")
		assert.Equal(t, nodeIP, correlatedFlow.K8S.DestinationServiceIp, "Expected correlated flow to have node IP")
		assert.Equal(t, nodeIP, correlatedFlow.K8S.DestinationClusterIp, "Expected correlated flow to have node IP")
		assert.Equal(t, containerPort, correlatedFlow.K8S.DestinationServicePort, "Expected correlated flow to have the container port")
		assert.Equal(t, destinationServicePortName, correlatedFlow.K8S.DestinationServicePortName, "Expected correlated flow to have DestinationServicePortName")

		// Ensure cleanup
		flow := ap.fromExternalAggregator.CorrelateExternal(destinationNodeRecord)
		assert.Nil(t, flow, "Expected flow to have been cleared from store")
	})
	t.Run("destination node flow arrives first", func(t *testing.T) {
		ap := newAggregationProcess()

		// Add the destinationNodeFlow
		destinationNodeRecord, destinationNodeRecordFlowKey := generateDestinationNodeFlowAndFlowKey()
		ap.addOrUpdateRecordInMap(destinationNodeRecordFlowKey, destinationNodeRecord, false)
		key := ap.fromExternalAggregator.generateFromExternalStoreKey(destinationNodeRecord)
		_, exists := ap.fromExternalAggregator.FromExternalStore[key]
		assert.True(t, exists, "Expected flow to have been stored")

		// Add the sourceNodeFlow
		sourceNodeRecord, sourceNodeRecordFlowKey := generateSourceNodeFlowAndFlowKey()
		ap.addOrUpdateRecordInMap(sourceNodeRecordFlowKey, sourceNodeRecord, false)

		flowKey := destinationNodeRecordFlowKey
		flowKey.SourceAddress = flowrecord.IpAddressAsString(sourceNodeRecord.Ip.Source)
		assert.Equal(t, 1, ap.expirePriorityQueue.Len(), "Expected flow to be correlated and added to queue")
		item := ap.expirePriorityQueue.Peek()
		got := item.flowKey
		assert.Equal(t, flowKey, got, "Expected flow to be correlated and added to queue")

		record, exists := ap.flowKeyRecordMap[*flowKey]
		assert.True(t, exists, "Expected correlated flow to be added to flowKeyRecordMap")
		assert.True(t, item.flowRecord.ReadyToSend, "Expected correlated flow to be marked ready to send for export")

		correlatedFlow := record.Record
		assert.NotNil(t, correlatedFlow, "Expected stored flow to not be nil")
		assert.Equal(t, externalIP, correlatedFlow.Ip.Source, "Expected correlated flow to have original source IP")
		assert.Equal(t, nodeIP, correlatedFlow.K8S.DestinationServiceIp, "Expected correlated flow to have node IP")
		assert.Equal(t, nodeIP, correlatedFlow.K8S.DestinationClusterIp, "Expected correlated flow to have node IP")
		assert.Equal(t, containerPort, correlatedFlow.K8S.DestinationServicePort, "Expected correlated flow to have the container port")
		assert.Equal(t, destinationServicePortName, correlatedFlow.K8S.DestinationServicePortName, "Expected correlated flow to have DestinationServicePortName")

		// Ensure cleanup
		flow := ap.fromExternalAggregator.CorrelateExternal(sourceNodeRecord)
		assert.Nil(t, flow, "Expected flow to have been cleared from store")
	})
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
			ap := newAggregationProcess()
			ap.fromExternalAggregator.nodeIndexer = tc.setupIndexer()
			if tc.want {
				assert.True(t, ap.fromExternalAggregator.isGateway(tc.ip))
			} else {
				assert.False(t, ap.fromExternalAggregator.isGateway(tc.ip))
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
			ap := newAggregationProcess()
			if tc.expected {
				assert.True(t, ap.fromExternalAggregator.FromExternalCorrelationRequired(tc.flow))
			} else {
				assert.False(t, ap.fromExternalAggregator.FromExternalCorrelationRequired(tc.flow))
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
		ap := newAggregationProcess()
		sourceNodeFlow, _ := generateSourceNodeFlowAndFlowKey()
		exists := ap.fromExternalAggregator.StoreIfNew(sourceNodeFlow)
		assert.True(t, exists, "Expected not to find flow in an empty store")

		key := ap.fromExternalAggregator.generateFromExternalStoreKey(sourceNodeFlow)
		assert.True(t, contains(ap.fromExternalAggregator, key), "Expected flow to have been stored")
	})
	t.Run("flow is in store", func(t *testing.T) {
		ap := newAggregationProcess()
		sourceNodeFlow, _ := generateSourceNodeFlowAndFlowKey()
		destinationNodeFlow, _ := generateDestinationNodeFlowAndFlowKey()
		ap.fromExternalAggregator.StoreIfNew(sourceNodeFlow)
		exists := ap.fromExternalAggregator.StoreIfNew(destinationNodeFlow)
		assert.False(t, exists, "Expected other half of flow to have been stored")
	})
}

func TestExpiresStaleFlows(t *testing.T) {
	ap := newAggregationProcess()
	sourceNodeFlow, _ := generateSourceNodeFlowAndFlowKey()
	exists := ap.fromExternalAggregator.StoreIfNew(sourceNodeFlow)
	assert.True(t, exists, "Expected not to find flow in an empty store")
	time.Sleep(10 * time.Second) //todo make ttl configurable on newAggregationProcess

	key := ap.fromExternalAggregator.generateFromExternalStoreKey(sourceNodeFlow)
	assert.False(t, contains(ap.fromExternalAggregator, key), "Expected flow to have been cleaned up")
}

func TestStopIsThreadSafe(t *testing.T) {
	ap := newAggregationProcess()

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ap.fromExternalAggregator.stop()
		}()
	}
	wg.Wait()

	select {
	case <-ap.fromExternalAggregator.stopCh:
	default:
		t.Fatal("Expected stopCh to be closed, but it was still open")
	}
}
