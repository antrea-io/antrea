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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	clocktesting "k8s.io/utils/clock/testing"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	"antrea.io/antrea/v2/pkg/flowaggregator/flowrecord"
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

// Shared test fixtures for from-external flow tests.
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
		Stats:         &flowpb.Stats{},
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
		{"k8s nil flow", &flowpb.Flow{}, false},
		{
			"FROM_EXTERNAL with destination pod (single-node, not source-node)",
			&flowpb.Flow{
				K8S: &flowpb.Kubernetes{
					FlowType: flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL, DestinationPodName: "pod", DestinationPodNamespace: "ns",
				},
			},
			false,
		},
		{
			"TO_EXTERNAL flow",
			&flowpb.Flow{K8S: &flowpb.Kubernetes{FlowType: flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL}},
			false,
		},
		{"destination-node INTER_NODE flow", destinationNodeFlow, false},
		{"source-node FROM_EXTERNAL flow", sourceNodeFlow, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, isSourceNodeFromExternalFlow(tc.flow))
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
		{"k8s nil flow", &flowpb.Flow{}, false},
		{"FROM_EXTERNAL source-node flow", sourceNodeFlow, false},
		{
			"INTER_NODE with SourcePodName set (regular inter-node)",
			&flowpb.Flow{
				K8S: &flowpb.Kubernetes{FlowType: flowpb.FlowType_FLOW_TYPE_INTER_NODE, SourcePodName: "source-pod", DestinationPodName: "dst-pod"},
			},
			false,
		},
		{
			"INTER_NODE with ProxySnatIp set",
			&flowpb.Flow{
				K8S:         &flowpb.Kubernetes{FlowType: flowpb.FlowType_FLOW_TYPE_INTER_NODE, DestinationPodName: "pod"},
				ProxySnatIp: gatewayIP,
			},
			false,
		},
		{"destination-node INTER_NODE flow (from srcIsGw branch)", destinationNodeFlow, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, isDestinationNodeFromExternalFlow(tc.flow))
		})
	}
}

func TestGetExternalCorrelationFlowKey(t *testing.T) {
	sourceNodeFlow, _ := generateSourceNodeFlowAndFlowKey()
	_, destFlowKey := generateDestinationNodeFlowAndFlowKey()
	correlationKey := getExternalCorrelationFlowKey(sourceNodeFlow)
	assert.Equal(t, destFlowKey, correlationKey, "Correlation key for source-node flow should match destination-node FlowKey")
}

func TestAddOrUpdateRecordInMap_FromExternalMerge(t *testing.T) {
	t.Run("source node arrives first, then destination node", func(t *testing.T) {
		ap := newAggregationProcess()

		sourceNodeRecord, sourceNodeFlowKey := generateSourceNodeFlowAndFlowKey()
		ap.addOrUpdateRecordInMap(sourceNodeFlowKey, sourceNodeRecord, false)
		// Source-node stored under correlation key; 1 entry in map.
		assert.Equal(t, 1, len(ap.flowKeyRecordMap))

		destinationNodeRecord, destNodeFlowKey := generateDestinationNodeFlowAndFlowKey()
		ap.addOrUpdateRecordInMap(destNodeFlowKey, destinationNodeRecord, false)
		// After merge: the entry is re-keyed to (externalIP, clientPort, ...).
		assert.Equal(t, 1, len(ap.flowKeyRecordMap), "Should still have 1 entry after merge")

		finalKey := &FlowKey{
			SourceAddress:      flowrecord.IpAddressAsString(externalIP),
			DestinationAddress: flowrecord.IpAddressAsString(podIP),
			Protocol:           6,
			SourcePort:         uint16(sourceNodeRecord.Transport.SourcePort),
			DestinationPort:    80,
		}
		record, exists := ap.flowKeyRecordMap[*finalKey]
		require.True(t, exists, "Expected merged record under final FlowKey (externalIP, clientPort, ...)")
		assert.True(t, record.ReadyToSend, "Merged record should be ReadyToSend")
		assert.Equal(t, flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL, record.Record.K8S.FlowType)
		assert.Equal(t, externalIP, record.Record.Ip.Source)
		assert.Equal(t, sourceNodeRecord.Transport.SourcePort, record.Record.Transport.SourcePort)
		assert.Equal(t, nodeIP, record.Record.K8S.DestinationServiceIp)
		assert.Equal(t, destinationServicePortName, record.Record.K8S.DestinationServicePortName)
	})

	t.Run("destination node arrives first, then source node", func(t *testing.T) {
		ap := newAggregationProcess()

		destinationNodeRecord, destNodeFlowKey := generateDestinationNodeFlowAndFlowKey()
		ap.addOrUpdateRecordInMap(destNodeFlowKey, destinationNodeRecord, false)
		assert.Equal(t, 1, len(ap.flowKeyRecordMap))

		sourceNodeRecord, sourceNodeFlowKey := generateSourceNodeFlowAndFlowKey()
		ap.addOrUpdateRecordInMap(sourceNodeFlowKey, sourceNodeRecord, false)
		assert.Equal(t, 1, len(ap.flowKeyRecordMap), "Should still have 1 entry after merge")

		finalKey := &FlowKey{
			SourceAddress:      flowrecord.IpAddressAsString(externalIP),
			DestinationAddress: flowrecord.IpAddressAsString(podIP),
			Protocol:           6,
			SourcePort:         uint16(sourceNodeRecord.Transport.SourcePort),
			DestinationPort:    80,
		}
		record, exists := ap.flowKeyRecordMap[*finalKey]
		require.True(t, exists, "Expected merged record under final FlowKey (externalIP, clientPort, ...)")
		assert.True(t, record.ReadyToSend, "Merged record should be ReadyToSend")
		assert.Equal(t, flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL, record.Record.K8S.FlowType)
		assert.Equal(t, externalIP, record.Record.Ip.Source)
		assert.Equal(t, nodeIP, record.Record.K8S.DestinationServiceIp)
		assert.Equal(t, destinationServicePortName, record.Record.K8S.DestinationServicePortName)
	})

	t.Run("single-node FROM_EXTERNAL (no merge needed)", func(t *testing.T) {
		ap := newAggregationProcess()
		singleNodeRecord := &flowpb.Flow{
			K8S: &flowpb.Kubernetes{
				FlowType:                flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL,
				DestinationPodName:      "nginx",
				DestinationPodNamespace: "default",
			},
			Ip:           sourceNodeIP,
			Transport:    &flowpb.Transport{ProtocolNumber: 6, SourcePort: 12345, DestinationPort: 80},
			Stats:        &flowpb.Stats{},
			ReverseStats: &flowpb.Stats{},
			StartTs:      timestamppb.New(currTime),
			EndTs:        timestamppb.New(currTime.Add(time.Minute)),
		}
		flowKey, isIPv4 := getFlowKeyFromRecord(singleNodeRecord)
		ap.addOrUpdateRecordInMap(flowKey, singleNodeRecord, isIPv4)
		assert.Equal(t, 1, len(ap.flowKeyRecordMap))
		record := ap.flowKeyRecordMap[*flowKey]
		assert.True(t, record.ReadyToSend, "Single-node FROM_EXTERNAL should be ReadyToSend immediately")
	})
}
