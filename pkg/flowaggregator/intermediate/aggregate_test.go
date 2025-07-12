// Copyright 2025 Antrea Authors
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
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	clocktesting "k8s.io/utils/clock/testing"

<<<<<<< HEAD
	flowpb "antrea.io/antrea/apis/pkg/apis/flow/v1alpha1"
=======
	flowpb "antrea.io/antrea/pkg/apis/flow/v1alpha1"
>>>>>>> origin/main
)

func init() {
	MaxRetries = 1
	MinExpiryTime = 0
}

const (
	testTemplateID     = uint16(256)
	testActiveExpiry   = 100 * time.Millisecond
	testInactiveExpiry = 150 * time.Millisecond
	testMaxRetries     = 2
)

func getEmptyFlowRecord() *flowpb.Flow {
	return &flowpb.Flow{
		Ipfix:        &flowpb.IPFIX{},
		StartTs:      &timestamppb.Timestamp{},
		EndTs:        &timestamppb.Timestamp{},
		Ip:           &flowpb.IP{},
		Transport:    &flowpb.Transport{},
		K8S:          &flowpb.Kubernetes{},
		Stats:        &flowpb.Stats{},
		ReverseStats: &flowpb.Stats{},
		App:          &flowpb.App{},
	}
}

func getBaseFlowRecord(isIPv6 bool, flowType flowpb.FlowType, isUpdatedRecord bool) *flowpb.Flow {
	record := getEmptyFlowRecord()
	record.Transport.SourcePort = 1234
	record.Transport.DestinationPort = 5678
	record.Transport.ProtocolNumber = 6
	record.K8S.SourcePodName = "pod1"
	record.K8S.DestinationPodName = "pod2"
	if isIPv6 {
		record.Ip.Version = flowpb.IPVersion_IP_VERSION_6
		record.Ip.Source = netip.MustParseAddr("2001:0:3238:DFE1:63::FEFB").AsSlice()
		record.Ip.Destination = netip.MustParseAddr("2001:0:3238:DFE1:63::FEFC").AsSlice()
	} else {
		record.Ip.Version = flowpb.IPVersion_IP_VERSION_4
		record.Ip.Source = netip.MustParseAddr("10.0.0.1").AsSlice()
		record.Ip.Destination = netip.MustParseAddr("10.0.0.2").AsSlice()
	}
	if !isUpdatedRecord {
		record.EndTs.Seconds = 1
		record.EndReason = flowpb.FlowEndReason_FLOW_END_REASON_ACTIVE_TIMEOUT
		record.Transport.Protocol = &flowpb.Transport_TCP{
			TCP: &flowpb.TCP{
				StateName: "ESTABLISHED",
			},
		}
		record.App.HttpVals = []byte("{\"0\":\"{hostname:10.10.0.1,url:/public/,http_user_agent:curl/7.74.0,http_content_type:text/html,http_method:GET,protocol:HTTP/1.1,status:200,length:153}\"}")
	} else {
		record.EndTs.Seconds = 10
		record.EndReason = flowpb.FlowEndReason_FLOW_END_REASON_END_OF_FLOW
		record.Transport.Protocol = &flowpb.Transport_TCP{
			TCP: &flowpb.TCP{
				StateName: "TIME_WAIT",
			},
		}
		record.App.HttpVals = []byte("{\"0\":\"{hostname:10.10.0.1,url:/public/,http_user_agent:curl/7.74.0,http_content_type:text/html,http_method:GET,protocol:HTTP/1.1,status:200,length:153}\"}")
	}
	record.K8S.FlowType = flowType
	return record
}

func createFlowRecordForSrc(isIPv6 bool, flowType flowpb.FlowType, isUpdatedRecord bool, egressNetworkPolicyRuleAction flowpb.NetworkPolicyRuleAction) *flowpb.Flow {
	record := getBaseFlowRecord(isIPv6, flowType, isUpdatedRecord)
	if flowType != flowpb.FlowType_FLOW_TYPE_INTRA_NODE {
		record.K8S.DestinationPodName = ""
	}
	record.K8S.DestinationServicePort = 4739
	if isIPv6 {
		record.K8S.DestinationClusterIp = netip.MustParseAddr("2001:0:3238:BBBB:63::AAAA").AsSlice()
	} else {
		record.K8S.DestinationClusterIp = netip.MustParseAddr("192.168.0.1").AsSlice()
	}
	record.K8S.EgressNetworkPolicyRuleAction = egressNetworkPolicyRuleAction
	if !isUpdatedRecord {
		record.Stats.PacketTotalCount = 500
		record.ReverseStats.PacketTotalCount = 500
		record.Stats.OctetTotalCount = 1000
		record.ReverseStats.OctetTotalCount = 1000
	} else {
		record.Stats.PacketTotalCount = 1000
		record.ReverseStats.PacketTotalCount = 1000
		record.Stats.PacketDeltaCount = 500
		record.ReverseStats.PacketDeltaCount = 500
		record.Stats.OctetTotalCount = 2000
		record.ReverseStats.OctetTotalCount = 2000
		record.Stats.OctetDeltaCount = 1000
		record.ReverseStats.OctetDeltaCount = 1000
	}

	return record
}

func createFlowRecordForDst(isIPv6 bool, flowType flowpb.FlowType, isUpdatedRecord bool, ingressNetworkPolicyRuleAction flowpb.NetworkPolicyRuleAction) *flowpb.Flow {
	record := getBaseFlowRecord(isIPv6, flowType, isUpdatedRecord)
	if flowType != flowpb.FlowType_FLOW_TYPE_INTRA_NODE {
		record.K8S.SourcePodName = ""
	}
	if flowType == flowpb.FlowType_FLOW_TYPE_INTRA_NODE {
		record.K8S.DestinationServicePort = 4739
		if isIPv6 {
			record.K8S.DestinationClusterIp = netip.MustParseAddr("2001:0:3238:BBBB:63::AAAA").AsSlice()
		} else {
			record.K8S.DestinationClusterIp = netip.MustParseAddr("192.168.0.1").AsSlice()
		}
	}
	record.K8S.IngressNetworkPolicyRuleAction = ingressNetworkPolicyRuleAction
	if !isUpdatedRecord {
		record.Stats.PacketTotalCount = 502
		record.ReverseStats.PacketTotalCount = 502
		record.Stats.OctetTotalCount = 1020
		record.ReverseStats.OctetTotalCount = 1020
	} else {
		record.Stats.PacketTotalCount = 1005
		record.ReverseStats.PacketTotalCount = 1005
		record.Stats.PacketDeltaCount = 503
		record.ReverseStats.PacketDeltaCount = 503
		record.Stats.OctetTotalCount = 2050
		record.ReverseStats.OctetTotalCount = 2050
		record.Stats.OctetDeltaCount = 1030
		record.ReverseStats.OctetDeltaCount = 1030
	}

	return record
}

func TestInitAggregationProcess(t *testing.T) {
	t.Run("no input channel", func(t *testing.T) {
		_, err := InitAggregationProcess(AggregationInput{
			WorkerNum: 2,
		})
		assert.Error(t, err)
	})
	t.Run("input channel", func(t *testing.T) {
		aggregationProcess, err := InitAggregationProcess(AggregationInput{
			RecordChan: make(chan *flowpb.Flow),
			WorkerNum:  2,
		})
		require.NoError(t, err)
		assert.Equal(t, 2, aggregationProcess.workerNum)
	})
}

func TestGetTupleRecordMap(t *testing.T) {
	recordChan := make(chan *flowpb.Flow)
	input := AggregationInput{
		RecordChan: recordChan,
		WorkerNum:  2,
	}
	aggregationProcess, _ := InitAggregationProcess(input)
	assert.Equal(t, aggregationProcess.flowKeyRecordMap, aggregationProcess.flowKeyRecordMap)
}

func TestAggregateRecordByFlowKey(t *testing.T) {
	recordChan := make(chan *flowpb.Flow)
	input := AggregationInput{
		RecordChan:            recordChan,
		WorkerNum:             2,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	aggregationProcess, _ := InitAggregationProcess(input)
	record := createFlowRecordForSrc(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	require.NoError(t, aggregationProcess.aggregateRecordByFlowKey(record))
	assert.NotZero(t, uint64(1), aggregationProcess.GetNumFlows())
	assert.NotZero(t, aggregationProcess.expirePriorityQueue.Len())
	flowKey := FlowKey{"10.0.0.1", "10.0.0.2", 6, 1234, 5678}
	aggRecord := aggregationProcess.flowKeyRecordMap[flowKey]
	assert.NotNil(t, aggregationProcess.flowKeyRecordMap[flowKey])
	item := aggregationProcess.expirePriorityQueue.Peek()
	assert.NotNil(t, item)
	assert.Same(t, record, aggRecord.Record)
	assert.Equal(t, []byte{0xa, 0x0, 0x0, 0x1}, aggRecord.Record.Ip.Source)

	record = createFlowRecordForSrc(true, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	require.NoError(t, aggregationProcess.aggregateRecordByFlowKey(record))
	assert.Equal(t, int64(2), aggregationProcess.GetNumFlows())
	assert.Equal(t, 2, aggregationProcess.expirePriorityQueue.Len())
	flowKey = FlowKey{"2001:0:3238:dfe1:63::fefb", "2001:0:3238:dfe1:63::fefc", 6, 1234, 5678}
	assert.NotNil(t, aggregationProcess.flowKeyRecordMap[flowKey])
	aggRecord = aggregationProcess.flowKeyRecordMap[flowKey]
	assert.Same(t, record, aggRecord.Record)
	assert.Equal(t, []byte{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xdf, 0xe1, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xfe, 0xfb}, aggRecord.Record.Ip.Source)

	// Test data record with invalid "flowEndSeconds" field
	record.EndTs.Seconds = 0
	assert.NoError(t, aggregationProcess.aggregateRecordByFlowKey(record))
}

func TestAggregationProcess(t *testing.T) {
	recordChan := make(chan *flowpb.Flow)
	input := AggregationInput{
		RecordChan: recordChan,
		WorkerNum:  2,
	}
	aggregationProcess, _ := InitAggregationProcess(input)
	record := createFlowRecordForSrc(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	go func() {
		recordChan <- record
		time.Sleep(time.Second)
		close(recordChan)
		aggregationProcess.Stop()
	}()
	// the Start() function is blocking until above goroutine with Stop() finishes
	// Proper usage of aggregation process is to have Start() in a goroutine with external channel
	aggregationProcess.Start()
	flowKey := FlowKey{
		"10.0.0.1", "10.0.0.2", 6, 1234, 5678,
	}
	aggRecord := aggregationProcess.flowKeyRecordMap[flowKey]
	assert.Same(t, aggRecord.Record, record, "records should be equal")
}

func BenchmarkAggregateRecordByFlowKey(b *testing.B) {
	bench := func(b *testing.B, isIPv6 bool) {
		recordChan := make(chan *flowpb.Flow)
		input := AggregationInput{
			RecordChan: recordChan,
			WorkerNum:  1, // not relevant for this benchmark (not calling Start)
		}
		ap, err := InitAggregationProcess(input)
		require.NoError(b, err)
		record1 := createFlowRecordForSrc(isIPv6, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
		record2 := createFlowRecordForDst(isIPv6, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			require.NoError(b, ap.aggregateRecordByFlowKey(record1))
			require.NoError(b, ap.aggregateRecordByFlowKey(record2))
			assert.EqualValues(b, 1, ap.GetNumFlows())
		}
	}

	b.Run("ipv4", func(b *testing.B) { bench(b, false) })
	b.Run("ipv6", func(b *testing.B) { bench(b, true) })
}

func TestCorrelateRecordsForInterNodeFlow(t *testing.T) {
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
	// Test the scenario, where record1 is added first and then record2.
	record1 := createFlowRecordForSrc(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	record2 := createFlowRecordForDst(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	runCorrelationAndCheckResult(t, ap, clock, record1, record2, false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, true)
	// Cleanup the flowKeyMap in aggregation process.
	flowKey1, _ := getFlowKeyFromRecord(record1)
	err := ap.deleteFlowKeyFromMap(*flowKey1)
	assert.NoError(t, err)
	heap.Pop(&ap.expirePriorityQueue)
	// Test the scenario, where record2 is added first and then record1.
	record1 = createFlowRecordForSrc(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	record2 = createFlowRecordForDst(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	runCorrelationAndCheckResult(t, ap, clock, record2, record1, false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, true)
	// Cleanup the flowKeyMap in aggregation process.
	err = ap.deleteFlowKeyFromMap(*flowKey1)
	assert.NoError(t, err)
	heap.Pop(&ap.expirePriorityQueue)
	// Test IPv6 fields.
	// Test the scenario, where record1 is added first and then record2.
	record1 = createFlowRecordForSrc(true, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	record2 = createFlowRecordForDst(true, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	runCorrelationAndCheckResult(t, ap, clock, record1, record2, true, flowpb.FlowType_FLOW_TYPE_INTER_NODE, true)
	// Cleanup the flowKeyMap in aggregation process.
	flowKey1, _ = getFlowKeyFromRecord(record1)
	err = ap.deleteFlowKeyFromMap(*flowKey1)
	assert.NoError(t, err)
	heap.Pop(&ap.expirePriorityQueue)
	// Test the scenario, where record2 is added first and then record1.
	record1 = createFlowRecordForSrc(true, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	record2 = createFlowRecordForDst(true, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	runCorrelationAndCheckResult(t, ap, clock, record2, record1, true, flowpb.FlowType_FLOW_TYPE_INTER_NODE, true)
}

func TestCorrelateRecordsForInterNodeDenyFlow(t *testing.T) {
	recordChan := make(chan *flowpb.Flow)
	input := AggregationInput{
		RecordChan: recordChan,
		WorkerNum:  2,
	}
	clock := clocktesting.NewFakeClock(time.Now())
	ap, _ := initAggregationProcessWithClock(input, clock)
	// Test the scenario, where src record has egress deny rule
	record1 := createFlowRecordForSrc(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP)
	runCorrelationAndCheckResult(t, ap, clock, record1, nil, false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false)
	// Cleanup the flowKeyMap in aggregation process.
	flowKey1, _ := getFlowKeyFromRecord(record1)
	ap.deleteFlowKeyFromMap(*flowKey1)
	heap.Pop(&ap.expirePriorityQueue)
	// Test the scenario, where dst record has ingress reject rule
	record2 := createFlowRecordForDst(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_REJECT)
	runCorrelationAndCheckResult(t, ap, clock, record2, nil, false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false)
	// Cleanup the flowKeyMap in aggregation process.
	ap.deleteFlowKeyFromMap(*flowKey1)
	heap.Pop(&ap.expirePriorityQueue)
	// Test the scenario, where dst record has ingress drop rule
	record1 = createFlowRecordForSrc(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	record2 = createFlowRecordForDst(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP)
	runCorrelationAndCheckResult(t, ap, clock, record1, record2, false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, true)
	// Cleanup the flowKeyMap in aggregation process.
	ap.deleteFlowKeyFromMap(*flowKey1)
}

func TestCorrelateRecordsForIntraNodeFlow(t *testing.T) {
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
	record1 := createFlowRecordForSrc(false, flowpb.FlowType_FLOW_TYPE_INTRA_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	runCorrelationAndCheckResult(t, ap, clock, record1, nil, false, flowpb.FlowType_FLOW_TYPE_INTRA_NODE, false)
	// Cleanup the flowKeyMap in aggregation process.
	flowKey1, _ := getFlowKeyFromRecord(record1)
	err := ap.deleteFlowKeyFromMap(*flowKey1)
	assert.NoError(t, err)
	heap.Pop(&ap.expirePriorityQueue)
	// Test IPv6 fields.
	record1 = createFlowRecordForSrc(true, flowpb.FlowType_FLOW_TYPE_INTRA_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	runCorrelationAndCheckResult(t, ap, clock, record1, nil, true, flowpb.FlowType_FLOW_TYPE_INTRA_NODE, false)
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

func TestAggregateRecordsForInterNodeFlow(t *testing.T) {
	recordChan := make(chan *flowpb.Flow)
	input := AggregationInput{
		RecordChan:            recordChan,
		WorkerNum:             2,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	clock := clocktesting.NewFakeClock(time.Now())
	ap, _ := initAggregationProcessWithClock(input, clock)

	// Test the scenario (added in order): srcRecord, dstRecord, record1_updated, record2_updated
	srcRecord := createFlowRecordForSrc(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	dstRecord := createFlowRecordForDst(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	latestSrcRecord := createFlowRecordForSrc(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, true, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	latestDstRecord := createFlowRecordForDst(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, true, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	runAggregationAndCheckResult(t, ap, clock, srcRecord, dstRecord, latestSrcRecord, latestDstRecord, false)
}

func TestDeleteFlowKeyFromMapWithLock(t *testing.T) {
	recordChan := make(chan *flowpb.Flow)
	input := AggregationInput{
		RecordChan: recordChan,
		WorkerNum:  2,
	}
	aggregationProcess, _ := InitAggregationProcess(input)
	record := createFlowRecordForSrc(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	flowKey1 := FlowKey{"10.0.0.1", "10.0.0.2", 6, 1234, 5678}
	flowKey2 := FlowKey{"2001:0:3238:dfe1:63::fefb", "2001:0:3238:dfe1:63::fefc", 6, 1234, 5678}
	aggFlowRecord := &AggregationFlowRecord{
		Record:                    record,
		PriorityQueueItem:         &ItemToExpire{},
		ReadyToSend:               true,
		waitForReadyToSendRetries: 0,
		areCorrelatedFieldsFilled: false,
		areExternalFieldsFilled:   false,
	}
	aggregationProcess.flowKeyRecordMap[flowKey1] = aggFlowRecord
	assert.Equal(t, int64(1), aggregationProcess.GetNumFlows())
	err := aggregationProcess.deleteFlowKeyFromMap(flowKey2)
	assert.Error(t, err)
	assert.Equal(t, int64(1), aggregationProcess.GetNumFlows())
	err = aggregationProcess.deleteFlowKeyFromMap(flowKey1)
	assert.NoError(t, err)
	assert.Empty(t, aggregationProcess.flowKeyRecordMap)
}

func TestGetExpiryFromExpirePriorityQueue(t *testing.T) {
	recordChan := make(chan *flowpb.Flow)
	input := AggregationInput{
		RecordChan:            recordChan,
		WorkerNum:             2,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	ap, _ := InitAggregationProcess(input)
	// Add records with IPv4 fields.
	recordIPv4Src := createFlowRecordForSrc(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	recordIPv4Dst := createFlowRecordForDst(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	// Add records with IPv6 fields.
	recordIPv6Src := createFlowRecordForSrc(true, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	recordIPv6Dst := createFlowRecordForDst(true, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	testCases := []struct {
		name    string
		records []*flowpb.Flow
	}{
		{
			"empty queue",
			nil,
		},
		{
			"One aggregation record",
			[]*flowpb.Flow{recordIPv4Src, recordIPv4Dst},
		},
		{
			"Two aggregation records",
			[]*flowpb.Flow{recordIPv4Src, recordIPv4Dst, recordIPv6Src, recordIPv6Dst},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, record := range tc.records {
				flowKey, isIPv4 := getFlowKeyFromRecord(record)
				ap.addOrUpdateRecordInMap(flowKey, record, isIPv4)
			}
			expiryTime := ap.GetExpiryFromExpirePriorityQueue()
			assert.LessOrEqualf(t, expiryTime.Nanoseconds(), testActiveExpiry.Nanoseconds(), "incorrect expiry time")
		})
	}
}

func assertElementMap(t *testing.T, record map[string]interface{}, ipv6 bool) {
	if ipv6 {
		assert.Equal(t, net.ParseIP("2001:0:3238:dfe1:63::fefb"), record["sourceIPv6Address"])
		assert.Equal(t, net.ParseIP("2001:0:3238:dfe1:63::fefc"), record["destinationIPv6Address"])
		assert.Equal(t, net.ParseIP("2001:0:3238:bbbb:63::aaaa"), record["destinationClusterIPv6"])
	} else {
		assert.Equal(t, net.ParseIP("10.0.0.1").To4(), record["sourceIPv4Address"])
		assert.Equal(t, net.ParseIP("10.0.0.2").To4(), record["destinationIPv4Address"])
		assert.Equal(t, net.ParseIP("192.168.0.1").To4(), record["destinationClusterIPv4"])
	}
	assert.Equal(t, uint16(1234), record["sourceTransportPort"])
	assert.Equal(t, uint16(5678), record["destinationTransportPort"])
	assert.Equal(t, uint8(6), record["protocolIdentifier"])
	assert.Equal(t, "pod1", record["sourcePodName"])
	assert.Equal(t, "pod2", record["destinationPodName"])
	assert.Equal(t, uint16(4739), record["destinationServicePort"])
	assert.Equal(t, uint32(0), record["flowStartSeconds"])
	assert.Equal(t, uint32(1), record["flowEndSeconds"])
	assert.Equal(t, uint32(1), record["flowEndSecondsFromSourceNode"])
	assert.Equal(t, uint32(1), record["flowEndSecondsFromDestinationNode"])
	assert.Equal(t, uint8(2), record["flowType"])
	assert.Equal(t, uint8(2), record["flowEndReason"])
	assert.Equal(t, "ESTABLISHED", record["tcpState"])
	assert.Equal(t, uint8(0), record["ingressNetworkPolicyRuleAction"])
	assert.Equal(t, uint8(0), record["egressNetworkPolicyRuleAction"])
	assert.Equal(t, uint64(502), record["packetTotalCount"])
	assert.Equal(t, uint64(502), record["reversePacketTotalCount"])
	assert.Equal(t, uint64(1020), record["octetTotalCount"])
	assert.Equal(t, uint64(1020), record["reverseOctetTotalCount"])
	assert.Equal(t, uint64(1020*8), record["throughput"])
	assert.Equal(t, uint64(1020*8), record["reverseThroughput"])
	assert.Equal(t, uint64(0), record["packetDeltaCount"])
	assert.Equal(t, uint64(502), record["reversePacketTotalCount"])
	assert.Equal(t, uint64(0), record["reversePacketDeltaCount"])
}

func TestGetRecords(t *testing.T) {
	recordChan := make(chan *flowpb.Flow)
	input := AggregationInput{
		RecordChan:            recordChan,
		WorkerNum:             2,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	ap, _ := InitAggregationProcess(input)

	// Add records with IPv4 fields.
	recordIPv4Src := createFlowRecordForSrc(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	recordIPv4Dst := createFlowRecordForDst(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	// Add records with IPv6 fields.
	recordIPv6Src := createFlowRecordForSrc(true, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	recordIPv6Dst := createFlowRecordForDst(true, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)

	records := []*flowpb.Flow{recordIPv4Src, recordIPv4Dst, recordIPv6Src, recordIPv6Dst}
	for _, record := range records {
		flowKey, isIPv4 := getFlowKeyFromRecord(record)
		ap.addOrUpdateRecordInMap(flowKey, record, isIPv4)
	}

	flowKeyIPv4, _ := getFlowKeyFromRecord(recordIPv4Src)
	partialFlowKeyIPv6 := &FlowKey{
		SourceAddress: "2001:0:3238:dfe1:63::fefb",
	}
	testCases := []struct {
		name        string
		flowKey     *FlowKey
		expectedLen int
	}{
		{
			"Empty flowkey",
			nil,
			2,
		},
		{
			"IPv4 flowkey",
			flowKeyIPv4,
			1,
		},
		{
			"IPv6 flowkey",
			partialFlowKeyIPv6,
			1,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			records := ap.GetRecords(tc.flowKey)
			assert.Equalf(t, tc.expectedLen, len(records), "%s: Number of records string is incorrect, expected %d got %d", tc.name, tc.expectedLen, len(records))
			if tc.flowKey != nil {
				assertElementMap(t, records[0], tc.name == "IPv6 flowkey")
			} else {
				if _, ok := records[0]["sourceIPv6Address"]; ok {
					assertElementMap(t, records[0], true)
					assertElementMap(t, records[1], false)
				} else {
					assertElementMap(t, records[0], false)
					assertElementMap(t, records[1], true)
				}
			}
		})
	}
}

func TestForAllExpiredFlowRecordsDo(t *testing.T) {
	recordChan := make(chan *flowpb.Flow)
	input := AggregationInput{
		RecordChan:            recordChan,
		WorkerNum:             2,
		ActiveExpiryTimeout:   testActiveExpiry,
		InactiveExpiryTimeout: testInactiveExpiry,
	}
	ap, _ := InitAggregationProcess(input)
	// Add records with IPv4 fields.
	recordIPv4Src := createFlowRecordForSrc(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	recordIPv4Dst := createFlowRecordForDst(false, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	// Add records with IPv6 fields.
	recordIPv6Src := createFlowRecordForSrc(true, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	recordIPv6Dst := createFlowRecordForDst(true, flowpb.FlowType_FLOW_TYPE_INTER_NODE, false, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
	numExecutions := 0
	testCallback := func(key FlowKey, record *AggregationFlowRecord) error {
		numExecutions = numExecutions + 1
		return nil
	}

	testCases := []struct {
		name               string
		records            []*flowpb.Flow
		expectedExecutions int
		expectedPQLen      int
	}{
		{
			"empty queue",
			nil,
			0,
			0,
		},
		{
			"One aggregation record and none expired",
			[]*flowpb.Flow{recordIPv4Src, recordIPv4Dst},
			0,
			1,
		},
		{
			"One aggregation record and one expired",
			[]*flowpb.Flow{recordIPv4Src, recordIPv4Dst},
			1,
			1,
		},
		{
			"Two aggregation records and one expired",
			[]*flowpb.Flow{recordIPv4Src, recordIPv4Dst, recordIPv6Src, recordIPv6Dst},
			1,
			2,
		},
		{
			"Two aggregation records and two expired",
			[]*flowpb.Flow{recordIPv4Src, recordIPv4Dst, recordIPv6Src, recordIPv6Dst},
			2,
			0,
		},
		{
			"One aggregation record and waitForReadyToSendRetries reach maximum",
			[]*flowpb.Flow{recordIPv4Src},
			0,
			0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			numExecutions = 0
			for _, record := range tc.records {
				flowKey, isIPv4 := getFlowKeyFromRecord(record)
				ap.addOrUpdateRecordInMap(flowKey, record, isIPv4)
			}
			switch tc.name {
			case "One aggregation record and one expired":
				time.Sleep(testActiveExpiry)
				err := ap.ForAllExpiredFlowRecordsDo(testCallback)
				assert.NoError(t, err)
			case "Two aggregation records and one expired":
				time.Sleep(testActiveExpiry)
				secondAggRec := ap.expirePriorityQueue[1]
				ap.expirePriorityQueue.Update(secondAggRec, secondAggRec.flowKey,
					secondAggRec.flowRecord, secondAggRec.activeExpireTime.Add(testActiveExpiry), secondAggRec.inactiveExpireTime.Add(testInactiveExpiry))
				err := ap.ForAllExpiredFlowRecordsDo(testCallback)
				assert.NoError(t, err)
			case "Two aggregation records and two expired":
				time.Sleep(2 * testActiveExpiry)
				err := ap.ForAllExpiredFlowRecordsDo(testCallback)
				assert.NoError(t, err)
			case "One aggregation record and waitForReadyToSendRetries reach maximum":
				for i := 0; i < testMaxRetries; i++ {
					time.Sleep(testActiveExpiry)
					err := ap.ForAllExpiredFlowRecordsDo(testCallback)
					assert.NoError(t, err)
				}
			default:
				break
			}
			assert.Equalf(t, tc.expectedExecutions, numExecutions, "number of callback executions are incorrect")
			assert.Equalf(t, tc.expectedPQLen, ap.expirePriorityQueue.Len(), "expected pq length not correct")
		})
	}
}

func runCorrelationAndCheckResult(t *testing.T, ap *aggregationProcess, clock *clocktesting.FakeClock, record1, record2 *flowpb.Flow, isIPv6 bool, flowType flowpb.FlowType, needsCorrelation bool) {
	flowKey1, isIPv4 := getFlowKeyFromRecord(record1)
	ap.addOrUpdateRecordInMap(flowKey1, record1, isIPv4)
	item := ap.expirePriorityQueue.Peek()
	oldActiveExpiryTime := item.activeExpireTime
	oldInactiveExpiryTime := item.inactiveExpireTime
	if flowType != flowpb.FlowType_FLOW_TYPE_INTRA_NODE && needsCorrelation {
		clock.Step(10 * time.Millisecond)
		flowKey2, isIPv4 := getFlowKeyFromRecord(record2)
		assert.Equalf(t, *flowKey1, *flowKey2, "flow keys should be equal.")
		ap.addOrUpdateRecordInMap(flowKey2, record2, isIPv4)
	}
	assert.Equal(t, int64(1), ap.GetNumFlows())
	assert.Equal(t, 1, ap.expirePriorityQueue.Len())
	aggRecord := ap.flowKeyRecordMap[*flowKey1]
	item = ap.expirePriorityQueue.Peek()
	assert.Equal(t, *aggRecord, *item.flowRecord)
	assert.Equal(t, oldActiveExpiryTime, item.activeExpireTime)
	if flowType != flowpb.FlowType_FLOW_TYPE_INTRA_NODE && needsCorrelation {
		assert.Equal(t, oldInactiveExpiryTime.Add(10*time.Millisecond), item.inactiveExpireTime)
		assert.True(t, ap.AreCorrelatedFieldsFilled(*aggRecord))
	}
	if flowType == flowpb.FlowType_FLOW_TYPE_INTRA_NODE || needsCorrelation {
		assert.Equal(t, "pod1", aggRecord.Record.K8S.SourcePodName)
		assert.Equal(t, "pod2", aggRecord.Record.K8S.DestinationPodName)
		if !isIPv6 {
			assert.Equal(t, netip.MustParseAddr("192.168.0.1").AsSlice(), aggRecord.Record.K8S.DestinationClusterIp)
		} else {
			assert.Equal(t, netip.MustParseAddr("2001:0:3238:BBBB:63::AAAA").AsSlice(), aggRecord.Record.K8S.DestinationClusterIp)
		}
		assert.EqualValues(t, 4739, aggRecord.Record.K8S.DestinationServicePort)
		assert.True(t, ap.AreCorrelatedFieldsFilled(*aggRecord))
	} else if flowType == flowpb.FlowType_FLOW_TYPE_INTER_NODE {
		// for inter-Node deny connections, either src or dst Pod info will be resolved.
		assert.True(t, aggRecord.Record.K8S.SourcePodName == "" || aggRecord.Record.K8S.DestinationPodName == "")
		assert.True(t, aggRecord.Record.K8S.EgressNetworkPolicyRuleAction != flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION || aggRecord.Record.K8S.IngressNetworkPolicyRuleAction != flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
		assert.False(t, ap.AreCorrelatedFieldsFilled(*aggRecord))
	} else if flowType == flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL {
		assert.True(t, aggRecord.Record.K8S.SourcePodName == "" || aggRecord.Record.K8S.DestinationPodName == "")
		assert.True(t, ap.AreCorrelatedFieldsFilled(*aggRecord))
	}
}

func runAggregationAndCheckResult(t *testing.T, ap *aggregationProcess, clock *clocktesting.FakeClock, srcRecord, dstRecord, srcRecordLatest, dstRecordLatest *flowpb.Flow, isIntraNode bool) {
	flowKey, isIPv4 := getFlowKeyFromRecord(srcRecord)
	addOrUpdateRecordInMap := func(record *flowpb.Flow) {
		ap.addOrUpdateRecordInMap(flowKey, record, isIPv4)
		clock.Step(10 * time.Millisecond)
	}

	addOrUpdateRecordInMap(srcRecord)
	item := ap.expirePriorityQueue.Peek()
	oldActiveExpiryTime := item.activeExpireTime
	oldInactiveExpiryTime := item.inactiveExpireTime

	if !isIntraNode {
		addOrUpdateRecordInMap(dstRecord)
	}
	addOrUpdateRecordInMap(srcRecordLatest)
	if !isIntraNode {
		addOrUpdateRecordInMap(dstRecordLatest)
	}
	assert.Equal(t, int64(1), ap.GetNumFlows())
	assert.Equal(t, 1, ap.expirePriorityQueue.Len())
	aggRecord := ap.flowKeyRecordMap[*flowKey]
	item = ap.expirePriorityQueue.Peek()
	assert.Equal(t, *aggRecord, *item.flowRecord)
	assert.Equal(t, oldActiveExpiryTime, item.activeExpireTime)
	if !isIntraNode {
		assert.NotEqual(t, oldInactiveExpiryTime, item.inactiveExpireTime)
	}
	assert.Equal(t, "pod1", aggRecord.Record.K8S.SourcePodName)
	assert.Equal(t, "pod2", aggRecord.Record.K8S.DestinationPodName)
	assert.Equal(t, netip.MustParseAddr("192.168.0.1").AsSlice(), aggRecord.Record.K8S.DestinationClusterIp)
	assert.EqualValues(t, 4739, aggRecord.Record.K8S.DestinationServicePort)
	assert.Equal(t, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION, aggRecord.Record.K8S.IngressNetworkPolicyRuleAction)

	assert.Equal(t, dstRecordLatest.EndTs, aggRecord.Record.EndTs)
	assert.Equal(t, dstRecordLatest.EndReason, aggRecord.Record.EndReason)
	assert.Equal(t, dstRecordLatest.Transport, aggRecord.Record.Transport)
	assert.Equal(t, dstRecordLatest.App, aggRecord.Record.App)

	assert.Equal(t, dstRecordLatest.Stats, aggRecord.Record.Stats)
	assert.Equal(t, dstRecordLatest.ReverseStats, aggRecord.Record.ReverseStats)

	assert.Equal(t, srcRecordLatest.Stats, aggRecord.Record.Aggregation.StatsFromSource)
	assert.Equal(t, srcRecordLatest.ReverseStats, aggRecord.Record.Aggregation.ReverseStatsFromSource)

	assert.Equal(t, dstRecordLatest.Stats, aggRecord.Record.Aggregation.StatsFromDestination)
	assert.Equal(t, dstRecordLatest.ReverseStats, aggRecord.Record.Aggregation.ReverseStatsFromDestination)

	assert.EqualValues(t, 915, aggRecord.Record.Aggregation.Throughput)
	assert.EqualValues(t, 915, aggRecord.Record.Aggregation.ReverseThroughput)
	assert.EqualValues(t, 888, aggRecord.Record.Aggregation.ThroughputFromSource)
	assert.EqualValues(t, 888, aggRecord.Record.Aggregation.ReverseThroughputFromSource)
	assert.EqualValues(t, 915, aggRecord.Record.Aggregation.ThroughputFromDestination)
	assert.EqualValues(t, 915, aggRecord.Record.Aggregation.ReverseThroughputFromDestination)
}
