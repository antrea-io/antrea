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
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)
var (
	MaxRetries    = 2
	MinExpiryTime = 100 * time.Millisecond
)
type aggregationProcess struct {
	// flowKeyRecordMap maps each connection (5-tuple) with its records
	flowKeyRecordMap map[FlowKey]*AggregationFlowRecord
	// expirePriorityQueue helps to maintain a priority queue for the records given
	// active expiry and inactive expiry timeouts.
	expirePriorityQueue TimeToExpirePriorityQueue
	// mutex allows multiple readers or one writer at the same time
	mutex sync.RWMutex
	// recordChan is the channel to receive the flow records to process
	recordChan <-chan *flowpb.Flow
	// workerNum is the number of workers to process the messages
	workerNum int
	// workerList is the list of workers
	workerList []aggregationWorker
	// activeExpiryTimeout helps in identifying records that elapsed active expiry
	// timeout. Active expiry timeout is a periodic expiry interval for every flow
	// record in the aggregation record map.
	activeExpiryTimeout time.Duration
	// inactiveExpiryTimeout helps in identifying records that elapsed inactive expiry
	// timeout. Inactive expiry timeout is an expiry interval that gets reset every
	// time a new record is received for the existing record in the aggregation
	// record map.
	inactiveExpiryTimeout time.Duration
	// stopChan is the channel to receive stop message
	stopChan chan bool
	clock    clock.Clock
}
type AggregationInput struct {
	RecordChan            <-chan *flowpb.Flow
	WorkerNum             int
	ActiveExpiryTimeout   time.Duration
	InactiveExpiryTimeout time.Duration
}
func initAggregationProcessWithClock(input AggregationInput, clock clock.Clock) (*aggregationProcess, error) {
	if input.RecordChan == nil {
		return nil, fmt.Errorf("cannot create aggregationProcess process without input channel")
	}
	if input.WorkerNum <= 0 {
		return nil, fmt.Errorf("worker number cannot be <= 0")
	}
	return &aggregationProcess{
		make(map[FlowKey]*AggregationFlowRecord),
		make(TimeToExpirePriorityQueue, 0),
		sync.RWMutex{},
		input.RecordChan,
		input.WorkerNum,
		make([]aggregationWorker, 0),
		input.ActiveExpiryTimeout,
		input.InactiveExpiryTimeout,
		make(chan bool),
		clock,
	}, nil
}
func InitAggregationProcess(input AggregationInput) (*aggregationProcess, error) {
	return initAggregationProcessWithClock(input, clock.RealClock{})
}
func (a *aggregationProcess) Start() {
	a.mutex.Lock()
	for i := 0; i < a.workerNum; i++ {
		w := createWorker(i, a.recordChan, a.aggregateRecordByFlowKey)
		w.start()
		a.workerList = append(a.workerList, w)
	}
	a.mutex.Unlock()
	<-a.stopChan
}
func (a *aggregationProcess) Stop() {
	a.mutex.Lock()
	for _, worker := range a.workerList {
		worker.stop()
	}
	a.mutex.Unlock()
	a.stopChan <- true
}
// GetNumFlows returns total number of connections/flows stored in map
func (a *aggregationProcess) GetNumFlows() int64 {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return int64(len(a.flowKeyRecordMap))
}
func (a *aggregationProcess) aggregateRecordByFlowKey(record *flowpb.Flow) error {
	flowKey, isIPv4 := getFlowKeyFromRecord(record)
	a.addOrUpdateRecordInMap(flowKey, record, isIPv4)
	return nil
}
// ForAllRecordsDo takes in callback function to process the operations to flowkey->records pairs in the map
func (a *aggregationProcess) ForAllRecordsDo(callback FlowKeyRecordMapCallBack) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	for k, v := range a.flowKeyRecordMap {
		err := callback(k, v)
		if err != nil {
			klog.Errorf("Callback execution failed for flow with key: %v, records: %v, error: %v", k, v, err)
			return err
		}
	}
	return nil
}
func (a *aggregationProcess) deleteFlowKeyFromMap(flowKey FlowKey) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return a.deleteFlowKeyFromMapWithoutLock(flowKey)
}
func (a *aggregationProcess) deleteFlowKeyFromMapWithoutLock(flowKey FlowKey) error {
	_, exists := a.flowKeyRecordMap[flowKey]
	if !exists {
		return fmt.Errorf("flow key %v is not present in the map", flowKey)
	}
	delete(a.flowKeyRecordMap, flowKey)
	return nil
}
// GetExpiryFromExpirePriorityQueue returns the earliest timestamp (active expiry
// or inactive expiry) from expire priority queue.
func (a *aggregationProcess) GetExpiryFromExpirePriorityQueue() time.Duration {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	currTime := a.clock.Now()
	if a.expirePriorityQueue.Len() > 0 {
		// Get the minExpireTime of the top item in expirePriorityQueue.
		expiryDuration := MinExpiryTime + a.expirePriorityQueue.minExpireTime(0).Sub(currTime)
		if expiryDuration < 0 {
			return MinExpiryTime
		}
		return expiryDuration
	}
	if a.activeExpiryTimeout < a.inactiveExpiryTimeout {
		return a.activeExpiryTimeout
	}
	return a.inactiveExpiryTimeout
}
// GetRecords returns map format flow records given a flow key.
// In order to preserve backwards-compatibility (after migrating to Protobuf to represent flow
// records), map keys are the names of the corresponding information elements, and values are typed
// based on the IE type. Not all "elements" are included.
// Returns partially matched flow records if the flow key is not complete.
// Returns all the flow records if the flow key is not provided.
func (a *aggregationProcess) GetRecords(flowKey *FlowKey) []map[string]interface{} {
	flowToMap := func(f *flowpb.Flow) map[string]interface{} {
		m := map[string]interface{}{
			"sourceTransportPort":               uint16(f.Transport.SourcePort),
			"destinationTransportPort":          uint16(f.Transport.DestinationPort),
			"protocolIdentifier":                uint8(f.Transport.ProtocolNumber),
			"tcpState":                          f.Transport.GetTCP().GetStateName(),
			"flowStartSeconds":                  uint32(f.StartTs.Seconds),
			"flowEndSeconds":                    uint32(f.EndTs.Seconds),
			"flowEndSecondsFromSourceNode":      uint32(f.Aggregation.EndTsFromSource.Seconds),
			"flowEndSecondsFromDestinationNode": uint32(f.Aggregation.EndTsFromDestination.Seconds),
			"flowType":                          uint8(f.K8S.FlowType),
			"sourcePodName":                     f.K8S.SourcePodName,
			"sourcePodNamespace":                f.K8S.SourcePodNamespace,
			"sourceNodeName":                    f.K8S.SourceNodeName,
			"destinationPodName":                f.K8S.DestinationPodName,
			"destinationPodNamespace":           f.K8S.DestinationPodNamespace,
			"destinationNodeName":               f.K8S.DestinationNodeName,
			"destinationServicePort":            uint16(f.K8S.DestinationServicePort),
			"destinationServicePortName":        f.K8S.DestinationServicePortName,
			"ingressNetworkPolicyNamespace":     f.K8S.IngressNetworkPolicyNamespace,
			"ingressNetworkPolicyName":          f.K8S.IngressNetworkPolicyName,
			"ingressNetworkPolicyRuleName":      f.K8S.IngressNetworkPolicyRuleName,
			"ingressNetworkPolicyRuleAction":    uint8(f.K8S.IngressNetworkPolicyRuleAction),
			"egressNetworkPolicyNamespace":      f.K8S.EgressNetworkPolicyNamespace,
			"egressNetworkPolicyName":           f.K8S.EgressNetworkPolicyName,
			"egressNetworkPolicyRuleName":       f.K8S.EgressNetworkPolicyRuleName,
			"egressNetworkPolicyRuleAction":     uint8(f.K8S.EgressNetworkPolicyRuleAction),
			"flowEndReason":                     uint8(f.EndReason),
			"egressName":                        f.K8S.EgressName,
			"egressIP":                          net.IP(f.K8S.EgressIp),
			"egressNodeName":                    f.K8S.EgressNodeName,
			"packetTotalCount":                  f.Stats.PacketTotalCount,
			"reversePacketTotalCount":           f.ReverseStats.PacketTotalCount,
			"octetTotalCount":                   f.Stats.OctetTotalCount,
			"reverseOctetTotalCount":            f.ReverseStats.OctetTotalCount,
			"packetDeltaCount":                  f.Stats.PacketDeltaCount,
			"reversePacketDeltaCount":           f.ReverseStats.PacketDeltaCount,
			"octetDeltaCount":                   f.Stats.OctetDeltaCount,
			"reverseOctetDeltaCount":            f.ReverseStats.OctetDeltaCount,
			"throughput":                        f.Aggregation.Throughput,
			"reverseThroughput":                 f.Aggregation.ReverseThroughput,
		}
		if f.Ip.Version == flowpb.IPVersion_IP_VERSION_4 {
			m["sourceIPv4Address"] = net.IP(f.Ip.Source)
			m["destinationIPv4Address"] = net.IP(f.Ip.Destination)
			m["destinationClusterIPv4"] = net.IP(f.K8S.DestinationClusterIp)
		} else {
			m["sourceIPv6Address"] = net.IP(f.Ip.Source)
			m["destinationIPv6Address"] = net.IP(f.Ip.Destination)
			m["destinationClusterIPv6"] = net.IP(f.K8S.DestinationClusterIp)
		}
		return m
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()
	var records []map[string]interface{}
	// Complete filter
	if flowKey != nil && flowKey.SourceAddress != "" && flowKey.DestinationAddress != "" &&
		flowKey.Protocol != 0 && flowKey.SourcePort != 0 && flowKey.DestinationPort != 0 {
		if record, ok := a.flowKeyRecordMap[*flowKey]; ok {
			records = append(records, flowToMap(record.Record))
		}
		return records
	}
	// Partial filter
	for currentFlowKey, record := range a.flowKeyRecordMap {
		if flowKey != nil {
			if (flowKey.SourceAddress != "" && flowKey.SourceAddress != currentFlowKey.SourceAddress) ||
				(flowKey.DestinationAddress != "" && flowKey.DestinationAddress != currentFlowKey.DestinationAddress) ||
				(flowKey.Protocol != 0 && flowKey.Protocol != currentFlowKey.Protocol) ||
				(flowKey.SourcePort != 0 && flowKey.SourcePort != currentFlowKey.SourcePort) ||
				(flowKey.DestinationPort != 0 && flowKey.DestinationPort != currentFlowKey.DestinationPort) {
				continue
			}
		}
		records = append(records, flowToMap(record.Record))
	}
	return records
}
func (a *aggregationProcess) ForAllExpiredFlowRecordsDo(callback FlowKeyRecordMapCallBack) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.expirePriorityQueue.Len() == 0 {
		return nil
	}
	currTime := a.clock.Now()
	for a.expirePriorityQueue.Len() > 0 {
		topItem := a.expirePriorityQueue.Peek()
		if topItem.activeExpireTime.After(currTime) && topItem.inactiveExpireTime.After(currTime) {
			// We do not have to check other items anymore.
			break
		}
		// Pop the record item from the priority queue
		pqItem := heap.Pop(&a.expirePriorityQueue).(*ItemToExpire)
		if !pqItem.flowRecord.ReadyToSend {
			// Reset the timeouts and add the record to priority queue.
			// Delete the record after max retries.
			pqItem.flowRecord.waitForReadyToSendRetries = pqItem.flowRecord.waitForReadyToSendRetries + 1
			if pqItem.flowRecord.waitForReadyToSendRetries > MaxRetries {
				klog.V(2).Infof("Deleting the record after waiting for ready to send with key: %v record: %v", pqItem.flowKey, pqItem.flowRecord)
				if err := a.deleteFlowKeyFromMapWithoutLock(*pqItem.flowKey); err != nil {
					return fmt.Errorf("error while deleting flow record after max retries: %v", err)
				}
			} else {
				pqItem.activeExpireTime = currTime.Add(a.activeExpiryTimeout)
				pqItem.inactiveExpireTime = currTime.Add(a.inactiveExpiryTimeout)
				heap.Push(&a.expirePriorityQueue, pqItem)
			}
			continue
		}
		err := callback(*pqItem.flowKey, pqItem.flowRecord)
		if err != nil {
			return fmt.Errorf("callback execution failed for popped flow record with key: %v, record: %v, error: %v", pqItem.flowKey, pqItem.flowRecord, err)
		}
		// Delete the flow record if it is expired because of inactive expiry timeout.
		if pqItem.inactiveExpireTime.Before(currTime) {
			if err = a.deleteFlowKeyFromMapWithoutLock(*pqItem.flowKey); err != nil {
				return fmt.Errorf("error while deleting flow record after inactive expiry: %v", err)
			}
			continue
		}
		// Reset the expireTime for the popped item and push it to the priority queue.
		if pqItem.activeExpireTime.Before(currTime) {
			// Reset the active expire timeout and push the record into priority
			// queue.
			pqItem.activeExpireTime = currTime.Add(a.activeExpiryTimeout)
			heap.Push(&a.expirePriorityQueue, pqItem)
		}
	}
	return nil
}
func (a *aggregationProcess) SetCorrelatedFieldsFilled(record *AggregationFlowRecord, isFilled bool) {
	record.areCorrelatedFieldsFilled = isFilled
}
func (a *aggregationProcess) AreCorrelatedFieldsFilled(record AggregationFlowRecord) bool {
	return record.areCorrelatedFieldsFilled
}
func (a *aggregationProcess) SetExternalFieldsFilled(record *AggregationFlowRecord, isFilled bool) {
	record.areExternalFieldsFilled = isFilled
}
func (a *aggregationProcess) AreExternalFieldsFilled(record AggregationFlowRecord) bool {
	return record.areExternalFieldsFilled
}
func (a *aggregationProcess) IsAggregatedRecordIPv4(record AggregationFlowRecord) bool {
	return record.isIPv4
}
// addOrUpdateRecordInMap either adds the record to flowKeyMap or updates the record in
// flowKeyMap by doing correlation or updating the stats.
func (a *aggregationProcess) addOrUpdateRecordInMap(flowKey *FlowKey, record *flowpb.Flow, isIPv4 bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	correlationRequired := isCorrelationRequired(record.K8S.FlowType, record)
	currTime := a.clock.Now()
	aggregationRecord, exist := a.flowKeyRecordMap[*flowKey]
	if exist {
		if correlationRequired {
			// Do correlation of records if record belongs to inter-node flow and
			// records from source and destination node are not received.
			if !aggregationRecord.ReadyToSend && !areRecordsFromSameNode(record, aggregationRecord.Record) {
				a.correlateRecords(record, aggregationRecord.Record)
				aggregationRecord.ReadyToSend = true
				aggregationRecord.areCorrelatedFieldsFilled = true
			}
			// Aggregation of incoming flow record with existing by updating stats
			// and flow timestamps.
			if isRecordFromSrc(record) {
				a.aggregateRecords(record, aggregationRecord.Record, true, false)
			} else {
				a.aggregateRecords(record, aggregationRecord.Record, false, true)
			}
		} else {
			// For flows that do not need correlation, just do aggregation of the
			// flow record with existing record by updating the stats and flow timestamps.
			a.aggregateRecords(record, aggregationRecord.Record, true, true)
		}
		// Reset the inactive expiry time in the queue item with updated aggregate
		// record.
		a.expirePriorityQueue.Update(aggregationRecord.PriorityQueueItem,
			flowKey, aggregationRecord, aggregationRecord.PriorityQueueItem.activeExpireTime, currTime.Add(a.inactiveExpiryTimeout))
	} else {
		record.Aggregation = &flowpb.Aggregation{}
		// Add all the new stat fields and initialize them.
		if correlationRequired {
			if isRecordFromSrc(record) {
				a.addFieldsForStatsAggregation(record, true, false)
				a.addFieldsForThroughputCalculation(record, true, false)
			} else {
				a.addFieldsForStatsAggregation(record, false, true)
				a.addFieldsForThroughputCalculation(record, false, true)
			}
		} else {
			a.addFieldsForStatsAggregation(record, true, true)
			a.addFieldsForThroughputCalculation(record, true, true)
		}
		aggregationRecord = &AggregationFlowRecord{
			Record:                    record,
			ReadyToSend:               false,
			waitForReadyToSendRetries: 0,
			isIPv4:                    isIPv4,
		}
		if !correlationRequired {
			aggregationRecord.ReadyToSend = true
			// If no correlation is required for an Inter-Node record, K8s metadata is
			// expected to be not completely filled. For Intra-Node flows and ToExternal
			// flows, areCorrelatedFieldsFilled is set to true by default.
			if record.K8S.FlowType == flowpb.FlowType_FLOW_TYPE_INTER_NODE {
				aggregationRecord.areCorrelatedFieldsFilled = false
			} else {
				aggregationRecord.areCorrelatedFieldsFilled = true
			}
		}
		aggregationRecord.areExternalFieldsFilled = false
		// Push the record to the priority queue.
		pqItem := &ItemToExpire{
			flowKey: flowKey,
		}
		aggregationRecord.PriorityQueueItem = pqItem
		pqItem.flowRecord = aggregationRecord
		pqItem.activeExpireTime = currTime.Add(a.activeExpiryTimeout)
		pqItem.inactiveExpireTime = currTime.Add(a.inactiveExpiryTimeout)
		heap.Push(&a.expirePriorityQueue, pqItem)
	}
	a.flowKeyRecordMap[*flowKey] = aggregationRecord
}
// correlateRecords correlate the incomingRecord with existingRecord using correlation
// fields. This is called for records whose flowType is InterNode.
func (a *aggregationProcess) correlateRecords(incomingRecord, existingRecord *flowpb.Flow) {
	if sourcePodName := incomingRecord.K8S.SourcePodName; sourcePodName != "" {
		existingRecord.K8S.SourcePodName = sourcePodName
	}
	if sourcePodNamespace := incomingRecord.K8S.SourcePodNamespace; sourcePodNamespace != "" {
		existingRecord.K8S.SourcePodNamespace = sourcePodNamespace
	}
	if sourceNodeName := incomingRecord.K8S.SourceNodeName; sourceNodeName != "" {
		existingRecord.K8S.SourceNodeName = sourceNodeName
	}
	if destinationPodName := incomingRecord.K8S.DestinationPodName; destinationPodName != "" {
		existingRecord.K8S.DestinationPodName = destinationPodName
	}
	if destinationPodNamespace := incomingRecord.K8S.DestinationPodNamespace; destinationPodNamespace != "" {
		existingRecord.K8S.DestinationPodNamespace = destinationPodNamespace
	}
	if destinationNodeName := incomingRecord.K8S.DestinationNodeName; destinationNodeName != "" {
		existingRecord.K8S.DestinationNodeName = destinationNodeName
	}
	if destinationClusterIP := incomingRecord.K8S.DestinationClusterIp; destinationClusterIP != nil {
		existingRecord.K8S.DestinationClusterIp = destinationClusterIP
	}
	if destinationServicePort := incomingRecord.K8S.DestinationServicePort; destinationServicePort != 0 {
		existingRecord.K8S.DestinationServicePort = destinationServicePort
	}
	if destinationServicePortName := incomingRecord.K8S.DestinationServicePortName; destinationServicePortName != "" {
		existingRecord.K8S.DestinationServicePortName = destinationServicePortName
	}
	if ingressNetworkPolicyName := incomingRecord.K8S.IngressNetworkPolicyName; ingressNetworkPolicyName != "" {
		existingRecord.K8S.IngressNetworkPolicyName = ingressNetworkPolicyName
	}
	if ingressNetworkPolicyNamespace := incomingRecord.K8S.IngressNetworkPolicyNamespace; ingressNetworkPolicyNamespace != "" {
		existingRecord.K8S.IngressNetworkPolicyNamespace = ingressNetworkPolicyNamespace
	}
	if ingressNetworkPolicyRuleAction := incomingRecord.K8S.IngressNetworkPolicyRuleAction; ingressNetworkPolicyRuleAction != flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION {
		existingRecord.K8S.IngressNetworkPolicyRuleAction = ingressNetworkPolicyRuleAction
	}
	if ingressNetworkPolicyType := incomingRecord.K8S.IngressNetworkPolicyType; ingressNetworkPolicyType != flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_UNSPECIFIED {
		existingRecord.K8S.IngressNetworkPolicyType = ingressNetworkPolicyType
	}
	if ingressNetworkPolicyRuleName := incomingRecord.K8S.IngressNetworkPolicyRuleName; ingressNetworkPolicyRuleName != "" {
		existingRecord.K8S.IngressNetworkPolicyRuleName = ingressNetworkPolicyRuleName
	}
	if egressNetworkPolicyName := incomingRecord.K8S.EgressNetworkPolicyName; egressNetworkPolicyName != "" {
		existingRecord.K8S.EgressNetworkPolicyName = egressNetworkPolicyName
	}
	if egressNetworkPolicyNamespace := incomingRecord.K8S.EgressNetworkPolicyNamespace; egressNetworkPolicyNamespace != "" {
		existingRecord.K8S.EgressNetworkPolicyNamespace = egressNetworkPolicyNamespace
	}
	if egressNetworkPolicyRuleAction := incomingRecord.K8S.EgressNetworkPolicyRuleAction; egressNetworkPolicyRuleAction != flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION {
		existingRecord.K8S.EgressNetworkPolicyRuleAction = egressNetworkPolicyRuleAction
	}
	if egressNetworkPolicyType := incomingRecord.K8S.EgressNetworkPolicyType; egressNetworkPolicyType != flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_UNSPECIFIED {
		existingRecord.K8S.EgressNetworkPolicyType = egressNetworkPolicyType
	}
	if egressNetworkPolicyRuleName := incomingRecord.K8S.EgressNetworkPolicyRuleName; egressNetworkPolicyRuleName != "" {
		existingRecord.K8S.EgressNetworkPolicyRuleName = egressNetworkPolicyRuleName
	}
}
// aggregateRecords aggregate the incomingRecord with existingRecord by updating
// stats and flow timestamps.
func (a *aggregationProcess) aggregateRecords(incomingRecord, existingRecord *flowpb.Flow, fillSrcStats, fillDstStats bool) {
	isLatest := false
	var prevFlowEndSeconds, flowEndSecondsDiff int64
	if incomingRecord.EndTs != nil && existingRecord.EndTs != nil {
		incomingVal := incomingRecord.EndTs.Seconds
		existingVal := existingRecord.EndTs.Seconds
		if incomingVal >= existingVal {
			isLatest = true
			existingRecord.EndTs.Seconds = incomingVal
		}
		// Update the flowEndSecondsFromSource/DestinationNode fields, and compute
		// the time difference between the incoming record and the last record.
		if fillSrcStats {
			prevFlowEndSeconds = a.updateFlowEndSecondsFromNodes(incomingRecord, existingRecord, true, incomingVal)
		}
		if fillDstStats {
			prevFlowEndSeconds = a.updateFlowEndSecondsFromNodes(incomingRecord, existingRecord, false, incomingVal)
		}
		// Skip the aggregation process if the incoming record is not the latest
		// from its coming node; for intra-node flows. Also to avoid to assign
		// zero value to flowEndSecondsDiff.
		if incomingVal <= prevFlowEndSeconds {
			klog.V(4).InfoS("The incoming record doesn't have the latest flowEndSeconds", "previous value", prevFlowEndSeconds, "incoming value", incomingVal, "from source node", fillSrcStats, "from destination node", fillDstStats)
			return
		}
		flowEndSecondsDiff = incomingVal - prevFlowEndSeconds
	}
	// If the aggregated flow is set with flowEndReason as "EndOfFlowReason", then we do not have to set again.
	if existingRecord.EndReason != flowpb.FlowEndReason_FLOW_END_REASON_END_OF_FLOW {
		existingRecord.EndReason = incomingRecord.EndReason
	}
	// Update tcpState when flow end timestamp is the latest.
	if isLatest {
		// This code will need to change if more fields are added to Transport.Protocol.
		existingRecord.Transport.Protocol = incomingRecord.Transport.Protocol
	}
	if incomingRecord.App.HttpVals != nil {
		updatedHttpVals, err := fillHttpVals(incomingRecord.App.HttpVals, existingRecord.App.HttpVals)
		if err != nil {
			klog.ErrorS(err, "httpVals could not be updated")
			existingRecord.App.HttpVals = incomingRecord.App.HttpVals
		} else {
			existingRecord.App.HttpVals = updatedHttpVals
		}
	}
	aggregateStats := func(incoming, existing *flowpb.Stats) {
		existing.PacketTotalCount = incoming.PacketTotalCount
		existing.PacketDeltaCount += incoming.PacketDeltaCount
		existing.OctetTotalCount = incoming.OctetTotalCount
		existing.OctetDeltaCount += incoming.OctetDeltaCount
	}
	var totalCountDiff, reverseTotalCountDiff uint64
	if fillSrcStats {
		incoming := incomingRecord.Stats
		existing := existingRecord.Aggregation.StatsFromSource
		totalCountDiff = incoming.OctetTotalCount - existing.OctetTotalCount
		aggregateStats(incoming, existing)
		incoming = incomingRecord.ReverseStats
		existing = existingRecord.Aggregation.ReverseStatsFromSource
		reverseTotalCountDiff = incoming.OctetTotalCount - existing.OctetTotalCount
		aggregateStats(incoming, existing)
	}
	if fillDstStats {
		incoming := incomingRecord.Stats
		existing := existingRecord.Aggregation.StatsFromDestination
		totalCountDiff = incoming.OctetTotalCount - existing.OctetTotalCount
		aggregateStats(incoming, existing)
		incoming = incomingRecord.ReverseStats
		existing = existingRecord.Aggregation.ReverseStatsFromDestination
		reverseTotalCountDiff = incoming.OctetTotalCount - existing.OctetTotalCount
		aggregateStats(incoming, existing)
	}
	updateCommonStats := func(from, existing *flowpb.Stats) {
		if existing.PacketTotalCount < from.PacketTotalCount {
			existing.PacketTotalCount = from.PacketTotalCount
		}
		existing.PacketDeltaCount = from.PacketDeltaCount
		if existing.OctetTotalCount < from.OctetTotalCount {
			existing.OctetTotalCount = from.OctetTotalCount
		}
		existing.OctetDeltaCount = from.OctetDeltaCount
	}
	if isLatest {
		if fillSrcStats {
			updateCommonStats(existingRecord.Aggregation.StatsFromSource, existingRecord.Stats)
			updateCommonStats(existingRecord.Aggregation.ReverseStatsFromSource, existingRecord.ReverseStats)
		}
		if fillDstStats {
			updateCommonStats(existingRecord.Aggregation.StatsFromDestination, existingRecord.Stats)
			updateCommonStats(existingRecord.Aggregation.ReverseStatsFromDestination, existingRecord.ReverseStats)
		}
	}
	// Update the throughput & reverseThroughput fields:
	// throughput = (octetTotalCount - prevOctetTotalCount) / (flowEndSeconds - prevFlowEndSeconds)
	// reverseThroughput = (reverseOctetTotalCount - prevReverseOctetTotalCount) / (flowEndSeconds - prevFlowEndSeconds)
	throughput := totalCountDiff * 8 / uint64(flowEndSecondsDiff)
	reverseThroughput := reverseTotalCountDiff * 8 / uint64(flowEndSecondsDiff)
	if fillSrcStats {
		existingRecord.Aggregation.ThroughputFromSource = throughput
		existingRecord.Aggregation.ReverseThroughputFromSource = reverseThroughput
	}
	if fillDstStats {
		existingRecord.Aggregation.ThroughputFromDestination = throughput
		existingRecord.Aggregation.ReverseThroughputFromDestination = reverseThroughput
	}
	if isLatest {
		existingRecord.Aggregation.Throughput = throughput
		existingRecord.Aggregation.ReverseThroughput = reverseThroughput
	}
}
// ResetStatAndThroughputElementsInRecord is called by the user after the aggregation
// record is sent after its expiry either by active or inactive expiry interval. This
// should be called by user after acquiring the mutex in the Aggregation process.
func (a *aggregationProcess) ResetStatAndThroughputElementsInRecord(record *flowpb.Flow) error {
	// TotalCount statistic elements should not be reset to zeroes as they are used in the
	// throughput calculation.
	resetDeltaStats := func(stats *flowpb.Stats) {
		stats.PacketDeltaCount = 0
		stats.OctetDeltaCount = 0
	}
	resetDeltaStats(record.Stats)
	resetDeltaStats(record.ReverseStats)
	resetDeltaStats(record.Aggregation.StatsFromSource)
	resetDeltaStats(record.Aggregation.ReverseStatsFromSource)
	resetDeltaStats(record.Aggregation.StatsFromDestination)
	resetDeltaStats(record.Aggregation.ReverseStatsFromDestination)
	record.Aggregation.ThroughputFromSource = 0
	record.Aggregation.ReverseThroughputFromSource = 0
	record.Aggregation.ThroughputFromDestination = 0
	record.Aggregation.ReverseThroughputFromDestination = 0
	record.Aggregation.Throughput = 0
	record.Aggregation.ReverseThroughput = 0
	return nil
}
func (a *aggregationProcess) addFieldsForStatsAggregation(record *flowpb.Flow, fillSrcStats, fillDstStats bool) {
	record.Aggregation.StatsFromSource = &flowpb.Stats{}
	record.Aggregation.ReverseStatsFromSource = &flowpb.Stats{}
	record.Aggregation.StatsFromDestination = &flowpb.Stats{}
	record.Aggregation.ReverseStatsFromDestination = &flowpb.Stats{}
	copyStats := func(from, to *flowpb.Stats) {
		to.PacketTotalCount = from.PacketTotalCount
		to.PacketDeltaCount = from.PacketDeltaCount
		to.OctetTotalCount = from.OctetTotalCount
		to.OctetDeltaCount = from.OctetDeltaCount
	}
	if fillSrcStats {
		copyStats(record.Stats, record.Aggregation.StatsFromSource)
		copyStats(record.ReverseStats, record.Aggregation.ReverseStatsFromSource)
	}
	if fillDstStats {
		copyStats(record.Stats, record.Aggregation.StatsFromDestination)
		copyStats(record.ReverseStats, record.Aggregation.ReverseStatsFromDestination)
	}
}
func (a *aggregationProcess) addFieldsForThroughputCalculation(record *flowpb.Flow, fillSrcStats, fillDstStats bool) {
	timeStart := record.StartTs.Seconds
	timeEnd := record.EndTs.Seconds
	byteCount := record.Stats.OctetTotalCount
	reverseByteCount := record.ReverseStats.OctetTotalCount
	record.Aggregation.EndTsFromSource = &timestamppb.Timestamp{}
	if fillSrcStats {
		record.Aggregation.EndTsFromSource.Seconds = timeEnd
	}
	record.Aggregation.EndTsFromDestination = &timestamppb.Timestamp{}
	if fillDstStats {
		record.Aggregation.EndTsFromDestination.Seconds = timeEnd
	}
	// Initialize the throughput elements.
	var throughput, reverseThroughput uint64
	// For the edge case when the record has the same timeEnd and timeStart values,
	// we will initialize the throughput fields with zero values.
	if timeEnd > timeStart {
		throughput = byteCount * 8 / uint64(timeEnd-timeStart)
		reverseThroughput = reverseByteCount * 8 / uint64(timeEnd-timeStart)
	}
	record.Aggregation.Throughput = throughput
	record.Aggregation.ReverseThroughput = reverseThroughput
	if fillSrcStats {
		record.Aggregation.ThroughputFromSource = throughput
		record.Aggregation.ReverseThroughputFromSource = reverseThroughput
	}
	if fillDstStats {
		record.Aggregation.ThroughputFromDestination = throughput
		record.Aggregation.ReverseThroughputFromDestination = reverseThroughput
	}
}
// updateFlowEndSecondsFromNodes updates the value of flowEndSecondsFromSourceNode
// or flowEndSecondsFromDestinationNode, returning the previous value before update.
func (a *aggregationProcess) updateFlowEndSecondsFromNodes(incomingRecord, existingRecord *flowpb.Flow, isSrc bool, incomingVal int64) int64 {
	existingVal := existingRecord.Aggregation.EndTsFromSource.Seconds
	if !isSrc {
		existingVal = existingRecord.Aggregation.EndTsFromDestination.Seconds
	}
	// When the incoming record is the first record from its node, the existingVal of the field
	// is zero, we set it by flowStartSeconds. time_diff = flowEndSeconds - flowStartSeconds
	if existingVal == 0 {
		existingVal = incomingRecord.StartTs.Seconds
	}
	if isSrc {
		existingRecord.Aggregation.EndTsFromSource.Seconds = incomingVal
	} else {
		existingRecord.Aggregation.EndTsFromDestination.Seconds = incomingVal
	}
	return existingVal
}
// isRecordFromSrc returns true if record belongs to inter-node flow and from source node.
func isRecordFromSrc(record *flowpb.Flow) bool {
	return record.K8S.SourcePodName != "" && record.K8S.DestinationPodName == ""
}
// isRecordFromDst returns true if record belongs to inter-node flow and from destination node.
func isRecordFromDst(record *flowpb.Flow) bool {
	return record.K8S.DestinationPodName != "" && record.K8S.SourcePodName == ""
}
func areRecordsFromSameNode(record1, record2 *flowpb.Flow) bool {
	// If both records of inter-node flow are from source node, then send true.
	if isRecordFromSrc(record1) && isRecordFromSrc(record2) {
		return true
	}
	// If both records of inter-node flow are from destination node, then send true.
	if isRecordFromDst(record1) && isRecordFromDst(record2) {
		return true
	}
	return false
}
// getFlowKeyFromRecord returns 5-tuple from data record
func getFlowKeyFromRecord(record *flowpb.Flow) (*FlowKey, bool) {
	source := net.IP(record.Ip.Source).String()
	destination := net.IP(record.Ip.Destination).String()
	flowKey := &FlowKey{
		SourceAddress:      source,
		DestinationAddress: destination,
		Protocol:           uint8(record.Transport.ProtocolNumber),
		SourcePort:         uint16(record.Transport.SourcePort),
		DestinationPort:    uint16(record.Transport.DestinationPort),
	}
	return flowKey, record.Ip.Version == flowpb.IPVersion_IP_VERSION_4
}
// isCorrelationRequired returns true for InterNode flowType when
// either the egressNetworkPolicyRuleAction is not deny (drop/reject) or
// the ingressNetworkPolicyRuleAction is not reject.
func isCorrelationRequired(flowType flowpb.FlowType, record *flowpb.Flow) bool {
	return flowType == flowpb.FlowType_FLOW_TYPE_INTER_NODE &&
		record.K8S.EgressNetworkPolicyRuleAction != flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP &&
		record.K8S.EgressNetworkPolicyRuleAction != flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_REJECT &&
		record.K8S.IngressNetworkPolicyRuleAction != flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_REJECT
}
func fillHttpVals(incomingHttpVals, existingHttpVals []byte) ([]byte, error) {
	incomingHttpValsJson := make(map[int32]string)
	existingHttpValsJson := make(map[int32]string)
	if len(incomingHttpVals) > 0 {
		if err := json.Unmarshal(incomingHttpVals, &incomingHttpValsJson); err != nil {
			return nil, fmt.Errorf("error parsing JSON: %w", err)
		}
	}
	if len(existingHttpVals) > 0 {
		if err := json.Unmarshal(existingHttpVals, &existingHttpValsJson); err != nil {
			return nil, fmt.Errorf("error parsing JSON: %w", err)
		}
	}
	for key, value := range existingHttpValsJson {
		incomingHttpValsJson[key] = value
	}
	updatedHttpVals, err := json.Marshal(incomingHttpValsJson)
	if err != nil {
		return nil, fmt.Errorf("error converting JSON to string: %w", err)
	}
	return updatedHttpVals, nil
}
