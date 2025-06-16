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
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
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
	// messageChan is the channel to receive the messages to process
	messageChan <-chan *entities.Message
	// recordChan is the channel to receive the records to process
	recordChan <-chan entities.Record
	// workerNum is the number of workers to process the messages
	workerNum int
	// workerList is the list of workers
	workerList []aggregationWorker
	// correlateFields are the fields to be filled when correlating records of the
	// flow whose type is registry.InterNode(pkg/registry/registry.go).
	correlateFields []string
	// aggregateElements consists of stats and non-stats elements that need to be
	// updated. In addition, new aggregation elements that has to be added to record
	// to handle correlated records from two nodes should be given.
	// TODO: Add checks to validate the lists inside such as no duplicates, order
	// of stats etc.
	aggregateElements *AggregationElements
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
}

type AggregationInput struct {
	// Exactly one of MessageChan or RecordChan must be set.
	MessageChan           <-chan *entities.Message
	RecordChan            <-chan entities.Record
	WorkerNum             int
	CorrelateFields       []string
	AggregateElements     *AggregationElements
	ActiveExpiryTimeout   time.Duration
	InactiveExpiryTimeout time.Duration
}

// InitaggregationProcess takes in message channel (e.g. from collector) as input
// channel, workerNum(number of workers to process message), and
// correlateFields(fields to be correlated and filled).
func InitAggregationProcess(input AggregationInput) (*aggregationProcess, error) {
	if input.MessageChan == nil && input.RecordChan == nil {
		return nil, fmt.Errorf("cannot create aggregationProcess process without input channel")
	}
	if input.MessageChan != nil && input.RecordChan != nil {
		return nil, fmt.Errorf("only one input channel should be provided")
	}
	if input.WorkerNum <= 0 {
		return nil, fmt.Errorf("worker number cannot be <= 0")
	}
	if input.AggregateElements != nil {
		if (len(input.AggregateElements.StatsElements) != len(input.AggregateElements.AggregatedSourceStatsElements)) || (len(input.AggregateElements.StatsElements) != len(input.AggregateElements.AggregatedDestinationStatsElements)) {
			return nil, fmt.Errorf("stats elements, source stats elements and destination stats elemenst length should be equal")
		}
		if (len(input.AggregateElements.ThroughputElements) != len(input.AggregateElements.SourceThroughputElements)) || (len(input.AggregateElements.ThroughputElements) != len(input.AggregateElements.DestinationThroughputElements)) {
			return nil, fmt.Errorf("throughput elements, source throughput elements and destination throughput elemenst length should be equal")
		}
	}
	return &aggregationProcess{
		make(map[FlowKey]*AggregationFlowRecord),
		make(TimeToExpirePriorityQueue, 0),
		sync.RWMutex{},
		input.MessageChan,
		input.RecordChan,
		input.WorkerNum,
		make([]aggregationWorker, 0),
		input.CorrelateFields,
		input.AggregateElements,
		input.ActiveExpiryTimeout,
		input.InactiveExpiryTimeout,
		make(chan bool),
	}, nil
}

func (a *aggregationProcess) Start() {
	a.mutex.Lock()
	for i := 0; i < a.workerNum; i++ {
		var w aggregationWorker
		if a.messageChan != nil {
			w = createWorker(i, a.messageChan, a.AggregateMsgByFlowKey)
		} else {
			w = createWorker(i, a.recordChan, a.aggregateRecordByFlowKey)
		}
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

func (a *aggregationProcess) aggregateRecordByFlowKey(record entities.Record) error {
	flowKey, isIPv4, err := getFlowKeyFromRecord(record)
	if err != nil {
		return err
	}
	if err = a.addOrUpdateRecordInMap(flowKey, record, isIPv4); err != nil {
		return err
	}
	return nil
}

// AggregateMsgByFlowKey gets flow key from records in message and stores in cache
func (a *aggregationProcess) AggregateMsgByFlowKey(message *entities.Message) error {
	set := message.GetSet()
	if set.GetSetType() != entities.Data { // only process data records
		return nil
	}

	records := set.GetRecords()
	invalidRecs := 0
	for _, record := range records {
		// Validate the data record. If invalid, we log the error and move to the next
		// record.
		if !validateDataRecord(record) {
			klog.Errorf("Invalid data record because decoded values of elements are not valid.")
			invalidRecs = invalidRecs + 1
		} else {
			if err := a.aggregateRecordByFlowKey(record); err != nil {
				return err
			}
		}
	}
	if invalidRecs == len(records) {
		return fmt.Errorf("all data records in the message are invalid")
	}
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

	currTime := time.Now()
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
// The key of the map is the element name and the value is the IE object.
// Returns partially matched flow records if the flow key is not complete.
// Returns all the flow records if the flow key is not provided.
func (a *aggregationProcess) GetRecords(flowKey *FlowKey) []map[string]interface{} {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	var records []map[string]interface{}
	// Complete filter
	if flowKey != nil && flowKey.SourceAddress != "" && flowKey.DestinationAddress != "" &&
		flowKey.Protocol != 0 && flowKey.SourcePort != 0 && flowKey.DestinationPort != 0 {
		if record, ok := a.flowKeyRecordMap[*flowKey]; ok {
			records = append(records, record.Record.GetElementMap())
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
		records = append(records, record.Record.GetElementMap())
	}
	return records
}

func (a *aggregationProcess) ForAllExpiredFlowRecordsDo(callback FlowKeyRecordMapCallBack) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if a.expirePriorityQueue.Len() == 0 {
		return nil
	}
	currTime := time.Now()
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
func (a *aggregationProcess) addOrUpdateRecordInMap(flowKey *FlowKey, record entities.Record, isIPv4 bool) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	var flowType uint8
	var err error
	if flowTypeIE, _, exist := record.GetInfoElementWithValue("flowType"); exist {
		flowType = flowTypeIE.GetUnsigned8Value()
	} else {
		klog.Warning("FlowType does not exist in current record.")
	}
	correlationRequired := isCorrelationRequired(flowType, record)

	currTime := time.Now()
	aggregationRecord, exist := a.flowKeyRecordMap[*flowKey]
	if exist {
		if correlationRequired {
			// Do correlation of records if record belongs to inter-node flow and
			// records from source and destination node are not received.
			if !aggregationRecord.ReadyToSend && !areRecordsFromSameNode(record, aggregationRecord.Record) {
				if err = a.correlateRecords(record, aggregationRecord.Record); err != nil {
					return err
				}
				aggregationRecord.ReadyToSend = true
				aggregationRecord.areCorrelatedFieldsFilled = true
			}
			// Aggregation of incoming flow record with existing by updating stats
			// and flow timestamps.
			if isRecordFromSrc(record) {
				if err = a.aggregateRecords(record, aggregationRecord.Record, true, false); err != nil {
					return err
				}
			} else {
				if err = a.aggregateRecords(record, aggregationRecord.Record, false, true); err != nil {
					return err
				}
			}
		} else {
			// For flows that do not need correlation, just do aggregation of the
			// flow record with existing record by updating the stats and flow timestamps.
			if err = a.aggregateRecords(record, aggregationRecord.Record, true, true); err != nil {
				return err
			}
		}
		// Reset the inactive expiry time in the queue item with updated aggregate
		// record.
		a.expirePriorityQueue.Update(aggregationRecord.PriorityQueueItem,
			flowKey, aggregationRecord, aggregationRecord.PriorityQueueItem.activeExpireTime, currTime.Add(a.inactiveExpiryTimeout))
	} else {
		// Add all the new stat fields and initialize them.
		if correlationRequired {
			if isRecordFromSrc(record) {
				if err := a.addFieldsForStatsAggregation(record, true, false); err != nil {
					return err
				}
				if err := a.addFieldsForThroughputCalculation(record, true, false); err != nil {
					return err
				}
			} else {
				if err := a.addFieldsForStatsAggregation(record, false, true); err != nil {
					return err
				}
				if err := a.addFieldsForThroughputCalculation(record, false, true); err != nil {
					return err
				}
			}
		} else {
			if err := a.addFieldsForStatsAggregation(record, true, true); err != nil {
				return err
			}
			if err := a.addFieldsForThroughputCalculation(record, true, true); err != nil {
				return err
			}
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
			if flowType == registry.FlowTypeInterNode {
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
	return nil
}

// correlateRecords correlate the incomingRecord with existingRecord using correlation
// fields. This is called for records whose flowType is InterNode(pkg/registry/registry.go).
func (a *aggregationProcess) correlateRecords(incomingRecord, existingRecord entities.Record) error {
	for _, field := range a.correlateFields {
		if ieWithValue, _, exist := incomingRecord.GetInfoElementWithValue(field); exist {
			switch ieWithValue.GetDataType() {
			case entities.String:
				val := ieWithValue.GetStringValue()
				if val != "" {
					existingIeWithValue, _, _ := existingRecord.GetInfoElementWithValue(field)
					existingIeWithValue.SetStringValue(val)
				}
			case entities.Unsigned8:
				val := ieWithValue.GetUnsigned8Value()
				if val != uint8(0) {
					existingIeWithValue, _, _ := existingRecord.GetInfoElementWithValue(field)
					existingIeWithValue.SetUnsigned8Value(val)
				}
			case entities.Unsigned16:
				val := ieWithValue.GetUnsigned16Value()
				if val != uint16(0) {
					existingIeWithValue, _, _ := existingRecord.GetInfoElementWithValue(field)
					existingIeWithValue.SetUnsigned16Value(val)
				}
			case entities.Signed32:
				val := ieWithValue.GetSigned32Value()
				if val != int32(0) {
					existingIeWithValue, _, _ := existingRecord.GetInfoElementWithValue(field)
					existingIeWithValue.SetSigned32Value(val)
				}
			case entities.Ipv4Address:
				val := ieWithValue.GetIPAddressValue()
				ipInString := val.To4().String()
				if ipInString != "0.0.0.0" {
					existingIeWithValue, _, _ := existingRecord.GetInfoElementWithValue(field)
					existingIeWithValue.SetIPAddressValue(val)
				}
			case entities.Ipv6Address:
				val := ieWithValue.GetIPAddressValue()
				ipInString := val.To16().String()
				if ipInString != net.ParseIP("::0").To16().String() {
					existingIeWithValue, _, _ := existingRecord.GetInfoElementWithValue(field)
					existingIeWithValue.SetIPAddressValue(val)
				}
			default:
				klog.Errorf("Fields with dataType %v is not supported in correlation fields list.", ieWithValue.GetDataType())
			}
		}
	}
	return nil
}

// aggregateRecords aggregate the incomingRecord with existingRecord by updating
// stats and flow timestamps.
func (a *aggregationProcess) aggregateRecords(incomingRecord, existingRecord entities.Record, fillSrcStats, fillDstStats bool) error {
	if a.aggregateElements == nil {
		return nil
	}
	isLatest := false
	var prevFlowEndSeconds, flowEndSecondsDiff uint32
	if ieWithValue, _, exist := incomingRecord.GetInfoElementWithValue("flowEndSeconds"); exist {
		if existingIeWithValue, _, exist2 := existingRecord.GetInfoElementWithValue("flowEndSeconds"); exist2 {
			incomingVal := ieWithValue.GetUnsigned32Value()
			existingVal := existingIeWithValue.GetUnsigned32Value()
			if incomingVal >= existingVal {
				isLatest = true
				existingIeWithValue.SetUnsigned32Value(incomingVal)
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
				return nil
			}
			flowEndSecondsDiff = incomingVal - prevFlowEndSeconds
		}
	}
	for _, element := range a.aggregateElements.NonStatsElements {
		if ieWithValue, _, exist := incomingRecord.GetInfoElementWithValue(element); exist {
			existingIeWithValue, _, _ := existingRecord.GetInfoElementWithValue(element)
			switch ieWithValue.GetName() {
			case "flowEndSeconds":
				// Flow end timestamp is already updated.
				break
			case "flowEndReason":
				// If the aggregated flow is set with flowEndReason as "EndOfFlowReason",
				// then we do not have to set again.
				existingVal := existingIeWithValue.GetUnsigned8Value()
				incomingVal := ieWithValue.GetUnsigned8Value()
				if existingVal != registry.EndOfFlowReason {
					existingIeWithValue.SetUnsigned8Value(incomingVal)
				}
			case "tcpState":
				// Update tcpState when flow end timestamp is the latest
				if isLatest {
					incomingVal := ieWithValue.GetStringValue()
					existingIeWithValue.SetStringValue(incomingVal)
				}
			case "httpVals":
				incomingVal := ieWithValue.GetStringValue()
				existingVal := existingIeWithValue.GetStringValue()
				updatedHttpVals, err := fillHttpVals(incomingVal, existingVal)
				if err != nil {
					klog.Errorf("httpVals could not be updated, err: %v", err)
					existingIeWithValue.SetStringValue(incomingVal)
				} else {
					existingIeWithValue.SetStringValue(updatedHttpVals)
				}
			default:
				klog.Errorf("Fields with name %v is not supported in aggregation fields list.", element)
			}
		} else {
			return fmt.Errorf("element with name %v in nonStatsElements not present in the incoming record", element)
		}
	}

	statsElementList := a.aggregateElements.StatsElements
	antreaSourceStatsElements := a.aggregateElements.AggregatedSourceStatsElements
	antreaDestinationStatsElements := a.aggregateElements.AggregatedDestinationStatsElements
	var totalCountDiff, reverseTotalCountDiff uint64
	for i, element := range statsElementList {
		isDelta := strings.Contains(element, "Delta")
		if ieWithValue, _, exist := incomingRecord.GetInfoElementWithValue(element); exist {
			incomingVal := ieWithValue.GetUnsigned64Value()
			// Update the source fields in antreaSourceStatsElements list
			if fillSrcStats {
				if srcExistingIeWithValue, _, exist := existingRecord.GetInfoElementWithValue(antreaSourceStatsElements[i]); exist {
					existingVal := srcExistingIeWithValue.GetUnsigned64Value()
					if !isDelta {
						srcExistingIeWithValue.SetUnsigned64Value(incomingVal)
						switch antreaSourceStatsElements[i] {
						case "octetTotalCountFromSourceNode":
							totalCountDiff = incomingVal - existingVal
						case "reverseOctetTotalCountFromSourceNode":
							reverseTotalCountDiff = incomingVal - existingVal
						}
					} else {
						srcExistingIeWithValue.SetUnsigned64Value(incomingVal + existingVal)
					}
				} else {
					return fmt.Errorf("element does not exist in the record: %v", antreaSourceStatsElements[i])
				}
			}
			// Update the destination fields in antreaDestinationStatsElements list
			if fillDstStats {
				if dstExistingIeWithValue, _, exist := existingRecord.GetInfoElementWithValue(antreaDestinationStatsElements[i]); exist {
					existingVal := dstExistingIeWithValue.GetUnsigned64Value()
					if !isDelta {
						dstExistingIeWithValue.SetUnsigned64Value(incomingVal)
						switch antreaDestinationStatsElements[i] {
						case "octetTotalCountFromDestinationNode":
							totalCountDiff = incomingVal - existingVal
						case "reverseOctetTotalCountFromDestinationNode":
							reverseTotalCountDiff = incomingVal - existingVal
						}
					} else {
						dstExistingIeWithValue.SetUnsigned64Value(incomingVal + existingVal)
					}
				} else {
					return fmt.Errorf("element does not exist in the record: %v", antreaDestinationStatsElements[i])
				}
			}
			// Update the corresponding common element in statsElement list.
			commonExistingIeWithValue, _, _ := existingRecord.GetInfoElementWithValue(element)
			if isLatest {
				if !isDelta {
					if commonExistingIeWithValue.GetUnsigned64Value() < incomingVal {
						commonExistingIeWithValue.SetUnsigned64Value(incomingVal)
					}
				} else {
					if fillSrcStats {
						srcIe, _, _ := existingRecord.GetInfoElementWithValue(antreaSourceStatsElements[i])
						commonExistingIeWithValue.SetUnsigned64Value(srcIe.GetUnsigned64Value())
					}
					if fillDstStats {
						dstIe, _, _ := existingRecord.GetInfoElementWithValue(antreaDestinationStatsElements[i])
						commonExistingIeWithValue.SetUnsigned64Value(dstIe.GetUnsigned64Value())
					}
				}
			}
		} else {
			return fmt.Errorf("element with name %v in statsElements not present in the incoming record", element)
		}
	}

	// Update the throughput & reverseThroughput fields:
	// throughput = (octetTotalCount - prevOctetTotalCount) / (flowEndSeconds - prevFlowEndSeconds)
	// reverseThroughput = (reverseOctetTotalCount - prevReverseOctetTotalCount) / (flowEndSeconds - prevFlowEndSeconds)
	antreaThroughputElements := a.aggregateElements.ThroughputElements
	antreaSourceThroughputElements := a.aggregateElements.SourceThroughputElements
	antreaDestinationThroughputElements := a.aggregateElements.DestinationThroughputElements
	throughput := totalCountDiff * 8 / uint64(flowEndSecondsDiff)
	reverseThroughput := reverseTotalCountDiff * 8 / uint64(flowEndSecondsDiff)
	throughputVals := []uint64{throughput, reverseThroughput}
	for i, element := range antreaThroughputElements {
		if fillSrcStats {
			ie, _, _ := existingRecord.GetInfoElementWithValue(antreaSourceThroughputElements[i])
			ie.SetUnsigned64Value(throughputVals[i])
		}
		if fillDstStats {
			ie, _, _ := existingRecord.GetInfoElementWithValue(antreaDestinationThroughputElements[i])
			ie.SetUnsigned64Value(throughputVals[i])
		}
		if isLatest {
			ie, _, _ := existingRecord.GetInfoElementWithValue(element)
			ie.SetUnsigned64Value(throughputVals[i])
		}
	}
	return nil
}

// ResetStatAndThroughputElementsInRecord is called by the user after the aggregation
// record is sent after its expiry either by active or inactive expiry interval. This
// should be called by user after acquiring the mutex in the Aggregation process.
func (a *aggregationProcess) ResetStatAndThroughputElementsInRecord(record entities.Record) error {
	statsElementList := a.aggregateElements.StatsElements
	antreaSourceStatsElements := a.aggregateElements.AggregatedSourceStatsElements
	antreaDestinationStatsElements := a.aggregateElements.AggregatedDestinationStatsElements
	for i, element := range statsElementList {
		// TotalCount statistic elements should not be reset to zeroes as they are used in the
		// throughput calculation.
		isDelta := strings.Contains(element, "Delta")
		if !isDelta {
			continue
		}
		for _, array := range [][]string{statsElementList, antreaSourceStatsElements, antreaDestinationStatsElements} {
			if ieWithValue, _, exist := record.GetInfoElementWithValue(array[i]); exist {
				ieWithValue.ResetValue()
			} else {
				return fmt.Errorf("element with name %v in statsElements is not present in the record", array[i])
			}
		}
	}
	throughputElements := a.aggregateElements.ThroughputElements
	sourceThroughputElements := a.aggregateElements.SourceThroughputElements
	destinationThroughputElements := a.aggregateElements.DestinationThroughputElements
	for i := range throughputElements {
		for _, array := range [][]string{throughputElements, sourceThroughputElements, destinationThroughputElements} {
			if ieWithValue, _, exist := record.GetInfoElementWithValue(array[i]); exist {
				ieWithValue.ResetValue()
			} else {
				return fmt.Errorf("element with name %v in throughputElements is not present in the record", array[i])
			}
		}
	}
	return nil
}

func (a *aggregationProcess) addFieldsForStatsAggregation(record entities.Record, fillSrcStats, fillDstStats bool) error {
	if a.aggregateElements == nil {
		return nil
	}
	statsElementList := a.aggregateElements.StatsElements
	antreaSourceStatsElements := a.aggregateElements.AggregatedSourceStatsElements
	antreaDestinationStatsElements := a.aggregateElements.AggregatedDestinationStatsElements

	// Initialize the values of newly added stats info elements.
	for i, element := range statsElementList {
		if ieWithValue, _, exist := record.GetInfoElementWithValue(element); exist {
			// Initialize the corresponding source element in antreaStatsElement list.
			value := uint64(0)
			ie, err := registry.GetInfoElement(antreaSourceStatsElements[i], registry.AntreaEnterpriseID)
			if err != nil {
				return err
			}
			if fillSrcStats {
				value = ieWithValue.GetUnsigned64Value()
			}
			if err = record.AddInfoElement(entities.NewUnsigned64InfoElement(ie, value)); err != nil {
				return err
			}

			// Initialize the corresponding destination element in antreaStatsElement list.
			ie, err = registry.GetInfoElement(antreaDestinationStatsElements[i], registry.AntreaEnterpriseID)
			if err != nil {
				return err
			}
			value = uint64(0)
			if fillDstStats {
				value = ieWithValue.GetUnsigned64Value()
			}
			if err = record.AddInfoElement(entities.NewUnsigned64InfoElement(ie, value)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *aggregationProcess) addFieldsForThroughputCalculation(record entities.Record, fillSrcStats, fillDstStats bool) error {
	if a.aggregateElements == nil {
		return nil
	}
	antreaFlowEndSecondsElements := a.aggregateElements.AntreaFlowEndSecondsElements
	antreaThroughputElements := a.aggregateElements.ThroughputElements
	antreaSourceThroughputElements := a.aggregateElements.SourceThroughputElements
	antreaDestinationThroughputElements := a.aggregateElements.DestinationThroughputElements

	var timeStart, timeEnd uint32
	var byteCount, reverseByteCount uint64
	timeStart, err := getUnsigned32ValueByIeName(record, "flowStartSeconds")
	if err != nil {
		return err
	}
	timeEnd, err = getUnsigned32ValueByIeName(record, "flowEndSeconds")
	if err != nil {
		return err
	}
	byteCount, err = getUnsigned64ValueByIeName(record, "octetTotalCount")
	if err != nil {
		return err
	}
	reverseByteCount, err = getUnsigned64ValueByIeName(record, "reverseOctetTotalCount")
	if err != nil {
		return err
	}

	// Initialize flowEndSecondsFromSourceNode and flowEndSecondsFromDestinationNode.
	for _, ieName := range antreaFlowEndSecondsElements {
		ie, err := registry.GetInfoElement(ieName, registry.AntreaEnterpriseID)
		if err != nil {
			return err
		}
		value := uint32(0)
		if (fillSrcStats && strings.Contains(ieName, "Source")) || (fillDstStats && strings.Contains(ieName, "Destination")) {
			value = timeEnd
		}
		if err = record.AddInfoElement(entities.NewUnsigned32InfoElement(ie, value)); err != nil {
			return err
		}
	}

	// Initialize the throughput elements.
	var incomingVal, reverseIncomingVal uint64
	// For the edge case when the record has the same timeEnd and timeStart values,
	// we will initialize the throughput fields with zero values.
	if timeEnd > timeStart {
		incomingVal = byteCount * 8 / (uint64(timeEnd - timeStart))
		reverseIncomingVal = reverseByteCount * 8 / (uint64(timeEnd - timeStart))
	}
	throughputVals := []uint64{incomingVal, reverseIncomingVal}
	for i, element := range antreaThroughputElements {
		// add common throughput elements
		value := throughputVals[i]
		ie, err := registry.GetInfoElement(element, registry.AntreaEnterpriseID)
		if err != nil {
			return err
		}
		if err = record.AddInfoElement(entities.NewUnsigned64InfoElement(ie, value)); err != nil {
			return err
		}
		// add source throughput elements
		value = uint64(0)
		ie, err = registry.GetInfoElement(antreaSourceThroughputElements[i], registry.AntreaEnterpriseID)
		if err != nil {
			return err
		}
		if fillSrcStats {
			value = throughputVals[i]
		}
		if err = record.AddInfoElement(entities.NewUnsigned64InfoElement(ie, value)); err != nil {
			return err
		}
		// add destination throughput elements
		value = uint64(0)
		ie, err = registry.GetInfoElement(antreaDestinationThroughputElements[i], registry.AntreaEnterpriseID)
		if err != nil {
			return err
		}
		if fillDstStats {
			value = throughputVals[i]
		}
		if err = record.AddInfoElement(entities.NewUnsigned64InfoElement(ie, value)); err != nil {
			return err
		}
	}
	return nil
}

// updateFlowEndSecondsFromNodes updates the value of flowEndSecondsFromSourceNode
// or flowEndSecondsFromDestinationNode, returning the previous value before update.
func (a *aggregationProcess) updateFlowEndSecondsFromNodes(incomingRecord, existingRecord entities.Record, isSrc bool, incomingVal uint32) uint32 {
	ieName := "flowEndSecondsFromSourceNode"
	if !isSrc {
		ieName = "flowEndSecondsFromDestinationNode"
	}
	existingIe, _, _ := existingRecord.GetInfoElementWithValue(ieName)
	existingVal := existingIe.GetUnsigned32Value()
	// When the incoming record is the first record from its node, the existingVal of the field
	// is zero, we set it by flowStartSeconds. time_diff = flowEndSeconds - flowStartSeconds
	if existingVal == 0 {
		incomingIe, _, _ := incomingRecord.GetInfoElementWithValue("flowStartSeconds")
		existingVal = incomingIe.GetUnsigned32Value()
	}
	existingIe.SetUnsigned32Value(incomingVal)
	return existingVal
}

// TODO: We can consider to add similar methods into record interface.
func getUnsigned64ValueByIeName(record entities.Record, ieName string) (uint64, error) {
	if ieWithValue, _, exist := record.GetInfoElementWithValue(ieName); exist {
		return ieWithValue.GetUnsigned64Value(), nil
	} else {
		return uint64(0), fmt.Errorf("element with name %s not present in the incoming record", ieName)
	}
}

func getUnsigned32ValueByIeName(record entities.Record, ieName string) (uint32, error) {
	if ieWithValue, _, exist := record.GetInfoElementWithValue(ieName); exist {
		return ieWithValue.GetUnsigned32Value(), nil
	} else {
		return uint32(0), fmt.Errorf("element with name %s not present in the incoming record", ieName)
	}
}

// isRecordFromSrc returns true if record belongs to inter-node flow and from source node.
func isRecordFromSrc(record entities.Record) bool {
	if srcIEWithValue, _, exist := record.GetInfoElementWithValue("sourcePodName"); exist {
		if srcIEWithValue.GetStringValue() == "" {
			return false
		}
	} else {
		return false
	}
	if dstIEWithValue, _, exist := record.GetInfoElementWithValue("destinationPodName"); exist {
		if dstIEWithValue.GetStringValue() != "" {
			return false
		}
	}
	return true
}

// isRecordFromDst returns true if record belongs to inter-node flow and from destination node.
func isRecordFromDst(record entities.Record) bool {
	if dstIEWithValue, _, exist := record.GetInfoElementWithValue("destinationPodName"); exist {
		if dstIEWithValue.GetStringValue() == "" {
			return false
		}
	} else {
		return false
	}
	if srcIEWithValue, _, exist := record.GetInfoElementWithValue("sourcePodName"); exist {
		if srcIEWithValue.GetStringValue() != "" {
			return false
		}
	}
	return true
}

func areRecordsFromSameNode(record1 entities.Record, record2 entities.Record) bool {
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
func getFlowKeyFromRecord(record entities.Record) (*FlowKey, bool, error) {
	flowKey := &FlowKey{}
	elementList := []string{
		"sourceTransportPort",
		"destinationTransportPort",
		"protocolIdentifier",
		"sourceIPv4Address",
		"destinationIPv4Address",
		"sourceIPv6Address",
		"destinationIPv6Address",
	}
	var isSrcIPv4Filled, isDstIPv4Filled bool
	for _, name := range elementList {
		switch name {
		case "sourceTransportPort", "destinationTransportPort":
			element, _, exist := record.GetInfoElementWithValue(name)
			if !exist {
				return nil, false, fmt.Errorf("%s does not exist", name)
			}
			if name == "sourceTransportPort" {
				flowKey.SourcePort = element.GetUnsigned16Value()
			} else {
				flowKey.DestinationPort = element.GetUnsigned16Value()
			}
		case "sourceIPv4Address", "destinationIPv4Address":
			element, _, exist := record.GetInfoElementWithValue(name)
			if !exist {
				break
			}
			if strings.Contains(name, "source") {
				isSrcIPv4Filled = true
				flowKey.SourceAddress = element.GetIPAddressValue().String()
			} else {
				isDstIPv4Filled = true
				flowKey.DestinationAddress = element.GetIPAddressValue().String()
			}
		case "sourceIPv6Address", "destinationIPv6Address":
			element, _, exist := record.GetInfoElementWithValue(name)
			if (isSrcIPv4Filled && strings.Contains(name, "source")) || (isDstIPv4Filled && strings.Contains(name, "destination")) {
				if exist {
					klog.Warning("Two ip versions (IPv4 and IPv6) are not supported for flow key.")
				}
				break
			}
			if !exist {
				return nil, false, fmt.Errorf("%s does not exist", name)
			}
			if strings.Contains(name, "source") {
				flowKey.SourceAddress = element.GetIPAddressValue().String()
			} else {
				flowKey.DestinationAddress = element.GetIPAddressValue().String()
			}
		case "protocolIdentifier":
			element, _, exist := record.GetInfoElementWithValue(name)
			if !exist {
				return nil, false, fmt.Errorf("%s does not exist", name)
			}
			flowKey.Protocol = element.GetUnsigned8Value()
		}
	}
	return flowKey, isSrcIPv4Filled && isDstIPv4Filled, nil
}

func validateDataRecord(record entities.Record) bool {
	return record.GetFieldCount() == uint16(len(record.GetOrderedElementList()))
}

// isCorrelationRequired returns true for InterNode flowType when
// either the egressNetworkPolicyRuleAction is not deny (drop/reject) or
// the ingressNetworkPolicyRuleAction is not reject.
func isCorrelationRequired(flowType uint8, record entities.Record) bool {
	if flowType == registry.FlowTypeInterNode {
		if egressRuleActionIe, _, exist := record.GetInfoElementWithValue("egressNetworkPolicyRuleAction"); exist {
			egressRuleAction := egressRuleActionIe.GetUnsigned8Value()
			if egressRuleAction == registry.NetworkPolicyRuleActionDrop || egressRuleAction == registry.NetworkPolicyRuleActionReject {
				return false
			}
		}
		if ingressRuleActionIe, _, exist := record.GetInfoElementWithValue("ingressNetworkPolicyRuleAction"); exist {
			ingressRuleAction := ingressRuleActionIe.GetUnsigned8Value()
			if ingressRuleAction == registry.NetworkPolicyRuleActionReject {
				return false
			}
		}
		return true
	}
	return false
}

func fillHttpVals(incomingHttpVals, existingHttpVals string) (string, error) {
	incomingHttpValsJson := make(map[int32]string)
	existingHttpValsJson := make(map[int32]string)

	if incomingHttpVals != "" {
		if err := json.Unmarshal([]byte(incomingHttpVals), &incomingHttpValsJson); err != nil {
			return "", fmt.Errorf("error parsing JSON: %v", err)
		}
	}
	if existingHttpVals != "" {
		if err := json.Unmarshal([]byte(existingHttpVals), &existingHttpValsJson); err != nil {
			return "", fmt.Errorf("error parsing JSON: %v", err)
		}
	}
	for key, value := range existingHttpValsJson {
		incomingHttpValsJson[key] = value
	}
	updatedHttpVals, err := json.Marshal(incomingHttpValsJson)
	if err != nil {
		return "", fmt.Errorf("error converting JSON to string: %v", err)
	}
	return string(updatedHttpVals), nil
}
