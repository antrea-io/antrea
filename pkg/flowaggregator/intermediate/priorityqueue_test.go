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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func makeFlowKey(srcIP, dstIP string, srcPort, dstPort uint16, proto uint8) FlowKey {
	return FlowKey{
		SourceAddress:      srcIP,
		DestinationAddress: dstIP,
		Protocol:           proto,
		SourcePort:         srcPort,
		DestinationPort:    dstPort,
	}
}
func TestTimeToExpirePriorityQueue(t *testing.T) {
	testFlowsMap := []FlowKey{
		makeFlowKey("10.0.0.1", "10.0.0.2", 13001, 8080, 6),
		makeFlowKey("10.0.0.3", "10.0.0.4", 14001, 80, 6),
		makeFlowKey("10.0.0.1", "10.0.0.2", 1300, 8181, 17),
		makeFlowKey("10.0.0.2", "10.0.0.3", 1001, 8888, 17),
	}
	startTime := time.Now()
	testFlowsWithExpire := map[FlowKey][]time.Time{
		testFlowsMap[0]: {startTime.Add(4 * time.Second), startTime.Add(6 * time.Second)},
		testFlowsMap[1]: {startTime.Add(10 * time.Second), startTime.Add(12 * time.Second)},
		testFlowsMap[2]: {startTime.Add(1 * time.Second), startTime.Add(3 * time.Second)},
	}
	testPriorityQueue := make(TimeToExpirePriorityQueue, 0)
	i := 0
	for key, value := range testFlowsWithExpire {
		item := &ItemToExpire{
			flowKey:            &key,
			activeExpireTime:   value[0],
			inactiveExpireTime: value[1],
			index:              i,
		}
		testPriorityQueue = append(testPriorityQueue, item)
		i++
	}
	heap.Init(&testPriorityQueue)
	// Add new flow to the priority queue
	testFlowsWithExpire[testFlowsMap[3]] = []time.Time{startTime.Add(3 * time.Second), startTime.Add(500 * time.Millisecond)}
	newFlowItem := &ItemToExpire{
		flowKey:            &testFlowsMap[3],
		activeExpireTime:   startTime.Add(3 * time.Second),
		inactiveExpireTime: startTime.Add(500 * time.Millisecond),
	}
	heap.Push(&testPriorityQueue, newFlowItem)
	// Test the Peek() function
	flowReadyToExpire := testPriorityQueue.Peek()
	assert.Equalf(t, testFlowsWithExpire[testFlowsMap[3]][0], flowReadyToExpire.activeExpireTime, "Peek() method returns wrong value")
	assert.Equalf(t, testFlowsWithExpire[testFlowsMap[3]][1], flowReadyToExpire.inactiveExpireTime, "Peek() method returns wrong value")
	// Test the Update function
	testPriorityQueue.Update(newFlowItem, &testFlowsMap[3], &AggregationFlowRecord{}, startTime.Add(2*time.Second), startTime.Add(4*time.Second))
	testFlowsWithExpire[testFlowsMap[3]] = []time.Time{startTime.Add(2 * time.Second), startTime.Add(4 * time.Second)}
	assert.Equalf(t, testFlowsWithExpire[testFlowsMap[3]][0], newFlowItem.activeExpireTime, "Update method doesn't work")
	assert.Equalf(t, testFlowsWithExpire[testFlowsMap[3]][1], newFlowItem.inactiveExpireTime, "Update method doesn't work")
	// Test the Pop function
	for testPriorityQueue.Len() > 0 {
		queueLen := testPriorityQueue.Len()
		item := heap.Pop(&testPriorityQueue).(*ItemToExpire)
		switch queueLen {
		case 1:
			assert.Equal(t, testFlowsWithExpire[testFlowsMap[1]][0], item.activeExpireTime)
			assert.Equal(t, testFlowsWithExpire[testFlowsMap[1]][1], item.inactiveExpireTime)
		case 2:
			assert.Equal(t, testFlowsWithExpire[testFlowsMap[0]][0], item.activeExpireTime)
			assert.Equal(t, testFlowsWithExpire[testFlowsMap[0]][1], item.inactiveExpireTime)
		case 3:
			assert.Equal(t, testFlowsWithExpire[testFlowsMap[3]][0], item.activeExpireTime)
			assert.Equal(t, testFlowsWithExpire[testFlowsMap[3]][1], item.inactiveExpireTime)
		case 4:
			assert.Equal(t, testFlowsWithExpire[testFlowsMap[2]][0], item.activeExpireTime)
			assert.Equal(t, testFlowsWithExpire[testFlowsMap[2]][1], item.inactiveExpireTime)
		default:
			t.Fatalf("queue length %v is not valid value", queueLen)
		}
	}
}
