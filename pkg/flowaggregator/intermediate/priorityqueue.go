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
	"time"
)

type ItemToExpire struct {
	// Flow related info
	flowKey            *FlowKey
	flowRecord         *AggregationFlowRecord
	activeExpireTime   time.Time
	inactiveExpireTime time.Time
	// Index in the priority queue (heap)
	index int
}

type TimeToExpirePriorityQueue []*ItemToExpire

func (pq TimeToExpirePriorityQueue) Len() int {
	return len(pq)
}

func (pq TimeToExpirePriorityQueue) minExpireTime(i int) time.Time {
	if pq[i].activeExpireTime.Before(pq[i].inactiveExpireTime) {
		return pq[i].activeExpireTime
	} else {
		return pq[i].inactiveExpireTime
	}
}

func (pq TimeToExpirePriorityQueue) Less(i, j int) bool {
	return pq.minExpireTime(i).Before(pq.minExpireTime(j))
}

func (pq TimeToExpirePriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *TimeToExpirePriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*ItemToExpire)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *TimeToExpirePriorityQueue) Pop() interface{} {
	n := len(*pq)
	item := (*pq)[n-1]
	item.index = -1
	*pq = (*pq)[0:(n - 1)]
	return item
}

// Peek returns the item at the beginning of the queue, without removing the
// item or otherwise mutating the queue. It is safe to call directly.
func (pq TimeToExpirePriorityQueue) Peek() *ItemToExpire {
	return pq[0]
}

// update modifies the priority and flow record of an Item in the queue.
func (pq *TimeToExpirePriorityQueue) Update(item *ItemToExpire, flowKey *FlowKey, flowRecord *AggregationFlowRecord, activeExpireTime time.Time, inactiveExpireTime time.Time) {
	item.flowKey = flowKey
	item.flowRecord = flowRecord
	item.activeExpireTime = activeExpireTime
	item.inactiveExpireTime = inactiveExpireTime
	heap.Fix(pq, item.index)
}
