// Copyright 2019 Antrea Authors
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

package networkpolicy

import (
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"

	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/types"
)

var (
	minAsyncDeleteInterval = time.Second * 5
)

// idAllocator provides interfaces to allocate and release uint32 IDs. It's thread-safe.
// It caches the last allocated ID and the IDs that have been released.
// If no IDs that have been released, the next allocated IP will be lastAllocatedID+1.
// If there are IDs that have been released, they will be reused FIFO.
type idAllocator struct {
	sync.Mutex
	// lastAllocatedID is the last allocated ID.
	// IDs that are greater than it must be available.
	// IDs that are less than or equal to it are available if they are in availableSet,
	// otherwise unavailable.
	lastAllocatedID uint32

	// availableSet maintains the IDs that can be reused for allocation.
	availableSet map[uint32]struct{}
	// availableSlice maintains the order of release.
	availableSlice []uint32
	// asyncRuleCache maintains rules in a cache and deletes the rules asynchronously
	// after a given delete interval.
	asyncRuleCache cache.Store
	// deleteQueue is used to place a rule ID after a given delay for deleting the
	// the rule in the asyncRuleCache.
	deleteQueue workqueue.DelayingInterface
	// deleteInterval is the delay interval for deleting the rule in the asyncRuleCache.
	deleteInterval time.Duration
}

// asyncRuleCacheKeyFunc knows how to get key of a *rule.
func asyncRuleCacheKeyFunc(obj interface{}) (string, error) {
	rule := obj.(*types.PolicyRule)
	return strconv.Itoa(int(rule.FlowID)), nil
}

// newIDAllocator returns a new *idAllocator.
// It takes a list of allocated IDs, which can be used for the restart case.
func newIDAllocator(asyncRuleDeleteInterval time.Duration, allocatedIDs ...uint32) *idAllocator {
	allocator := &idAllocator{
		availableSet:   make(map[uint32]struct{}),
		asyncRuleCache: cache.NewStore(asyncRuleCacheKeyFunc),
		deleteQueue:    workqueue.NewNamedDelayingQueue("async_delete_networkpolicyrule"),
	}

	// Set the deleteInterval.
	if minAsyncDeleteInterval > asyncRuleDeleteInterval {
		allocator.deleteInterval = minAsyncDeleteInterval
	} else {
		allocator.deleteInterval = asyncRuleDeleteInterval
	}

	var maxID uint32
	allocatedSet := make(map[uint32]struct{}, len(allocatedIDs))
	for _, id := range allocatedIDs {
		allocatedSet[id] = struct{}{}
		if id > maxID {
			maxID = id
		}
	}
	for id := uint32(1); id < maxID; id++ {
		if _, exists := allocatedSet[id]; !exists {
			allocator.availableSet[id] = struct{}{}
			allocator.availableSlice = append(allocator.availableSlice, id)
		}
	}
	allocator.lastAllocatedID = maxID
	return allocator
}

// allocateForRule allocates an uint32 ID for a given rule if it's available, otherwise
// an error is returned. It will try to reuse the IDs that have been released first,
// then allocate a new ID by incrementing the last allocated one.
func (a *idAllocator) allocateForRule(rule *types.PolicyRule) error {
	a.Lock()
	defer a.Unlock()

	if len(a.availableSlice) > 0 {
		var id uint32
		id, a.availableSlice = a.availableSlice[0], a.availableSlice[1:]
		delete(a.availableSet, id)

		// Add ID to the rule and the rule to asyncRuleCache.
		rule.FlowID = id
		a.asyncRuleCache.Add(rule)

		return nil
	}
	if a.lastAllocatedID == math.MaxUint32 {
		return fmt.Errorf("no ID available")
	}
	a.lastAllocatedID++

	// Add ID to the rule and the rule to asyncRuleCache.
	rule.FlowID = a.lastAllocatedID
	a.asyncRuleCache.Add(rule)

	return nil
}

// forgetRule adds the rule to the async delete queue with a given delay.
func (a *idAllocator) forgetRule(ruleID uint32) {
	a.deleteQueue.AddAfter(ruleID, a.deleteInterval)
}

func (a *idAllocator) getRuleFromAsyncCache(ruleID uint32) (*types.PolicyRule, bool, error) {
	rule, exists, err := a.asyncRuleCache.GetByKey(strconv.Itoa(int(ruleID)))
	if err != nil || !exists {
		return nil, exists, err
	}
	return rule.(*types.PolicyRule), exists, nil
}

// worker runs a worker thread that just dequeues item from deleteQueue,
// deletes them from the asyncRuleCache, and releases the associated ID.
func (a *idAllocator) worker() {
	for a.processDeleteQueueItem() {
	}
}

func (a *idAllocator) processDeleteQueueItem() bool {
	key, quit := a.deleteQueue.Get()
	if quit {
		return false
	}
	defer a.deleteQueue.Done(key)

	rule, exists, err := a.getRuleFromAsyncCache(key.(uint32))
	if !exists {
		klog.Warningf("Rule with id %v is not present in the async rule cache", key.(uint32))
		return true
	}
	if err != nil {
		klog.Errorf("Unexpected error when trying to get rule with id %d: %v", key.(uint32), err)
		return true
	}
	if err := a.asyncRuleCache.Delete(rule); err != nil {
		klog.Errorf("Unexpected error when trying to delete rule: %v", err)
		return true
	}

	if err := a.release(key.(uint32)); err != nil {
		klog.Errorf("Unexpected error when releasing id %d: %v", key.(uint32), err)
		return true
	}

	return true
}

// release releases an uint32 ID if it has been allocated before, otherwise error is returned.
func (a *idAllocator) release(id uint32) error {
	a.Lock()
	defer a.Unlock()

	if _, exists := a.availableSet[id]; exists {
		return fmt.Errorf("ID %d has been released, duplicate release is not allowed", id)
	}
	if id > a.lastAllocatedID {
		return fmt.Errorf("ID %d was not allocated, can't be released", id)
	}
	a.availableSet[id] = struct{}{}
	a.availableSlice = append(a.availableSlice, id)
	return nil
}
