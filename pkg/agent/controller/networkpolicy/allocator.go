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

	"github.com/vmware-tanzu/antrea/pkg/agent/types"
)

const (
	asyncDeleteInterval = time.Second * 5
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
	asyncRuleCache *asyncRuleCache
}

// newIDAllocator returns a new *idAllocator.
// It takes a list of allocated IDs, which can be used for the restart case.
func newIDAllocator(allocatedIDs ...uint32) *idAllocator {
	allocator := &idAllocator{
		availableSet:   make(map[uint32]struct{}),
		asyncRuleCache: NewAsyncRuleCache(),
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
		a.asyncRuleCache.rules.Add(rule)

		return nil
	}
	if a.lastAllocatedID == math.MaxUint32 {
		return fmt.Errorf("no ID available")
	}
	a.lastAllocatedID++

	// Add ID to the rule and the rule to asyncRuleCache.
	rule.FlowID = a.lastAllocatedID
	a.asyncRuleCache.rules.Add(rule)

	return nil
}

// forgetRule adds the rule to the async delete queue with a given delay.
func (a *idAllocator) forgetRule(ruleID uint32) {
	a.asyncRuleCache.deleteQueue.AddAfter(ruleID, asyncDeleteInterval)
}

func (a *idAllocator) getRuleFromAsyncCache(ruleID uint32) (*types.PolicyRule, error) {
	rule, exists, err := a.asyncRuleCache.rules.GetByKey(strconv.Itoa(int(ruleID)))
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("rule is not present in async rule cache")
	}
	return rule.(*types.PolicyRule), nil
}

// worker runs a worker thread that just dequeues item from asyncRuleCache.deleteQueue,
// deletes them from asyncRuleCache, and releases the associated ID.
func (a *idAllocator) worker() {
	for a.processDeleteQueueItem() {
	}
}

func (a *idAllocator) processDeleteQueueItem() bool {
	key, quit := a.asyncRuleCache.deleteQueue.Get()
	if quit {
		return false
	}
	defer a.asyncRuleCache.deleteQueue.Done(key)

	rule, err := a.getRuleFromAsyncCache(key.(uint32))
	if err != nil {
		return false
	}
	if err := a.asyncRuleCache.rules.Delete(rule); err != nil {
		return false
	}

	if err := a.release(key.(uint32)); err != nil {
		return false
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

// asyncRuleCache maintains asynchronous NetworkPolicy rule cache with ID as the key.
type asyncRuleCache struct {
	rules       cache.Store
	deleteQueue workqueue.DelayingInterface
}

// asyncRuleCacheKeyFunc knows how to get key of a *rule.
func asyncRuleCacheKeyFunc(obj interface{}) (string, error) {
	rule := obj.(*types.PolicyRule)
	return strconv.Itoa(int(rule.FlowID)), nil
}

func NewAsyncRuleCache() *asyncRuleCache {
	return &asyncRuleCache{
		rules:       cache.NewStore(asyncRuleCacheKeyFunc),
		deleteQueue: workqueue.NewNamedDelayingQueue("async_delete_networkpolicyrule"),
	}
}
