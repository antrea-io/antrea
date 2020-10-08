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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
)

const (
	testAsyncDeleteInterval = time.Millisecond * 5
)

func TestNewIDAllocator(t *testing.T) {
	tests := []struct {
		name                    string
		args                    []uint32
		expectedLastAllocatedID uint32
		expectedAvailableSets   map[uint32]struct{}
		expectedAvailableSlice  []uint32
	}{
		{
			"zero-allocated-ids",
			nil,
			0,
			map[uint32]struct{}{},
			nil,
		},
		{
			"consecutive-allocated-ids",
			[]uint32{1, 2},
			2,
			map[uint32]struct{}{},
			nil,
		},
		{
			"inconsecutive-allocated-ids",
			[]uint32{2, 7, 5},
			7,
			map[uint32]struct{}{1: {}, 3: {}, 4: {}, 6: {}},
			[]uint32{1, 3, 4, 6},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newIDAllocator(tt.args...)
			assert.Equalf(t, tt.expectedLastAllocatedID, got.lastAllocatedID, "Got lastAllocatedID %v, expected %v", got.lastAllocatedID, tt.expectedLastAllocatedID)
			assert.Equalf(t, tt.expectedAvailableSets, got.availableSet, "Got availableSet %v, expected %v", got.availableSet, tt.expectedAvailableSets)
			assert.Equalf(t, tt.expectedAvailableSlice, got.availableSlice, "Got availableSlice %v, expected %v", got.availableSlice, tt.expectedAvailableSlice)
		})
	}
}

func TestAllocateForRule(t *testing.T) {
	rule := &types.PolicyRule{
		Direction: v1beta2.DirectionIn,
		From:      []types.Address{},
		To:        ofPortsToOFAddresses(sets.NewInt32(1)),
		Service:   nil,
	}
	tests := []struct {
		name        string
		args        []uint32
		rule        *types.PolicyRule
		expectedID  uint32
		expectedErr error
	}{
		{
			"zero-allocated-ids",
			nil,
			rule,
			1,
			nil,
		},
		{
			"consecutive-allocated-ids",
			[]uint32{1, 2},
			rule,
			3,
			nil,
		},
		{
			"inconsecutive-allocated-ids",
			[]uint32{1, 7, 5},
			rule,
			2,
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newIDAllocator(tt.args...)
			actualErr := a.allocateForRule(tt.rule)
			if actualErr != tt.expectedErr {
				t.Fatalf("Got error %v, expected %v", actualErr, tt.expectedErr)
			}
			assert.Equalf(t, tt.expectedID, tt.rule.FlowID, "Got id %v, expected %v", tt.rule.FlowID, tt.expectedID)
			ruleFromCache, err := a.getRuleFromAsyncCache(tt.expectedID)
			assert.Nilf(t, err, "getRuleFromAsyncCache should return valid rule with id: %v", tt.expectedID)
			assert.Equalf(t, tt.rule, ruleFromCache, "getRuleFromAsyncCache should return expected rule")
		})
	}
}

func TestRelease(t *testing.T) {
	tests := []struct {
		name                   string
		newArgs                []uint32
		releaseArgs            uint32
		expectedErr            error
		expectedAvailableSets  map[uint32]struct{}
		expectedAvailableSlice []uint32
	}{
		{
			"duplicate-release",
			[]uint32{2},
			1,
			fmt.Errorf("ID %d has been released, duplicate release is not allowed", 1),
			map[uint32]struct{}{1: {}},
			[]uint32{1},
		},
		{
			"invalid-release",
			[]uint32{1, 2},
			5,
			fmt.Errorf("ID %d was not allocated, can't be released", 5),
			map[uint32]struct{}{},
			nil,
		},
		{
			"valid-release",
			[]uint32{1, 2, 3},
			2,
			nil,
			map[uint32]struct{}{2: {}},
			[]uint32{2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newIDAllocator(tt.newArgs...)
			actualErr := a.release(tt.releaseArgs)
			assert.Equalf(t, tt.expectedErr, actualErr, "Got error %v, expected %v", actualErr, tt.expectedErr)
			assert.Equalf(t, tt.expectedAvailableSets, a.availableSet, "Got availableSet %v, expected %v", a.availableSet, tt.expectedAvailableSets)
			assert.Equalf(t, tt.expectedAvailableSlice, a.availableSlice, "Got availableSlice %v, expected %v", a.availableSlice, tt.expectedAvailableSlice)
		})
	}
}

func TestWorker(t *testing.T) {
	rule := &types.PolicyRule{
		Direction: v1beta2.DirectionIn,
		From:      []types.Address{},
		To:        ofPortsToOFAddresses(sets.NewInt32(1)),
		Service:   nil,
	}
	tests := []struct {
		name        string
		args        []uint32
		rule        *types.PolicyRule
		expectedID  uint32
		expectedErr error
	}{
		{
			"delete-rule-from-async-rule-cache",
			nil,
			rule,
			1,
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newIDAllocator(tt.args...)
			actualErr := a.allocateForRule(tt.rule)
			if actualErr != tt.expectedErr {
				t.Fatalf("Got error %v, expected %v", actualErr, tt.expectedErr)
			}
			stopCh := make(chan struct{})
			defer close(stopCh)
			go wait.Until(a.worker, time.Millisecond, stopCh)

			a.asyncRuleCache.deleteQueue.AddAfter(tt.rule.FlowID, testAsyncDeleteInterval)
			conditionFunc := func() (bool, error) {
				a.Lock()
				defer a.Unlock()
				if len(a.availableSlice) > 0 {
					return true, nil
				}
				return false, nil
			}
			if err := wait.Poll(time.Millisecond, time.Millisecond * 10, conditionFunc); err != nil {
				t.Fatalf("Expect the rule with id %v to be deleted from async rule cache", tt.expectedID)
			}
			_, err := a.getRuleFromAsyncCache(tt.expectedID)
			assert.NotNilf(t, err, "Expect rule to be not present in asyncRuleCache")
		})
	}
}
