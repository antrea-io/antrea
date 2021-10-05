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
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

var (
	testAsyncDeleteInterval    = 50 * time.Millisecond
	testMinAsyncDeleteInterval = 100 * time.Millisecond
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
			minAsyncDeleteInterval = testMinAsyncDeleteInterval
			got := newIDAllocator(testAsyncDeleteInterval, tt.args...)
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
			minAsyncDeleteInterval = testMinAsyncDeleteInterval
			a := newIDAllocator(testAsyncDeleteInterval, tt.args...)
			actualErr := a.allocateForRule(tt.rule)
			if actualErr != tt.expectedErr {
				t.Fatalf("Got error %v, expected %v", actualErr, tt.expectedErr)
			}
			assert.Equalf(t, tt.expectedID, tt.rule.FlowID, "Got id %v, expected %v", tt.rule.FlowID, tt.expectedID)
			ruleFromCache, exists, err := a.getRuleFromAsyncCache(tt.expectedID)
			assert.Truef(t, exists, "Rule with id %d should present in the async rule cache", tt.expectedID)
			assert.NoErrorf(t, err, "getRuleFromAsyncCache should return valid rule with id: %v", tt.expectedID)
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
			minAsyncDeleteInterval = testMinAsyncDeleteInterval
			a := newIDAllocator(testAsyncDeleteInterval, tt.newArgs...)
			actualErr := a.release(tt.releaseArgs)
			assert.Equalf(t, tt.expectedErr, actualErr, "Got error %v, expected %v", actualErr, tt.expectedErr)
			assert.Equalf(t, tt.expectedAvailableSets, a.availableSet, "Got availableSet %v, expected %v", a.availableSet, tt.expectedAvailableSets)
			assert.Equalf(t, tt.expectedAvailableSlice, a.availableSlice, "Got availableSlice %v, expected %v", a.availableSlice, tt.expectedAvailableSlice)
		})
	}
}

func TestIdAllocatorWorker(t *testing.T) {
	rule := &types.PolicyRule{
		Direction: v1beta2.DirectionIn,
		From:      []types.Address{},
		To:        ofPortsToOFAddresses(sets.NewInt32(1)),
		Service:   nil,
	}
	tests := []struct {
		name                    string
		args                    []uint32
		testAsyncDeleteInterval time.Duration
		expectedDeleteInterval  time.Duration
		rule                    *types.PolicyRule
		expectedID              uint32
	}{
		{
			// testMinAsyncDeleteInterval(100ms) is larger than testAsyncDeleteInterval(50ms),
			// so rule should take at least 100ms to be deleted.
			"delete-rule-with-test-min-async-delete-interval",
			nil,
			50 * time.Millisecond,
			100 * time.Millisecond,
			rule,
			1,
		},
		{
			// testAsyncDeleteInterval(200ms) is larger than testMinAsyncDeleteInterval(100ms),
			// so rule should take at least 200ms to be deleted.
			"delete-rule-with-test-async-delete-interval",
			nil,
			200 * time.Millisecond,
			200 * time.Millisecond,
			rule,
			1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startTime := time.Now()
			expectedDeleteTime := startTime.Add(tt.expectedDeleteInterval)
			fakeClock := clock.NewFakeClock(startTime)
			minAsyncDeleteInterval = testMinAsyncDeleteInterval
			testAsyncDeleteInterval = tt.testAsyncDeleteInterval
			a := newIDAllocatorWithCustomClock(fakeClock, testAsyncDeleteInterval, tt.args...)
			require.NoError(t, a.allocateForRule(tt.rule), "Error allocating ID for rule")
			stopCh := make(chan struct{})
			defer close(stopCh)
			go a.runWorker(stopCh)

			a.forgetRule(tt.rule.FlowID)

			ruleHasBeenDeleted := func() bool {
				a.Lock()
				defer a.Unlock()
				return len(a.availableSlice) > 0
			}

			fakeClock.SetTime(expectedDeleteTime.Add(-10 * time.Millisecond))

			// We wait for a small duration and ensure that the rule is not deleted.
			err := wait.PollImmediate(10*time.Millisecond, 100*time.Millisecond, func() (bool, error) {
				return ruleHasBeenDeleted(), nil
			})
			require.Error(t, err, "Rule ID was unexpectedly released")
			_, exists, err := a.getRuleFromAsyncCache(tt.expectedID)
			require.NoError(t, err)
			assert.True(t, exists, "Rule should be present in asyncRuleCache")

			fakeClock.SetTime(expectedDeleteTime.Add(10 * time.Millisecond))

			err = wait.PollImmediate(10*time.Millisecond, 1*time.Second, func() (bool, error) {
				return ruleHasBeenDeleted(), nil
			})
			require.NoError(t, err, "Rule ID was not released")
			_, exists, err = a.getRuleFromAsyncCache(tt.expectedID)
			require.NoError(t, err)
			assert.False(t, exists, "Rule should not be present in asyncRuleCache")
		})
	}
}
