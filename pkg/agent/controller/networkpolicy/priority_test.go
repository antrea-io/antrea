// Copyright 2020 Antrea Authors
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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vmware-tanzu/antrea/pkg/agent/types"
)

var (
	p111  = types.Priority{TierPriority: 1, PolicyPriority: 1, RulePriority: 0}
	p1121 = types.Priority{TierPriority: 1, PolicyPriority: 1.2, RulePriority: 0}
	p1122 = types.Priority{TierPriority: 1, PolicyPriority: 1.2, RulePriority: 1}
	p1131 = types.Priority{TierPriority: 1, PolicyPriority: 1.3, RulePriority: 0}
	p1132 = types.Priority{TierPriority: 1, PolicyPriority: 1.3, RulePriority: 1}
	p1141 = types.Priority{TierPriority: 1, PolicyPriority: 1.4, RulePriority: 0}
	p1142 = types.Priority{TierPriority: 1, PolicyPriority: 1.4, RulePriority: 1}
	p1161 = types.Priority{TierPriority: 1, PolicyPriority: 1.6, RulePriority: 0}
	p191  = types.Priority{TierPriority: 1, PolicyPriority: 9, RulePriority: 0}
	p192  = types.Priority{TierPriority: 1, PolicyPriority: 9, RulePriority: 1}
	p193  = types.Priority{TierPriority: 1, PolicyPriority: 9, RulePriority: 2}
	p194  = types.Priority{TierPriority: 1, PolicyPriority: 9, RulePriority: 3}
)

func TestUpdatePriorityAssignment(t *testing.T) {
	tests := []struct {
		name                string
		argsPriorities      []types.Priority
		argsOFPriorities    []uint16
		expectedPriorityMap map[types.Priority]uint16
		expectedOFMap       map[uint16]types.Priority
		expectedSorted      []uint16
	}{
		{
			"in-order",
			[]types.Priority{p111, p1121, p1122},
			[]uint16{10000, 9999, 9998},
			map[types.Priority]uint16{p111: 10000, p1121: 9999, p1122: 9998},
			map[uint16]types.Priority{10000: p111, 9999: p1121, 9998: p1122},
			[]uint16{9998, 9999, 10000},
		},
		{
			"reverse-order",
			[]types.Priority{p1122, p1121, p111},
			[]uint16{9998, 9999, 10000},
			map[types.Priority]uint16{p111: 10000, p1121: 9999, p1122: 9998},
			map[uint16]types.Priority{10000: p111, 9999: p1121, 9998: p1122},
			[]uint16{9998, 9999, 10000},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pa := newPriorityAssigner(InitialOFPrioritySingleTierPerTable)
			for i := 0; i < len(tt.argsPriorities); i++ {
				pa.updatePriorityAssignment(tt.argsOFPriorities[i], tt.argsPriorities[i])
			}
			assert.Equalf(t, tt.expectedPriorityMap, pa.priorityMap, "Got priorityMap %v, expected %v", pa.priorityMap, tt.expectedPriorityMap)
			assert.Equalf(t, tt.expectedOFMap, pa.ofPriorityMap, "Got ofPriorityMap %v, expected %v", pa.ofPriorityMap, tt.expectedOFMap)
			assert.Equalf(t, tt.expectedSorted, pa.sortedOFPriorities, "Got sortedOFPriorities %v, expected %v", pa.sortedOFPriorities, tt.expectedSorted)
		})
	}
}

func TestGetInsertionPoint(t *testing.T) {
	tests := []struct {
		name                 string
		argsPriorities       []types.Priority
		argsOFPriorities     []uint16
		insertingPriority    types.Priority
		initialOFPriority    uint16
		expectInsertionPoint uint16
		expectOccupied       bool
	}{
		{
			"spot-on",
			[]types.Priority{},
			[]uint16{},
			p111,
			10000,
			10000,
			false,
		},
		{
			"stepped-on-toes-lower",
			[]types.Priority{p111},
			[]uint16{10000},
			p1121,
			10000,
			9999,
			false,
		},
		{
			"stepped-on-toes-higher",
			[]types.Priority{p1121},
			[]uint16{10000},
			p111,
			10000,
			10001,
			false,
		},
		{
			"search-up",
			[]types.Priority{p1121, p1122, p1131, p1132},
			[]uint16{10000, 9999, 9998, 9997},
			p111,
			9998,
			10001,
			false,
		},
		{
			"search-down",
			[]types.Priority{p1121, p1122, p1131},
			[]uint16{10000, 9999, 9998},
			p1132,
			10000,
			9997,
			false,
		},
		{
			"find-insertion-up",
			[]types.Priority{p111, p1121, p1131, p1132},
			[]uint16{10000, 9999, 9998, 9997},
			p1122,
			9997,
			9999,
			true,
		},
		{
			"find-insertion-down",
			[]types.Priority{p111, p1121, p1131, p1132},
			[]uint16{10000, 9999, 9998, 9997},
			p1122,
			10000,
			9999,
			true,
		},
		{
			"upper-bound",
			[]types.Priority{p1121, p1122, p1131},
			[]uint16{PriorityTopCNP, PriorityTopCNP - 1, PriorityTopCNP - 2},
			p111,
			PriorityTopCNP - 2,
			PriorityTopCNP + 1,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pa := newPriorityAssigner(func(p types.Priority) uint16 {
				return tt.initialOFPriority
			})
			for i := 0; i < len(tt.argsPriorities); i++ {
				pa.updatePriorityAssignment(tt.argsOFPriorities[i], tt.argsPriorities[i])
			}
			got, occupied := pa.getInsertionPoint(tt.insertingPriority)
			assert.Equalf(t, tt.expectInsertionPoint, got, "Got insertion point %v, expected %v", got, tt.expectInsertionPoint)
			assert.Equalf(t, tt.expectOccupied, occupied, "Got insertion point occupied %v, expected %v", got, tt.expectOccupied)
		})
	}
}

func TestReassignPriorities(t *testing.T) {

	tests := []struct {
		name                string
		argsPriorities      []types.Priority
		argsOFPriorities    []uint16
		insertingPriorities []types.Priority
		insertionPoints     []uint16
		expectedAssigned    []uint16
		expectedUpdates     []map[uint16]uint16
	}{
		{
			"sift-down-at-upper-bound",
			[]types.Priority{p192, p194},
			[]uint16{PriorityTopCNP, PriorityTopCNP - 1},
			[]types.Priority{p191, p193},
			[]uint16{PriorityTopCNP + 1, PriorityTopCNP - 1},
			[]uint16{PriorityTopCNP, PriorityTopCNP - 2},
			[]map[uint16]uint16{
				{
					PriorityTopCNP:     PriorityTopCNP - 1,
					PriorityTopCNP - 1: PriorityTopCNP - 2,
				},
				{
					PriorityTopCNP - 2: PriorityTopCNP - 3,
				},
			},
		},
		{
			"sift-up-at-lower-bound",
			[]types.Priority{p1131, p1121},
			[]uint16{PriorityBottomCNP, PriorityBottomCNP + 1},
			[]types.Priority{p1122, p1132},
			[]uint16{PriorityBottomCNP + 1, PriorityBottomCNP},
			[]uint16{PriorityBottomCNP + 1, PriorityBottomCNP},
			[]map[uint16]uint16{
				{
					PriorityBottomCNP + 1: PriorityBottomCNP + 2,
				},
				{
					PriorityBottomCNP:     PriorityBottomCNP + 1,
					PriorityBottomCNP + 1: PriorityBottomCNP + 2,
					PriorityBottomCNP + 2: PriorityBottomCNP + 3,
				},
			},
		},
		{
			"sift-based-on-cost",
			[]types.Priority{p111, p1122, p1132},
			[]uint16{10000, 9999, 9998},
			[]types.Priority{p1131, p1121},
			[]uint16{9999, 10000},
			[]uint16{9998, 10000},
			[]map[uint16]uint16{
				{9998: 9997}, {10000: 10001},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pa := newPriorityAssigner(InitialOFPrioritySingleTierPerTable)
			for i := 0; i < len(tt.argsPriorities); i++ {
				pa.updatePriorityAssignment(tt.argsOFPriorities[i], tt.argsPriorities[i])
			}
			for i := 0; i < len(tt.insertingPriorities); i++ {
				got, updates, err := pa.reassignPriorities(tt.insertionPoints[i], tt.insertingPriorities[i])
				assert.Equalf(t, err, nil, "Error occurred in reassigning priorities")
				assert.Equalf(t, tt.expectedAssigned[i], *got, "Got %v for priority %v, expected %v",
					got, tt.insertingPriorities[i], tt.expectedAssigned[i])
				assert.Equalf(t, tt.expectedUpdates[i], updates, "Got updates %v for priority %v, expected %v",
					updates, tt.insertingPriorities[i], tt.expectedUpdates[i])
			}
		})
	}
}

func TestRegisterPrioritiesAndRelease(t *testing.T) {
	pa := newPriorityAssigner(InitialOFPrioritySingleTierPerTable)
	err := pa.RegisterPriorities([]types.Priority{
		p111, p1121, p1122, p1141, p1142, p1131, p1161,
	})
	assert.Equalf(t, err, nil, "Error occurred in registering priorities")
	expectedOFMap := map[uint16]types.Priority{
		64360: p111, 64359: p1121, 64358: p1122, 64357: p1131, 64356: p1141, 64355: p1142, 64354: p1161,
	}
	assert.Equalf(t, expectedOFMap, pa.ofPriorityMap, "Got ofPriorityMap %v, expected %v", pa.ofPriorityMap, expectedOFMap)

	pa.Release(64359)
	pa.Release(64356)
	pa.Release(64354)
	expectedOFMap = map[uint16]types.Priority{
		64360: p111, 64358: p1122, 64357: p1131, 64355: p1142,
	}
	expectedPriorityMap := map[types.Priority]uint16{
		p111: 64360, p1122: 64358, p1131: 64357, p1142: 64355,
	}
	expectedSorted := []uint16{64355, 64357, 64358, 64360}
	assert.Equalf(t, expectedOFMap, pa.ofPriorityMap, "Got ofPriorityMap %v, expected %v", pa.ofPriorityMap, expectedOFMap)
	assert.Equalf(t, expectedPriorityMap, pa.priorityMap, "Got priorityMap %v, expected %v", pa.priorityMap, expectedPriorityMap)
	assert.Equalf(t, expectedSorted, pa.sortedOFPriorities, "Got sortedOFPriorities %v, expected %v", pa.sortedOFPriorities, expectedSorted)
}
