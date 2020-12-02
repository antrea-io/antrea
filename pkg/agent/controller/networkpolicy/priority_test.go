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
	p110  = types.Priority{TierPriority: 1, PolicyPriority: 1, RulePriority: 0}
	p1120 = types.Priority{TierPriority: 1, PolicyPriority: 1.2, RulePriority: 0}
	p1121 = types.Priority{TierPriority: 1, PolicyPriority: 1.2, RulePriority: 1}
	p1130 = types.Priority{TierPriority: 1, PolicyPriority: 1.3, RulePriority: 0}
	p1131 = types.Priority{TierPriority: 1, PolicyPriority: 1.3, RulePriority: 1}
	p1132 = types.Priority{TierPriority: 1, PolicyPriority: 1.3, RulePriority: 2}
	p1133 = types.Priority{TierPriority: 1, PolicyPriority: 1.3, RulePriority: 3}
	p1140 = types.Priority{TierPriority: 1, PolicyPriority: 1.4, RulePriority: 0}
	p1141 = types.Priority{TierPriority: 1, PolicyPriority: 1.4, RulePriority: 1}
	p1142 = types.Priority{TierPriority: 1, PolicyPriority: 1.4, RulePriority: 2}
	p190  = types.Priority{TierPriority: 1, PolicyPriority: 9, RulePriority: 0}
	p191  = types.Priority{TierPriority: 1, PolicyPriority: 9, RulePriority: 1}
	p192  = types.Priority{TierPriority: 1, PolicyPriority: 9, RulePriority: 2}
	p193  = types.Priority{TierPriority: 1, PolicyPriority: 9, RulePriority: 3}
)

func TestUpdatePriorityAssignment(t *testing.T) {
	tests := []struct {
		name                string
		argsPriorities      []types.Priority
		argsOFPriorities    []uint16
		expectedPriorityMap map[types.Priority]uint16
		expectedOFMap       map[uint16]types.Priority
		expectedSorted      types.ByPriority
	}{
		{
			"in-order",
			[]types.Priority{p110, p1120, p1121},
			[]uint16{10000, 9999, 9998},
			map[types.Priority]uint16{p110: 10000, p1120: 9999, p1121: 9998},
			map[uint16]types.Priority{10000: p110, 9999: p1120, 9998: p1121},
			[]types.Priority{p1121, p1120, p110},
		},
		{
			"reverse-order",
			[]types.Priority{p1121, p1120, p110},
			[]uint16{9998, 9999, 10000},
			map[types.Priority]uint16{p110: 10000, p1120: 9999, p1121: 9998},
			map[uint16]types.Priority{10000: p110, 9999: p1120, 9998: p1121},
			[]types.Priority{p1121, p1120, p110},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pa := newPriorityAssigner(false)
			for i := 0; i < len(tt.argsPriorities); i++ {
				pa.updatePriorityAssignment(tt.argsOFPriorities[i], tt.argsPriorities[i])
			}
			assert.Equalf(t, tt.expectedPriorityMap, pa.priorityMap, "Got unexpected priorityMap")
			assert.Equalf(t, tt.expectedOFMap, pa.ofPriorityMap, "Got unexpected ofPriorityMap")
			assert.Equalf(t, tt.expectedSorted, pa.sortedPriorities, "Got unexpected sortedPriorities")
		})
	}
}

func TestReassignBoundaryPriorities(t *testing.T) {
	prioritiesToRegister := []types.Priority{p1133, p1132, p1131, p1130}
	tests := []struct {
		name                 string
		lowerBound           uint16
		upperBound           uint16
		originalPriorities   []types.Priority
		originalOfPriorities []uint16
		expectedPriorityMap  map[types.Priority]uint16
		expectedUpdates      map[types.Priority]*PriorityUpdate
	}{
		{
			"push-down-single",
			10000,
			10001,
			[]types.Priority{p1140, p1121, p1120},
			[]uint16{10000, 10001, 10002},
			map[types.Priority]uint16{
				p1140: 9996, p1133: 9997, p1132: 9998, p1131: 9999, p1130: 10000, p1121: 10001, p1120: 10002},
			map[types.Priority]*PriorityUpdate{p1140: {10000, 9996}},
		},
		{
			"push-down-multiple",
			10000,
			10001,
			[]types.Priority{p190, p1140, p1121, p1120},
			[]uint16{9998, 10000, 10001, 10002},
			map[types.Priority]uint16{
				p190: 9995, p1140: 9996, p1133: 9997, p1132: 9998,
				p1131: 9999, p1130: 10000, p1121: 10001, p1120: 10002},
			map[types.Priority]*PriorityUpdate{
				p1140: {10000, 9996},
				p190:  {9998, 9995},
			},
		},
		{
			"push-up-single",
			10000,
			10002,
			[]types.Priority{p1142, p1141, p1140, p1121},
			[]uint16{9998, 9999, 10000, 10002},
			map[types.Priority]uint16{
				p1142: 9998, p1141: 9999, p1140: 10000, p1133: 10001,
				p1132: 10002, p1131: 10003, p1130: 10004, p1121: 10005},
			map[types.Priority]*PriorityUpdate{p1121: {10002, 10005}},
		},
		{
			"push-up-multiple",
			10000,
			10002,
			[]types.Priority{p1142, p1141, p1140, p1121, p1120},
			[]uint16{9998, 9999, 10000, 10002, 10003},
			map[types.Priority]uint16{
				p1142: 9998, p1141: 9999, p1140: 10000, p1133: 10001,
				p1132: 10002, p1131: 10003, p1130: 10004, p1121: 10005, p1120: 10006},
			map[types.Priority]*PriorityUpdate{
				p1121: {10002, 10005},
				p1120: {10003, 10006},
			},
		},
		{
			"reassign-minimum-possible",
			10000,
			10002,
			[]types.Priority{p193, p192, p191, p190, p1140, p1121, p1120},
			[]uint16{9994, 9995, 9996, 9997, 10000, 10002, 10003},
			map[types.Priority]uint16{
				p193: 9994, p192: 9995, p191: 9996, p190: 9997, p1140: 10000,
				p1133: 10001, p1132: 10002, p1131: 10003, p1130: 10004,
				p1121: 10005, p1120: 10006},
			map[types.Priority]*PriorityUpdate{
				p1121: {10002, 10005},
				p1120: {10003, 10006},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pa := newPriorityAssigner(false)
			for i, p := range tt.originalOfPriorities {
				pa.updatePriorityAssignment(p, tt.originalPriorities[i])
			}
			priorityUpdates := map[types.Priority]*PriorityUpdate{}
			err := pa.reassignBoundaryPriorities(tt.lowerBound, tt.upperBound, prioritiesToRegister, priorityUpdates)
			assert.Equalf(t, nil, err, "Error occurred in reassignment")
			assert.Equalf(t, tt.expectedPriorityMap, pa.priorityMap, "priorityMap unexpected after reassignment")
			assert.Equalf(t, tt.expectedUpdates, priorityUpdates, "priority updates unexpected after reassignment")
		})
	}
}

func TestInsertConsecutivePriorities(t *testing.T) {
	prioritiesToRegister := []types.Priority{p1133, p1132, p1131, p1130}
	pa := newPriorityAssigner(false)
	insertionLow := pa.initialOFPriority(prioritiesToRegister[0])
	insertionHigh := pa.initialOFPriority(prioritiesToRegister[3])
	tests := []struct {
		name                  string
		originalPriorities    []types.Priority
		originalOfPriorities  []uint16
		expectedOFPriorityMap map[uint16]types.Priority
	}{
		{
			"empty-map",
			[]types.Priority{},
			[]uint16{},
			map[uint16]types.Priority{
				insertionLow: p1133, insertionLow + 1: p1132, insertionLow + 2: p1131, insertionHigh: p1130,
			},
		},
		{
			"irrelevant-high-priority",
			[]types.Priority{p110},
			[]uint16{insertionLow + 100},
			map[uint16]types.Priority{
				insertionLow: p1133, insertionLow + 1: p1132, insertionLow + 2: p1131, insertionHigh: p1130,
				insertionLow + 100: p110,
			},
		},
		{
			"irrelevant-low-priority",
			[]types.Priority{p1140},
			[]uint16{insertionLow - 100},
			map[uint16]types.Priority{
				insertionLow - 100: p1140,
				insertionLow:       p1133, insertionLow + 1: p1132, insertionLow + 2: p1131, insertionHigh: p1130,
			},
		},
		{
			"irrelevant-surrounding-priorities",
			[]types.Priority{p1141, p1140, p1121, p1120},
			[]uint16{insertionLow - 100, insertionLow - 99, insertionLow + 99, insertionLow + 100},
			map[uint16]types.Priority{
				insertionLow - 100: p1141, insertionLow - 99: p1140,
				insertionLow: p1133, insertionLow + 1: p1132, insertionLow + 2: p1131, insertionHigh: p1130,
				insertionLow + 99: p1121, insertionLow + 100: p1120,
			},
		},
		{
			"overlapping-low-priorities",
			[]types.Priority{p1141, p1140},
			[]uint16{insertionLow + 1, insertionLow + 2},
			map[uint16]types.Priority{
				insertionLow + 1: p1141, insertionLow + 2: p1140,
				insertionLow + 3 + zoneOffset: p1133, insertionLow + 4 + zoneOffset: p1132,
				insertionLow + 5 + zoneOffset: p1131, insertionLow + 6 + zoneOffset: p1130,
			},
		},
		{
			"overlapping-high-priorities",
			[]types.Priority{p1121, p1120},
			[]uint16{insertionLow + 1, insertionLow + 2},
			map[uint16]types.Priority{
				insertionLow - zoneOffset - 3: p1133, insertionLow - zoneOffset - 2: p1132,
				insertionLow - zoneOffset - 1: p1131, insertionLow - zoneOffset: p1130,
				insertionLow + 1: p1121, insertionLow + 2: p1120,
			},
		},
		{
			"priorities-with-small-gap",
			[]types.Priority{p1141, p1140, p1121, p1120},
			[]uint16{insertionLow + 1, insertionLow + 2, insertionLow + 9, insertionLow + 10},
			map[uint16]types.Priority{
				insertionLow + 1: p1141, insertionLow + 2: p1140,
				insertionLow + 4: p1133, insertionLow + 5: p1132, insertionLow + 6: p1131, insertionLow + 7: p1130,
				insertionLow + 9: p1121, insertionLow + 10: p1120,
			},
		},
		{
			"gap-just-enough-for-insertion",
			[]types.Priority{p1141, p1140, p1121, p1120},
			[]uint16{insertionLow - 1, insertionLow, insertionLow + 5, insertionLow + 6},
			map[uint16]types.Priority{
				insertionLow - 1: p1141, insertionLow: p1140,
				insertionLow + 1: p1133, insertionLow + 2: p1132, insertionLow + 3: p1131, insertionLow + 4: p1130,
				insertionLow + 5: p1121, insertionLow + 6: p1120,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pa := newPriorityAssigner(false)
			for i, p := range tt.originalOfPriorities {
				pa.updatePriorityAssignment(p, tt.originalPriorities[i])
			}
			priorityUpdates := map[types.Priority]*PriorityUpdate{}
			err := pa.insertConsecutivePriorities(prioritiesToRegister, priorityUpdates)
			assert.Equalf(t, nil, err, "Error occurred in priority insertion")
			assert.Equalf(t, tt.expectedOFPriorityMap, pa.ofPriorityMap, "priorityMap unexpected after insertion")
		})
	}
}

func TestRegisterPrioritiesAndRevert(t *testing.T) {
	pa := newPriorityAssigner(false)
	prioritiesToRegister := []types.Priority{p1132, p1131, p1130, p190, p191}
	insertionPoint1132 := pa.initialOFPriority(p1132)
	insertionPoint191 := pa.initialOFPriority(p191)
	pa.updatePriorityAssignment(insertionPoint1132-1, p1140)
	pa.updatePriorityAssignment(insertionPoint1132+2, p1121)
	pa.updatePriorityAssignment(insertionPoint1132+3, p1120)

	expectedOFMapAfterRegister := map[uint16]types.Priority{
		insertionPoint1132 - 2: p1140,
		insertionPoint1132 - 1: p1132, insertionPoint1132: p1131, insertionPoint1132 + 1: p1130,
		insertionPoint1132 + 2: p1121, insertionPoint1132 + 3: p1120,
		insertionPoint191: p191, insertionPoint191 + 1: p190,
	}
	_, revertFunc, err := pa.RegisterPriorities(prioritiesToRegister)
	assert.Equalf(t, nil, err, "Error occurred in priority registration")
	assert.Equalf(t, expectedOFMapAfterRegister, pa.ofPriorityMap, "priorityMap unexpected after registration")

	expectedOFMapAfterRevert := map[uint16]types.Priority{
		insertionPoint1132 - 1: p1140, insertionPoint1132 + 2: p1121, insertionPoint1132 + 3: p1120,
	}
	revertFunc()
	assert.Equalf(t, expectedOFMapAfterRevert, pa.ofPriorityMap, "priorityMap unexpected after revert")
}

func generatePriorities(tierPriority, start, end int32, policyPriority float64) []types.Priority {
	priorities := make([]types.Priority, end-start+1)
	for i := start; i <= end; i++ {
		priorities[i-start] = types.Priority{TierPriority: tierPriority, PolicyPriority: policyPriority, RulePriority: i - start}
	}
	return priorities
}

func TestRegisterAllOFPriorities(t *testing.T) {
	pa := newPriorityAssigner(true)
	maxPriorities := generatePriorities(253, int32(BaselinePolicyBottomPriority), int32(BaselinePolicyTopPriority), 5)
	_, _, err := pa.RegisterPriorities(maxPriorities)
	assert.Equalf(t, nil, err, "Error occurred in registering max number of allowed priorities in baseline tier")

	extraPriority := types.Priority{
		TierPriority:   253,
		PolicyPriority: 5,
		RulePriority:   int32(BaselinePolicyTopPriority) - int32(BaselinePolicyBottomPriority) + 1,
	}
	_, _, err = pa.RegisterPriorities([]types.Priority{extraPriority})
	assert.Errorf(t, err, "Error should be raised after max number of priorities are registered in baseline tier")

	pa = newPriorityAssigner(false)
	consecPriorities1 := generatePriorities(5, int32(PolicyBottomPriority), 10000, 5)
	_, _, err = pa.RegisterPriorities(consecPriorities1)

	assert.Equalf(t, nil, err, "Error occurred before registering max number of allowed priorities")
	consecPriorities2 := generatePriorities(10, 10001, int32(PolicyTopPriority), 5)
	_, _, err = pa.RegisterPriorities(consecPriorities2)
	assert.Equalf(t, nil, err, "Error occurred in registering max number of allowed priorities")

	_, _, err = pa.RegisterPriorities([]types.Priority{extraPriority})
	assert.Errorf(t, err, "Error should be raised after max number of priorities are registered")
}
