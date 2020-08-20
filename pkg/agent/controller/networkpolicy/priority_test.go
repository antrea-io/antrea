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
	p1140 = types.Priority{TierPriority: 1, PolicyPriority: 1.4, RulePriority: 0}
	p1141 = types.Priority{TierPriority: 1, PolicyPriority: 1.4, RulePriority: 1}
	p1160 = types.Priority{TierPriority: 1, PolicyPriority: 1.6, RulePriority: 0}
	p1161 = types.Priority{TierPriority: 1, PolicyPriority: 1.6, RulePriority: 1}
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
		expectedSorted      []uint16
	}{
		{
			"in-order",
			[]types.Priority{p110, p1120, p1121},
			[]uint16{10000, 9999, 9998},
			map[types.Priority]uint16{p110: 10000, p1120: 9999, p1121: 9998},
			map[uint16]types.Priority{10000: p110, 9999: p1120, 9998: p1121},
			[]uint16{9998, 9999, 10000},
		},
		{
			"reverse-order",
			[]types.Priority{p1121, p1120, p110},
			[]uint16{9998, 9999, 10000},
			map[types.Priority]uint16{p110: 10000, p1120: 9999, p1121: 9998},
			map[uint16]types.Priority{10000: p110, 9999: p1120, 9998: p1121},
			[]uint16{9998, 9999, 10000},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pa := newPriorityAssigner(InitialOFPrioritySingleTierPerTable)
			for i := 0; i < len(tt.argsPriorities); i++ {
				pa.updatePriorityAssignment(tt.argsOFPriorities[i], tt.argsPriorities[i])
			}
			assert.Equalf(t, tt.expectedPriorityMap, pa.priorityMap, "Got unexpected priorityMap")
			assert.Equalf(t, tt.expectedOFMap, pa.ofPriorityMap, "Got unexpected ofPriorityMap")
			assert.Equalf(t, tt.expectedSorted, pa.sortedOFPriorities, "Got unexpected sortedOFPriorities")
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
			p110,
			10000,
			10000,
			false,
		},
		{
			"stepped-on-toes-lower",
			[]types.Priority{p110},
			[]uint16{10000},
			p1120,
			10000,
			9999,
			false,
		},
		{
			"stepped-on-toes-higher",
			[]types.Priority{p1120},
			[]uint16{10000},
			p110,
			10000,
			10001,
			false,
		},
		{
			"search-up",
			[]types.Priority{p1120, p1121, p1130, p1131},
			[]uint16{10000, 9999, 9998, 9997},
			p110,
			9998,
			10001,
			false,
		},
		{
			"search-down",
			[]types.Priority{p1120, p1121, p1130},
			[]uint16{10000, 9999, 9998},
			p1131,
			10000,
			9997,
			false,
		},
		{
			"find-insertion-up",
			[]types.Priority{p110, p1120, p1130, p1131},
			[]uint16{10000, 9999, 9998, 9997},
			p1121,
			9997,
			9999,
			true,
		},
		{
			"find-insertion-down",
			[]types.Priority{p110, p1120, p1130, p1131},
			[]uint16{10000, 9999, 9998, 9997},
			p1121,
			10000,
			9999,
			true,
		},
		{
			"upper-bound",
			[]types.Priority{p1120, p1121, p1130},
			[]uint16{PriorityTopCNP, PriorityTopCNP - 1, PriorityTopCNP - 2},
			p110,
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
			assert.Equalf(t, tt.expectInsertionPoint, got, "Got unexpected insertion point")
			assert.Equalf(t, tt.expectOccupied, occupied, "Insertion point occupied status in unexpected")
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
			[]types.Priority{p191, p193},
			[]uint16{PriorityTopCNP, PriorityTopCNP - 1},
			[]types.Priority{p190, p192},
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
			[]types.Priority{p1130, p1120},
			[]uint16{PriorityBottomCNP, PriorityBottomCNP + 1},
			[]types.Priority{p1121, p1131},
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
			[]types.Priority{p110, p1121, p1131},
			[]uint16{10000, 9999, 9998},
			[]types.Priority{p1130, p1120},
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
				got, updates, _, err := pa.reassignPriorities(tt.insertionPoints[i], tt.insertingPriorities[i])
				assert.Equalf(t, err, nil, "Error occurred in reassigning priorities")
				assert.Equalf(t, tt.expectedAssigned[i], *got, "Got unexpected assigned priority")
				assert.Equalf(t, tt.expectedUpdates[i], updates, "Got unexpected priority updates")
			}
		})
	}
}

func TestRegisterPrioritiesAndRelease(t *testing.T) {
	pa := newPriorityAssigner(InitialOFPrioritySingleTierPerTable)
	err := pa.RegisterPriorities([]types.Priority{
		p110, p1120, p1121, p1140, p1141, p1130, p1160,
	})
	assert.Equalf(t, err, nil, "Error occurred in registering priorities")
	expectedOFMap := map[uint16]types.Priority{
		64360: p110, 64359: p1120, 64358: p1121, 64357: p1130, 64356: p1140, 64355: p1141, 64354: p1160,
	}
	assert.Equalf(t, expectedOFMap, pa.ofPriorityMap, "Got unexpected ofPriorityMap")

	pa.Release(64359)
	pa.Release(64356)
	pa.Release(64354)
	expectedOFMap = map[uint16]types.Priority{
		64360: p110, 64358: p1121, 64357: p1130, 64355: p1141,
	}
	expectedPriorityMap := map[types.Priority]uint16{
		p110: 64360, p1121: 64358, p1130: 64357, p1141: 64355,
	}
	expectedSorted := []uint16{64355, 64357, 64358, 64360}
	assert.Equalf(t, expectedOFMap, pa.ofPriorityMap, "Got unexpected priorityMap")
	assert.Equalf(t, expectedPriorityMap, pa.priorityMap, "Got unexpected ofPriorityMap")
	assert.Equalf(t, expectedSorted, pa.sortedOFPriorities, "Got unexpected sortedOFPriorities")
}

func TestRevertUpdates(t *testing.T) {
	tests := []struct {
		name                string
		insertionPoint      uint16
		extraPriority       types.Priority
		originalPriorityMap map[types.Priority]uint16
		originalOFMap       map[uint16]types.Priority
		originalSorted      []uint16
	}{
		{
			"single-update-up",
			9999,
			p1121,
			map[types.Priority]uint16{p1120: 9999, p1130: 9998},
			map[uint16]types.Priority{9999: p1120, 9998: p1130},
			[]uint16{9998, 9999},
		},
		{
			"multiple-updates-up",
			9997,
			p1131,
			map[types.Priority]uint16{
				p1120: 9999, p1121: 9998, p1130: 9997, p1140: 9996, p1141: 9995, p1160: 9994, p1161: 9993},
			map[uint16]types.Priority{
				9999: p1120, 9998: p1121, 9997: p1130, 9996: p1140, 9995: p1141, 9994: p1160, 9993: p1161},
			[]uint16{9993, 9994, 9995, 9996, 9997, 9998, 9999},
		},
		{
			"single-update-down",
			9999,
			p1121,
			map[types.Priority]uint16{p1120: 10000, p1130: 9999},
			map[uint16]types.Priority{10000: p1120, 9999: p1130},
			[]uint16{9999, 10000},
		},
		{
			"multiple-updates-down",
			9998,
			p1131,
			map[types.Priority]uint16{
				p1120: 10000, p1121: 9999, p1130: 9998, p1140: 9997, p1141: 9996, p1160: 9995},
			map[uint16]types.Priority{
				10000: p1120, 9999: p1121, 9998: p1130, 9997: p1140, 9996: p1141, 9995: p1160},
			[]uint16{9995, 9996, 9997, 9998, 9999, 10000},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pa := newPriorityAssigner(func(p types.Priority) uint16 {
				return tt.insertionPoint
			})
			for ofPriority, p := range tt.originalOFMap {
				pa.updatePriorityAssignment(ofPriority, p)
			}
			_, _, revertFunc, _ := pa.GetOFPriority(tt.extraPriority)
			revertFunc()
			assert.Equalf(t, tt.originalPriorityMap, pa.priorityMap, "Got unexpected priorityMap")
			assert.Equalf(t, tt.originalOFMap, pa.ofPriorityMap, "Got unexpected ofPriorityMap")
			assert.Equalf(t, tt.originalSorted, pa.sortedOFPriorities, "Got unexpected sortedOFPriorities")
		})
	}
}
