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
	"fmt"
	"math"
	"sort"

	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/types"
)

const (
	MaxUint16                    = ^uint16(0)
	zoneOffset                   = uint16(5)
	DefaultTierPriority          = int32(250)
	BaselinePolicyBottomPriority = uint16(10)
	BaselinePolicyTopPriority    = uint16(180)
	PolicyBottomPriority         = uint16(100)
	PolicyTopPriority            = uint16(65000)
	PriorityOffsetBaselineTier   = float64(10)
	TierOffsetBaselineTier       = uint16(0)
	PriorityOffsetMultiTier      = float64(20)
	PriorityOffsetDefaultTier    = float64(100)
	TierOffsetMultiTier          = uint16(200)
)

// PriorityUpdate stores the original and updated ofPriority of a Priority.
type PriorityUpdate struct {
	Original uint16
	Updated  uint16
}

// reassignCost stores the cost of reassigning registered Priorities, if all registered
// Priorities in the lowerBound-upperBound range were to be rearranged.
type reassignCost struct {
	lowerBound uint16
	upperBound uint16
	cost       int
}

// priorityUpdatesToOFUpdates converts a map of Priority and its ofPriority update to a map
// of ofPriority updates.
func priorityUpdatesToOFUpdates(allUpdates map[types.Priority]*PriorityUpdate) map[uint16]uint16 {
	processed := map[uint16]uint16{}
	for _, update := range allUpdates {
		processed[update.Original] = update.Updated
	}
	return processed
}

// priorityAssigner is a struct that maintains the current boundaries of
// all ClusterNetworkPolicy categories/priorities and rule priorities, and knows
// how to re-assign priorities if certain section overflows.
type priorityAssigner struct {
	// priorityMap maintains the current mapping between a known Priority to OpenFlow priority.
	priorityMap map[types.Priority]uint16
	// ofPriorityMap maintains the current mapping of OpenFlow priorities in the table to Priorities.
	ofPriorityMap map[uint16]types.Priority
	// sortedPriorities maintains a list of sorted Priorities currently registered in the table.
	sortedPriorities types.ByPriority
	// isBaselineTier keeps track of if the priorityAssigner is responsible for handling the baseline Tier
	// table (which is shared with K8s NetworkPolicy default tables) or the Antrea Policy tables.
	isBaselineTier bool
	// policyBottomPriority keeps track of the lowest ofPriority allowed for flow creation in the table it manages.
	policyBottomPriority uint16
	// policyTopPriority keeps track of the highest ofPriority allowed for flow creation in the table it manages.
	policyTopPriority uint16
}

func newPriorityAssigner(isBaselineTier bool) *priorityAssigner {
	bottomPriority := PolicyBottomPriority
	topPriority := PolicyTopPriority
	if isBaselineTier {
		bottomPriority = BaselinePolicyBottomPriority
		topPriority = BaselinePolicyTopPriority
	}
	pa := &priorityAssigner{
		priorityMap:          map[types.Priority]uint16{},
		ofPriorityMap:        map[uint16]types.Priority{},
		sortedPriorities:     []types.Priority{},
		isBaselineTier:       isBaselineTier,
		policyBottomPriority: bottomPriority,
		policyTopPriority:    topPriority,
	}
	return pa
}

// initialOFPriority is a heuristic function that will map types.Priority to a specific initial
// OpenFlow priority in a table. It is used to space out the priorities in the OVS table and provide an
// initial guess on the OpenFlow priority that can be assigned to the input Priority. If that OpenFlow
// priority is not available, or if the surrounding priorities are out of place, insertConsecutivePriorities()
// will then search for the appropriate OpenFlow priority to insert the input Priority.
// It computes the initial OpenFlow priority by offsetting the tier priority, policy priority and rule priority
// with pre-determined coefficients.
func (pa *priorityAssigner) initialOFPriority(p types.Priority) uint16 {
	tierOffsetBase := TierOffsetMultiTier
	priorityOffsetBase := PriorityOffsetMultiTier
	if p.TierPriority == DefaultTierPriority {
		priorityOffsetBase = PriorityOffsetDefaultTier
	}
	if pa.isBaselineTier {
		tierOffsetBase = TierOffsetBaselineTier
		priorityOffsetBase = PriorityOffsetBaselineTier
	}
	tierOffset := tierOffsetBase * uint16(p.TierPriority)
	priorityOffset := uint16(p.PolicyPriority * priorityOffsetBase)
	offSet := tierOffset + priorityOffset + uint16(p.RulePriority)
	// Cannot return a negative OF priority.
	if pa.policyTopPriority-pa.policyBottomPriority < offSet {
		return pa.policyBottomPriority
	}
	return pa.policyTopPriority - offSet
}

// updatePriorityAssignment updates all the local maps to correlate input ofPriority and Priority.
func (pa *priorityAssigner) updatePriorityAssignment(ofPriority uint16, p types.Priority) {
	if _, exists := pa.priorityMap[p]; !exists {
		// idx is the insertion point for the newly registered Priority.
		idx := sort.Search(len(pa.sortedPriorities), func(i int) bool { return p.Less(pa.sortedPriorities[i]) })
		pa.sortedPriorities = append(pa.sortedPriorities, types.Priority{})
		// Move elements starting from idx back one position to make room for the inserting Priority.
		copy(pa.sortedPriorities[idx+1:], pa.sortedPriorities[idx:])
		pa.sortedPriorities[idx] = p
	}
	pa.ofPriorityMap[ofPriority] = p
	pa.priorityMap[p] = ofPriority
}

// findReassignBoundaries finds the range to reassign Priorities that minimizes the number of
// registered Priorities to be reassigned.
func (pa *priorityAssigner) findReassignBoundaries(lowerBound, upperBound uint16, numNewPriorities, gap int) (uint16, uint16, error) {
	target := numNewPriorities - gap
	// To reach the target number of slots to be added into the gap, Priorities needs to be sifted upwards or
	// downwards (or both), and empty slots from lower and higher ofPriority space will be swapped into the gap.
	// costMap maintains the costs and reassign boundaries for each combination of lower empty slots used and
	// higher empty slots used, with the sum equals the target. For example, if the target is 2, the maps stores
	//  {0: cost of using 0 lower empty slots and 2 higher empty slots,
	//   1: cost of using 1 lower empty slot and 1 higher empty slot each,
	//   2: cost of using 2 lower empty slots and 0 higher empty slots}
	costMap := map[int]*reassignCost{}
	reassignBoundLow, reassignBoundHigh := lowerBound, upperBound
	costSiftDown, costSiftUp, emptiedSlotsLow, emptiedSlotsHigh := 0, 0, 0, 0
	for reassignBoundLow >= pa.policyBottomPriority && emptiedSlotsLow < target {
		if _, exists := pa.ofPriorityMap[reassignBoundLow]; exists {
			costSiftDown++
		} else {
			emptiedSlotsLow++
			costMap[emptiedSlotsLow] = &reassignCost{reassignBoundLow, upperBound - 1, costSiftDown}
		}
		reassignBoundLow--
	}
	for reassignBoundHigh <= pa.policyTopPriority && emptiedSlotsHigh < target {
		if _, exists := pa.ofPriorityMap[reassignBoundHigh]; exists {
			costSiftUp++
		} else {
			emptiedSlotsHigh++
			// visit costMap in the reverse direction
			mapIndex := target - emptiedSlotsHigh
			c, ok := costMap[mapIndex]
			// only add to the costMap if the counterpart cost is available. i.e. if the target is 4, and cost for
			// using 2 empty slots high is computed, it does not make sense to store this cost if there's no entry
			// for cost that uses 2 empty slots low (indicating no 2 empty slots can be found starting from lowerBound).
			if ok {
				c.cost = costSiftDown + costSiftUp
				c.upperBound = reassignBoundHigh
			} else if mapIndex == 0 {
				costMap[mapIndex] = &reassignCost{lowerBound + 1, reassignBoundHigh, costSiftUp}
			}
		}
		reassignBoundHigh++
	}
	minCost, minCostIndex := math.MaxInt32, 0
	for i := target; i >= 0; i-- {
		if cost, exists := costMap[i]; exists && cost.cost < minCost {
			// make sure that the reassign range adds up to the number of all Priorities to be registered.
			if int(cost.upperBound-cost.lowerBound)+1 == numNewPriorities+cost.cost {
				minCost = cost.cost
				minCostIndex = i
			}
		}
	}
	if minCost == math.MaxInt32 {
		// theoretically this should not happen since Priority overflow is checked earlier.
		return lowerBound, upperBound, fmt.Errorf("failed to push boundary priorities to reach numNewPriorities")
	}
	return costMap[minCostIndex].lowerBound, costMap[minCostIndex].upperBound, nil
}

// reassignBoundaryPriorities reassigns Priorities from lowerBound / upperBound or both, to make room for
// new Priorities to be registered. It also records all the priority updates due to the reassignment in the
// map of updates, which is passed to it as parameter.
func (pa *priorityAssigner) reassignBoundaryPriorities(lowerBound, upperBound uint16, prioritiesToRegister types.ByPriority,
	updates map[types.Priority]*PriorityUpdate) error {
	numNewPriorities, gap := len(prioritiesToRegister), int(upperBound-lowerBound-1)
	low, high, err := pa.findReassignBoundaries(lowerBound, upperBound, numNewPriorities, gap)
	if err != nil {
		return err
	}
	// siftedPrioritiesLow and siftedPrioritiesHigh keep track of Priorities that need to be reassigned,
	// below the lowerBound and above the upperBound respectively.
	var siftedPrioritiesLow, siftedPrioritiesHigh types.ByPriority
	for i := low; i <= lowerBound; i++ {
		if p, exists := pa.ofPriorityMap[i]; exists {
			siftedPrioritiesLow = append(siftedPrioritiesLow, p)
		}
	}
	for i := upperBound; i <= high; i++ {
		if p, exists := pa.ofPriorityMap[i]; exists {
			siftedPrioritiesHigh = append(siftedPrioritiesHigh, p)
		}
	}
	allPriorities := append(siftedPrioritiesLow, prioritiesToRegister...)
	allPriorities = append(allPriorities, siftedPrioritiesHigh...)
	reassignedPriorities := append(siftedPrioritiesLow, siftedPrioritiesHigh...)
	// record the ofPriorities of the reassigned Priorities before the reassignment.
	for _, p := range reassignedPriorities {
		// if exists (the Priority has already been reassigned in a previous step), the original
		// ofPriority of that Priority would have been recorded.
		if _, exists := updates[p]; !exists {
			updates[p] = &PriorityUpdate{Original: pa.priorityMap[p]}
		}
	}
	// assign ofPriorities by the order of siftedPrioritiesLow, prioritiesToRegister and siftedPrioritiesHigh.
	for i, p := range allPriorities {
		pa.updatePriorityAssignment(low+uint16(i), p)
	}
	// record the ofPriorities of the reassigned Priorities after the reassignment.
	for _, p := range reassignedPriorities {
		updates[p].Updated = pa.priorityMap[p]
	}
	return nil
}

// GetOFPriority returns if the Priority is registered with the priorityAssigner,
// and retrieves the corresponding ofPriority.
func (pa *priorityAssigner) GetOFPriority(p types.Priority) (uint16, bool) {
	of, registered := pa.priorityMap[p]
	return of, registered
}

// RegisterPriorities registers a list of Priorities with the priorityAssigner. It allocates ofPriorities for
// input Priorities that are not yet registered. It also returns the ofPriority updates if there are reassignments,
// as well as a revert function that can undo the registration if any error occurred in data plane.
// Note that this function modifies the priorities slice in the parameter, as it only keeps the Priorities which
// this priorityAssigner has not yet registered.
func (pa *priorityAssigner) RegisterPriorities(priorities []types.Priority) (map[uint16]uint16, func(), error) {
	// create a zero-length slice with the same underlying array to save memory usage.
	prioritiesToRegister := priorities[:0]
	for _, p := range priorities {
		if _, exists := pa.priorityMap[p]; !exists {
			prioritiesToRegister = append(prioritiesToRegister, p)
		}
	}
	numPriorityToRegister := len(prioritiesToRegister)
	klog.V(2).Infof("%v new Priorities need to be registered", numPriorityToRegister)
	if numPriorityToRegister == 0 {
		return nil, nil, nil
	} else if uint16(numPriorityToRegister+len(pa.sortedPriorities)) > pa.policyTopPriority-pa.policyBottomPriority+1 {
		return nil, nil, fmt.Errorf("number of priorities to be registered is greater than available openflow priorities")
	}
	sort.Sort(types.ByPriority(prioritiesToRegister))
	var consecutivePriorities [][]types.Priority
	// break the Priorities into lists of consecutive Priorities.
	for i, j := 0, 1; j <= numPriorityToRegister; j++ {
		if j == numPriorityToRegister || !prioritiesToRegister[j].IsConsecutive(prioritiesToRegister[j-1]) {
			consecutivePriorities = append(consecutivePriorities, prioritiesToRegister[i:j])
			i = j
		}
	}
	return pa.registerConsecutivePriorities(consecutivePriorities)
}

// registerConsecutivePriorities registers lists of consecutive Priorities with the priorityAssigner.
func (pa *priorityAssigner) registerConsecutivePriorities(consecutivePriorities [][]types.Priority) (map[uint16]uint16, func(), error) {
	allPriorityUpdates := map[types.Priority]*PriorityUpdate{}
	revertFunc := func() {
		// in case of error, all new Priorities need to be unregistered.
		for _, newPriorities := range consecutivePriorities {
			for _, p := range newPriorities {
				if of, exist := pa.priorityMap[p]; exist {
					pa.unregisterPriority(p)
					pa.deletePriorityMapping(of, p)
				}
			}
		}
		// all reassigned Priorities need to be assigned back to the original ofPriorities.
		for p, update := range allPriorityUpdates {
			if of, ok := pa.priorityMap[p]; ok {
				pa.deletePriorityMapping(of, p)
			}
			pa.ofPriorityMap[update.Original] = p
			pa.priorityMap[p] = update.Original
		}
	}
	for _, priorities := range consecutivePriorities {
		if err := pa.insertConsecutivePriorities(priorities, allPriorityUpdates); err != nil {
			// if failure occurred at any point, revert Priorities registered so far.
			revertFunc()
			return nil, nil, err
		}
	}
	return priorityUpdatesToOFUpdates(allPriorityUpdates), revertFunc, nil
}

// insertConsecutivePriorities inserts a list of consecutive Priorities into the ofPriority space.
// It first identifies the lower and upper bound for insertion, by obtaining the ofPriorities of
// registered Priorities surrounding (immediately lower and higher than) the inserting Priorities.
// It then decides the range to register new Priorities, and reassign existing ones if necessary.
func (pa *priorityAssigner) insertConsecutivePriorities(priorities types.ByPriority, updates map[types.Priority]*PriorityUpdate) error {
	numPriorities := len(priorities)
	pLow, pHigh := priorities[0], priorities[numPriorities-1]
	insertionPointLow := pa.initialOFPriority(pLow)
	insertionPointHigh := pa.initialOFPriority(pHigh)
	// get the index for inserting the lowest Priority into the registered Priorities.
	insertionIdx := sort.Search(len(pa.sortedPriorities), func(i int) bool { return pLow.Less(pa.sortedPriorities[i]) })
	upperBound, lowerBound := pa.policyTopPriority, pa.policyBottomPriority
	if insertionIdx > 0 {
		// set lowerBound to the ofPriority of the registered Priority that is immediately lower than the inserting Priorities.
		lowerBound = pa.priorityMap[pa.sortedPriorities[insertionIdx-1]]
	}
	if insertionIdx < len(pa.sortedPriorities) {
		// set upperBound to the ofPriority of the registered Priority that is immediately higher than the inserting Priorities.
		upperBound = pa.priorityMap[pa.sortedPriorities[insertionIdx]]
	}
	// not enough space to insert Priorities.
	if upperBound-lowerBound-1 < uint16(numPriorities) {
		return pa.reassignBoundaryPriorities(lowerBound, upperBound, priorities, updates)
	}
	switch {
	// ofPriorities provided by the heuristic function are good.
	case insertionPointLow > lowerBound && insertionPointHigh < upperBound:
		break
	// ofPriorities returned by the heuristic function overlap with existing Priorities/are out of place.
	// If the Priorities to be registered overlap with lower Priorities/are lower than the lower Priorities,
	// and the gap between lowerBound and upperBound for insertion is large, then we insert these Priorities
	// above the lowerBound, offsetted by a constant zoneOffset. Vice versa for the other way around.
	// 5 is chosen as the zoneOffset here since it gives some buffer in case Priorities are again created
	// in between those zones, while in the meantime keeps priority assignments compact.
	case upperBound-lowerBound-1 >= uint16(numPriorities)+2*zoneOffset:
		if insertionPointLow <= lowerBound {
			insertionPointLow = lowerBound + zoneOffset + 1
		} else {
			insertionPointLow = upperBound - zoneOffset - uint16(len(priorities))
		}
	// when the window between upper/lowerBound is small, simply put the Priorities in the middle of the window.
	default:
		insertionPointLow = lowerBound + (upperBound-lowerBound-uint16(numPriorities))/2 + 1
	}
	for i := 0; i < len(priorities); i++ {
		pa.updatePriorityAssignment(insertionPointLow+uint16(i), priorities[i])
	}
	return nil
}

// Release removes the priority that currently corresponds to the input OFPriority from the known priorities.
func (pa *priorityAssigner) Release(ofPriority uint16) {
	priority, exists := pa.ofPriorityMap[ofPriority]
	if !exists {
		klog.V(2).Infof("OF priority %v not known, skip releasing priority", ofPriority)
		return
	}
	klog.V(4).Infof("Releasing ofPriority %v", ofPriority)
	pa.deletePriorityMapping(ofPriority, priority)
	pa.unregisterPriority(priority)
}

// deletePriorityMapping removes the Priority <-> ofPriority mapping from the input
func (pa *priorityAssigner) deletePriorityMapping(ofPriority uint16, priority types.Priority) {
	delete(pa.priorityMap, priority)
	delete(pa.ofPriorityMap, ofPriority)
}

// unregisterPriority unregisters the Priority from the known Priorities.
func (pa *priorityAssigner) unregisterPriority(priority types.Priority) {
	idxToDel := sort.Search(len(pa.sortedPriorities), func(i int) bool { return priority.Less(pa.sortedPriorities[i]) }) - 1
	if idxToDel < 0 || !priority.Equals(pa.sortedPriorities[idxToDel]) {
		return
	}
	pa.sortedPriorities = append(pa.sortedPriorities[:idxToDel], pa.sortedPriorities[idxToDel+1:]...)
}
