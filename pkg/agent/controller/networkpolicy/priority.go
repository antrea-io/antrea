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
	"sort"

	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/types"
)

const (
	MaxUint16                = ^uint16(0)
	PolicyBottomPriority     = uint16(100)
	PolicyTopPriority        = uint16(65000)
	zoneOffset               = uint16(5)
	PriorityOffsetSingleTier = float64(640)
	TierOffsetSingleTier     = uint16(0)
	PriorityOffsetMultiTier  = float64(20)
	TierOffsetMultiTier      = uint16(250)
)

// PriorityUpdate stores the original and updated ofPriority of a Priority.
type PriorityUpdate struct {
	Original uint16
	Updated  uint16
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

// InitialOFPriorityGetter is a heuristics function that will map types.Priority to a specific initial
// OpenFlow priority in a table. It is used to space out the priorities in the OVS table and provide an
// initial guess on the OpenFlow priority that can be assigned to the input Priority. If that OpenFlow
// priority is not available, or if the surrounding priorities are out of place, insertConsecutivePriorities()
// will then search for the appropriate OpenFlow priority to insert the input Priority.
type InitialOFPriorityGetter func(p types.Priority, isSingleTier bool) uint16

// InitialOFPriority is an InitialOFPriorityGetter that can be used by OVS tables handling both single
// and multiple Antrea NetworkPolicy Tiers. It computes the initial OpenFlow priority by offsetting
// the tier priority, policy priority and rule priority with pre determined coefficients.
func InitialOFPriority(p types.Priority, isSingleTier bool) uint16 {
	tierOffsetBase := TierOffsetMultiTier
	priorityOffsetBase := PriorityOffsetMultiTier
	if isSingleTier {
		tierOffsetBase = TierOffsetSingleTier
		priorityOffsetBase = PriorityOffsetSingleTier
	}
	tierOffset := tierOffsetBase * uint16(p.TierPriority)
	priorityOffset := uint16(p.PolicyPriority * priorityOffsetBase)
	offSet := tierOffset + priorityOffset + uint16(p.RulePriority)
	// Cannot return a negative OF priority.
	if PolicyTopPriority-PolicyBottomPriority < offSet {
		return PolicyBottomPriority
	}
	return PolicyTopPriority - offSet
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
	// initialOFPriorityFunc determines the initial OpenFlow priority to be checked for input Priorities.
	initialOFPriorityFunc InitialOFPriorityGetter
	// isSingleTier keeps track of if the priorityAssigner is responsible for handling more than one Tier in
	// the OVS table that it manages.
	isSingleTier bool
}

func newPriorityAssigner(initialOFPriorityFunc InitialOFPriorityGetter, isSingleTier bool) *priorityAssigner {
	pa := &priorityAssigner{
		priorityMap:           map[types.Priority]uint16{},
		ofPriorityMap:         map[uint16]types.Priority{},
		sortedPriorities:      []types.Priority{},
		initialOFPriorityFunc: initialOFPriorityFunc,
		isSingleTier:          isSingleTier,
	}
	return pa
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

// getNextVacantOFPriority returns the first higher ofPriority that is currently vacant in the table,
// starting from, but not including, the input ofPriority. It also returns the distance between input
// ofPriority and next vacant ofPriority, as well as all the registered Priorities in between.
func (pa *priorityAssigner) getNextVacantOFPriority(ofPriority uint16) (*uint16, uint16, types.ByPriority) {
	var prioritiesInBetween types.ByPriority
	for i := ofPriority + 1; i <= PolicyTopPriority; i++ {
		p, exists := pa.ofPriorityMap[i]
		if !exists && i <= PolicyTopPriority {
			return &i, i - ofPriority, prioritiesInBetween
		} else {
			prioritiesInBetween = append(prioritiesInBetween, p)
		}
	}
	return nil, MaxUint16, prioritiesInBetween
}

// getLastVacantOFPriority returns the first lower ofPriority that is currently vacant in the table,
// starting from, but not including, the input ofPriority. It also returns the distance between input
// ofPriority and last vacant ofPriority, as well as all the registered Priorities in between.
func (pa *priorityAssigner) getLastVacantOFPriority(ofPriority uint16) (*uint16, uint16, types.ByPriority) {
	var prioritiesInBetween types.ByPriority
	for i := ofPriority - 1; i >= PolicyBottomPriority; i-- {
		p, exists := pa.ofPriorityMap[i]
		if !exists && i >= PolicyBottomPriority {
			sort.Sort(prioritiesInBetween)
			return &i, ofPriority - i, prioritiesInBetween
		} else {
			prioritiesInBetween = append(prioritiesInBetween, p)
		}
	}
	return nil, MaxUint16, prioritiesInBetween
}

// reassignBoundaryPriorities reassigns Priorities from lowerBound / upperBound or both, to make room for
// new Priorities to be registered. It also records all the priority updates due to the reassignment in the
// map updates which is passed to it as parameter.
func (pa *priorityAssigner) reassignBoundaryPriorities(lowerBound, upperBound uint16, prioritiesToRegister types.ByPriority,
	updates map[types.Priority]*PriorityUpdate) error {
	// gap keeps track of the vacant ofPriority thus far between lowerBound and upperBound.
	gap := upperBound - lowerBound - 1
	target := uint16(len(prioritiesToRegister))
	// siftedPrioritiesLow and siftedPrioritiesHigh keeps track of Priorities that needs to be reassigned,
	// below the lowerBound and above the upperBound, respectively.
	var siftedPrioritiesLow, siftedPrioritiesHigh types.ByPriority
	lowerBound, upperBound = lowerBound+1, upperBound-1
	for gap < target {
		lastVacant, costSiftDown, prioritiesDown := pa.getLastVacantOFPriority(lowerBound)
		nextVacant, costSiftUp, prioritiesUp := pa.getNextVacantOFPriority(upperBound)
		if costSiftUp < costSiftDown {
			siftedPrioritiesHigh = append(siftedPrioritiesHigh, prioritiesUp...)
			upperBound = *nextVacant
		} else if costSiftDown < MaxUint16 {
			siftedPrioritiesLow = append(prioritiesDown, siftedPrioritiesLow...)
			lowerBound = *lastVacant
		} else {
			return fmt.Errorf("failed to push boundary priorities to either direction")
		}
		gap++
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
		pa.updatePriorityAssignment(lowerBound+uint16(i), p)
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
func (pa *priorityAssigner) RegisterPriorities(priorities []types.Priority) (map[uint16]uint16, func(), error) {
	// create a zero-length slice with the same underlying array
	prioritiesToRegister := priorities[:0]
	for _, p := range priorities {
		if _, exists := pa.priorityMap[p]; !exists {
			prioritiesToRegister = append(prioritiesToRegister, p)
		}
	}
	numPriorityToRegister := len(prioritiesToRegister)
	if numPriorityToRegister == 0 {
		return nil, nil, nil
	} else if uint16(numPriorityToRegister+len(pa.sortedPriorities)) > PolicyTopPriority-PolicyBottomPriority+1 {
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
// registered Priority that is immediately lower and higher than the inserting Priorities. It then
// decides the range to register new Priorities, and reassign existing ones if necessary.
func (pa *priorityAssigner) insertConsecutivePriorities(priorities types.ByPriority, updates map[types.Priority]*PriorityUpdate) error {
	numPriorities := len(priorities)
	pLow, pHigh := priorities[0], priorities[numPriorities-1]
	insertionPointLow := pa.initialOFPriorityFunc(pLow, pa.isSingleTier)
	insertionPointHigh := pa.initialOFPriorityFunc(pHigh, pa.isSingleTier)
	// get the index for inserting the lowest Priority into the registered Priorities.
	insertionIdx := sort.Search(len(pa.sortedPriorities), func(i int) bool { return pLow.Less(pa.sortedPriorities[i]) })
	upperBound, lowerBound := PolicyTopPriority, PolicyBottomPriority
	if insertionIdx > 0 {
		// set lowerBound to the ofPriority of the registered Priority that is immediately lower than the inserting Priorities.
		lowerBound = pa.priorityMap[pa.sortedPriorities[insertionIdx-1]]
	}
	if insertionIdx < len(pa.sortedPriorities) {
		// set upperBound to the ofPriority of the registered Priority that is immediately higher than the inserting Priorities.
		upperBound = pa.priorityMap[pa.sortedPriorities[insertionIdx]]
	}
	// not enough space to insert Priorities.
	if upperBound-lowerBound-1 <= uint16(numPriorities) {
		return pa.reassignBoundaryPriorities(lowerBound, upperBound, priorities, updates)
	}
	switch {
	// ofPriorities provided by the heuristic function are good.
	case insertionPointLow > lowerBound && insertionPointHigh < upperBound:
		break
	// there are some overlaps between upper/lowerBound and insertionPointLow/High, and the window between
	// upper/lowerBound is large. Assign Priorities by offsetting the upper/lowerBound, depending on where
	// the overlap is. The rational is that overlapped Priorities would most likely to be more adjacent to
	// the registering Priorities.
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
