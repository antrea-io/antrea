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
	PriorityBottomCNP     = uint16(100)
	PriorityTopCNP        = uint16(65000)
	InitialPriorityOffset = uint16(640)
	InitialPriorityZones  = 100
)

// InitialOFPriorityGetter is a function that will map types.Priority to a specific initial OpenFlow
// priority in a table. It is used to space out the priorities in the OVS table and provide an initial
// "guess" on the OpenFlow priority that can be assigned to the input Priority. If that OpenFlow
// priority is not available, getInsertionPoint of priorityAssigner will then search for the appropriate
// OpenFlow priority to insert the input Priority.
type InitialOFPriorityGetter func(p types.Priority) uint16

// InitialOFPrioritySingleTierPerTable is an InitialOFPriorityGetter that can be used by OVS tables that
// handles only one Antrea NetworkPolicy Tier. It roughly divides the table into 100 zones and computes
// the initial OpenFlow priority based on rule priority.
func InitialOFPrioritySingleTierPerTable(p types.Priority) uint16 {
	priorityIndex := int32(math.Floor(p.PolicyPriority))
	if priorityIndex > InitialPriorityZones-1 {
		priorityIndex = InitialPriorityZones - 1
	}
	// Cannot return a negative OF priority.
	if PriorityTopCNP-InitialPriorityOffset*uint16(priorityIndex) <= uint16(p.RulePriority) {
		return PriorityBottomCNP
	}
	return PriorityTopCNP - InitialPriorityOffset*uint16(priorityIndex) - uint16(p.RulePriority)
}

// priorityAssigner is a struct that maintains the current mapping between types.Priority and
// OpenFlow priorities in a single OVS table. It also knows how to re-assign priorities if certain section overflows.
type priorityAssigner struct {
	// priorityMap maintains the current mapping of known Priorities to OpenFlow priorities.
	priorityMap map[types.Priority]uint16
	// ofPriorityMap maintains the current mapping of OpenFlow priorities in the table to Priorities.
	ofPriorityMap map[uint16]types.Priority
	// sortedPriorities maintains a slice of sorted OpenFlow priorities in the table that are occupied.
	sortedOFPriorities []uint16
	// initialOFPriorityFunc determines the initial OpenFlow priority to be checked for input Priorities.
	initialOFPriorityFunc InitialOFPriorityGetter
}

func newPriorityAssigner(initialOFPriorityFunc InitialOFPriorityGetter) *priorityAssigner {
	pa := &priorityAssigner{
		priorityMap:           map[types.Priority]uint16{},
		ofPriorityMap:         map[uint16]types.Priority{},
		sortedOFPriorities:    []uint16{},
		initialOFPriorityFunc: initialOFPriorityFunc,
	}
	return pa
}

// updatePriorityAssignment updates all the local maps to correlate input ofPriority and Priority.
// TODO: Add performance benchmark for priority allocation and ways to optimize sortedOFPriorities.
func (pa *priorityAssigner) updatePriorityAssignment(ofPriority uint16, p types.Priority) {
	if _, exists := pa.ofPriorityMap[ofPriority]; !exists {
		// idx is the insertion point for the newly allocated ofPriority.
		idx := sort.Search(len(pa.sortedOFPriorities), func(i int) bool { return ofPriority <= pa.sortedOFPriorities[i] })
		pa.sortedOFPriorities = append(pa.sortedOFPriorities, 0)
		// Move elements starting from idx back one position to make room for the inserting ofPriority.
		copy(pa.sortedOFPriorities[idx+1:], pa.sortedOFPriorities[idx:])
		pa.sortedOFPriorities[idx] = ofPriority
	}
	pa.ofPriorityMap[ofPriority] = p
	pa.priorityMap[p] = ofPriority
}

// getNextOccupiedOFPriority returns the first ofPriority higher than the input ofPriority that is
// currently occupied in the table, as well as the corresponding Priority.
// Note that if the input ofPriority itself is occupied, this function will return that ofPriority
// and the Priority that maps to it currently. The search is based on sortedOFPriorities as it assumes
// the table is sparse in most cases.
func (pa *priorityAssigner) getNextOccupiedOFPriority(ofPriority uint16) (*uint16, *types.Priority) {
	idx := sort.Search(len(pa.sortedOFPriorities), func(i int) bool { return ofPriority <= pa.sortedOFPriorities[i] })
	if idx < len(pa.sortedOFPriorities) {
		nextOccupied := pa.sortedOFPriorities[idx]
		priority := pa.ofPriorityMap[nextOccupied]
		return &nextOccupied, &priority
	}
	return nil, nil
}

// getNextVacantOFPriority returns the first higher ofPriority that is currently vacant in the table,
// starting from the input ofPriority.
// Note that if the input ofPriority itself is vacant, it will simply return that ofPriority.
// The search is incrementally against all ofPriorities available as it assumes the table is sparse in most cases.
func (pa *priorityAssigner) getNextVacantOFPriority(ofPriority uint16) *uint16 {
	for i := ofPriority; i <= PriorityTopCNP; i++ {
		// input ofPriority will be greater than or equal to PriorityBottomCNP
		if _, exists := pa.ofPriorityMap[i]; !exists {
			return &i
		}
	}
	return nil
}

// getLastOccupiedOFPriority returns the first ofPriority lower than the input ofPriority that is
// currently occupied in the table, as well as the corresponded Priority.
// Note that the function must return a ofPriority that is lower than the input ofPriority.
// The search is based on sortedOFPriorities as it assumes the table is sparse in most cases.
func (pa *priorityAssigner) getLastOccupiedOFPriority(ofPriority uint16) (*uint16, *types.Priority) {
	idx := sort.Search(len(pa.sortedOFPriorities), func(i int) bool { return ofPriority <= pa.sortedOFPriorities[i] })
	if idx > 0 {
		lastOccupied := pa.sortedOFPriorities[idx-1]
		priority := pa.ofPriorityMap[lastOccupied]
		return &lastOccupied, &priority
	}
	return nil, nil
}

// getLastVacantOFPriority returns the first lower ofPriority that is currently vacant in the table,
// starting from the ofPriority one below the input.
// The search is incrementally against all ofPriorities available as it assumes the table is sparse in most cases.
func (pa *priorityAssigner) getLastVacantOFPriority(ofPriority uint16) *uint16 {
	for i := ofPriority - 1; i >= PriorityBottomCNP; i-- {
		// ofPriority-1 will be less than or equal to PriorityTopCNP
		if _, exists := pa.ofPriorityMap[i]; !exists {
			return &i
		}
	}
	return nil
}

// upperBoundOk returns if the Priorities *on* and after the input ofPriority are higher than the input Priority.
func (pa *priorityAssigner) upperBoundOk(ofPriority uint16, p types.Priority) bool {
	of, priority := pa.getNextOccupiedOFPriority(ofPriority)
	return of == nil || p.Less(*priority)
}

// lowerBoundOk returns if the Priorities before the input ofPriority are lower than the input Priority.
func (pa *priorityAssigner) lowerBoundOk(ofPriority uint16, p types.Priority) bool {
	of, priority := pa.getLastOccupiedOFPriority(ofPriority)
	return of == nil || priority.Less(p)
}

// getInsertionPoint searches for the ofPriority to insert the input Priority in the table.
// It is guaranteed that the Priorities before the insertionPoint index is lower than the input Priority,
// and Priorities *on* and after the insertionPoint index is higher than the input Priority.
// ofPriority returned will range from PriorityBottomCNP to PriorityTopCNP+1.
func (pa *priorityAssigner) getInsertionPoint(p types.Priority) (uint16, bool) {
	insertionPoint := pa.initialOFPriorityFunc(p)
	occupied, upwardSearching := false, false
Loop:
	for insertionPoint >= PriorityBottomCNP && insertionPoint <= PriorityTopCNP {
		switch {
		case pa.upperBoundOk(insertionPoint, p) && pa.lowerBoundOk(insertionPoint, p):
			if _, occupied = pa.ofPriorityMap[insertionPoint]; occupied && !upwardSearching {
				if insertionPoint != PriorityBottomCNP {
					insertionPoint--
					continue Loop
				}
			}
			break Loop
		case pa.upperBoundOk(insertionPoint, p):
			insertionPoint--
		case pa.lowerBoundOk(insertionPoint, p):
			insertionPoint++
			upwardSearching = true
		}
	}
	return insertionPoint, occupied
}

// reassignPriorities re-arranges current Priority mappings to make place for the inserting Priority. It sifts
// existing priorties up or down based on cost (how many priorities it needs to move). siftPrioritiesDown is used
// as a tie-breaker. An error should only be returned if all the available ofPriorities in the table are occupied.
func (pa *priorityAssigner) reassignPriorities(insertionPoint uint16, p types.Priority) (*uint16, map[uint16]uint16, error) {
	nextVacant, lastVacant := pa.getNextVacantOFPriority(insertionPoint), pa.getLastVacantOFPriority(insertionPoint)
	switch {
	case (insertionPoint == PriorityBottomCNP || lastVacant == nil) && nextVacant != nil:
		return pa.siftPrioritiesUp(insertionPoint, *nextVacant, p)
	case (insertionPoint > PriorityTopCNP || nextVacant == nil) && lastVacant != nil:
		return pa.siftPrioritiesDown(insertionPoint-uint16(1), *lastVacant, p)
	case nextVacant != nil && lastVacant != nil:
		costSiftUp := *nextVacant - insertionPoint
		costSiftDown := insertionPoint - *lastVacant - uint16(1)
		if costSiftUp < costSiftDown {
			return pa.siftPrioritiesUp(insertionPoint, *nextVacant, p)
		} else {
			return pa.siftPrioritiesDown(insertionPoint-uint16(1), *lastVacant, p)
		}
	default:
		return nil, map[uint16]uint16{}, fmt.Errorf("no available Openflow priority left to insert priority %v", p)
	}
}

// siftPrioritiesUp moves all consecutive occupied ofPriorities and corresponding Priorities up by one ofPriority,
// starting from the insertionPoint. It also assigns the freed ofPriority to the input Priority.
func (pa *priorityAssigner) siftPrioritiesUp(insertionPoint, nextVacant uint16, p types.Priority) (*uint16, map[uint16]uint16, error) {
	priorityReassignments := map[uint16]uint16{}
	if insertionPoint >= nextVacant {
		return nil, priorityReassignments, fmt.Errorf("failed to determine the range for sifting priorities up")
	}
	for i := nextVacant; i > insertionPoint; i-- {
		p, _ := pa.ofPriorityMap[i-1]
		pa.updatePriorityAssignment(i, p)
		priorityReassignments[i-1] = i
		klog.V(4).Infof("Original priority %v now needs to be re-assigned %v", i-1, i)
	}
	pa.updatePriorityAssignment(insertionPoint, p)
	return &insertionPoint, priorityReassignments, nil
}

// siftPrioritiesDown moves all consecutive occupied ofPriorities and corresponding Priorities down by one ofPriority,
// starting from the insertionPoint. It also assigns the freed ofPriority to the input Priority.
func (pa *priorityAssigner) siftPrioritiesDown(insertionPoint, lastVacant uint16, p types.Priority) (*uint16, map[uint16]uint16, error) {
	priorityReassignments := map[uint16]uint16{}
	if insertionPoint <= lastVacant {
		return nil, priorityReassignments, fmt.Errorf("failed to determine the range for sifting priorities down")
	}
	for i := lastVacant; i < insertionPoint; i++ {
		p, _ := pa.ofPriorityMap[i+1]
		pa.updatePriorityAssignment(i, p)
		priorityReassignments[i+1] = i
		klog.V(4).Infof("Original priority %v now needs to be re-assigned %v", i+1, i)
	}
	pa.updatePriorityAssignment(insertionPoint, p)
	return &insertionPoint, priorityReassignments, nil
}

// GetOFPriority retrieves the OFPriority for the input Priority to be installed,
// and returns installed priorities that need to be re-assigned if necessary.
func (pa *priorityAssigner) GetOFPriority(p types.Priority) (*uint16, map[uint16]uint16, error) {
	if ofPriority, exists := pa.priorityMap[p]; exists {
		return &ofPriority, nil, nil
	}
	insertionPoint, occupied := pa.getInsertionPoint(p)
	if insertionPoint == PriorityBottomCNP || insertionPoint > PriorityTopCNP || occupied {
		return pa.reassignPriorities(insertionPoint, p)
	}
	pa.updatePriorityAssignment(insertionPoint, p)
	return &insertionPoint, nil, nil
}

// RegisterPriorities registers a list of Priorities to be created with the priorityAssigner.
// It is used to populate the priorityMap in case of batch rule adds.
func (pa *priorityAssigner) RegisterPriorities(priorities []types.Priority) error {
	for _, p := range priorities {
		if _, _, err := pa.GetOFPriority(p); err != nil {
			return err
		}
	}
	return nil
}

// Release removes the priority that currently corresponds to the input OFPriority from the known priorities.
func (pa *priorityAssigner) Release(ofPriority uint16) {
	priority, exists := pa.ofPriorityMap[ofPriority]
	if !exists {
		klog.V(2).Infof("OpenFlow priority %v not known to this table, skip releasing priority", ofPriority)
		return
	}
	delete(pa.priorityMap, priority)
	delete(pa.ofPriorityMap, ofPriority)
	idxToDel := sort.Search(len(pa.sortedOFPriorities), func(i int) bool { return ofPriority <= pa.sortedOFPriorities[i] })
	pa.sortedOFPriorities = append(pa.sortedOFPriorities[:idxToDel], pa.sortedOFPriorities[idxToDel+1:]...)
}
