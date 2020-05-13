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
	"strconv"

	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
)

const (
	PriorityBottomCNP     = uint16(100)
	InitialPriorityOffest = uint16(130)
	InitialPriorityZones  = 100
	DefaultTierStart      = uint16(13100)
)

// PriorityAssigner is an interface that maintains the current boundaries of
// all ClusterNetworkPolicy category/priorities and rule priorities, and knows
// how to re-assgin priorities if certain section overflows.
type PriorityAssigner interface {
	GetOFPriority(r *CompletedRule) (uint16, error)
	Forget(priorityStr string) error
}

// priority is a struct that is composed of CNP priority, rule priority and
// tier/category priority in the future. It is used as the basic unit for
// priority sorting.
type priority struct {
	policyPriority float64
	rulePriority   int32
}

// priorityAssigner implements PriorityAssigner
type priorityAssigner struct {
	// ofClient is the Openflow interface.
	ofClient openflow.Client
	// priorityHash maintains the current mapping between a known CNP priority to OF priority.
	priorityHash map[priority]uint16
	// priorityOffset stores the current size of a priority zone.
	// When tiering is introduced, each tier will keep its own priorityOffset.
	priorityOffset uint16
	// numPriorityZones stores the current number of numPriorityZones (within the default tier).
	// When tiering is introduced, each tier will keep its own numPriorityZones.
	numPriorityZones int32
}

func newPriorityAssinger(ofClient openflow.Client) *priorityAssigner {
	pa := &priorityAssigner{
		ofClient:         ofClient,
		priorityHash:     map[priority]uint16{},
		priorityOffset:   InitialPriorityOffest,
		numPriorityZones: InitialPriorityZones,
	}
	return pa
}

// getPriorityZoneStart returns the priorityZone index and size for the given priority.
// It maps policyPriority [0.0-1.0) to 0, [1.0-2.0) to 1 and so on so forth.
// policyPriorities over 99.0 will be mapped to zone 99, without zone expansion for now.
func (pa *priorityAssigner) getPriorityZoneIndex(p priority) int32 {
	floorPriority := int32(math.Floor(p.policyPriority))
	if floorPriority > pa.numPriorityZones-1 {
		floorPriority = pa.numPriorityZones - 1
	}
	return floorPriority
}

// getPriorityZoneStart returns the starting OF priority for the priorityZone for the input.
func (pa *priorityAssigner) getPriorityZoneStart(p priority) uint16 {
	priorityIndex := pa.getPriorityZoneIndex(p)
	return DefaultTierStart - pa.priorityOffset*uint16(priorityIndex)
}

// getPriorityZoneSize returns the size of the priorityZone for the input.
func (pa *priorityAssigner) getPriorityZoneSize(p priority) uint16 {
	zoneStart := pa.getPriorityZoneStart(p)
	if zoneStart-pa.priorityOffset < PriorityBottomCNP {
		return zoneStart - PriorityBottomCNP
	}
	return pa.priorityOffset
}

// sortPriorities sorts a list of priorities.
func (pa *priorityAssigner) sortPriorities(priorities []priority) {
	sort.Slice(priorities, func(i, j int) bool {
		if priorities[i].policyPriority == priorities[j].policyPriority {
			return priorities[i].rulePriority < priorities[j].rulePriority
		}
		return priorities[i].policyPriority < priorities[j].policyPriority
	})
}

// getIndexSamePriorityZone returns a list of sorted priorities that needs to be present in the same
// priority zone of the input priority, as well as the index of that priority zone.
// It inserts the input priority into the zone if it is a new priority known to the reconciler.
func (pa *priorityAssigner) getIndexSamePriorityZone(p priority, newKey bool) []priority {
	var affected []priority
	if newKey {
		affected = append(affected, p)
	}
	for k := range pa.priorityHash {
		if pa.getPriorityZoneStart(k) == pa.getPriorityZoneStart(p) {
			affected = append(affected, k)
		}
	}
	pa.sortPriorities(affected)
	return affected
}

// syncPriorityZone computes the new expected OF priorties for each priority in the same
// priority zone of the input priority, and calls ReassignActionPriority if necessary.
func (pa *priorityAssigner) syncPriorityZone(p priority, newKey bool) (*uint16, error) {

	// newPriority is the OF priority to be assigned for a new priority.
	// For priority Forget, newPriority returned should be nil.
	var newPriority uint16
	// priorityUpdates stores all the OF priority re-assignments to be performed by client
	priorityUpdates := map[uint16]uint16{}
	// priorityHashUpdates stores all intended updates to priorityHash.
	// The updates will only be committed if no errors arise in priority reassginment
	priorityHashUpdates := make(map[priority]uint16)

	affected := pa.getIndexSamePriorityZone(p, newKey)
	if uint16(len(affected)) > pa.getPriorityZoneSize(p) {
		// TODO: Dynamically adjust priorityZone size to handle overflow
		return nil, fmt.Errorf("priorityZone for [%v %v) has overflowed", pa.getPriorityZoneIndex(p), pa.getPriorityZoneIndex(p)+1)
	}
	for offset, priority := range affected {
		computedPriority := pa.getPriorityZoneStart(p) - uint16(offset)
		// In case where client is forgetting priority, all the affected entries should have isExistingPriorityUpdate true.
		oldOFPriority, isExistingPriorityUpdate := pa.priorityHash[priority]
		if isExistingPriorityUpdate && computedPriority != oldOFPriority {
			klog.V(2).Infof("Original priority %d needs to be reassigned %d now", oldOFPriority, computedPriority)
			priorityUpdates[oldOFPriority] = computedPriority
		} else if !isExistingPriorityUpdate {
			// A new Priority has been added to priorityHash
			newPriority = computedPriority
		}
		priorityHashUpdates[priority] = computedPriority
	}
	if len(priorityUpdates) > 0 {
		err := pa.ofClient.ReassignActionPriority(priorityUpdates)
		if err != nil {
			return nil, err
		}
	}
	// Update priorityHash only if no errors arise in priority reassginment
	for p, newOFPriority := range priorityHashUpdates {
		pa.priorityHash[p] = newOFPriority
	}
	return &newPriority, nil
}

// GetOFPriority retrieves the OFPriority for the input CompleteRule to be installed,
// and re-arrange installed priorities on OVS if necessary.
func (pa *priorityAssigner) GetOFPriority(r *CompletedRule) (*uint16, error) {
	p := priority{policyPriority: *r.PolicyPriority, rulePriority: r.Priority}
	ofPriority, exists := pa.priorityHash[p]
	if !exists {
		return pa.syncPriorityZone(p, true)
	}
	return &ofPriority, nil
}

// Forget removes the priority that currently corresponds to the input OFPriority from the priorityHash,
// and re-arrange installed priorities on OVS if necessary.
func (pa *priorityAssigner) Forget(priorityStr string) error {
	priorityNum, err := strconv.ParseUint(priorityStr, 10, 16)
	if err != nil {
		// Cannot parse the priority str. Theoretically this should never happen.
		return err
	}
	for priorityKey, p := range pa.priorityHash {
		if uint16(priorityNum) == p {
			delete(pa.priorityHash, priorityKey)
			_, err := pa.syncPriorityZone(priorityKey, false)
			return err
		}
	}
	klog.Infof("OF priority %s not stored in hash, skip forgetting priority!", priorityStr)
	return nil
}
