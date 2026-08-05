// Copyright 2026 Antrea Authors
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

package vlan

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// MaxID is the maximum VLAN ID supported by OVS and Antrea.
const MaxID uint16 = 4094

// IDRange is a parsed VLAN ID range. For a single VLAN ID, Start equals End.
type IDRange struct {
	Start uint16
	End   uint16
}

// ParseSpec parses a VLAN specification, either a single VLAN ID or an ID
// range, and validates that it is within the supported VLAN ID range.
func ParseSpec(spec string) (IDRange, error) {
	spec = strings.TrimSpace(spec)
	if startStr, endStr, ok := strings.Cut(spec, "-"); ok {
		start, err := strconv.ParseUint(startStr, 10, 16)
		if err != nil {
			return IDRange{}, fmt.Errorf("invalid VLAN range start %q: %w", startStr, err)
		}
		end, err := strconv.ParseUint(endStr, 10, 16)
		if err != nil {
			return IDRange{}, fmt.Errorf("invalid VLAN range end %q: %w", endStr, err)
		}
		if start > end {
			return IDRange{}, fmt.Errorf("VLAN range start %d is greater than end %d", start, end)
		}
		if end > uint64(MaxID) {
			return IDRange{}, fmt.Errorf("VLAN ID %d is greater than the maximum VLAN ID %d", end, MaxID)
		}
		return IDRange{Start: uint16(start), End: uint16(end)}, nil
	}

	id, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return IDRange{}, fmt.Errorf("invalid VLAN ID %q: %w", spec, err)
	}
	if id > uint64(MaxID) {
		return IDRange{}, fmt.Errorf("VLAN ID %d is greater than the maximum VLAN ID %d", id, MaxID)
	}
	return IDRange{Start: uint16(id), End: uint16(id)}, nil
}

// ExpandSpecs converts VLAN specifications into a sorted, deduplicated flat
// slice of VLAN IDs.
func ExpandSpecs(specs []string) ([]uint16, error) {
	var ids []uint16
	for _, spec := range specs {
		r, err := ParseSpec(spec)
		if err != nil {
			return nil, err
		}
		for id := r.Start; id <= r.End; id++ {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	return ids, nil
}
