// Copyright 2022 Antrea Authors
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

package openflow

import (
	"sync"

	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type GroupAllocator interface {
	Allocate() binding.GroupIDType
	Next() binding.GroupIDType
	Release(id binding.GroupIDType)
}

type groupAllocator struct {
	// mu is a lock for the groupAllocator.
	mu sync.Mutex

	groupIDCounter binding.GroupIDType
	recycled       []binding.GroupIDType
}

// Allocate allocates a new group ID. It allocates id from the "recycled" slices first, then increases the groupIDCounter if no
// recycled ids exist.
func (a *groupAllocator) Allocate() binding.GroupIDType {
	a.mu.Lock()
	defer a.mu.Unlock()
	var id binding.GroupIDType
	if len(a.recycled) != 0 {
		id = a.recycled[len(a.recycled)-1]
		a.recycled = a.recycled[:len(a.recycled)-1]
	} else {
		a.groupIDCounter += 1
		id = a.groupIDCounter
	}
	return id
}

// Next is a readonly method which returns the next available group ID. It's useful in tests to predict the group ID.
func (a *groupAllocator) Next() binding.GroupIDType {
	a.mu.Lock()
	defer a.mu.Unlock()
	var id binding.GroupIDType
	if len(a.recycled) != 0 {
		id = a.recycled[len(a.recycled)-1]
	} else {
		id = a.groupIDCounter + 1
	}
	return id
}

func (a *groupAllocator) Release(id binding.GroupIDType) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.recycled = append(a.recycled, id)
}

func NewGroupAllocator() GroupAllocator {
	return &groupAllocator{}
}
