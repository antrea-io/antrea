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
	Release(id binding.GroupIDType)
}

type BucketAllocator interface {
	Allocate() binding.BucketIDType
	Release(id binding.BucketIDType)
}

type groupAllocator struct {
	// mu is a lock for the groupAllocator.
	mu sync.Mutex

	groupIDCounter binding.GroupIDType
	recycled       []binding.GroupIDType
}

type bucketAllocator struct {
	// mu is a lock for the bucketAllocator.
	mu sync.Mutex

	bucketIDCounter binding.BucketIDType
	recycled        []binding.BucketIDType
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

func (a *groupAllocator) Release(id binding.GroupIDType) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.recycled = append(a.recycled, id)
}

func NewGroupAllocator(isIPv6 bool) GroupAllocator {
	var groupIDCounter binding.GroupIDType
	if isIPv6 {
		groupIDCounter = 0x10000000
	}
	return &groupAllocator{groupIDCounter: groupIDCounter}
}

// Allocate allocates a new bucket ID. It allocates id from the "recycled" slices first, then increases the bucketIDCounter if no
// recycled ids exist.
func (a *bucketAllocator) Allocate() binding.BucketIDType {
	a.mu.Lock()
	defer a.mu.Unlock()
	var id binding.BucketIDType
	if len(a.recycled) != 0 {
		id = a.recycled[len(a.recycled)-1]
		a.recycled = a.recycled[:len(a.recycled)-1]
	} else {
		a.bucketIDCounter += 1
		id = a.bucketIDCounter
	}
	return id
}

func (a *bucketAllocator) Release(id binding.BucketIDType) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.recycled = append(a.recycled, id)
}

func NewBucketAllocator() BucketAllocator {
	return &bucketAllocator{}
}
