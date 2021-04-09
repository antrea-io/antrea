// Copyright 2021 Antrea Authors
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

package egress

import (
	"container/list"
	"fmt"
	"sync"
)

type idAllocator struct {
	sync.Mutex
	maxID        uint32
	nextID       uint32
	availableIDs *list.List
}

func (a *idAllocator) allocate() (uint32, error) {
	a.Lock()
	defer a.Unlock()

	front := a.availableIDs.Front()
	if front != nil {
		return a.availableIDs.Remove(front).(uint32), nil
	}
	if a.nextID <= a.maxID {
		allocated := a.nextID
		a.nextID += 1
		return allocated, nil
	}
	return 0, fmt.Errorf("no ID available")
}

func (a *idAllocator) release(id uint32) error {
	a.Lock()
	defer a.Unlock()

	a.availableIDs.PushBack(id)
	return nil
}

func newIDAllocator(minID, maxID uint32) *idAllocator {
	availableIDs := list.New()
	return &idAllocator{
		nextID:       minID,
		maxID:        maxID,
		availableIDs: availableIDs,
	}
}
