// Copyright 2019 Antrea Authors
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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewIDAllocator(t *testing.T) {
	tests := []struct {
		name                    string
		args                    []uint32
		expectedLastAllocatedID uint32
		expectedAvailableSets   map[uint32]struct{}
		expectedAvailableSlice  []uint32
	}{
		{
			"zero-allocated-ids",
			nil,
			0,
			map[uint32]struct{}{},
			nil,
		},
		{
			"consecutive-allocated-ids",
			[]uint32{1, 2},
			2,
			map[uint32]struct{}{},
			nil,
		},
		{
			"inconsecutive-allocated-ids",
			[]uint32{2, 7, 5},
			7,
			map[uint32]struct{}{1: {}, 3: {}, 4: {}, 6: {}},
			[]uint32{1, 3, 4, 6},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newIDAllocator(tt.args...)
			assert.Equalf(t, tt.expectedLastAllocatedID, got.lastAllocatedID, "Got lastAllocatedID %v, expected %v", got.lastAllocatedID, tt.expectedLastAllocatedID)
			assert.Equalf(t, tt.expectedAvailableSets, got.availableSet, "Got availableSet %v, expected %v", got.availableSet, tt.expectedAvailableSets)
			assert.Equalf(t, tt.expectedAvailableSlice, got.availableSlice, "Got availableSlice %v, expected %v", got.availableSlice, tt.expectedAvailableSlice)
		})
	}
}

func TestAllocate(t *testing.T) {
	tests := []struct {
		name        string
		args        []uint32
		expectedID  uint32
		expectedErr error
	}{
		{
			"zero-allocated-ids",
			nil,
			1,
			nil,
		},
		{
			"consecutive-allocated-ids",
			[]uint32{1, 2},
			3,
			nil,
		},
		{
			"inconsecutive-allocated-ids",
			[]uint32{1, 7, 5},
			2,
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newIDAllocator(tt.args...)
			actualID, actualErr := a.allocate()
			if actualErr != tt.expectedErr {
				t.Fatalf("Got error %v, expected %v", actualErr, tt.expectedErr)
			}
			assert.Equalf(t, tt.expectedID, actualID, "Got id %v, expected %v", actualID, tt.expectedID)
		})
	}
}

func TestRelease(t *testing.T) {
	tests := []struct {
		name                   string
		newArgs                []uint32
		releaseArgs            uint32
		expectedErr            error
		expectedAvailableSets  map[uint32]struct{}
		expectedAvailableSlice []uint32
	}{
		{
			"duplicate-release",
			[]uint32{2},
			1,
			fmt.Errorf("ID %d has been released, duplicate release is not allowed", 1),
			map[uint32]struct{}{1: {}},
			[]uint32{1},
		},
		{
			"invalid-release",
			[]uint32{1, 2},
			5,
			fmt.Errorf("ID %d was not allocated, can't be released", 5),
			map[uint32]struct{}{},
			nil,
		},
		{
			"valid-release",
			[]uint32{1, 2, 3},
			2,
			nil,
			map[uint32]struct{}{2: {}},
			[]uint32{2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newIDAllocator(tt.newArgs...)
			actualErr := a.release(tt.releaseArgs)
			assert.Equalf(t, tt.expectedErr, actualErr, "Got error %v, expected %v", actualErr, tt.expectedErr)
			assert.Equalf(t, tt.expectedAvailableSets, a.availableSet, "Got availableSet %v, expected %v", a.availableSet, tt.expectedAvailableSets)
			assert.Equalf(t, tt.expectedAvailableSlice, a.availableSlice, "Got availableSlice %v, expected %v", a.availableSlice, tt.expectedAvailableSlice)
		})
	}
}
