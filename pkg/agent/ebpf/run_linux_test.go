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

//go:build linux

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeInterfaceChanges(t *testing.T) {
	watched := watchedInterface{name: "eth0", ifIndex: 2, mtu: 1500}
	missing := watched
	missing.missing = true
	tests := []struct {
		name            string
		watched         watchedInterface
		observed        observedInterface
		expectedChanges interfaceChanges
	}{
		{
			name:     "unchanged",
			watched:  watched,
			observed: observedInterface{found: true, ifIndex: 2, mtu: 1500, attached: true},
		},
		{
			name:            "recreated with another index",
			watched:         watched,
			observed:        observedInterface{found: true, ifIndex: 7, mtu: 1500},
			expectedChanges: interfaceChanges{reattach: true},
		},
		{
			name:            "MTU changed",
			watched:         watched,
			observed:        observedInterface{found: true, ifIndex: 2, mtu: 9000, attached: true},
			expectedChanges: interfaceChanges{updateMTU: true},
		},
		{
			name:            "recreated with another index and MTU",
			watched:         watched,
			observed:        observedInterface{found: true, ifIndex: 7, mtu: 9000},
			expectedChanges: interfaceChanges{reattach: true, updateMTU: true},
		},
		{
			name:            "filter removed from an interface which stayed",
			watched:         watched,
			observed:        observedInterface{found: true, ifIndex: 2, mtu: 1500, attached: false},
			expectedChanges: interfaceChanges{reattach: true},
		},
		{
			name:            "gone",
			watched:         watched,
			observed:        observedInterface{},
			expectedChanges: interfaceChanges{gone: true},
		},
		{
			// Reported once, not on every check while it stays gone.
			name:     "still gone",
			watched:  missing,
			observed: observedInterface{},
		},
		{
			// The attachment went with the interface, so a program is attached again even when the new
			// interface has the old index.
			name:            "back with the same index",
			watched:         missing,
			observed:        observedInterface{found: true, ifIndex: 2, mtu: 1500, attached: true},
			expectedChanges: interfaceChanges{reattach: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedChanges, computeInterfaceChanges(tt.watched, tt.observed))
		})
	}
}
