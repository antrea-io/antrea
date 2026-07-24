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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandSpecs(t *testing.T) {
	tests := []struct {
		name    string
		specs   []string
		want    []uint16
		wantErr string
	}{
		{
			name:  "single VLAN ID",
			specs: []string{"100"},
			want:  []uint16{100},
		},
		{
			name:  "range",
			specs: []string{"100-102"},
			want:  []uint16{100, 101, 102},
		},
		{
			name:  "overlapping ranges and IDs are sorted and deduplicated",
			specs: []string{"200-202", "100", "201", "100-101"},
			want:  []uint16{100, 101, 200, 201, 202},
		},
		{
			name:  "spaces are trimmed",
			specs: []string{" 10 ", " 12-13 "},
			want:  []uint16{10, 12, 13},
		},
		{
			name:    "invalid VLAN ID",
			specs:   []string{"4095"},
			wantErr: "VLAN ID 4095 is greater than the maximum VLAN ID 4094",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExpandSpecs(tc.specs)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
