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

package printers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateTableElementWithSummary(t *testing.T) {
	tests := []struct {
		name            string
		list            []string
		maxColumnLength int
		expected        string
	}{
		{
			name:            "empty list",
			list:            []string{},
			maxColumnLength: 10,
			expected:        "",
		},
		{
			name:            "all elements fit",
			list:            []string{"a", "b", "c"},
			maxColumnLength: 10,
			expected:        "a,b,c",
		},
		{
			name:            "elements are sorted",
			list:            []string{"c", "a", "b"},
			maxColumnLength: 10,
			expected:        "a,b,c",
		},
		{
			name:            "summary fits after the shown elements",
			list:            []string{"a", "b", "cccccccccccccccccccc"},
			maxColumnLength: 20,
			expected:        "a,b + 1 more...",
		},
		{
			name:            "fewer elements are shown to fit the summary",
			list:            []string{"aaaaaaaaaa", "bbbbbbbbbb", "cccccccccc"},
			maxColumnLength: 30,
			expected:        "aaaaaaaaaa + 2 more...",
		},
		{
			name:            "first element does not fit",
			list:            []string{"aaaaaaaaaaaaaaa", "b"},
			maxColumnLength: 10,
			expected:        "aaaaaaaaaaaaaaa + 1 more...",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, GenerateTableElementWithSummary(tt.list, tt.maxColumnLength))
		})
	}
}
