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

package sets

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/sets"
)

func getStringSets(start, end int) sets.Set[string] {
	s := sets.New[string]()
	for i := start; i < end; i++ {
		s.Insert(fmt.Sprintf("%v", i))
	}
	return s
}

func BenchmarkSymmetricDifferenceString(b *testing.B) {
	s1 := getStringSets(0, 2000)
	s2 := getStringSets(1000, 3000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SymmetricDifferenceString(s1, s2)
	}
}

func TestMergeString(t *testing.T) {
	tests := []struct {
		name string
		src  sets.Set[string]
		dst  sets.Set[string]
		want sets.Set[string]
	}{
		{
			name: "With common items",
			src:  getStringSets(1, 10),
			dst:  getStringSets(5, 15),
			want: getStringSets(1, 15),
		},
		{
			name: "Without common items",
			src:  getStringSets(1, 10),
			dst:  getStringSets(10, 15),
			want: getStringSets(1, 15),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeString(tt.dst, tt.src)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.want, tt.dst)
		})
	}
}

func TestSymmetricDifferenceString(t *testing.T) {
	tests := []struct {
		name string
		s1   sets.Set[string]
		s2   sets.Set[string]
		want sets.Set[string]
	}{
		{
			name: "Equivalent sets",
			s1:   getStringSets(1, 4),
			s2:   getStringSets(1, 4),
			want: sets.New[string](),
		},
		{
			name: "With common items",
			s1:   getStringSets(1, 4),
			s2:   getStringSets(3, 6),
			want: sets.New[string]("1", "2", "4", "5"),
		},
		{
			name: "Without common items",
			s1:   getStringSets(1, 4),
			s2:   getStringSets(4, 8),
			want: getStringSets(1, 8),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SymmetricDifferenceString(tt.s1, tt.s2)
			assert.Equal(t, tt.want, got)
		})
	}
}
