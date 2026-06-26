// Copyright 2025 Antrea Authors
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

func newStringSetRange(start, end int) sets.Set[string] {
	s := sets.New[string]()
	for i := start; i < end; i++ {
		s.Insert(fmt.Sprintf("%v", i))
	}
	return s
}

func newInt32SetRange(start, end int32) sets.Set[int32] {
	s := sets.New[int32]()
	for i := start; i < end; i++ {
		s.Insert(i)
	}
	return s
}

func newIntSetRange(start, end int) sets.Set[int] {
	s := sets.New[int]()
	for i := start; i < end; i++ {
		s.Insert(i)
	}
	return s
}

func TestMerge(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		tests := []struct {
			name string
			src  sets.Set[string]
			dst  sets.Set[string]
			want sets.Set[string]
		}{
			{
				name: "With common items",
				src:  newStringSetRange(1, 10),
				dst:  newStringSetRange(5, 15),
				want: newStringSetRange(1, 15),
			},
			{
				name: "Without common items",
				src:  newStringSetRange(1, 10),
				dst:  newStringSetRange(10, 15),
				want: newStringSetRange(1, 15),
			},
			{
				name: "Empty src",
				src:  sets.New[string](),
				dst:  newStringSetRange(1, 5),
				want: newStringSetRange(1, 5),
			},
			{
				name: "Empty dst",
				src:  newStringSetRange(1, 5),
				dst:  sets.New[string](),
				want: newStringSetRange(1, 5),
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := Merge(tt.dst, tt.src)
				assert.Equal(t, tt.want, got)
				// Verify dst is modified in-place.
				assert.Equal(t, tt.want, tt.dst)
			})
		}
	})

	t.Run("int32", func(t *testing.T) {
		tests := []struct {
			name string
			src  sets.Set[int32]
			dst  sets.Set[int32]
			want sets.Set[int32]
		}{
			{
				name: "With common items",
				src:  newInt32SetRange(1, 10),
				dst:  newInt32SetRange(5, 15),
				want: newInt32SetRange(1, 15),
			},
			{
				name: "Without common items",
				src:  newInt32SetRange(1, 10),
				dst:  newInt32SetRange(10, 15),
				want: newInt32SetRange(1, 15),
			},
			{
				name: "Empty src",
				src:  sets.New[int32](),
				dst:  newInt32SetRange(1, 5),
				want: newInt32SetRange(1, 5),
			},
			{
				name: "Empty dst",
				src:  newInt32SetRange(1, 5),
				dst:  sets.New[int32](),
				want: newInt32SetRange(1, 5),
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := Merge(tt.dst, tt.src)
				assert.Equal(t, tt.want, got)
				assert.Equal(t, tt.want, tt.dst)
			})
		}
	})

	t.Run("int", func(t *testing.T) {
		tests := []struct {
			name string
			src  sets.Set[int]
			dst  sets.Set[int]
			want sets.Set[int]
		}{
			{
				name: "With common items",
				src:  newIntSetRange(1, 10),
				dst:  newIntSetRange(5, 15),
				want: newIntSetRange(1, 15),
			},
			{
				name: "Without common items",
				src:  newIntSetRange(1, 10),
				dst:  newIntSetRange(10, 15),
				want: newIntSetRange(1, 15),
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := Merge(tt.dst, tt.src)
				assert.Equal(t, tt.want, got)
				assert.Equal(t, tt.want, tt.dst)
			})
		}
	})
}

func TestSymmetricDifference(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		tests := []struct {
			name string
			s1   sets.Set[string]
			s2   sets.Set[string]
			want sets.Set[string]
		}{
			{
				name: "Equivalent sets",
				s1:   newStringSetRange(1, 4),
				s2:   newStringSetRange(1, 4),
				want: sets.New[string](),
			},
			{
				name: "With common items",
				s1:   newStringSetRange(1, 4),
				s2:   newStringSetRange(3, 6),
				want: sets.New[string]("1", "2", "4", "5"),
			},
			{
				name: "Without common items",
				s1:   newStringSetRange(1, 4),
				s2:   newStringSetRange(4, 8),
				want: newStringSetRange(1, 8),
			},
			{
				name: "Both empty",
				s1:   sets.New[string](),
				s2:   sets.New[string](),
				want: sets.New[string](),
			},
			{
				name: "First empty",
				s1:   sets.New[string](),
				s2:   newStringSetRange(1, 4),
				want: newStringSetRange(1, 4),
			},
			{
				name: "Second empty",
				s1:   newStringSetRange(1, 4),
				s2:   sets.New[string](),
				want: newStringSetRange(1, 4),
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := SymmetricDifference(tt.s1, tt.s2)
				assert.Equal(t, tt.want, got)
			})
		}
	})

	t.Run("int32", func(t *testing.T) {
		tests := []struct {
			name string
			s1   sets.Set[int32]
			s2   sets.Set[int32]
			want sets.Set[int32]
		}{
			{
				name: "Equivalent sets",
				s1:   newInt32SetRange(1, 4),
				s2:   newInt32SetRange(1, 4),
				want: sets.New[int32](),
			},
			{
				name: "With common items",
				s1:   newInt32SetRange(1, 4),
				s2:   newInt32SetRange(3, 6),
				want: sets.New[int32](1, 2, 4, 5),
			},
			{
				name: "Without common items",
				s1:   newInt32SetRange(1, 4),
				s2:   newInt32SetRange(4, 8),
				want: newInt32SetRange(1, 8),
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := SymmetricDifference(tt.s1, tt.s2)
				assert.Equal(t, tt.want, got)
			})
		}
	})

	t.Run("int", func(t *testing.T) {
		tests := []struct {
			name string
			s1   sets.Set[int]
			s2   sets.Set[int]
			want sets.Set[int]
		}{
			{
				name: "Equivalent sets",
				s1:   newIntSetRange(1, 4),
				s2:   newIntSetRange(1, 4),
				want: sets.New[int](),
			},
			{
				name: "With common items",
				s1:   newIntSetRange(1, 4),
				s2:   newIntSetRange(3, 6),
				want: sets.New[int](1, 2, 4, 5),
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := SymmetricDifference(tt.s1, tt.s2)
				assert.Equal(t, tt.want, got)
			})
		}
	})
}

// benchSink prevents the compiler from eliminating benchmark calls.
var benchSink sets.Set[string]

func BenchmarkSymmetricDifference(b *testing.B) {
	s1 := newStringSetRange(0, 2000)
	s2 := newStringSetRange(1000, 3000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = SymmetricDifference(s1, s2)
	}
}
