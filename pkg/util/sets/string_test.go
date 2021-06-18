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

func getSets(start, end int) sets.String {
	s := sets.NewString()
	for i := start; i < end; i++ {
		s.Insert(fmt.Sprintf("%v", i))
	}
	return s
}

func BenchmarkSymmetricDifference(b *testing.B) {
	s1 := getSets(0, 2000)
	s2 := getSets(1000, 3000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SymmetricDifference(s1, s2)
	}
}

func TestMerge(t *testing.T) {
	tests := []struct {
		name string
		src  sets.String
		dst  sets.String
		want sets.String
	}{
		{
			name: "With common items",
			src:  getSets(1, 10),
			dst:  getSets(5, 15),
			want: getSets(1, 15),
		},
		{
			name: "Without common items",
			src:  getSets(1, 10),
			dst:  getSets(10, 15),
			want: getSets(1, 15),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Merge(tt.dst, tt.src)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.want, tt.dst)
		})
	}
}

func TestSymmetricDifference(t *testing.T) {
	tests := []struct {
		name string
		s1   sets.String
		s2   sets.String
		want sets.String
	}{
		{
			name: "Equivalent sets",
			s1:   getSets(1, 4),
			s2:   getSets(1, 4),
			want: sets.NewString(),
		},
		{
			name: "With common items",
			s1:   getSets(1, 4),
			s2:   getSets(3, 6),
			want: sets.NewString("1", "2", "4", "5"),
		},
		{
			name: "Without common items",
			s1:   getSets(1, 4),
			s2:   getSets(4, 8),
			want: getSets(1, 8),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SymmetricDifference(tt.s1, tt.s2)
			assert.Equal(t, tt.want, got)
		})
	}
}
