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
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/sets"
)

func getInt32Sets(start, end int) sets.Set[int32] {
	s := sets.New[int32]()
	for i := start; i < end; i++ {
		s.Insert(int32(i))
	}
	return s
}

func TestMergeInt32(t *testing.T) {
	tests := []struct {
		name string
		src  sets.Set[int32]
		dst  sets.Set[int32]
		want sets.Set[int32]
	}{
		{
			name: "With common items",
			src:  getInt32Sets(1, 10),
			dst:  getInt32Sets(5, 15),
			want: getInt32Sets(1, 15),
		},
		{
			name: "Without common items",
			src:  getInt32Sets(1, 10),
			dst:  getInt32Sets(10, 15),
			want: getInt32Sets(1, 15),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeInt32(tt.dst, tt.src)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.want, tt.dst)
		})
	}
}
