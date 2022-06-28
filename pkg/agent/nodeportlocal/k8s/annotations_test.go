//go:build !windows
// +build !windows

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

package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/agent/nodeportlocal/types"
)

func BenchmarkCompareNPLAnnotationLists(b *testing.B) {
	const nodeIP = "127.0.0.1"
	a1 := types.NPLAnnotation{
		PodPort:  80,
		NodeIP:   nodeIP,
		NodePort: 61000,
	}
	a2 := types.NPLAnnotation{
		PodPort:  8080,
		NodeIP:   nodeIP,
		NodePort: 61001,
	}
	a3 := types.NPLAnnotation{
		PodPort:  81,
		NodeIP:   nodeIP,
		NodePort: 61002,
	}
	a4 := types.NPLAnnotation{
		PodPort:  8081,
		NodeIP:   nodeIP,
		NodePort: 61003,
	}
	benchmarkCases := []struct {
		name         string
		annotations1 []types.NPLAnnotation
		annotations2 []types.NPLAnnotation
		equal        bool
	}{
		{
			"EqualSameOrder",
			[]types.NPLAnnotation{a2, a1, a3},
			[]types.NPLAnnotation{a2, a1, a3},
			true,
		},
		{
			"EqualDifferentOrder",
			[]types.NPLAnnotation{a1, a2, a3},
			[]types.NPLAnnotation{a3, a2, a1},
			true,
		},
		{
			"NotEqualSameLength",
			[]types.NPLAnnotation{a1, a2, a3},
			[]types.NPLAnnotation{a3, a2, a4},
			false,
		},
		{
			"NotEqualDifferentLength",
			[]types.NPLAnnotation{a1, a2, a3},
			[]types.NPLAnnotation{a1, a2, a3, a4},
			false,
		},
	}

	for _, bc := range benchmarkCases {
		bc := bc
		b.Run(bc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result := compareNPLAnnotationLists(bc.annotations1, bc.annotations2)
				assert.Equal(b, bc.equal, result)
			}
		})
	}
}
