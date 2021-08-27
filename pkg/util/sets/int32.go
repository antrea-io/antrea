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

import "k8s.io/apimachinery/pkg/util/sets"

// MergeInt32 merges the src sets into dst and returns dst.
// This assumes that dst is non-nil.
// For example:
// s1 = {a1, a2, a3}
// s2 = {a1, a2, a4, a5}
// MergeInt32(s1, s2) = {a1, a2, a3, a4, a5}
// s1 = {a1, a2, a3, a4, a5}
//
// It supersedes s1.Union(s2) when constructing a new set is not the intention.
func MergeInt32(dst, src sets.Int32) sets.Int32 {
	for item := range src {
		dst.Insert(item)
	}
	return dst
}
