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

// Deprecated: MergeString is a type-specific version of Merge.
// Use Merge instead.
func MergeString(dst, src sets.Set[string]) sets.Set[string] {
	return Merge(dst, src)
}

// Deprecated: SymmetricDifferenceString is a type-specific version of SymmetricDifference.
// Use SymmetricDifference instead.
func SymmetricDifferenceString(s1, s2 sets.Set[string]) sets.Set[string] {
	return SymmetricDifference(s1, s2)
}
