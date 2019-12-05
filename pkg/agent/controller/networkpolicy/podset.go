// Copyright 2019 Antrea Authors
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

package networkpolicy

import (
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
)

// TODO: use set-gen to generate it.
type podSet map[v1beta1.PodReference]sets.Empty

// Union returns a new set which includes items in either s1 or s2.
func (s podSet) Union(o podSet) podSet {
	result := podSet{}
	for key := range s {
		result.Insert(key)
	}
	for key := range o {
		result.Insert(key)
	}
	return result
}

// Difference returns a set of objects that are not in s2
// For example:
// s1 = {a1, a2, a3}
// s2 = {a1, a2, a4, a5}
// s1.Difference(s2) = {a3}
// s2.Difference(s1) = {a4, a5}
func (s podSet) Difference(s2 podSet) podSet {
	result := newPodSet()
	for key := range s {
		if _, contained := s2[key]; !contained {
			result.Insert(key)
		}
	}
	return result
}

// Insert adds items to the set.
func (s podSet) Insert(items ...v1beta1.PodReference) {
	for _, item := range items {
		s[item] = sets.Empty{}
	}
}

// IsSuperset returns true if and only if s1 is a superset of s2.
func (s1 podSet) IsSuperset(s2 podSet) bool {
	for item := range s2 {
		_, contained := s1[item]
		if !contained {
			return false
		}
	}
	return true
}

// Equal returns true if and only if s1 is equal (as a set) to s2.
// Two sets are equal if their membership is identical.
// (In practice, this means same elements, order doesn't matter)
func (s1 podSet) Equal(s2 podSet) bool {
	return len(s1) == len(s2) && s1.IsSuperset(s2)
}

// newPodSet builds an podSet from a list of v1beta1.PodReference.
func newPodSet(pods ...v1beta1.PodReference) podSet {
	s := podSet{}
	for _, a := range pods {
		s[a] = sets.Empty{}
	}
	return s
}
