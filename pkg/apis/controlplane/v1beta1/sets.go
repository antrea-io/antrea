// Copyright 2020 Antrea Authors
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

package v1beta1

import (
	"strings"
)

// groupMemberPodKey is used to uniquely identify GroupMemberPod. Either Pod or
// IP is used as unique key.
type groupMemberPodKey string

// GroupMemberPodSet is a set of GroupMemberPods.
type GroupMemberPodSet map[groupMemberPodKey]*GroupMemberPod

// normalizeGroupMemberPod calculates the groupMemberPodKey of the provided
// GroupMemberPod based on the Pod's namespaced name or IP.
func normalizeGroupMemberPod(pod *GroupMemberPod) groupMemberPodKey {
	// "/" is illegal in Namespace and name so is safe as the delimiter.
	const delimiter = "/"
	var b strings.Builder
	if pod.Pod != nil {
		b.WriteString(pod.Pod.Namespace)
		b.WriteString(delimiter)
		b.WriteString(pod.Pod.Name)
	} else if len(pod.IP) != 0 {
		b.Write(pod.IP)
	}
	return groupMemberPodKey(b.String())
}

// NewGroupMemberPodSet builds a GroupMemberPodSet from a list of GroupMemberPod.
func NewGroupMemberPodSet(items ...*GroupMemberPod) GroupMemberPodSet {
	m := GroupMemberPodSet{}
	m.Insert(items...)
	return m
}

// Insert adds items to the set.
func (s GroupMemberPodSet) Insert(items ...*GroupMemberPod) {
	for _, item := range items {
		s[normalizeGroupMemberPod(item)] = item
	}
}

// Delete removes all items from the set.
func (s GroupMemberPodSet) Delete(items ...*GroupMemberPod) {
	for _, item := range items {
		delete(s, normalizeGroupMemberPod(item))
	}
}

// Has returns true if and only if item is contained in the set.
func (s GroupMemberPodSet) Has(item *GroupMemberPod) bool {
	_, contained := s[normalizeGroupMemberPod(item)]
	return contained
}

// Difference returns a set of Pod references that are not in o.
func (s GroupMemberPodSet) Difference(o GroupMemberPodSet) GroupMemberPodSet {
	result := GroupMemberPodSet{}
	for key, item := range s {
		if _, contained := o[key]; !contained {
			result[key] = item
		}
	}
	return result
}

// Union returns a new set which includes items in either m or o.
func (s GroupMemberPodSet) Union(o GroupMemberPodSet) GroupMemberPodSet {
	result := GroupMemberPodSet{}
	for key, item := range s {
		result[key] = item
	}
	for key, item := range o {
		result[key] = item
	}
	return result
}

// Merge merges the other set into the set.
// For example:
// s1 = {a1, a2, a3}
// s2 = {a1, a2, a4, a5}
// s1.Merge(s2) = {a1, a2, a3, a4, a5}
// s1 = {a1, a2, a3, a4, a5}
//
// It should be used instead of s1.Union(s2) when constructing a new set is not required.
func (s GroupMemberSet) Merge(o GroupMemberSet) GroupMemberSet {
	for key, item := range o {
		s[key] = item
	}
	return s
}

// IsSuperset returns true if and only if s1 is a superset of s2.
func (s GroupMemberPodSet) IsSuperset(o GroupMemberPodSet) bool {
	for key := range o {
		_, contained := s[key]
		if !contained {
			return false
		}
	}
	return true
}

// Equal returns true if and only if s1 is equal (as a set) to s2.
// Two sets are equal if their membership is identical.
// (In practice, this means same elements, order doesn't matter)
func (s GroupMemberPodSet) Equal(o GroupMemberPodSet) bool {
	return len(s) == len(o) && s.IsSuperset(o)
}

// Items returns the slice with contents in random order.
func (s GroupMemberPodSet) Items() []*GroupMemberPod {
	res := make([]*GroupMemberPod, 0, len(s))
	for _, item := range s {
		res = append(res, item)
	}
	return res
}

// groupMemberKey is used to uniquely identify GroupMember.
type groupMemberKey string

// GroupMemberSet is a set of GroupMembers.
// +k8s:openapi-gen=false
// +k8s:deepcopy-gen=false
type GroupMemberSet map[groupMemberKey]*GroupMember

// normalizeGroupMember calculates the groupMemberKey of the provided
// GroupMember based on the Pod's namespaced name or IP.
func normalizeGroupMember(member *GroupMember) groupMemberKey {
	// "/" is illegal in Namespace and name so is safe as the delimiter.
	const delimiter = "/"
	var b strings.Builder
	if member.Pod != nil {
		b.WriteString(member.Pod.Namespace)
		b.WriteString(delimiter)
		b.WriteString(member.Pod.Name)
	} else if member.ExternalEntity != nil {
		b.WriteString(member.ExternalEntity.Namespace)
		b.WriteString(delimiter)
		b.WriteString(member.ExternalEntity.Name)
	} else if len(member.Endpoints) != 0 {
		for _, ep := range member.Endpoints {
			b.Write(ep.IP)
		}
	}
	return groupMemberKey(b.String())
}

// NewGroupMemberSet builds a GroupMemberSet from a list of GroupMember.
func NewGroupMemberSet(items ...*GroupMember) GroupMemberSet {
	m := GroupMemberSet{}
	m.Insert(items...)
	return m
}

// Insert adds items to the set.
func (s GroupMemberSet) Insert(items ...*GroupMember) {
	for _, item := range items {
		s[normalizeGroupMember(item)] = item
	}
}

// Delete removes all items from the set.
func (s GroupMemberSet) Delete(items ...*GroupMember) {
	for _, item := range items {
		delete(s, normalizeGroupMember(item))
	}
}

// Has returns true if and only if item is contained in the set.
func (s GroupMemberSet) Has(item *GroupMember) bool {
	_, contained := s[normalizeGroupMember(item)]
	return contained
}

// Difference returns a set of GroupMembers that are not in o.
func (s GroupMemberSet) Difference(o GroupMemberSet) GroupMemberSet {
	result := GroupMemberSet{}
	for key, item := range s {
		if _, contained := o[key]; !contained {
			result[key] = item
		}
	}
	return result
}

// Union returns a new set which includes items in either m or o.
func (s GroupMemberSet) Union(o GroupMemberSet) GroupMemberSet {
	result := GroupMemberSet{}
	for key, item := range s {
		result[key] = item
	}
	for key, item := range o {
		result[key] = item
	}
	return result
}

// IsSuperset returns true if and only if s1 is a superset of s2.
func (s GroupMemberSet) IsSuperset(o GroupMemberSet) bool {
	for key := range o {
		_, contained := s[key]
		if !contained {
			return false
		}
	}
	return true
}

// Equal returns true if and only if s1 is equal (as a set) to s2.
// Two sets are equal if their membership is identical.
// (In practice, this means same elements, order doesn't matter)
func (s GroupMemberSet) Equal(o GroupMemberSet) bool {
	return len(s) == len(o) && s.IsSuperset(o)
}

// Items returns the slice with contents in random order.
func (s GroupMemberSet) Items() []*GroupMember {
	res := make([]*GroupMember, 0, len(s))
	for _, item := range s {
		res = append(res, item)
	}
	return res
}
