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

package controlplane

import (
	"net"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
)

// groupMemberKey is used to uniquely identify GroupMember.
type groupMemberKey string

// GroupMemberSet is a set of GroupMembers.
// +k8s:openapi-gen=false
// +k8s:deepcopy-gen=false
type GroupMemberSet map[groupMemberKey]*GroupMember

// normalizeGroupMember calculates the groupMemberKey of the provided
// GroupMember based on the Pod/ExternalEntity/Service's namespaced name and IPs.
// For GroupMembers in appliedToGroups, the IPs are not set, so the
// generated key does not contain IP information.
func normalizeGroupMember(member *GroupMember) groupMemberKey {
	// "/" is illegal in Namespace and name so is safe as the delimiter.
	const delimiter = "/"
	var b strings.Builder
	if member.Pod != nil {
		b.WriteString("Pod:")
		b.WriteString(member.Pod.Namespace)
		b.WriteString(delimiter)
		b.WriteString(member.Pod.Name)
	} else if member.ExternalEntity != nil {
		b.WriteString("ExternalEntity:")
		b.WriteString(member.ExternalEntity.Namespace)
		b.WriteString(delimiter)
		b.WriteString(member.ExternalEntity.Name)
	} else if member.Service != nil {
		b.WriteString("Service:")
		b.WriteString(member.Service.Namespace)
		b.WriteString(delimiter)
		b.WriteString(member.Service.Name)
	}
	for _, ip := range member.IPs {
		b.Write(ip)
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

// IPDifference returns a String set of GroupMember IPs that are not in o.
func (s GroupMemberSet) IPDifference(o GroupMemberSet) sets.Set[string] {
	sIPs, oIPs := sets.New[string](), sets.New[string]()
	for _, m := range s {
		for _, ip := range m.IPs {
			sIPs.Insert(net.IP(ip).String())
		}
	}
	for _, m := range o {
		for _, ip := range m.IPs {
			oIPs.Insert(net.IP(ip).String())
		}
	}
	return sIPs.Difference(oIPs)
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
