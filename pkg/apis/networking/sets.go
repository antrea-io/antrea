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

package networking

import (
	"crypto/md5"
	"encoding/hex"

	"github.com/davecgh/go-spew/spew"
)

var (
	printer = spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
)

// groupMemberPodHash is used to uniquely identify GroupMemberPod. Only Pod and
// IP field are included as unique identifiers.
type groupMemberPodHash string

// GroupMemberPodSet is a set of GroupMemberPods.
type GroupMemberPodSet map[groupMemberPodHash]*GroupMemberPod

// hashGroupMemberPod uses the spew library which follows pointers and prints
// actual values of the nested objects to ensure the hash does not change when
// a pointer changes.
func hashGroupMemberPod(pod *GroupMemberPod) groupMemberPodHash {
	hasher := md5.New()
	hashObj := GroupMemberPod{Pod: pod.Pod, IP: pod.IP}
	printer.Fprintf(hasher, "%#v", hashObj)
	return groupMemberPodHash(hex.EncodeToString(hasher.Sum(nil)[0:]))
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
		s[hashGroupMemberPod(item)] = item
	}
}

// Delete removes all items from the set.
func (s GroupMemberPodSet) Delete(items ...*GroupMemberPod) {
	for _, item := range items {
		delete(s, hashGroupMemberPod(item))
	}
}

// Has returns true if and only if item is contained in the set.
func (s GroupMemberPodSet) Has(item *GroupMemberPod) bool {
	_, contained := s[hashGroupMemberPod(item)]
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

// groupMemberHash is used to uniquely identify GroupMember.
type groupMemberHash string

// GroupMemberSet is a set of GroupMembers.
// +k8s:openapi-gen=false
// +k8s:deepcopy-gen=false
type GroupMemberSet map[groupMemberHash]*GroupMember

// hashGroupMember uses the spew library which follows pointers and prints
// actual values of the nested objects to ensure the hash does not change when
// a pointer changes.
func hashGroupMember(member *GroupMember) groupMemberHash {
	hasher := md5.New()
	printer.Fprintf(hasher, "%#v", *member)
	return groupMemberHash(hex.EncodeToString(hasher.Sum(nil)[0:]))
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
		s[hashGroupMember(item)] = item
	}
}

// Delete removes all items from the set.
func (s GroupMemberSet) Delete(items ...*GroupMember) {
	for _, item := range items {
		delete(s, hashGroupMember(item))
	}
}

// Has returns true if and only if item is contained in the set.
func (s GroupMemberSet) Has(item *GroupMember) bool {
	_, contained := s[hashGroupMember(item)]
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

// Conversion functions
func (g *GroupMember) ToGroupMemberPod() *GroupMemberPod {
	return &GroupMemberPod{
		Pod:   g.Pod,
		IP:    g.Endpoints[0].IP,
		Ports: g.Endpoints[0].Ports,
	}
}

func (p *GroupMemberPod) ToGroupMember() *GroupMember {
	return &GroupMember{
		Pod: p.Pod,
		Endpoints: []Endpoint{
			{IP: p.IP, Ports: p.Ports},
		},
	}
}
