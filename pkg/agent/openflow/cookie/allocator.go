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

package cookie

import (
	"fmt"
)

const (
	BitwidthRound           = 16
	BitwidthCategory        = 8
	BitwidthReserved        = 64 - BitwidthCategory - BitwidthRound
	RoundMask        uint64 = 0xffff_0000_0000_0000
	CategoryMask     uint64 = 0x0000_ff00_0000_0000
)

// Category represents the flow entry category.
type Category uint64

const (
	Default Category = iota
	Gateway
	Node
	Pod
	Service
	Policy
	SNAT
)

func (c Category) String() string {
	switch c {
	case Default:
		return "Default"
	case Gateway:
		return "Gateway"
	case Node:
		return "Node"
	case Pod:
		return "Pod"
	case Service:
		return "Service"
	case Policy:
		return "Policy"
	case SNAT:
		return "SNAT"
	default:
		return "Invalid"
	}
}

// ID defines segments a cookie ID contains. An ID is composed like:
//  |------------------------- ID --------------------------|
//  |- round 16bits -|- category 8bits -|- reserved 8bits -|- objectID 32bits -|
// The round segment represents the round id.
// The category segment represents the category of flow this ID belongs.
type ID uint64

func newID(round uint64, cat Category, objectID uint32) ID {
	r := uint64(0)
	r |= round << (64 - BitwidthRound)
	r |= (uint64(cat) << BitwidthReserved) & CategoryMask
	r |= uint64(objectID)
	return ID(r)
}

// CookieMaskForRound returns a cookie and mask value that can be used to select
// all flows belonging to the provided round.
func CookieMaskForRound(round uint64) (uint64, uint64) {
	return round << (64 - BitwidthRound), RoundMask
}

// Raw returns the unit64 type value of the ID.
func (i ID) Raw() uint64 {
	return uint64(i)
}

// Round returns the round number of the ID.
func (i ID) Round() uint64 {
	return i.Raw() >> (64 - BitwidthRound)
}

// Category returns the category of the ID.
func (i ID) Category() Category {
	return Category((i.Raw() & CategoryMask) >> BitwidthReserved)
}

// String returns the string representation of the ID.
func (i ID) String() string {
	return fmt.Sprintf("<round:%d,category:%s>", i.Round(), i.Category().String())
}

// Allocator defines operations of a cookie ID allocator.
type Allocator interface {
	// Request gets a cookie IDs of the flow category.
	Request(cat Category) ID
	// RequestWithObjectID gets a cookie ID of the flow category and objectID.
	RequestWithObjectID(cat Category, objectID uint32) ID
}

type allocator struct {
	round uint64
}

// Request returns a ID with the given category.
func (a *allocator) Request(cat Category) ID {
	return newID(a.round, cat, 0)
}

func (a *allocator) RequestWithObjectID(cat Category, objectID uint32) ID {
	return newID(a.round, cat, objectID)
}

// NewAllocator creates a cookie ID allocator by using the given round number.
// Only last 16 bits of the round number would be used.
func NewAllocator(round uint64) Allocator {
	a := &allocator{round: round}
	return a
}
