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

package openflow

import (
	"os/exec"
	"time"
)

var executor = exec.Command

type versionType = string
type protocol = string
type TableIDType uint8

const LastTableID TableIDType = 0xff

type missActionType uint32
type Range [2]uint32

const (
	Version13 versionType = "Openflow13"

	ProtocolIP  protocol = "ip"
	ProtocolARP protocol = "arp"
)

const (
	TableMissActionDrop missActionType = iota
	TableMissActionNormal
	TableMissActionNext
)

// Bridge defines operations on an openflow bridge.
type Bridge interface {
	CreateTable(id, next TableIDType, missAction missActionType) Table
	GetName() string
	DeleteTable(id TableIDType) bool
	DumpTableStatus() []TableStatus
}

func NewBridge(name string) Bridge {
	return &commandBridge{
		name:       name,
		tableCache: map[TableIDType]Table{},
	}
}

// TableStatus represents the status of a specific flow table. The status is useful for debugging.
type TableStatus struct {
	ID         uint      `json:"id"`
	FlowCount  uint      `json:"flowCount"`
	UpdateTime time.Time `json:"updateTime"`
}

type Table interface {
	GetID() TableIDType
	BuildFlow() FlowBuilder
	GetMissAction() missActionType
	Status() TableStatus
	GetNext() TableIDType

	updateStatus(flowCountDelta int)
}

type Flow interface {
	Add() error
	Modify() error
	Delete() error
	String() string
	Table() Table
}

type Action interface {
	SetField(key, value string) FlowBuilder
	Load(name string, value uint64) FlowBuilder
	LoadRange(name string, addr uint32, to Range) FlowBuilder
	Move(from, to string) FlowBuilder
	MoveRange(fromName, toName string, from, to Range) FlowBuilder
	Resubmit(port string, table TableIDType) FlowBuilder
	CT(commit bool, tableID TableIDType, zone int, actions ...string) FlowBuilder
	Drop() FlowBuilder
	Output(port int) FlowBuilder
	OutputFieldRange(from string, rng Range) FlowBuilder
	OutputInPort() FlowBuilder
	DecTTL() FlowBuilder
	Normal() FlowBuilder
	Conjunction(conjID uint32, clauseID uint8, nClause uint8) FlowBuilder
}

type FlowBuilder interface {
	Priority(value uint32) FlowBuilder
	Switch(name string) FlowBuilder
	MatchProtocol(name protocol) FlowBuilder
	MatchField(name, value string) FlowBuilder
	MatchFieldRange(name, value string, rng Range) FlowBuilder
	CTState(value string) FlowBuilder
	CTMark(value string) FlowBuilder

	Action() Action
	Done() Flow
}
