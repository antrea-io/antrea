// Copyright 2019 OKN Authors
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

import "os/exec"

var executor = exec.Command

type versionType = string
type protocol = string
type builderType = commandBuilder

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

type Bridge struct {
	Name string
}

func (b *Bridge) CreateTable(id, next TableIDType, missActionType missActionType) *Table {
	return &Table{
		Bridge:     b.Name,
		ID:         id,
		Next:       next,
		MissAction: missActionType,
	}
}

func (b *Bridge) DeleteTable(id TableIDType) bool {
	// TODO: no need to delete table currently
	return true
}

type Table struct {
	Bridge     string
	ID, Next   TableIDType
	MissAction missActionType
}

type Flow interface {
	Add() error
	Modify() error
	Delete() error
	String() string
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
	Table(id TableIDType) FlowBuilder
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

func (t *Table) BuildFlow() FlowBuilder {
	return new(builderType).Table(t.ID).Switch(t.Bridge)
}
