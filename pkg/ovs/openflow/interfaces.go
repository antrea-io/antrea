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
