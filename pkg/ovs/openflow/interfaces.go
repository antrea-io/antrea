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
	"net"
	"os/exec"
	"time"
)

var executor = exec.Command

type versionType = string
type protocol = string
type TableIDType uint8

const LastTableID TableIDType = 0xff

type MissActionType uint32
type Range [2]uint32

const (
	Version13 versionType = "Openflow13"

	ProtocolIP   protocol = "ip"
	ProtocolARP  protocol = "arp"
	ProtocolTCP  protocol = "tcp"
	ProtocolUDP  protocol = "udp"
	ProtocolSCTP protocol = "sctp"
	ProtocolICMP protocol = "icmp"
)

const (
	TableMissActionDrop MissActionType = iota
	TableMissActionNormal
	TableMissActionNext
)

const (
	NxmFieldSrcMAC  = "NXM_OF_ETH_SRC"
	NxmFieldDstMAC  = "NXM_OF_ETH_DST"
	NxmFieldARPSha  = "NXM_NX_ARP_SHA"
	NxmFieldARPTha  = "NXM_NX_ARP_THA"
	NxmFieldARPSpa  = "NXM_OF_ARP_SPA"
	NxmFieldARPTpa  = "NXM_OF_ARP_TPA"
	NxmFieldCtLabel = "NXM_NX_CT_LABEL"
	NxmFieldCtMark  = "NXM_NX_CT_MARK"
	NxmFieldARPOp   = "NXM_OF_ARP_OP"
	NxmFieldReg     = "NXM_NX_REG"
)

//go:generate mockgen -copyright_file ../../../hack/boilerplate/license_header.go.txt -destination testing/mock_openflow.go -package=testing github.com/vmware-tanzu/antrea/pkg/ovs/openflow Bridge,Table,Flow,Action,FlowBuilder
// Bridge defines operations on an openflow bridge.
type Bridge interface {
	CreateTable(id, next TableIDType, missAction MissActionType) Table
	GetName() string
	DeleteTable(id TableIDType) bool
	DumpTableStatus() []TableStatus
	// Connect initiates connection to the OFSwitch. It will block until the connection is established.
	// If Bridge is not connected in maxRetry times, it will return error.
	Connect(maxRetry int) error
	// Disconnect stops connection to the OFSwitch.
	Disconnect() error
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
	GetMissAction() MissActionType
	Status() TableStatus
	GetNext() TableIDType
}

type updater interface {
	UpdateStatus(delta int)
}

type Flow interface {
	Add() error
	Modify() error
	Delete() error
	String() string
	MatchString() string
	GetTable() Table
	// CopyToBuilder returns a new FlowBuilder that copies the matches of the Flow, but does not not copy the actions.
	CopyToBuilder() FlowBuilder
}

type Action interface {
	LoadARPOperation(value uint16) FlowBuilder
	LoadRegRange(regID int, value uint32, to Range) FlowBuilder
	LoadRange(name string, addr uint32, to Range) FlowBuilder
	Move(from, to string) FlowBuilder
	MoveRange(fromName, toName string, from, to Range) FlowBuilder
	Resubmit(port string, table TableIDType) FlowBuilder
	CT(commit bool, tableID TableIDType, zone int) CTAction
	Drop() FlowBuilder
	Output(port int) FlowBuilder
	OutputFieldRange(from string, rng Range) FlowBuilder
	OutputRegRange(regID int, rng Range) FlowBuilder
	OutputInPort() FlowBuilder
	SetDstMAC(addr net.HardwareAddr) FlowBuilder
	SetSrcMAC(addr net.HardwareAddr) FlowBuilder
	SetARPSha(addr net.HardwareAddr) FlowBuilder
	SetARPTha(addr net.HardwareAddr) FlowBuilder
	SetARPSpa(addr net.IP) FlowBuilder
	SetARPTpa(addr net.IP) FlowBuilder
	SetSrcIP(addr net.IP) FlowBuilder
	SetDstIP(addr net.IP) FlowBuilder
	SetTunnelDst(addr net.IP) FlowBuilder
	DecTTL() FlowBuilder
	Normal() FlowBuilder
	Conjunction(conjID uint32, clauseID uint8, nClause uint8) FlowBuilder
}

type FlowBuilder interface {
	Priority(value uint32) FlowBuilder
	MatchProtocol(name protocol) FlowBuilder
	MatchReg(regID int, data uint32) FlowBuilder
	MatchRegRange(regID int, data uint32, rng Range) FlowBuilder
	MatchInPort(inPort uint32) FlowBuilder
	MatchDstIP(ip net.IP) FlowBuilder
	MatchDstIPNet(ipNet net.IPNet) FlowBuilder
	MatchSrcIP(ip net.IP) FlowBuilder
	MatchSrcIPNet(ipNet net.IPNet) FlowBuilder
	MatchDstMAC(mac net.HardwareAddr) FlowBuilder
	MatchSrcMAC(mac net.HardwareAddr) FlowBuilder
	MatchARPSha(mac net.HardwareAddr) FlowBuilder
	MatchARPTha(mac net.HardwareAddr) FlowBuilder
	MatchARPSpa(ip net.IP) FlowBuilder
	MatchARPTpa(ip net.IP) FlowBuilder
	MatchARPOp(op uint16) FlowBuilder
	MatchCTState(value string) FlowBuilder
	MatchCTMark(value string) FlowBuilder
	MatchConjID(value uint32) FlowBuilder
	MatchTCPDstPort(port uint16) FlowBuilder
	MatchUDPDstPort(port uint16) FlowBuilder
	MatchSCTPDstPort(port uint16) FlowBuilder
	Cookie(cookieID uint64) FlowBuilder
	Action() Action
	Done() Flow
}

type CTAction interface {
	LoadToMark(value uint32) CTAction
	LoadToLabelRange(value uint64, rng *Range) CTAction
	MoveToLabel(fromName string, fromRng, labelRng *Range) CTAction
	CTDone() FlowBuilder
}

type ctBase struct {
	commit  bool
	force   bool
	ctTable uint8
	ctZone  uint16
}
