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
	"time"

	"github.com/contiv/ofnet/ofctrl"
)

type Protocol string
type TableIDType uint8
type GroupIDType uint32

type MissActionType uint32
type Range [2]uint32
type OFOperation int

const (
	LastTableID TableIDType = 0xff
	TableIDAll              = LastTableID
)

const (
	ProtocolIP   Protocol = "ip"
	ProtocolARP  Protocol = "arp"
	ProtocolTCP  Protocol = "tcp"
	ProtocolUDP  Protocol = "udp"
	ProtocolSCTP Protocol = "sctp"
	ProtocolICMP Protocol = "icmp"
)

const (
	TableMissActionDrop MissActionType = iota
	TableMissActionNormal
	TableMissActionNext
	TableMissActionNone
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

const (
	AddMessage OFOperation = iota
	ModifyMessage
	DeleteMessage
)

// Bridge defines operations on an openflow bridge.
type Bridge interface {
	CreateTable(id, next TableIDType, missAction MissActionType) Table
	DeleteTable(id TableIDType) bool
	CreateGroup(id GroupIDType) Group
	DeleteGroup(id GroupIDType) bool
	DumpTableStatus() []TableStatus
	// DumpFlows queries the Openflow entries from OFSwitch. The filter of the query is Openflow cookieID; the result is
	// a map from flow cookieID to FlowStates.
	DumpFlows(cookieID, cookieMask uint64) map[uint64]*FlowStates
	// DeleteFlowsByCookie removes Openflow entries from OFSwitch. The removed Openflow entries use the specific CookieID.
	DeleteFlowsByCookie(cookieID, cookieMask uint64) error
	// AddFlowsInBundle syncs multiple Openflow entries in a single transaction. This operation could add new flows in
	// "addFlows", modify flows in "modFlows", and remove flows in "delFlows" in the same bundle.
	AddFlowsInBundle(addflows []Flow, modFlows []Flow, delFlows []Flow) error
	// AddOFEntriesInBundle syncs multiple Openflow entries(including Flow and Group) in a single transaction. This
	// operation could add new entries in "addEntries", modify entries in "modEntries", and remove entries in
	// "delEntries" in the same bundle.
	AddOFEntriesInBundle(addEntries []OFEntry, modEntries []OFEntry, delEntries []OFEntry) error
	// Connect initiates connection to the OFSwitch. It will block until the connection is established. connectCh is used to
	// send notification whenever the switch is connected or reconnected.
	Connect(maxRetrySec int, connectCh chan struct{}) error
	// Disconnect stops connection to the OFSwitch.
	Disconnect() error
	// IsConnected returns the OFSwitch's connection status. The result is true if the OFSwitch is connected.
	IsConnected() bool
}

// TableStatus represents the status of a specific flow table. The status is useful for debugging.
type TableStatus struct {
	ID         uint      `json:"id"`
	FlowCount  uint      `json:"flowCount"`
	UpdateTime time.Time `json:"updateTime"`
}

type Table interface {
	GetID() TableIDType
	BuildFlow(priority uint16) FlowBuilder
	GetMissAction() MissActionType
	Status() TableStatus
	GetNext() TableIDType
}

type EntryType string

const (
	FlowEntry  EntryType = "FlowEntry"
	GroupEntry EntryType = "GroupEntry"
)

type OFEntry interface {
	Add() error
	Modify() error
	Delete() error
	Type() EntryType
	KeyString() string
	// Reset ensures that the entry is "correct" and that the Add /
	// Modify / Delete methods can be called on this object. This method
	// should be called if a reconnection event happened.
	Reset()
	// GetBundleMessage returns ofctrl.OpenFlowModMessage which can be used in Bundle messages. operation specifies what
	// operation is expected to be taken on the OFEntry.
	GetBundleMessage(operation OFOperation) (ofctrl.OpenFlowModMessage, error)
}

type Flow interface {
	OFEntry
	MatchString() string
	// CopyToBuilder returns a new FlowBuilder that copies the matches of the Flow, but does not copy the actions.
	CopyToBuilder() FlowBuilder
}

type Action interface {
	LoadARPOperation(value uint16) FlowBuilder
	LoadRegRange(regID int, value uint32, to Range) FlowBuilder
	LoadRange(name string, addr uint64, to Range) FlowBuilder
	Move(from, to string) FlowBuilder
	MoveRange(fromName, toName string, from, to Range) FlowBuilder
	Resubmit(port uint16, table TableIDType) FlowBuilder
	ResubmitToTable(table TableIDType) FlowBuilder
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
	Group(id GroupIDType) FlowBuilder
	Learn(id TableIDType, priority uint16, idleTimeout, hardTimeout uint16, cookieID uint64) LearnAction
}

type FlowBuilder interface {
	MatchProtocol(name Protocol) FlowBuilder
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
	MatchCTStateNew(isSet bool) FlowBuilder
	MatchCTStateRel(isSet bool) FlowBuilder
	MatchCTStateRpl(isSet bool) FlowBuilder
	MatchCTStateEst(isSet bool) FlowBuilder
	MatchCTStateTrk(isSet bool) FlowBuilder
	MatchCTStateInv(isSet bool) FlowBuilder
	MatchCTMark(value uint32) FlowBuilder
	MatchConjID(value uint32) FlowBuilder
	MatchTCPDstPort(port uint16) FlowBuilder
	MatchUDPDstPort(port uint16) FlowBuilder
	MatchSCTPDstPort(port uint16) FlowBuilder
	Cookie(cookieID uint64) FlowBuilder
	Action() Action
	Done() Flow
}

type LearnAction interface {
	DeleteLearned() LearnAction
	MatchEthernetProtocolIP() LearnAction
	MatchTransportDst(protocol Protocol) LearnAction
	MatchLearnedTCPDstPort() LearnAction
	MatchLearnedUDPDstPort() LearnAction
	MatchLearnedSrcIP() LearnAction
	MatchLearnedDstIP() LearnAction
	MatchReg(regID int, data uint32, rng Range) LearnAction
	LoadReg(regID int, data uint32, rng Range) LearnAction
	LoadRegToReg(fromRegID, toRegID int, fromRng, toRng Range) LearnAction
	Done() FlowBuilder
}

type Group interface {
	OFEntry
	Bucket() BucketBuilder
}

type BucketBuilder interface {
	Weight(val uint16) BucketBuilder
	LoadReg(regID int, data uint32) BucketBuilder
	LoadRegRange(regID int, data uint32, rng Range) BucketBuilder
	ResubmitToTable(tableID TableIDType) BucketBuilder
	Done() Group
}

type CTAction interface {
	LoadToMark(value uint32) CTAction
	LoadToLabelRange(value uint64, rng *Range) CTAction
	MoveToLabel(fromName string, fromRng, labelRng *Range) CTAction
	// NAT action is used if the packet is not committed into the conntrack zone, and is required to leverage the
	// original NAT configurations.
	NAT() CTAction
	// SNAT actions is used to translate the source IP to a specific address or address in a pool when committing the
	// packet into the conntrack zone. If a single IP is used as the target address, StartIP and EndIP in the range
	// should be the same. portRange could be nil.
	SNAT(ipRange *IPRange, portRange *PortRange) CTAction
	// DNAT actions is used to translate the destination IP to a specific address or address in a pool when committing
	// the packet into the conntrack zone. If a single IP is used as the target address, StartIP and EndIP in the range
	// should be the same. portRange could be nil.
	DNAT(ipRange *IPRange, portRange *PortRange) CTAction
	CTDone() FlowBuilder
}

type ctBase struct {
	commit  bool
	force   bool
	ctTable uint8
	ctZone  uint16
}

type IPRange struct {
	StartIP net.IP
	EndIP   net.IP
}

type PortRange struct {
	StartPort uint16
	EndPort   uint16
}
