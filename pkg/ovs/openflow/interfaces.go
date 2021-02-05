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
	ProtocolIP     Protocol = "ip"
	ProtocolIPv6   Protocol = "ipv6"
	ProtocolARP    Protocol = "arp"
	ProtocolTCP    Protocol = "tcp"
	ProtocolTCPv6  Protocol = "tcpv6"
	ProtocolUDP    Protocol = "udp"
	ProtocolUDPv6  Protocol = "udpv6"
	ProtocolSCTP   Protocol = "sctp"
	ProtocolSCTPv6 Protocol = "sctpv6"
	ProtocolICMP   Protocol = "icmp"
	ProtocolICMPv6 Protocol = "icmpv6"
)

const (
	TableMissActionDrop MissActionType = iota
	TableMissActionNormal
	TableMissActionNext
	TableMissActionNone
)

const (
	NxmFieldSrcMAC      = "NXM_OF_ETH_SRC"
	NxmFieldDstMAC      = "NXM_OF_ETH_DST"
	NxmFieldARPSha      = "NXM_NX_ARP_SHA"
	NxmFieldARPTha      = "NXM_NX_ARP_THA"
	NxmFieldARPSpa      = "NXM_OF_ARP_SPA"
	NxmFieldARPTpa      = "NXM_OF_ARP_TPA"
	NxmFieldCtLabel     = "NXM_NX_CT_LABEL"
	NxmFieldCtMark      = "NXM_NX_CT_MARK"
	NxmFieldARPOp       = "NXM_OF_ARP_OP"
	NxmFieldReg         = "NXM_NX_REG"
	NxmFieldTunMetadata = "NXM_NX_TUN_METADATA"
	NxmFieldIPToS       = "NXM_OF_IP_TOS"
	NxmFieldXXReg       = "NXM_NX_XXREG"
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
	DumpFlows(cookieID, cookieMask uint64) (map[uint64]*FlowStates, error)
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
	// SubscribePacketIn registers a consumer to listen to PacketIn messages matching the provided reason. When the
	// Bridge receives a PacketIn message with the specified reason, it sends the message to the consumer using the
	// provided channel.
	SubscribePacketIn(reason uint8, ch chan *ofctrl.PacketIn) error
	// AddTLVMap adds a TLV mapping with OVS field tun_metadataX. The value loaded in tun_metadataX is transported by
	// Geneve header with the specified <optClass, optType, optLength>. The value of OptLength must be a multiple of 4.
	// The value loaded into field tun_metadataX must fit within optLength bytes.
	AddTLVMap(optClass uint16, optType uint8, optLength uint8, tunMetadataIndex uint16) error
	// SendPacketOut sends a packetOut message to the OVS Bridge.
	SendPacketOut(packetOut *ofctrl.PacketOut) error
	// BuildPacketOut returns a new PacketOutBuilder.
	BuildPacketOut() PacketOutBuilder
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
	// Returns the flow priority associated with OFEntry
	FlowPriority() uint16
	FlowProtocol() Protocol
	MatchString() string
	// CopyToBuilder returns a new FlowBuilder that copies the matches of the Flow.
	// It copies the original actions of the Flow only if copyActions is set to true, and
	// resets the priority in the new FlowBuilder if the provided priority is not 0.
	CopyToBuilder(priority uint16, copyActions bool) FlowBuilder
	IsDropFlow() bool
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
	GotoTable(table TableIDType) FlowBuilder
	SendToController(reason uint8) FlowBuilder
	Note(notes string) FlowBuilder
}

type FlowBuilder interface {
	MatchPriority(uint16) FlowBuilder
	MatchProtocol(name Protocol) FlowBuilder
	MatchReg(regID int, data uint32) FlowBuilder
	MatchXXReg(regID int, data []byte) FlowBuilder
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
	MatchIPDscp(dscp uint8) FlowBuilder
	MatchCTStateNew(isSet bool) FlowBuilder
	MatchCTStateRel(isSet bool) FlowBuilder
	MatchCTStateRpl(isSet bool) FlowBuilder
	MatchCTStateEst(isSet bool) FlowBuilder
	MatchCTStateTrk(isSet bool) FlowBuilder
	MatchCTStateInv(isSet bool) FlowBuilder
	MatchCTStateDnat(isSet bool) FlowBuilder
	MatchCTStateSnat(isSet bool) FlowBuilder
	MatchCTMark(value uint32, mask *uint32) FlowBuilder
	MatchCTLabelRange(high, low uint64, bitRange Range) FlowBuilder
	MatchConjID(value uint32) FlowBuilder
	MatchDstPort(port uint16, portMask *uint16) FlowBuilder
	MatchICMPv6Type(icmp6Type byte) FlowBuilder
	MatchICMPv6Code(icmp6Code byte) FlowBuilder
	MatchTunMetadata(index int, data uint32) FlowBuilder
	// MatchCTSrcIP matches the source IPv4 address of the connection tracker original direction tuple.
	MatchCTSrcIP(ip net.IP) FlowBuilder
	// MatchCTSrcIPNet matches the source IPv4 address of the connection tracker original direction tuple with IP masking.
	MatchCTSrcIPNet(ipnet net.IPNet) FlowBuilder
	// MatchCTDstIP matches the destination IPv4 address of the connection tracker original direction tuple.
	MatchCTDstIP(ip net.IP) FlowBuilder
	// MatchCTDstIP matches the destination IPv4 address of the connection tracker original direction tuple with IP masking.
	MatchCTDstIPNet(ipNet net.IPNet) FlowBuilder
	// MatchCTSrcPort matches the transport source port of the connection tracker original direction tuple.
	MatchCTSrcPort(port uint16) FlowBuilder
	// MatchCTDstPort matches the transport destination port of the connection tracker original direction tuple.
	MatchCTDstPort(port uint16) FlowBuilder
	// MatchCTProtocol matches the IP protocol type of the connection tracker original direction tuple.
	MatchCTProtocol(proto Protocol) FlowBuilder
	Cookie(cookieID uint64) FlowBuilder
	SetHardTimeout(timout uint16) FlowBuilder
	SetIdleTimeout(timeout uint16) FlowBuilder
	Action() Action
	Done() Flow
}

type LearnAction interface {
	DeleteLearned() LearnAction
	MatchEthernetProtocolIP(isIPv6 bool) LearnAction
	MatchTransportDst(protocol Protocol) LearnAction
	MatchLearnedTCPDstPort() LearnAction
	MatchLearnedUDPDstPort() LearnAction
	MatchLearnedSCTPDstPort() LearnAction
	MatchLearnedTCPv6DstPort() LearnAction
	MatchLearnedUDPv6DstPort() LearnAction
	MatchLearnedSCTPv6DstPort() LearnAction
	MatchLearnedSrcIP() LearnAction
	MatchLearnedDstIP() LearnAction
	MatchLearnedSrcIPv6() LearnAction
	MatchLearnedDstIPv6() LearnAction
	MatchReg(regID int, data uint32, rng Range) LearnAction
	LoadReg(regID int, data uint32, rng Range) LearnAction
	LoadRegToReg(fromRegID, toRegID int, fromRng, toRng Range) LearnAction
	LoadXXRegToXXReg(fromRegID, toRegID int, fromRng, toRng Range) LearnAction
	SetDstMAC(mac net.HardwareAddr) LearnAction
	Done() FlowBuilder
}

type Group interface {
	OFEntry
	ResetBuckets() Group
	Bucket() BucketBuilder
}

type BucketBuilder interface {
	Weight(val uint16) BucketBuilder
	LoadReg(regID int, data uint32) BucketBuilder
	LoadXXReg(regID int, data []byte) BucketBuilder
	LoadRegRange(regID int, data uint32, rng Range) BucketBuilder
	ResubmitToTable(tableID TableIDType) BucketBuilder
	Done() Group
}

type CTAction interface {
	LoadToMark(value uint32) CTAction
	LoadToLabelRange(value uint64, rng *Range) CTAction
	MoveToLabel(fromName string, fromRng, labelRng *Range) CTAction
	// NAT action translates the packet in the way that the connection was committed into the conntrack zone, e.g., if
	// a connection was committed with SNAT, the later packets would be translated with the earlier SNAT configurations.
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

type PacketOutBuilder interface {
	SetSrcMAC(mac net.HardwareAddr) PacketOutBuilder
	SetDstMAC(mac net.HardwareAddr) PacketOutBuilder
	SetSrcIP(ip net.IP) PacketOutBuilder
	SetDstIP(ip net.IP) PacketOutBuilder
	SetIPProtocol(protocol Protocol) PacketOutBuilder
	SetTTL(ttl uint8) PacketOutBuilder
	SetIPFlags(flags uint16) PacketOutBuilder
	SetTCPSrcPort(port uint16) PacketOutBuilder
	SetTCPDstPort(port uint16) PacketOutBuilder
	SetTCPFlags(flags uint8) PacketOutBuilder
	SetUDPSrcPort(port uint16) PacketOutBuilder
	SetUDPDstPort(port uint16) PacketOutBuilder
	SetICMPType(icmpType uint8) PacketOutBuilder
	SetICMPCode(icmpCode uint8) PacketOutBuilder
	SetICMPID(id uint16) PacketOutBuilder
	SetICMPSequence(seq uint16) PacketOutBuilder
	SetInport(inPort uint32) PacketOutBuilder
	SetOutport(outport uint32) PacketOutBuilder
	AddLoadAction(name string, data uint64, rng Range) PacketOutBuilder
	Done() *ofctrl.PacketOut
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
