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

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
)

type Protocol string
type GroupIDType uint32
type MeterIDType uint32

type MissActionType uint32
type Range [2]uint32
type OFOperation int

const (
	LastTableID uint8 = 0xff
	TableIDAll        = LastTableID
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
	ProtocolIGMP   Protocol = "igmp"
)

const (
	TableMissActionNone MissActionType = iota
	TableMissActionDrop
	TableMissActionNormal
	TableMissActionNext
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
	NxmFieldPktMark     = "NXM_NX_PKT_MARK"
	NxmFieldSrcIPv4     = "NXM_OF_IP_SRC"
	NxmFieldDstIPv4     = "NXM_OF_IP_DST"
	NxmFieldSrcIPv6     = "NXM_NX_IPV6_SRC"
	NxmFieldDstIPv6     = "NXM_NX_IPV6_DST"
	NxmFieldTunIPv4Src  = "NXM_NX_TUN_IPV4_SRC"
	NxmFieldEthType     = "NXM_OF_ETH_TYPE"
	NxmFieldIPProto     = "NXM_OF_IP_PROTO"

	OxmFieldVLANVID = "OXM_OF_VLAN_VID"
	OxmFieldInPort  = "OXM_OF_IN_PORT"
	OxmFieldTCPDst  = "OXM_OF_TCP_DST"
	OxmFieldUDPDst  = "OXM_OF_UDP_DST"
	OxmFieldSCTPDst = "OXM_OF_SCTP_DST"
	OxmFieldTCPSrc  = "OXM_OF_TCP_SRC"
	OxmFieldUDPSrc  = "OXM_OF_UDP_SRC"
	OxmFieldSCTPSrc = "OXM_OF_SCTP_SRC"
)

const (
	AddMessage OFOperation = iota
	ModifyMessage
	DeleteMessage
)

// IPDSCPToSRange stores the DSCP bits in ToS field of IP header.
var IPDSCPToSRange = &Range{2, 7}

// VLANVIDRange stores the VLAN VID range
var VLANVIDRange = &Range{0, 11}

// Bridge defines operations on an openflow bridge.
type Bridge interface {
	NewTable(table Table, next uint8, missAction MissActionType) Table
	GetTableByID(id uint8) (Table, error)
	NewGroupTypeAll(id GroupIDType) Group
	NewGroup(id GroupIDType) Group
	// DeleteGroupAll deletes all group entries from the switch.
	DeleteGroupAll() error
	NewMeter(id MeterIDType, flags ofctrl.MeterFlag) Meter
	// DeleteMeterAll deletes all meter entries from the switch.
	DeleteMeterAll() error
	GetMeterStats(handleMeterStatsReply func(meterID int, packetCount int64)) error
	DumpTableStatus() []TableStatus
	// DumpFlows queries the Openflow entries from OFSwitch. The filter of the query is Openflow cookieID; the result is
	// a map from flow cookieID to FlowStates.
	DumpFlows(cookieID, cookieMask uint64) (map[uint64]*FlowStates, error)
	// DeleteFlowsByCookie removes Openflow entries from OFSwitch. The removed Openflow entries use the specific CookieID.
	DeleteFlowsByCookie(cookieID, cookieMask uint64) error
	// AddFlowsInBundle syncs multiple Openflow entries in a single transaction. This operation could add new flows in
	// "addFlows", modify flows in "modFlows", and remove flows in "delFlows" in the same bundle.
	AddFlowsInBundle(addflows, modFlows, delFlows []*openflow15.FlowMod) error
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
	SubscribePacketIn(category uint8, pktInQueue *PacketInQueue) error
	// SendPacketOut sends a packetOut message to the OVS Bridge.
	SendPacketOut(packetOut *ofctrl.PacketOut) error
	// ResumePacket resumes a paused packetIn.
	ResumePacket(packetIn *ofctrl.PacketIn) error
	// BuildPacketOut returns a new PacketOutBuilder.
	BuildPacketOut() PacketOutBuilder
}

// TableStatus represents the status of a specific flow table. The status is useful for debugging.
type TableStatus struct {
	ID         uint      `json:"id"`
	Name       string    `json:"name"`
	FlowCount  uint      `json:"flowCount"`
	UpdateTime time.Time `json:"updateTime"`
}

type Table interface {
	GetID() uint8
	GetName() string
	BuildFlow(priority uint16) FlowBuilder
	GetMissAction() MissActionType
	Status() TableStatus
	GetNext() uint8
	SetNext(next uint8)
	SetMissAction(action MissActionType)
	GetStageID() StageID
	// SetTable is used only for testing.
	SetTable()
}

type PipelineID uint8

type StageID uint8

type Pipeline interface {
	GetFirstTableInStage(id StageID) Table
	GetFirstTable() Table
	ListAllTables() []Table
	IsLastTable(t Table) bool
}

type EntryType string

const (
	FlowEntry  EntryType = "FlowEntry"
	GroupEntry EntryType = "GroupEntry"
	MeterEntry EntryType = "MeterEntry"
)

type OFEntry interface {
	Add() error
	Modify() error
	Delete() error
	Type() EntryType
	// Reset ensures that the entry is "correct" and that the Add /
	// Modify / Delete methods can be called on this object. This method
	// should be called if a reconnection event happened.
	Reset()
	// GetBundleMessages returns a slice of ofctrl.OpenFlowModMessage which can be used in Bundle messages. operation
	// specifies what operation is expected to be taken on the OFEntry.
	GetBundleMessages(operation OFOperation) ([]ofctrl.OpenFlowModMessage, error)
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
}

type Action interface {
	LoadARPOperation(value uint16) FlowBuilder
	LoadToRegField(field *RegField, value uint32) FlowBuilder
	LoadRegMark(marks ...*RegMark) FlowBuilder
	LoadPktMarkRange(value uint32, to *Range) FlowBuilder
	LoadIPDSCP(value uint8) FlowBuilder
	Move(from, to string) FlowBuilder
	MoveRange(fromName, toName string, from, to Range) FlowBuilder
	ResubmitToTables(tables ...uint8) FlowBuilder
	CT(commit bool, tableID uint8, zone int, zoneSrcField *RegField) CTAction
	Drop() FlowBuilder
	Output(port uint32) FlowBuilder
	OutputFieldRange(from string, rng *Range) FlowBuilder
	OutputToRegField(field *RegField) FlowBuilder
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
	SetTunnelID(tunnelID uint64) FlowBuilder
	PopVLAN() FlowBuilder
	PushVLAN(etherType uint16) FlowBuilder
	SetVLAN(vlanID uint16) FlowBuilder
	DecTTL() FlowBuilder
	Normal() FlowBuilder
	Conjunction(conjID uint32, clauseID uint8, nClause uint8) FlowBuilder
	Group(id GroupIDType) FlowBuilder
	Learn(id uint8, priority uint16, idleTimeout, hardTimeout, finIdleTimeout, finHardTimeout uint16, cookieID uint64) LearnAction
	GotoTable(table uint8) FlowBuilder
	NextTable() FlowBuilder
	GotoStage(stage StageID) FlowBuilder
	SendToController(userdata []byte, pause bool) FlowBuilder
	Note(notes string) FlowBuilder
	Meter(meterID uint32) FlowBuilder
}

type FlowBuilder interface {
	MatchPriority(uint16) FlowBuilder
	MatchProtocol(name Protocol) FlowBuilder
	MatchIPProtocolValue(isIPv6 bool, protoValue uint8) FlowBuilder
	MatchXXReg(regID int, data []byte) FlowBuilder
	MatchRegMark(marks ...*RegMark) FlowBuilder
	MatchRegFieldWithValue(field *RegField, data uint32) FlowBuilder
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
	MatchIPDSCP(dscp uint8) FlowBuilder
	MatchCTState(ctStates *openflow15.CTStates) FlowBuilder
	MatchCTStateNew(isSet bool) FlowBuilder
	MatchCTStateRel(isSet bool) FlowBuilder
	MatchCTStateRpl(isSet bool) FlowBuilder
	MatchCTStateEst(isSet bool) FlowBuilder
	MatchCTStateTrk(isSet bool) FlowBuilder
	MatchCTStateInv(isSet bool) FlowBuilder
	MatchCTStateDNAT(isSet bool) FlowBuilder
	MatchCTStateSNAT(isSet bool) FlowBuilder
	MatchCTMark(marks ...*CtMark) FlowBuilder
	MatchCTLabelField(high, low uint64, field *CtLabel) FlowBuilder
	MatchPktMark(value uint32, mask *uint32) FlowBuilder
	MatchConjID(value uint32) FlowBuilder
	MatchDstPort(port uint16, portMask *uint16) FlowBuilder
	MatchSrcPort(port uint16, portMask *uint16) FlowBuilder
	MatchTCPFlags(flag, mask uint16) FlowBuilder
	MatchICMPType(icmpType byte) FlowBuilder
	MatchICMPCode(icmpCode byte) FlowBuilder
	MatchICMPv6Type(icmp6Type byte) FlowBuilder
	MatchICMPv6Code(icmp6Code byte) FlowBuilder
	MatchTunnelDst(dstIP net.IP) FlowBuilder
	MatchTunnelID(tunnelID uint64) FlowBuilder
	MatchVLAN(nonVLAN bool, vlanId uint16, vlanMask *uint16) FlowBuilder
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
	MatchEthernetProtocol(isIPv6 bool) LearnAction
	MatchIPProtocol(protocol Protocol) LearnAction
	MatchLearnedDstPort(protocol Protocol) LearnAction
	MatchLearnedSrcPort(protocol Protocol) LearnAction
	MatchLearnedSrcIP(isIPv6 bool) LearnAction
	MatchLearnedDstIP(isIPv6 bool) LearnAction
	MatchRegMark(marks ...*RegMark) LearnAction
	LoadRegMark(marks ...*RegMark) LearnAction
	LoadFieldToField(fromField, toField *RegField) LearnAction
	LoadXXRegToXXReg(fromXXField, toXXField *XXRegField) LearnAction
	Done() FlowBuilder
}

type Group interface {
	OFEntry
	ResetBuckets() Group
	Bucket() BucketBuilder
	GetID() GroupIDType
}

type BucketBuilder interface {
	Weight(val uint16) BucketBuilder
	LoadXXReg(regID int, data []byte) BucketBuilder
	LoadToRegField(field *RegField, data uint32) BucketBuilder
	LoadRegMark(mark *RegMark) BucketBuilder
	ResubmitToTable(tableID uint8) BucketBuilder
	SetTunnelDst(addr net.IP) BucketBuilder
	Done() Group
}

type Meter interface {
	OFEntry
	ResetMeterBands() Meter
	MeterBand() MeterBandBuilder
}

type MeterBandBuilder interface {
	MeterType(meterType ofctrl.MeterType) MeterBandBuilder
	Rate(rate uint32) MeterBandBuilder
	Burst(burst uint32) MeterBandBuilder
	PrecLevel(precLevel uint8) MeterBandBuilder
	Experimenter(experimenter uint32) MeterBandBuilder
	Done() Meter
}

type CTAction interface {
	LoadToCtMark(marks ...*CtMark) CTAction
	// LoadToLabelField loads a data into ct_label field. If the expected label is larger than the max value of uint64
	// (0xffffffffffffffff), call this function twice: one is to set the low 64 bits, and the other is to set the high
	// 64 bits.
	LoadToLabelField(value uint64, labelField *CtLabel) CTAction
	MoveToLabel(fromName string, fromRng, labelRng *Range) CTAction
	MoveToCtMarkField(fromRegField *RegField, ctMark *CtMarkField) CTAction
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
	SetIPProtocolValue(isIPv6 bool, protoValue uint8) PacketOutBuilder
	SetTTL(ttl uint8) PacketOutBuilder
	SetIPFlags(flags uint16) PacketOutBuilder
	SetIPHeaderID(id uint16) PacketOutBuilder
	SetTCPSrcPort(port uint16) PacketOutBuilder
	SetTCPDstPort(port uint16) PacketOutBuilder
	SetTCPFlags(flags uint8) PacketOutBuilder
	SetTCPSeqNum(seqNum uint32) PacketOutBuilder
	SetTCPAckNum(ackNum uint32) PacketOutBuilder
	SetTCPHdrLen(hdrLen uint8) PacketOutBuilder
	SetTCPWinSize(winSize uint16) PacketOutBuilder
	SetTCPData(data []byte) PacketOutBuilder
	SetUDPSrcPort(port uint16) PacketOutBuilder
	SetUDPDstPort(port uint16) PacketOutBuilder
	SetUDPData(data []byte) PacketOutBuilder
	SetICMPType(icmpType uint8) PacketOutBuilder
	SetICMPCode(icmpCode uint8) PacketOutBuilder
	SetICMPID(id uint16) PacketOutBuilder
	SetICMPSequence(seq uint16) PacketOutBuilder
	SetICMPData(data []byte) PacketOutBuilder
	SetInport(inPort uint32) PacketOutBuilder
	SetOutport(outport uint32) PacketOutBuilder
	// AddSetIPTOSAction sets the IP_TOS field in the packet-out message. The action clears the two ECN bits as 0,
	// and only 2-7 bits of the DSCP field in IP header is set.
	AddSetIPTOSAction(data uint8) PacketOutBuilder
	AddLoadRegMark(mark *RegMark) PacketOutBuilder
	AddResubmitAction(inPort *uint16, table *uint8) PacketOutBuilder
	SetL4Packet(packet util.Message) PacketOutBuilder
	SetEthPacket(packet *protocol.Ethernet) PacketOutBuilder
	Done() *ofctrl.PacketOut
}

type ctBase struct {
	commit         bool
	force          bool
	ctTable        uint8
	ctZoneImm      uint16
	ctZoneSrcField *RegField
}

type IPRange struct {
	StartIP net.IP
	EndIP   net.IP
}

type PortRange struct {
	StartPort uint16
	EndPort   uint16
}

type Packet struct {
	IsIPv6          bool
	DestinationMAC  net.HardwareAddr
	SourceMAC       net.HardwareAddr
	DestinationIP   net.IP
	SourceIP        net.IP
	IPLength        uint16
	IPProto         uint8
	IPFlags         uint16
	TTL             uint8
	DestinationPort uint16
	SourcePort      uint16
	TCPFlags        uint8
	ICMPType        uint8
	ICMPCode        uint8
	ICMPEchoID      uint16
	ICMPEchoSeq     uint16
}

// RegField specifies a bit range of a register. regID is the register number, and rng is the range of bits
// taken by the field. The OF client could use a RegField to cache or match varied value.
type RegField struct {
	regID int
	rng   *Range
}

// RegMark is a value saved in a RegField. A RegMark is used to indicate the traffic
// has some expected characteristics.
type RegMark struct {
	field *RegField
	value uint32
}

// XXRegField specifies a xxreg with a required bit range.
type XXRegField RegField

// CtMarkField specifies a bit range of a CT mark. rng is the range of bits taken by the field. The OF client could use a
// CtMarkField to cache or match varied value.
type CtMarkField struct {
	rng *Range
}

// CtMark is used to indicate the connection characteristics.
type CtMark struct {
	field *CtMarkField
	value uint32
}

type CtLabel struct {
	rng *Range
}
