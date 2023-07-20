// Copyright 2022 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openflow

import (
	"encoding/binary"
	"net"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	utilnet "k8s.io/utils/net"
)

type ofFlowAction struct {
	builder *ofFlowBuilder
}

// Drop is an action to drop packets.
func (a *ofFlowAction) Drop() FlowBuilder {
	a.builder.Drop()
	return a.builder
}

// Output is an action to output packets to the specified ofport.
func (a *ofFlowAction) Output(port uint32) FlowBuilder {
	outputAction := ofctrl.NewOutputPort(port)
	a.builder.ApplyAction(outputAction)
	return a.builder
}

// OutputFieldRange is an action to output packets to the port located in the specified NXM field with rng.
func (a *ofFlowAction) OutputFieldRange(name string, rng *Range) FlowBuilder {
	outputAction, _ := ofctrl.NewNXOutput(name, int(rng[0]), int(rng[1]))
	a.builder.ApplyAction(outputAction)
	return a.builder
}

func (a *ofFlowAction) OutputToRegField(field *RegField) FlowBuilder {
	name := field.GetNXFieldName()
	return a.OutputFieldRange(name, field.rng)
}

// OutputInPort is an action to output packets to the ofport from where the packet enters the OFSwitch.
func (a *ofFlowAction) OutputInPort() FlowBuilder {
	outputAction := ofctrl.NewOutputInPort()
	a.builder.ApplyAction(outputAction)
	return a.builder
}

// CT is an action to set conntrack marks and return CTAction to add actions that is executed with conntrack context.
// zone will be ignored if zoneSrcField is not nil.
func (a *ofFlowAction) CT(commit bool, tableID uint8, zone int, zoneSrcField *RegField) CTAction {
	base := ctBase{
		commit:         commit,
		force:          false,
		ctTable:        tableID,
		ctZoneImm:      uint16(zone),
		ctZoneSrcField: zoneSrcField,
	}
	ct := &ofCTAction{
		ctBase:  base,
		builder: a.builder,
	}
	return ct
}

// ofCTAction is a struct to implement CTAction.
type ofCTAction struct {
	ctBase
	actions []openflow15.Action
	builder *ofFlowBuilder
}

func (a *ofCTAction) LoadToCtMark(marks ...*CtMark) CTAction {
	for _, mark := range marks {
		maskData := ^uint32(0) >> (32 - mark.field.rng.Length()) << mark.field.rng.Offset()
		valueData := mark.value << mark.field.rng.Offset()
		ctMarkField := openflow15.NewCTMarkMatchField(valueData, &maskData)
		action := openflow15.NewActionSetField(*ctMarkField)
		a.actions = append(a.actions, action)
	}
	return a
}

func (a *ofCTAction) LoadToLabelField(value uint64, labelField *CtLabel) CTAction {
	var labelBytes, maskBytes [16]byte

	mask := ^uint64(0) >> (64 - labelField.rng.Length()) << (labelField.rng.Offset() % 64)
	valueData := value << (labelField.rng.Offset() % 64)
	if labelField.rng.Offset() > 63 {
		binary.BigEndian.PutUint64(maskBytes[0:8], mask)
		binary.BigEndian.PutUint64(labelBytes[0:8], valueData)
	} else {
		binary.BigEndian.PutUint64(maskBytes[8:], mask)
		binary.BigEndian.PutUint64(labelBytes[8:], valueData)
	}
	ctLabelField := openflow15.NewCTLabelMatchField(labelBytes, &maskBytes)
	action := openflow15.NewActionSetField(*ctLabelField)
	a.actions = append(a.actions, action)
	return a
}

// MoveToLabel is an action to move data into ct_label.
func (a *ofCTAction) MoveToLabel(fromName string, fromRng, labelRng *Range) CTAction {
	fromField, _ := openflow15.FindOxmIdByName(fromName, false)
	toField, _ := openflow15.FindOxmIdByName(NxmFieldCtLabel, false)
	a.move(fromField, toField, uint16(fromRng.Length()), uint16(fromRng[0]), uint16(labelRng[0]))
	return a
}

// MoveToCtMarkField is an action to move data into ct_mark.
func (a *ofCTAction) MoveToCtMarkField(fromRegField *RegField, ctMarkField *CtMarkField) CTAction {
	fromField, _ := openflow15.FindOxmIdByName(fromRegField.GetNXFieldName(), false)
	toField, _ := openflow15.FindOxmIdByName(NxmFieldCtMark, false)
	a.move(fromField, toField, uint16(fromRegField.GetRange().Length()), uint16(fromRegField.GetRange()[0]), uint16(ctMarkField.rng[0]))
	return a
}

func (a *ofCTAction) move(fromField *openflow15.OxmId, toField *openflow15.OxmId, nBits, fromStart, toStart uint16) {
	action := openflow15.NewActionCopyField(nBits, fromStart, toStart, *fromField, *toField)
	a.actions = append(a.actions, action)
}

func (a *ofCTAction) natAction(isSNAT bool, ipRange *IPRange, portRange *PortRange) CTAction {
	action := openflow15.NewNXActionCTNAT()
	if isSNAT {
		action.SetSNAT()
	} else {
		action.SetDNAT()
	}

	// ipRange should not be nil. The check here is for code safety.
	if ipRange != nil {
		if utilnet.IsIPv6(ipRange.StartIP) {
			action.SetRangeIPv6Min(ipRange.StartIP)
			action.SetRangeIPv6Max(ipRange.EndIP)
		} else {
			action.SetRangeIPv4Min(ipRange.StartIP)
			action.SetRangeIPv4Max(ipRange.EndIP)
		}
	}
	if portRange != nil {
		action.SetRangeProtoMin(&portRange.StartPort)
		action.SetRangeProtoMax(&portRange.EndPort)
	}
	a.actions = append(a.actions, action)
	return a
}

func (a *ofCTAction) SNAT(ipRange *IPRange, portRange *PortRange) CTAction {
	return a.natAction(true, ipRange, portRange)
}

func (a *ofCTAction) DNAT(ipRange *IPRange, portRange *PortRange) CTAction {
	return a.natAction(false, ipRange, portRange)
}

func (a *ofCTAction) NAT() CTAction {
	action := openflow15.NewNXActionCTNAT()
	a.actions = append(a.actions, action)
	return a
}

// CTDone sets the conntrack action in the Openflow rule and it returns FlowBuilder.
func (a *ofCTAction) CTDone() FlowBuilder {
	var conntrackAct *ofctrl.NXConnTrackAction
	if a.ctZoneSrcField == nil {
		conntrackAct = ofctrl.NewNXConnTrackAction(a.commit, a.force, &a.ctTable, &a.ctZoneImm, a.actions...)
	} else {
		conntrackAct = ofctrl.NewNXConnTrackActionWithZoneField(a.commit, a.force, &a.ctTable, nil, a.ctZoneSrcField.GetNXFieldName(), a.ctZoneSrcField.GetRange().ToNXRange(), a.actions...)
	}
	a.builder.ApplyAction(conntrackAct)
	return a.builder
}

// SetDstMAC is an action to modify packet destination MAC address to the specified address.
func (a *ofFlowAction) SetDstMAC(addr net.HardwareAddr) FlowBuilder {
	setDstMACAct := &ofctrl.SetDstMACAction{MAC: addr}
	a.builder.ApplyAction(setDstMACAct)
	return a.builder
}

// SetSrcMAC is an action to modify packet source MAC address to the specified address.
func (a *ofFlowAction) SetSrcMAC(addr net.HardwareAddr) FlowBuilder {
	setSrcMACAct := &ofctrl.SetSrcMACAction{MAC: addr}
	a.builder.ApplyAction(setSrcMACAct)
	return a.builder
}

// SetARPSha is an action to modify ARP packet source hardware address to the specified address.
func (a *ofFlowAction) SetARPSha(addr net.HardwareAddr) FlowBuilder {
	setARPShaAct := &ofctrl.SetARPShaAction{MAC: addr}
	a.builder.ApplyAction(setARPShaAct)
	return a.builder
}

// SetARPTha is an action to modify ARP packet target hardware address to the specified address.
func (a *ofFlowAction) SetARPTha(addr net.HardwareAddr) FlowBuilder {
	setARPThaAct := &ofctrl.SetARPThaAction{MAC: addr}
	a.builder.ApplyAction(setARPThaAct)
	return a.builder
}

// SetARPSpa is an action to modify ARP packet source protocol address to the specified address.
func (a *ofFlowAction) SetARPSpa(addr net.IP) FlowBuilder {
	setARPSpaAct := &ofctrl.SetARPSpaAction{IP: addr}
	a.builder.ApplyAction(setARPSpaAct)
	return a.builder
}

// SetARPTpa is an action to modify ARP packet target protocol address to the specified address.
func (a *ofFlowAction) SetARPTpa(addr net.IP) FlowBuilder {
	setARPTpaAct := &ofctrl.SetARPTpaAction{IP: addr}
	a.builder.ApplyAction(setARPTpaAct)
	return a.builder
}

// SetSrcIP is an action to modify packet source IP address to the specified address.
func (a *ofFlowAction) SetSrcIP(addr net.IP) FlowBuilder {
	setSrcIPAct := &ofctrl.SetSrcIPAction{IP: addr}
	a.builder.ApplyAction(setSrcIPAct)
	return a.builder
}

// SetDstIP is an action to modify packet destination IP address to the specified address.
func (a *ofFlowAction) SetDstIP(addr net.IP) FlowBuilder {
	setDstIPAct := &ofctrl.SetDstIPAction{IP: addr}
	a.builder.ApplyAction(setDstIPAct)
	return a.builder
}

// SetTunnelDst is an action to modify packet tunnel destination address to the specified address.
func (a *ofFlowAction) SetTunnelDst(addr net.IP) FlowBuilder {
	setTunDstAct := &ofctrl.SetTunnelDstAction{IP: addr}
	a.builder.ApplyAction(setTunDstAct)
	return a.builder
}

// SetTunnelID is an action to modify packet tunnel ID to the specified ID.
func (a *ofFlowAction) SetTunnelID(tunnelID uint64) FlowBuilder {
	setTunIDAct := &ofctrl.SetTunnelIDAction{TunnelID: tunnelID}
	a.builder.ApplyAction(setTunIDAct)
	return a.builder
}

// PopVLAN is an action to pop VLAN ID.
func (a *ofFlowAction) PopVLAN() FlowBuilder {
	popVLANAct := &ofctrl.PopVLANAction{}
	a.builder.ApplyAction(popVLANAct)
	return a.builder
}

// PushVLAN is an action to add VLAN ID.
func (a *ofFlowAction) PushVLAN(etherType uint16) FlowBuilder {
	pushVLANAct := &ofctrl.PushVLANAction{EtherType: etherType}
	a.builder.ApplyAction(pushVLANAct)
	return a.builder
}

// SetVLAN is an action to set existing VLAN ID.
func (a *ofFlowAction) SetVLAN(vlanID uint16) FlowBuilder {
	setVLANAct := &ofctrl.SetVLANAction{VlanID: vlanID}
	a.builder.ApplyAction(setVLANAct)
	return a.builder
}

// LoadARPOperation is an action to load data to NXM_OF_ARP_OP field.
func (a *ofFlowAction) LoadARPOperation(value uint16) FlowBuilder {
	loadAct := &ofctrl.SetARPOpAction{Value: value}
	a.builder.ApplyAction(loadAct)
	return a.builder
}

func (a *ofFlowAction) LoadToRegField(field *RegField, value uint32) FlowBuilder {
	valueData := value
	mask := uint32(0)
	if field.rng != nil {
		mask = ^mask >> (32 - field.rng.Length()) << field.rng.Offset()
		valueData = valueData << field.rng.Offset()
	}
	f := openflow15.NewRegMatchFieldWithMask(field.regID, valueData, mask)
	act := ofctrl.NewSetFieldAction(f)
	a.builder.ApplyAction(act)
	return a.builder
}

func (a *ofFlowAction) LoadRegMark(marks ...*RegMark) FlowBuilder {
	var fb FlowBuilder
	fb = a.builder
	for _, mark := range marks {
		fb = a.LoadToRegField(mark.field, mark.value)
	}
	return fb
}

// LoadPktMarkRange is an action to load data into pkt_mark at specified range.
func (a *ofFlowAction) LoadPktMarkRange(value uint32, rng *Range) FlowBuilder {
	pktMarkField, _ := openflow15.FindFieldHeaderByName(NxmFieldPktMark, true)
	valueBytes := make([]byte, 4)
	maskBytes := make([]byte, 4)
	valueData := value
	mask := uint32(0)
	if rng != nil {
		mask = ^mask >> (32 - rng.Length()) << rng.Offset()
		binary.BigEndian.PutUint32(maskBytes, mask)
		pktMarkField.Mask = util.NewBuffer(maskBytes)
		valueData = valueData << rng.Offset()
	}
	binary.BigEndian.PutUint32(valueBytes, valueData)
	pktMarkField.Value = util.NewBuffer(valueBytes)
	return a.setField(pktMarkField)
}

// LoadIPDSCP is an action to load data to IP DSCP bits.
func (a *ofFlowAction) LoadIPDSCP(value uint8) FlowBuilder {
	field, _ := openflow15.FindFieldHeaderByName(NxmFieldIPToS, true)
	field.Value = &openflow15.IpDscpField{Dscp: value << IPDSCPToSRange.Offset()}
	field.Mask = &openflow15.IpDscpField{Dscp: uint8(0xff) >> (8 - IPDSCPToSRange.Length()) << IPDSCPToSRange.Offset()}
	return a.setField(field)
}

func (a *ofFlowAction) setField(field *openflow15.MatchField) FlowBuilder {
	loadAct := ofctrl.NewSetFieldAction(field)
	a.builder.ApplyAction(loadAct)
	return a.builder
}

// Move is an action to copy all data from "fromField" to "toField". Fields with name "fromField" and "fromField" should
// have the same data length, otherwise there will be error when realizing the flow on OFSwitch.
func (a *ofFlowAction) Move(fromField, toField string) FlowBuilder {
	_, fromRange, _ := getFieldRange(fromField)
	_, toRange, _ := getFieldRange(fromField)
	return a.MoveRange(fromField, toField, fromRange, toRange)
}

// MoveRange is an action to move data from "fromField" at "fromRange" to "toField" at "toRange".
func (a *ofFlowAction) MoveRange(fromField, toField string, fromRange, toRange Range) FlowBuilder {
	srcOxmId, _ := openflow15.FindOxmIdByName(fromField, false)
	dstOxmId, _ := openflow15.FindOxmIdByName(toField, false)
	return a.copyField(srcOxmId, dstOxmId, fromRange, toRange)
}

func (a *ofFlowAction) copyField(srcOxmId, dstOxmId *openflow15.OxmId, fromRange, toRange Range) FlowBuilder {
	nBits := fromRange.ToNXRange().GetNbits()
	srcOffset := fromRange.ToNXRange().GetOfs()
	dstOffset := toRange.ToNXRange().GetOfs()
	moveAct := ofctrl.NewCopyFieldAction(nBits, srcOffset, dstOffset, srcOxmId, dstOxmId)
	a.builder.ApplyAction(moveAct)
	return a.builder
}

// Resubmit is an action to resubmit packet to the specified table with the port as new in_port. If port is empty string,
// the in_port field is not changed.
func (a *ofFlowAction) Resubmit(ofPort uint16, tableID uint8) FlowBuilder {
	table := tableID
	resubmitAct := ofctrl.NewResubmit(&ofPort, &table)
	a.builder.ApplyAction(resubmitAct)
	return a.builder
}

func (a *ofFlowAction) ResubmitToTables(tables ...uint8) FlowBuilder {
	var fb FlowBuilder
	for _, t := range tables {
		fb = a.Resubmit(openflow15.OFPP_IN_PORT, t)
	}
	return fb
}

// DecTTL is an action to decrease TTL. It is used in routing functions implemented by Openflow.
func (a *ofFlowAction) DecTTL() FlowBuilder {
	decTTLAct := new(ofctrl.DecTTLAction)
	a.builder.ApplyAction(decTTLAct)
	return a.builder
}

// Normal is an action to leverage OVS fwd table to forwarding packets.
func (a *ofFlowAction) Normal() FlowBuilder {
	normalAction := ofctrl.NewOutputNormal()
	a.builder.ApplyAction(normalAction)
	return a.builder
}

// Conjunction is an action to add new conjunction configuration to conjunctive match flow.
func (a *ofFlowAction) Conjunction(conjID uint32, clauseID uint8, nClause uint8) FlowBuilder {
	conjunctionAct, _ := ofctrl.NewNXConjunctionAction(conjID, clauseID, nClause)
	a.builder.ApplyAction(conjunctionAct)
	return a.builder
}

// Group is an action to forward packets to groups to do load-balance.
func (a *ofFlowAction) Group(id GroupIDType) FlowBuilder {
	group := &ofctrl.Group{
		Switch: a.builder.Flow.Table.Switch,
		ID:     uint32(id),
	}
	a.builder.ApplyAction(group)
	return a.builder
}

// Note annotates the OpenFlow entry. The notes are presented as hex digits in the OpenFlow entry, and it will be
// padded on the right to make the total number of bytes 6 more than a multiple of 8.
func (a *ofFlowAction) Note(notes string) FlowBuilder {
	noteAct := &ofctrl.NXNoteAction{Notes: []byte(notes)}
	a.builder.ApplyAction(noteAct)
	return a.builder
}

// SendToController will send the packet to the OVS controller.
// If pause option is true, the packet will be sent to the controller and meanwhile
// also paused in the pipeline. The controller could use a resume message to resume
// this packet letting it continue its journey in the pipeline from where it was
// paused.
// As for the userdata, the first 2 bytes are used for packetIn. The first byte is
// packetIn category, which indicates the handler of this packetIn. The second
// byte is packetIn operation, which indicates the operation(s) that should be
// executed by the handler.
func (a *ofFlowAction) SendToController(userdata []byte, pause bool) FlowBuilder {
	if a.builder.ofFlow.Table != nil && a.builder.ofFlow.Table.Switch != nil {
		controllerAct := &ofctrl.NXController{
			Version2:     true,
			ControllerID: a.builder.ofFlow.Table.Switch.GetControllerID(),
			UserData:     userdata,
			Pause:        pause,
		}
		a.builder.ApplyAction(controllerAct)
	}
	return a.builder
}

func (a *ofFlowAction) Meter(meterID uint32) FlowBuilder {
	meterAction := ofctrl.NewMeterAction(meterID)
	a.builder.ApplyAction(meterAction)
	return a.builder
}

// Learn is an action which adds or modifies a flow in an OpenFlow table.
func (a *ofFlowAction) Learn(id uint8, priority uint16, idleTimeout, hardTimeout, finIdleTimeout, finHardTimeout uint16, cookieID uint64) LearnAction {
	la := &ofLearnAction{
		flowBuilder: a.builder,
		nxLearn:     ofctrl.NewLearnAction(id, priority, idleTimeout, hardTimeout, finIdleTimeout, finHardTimeout, cookieID),
	}
	return la
}

// ofLearnAction is used to describe actions in the learned flow.
type ofLearnAction struct {
	flowBuilder *ofFlowBuilder
	nxLearn     *ofctrl.FlowLearn
}

// DeleteLearned makes learned flows to be deleted when current flow is being deleted.
func (a *ofLearnAction) DeleteLearned() LearnAction {
	a.nxLearn.DeleteLearnedFlowsAfterDeletion()
	return a
}

// MatchEthernetProtocol specifies that the NXM_OF_ETH_TYPE field in the
// learned flow must match IP(0x800) or IPv6(0x86dd).
func (a *ofLearnAction) MatchEthernetProtocol(isIPv6 bool) LearnAction {
	ethTypeVal := make([]byte, 2)
	var ipProto uint16 = 0x800
	if isIPv6 {
		ipProto = 0x86dd
	}
	binary.BigEndian.PutUint16(ethTypeVal, ipProto)
	a.nxLearn.AddMatch(&ofctrl.LearnField{Name: NxmFieldEthType}, 2*8, nil, ethTypeVal)
	return a
}

func (a *ofLearnAction) MatchIPProtocol(protocol Protocol) LearnAction {
	var ipProtoValue int
	switch protocol {
	case ProtocolTCP:
		ipProtoValue = ofctrl.IP_PROTO_TCP
	case ProtocolUDP:
		ipProtoValue = ofctrl.IP_PROTO_UDP
	case ProtocolSCTP:
		ipProtoValue = ofctrl.IP_PROTO_SCTP
	case ProtocolTCPv6:
		ipProtoValue = ofctrl.IP_PROTO_TCP
	case ProtocolUDPv6:
		ipProtoValue = ofctrl.IP_PROTO_UDP
	case ProtocolSCTPv6:
		ipProtoValue = ofctrl.IP_PROTO_SCTP
	default:
		// Return directly if the protocol is not supported.
		return a
	}
	ipTypeVal := make([]byte, 2)
	ipTypeVal[1] = byte(ipProtoValue)
	a.nxLearn.AddMatch(&ofctrl.LearnField{Name: NxmFieldIPProto}, 1*8, nil, ipTypeVal)
	return a
}

// MatchLearnedDstPort specifies that the transport layer destination field
// {tcp|udp|sctp}_dst in the learned flow must match the same field of the packet
// currently being processed. It only accepts ProtocolTCP, ProtocolUDP, or
// ProtocolSCTP, and does nothing for other protocols.
func (a *ofLearnAction) MatchLearnedDstPort(protocol Protocol) LearnAction {
	// OXM_OF fields support TCP, UDP and SCTP, but NXM_OF fields only support TCP and UDP. So here use "OXM_OF_" to
	// generate the field name.
	var regName string
	switch protocol {
	case ProtocolTCP, ProtocolTCPv6:
		regName = OxmFieldTCPDst
	case ProtocolUDP, ProtocolUDPv6:
		regName = OxmFieldUDPDst
	case ProtocolSCTP, ProtocolSCTPv6:
		regName = OxmFieldSCTPDst
	default:
		// Return directly if the protocol is not supported.
		return a
	}
	a.nxLearn.AddMatch(&ofctrl.LearnField{Name: regName}, 2*8, &ofctrl.LearnField{Name: regName}, nil)
	return a
}

// MatchLearnedSrcPort specifies that the transport layer source field
// {tcp|udp|sctp}_src in the learned flow must match the same field of the packet
// currently being processed. It only accepts ProtocolTCP, ProtocolUDP, or
// ProtocolSCTP, and does nothing for other protocols.
func (a *ofLearnAction) MatchLearnedSrcPort(protocol Protocol) LearnAction {
	// OXM_OF fields support TCP, UDP and SCTP, but NXM_OF fields only support TCP and UDP. So here use "OXM_OF_" to
	// generate the field name.
	var regName string
	switch protocol {
	case ProtocolTCP, ProtocolTCPv6:
		regName = OxmFieldTCPSrc
	case ProtocolUDP, ProtocolUDPv6:
		regName = OxmFieldUDPSrc
	case ProtocolSCTP, ProtocolSCTPv6:
		regName = OxmFieldSCTPSrc
	default:
		// Return directly if the protocol is not supported.
		return a
	}
	a.nxLearn.AddMatch(&ofctrl.LearnField{Name: regName}, 2*8, &ofctrl.LearnField{Name: regName}, nil)
	return a
}

// MatchLearnedSrcIP makes the learned flow match the nw_src of current IP packet.
func (a *ofLearnAction) MatchLearnedSrcIP(isIPv6 bool) LearnAction {
	regName := NxmFieldSrcIPv4
	learnBits := uint16(4 * 8)
	if isIPv6 {
		regName = NxmFieldSrcIPv6
		learnBits = 16 * 8
	}
	a.nxLearn.AddMatch(&ofctrl.LearnField{Name: regName}, learnBits, &ofctrl.LearnField{Name: regName}, nil)
	return a
}

// MatchLearnedDstIP makes the learned flow match the nw_dst of current IP packet.
func (a *ofLearnAction) MatchLearnedDstIP(isIPv6 bool) LearnAction {
	regName := NxmFieldDstIPv4
	learnBits := uint16(4 * 8)
	if isIPv6 {
		regName = NxmFieldDstIPv6
		learnBits = 16 * 8
	}
	a.nxLearn.AddMatch(&ofctrl.LearnField{Name: regName}, learnBits, &ofctrl.LearnField{Name: regName}, nil)
	return a
}

func (a *ofLearnAction) MatchRegMark(marks ...*RegMark) LearnAction {
	for _, mark := range marks {
		toField := &ofctrl.LearnField{Name: mark.field.GetNXFieldName(), Start: uint16(mark.field.rng[0])}
		valBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(valBuf, mark.value)
		offset := (mark.field.rng.Length() + 7) / 8
		if offset < 2 {
			offset = 2
		}
		a.nxLearn.AddMatch(toField, uint16(mark.field.rng.Length()), nil, valBuf[4-offset:])
	}
	return a
}

func (a *ofLearnAction) LoadFieldToField(fromField, toField *RegField) LearnAction {
	from := &ofctrl.LearnField{Name: fromField.GetNXFieldName(), Start: uint16(fromField.rng[0])}
	to := &ofctrl.LearnField{Name: toField.GetNXFieldName(), Start: uint16(toField.rng[0])}
	a.nxLearn.AddLoadAction(to, uint16(toField.rng.Length()), from, nil)
	return a
}

// LoadXXRegToXXReg makes the learned flow to load reg[fromXXField.regID] to reg[toXXField.regID]
// with specific ranges.
func (a *ofLearnAction) LoadXXRegToXXReg(fromXXField, toXXField *XXRegField) LearnAction {
	from := &ofctrl.LearnField{Name: fromXXField.GetNXFieldName(), Start: uint16(fromXXField.rng[0])}
	to := &ofctrl.LearnField{Name: toXXField.GetNXFieldName(), Start: uint16(toXXField.rng[0])}
	a.nxLearn.AddLoadAction(to, uint16(toXXField.rng.Length()), from, nil)
	return a
}

func (a *ofLearnAction) LoadRegMark(marks ...*RegMark) LearnAction {
	for _, mark := range marks {
		toField := &ofctrl.LearnField{Name: mark.field.GetNXFieldName(), Start: uint16(mark.field.rng[0])}
		valBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(valBuf, mark.value)
		offset := (mark.field.rng.Length() + 7) / 8
		if offset < 2 {
			offset = 2
		}
		a.nxLearn.AddLoadAction(toField, uint16(mark.field.rng.Length()), nil, valBuf[4-offset:])
	}
	return a
}

func (a *ofLearnAction) Done() FlowBuilder {
	a.flowBuilder.ApplyAction(a.nxLearn)
	return a.flowBuilder
}

func getFieldRange(name string) (*openflow15.MatchField, Range, error) {
	field, err := openflow15.FindFieldHeaderByName(name, false)
	if err != nil {
		return field, Range{0, 0}, err
	}
	return field, Range{0, uint32(field.Length)*8 - 1}, nil
}

// GotoTable is an action to jump to the specified table.
func (a *ofFlowAction) GotoTable(tableID uint8) FlowBuilder {
	a.builder.ofFlow.Goto(tableID)
	return a.builder
}

func (a *ofFlowAction) NextTable() FlowBuilder {
	tableID := a.builder.ofFlow.table.next
	a.builder.ofFlow.Goto(tableID)
	return a.builder
}

func (a *ofFlowAction) GotoStage(stage StageID) FlowBuilder {
	pipeline := pipelineCache[a.builder.ofFlow.table.pipelineID]
	table := pipeline.GetFirstTableInStage(stage)
	a.builder.ofFlow.Goto(table.GetID())
	return a.builder
}
