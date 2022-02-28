package openflow

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	utilnet "k8s.io/utils/net"

	"antrea.io/libOpenflow/openflow13"
	"antrea.io/ofnet/ofctrl"
)

type ofFlowAction struct {
	builder *ofFlowBuilder
}

// Drop is an action to drop packets.
func (a *ofFlowAction) Drop() FlowBuilder {
	a.builder.Drop()
	a.builder.isDropFlow = true
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
func (a *ofFlowAction) CT(commit bool, tableID uint8, zone int) CTAction {
	base := ctBase{
		commit:  commit,
		force:   false,
		ctTable: tableID,
		ctZone:  uint16(zone),
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
	actions []openflow13.Action
	builder *ofFlowBuilder
}

// LoadToMark is an action to load data into ct_mark.
func (a *ofCTAction) LoadToMark(value uint32) CTAction {
	field, rng, _ := getFieldRange(NxmFieldCtMark)
	a.load(field, uint64(value), &rng)
	return a
}

func (a *ofCTAction) LoadToCtMark(mark *CtMark) CTAction {
	field, _, _ := getFieldRange(NxmFieldCtMark)
	a.load(field, uint64(mark.value), mark.field.rng)
	return a
}

func (a *ofCTAction) LoadToLabelField(value uint64, labelField *CtLabel) CTAction {
	field, _, _ := getFieldRange(NxmFieldCtLabel)
	a.load(field, value, labelField.rng)
	return a
}

func (a *ofCTAction) load(field *openflow13.MatchField, value uint64, rng *Range) {
	action := openflow13.NewNXActionRegLoad(rng.ToNXRange().ToOfsBits(), field, value)
	a.actions = append(a.actions, action)
}

// MoveToLabel is an action to move data into ct_label.
func (a *ofCTAction) MoveToLabel(fromName string, fromRng, labelRng *Range) CTAction {
	fromField, _ := openflow13.FindFieldHeaderByName(fromName, false)
	toField, _ := openflow13.FindFieldHeaderByName(NxmFieldCtLabel, false)
	a.move(fromField, toField, uint16(fromRng.Length()), uint16(fromRng[0]), uint16(labelRng[0]))
	return a
}

// MoveToCtMarkField is an action to move data into ct_mark.
func (a *ofCTAction) MoveToCtMarkField(fromRegField *RegField, ctMarkField *CtMarkField) CTAction {
	fromField, _ := openflow13.FindFieldHeaderByName(fromRegField.GetNXFieldName(), false)
	toField, _ := openflow13.FindFieldHeaderByName(NxmFieldCtMark, false)
	a.move(fromField, toField, uint16(fromRegField.GetRange().Length()), uint16(fromRegField.GetRange()[0]), uint16(ctMarkField.rng[0]))
	return a
}

func (a *ofCTAction) move(fromField *openflow13.MatchField, toField *openflow13.MatchField, nBits, fromStart, toStart uint16) {
	action := openflow13.NewNXActionRegMove(nBits, fromStart, toStart, fromField, toField)
	a.actions = append(a.actions, action)
}

func (a *ofCTAction) natAction(isSNAT bool, ipRange *IPRange, portRange *PortRange) CTAction {
	action := openflow13.NewNXActionCTNAT()
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
	action := openflow13.NewNXActionCTNAT()
	a.actions = append(a.actions, action)
	return a
}

// CTDone sets the conntrack action in the Openflow rule and it returns FlowBuilder.
func (a *ofCTAction) CTDone() FlowBuilder {
	conntrackAct := ofctrl.NewNXConnTrackAction(a.commit, a.force, &a.ctTable, &a.ctZone, a.actions...)
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

// LoadARPOperation is an action to Load data to NXM_OF_ARP_OP field.
func (a *ofFlowAction) LoadARPOperation(value uint16) FlowBuilder {
	loadAct, _ := ofctrl.NewNXLoadAction(NxmFieldARPOp, uint64(value), openflow13.NewNXRange(0, 15))
	a.builder.ApplyAction(loadAct)
	return a.builder
}

// LoadRange is an action to Load data to the target field at specified range.
func (a *ofFlowAction) LoadRange(name string, value uint64, rng *Range) FlowBuilder {
	loadAct, _ := ofctrl.NewNXLoadAction(name, value, rng.ToNXRange())
	if a.builder.ofFlow.Table != nil && a.builder.ofFlow.Table.Switch != nil {
		loadAct.ResetFieldLength(a.builder.ofFlow.Table.Switch)
	}
	a.builder.ApplyAction(loadAct)
	return a.builder
}

func (a *ofFlowAction) LoadToRegField(field *RegField, value uint32) FlowBuilder {
	name := field.GetNXFieldName()
	loadAct, _ := ofctrl.NewNXLoadAction(name, uint64(value), field.rng.ToNXRange())
	a.builder.ApplyAction(loadAct)
	return a.builder
}

func (a *ofFlowAction) LoadRegMark(mark *RegMark) FlowBuilder {
	return a.LoadToRegField(mark.field, mark.value)
}

// LoadToPktMarkRange is an action to load data into pkt_mark at specified range.
func (a *ofFlowAction) LoadPktMarkRange(value uint32, rng *Range) FlowBuilder {
	return a.LoadRange(NxmFieldPktMark, uint64(value), rng)
}

// LoadIPDSCP is an action to load data to IP DSCP bits.
func (a *ofFlowAction) LoadIPDSCP(value uint8) FlowBuilder {
	return a.LoadRange(NxmFieldIPToS, uint64(value), IPDSCPToSRange)
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
	moveAct, _ := ofctrl.NewNXMoveAction(fromField, toField, fromRange.ToNXRange(), toRange.ToNXRange())
	if a.builder.ofFlow.Table != nil && a.builder.ofFlow.Table.Switch != nil {
		moveAct.ResetFieldsLength(a.builder.ofFlow.Table.Switch)
	}
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

func (a *ofFlowAction) ResubmitToTable(table uint8) FlowBuilder {
	return a.Resubmit(openflow13.OFPP_IN_PORT, table)
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

func (a *ofFlowAction) SendToController(reason uint8) FlowBuilder {
	if a.builder.ofFlow.Table != nil && a.builder.ofFlow.Table.Switch != nil {
		controllerAct := &ofctrl.NXController{
			ControllerID: a.builder.ofFlow.Table.Switch.GetControllerID(),
			Reason:       reason,
		}
		a.builder.ApplyAction(controllerAct)
	}
	return a.builder
}

func (a *ofFlowAction) Meter(meterID uint32) FlowBuilder {
	a.builder.ofFlow.Meter(meterID)
	return a.builder
}

//  Learn is an action which adds or modifies a flow in an OpenFlow table.
func (a *ofFlowAction) Learn(id uint8, priority uint16, idleTimeout, hardTimeout uint16, cookieID uint64) LearnAction {
	la := &ofLearnAction{
		flowBuilder: a.builder,
		nxLearn:     ofctrl.NewLearnAction(id, priority, idleTimeout, hardTimeout, 0, 0, cookieID),
	}
	return la
}

// ofLearnAction is used to describe actions in the learn flow.
type ofLearnAction struct {
	flowBuilder *ofFlowBuilder
	nxLearn     *ofctrl.FlowLearn
}

// DeleteLearned makes learned flows to be deleted when current flow is being deleted.
func (a *ofLearnAction) DeleteLearned() LearnAction {
	a.nxLearn.DeleteLearnedFlowsAfterDeletion()
	return a
}

// MatchEthernetProtocolIP specifies that the NXM_OF_ETH_TYPE field in the
// learned flow must match IP(0x800).
func (a *ofLearnAction) MatchEthernetProtocolIP(isIPv6 bool) LearnAction {
	ethTypeVal := make([]byte, 2)
	var ipProto uint16 = 0x800
	if isIPv6 {
		ipProto = 0x86dd
	}
	binary.BigEndian.PutUint16(ethTypeVal, ipProto)
	a.nxLearn.AddMatch(&ofctrl.LearnField{Name: "NXM_OF_ETH_TYPE"}, 2*8, nil, ethTypeVal)
	return a
}

// MatchTransportDst specifies that the transport layer destination field
// {tcp|udp}_dst in the learned flow must match the same field of the packet
// currently being processed. It only accepts ProtocolTCP, ProtocolUDP, or
// ProtocolSCTP, otherwise this does nothing.
func (a *ofLearnAction) MatchTransportDst(protocol Protocol) LearnAction {
	var ipProtoValue int
	isIPv6 := false
	switch protocol {
	case ProtocolTCP:
		ipProtoValue = ofctrl.IP_PROTO_TCP
	case ProtocolUDP:
		ipProtoValue = ofctrl.IP_PROTO_UDP
	case ProtocolSCTP:
		ipProtoValue = ofctrl.IP_PROTO_SCTP
	case ProtocolTCPv6:
		ipProtoValue = ofctrl.IP_PROTO_TCP
		isIPv6 = true
	case ProtocolUDPv6:
		ipProtoValue = ofctrl.IP_PROTO_UDP
		isIPv6 = true
	case ProtocolSCTPv6:
		ipProtoValue = ofctrl.IP_PROTO_SCTP
		isIPv6 = true
	default:
		// Return directly if the protocol is not acceptable.
		return a
	}

	a.MatchEthernetProtocolIP(isIPv6)
	ipTypeVal := make([]byte, 2)
	ipTypeVal[1] = byte(ipProtoValue)
	a.nxLearn.AddMatch(&ofctrl.LearnField{Name: "NXM_OF_IP_PROTO"}, 1*8, nil, ipTypeVal)
	// OXM_OF fields support TCP, UDP and SCTP, but NXM_OF fields only support TCP and UDP. So here using "OXM_OF_" to
	// generate the field name.
	trimProtocol := strings.ReplaceAll(string(protocol), "v6", "")
	fieldName := fmt.Sprintf("OXM_OF_%s_DST", strings.ToUpper(trimProtocol))
	a.nxLearn.AddMatch(&ofctrl.LearnField{Name: fieldName}, 2*8, &ofctrl.LearnField{Name: fieldName}, nil)
	return a
}

// MatchLearnedTCPDstPort specifies that the tcp_dst field in the learned flow
// must match the tcp_dst of the packet currently being processed.
func (a *ofLearnAction) MatchLearnedTCPDstPort() LearnAction {
	return a.MatchTransportDst(ProtocolTCP)
}

// MatchLearnedTCPv6DstPort specifies that the tcp_dst field in the learned flow
// must match the tcp_dst of the packet currently being processed.
func (a *ofLearnAction) MatchLearnedTCPv6DstPort() LearnAction {
	return a.MatchTransportDst(ProtocolTCPv6)
}

// MatchLearnedUDPDstPort specifies that the udp_dst field in the learned flow
// must match the udp_dst of the packet currently being processed.
func (a *ofLearnAction) MatchLearnedUDPDstPort() LearnAction {
	return a.MatchTransportDst(ProtocolUDP)
}

// MatchLearnedUDPv6DstPort specifies that the udp_dst field in the learned flow
// must match the udp_dst of the packet currently being processed.
func (a *ofLearnAction) MatchLearnedUDPv6DstPort() LearnAction {
	return a.MatchTransportDst(ProtocolUDPv6)
}

// MatchLearnedSCTPDstPort specifies that the sctp_dst field in the learned flow
// must match the sctp_dst of the packet currently being processed.
func (a *ofLearnAction) MatchLearnedSCTPDstPort() LearnAction {
	return a.MatchTransportDst(ProtocolSCTP)
}

// MatchLearnedSCTPv6DstPort specifies that the sctp_dst field in the learned flow
// must match the sctp_dst of the packet currently being processed.
func (a *ofLearnAction) MatchLearnedSCTPv6DstPort() LearnAction {
	return a.MatchTransportDst(ProtocolSCTPv6)
}

// MatchLearnedSrcIP makes the learned flow to match the nw_src of current IP packet.
func (a *ofLearnAction) MatchLearnedSrcIP() LearnAction {
	a.nxLearn.AddMatch(&ofctrl.LearnField{Name: "NXM_OF_IP_SRC"}, 4*8, &ofctrl.LearnField{Name: "NXM_OF_IP_SRC"}, nil)
	return a
}

// MatchLearnedDstIP makes the learned flow to match the nw_dst of current IP packet.
func (a *ofLearnAction) MatchLearnedDstIP() LearnAction {
	a.nxLearn.AddMatch(&ofctrl.LearnField{Name: "NXM_OF_IP_DST"}, 4*8, &ofctrl.LearnField{Name: "NXM_OF_IP_DST"}, nil)
	return a
}

// MatchLearnedSrcIPv6 makes the learned flow to match the ipv6_src of current IPv6 packet.
func (a *ofLearnAction) MatchLearnedSrcIPv6() LearnAction {
	a.nxLearn.AddMatch(&ofctrl.LearnField{Name: "NXM_NX_IPV6_SRC"}, 16*8, &ofctrl.LearnField{Name: "NXM_NX_IPV6_SRC"}, nil)
	return a
}

// MatchLearnedDstIPv6 makes the learned flow to match the ipv6_dst of current IPv6 packet.
func (a *ofLearnAction) MatchLearnedDstIPv6() LearnAction {
	a.nxLearn.AddMatch(&ofctrl.LearnField{Name: "NXM_NX_IPV6_DST"}, 16*8, &ofctrl.LearnField{Name: "NXM_NX_IPV6_DST"}, nil)
	return a
}

func (a *ofLearnAction) MatchRegMark(mark *RegMark) LearnAction {
	toField := &ofctrl.LearnField{Name: mark.field.GetNXFieldName(), Start: uint16(mark.field.rng[0])}
	valBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(valBuf, mark.value)
	offset := (mark.field.rng.Length()-1)/8 + 1
	if offset < 2 {
		offset = 2
	}
	a.nxLearn.AddMatch(toField, uint16(mark.field.rng.Length()), nil, valBuf[4-offset:])
	return a
}

// MatchXXReg makes the learned flow to match the data in the xxreg of specific range.
func (a *ofLearnAction) MatchXXReg(regID int, data []byte, rng Range) LearnAction {
	s := fmt.Sprintf("%s%d", NxmFieldXXReg, regID)
	toField := &ofctrl.LearnField{Name: s, Start: uint16(rng[0])}
	offset := (rng.Length()-1)/8 + 1
	if offset < 2 {
		offset = 2
	}
	a.nxLearn.AddMatch(toField, uint16(rng.Length()), nil, data[16-offset:])
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

func (a *ofLearnAction) LoadRegMark(mark *RegMark) LearnAction {
	toField := &ofctrl.LearnField{Name: mark.field.GetNXFieldName(), Start: uint16(mark.field.rng[0])}
	valBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(valBuf, mark.value)
	offset := (mark.field.rng.Length()-1)/8 + 1
	if offset < 2 {
		offset = 2
	}
	a.nxLearn.AddLoadAction(toField, uint16(mark.field.rng.Length()), nil, valBuf[4-offset:])
	return a
}

func (a *ofLearnAction) SetDstMAC(mac net.HardwareAddr) LearnAction {
	toField := &ofctrl.LearnField{Name: "NXM_OF_ETH_DST"}
	a.nxLearn.AddLoadAction(toField, 48, nil, mac)
	return a
}

func (a *ofLearnAction) Done() FlowBuilder {
	a.flowBuilder.ApplyAction(a.nxLearn)
	return a.flowBuilder
}

func getFieldRange(name string) (*openflow13.MatchField, Range, error) {
	field, err := openflow13.FindFieldHeaderByName(name, false)
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
