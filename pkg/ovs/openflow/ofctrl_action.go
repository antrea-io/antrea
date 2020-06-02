package openflow

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
)

type ofFlowAction struct {
	builder *ofFlowBuilder
}

// Drop is an action to drop packets.
func (a *ofFlowAction) Drop() FlowBuilder {
	dropAction := a.builder.Flow.Table.Switch.DropAction()
	a.builder.ofFlow.lastAction = dropAction
	return a.builder
}

// Output is an action to output packets to the specified ofport.
func (a *ofFlowAction) Output(port int) FlowBuilder {
	outputAction := ofctrl.NewOutputPort(uint32(port))
	a.builder.ofFlow.lastAction = outputAction
	return a.builder
}

// OutputFieldRange is an action to output packets to the port located in the specified NXM field with rng.
func (a *ofFlowAction) OutputFieldRange(name string, rng Range) FlowBuilder {
	outputAction, _ := ofctrl.NewNXOutput(name, int(rng[0]), int(rng[1]))
	a.builder.ofFlow.lastAction = outputAction
	return a.builder
}

// OutputFieldRange is an action to output packets to a port which is located in the specified NXM register[rng[0]..rng[1]].
func (a *ofFlowAction) OutputRegRange(regID int, rng Range) FlowBuilder {
	name := fmt.Sprintf("%s%d", NxmFieldReg, regID)
	return a.OutputFieldRange(name, rng)
}

// OutputInPort is an action to output packets to the ofport from where the packet enters the OFSwitch.
func (a *ofFlowAction) OutputInPort() FlowBuilder {
	outputAction := ofctrl.NewOutputInPort()
	a.builder.ofFlow.lastAction = outputAction
	return a.builder
}

// CT is an action to set conntrack marks and return CTAction to add actions that is executed with conntrack context.
func (a *ofFlowAction) CT(commit bool, tableID TableIDType, zone int) CTAction {
	base := ctBase{
		commit:  commit,
		force:   false,
		ctTable: uint8(tableID),
		ctZone:  uint16(zone),
	}
	var repr string
	if commit {
		repr += "commit"
	}
	if tableID != LastTableID {
		if repr != "" {
			repr += ","
		}
		repr += fmt.Sprintf("table=%d", tableID)
	}
	if zone > 0 {
		if repr != "" {
			repr += ","
		}
		repr += fmt.Sprintf("zone=%d", zone)
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

// LoadToLabelRange is an action to load data into ct_label at specified range.
func (a *ofCTAction) LoadToLabelRange(value uint64, rng *Range) CTAction {
	field, _, _ := getFieldRange(NxmFieldCtLabel)
	a.load(field, value, rng)
	return a
}

func (a *ofCTAction) load(field *openflow13.MatchField, value uint64, rng *Range) {
	action := openflow13.NewNXActionRegLoad(rng.ToNXRange().ToOfsBits(), field, value)
	a.actions = append(a.actions, action)
}

// MoveToLabel is an action to move data into ct_mark.
func (a *ofCTAction) MoveToLabel(fromName string, fromRng, labelRng *Range) CTAction {
	fromField, _ := openflow13.FindFieldHeaderByName(fromName, false)
	toField, _ := openflow13.FindFieldHeaderByName(NxmFieldCtLabel, false)
	a.move(fromField, toField, uint16(fromRng.length()), uint16(fromRng[0]), uint16(labelRng[0]))
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
		action.SetRangeIPv4Min(ipRange.StartIP)
		action.SetRangeIPv4Max(ipRange.EndIP)
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
	a.builder.Flow.ConnTrack(a.commit, a.force, &a.ctTable, &a.ctZone, a.actions...)
	return a.builder
}

// SetDstMAC is an action to modify packet destination MAC address to the specified address.
func (a *ofFlowAction) SetDstMAC(addr net.HardwareAddr) FlowBuilder {
	a.builder.SetMacDa(addr)
	return a.builder
}

// SetSrcMAC is an action to modify packet source MAC address to the specified address.
func (a *ofFlowAction) SetSrcMAC(addr net.HardwareAddr) FlowBuilder {
	a.builder.SetMacSa(addr)
	return a.builder
}

// SetARPSha is an action to modify ARP packet source hardware address to the specified address.
func (a *ofFlowAction) SetARPSha(addr net.HardwareAddr) FlowBuilder {
	a.builder.SetARPSha(addr)
	return a.builder
}

// SetARPTha is an action to modify ARP packet target hardware address to the specified address.
func (a *ofFlowAction) SetARPTha(addr net.HardwareAddr) FlowBuilder {
	a.builder.SetARPTha(addr)
	return a.builder
}

// SetARPSpa is an action to modify ARP packet source protocol address to the specified address.
func (a *ofFlowAction) SetARPSpa(addr net.IP) FlowBuilder {
	a.builder.SetARPSpa(addr)
	return a.builder
}

// SetARPTpa is an action to modify ARP packet target protocol address to the specified address.
func (a *ofFlowAction) SetARPTpa(addr net.IP) FlowBuilder {
	a.builder.SetARPTpa(addr)
	return a.builder
}

// SetSrcIP is an action to modify packet source IP address to the specified address.
func (a *ofFlowAction) SetSrcIP(addr net.IP) FlowBuilder {
	a.builder.SetIPField(addr, "Src")
	return a.builder
}

// SetDstIP is an action to modify packet destination IP address to the specified address.
func (a *ofFlowAction) SetDstIP(addr net.IP) FlowBuilder {
	a.builder.SetIPField(addr, "Dst")
	return a.builder
}

// SetTunnelDst is an action to modify packet tunnel destination address to the specified address.
func (a *ofFlowAction) SetTunnelDst(addr net.IP) FlowBuilder {
	a.builder.SetIPField(addr, "TunDst")
	return a.builder
}

// LoadARPOperation is an action to Load data to NXM_OF_ARP_OP field.
func (a *ofFlowAction) LoadARPOperation(value uint16) FlowBuilder {
	a.builder.ofFlow.LoadReg(NxmFieldARPOp, uint64(value), openflow13.NewNXRange(0, 15))
	return a.builder
}

// LoadRange is an action to Load data to the target field at specified range.
func (a *ofFlowAction) LoadRange(name string, value uint64, rng Range) FlowBuilder {
	a.builder.ofFlow.LoadReg(name, value, rng.ToNXRange())
	return a.builder
}

// LoadRegRange is an action to Load data to the target register at specified range.
func (a *ofFlowAction) LoadRegRange(regID int, value uint32, rng Range) FlowBuilder {
	name := fmt.Sprintf("%s%d", NxmFieldReg, regID)
	a.builder.ofFlow.LoadReg(name, uint64(value), rng.ToNXRange())
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
	a.builder.ofFlow.MoveRegs(fromField, toField, fromRange.ToNXRange(), toRange.ToNXRange())
	return a.builder
}

// Resubmit is an action to resubmit packet to the specified table with the port as new in_port. If port is empty string,
// the in_port field is not changed.
func (a *ofFlowAction) Resubmit(ofPort uint16, tableID TableIDType) FlowBuilder {
	a.builder.ofFlow.Resubmit(ofPort, uint8(tableID))
	return a.builder
}

func (a *ofFlowAction) ResubmitToTable(table TableIDType) FlowBuilder {
	ofTableID := uint8(table)
	a.builder.ofFlow.Resubmit(openflow13.OFPP_IN_PORT, ofTableID)
	return a.builder
}

// DecTTL is an action to decrease TTL. It is used in routing functions implemented by Openflow.
func (a *ofFlowAction) DecTTL() FlowBuilder {
	a.builder.ofFlow.DecTTL()
	return a.builder
}

// Normal is an action to leverage OVS fwd table to forwarding packets.
func (a *ofFlowAction) Normal() FlowBuilder {
	normalAction := ofctrl.NewOutputNormal()
	a.builder.ofFlow.lastAction = normalAction
	return a.builder
}

// Conjunction is an action to add new conjunction configuration to conjunctive match flow.
func (a *ofFlowAction) Conjunction(conjID uint32, clauseID uint8, nClause uint8) FlowBuilder {
	a.builder.ofFlow.AddConjunction(conjID, clauseID, nClause)
	return a.builder
}

// Group is an action to forward packets to groups to do load-balance.
func (a *ofFlowAction) Group(id GroupIDType) FlowBuilder {
	group := &ofctrl.Group{
		Switch: a.builder.Flow.Table.Switch,
		ID:     uint32(id),
	}
	a.builder.ofFlow.lastAction = group
	return a.builder
}

//  Learn is an action which adds or modifies a flow in an OpenFlow table.
func (a *ofFlowAction) Learn(id TableIDType, priority uint16, idleTimeout, hardTimeout uint16, cookieID uint64) LearnAction {
	la := &ofLearnAction{
		flowBuilder: a.builder,
		nxLearn:     ofctrl.NewLearnAction(uint8(id), priority, idleTimeout, hardTimeout, 0, 0, cookieID),
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
func (a *ofLearnAction) MatchEthernetProtocolIP() LearnAction {
	ethTypeVal := make([]byte, 2)
	binary.BigEndian.PutUint16(ethTypeVal, 0x800)
	a.nxLearn.AddMatch(&ofctrl.LearnField{Name: "NXM_OF_ETH_TYPE"}, 2*8, nil, ethTypeVal)
	return a
}

// MatchTransportDst specifies that the transport layer destination field
// {tcp|udp}_dst in the learned flow must match the same field of the packet
// currently being processed. It only accepts ProtocolTCP or ProtocolUDP,
// otherwise this does nothing.
func (a *ofLearnAction) MatchTransportDst(protocol Protocol) LearnAction {
	if protocol != ProtocolTCP && protocol != ProtocolUDP {
		return a
	}
	a.MatchEthernetProtocolIP()
	ipTypeVal := make([]byte, 2)
	ipTypeVal[1] = byte(ofctrl.IP_PROTO_TCP)
	a.nxLearn.AddMatch(&ofctrl.LearnField{Name: "NXM_OF_IP_PROTO"}, 1*8, nil, ipTypeVal)
	fieldName := fmt.Sprintf("NXM_OF_%s_DST", strings.ToUpper(string(protocol)))
	a.nxLearn.AddMatch(&ofctrl.LearnField{Name: fieldName}, 2*8, &ofctrl.LearnField{Name: fieldName}, nil)
	return a
}

// MatchLearnedTCPDstPort specifies that the tcp_dst field in the learned flow
// must match the tcp_dst of the packet currently being processed.
func (a *ofLearnAction) MatchLearnedTCPDstPort() LearnAction {
	return a.MatchTransportDst(ProtocolTCP)
}

// MatchLearnedUDPDstPort specifies that the udp_dst field in the learned flow
// must match the udp_dst of the packet currently being processed.
func (a *ofLearnAction) MatchLearnedUDPDstPort() LearnAction {
	return a.MatchTransportDst(ProtocolUDP)
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

// MatchReg makes the learned flow to match the data in the reg of specific range.
func (a *ofLearnAction) MatchReg(regID int, data uint32, rng Range) LearnAction {
	toField := &ofctrl.LearnField{Name: fmt.Sprintf("NXM_NX_REG%d", regID), Start: uint16(rng[0])}
	valBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(valBuf, data)
	a.nxLearn.AddMatch(toField, uint16(rng.length()), nil, valBuf[4-rng.length()/8:])
	return a
}

// LoadRegToReg makes the learned flow to load reg[fromRegID] to reg[toRegID]
// with specific ranges.
func (a *ofLearnAction) LoadRegToReg(fromRegID, toRegID int, fromRng, toRng Range) LearnAction {
	fromField := &ofctrl.LearnField{Name: fmt.Sprintf("NXM_NX_REG%d", fromRegID), Start: uint16(fromRng[0])}
	toField := &ofctrl.LearnField{Name: fmt.Sprintf("NXM_NX_REG%d", toRegID), Start: uint16(toRng[0])}
	a.nxLearn.AddLoadAction(toField, uint16(toRng.length()), fromField, nil)
	return a
}

// LoadReg makes the learned flow to load data to reg[regID] with specific range.
func (a *ofLearnAction) LoadReg(regID int, data uint32, rng Range) LearnAction {
	toField := &ofctrl.LearnField{Name: fmt.Sprintf("NXM_NX_REG%d", regID), Start: uint16(rng[0])}
	valBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(valBuf, data)
	a.nxLearn.AddLoadAction(toField, uint16(rng.length()), nil, valBuf[4-rng.length()/8:])
	return a
}

func (a *ofLearnAction) Done() FlowBuilder {
	a.flowBuilder.Learn(a.nxLearn)
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
func (a *ofFlowAction) GotoTable(table TableIDType) FlowBuilder {
	// Use Table until new ofnet APIs are ready
	// a.builder.ofFlow.Goto(uint8(table))
	gotoTable := &ofctrl.Table{TableId: uint8(table)}
	a.builder.ofFlow.lastAction = gotoTable
	return a.builder
}
