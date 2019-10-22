package openflow

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
)

type ofFlowAction struct {
	builder *ofFlowBuilder
}

// Drop is an action to drop packets.
func (a *ofFlowAction) Drop() FlowBuilder {
	a.builder.actions = append(a.builder.actions, "drop")
	dropAction := a.builder.Flow.Table.Switch.DropAction()
	a.builder.ofFlow.lastAction = dropAction
	return a.builder
}

// Drop is an action to output packets to the specified ofport.
func (a *ofFlowAction) Output(port int) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("output:%d", port))
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
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("output:%s%d[%d..%d]", NxmFieldReg, regID, rng[0], rng[1]))
	name := fmt.Sprintf("%s%d", NxmFieldReg, regID)
	return a.OutputFieldRange(name, rng)
}

// OutputInPort is an action to output packets to the ofport from where the packet enters the OFSwitch.
func (a *ofFlowAction) OutputInPort() FlowBuilder {
	a.builder.actions = append(a.builder.actions, "in_port")
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
		repr:    repr,
	}
	return ct
}

// ofCTAction is a struct to implement CTAction.
type ofCTAction struct {
	ctBase
	actions    []openflow13.Action
	builder    *ofFlowBuilder
	strActions []string
	repr       string
}

// LoadToMark is an action to load data into ct_mark.
func (a *ofCTAction) LoadToMark(value uint32) CTAction {
	a.strActions = append(a.strActions, fmt.Sprintf("load:0x%x->%s[]", value, NxmFieldCtMark))
	field, rng, _ := getFieldRange(NxmFieldCtMark)
	a.load(field, uint64(value), &rng)
	return a
}

// LoadToLabelRange is an action to load data into ct_label at specified range.
func (a *ofCTAction) LoadToLabelRange(value uint64, rng *Range) CTAction {
	a.strActions = append(a.strActions, fmt.Sprintf("load:0x%x->%s[%d..%d]", value, NxmFieldCtLabel, rng[0], rng[1]))
	field, _, _ := getFieldRange(NxmFieldCtLabel)
	a.load(field, value, rng)
	return a
}

func (a *ofCTAction) load(field *openflow13.MatchField, value uint64, rng *Range) {
	action := openflow13.NewNXActionRegLoad(rng.ToNxRange().ToOfsBits(), field, value)
	a.actions = append(a.actions, action)
}

// MoveToLabel is an action to move data into ct_mark.
func (a *ofCTAction) MoveToLabel(fromName string, fromRng, labelRng *Range) CTAction {
	a.strActions = append(a.strActions, fmt.Sprintf("move:%s[%d..%d]->%s[%d..%d]", fromName, fromRng[0], fromRng[1], NxmFieldCtLabel, labelRng[0], labelRng[1]))
	fromField, _ := openflow13.FindFieldHeaderByName(fromName, false)
	toField, _ := openflow13.FindFieldHeaderByName(NxmFieldCtLabel, false)
	a.move(fromField, toField, uint16(fromRng.length()), uint16(fromRng[0]), uint16(labelRng[0]))
	return a
}

func (a *ofCTAction) move(fromField *openflow13.MatchField, toField *openflow13.MatchField, nBits, fromStart, toStart uint16) {
	action := openflow13.NewNXActionRegMove(nBits, fromStart, toStart, fromField, toField)
	a.actions = append(a.actions, action)
}

// CTDone is an action to return FlowBuilder.
func (a *ofCTAction) CTDone() FlowBuilder {
	a.builder.Flow.ConnTrack(a.commit, a.force, &a.ctTable, &a.ctZone, a.actions...)
	if len(a.strActions) > 0 {
		a.repr += fmt.Sprintf("exec(%s)", strings.Join(a.strActions, ","))
	}
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("ct(%s)", a.repr))
	return a.builder
}

func (a *ofFlowAction) SetField(key, value string) FlowBuilder {
	return a.builder
}

// SetDstMAC is an action to modify packet destination MAC address to the specified address.
func (a *ofFlowAction) SetDstMAC(addr net.HardwareAddr) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("set_field:dl_dst->%s", addr.String()))
	a.builder.SetMacDa(addr)
	return a.builder
}

// SetSrcMAC is an action to modify packet source MAC address to the specified address.
func (a *ofFlowAction) SetSrcMAC(addr net.HardwareAddr) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("set_field:dl_src->%s", addr.String()))
	a.builder.SetMacSa(addr)
	return a.builder
}

// SetARPSha is an action to modify ARP packet source hardware address to the specified address.
func (a *ofFlowAction) SetARPSha(addr net.HardwareAddr) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("set_field:arp_sha->%s", addr.String()))
	a.builder.SetARPSha(addr)
	return a.builder
}

// SetARPTha is an action to modify ARP packet target hardware address to the specified address.
func (a *ofFlowAction) SetARPTha(addr net.HardwareAddr) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("set_field:arp_tha->%s", addr.String()))
	a.builder.SetARPTha(addr)
	return a.builder
}

// SetARPSpa is an action to modify ARP packet source protocol address to the specified address.
func (a *ofFlowAction) SetARPSpa(addr net.IP) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("set_field:arp_spa->%s", addr.String()))
	a.builder.SetARPSpa(addr)
	return a.builder
}

// SetARPTpa is an action to modify ARP packet target protocol address to the specified address.
func (a *ofFlowAction) SetARPTpa(addr net.IP) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("set_field:arp_tpa->%s", addr.String()))
	a.builder.SetARPTpa(addr)
	return a.builder
}

// SetSrcIP is an action to modify packet source IP address to the specified address.
func (a *ofFlowAction) SetSrcIP(addr net.IP) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("set_field:nw_src->%s", addr.String()))
	a.builder.SetIPField(addr, "Src")
	return a.builder
}

// SetDstIP is an action to modify packet destination IP address to the specified address.
func (a *ofFlowAction) SetDstIP(addr net.IP) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("set_field:nw_dst->%s", addr.String()))
	a.builder.SetIPField(addr, "Dst")
	return a.builder
}

// SetTunnelDst is an action to modify packet tunnel destination address to the specified address.
func (a *ofFlowAction) SetTunnelDst(addr net.IP) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("set_field:tun_dst->%s", addr.String()))
	a.builder.SetIPField(addr, "TunDst")
	return a.builder
}

// LoadARPOperation is an action to Load data to NXM_OF_ARP_OP field.
func (a *ofFlowAction) LoadARPOperation(value uint16) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("load:%d->arp_op", value))
	a.builder.ofFlow.LoadReg(NxmFieldARPOp, uint64(value), openflow13.NewNXRange(0, 15))
	return a.builder
}

// LoadRange is an action to Load data to the target field at specified range.
func (a *ofFlowAction) LoadRange(name string, value uint32, rng Range) FlowBuilder {
	a.builder.ofFlow.LoadReg(name, uint64(value), rng.ToNxRange())
	return a.builder
}

// LoadRegRange is an action to Load data to the target register at specified range.
func (a *ofFlowAction) LoadRegRange(regID int, value uint32, rng Range) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("load:0x%x->NXM_NX_REG%d[%d..%d]", value, regID, rng[0], rng[1]))
	name := fmt.Sprintf("%s%d", NxmFieldReg, regID)
	a.builder.ofFlow.LoadReg(name, uint64(value), rng.ToNxRange())
	return a.builder
}

// Move is an action to copy all data from "fromField" to "toField". Fields with name "fromField" and "fromField" should
// have the same data length, otherwise there will be error when realize the flow on OFSwitch.
func (a *ofFlowAction) Move(fromField, toField string) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("move:%s[]->%s[]", fromField, toField))
	_, fromRange, _ := getFieldRange(fromField)
	_, toRange, _ := getFieldRange(fromField)
	return a.MoveRange(fromField, toField, fromRange, toRange)
}

// MoveRange is an action to move data from "fromField" at "fromRange" to "toField" at "toRange".
func (a *ofFlowAction) MoveRange(fromField, toField string, fromRange, toRange Range) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("move:%s[%d..%d]->%s[%d..%d]", fromField, fromRange[0], fromRange[1], toField, toRange[0], toRange[1]))
	a.builder.ofFlow.MoveRegs(fromField, toField, fromRange.ToNxRange(), toRange.ToNxRange())
	return a.builder
}

// Resubmit is an action to resubmit packet to the specified table with the port as new in_port. If port is empty string,
// the in_port field is not changed.
func (a *ofFlowAction) Resubmit(port string, table TableIDType) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("resubmit(%s,%d)", port, table))
	inport := 0
	var ofPort uint16 = 0xfff8
	if port != "" {
		inport, _ = strconv.Atoi(port)
		ofPort = uint16(inport)
	}
	ofTableID := uint8(table)
	resubmit := ofctrl.NewResubmit(&ofPort, &ofTableID)
	a.builder.ofFlow.lastAction = resubmit
	return a.builder
}

// DecTTL is an action to decrease TTL. It is used in routing functions implemented by Openflow.
func (a *ofFlowAction) DecTTL() FlowBuilder {
	a.builder.actions = append(a.builder.actions, "dec_ttl")
	a.builder.ofFlow.DecTTL()
	return a.builder
}

// Normal is an action to leverage OVS fwd table to forwarding packets.
func (a *ofFlowAction) Normal() FlowBuilder {
	a.builder.actions = append(a.builder.actions, "Normal")
	normalAction := ofctrl.NewOutputNormal()
	a.builder.ofFlow.lastAction = normalAction
	return a.builder
}

// Conjunction is an action to add new conjunction configuration to conjunctive match flow.
func (a *ofFlowAction) Conjunction(conjID uint32, clauseID uint8, nClause uint8) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("conjunction(%d,%d/%d)", conjID, clauseID, nClause))
	a.builder.ofFlow.AddConjunction(conjID, clauseID, nClause)
	return a.builder
}

func getFieldRange(name string) (*openflow13.MatchField, Range, error) {
	field, err := openflow13.FindFieldHeaderByName(name, false)
	if err != nil {
		return field, Range{0, 0}, err
	}
	return field, Range{0, uint32(field.Length)*8 - 1}, nil
}
