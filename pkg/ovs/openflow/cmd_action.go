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
	"fmt"
	"net"
	"strings"
)

type commandAction struct {
	builder *commandBuilder
}

func (a *commandAction) Drop() FlowBuilder {
	a.builder.actions = append(a.builder.actions, "drop")
	return a.builder
}

func (a *commandAction) Output(port int) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("output:%d", port))
	return a.builder
}

func (a *commandAction) OutputFieldRange(name string, rng Range) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("output:%s[%d..%d]", name, rng[0], rng[1]))
	return a.builder
}

func (a *commandAction) OutputRegRange(regID int, rng Range) FlowBuilder {
	return a.OutputFieldRange(fmt.Sprintf("%s%d", NxmFieldReg, regID), rng)
}

func (a *commandAction) OutputInPort() FlowBuilder {
	a.builder.actions = append(a.builder.actions, "in_port")
	return a.builder
}

type cmdCT struct {
	ctBase
	actions []string
	builder *commandBuilder
}

func (a *cmdCT) LoadToMark(value uint32) CTAction {
	action := fmt.Sprintf("load:0x%x->%s[]", value, NxmFieldCtMark)
	return a.addAction(action)
}

func (a *cmdCT) addAction(action string) CTAction {
	if a.actions == nil {
		a.actions = make([]string, 0)
	}
	a.actions = append(a.actions, action)
	return a
}

func (a *cmdCT) LoadToLabelRange(value uint64, labelRange *Range) CTAction {
	action := fmt.Sprintf("load:0x%x->%s[%d,%d]", value, NxmFieldCtLabel, labelRange[0], labelRange[1])
	return a.addAction(action)
}

func (a *cmdCT) MoveToLabel(fromName string, fromRng, labelRange *Range) CTAction {
	action := fmt.Sprintf("move:%s[%d..%d]->%s[%d..%d]", fromName, fromRng[0], fromRng[1], NxmFieldCtLabel, labelRange[0], labelRange[1])
	return a.addAction(action)
}

func (a *cmdCT) MoveSrcMACToLabel(labelRange *Range) CTAction {
	fromRange := Range{0, 47}
	return a.MoveToLabel(NxmFieldSrcMAC, &fromRange, labelRange)
}

func (a *cmdCT) CTDone() FlowBuilder {
	var repr string
	if a.commit {
		repr += "commit"
	}
	if a.ctTable > 0 {
		if repr != "" {
			repr += ","
		}
		repr += fmt.Sprintf("table=%d", a.ctTable)
	}
	if a.ctZone > 0 {
		if repr != "" {
			repr += ","
		}
		repr += fmt.Sprintf("zone=%d", a.ctZone)
	}
	if len(a.actions) > 0 {
		if repr != "" {
			repr += ","
		}
		repr += fmt.Sprintf("exec(%s)", strings.Join(a.actions, ","))
	}
	a.builder.actions = append(a.builder.actions, "ct("+repr+")")
	return a.builder
}

func (a *commandAction) CT(commit bool, tableID TableIDType, zone int) CTAction {
	base := ctBase{
		commit:  commit,
		force:   false,
		ctTable: uint8(tableID),
		ctZone:  uint16(zone),
	}
	ct := &cmdCT{
		ctBase:  base,
		builder: a.builder,
	}
	return ct
}

func (a *commandAction) SetField(key, value string) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("set_field:%s->%s", value, key))
	return a.builder
}

func (a *commandAction) Load(name string, value uint64) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("load:0x%x->%s[]", value, name))
	return a.builder
}

func (a *commandAction) LoadARPOperation(value uint16) FlowBuilder {
	return a.Load(NxmFieldARPOp, uint64(value))
}

func (a *commandAction) LoadRange(name string, addr uint32, to Range) FlowBuilder {
	a.builder.actions = append(
		a.builder.actions,
		fmt.Sprintf("load:0x%x->%s[%d..%d]", addr, name, to[0], to[1]),
	)
	return a.builder
}

func (a *commandAction) LoadRegRange(regID int, value uint32, to Range) FlowBuilder {
	return a.LoadRange(fmt.Sprintf("reg%d", regID), value, to)
}

func (a *commandAction) Move(from, to string) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("move:%s[]->%s[]", from, to))
	return a.builder
}

func (a *commandAction) MoveRange(fromName, toName string, from, to Range) FlowBuilder {
	a.builder.actions = append(
		a.builder.actions,
		fmt.Sprintf("move:%s[%d..%d]->%s[%d..%d]", fromName, from[0], from[1], toName, to[0], to[1]),
	)
	return a.builder
}

func (a *commandAction) Resubmit(port string, table TableIDType) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("resubmit(%s,%d)", port, table))
	return a.builder
}

func (a *commandAction) DecTTL() FlowBuilder {
	a.builder.actions = append(a.builder.actions, "dec_ttl")
	return a.builder
}

func (a *commandAction) Normal() FlowBuilder {
	a.builder.actions = append(a.builder.actions, "Normal")
	return a.builder
}

func (a *commandAction) Conjunction(conjID uint32, clauseID uint8, nClause uint8) FlowBuilder {
	a.builder.actions = append(a.builder.actions, fmt.Sprintf("conjunction(%d,%d/%d)", conjID, clauseID, nClause))
	return a.builder
}

func (a *commandAction) SetDstMAC(addr net.HardwareAddr) FlowBuilder {
	return a.SetField("dl_dst", addr.String())
}

func (a *commandAction) SetSrcMAC(addr net.HardwareAddr) FlowBuilder {
	return a.SetField("dl_src", addr.String())
}

func (a *commandAction) SetARPSha(addr net.HardwareAddr) FlowBuilder {
	return a.SetField("arp_sha", addr.String())
}

func (a *commandAction) SetARPTha(addr net.HardwareAddr) FlowBuilder {
	return a.SetField("arp_tha", addr.String())
}

func (a *commandAction) SetARPSpa(addr net.IP) FlowBuilder {
	return a.SetField("arp_spa", addr.String())
}

func (a *commandAction) SetARPTpa(addr net.IP) FlowBuilder {
	return a.SetField("arp_tpa", addr.String())
}

func (a *commandAction) SetSrcIP(addr net.IP) FlowBuilder {
	return a.SetField("nw_src", addr.String())
}

func (a *commandAction) SetDstIP(addr net.IP) FlowBuilder {
	return a.SetField("nw_dst", addr.String())
}

func (a *commandAction) SetTunnelDst(addr net.IP) FlowBuilder {
	return a.SetField("tun_dst", addr.String())
}
