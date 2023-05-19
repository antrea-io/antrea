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
	"fmt"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/ofnet/ofctrl"
)

type FlowStates struct {
	TableID         uint8
	PacketCount     uint64
	DurationNSecond uint32
}

type ofFlow struct {
	table *ofTable
	// The Flow.Table field can be updated by Reset(), which can be called by
	// ReplayFlows() when replaying the Flow to OVS. For thread safety, any access
	// to Flow.Table should hold the replayMutex read lock.
	*ofctrl.Flow

	// protocol adds a readable protocol type in the match string of ofFlow.
	protocol Protocol
	// ctStates is a temporary variable to maintain openflow15.CTStates. When FlowBuilder.Done is called, it is used to
	// set the CtStates field in ofctrl.Flow.Match.
	ctStates *openflow15.CTStates
}

func (f *ofFlow) String() string {
	flowMod, _ := f.getFlowMod()
	return FlowModToString(flowMod)
}

func (f *ofFlow) getFlowMod() (*openflow15.FlowMod, error) {
	flowMods, err := f.GetBundleMessages(AddMessage)
	if err != nil {
		return nil, err
	}
	if len(flowMods) == 0 {
		return nil, fmt.Errorf("no flowMod message is generated")
	}
	return flowMods[0].GetMessage().(*openflow15.FlowMod), nil
}

// Reset updates the ofFlow.Flow.Table field with ofFlow.table.Table.
// In the case of reconnecting to OVS, the ofnet library creates new OFTable
// objects. Reset() can be called to reset ofFlow.Flow.Table to the right value,
// before replaying the Flow to OVS.
func (f *ofFlow) Reset() {
	f.Flow.Table = f.table.Table
}

func (f *ofFlow) Add() error {
	err := f.Flow.Send(openflow15.FC_ADD)
	if err != nil {
		return err
	}
	f.table.UpdateStatus(1)
	return nil
}

func (f *ofFlow) Modify() error {
	err := f.Flow.Send(openflow15.FC_MODIFY_STRICT)
	if err != nil {
		return err
	}
	f.table.UpdateStatus(0)
	return nil
}

func (f *ofFlow) Delete() error {
	f.Flow.UpdateInstallStatus(true)
	err := f.Flow.Send(openflow15.FC_DELETE_STRICT)
	if err != nil {
		return err
	}
	f.table.UpdateStatus(-1)
	return nil
}

func (f *ofFlow) Type() EntryType {
	return FlowEntry
}

func (f *ofFlow) MatchString() string {
	flowMod, _ := f.getFlowMod()
	return FlowModMatchString(flowMod)
}

func (f *ofFlow) FlowPriority() uint16 {
	return f.Match.Priority
}

func (f *ofFlow) FlowProtocol() Protocol {
	return f.protocol
}

func (f *ofFlow) GetBundleMessages(entryOper OFOperation) ([]ofctrl.OpenFlowModMessage, error) {
	var operation int
	switch entryOper {
	case AddMessage:
		operation = openflow15.FC_ADD
	case ModifyMessage:
		operation = openflow15.FC_MODIFY_STRICT
	case DeleteMessage:
		operation = openflow15.FC_DELETE_STRICT
	}
	message, err := f.Flow.GetBundleMessage(operation)
	if err != nil {
		return nil, err
	}
	return []ofctrl.OpenFlowModMessage{message}, nil
}

// CopyToBuilder returns a new FlowBuilder that copies the table, protocols,
// matches, and CookieID of the Flow, but does not copy private status fields
// of the ofctrl.Flow, e.g. "realized" and "isInstalled". It copies the
// original actions of the Flow only if copyActions is set to true, and
// resets the priority in the new FlowBuilder if it is provided.
func (f *ofFlow) CopyToBuilder(priority uint16, copyActions bool) FlowBuilder {
	flow := &ofctrl.Flow{
		Table:      f.Flow.Table,
		CookieID:   f.Flow.CookieID,
		CookieMask: f.Flow.CookieMask,
		Match:      f.Flow.Match,
	}
	if copyActions {
		f.Flow.CopyActionsToNewFlow(flow)
	}
	if priority > 0 {
		flow.Match.Priority = priority
	}
	newFlow := ofFlow{
		table:    f.table,
		Flow:     flow,
		protocol: f.protocol,
	}
	return &ofFlowBuilder{newFlow}
}

func (r *Range) ToNXRange() *openflow15.NXRange {
	return openflow15.NewNXRange(int(r[0]), int(r[1]))
}

func (r *Range) Length() uint32 {
	return r[1] - r[0] + 1
}

func (r *Range) Offset() uint32 {
	return r[0]
}
