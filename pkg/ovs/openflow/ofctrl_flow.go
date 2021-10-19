package openflow

import (
	"fmt"
	"strings"

	"antrea.io/libOpenflow/openflow13"
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

	// matchers is string slice, it is used to generate a readable match string of the Flow.
	matchers []string
	// protocol adds a readable protocol type in the match string of ofFlow.
	protocol Protocol
	// ctStateString is a temporary variable for the readable ct_state configuration. Its value is changed when the client
	// updates the matching condition of "ct_states". When FlowBuilder.Done is called, its value is added into the matchers.
	ctStateString string
	// ctStates is a temporary variable to maintain openflow13.CTStates. When FlowBuilder.Done is called, it is used to
	// set the CtStates field in ofctrl.Flow.Match.
	ctStates *openflow13.CTStates
	// isDropFlow is true if this flow actions contain "drop"
	isDropFlow bool
}

func (f *ofFlow) String() string {
	s := strings.Join([]string{`&ofFlow{`,
		`table:` + fmt.Sprintf("%v", f.table.id) + `,`,
		`matchers:` + fmt.Sprintf("%v", f.matchers) + `,`,
		`protocol:` + fmt.Sprintf("%v", f.protocol) + `,`,
		`flow:` + fmt.Sprintf("%v", f.Flow) + `,`,
		`}`,
	}, "")
	return s
}

// Reset updates the ofFlow.Flow.Table field with ofFlow.table.Table.
// In the case of reconnecting to OVS, the ofnet library creates new OFTable
// objects. Reset() can be called to reset ofFlow.Flow.Table to the right value,
// before replaying the Flow to OVS.
func (f *ofFlow) Reset() {
	f.Flow.Table = f.table.Table
}

func (f *ofFlow) Add() error {
	err := f.Flow.Send(openflow13.FC_ADD)
	if err != nil {
		return err
	}
	f.table.UpdateStatus(1)
	return nil
}

func (f *ofFlow) Modify() error {
	err := f.Flow.Send(openflow13.FC_MODIFY_STRICT)
	if err != nil {
		return err
	}
	f.table.UpdateStatus(0)
	return nil
}

func (f *ofFlow) Delete() error {
	f.Flow.UpdateInstallStatus(true)
	err := f.Flow.Send(openflow13.FC_DELETE_STRICT)
	if err != nil {
		return err
	}
	f.table.UpdateStatus(-1)
	return nil
}

func (f *ofFlow) Type() EntryType {
	return FlowEntry
}

func (f *ofFlow) KeyString() string {
	return f.MatchString()
}

func (f *ofFlow) MatchString() string {
	repr := fmt.Sprintf("table=%d", f.table.id)
	if f.protocol != "" {
		repr = fmt.Sprintf("%s,%s", repr, f.protocol)
	}

	if len(f.matchers) > 0 {
		repr = fmt.Sprintf("%s,%s", repr, strings.Join(f.matchers, ","))
	}
	return repr
}

func (f *ofFlow) FlowPriority() uint16 {
	return f.Match.Priority
}

func (f *ofFlow) FlowProtocol() Protocol {
	return f.protocol
}

func (f *ofFlow) GetBundleMessage(entryOper OFOperation) (ofctrl.OpenFlowModMessage, error) {
	var operation int
	switch entryOper {
	case AddMessage:
		operation = openflow13.FC_ADD
	case ModifyMessage:
		operation = openflow13.FC_MODIFY_STRICT
	case DeleteMessage:
		operation = openflow13.FC_DELETE_STRICT
	}
	message, err := f.Flow.GetBundleMessage(operation)
	if err != nil {
		return nil, err
	}
	return message, nil
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
		matchers: f.matchers,
		protocol: f.protocol,
	}
	if copyActions {
		newFlow.isDropFlow = f.isDropFlow
	}
	return &ofFlowBuilder{newFlow}
}

func (f *ofFlow) IsDropFlow() bool {
	return f.isDropFlow
}

func (r *Range) ToNXRange() *openflow13.NXRange {
	return openflow13.NewNXRange(int(r[0]), int(r[1]))
}

func (r *Range) Length() uint32 {
	return r[1] - r[0] + 1
}
