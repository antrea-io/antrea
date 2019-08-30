package openflow

import (
	"fmt"
	"strings"
)

type commandFlow struct {
	table    TableIDType
	bridge   string
	priority uint32
	matchers []string
	actions  []string
}

func (e *commandFlow) format(withActions bool) string {
	repr := fmt.Sprintf("table=%d,priority=%d", e.table, e.priority)
	if len(e.matchers) > 0 {
		repr += fmt.Sprintf(",%s", strings.Join(e.matchers, ","))
	}
	if withActions {
		repr += fmt.Sprintf(",actions=%s", strings.Join(e.actions, ","))
	}
	return repr
}

func (e *commandFlow) Add() error {
	return executor("ovs-ofctl", "add-flow", e.bridge, "-O"+Version13, e.format(true)).Run()
}

func (e *commandFlow) Modify() error {
	return executor("ovs-ofctl", "mod-flows", e.bridge, "-O"+Version13, e.format(true)).Run()
}

func (e *commandFlow) Delete() error {
	return executor("ovs-ofctl", "del-flows", e.bridge, "-O"+Version13, e.format(false)).Run()
}

func (e *commandFlow) String() string {
	return e.format(true)
}
