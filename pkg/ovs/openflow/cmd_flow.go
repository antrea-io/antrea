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

func (f *commandFlow) format(withActions bool) string {
	repr := fmt.Sprintf("table=%d", f.table)

	if withActions {
		repr += fmt.Sprintf(",priority=%d", f.priority)
	}
	if len(f.matchers) > 0 {
		repr += fmt.Sprintf(",%s", strings.Join(f.matchers, ","))
	}
	if withActions && len(f.actions) > 0 {
		repr += fmt.Sprintf(",actions=%s", strings.Join(f.actions, ","))
	}

	return repr
}

func (f *commandFlow) Add() error {
	if output, err := executor("ovs-ofctl", "add-flow", f.bridge, "-O"+Version13, f.format(true)).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add flow %q: %v (%q)", f.format(true), err, output)
	}
	return nil
}

func (f *commandFlow) Modify() error {
	if output, err := executor("ovs-ofctl", "mod-flows", f.bridge, "-O"+Version13, f.format(true)).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to modify flow %q: %v (%q)", f.format(true), err, output)
	}
	return nil
}

func (f *commandFlow) Delete() error {
	if output, err := executor("ovs-ofctl", "del-flows", f.bridge, "-O"+Version13, f.format(false)).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to delete flow %q: %v (%q)", f.format(false), err, output)
	}
	return nil
}

func (f *commandFlow) String() string {
	return f.format(true)
}
