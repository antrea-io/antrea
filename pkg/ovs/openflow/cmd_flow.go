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
	"strings"
)

type commandFlow struct {
	table    Table
	bridge   string
	priority uint32
	cookie   uint64
	matchers []string
	actions  []string
}

func (f *commandFlow) SetCookie(id uint64) Flow {
	f.cookie = id
	return f
}

func (f *commandFlow) Cookie() uint64 {
	return f.cookie
}

func (f *commandFlow) GetTable() Table {
	return f.table
}

func (f *commandFlow) format(withActions bool) string {
	repr := fmt.Sprintf("table=%d", f.table.GetID())

	if withActions {
		repr += fmt.Sprintf(",priority=%d", f.priority)
	}
	if len(f.matchers) > 0 {
		repr += fmt.Sprintf(",cookie=%d", f.cookie)
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

	f.updateTableStatus(1)
	return nil
}

func (f *commandFlow) Modify() error {
	type a interface {
		UpdateStatus(delta int)
	}
	if output, err := executor("ovs-ofctl", "mod-flows", f.bridge, "-O"+Version13, f.format(true)).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to modify flow %q: %v (%q)", f.format(true), err, output)
	}

	f.updateTableStatus(0)
	return nil
}

func (f *commandFlow) Delete() error {
	if output, err := executor("ovs-ofctl", "del-flows", f.bridge, "-O"+Version13, f.format(false)).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to delete flow %q: %v (%q)", f.format(false), err, output)
	}
	f.updateTableStatus(-1)
	return nil
}

func (f *commandFlow) updateTableStatus(delta int) {
	if updater, ok := f.table.(updater); ok {
		updater.UpdateStatus(delta)
	}
}

func (f *commandFlow) String() string {
	return f.format(true)
}

func (f *commandFlow) MatchString() string {
	return f.format(false)
}

func (f *commandFlow) CopyToBuilder() FlowBuilder {
	var newFlow = commandFlow{
		table:    f.table,
		bridge:   f.bridge,
		priority: f.priority,
		matchers: f.matchers,
	}
	return &commandBuilder{newFlow}
}
