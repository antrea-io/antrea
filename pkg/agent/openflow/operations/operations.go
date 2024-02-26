// Copyright 2024 Antrea Authors
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

package operations

import (
	"fmt"
	"time"

	"antrea.io/libOpenflow/openflow15"

	"antrea.io/antrea/pkg/agent/metrics"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type ofAction int32

const (
	add ofAction = iota
	mod
	del
)

func (a ofAction) String() string {
	switch a {
	case add:
		return "add"
	case mod:
		return "modify"
	case del:
		return "delete"
	default:
		return "unknown"
	}
}

type OFEntryOperations interface {
	AddAll(flows []*openflow15.FlowMod) error
	ModifyAll(flows []*openflow15.FlowMod) error
	BundleOps(adds, mods, dels []*openflow15.FlowMod) error
	DeleteAll(flows []*openflow15.FlowMod) error
	AddOFEntries(ofEntries []binding.OFEntry) error
	ModifyOFEntries(ofEntries []binding.OFEntry) error
	DeleteOFEntries(ofEntries []binding.OFEntry) error
}

type ofEntryOperations struct {
	bridge binding.Bridge
}

func NewOFEntryOperations(b binding.Bridge) OFEntryOperations {
	return &ofEntryOperations{bridge: b}
}

func (c *ofEntryOperations) AddAll(flowMessages []*openflow15.FlowMod) error {
	return c.changeAll(map[ofAction][]*openflow15.FlowMod{add: flowMessages})
}

func (c *ofEntryOperations) ModifyAll(flowMessages []*openflow15.FlowMod) error {
	return c.changeAll(map[ofAction][]*openflow15.FlowMod{mod: flowMessages})
}

func (c *ofEntryOperations) DeleteAll(flowMessages []*openflow15.FlowMod) error {
	return c.changeAll(map[ofAction][]*openflow15.FlowMod{del: flowMessages})
}

func (c *ofEntryOperations) BundleOps(adds, mods, dels []*openflow15.FlowMod) error {
	return c.changeAll(map[ofAction][]*openflow15.FlowMod{add: adds, mod: mods, del: dels})
}

func (c *ofEntryOperations) AddOFEntries(ofEntries []binding.OFEntry) error {
	return c.changeOFEntries(ofEntries, add)
}

func (c *ofEntryOperations) ModifyOFEntries(ofEntries []binding.OFEntry) error {
	return c.changeOFEntries(ofEntries, mod)
}

func (c *ofEntryOperations) DeleteOFEntries(ofEntries []binding.OFEntry) error {
	return c.changeOFEntries(ofEntries, del)
}

func (c *ofEntryOperations) changeAll(flowsMap map[ofAction][]*openflow15.FlowMod) error {
	if len(flowsMap) == 0 {
		return nil
	}

	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		for k, v := range flowsMap {
			if len(v) != 0 {
				metrics.OVSFlowOpsLatency.WithLabelValues(k.String()).Observe(float64(d.Milliseconds()))
			}
		}
	}()

	if err := c.bridge.AddFlowsInBundle(flowsMap[add], flowsMap[mod], flowsMap[del]); err != nil {
		for k, v := range flowsMap {
			if len(v) != 0 {
				metrics.OVSFlowOpsErrorCount.WithLabelValues(k.String()).Inc()
			}
		}
		return err
	}
	for k, v := range flowsMap {
		if len(v) != 0 {
			metrics.OVSFlowOpsCount.WithLabelValues(k.String()).Inc()
		}
	}
	return nil
}

func (c *ofEntryOperations) changeOFEntries(ofEntries []binding.OFEntry, action ofAction) error {
	if len(ofEntries) == 0 {
		return nil
	}
	var adds, mods, dels []binding.OFEntry
	if action == add {
		adds = ofEntries
	} else if action == mod {
		mods = ofEntries
	} else if action == del {
		dels = ofEntries
	} else {
		return fmt.Errorf("OF Entries Action not exists: %s", action)
	}
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		metrics.OVSFlowOpsLatency.WithLabelValues(action.String()).Observe(float64(d.Milliseconds()))
	}()
	if err := c.bridge.AddOFEntriesInBundle(adds, mods, dels); err != nil {
		metrics.OVSFlowOpsErrorCount.WithLabelValues(action.String()).Inc()
		return err
	}
	metrics.OVSFlowOpsCount.WithLabelValues(action.String()).Inc()
	return nil
}
