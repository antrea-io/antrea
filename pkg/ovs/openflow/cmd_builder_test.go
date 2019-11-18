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
	"os/exec"
	"strings"
	"testing"
)

func withUnitTestExecutor(f func()) string {
	var executedCommand string
	unitTestExecutor := func(name string, args ...string) *exec.Cmd {
		executedCommand = name + " " + strings.Join(args, " ")
		return exec.Command("true")
	}
	executor = unitTestExecutor
	defer func() { executor = exec.Command }()
	f()
	return executedCommand
}

func TestBasic(t *testing.T) {
	dummyBridge := NewBridge("ut0")
	dummyTable := dummyBridge.CreateTable(TableIDType(0), TableIDType(10), TableMissActionNext)

	flow := dummyTable.BuildFlow().(*commandBuilder).
		MatchField("FIELD", "VALUE").
		Action().Resubmit("", TableIDType(10)).
		Done()

	executedCommand := withUnitTestExecutor(func() {
		if err := flow.Add(); err != nil {
			t.Fatalf("Flow <%s> adding failed, err: %s", flow.String(), err)
		}
	})
	expectedCommand := "ovs-ofctl add-flow ut0 -OOpenflow13 table=0,priority=0,cookie=0,FIELD=VALUE,actions=resubmit(,10)"
	if executedCommand != expectedCommand {
		t.Fatalf("Expected running <%s>, got <%s>", expectedCommand, executedCommand)
	}
}
