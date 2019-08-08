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
	dummyTable := &Table{
		ID:     TableIDType(0),
		Bridge: "ut0",
		Next:   TableIDType(10),
	}

	flow := dummyTable.BuildFlow().
		MatchField("FIELD", "VALUE").
		Action().Resubmit("", TableIDType(10)).
		Done()

	executedCommand := withUnitTestExecutor(func() {
		if err := flow.Add(); err != nil {
			t.Fatalf("Flow <%s> adding failed, err: %s", flow.String(), err)
		}
	})
	expectedCommand := "ovs-ofctl add-flow ut0 -OOpenflow13 table=0,priority=0,FIELD=VALUE,actions=resubmit(,10)"
	if executedCommand != expectedCommand {
		t.Fatalf("Expected running <%s>, got <%s>", expectedCommand, executedCommand)
	}
}
