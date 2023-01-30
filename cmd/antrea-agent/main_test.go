package main

import (
	"os"
	"testing"

	"antrea.io/antrea/cmd/antrea-agent/app/options"
)

func TestNewAgentCommand(t *testing.T) {
	runAntreaAgentFunc = func(o *options.Options) error {
		t.Log("fake AntreaAgent running")
		return nil
	}
	// As os.Args is a "global variable", it might be a good idea to keep the state from before the test and restore it after.
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()
	// The very first value in os.Args is a (path to) executable itself.
	os.Args = []string{"cmd"}
	cmd := newAgentCommand()
	if err := cmd.Execute(); err != nil {
		t.Errorf("Cannot execute version command: %v", err)
	}
}
