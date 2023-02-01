// Copyright 2023 Antrea Authors
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

package main

import (
	"os"
	"testing"

	"antrea.io/antrea/cmd/antrea-controller/app"
	"antrea.io/antrea/cmd/antrea-controller/app/options"
)

func TestNewControllerCommand(t *testing.T) {
	app.RunAntreaControllerFunc = func(o *options.Options) error {
		t.Log("fake AntreaController running")
		return nil
	}
	// As os.Args is a "global variable", it might be a good idea to keep the state from before the test and restore it after.
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()
	// The very first value in os.Args is a (path to) executable itself.
	os.Args = []string{"cmd"}
	cmd := newControllerCommand()
	if err := cmd.Execute(); err != nil {
		t.Errorf("Cannot execute version command: %v", err)
	}
}
