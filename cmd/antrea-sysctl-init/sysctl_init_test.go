//go:build linux
// +build linux

// Copyright 2025 Antrea Authors
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
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/exec"
	exectesting "k8s.io/utils/exec/testing"
)

func newFakeExec() *exectesting.FakeExec {
	fcmd := exectesting.FakeCmd{
		CombinedOutputScript: []exectesting.FakeAction{
			func() ([]byte, []byte, error) {
				return nil, nil, nil
			},
		},
	}
	return &exectesting.FakeExec{
		CommandScript: []exectesting.FakeCommandAction{
			func(cmd string, args ...string) exec.Cmd {
				return exectesting.InitFakeCmd(&fcmd, cmd, args...)
			},
		},
	}
}

func TestRun(t *testing.T) {
	opts := &options{
		hostGatewayName: "antrea-gw0",
	}

	tests := []struct {
		name string
		fs   afero.Fs
		err  string
	}{
		{
			name: "success",
			fs:   afero.NewMemMapFs(),
		},
		{
			name: "write file failure",
			fs:   afero.NewReadOnlyFs(afero.NewMemMapFs()),
			err:  "failed to write Antrea sysctl configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origFs := defaultFs
			origExec := defaultExec
			origSysctlFile := defaultSysctlFile
			defaultFs = tt.fs
			defaultExec = newFakeExec()
			defaultSysctlFile = "/antrea-test.conf"
			t.Cleanup(func() {
				defaultFs = origFs
				defaultExec = origExec
				defaultSysctlFile = origSysctlFile
			})

			err := run(opts)
			if tt.err != "" {
				assert.ErrorContains(t, err, tt.err)
			} else {
				require.NoError(t, err)

				exists, err := afero.Exists(defaultFs, defaultSysctlFile)
				require.NoError(t, err)
				require.True(t, exists)

				content, err := afero.ReadFile(defaultFs, defaultSysctlFile)
				require.NoError(t, err)
				require.Equal(t, buildAntreaSysctlConfig(opts.hostGatewayName), string(content))
			}
		})
	}
}
