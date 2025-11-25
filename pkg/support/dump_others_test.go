// Copyright 2020 Antrea Authors
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

//go:build !windows
// +build !windows

package support

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"antrea.io/antrea/pkg/util/logdir"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/exec"
	testingexec "k8s.io/utils/exec/testing"
)

func TestDumpLog(t *testing.T) {
	fs := afero.NewMemMapFs()
	logDir := logdir.GetLogDir()

	fs.MkdirAll(logDir, os.ModePerm)
	fs.Create(filepath.Join(logDir, "antrea-agent.log"))
	fs.Create(filepath.Join(logDir, "ovs.log"))
	fs.Create(filepath.Join(logDir, "kubelet.log"))

	dumper := NewAgentDumper(fs, nil, nil, nil, nil, "7s", true, true)
	err := dumper.DumpLog(baseDir)
	require.NoError(t, err)

	ok, err := afero.Exists(fs, filepath.Join(baseDir, "logs", "agent", "antrea-agent.log"))
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = afero.Exists(fs, filepath.Join(baseDir, "logs", "ovs", "ovs.log"))
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestDumpNFTables(t *testing.T) {
	const nftV4Output = "table ip antrea { chain antrea-chain { type filter hook input priority 0; } }"
	const nftV6Output = "table ip6 antrea { chain antrea-chain6 { type filter hook input priority 0; } }"

	v4ErrorAction := func() ([]byte, []byte, error) {
		return nil, nil, fmt.Errorf("v4 error")
	}
	v4SuccessAction := func() ([]byte, []byte, error) {
		return []byte(nftV4Output), nil, nil
	}
	v6SuccessAction := func() ([]byte, []byte, error) {
		return []byte(nftV6Output), nil, nil
	}
	emptySuccessAction := func() ([]byte, []byte, error) {
		return []byte(""), nil, nil
	}

	originalV4Check := nftablesIPv4Supported
	originalV6Check := nftablesIPv6Supported
	t.Cleanup(func() {
		nftablesIPv4Supported = originalV4Check
		nftablesIPv6Supported = originalV6Check
	})

	nftablesIPv4Supported = func() bool { return true }
	nftablesIPv6Supported = func() bool { return true }

	tests := []struct {
		name            string
		v4Enabled       bool
		v6Enabled       bool
		commandActions  []testingexec.FakeCommandAction
		expectedContent string
		expectFile      bool
		expectedErr     string
	}{
		{
			name:      "v4 enabled only",
			v4Enabled: true,
			v6Enabled: false,
			commandActions: []testingexec.FakeCommandAction{
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{
						CombinedOutputScript: []testingexec.FakeAction{v4SuccessAction},
					}
				},
			},
			expectedContent: nftV4Output + "\n",
			expectFile:      true,
		},
		{
			name:      "v6 enabled only",
			v4Enabled: false,
			v6Enabled: true,
			commandActions: []testingexec.FakeCommandAction{
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{
						CombinedOutputScript: []testingexec.FakeAction{v6SuccessAction},
					}
				},
			},
			expectedContent: nftV6Output + "\n",
			expectFile:      true,
		},
		{
			name:      "v4 and v6 enabled",
			v4Enabled: true,
			v6Enabled: true,
			commandActions: []testingexec.FakeCommandAction{
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{
						CombinedOutputScript: []testingexec.FakeAction{v4SuccessAction},
					}
				},
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{
						CombinedOutputScript: []testingexec.FakeAction{v6SuccessAction},
					}
				},
			},
			expectedContent: nftV4Output + "\n" + nftV6Output + "\n",
			expectFile:      true,
		},
		{
			name:      "v4 command error",
			v4Enabled: true,
			v6Enabled: true,
			commandActions: []testingexec.FakeCommandAction{
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{
						CombinedOutputScript: []testingexec.FakeAction{v4ErrorAction},
					}
				},
			},
			expectFile:  false,
			expectedErr: "failed to dump nftables table 'ip antrea': v4 error",
		},
		{
			name:      "no rules found (empty output)",
			v4Enabled: true,
			v6Enabled: true,
			commandActions: []testingexec.FakeCommandAction{
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{CombinedOutputScript: []testingexec.FakeAction{emptySuccessAction}}
				},
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{CombinedOutputScript: []testingexec.FakeAction{emptySuccessAction}}
				},
			},
			expectFile: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			fs.MkdirAll(baseDir, os.ModePerm)

			fakeExecutor := &testingexec.FakeExec{}
			fakeExecutor.CommandScript = tc.commandActions

			dumper := &agentDumper{
				fs:        fs,
				executor:  fakeExecutor,
				v4Enabled: tc.v4Enabled,
				v6Enabled: tc.v6Enabled,
			}

			err := dumper.dumpNFTables(baseDir)

			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}

			filePath := filepath.Join(baseDir, "nftables")

			ok, err := afero.Exists(fs, filePath)
			require.NoError(t, err)
			assert.Equal(t, tc.expectFile, ok, "Expected nftables file existence to be %t", tc.expectFile)

			if tc.expectFile {
				content, err := afero.ReadFile(fs, filePath)
				require.NoError(t, err)
				assert.Equal(t, tc.expectedContent, string(content), "File content does not match")
			}
		})
	}
}
