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
	const nftOutput = `table ip antrea { 
	chain antrea-chain { 
		type filter hook input priority 0; 
	} 
}`

	errorAction := func() ([]byte, []byte, error) {
		return nil, nil, fmt.Errorf("error")
	}
	successAction := func() ([]byte, []byte, error) {
		return []byte(nftOutput), nil, nil
	}
	emptySuccessAction := func() ([]byte, []byte, error) {
		return []byte(""), nil, nil
	}

	originalV4Check := nftablesIPv4Supported
	originalV6Check := nftablesIPv6Supported
	nftablesIPv4Supported = func() bool { return true }
	nftablesIPv6Supported = func() bool { return true }
	t.Cleanup(func() {
		nftablesIPv4Supported = originalV4Check
		nftablesIPv6Supported = originalV6Check
	})

	tests := []struct {
		name            string
		commandActions  []testingexec.FakeCommandAction
		expectedContent string
		expectFile      bool
		expectedErr     string
	}{
		{
			name: "dump succeeds and writes nftables file",
			commandActions: []testingexec.FakeCommandAction{
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{
						CombinedOutputScript: []testingexec.FakeAction{successAction},
					}
				},
			},
			expectedContent: nftOutput + "\n",
			expectFile:      true,
		},
		{
			name: "command failure returns error and no file is written",
			commandActions: []testingexec.FakeCommandAction{
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{
						CombinedOutputScript: []testingexec.FakeAction{errorAction},
					}
				},
			},
			expectFile:  false,
			expectedErr: "failed to dump nftables: error",
		},
		{
			name: "empty nft output does not create file",
			commandActions: []testingexec.FakeCommandAction{
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{
						CombinedOutputScript: []testingexec.FakeAction{emptySuccessAction},
					}
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
				v4Enabled: true,
				v6Enabled: true,
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

func TestDumpIPSets(t *testing.T) {
	tests := []struct {
		name          string
		output        string
		execError     error
		fsError       bool
		expectedError string
	}{
		{
			name:   "Successful dump",
			output: "ipset v7.11: save working",
		},
		{
			name:   "Empty output",
			output: "",
		},
		{
			name:          "Command failure",
			execError:     fmt.Errorf("ipset not found"),
			expectedError: "error when dumping ipset: ipset not found",
		},
		{
			name:          "Filesystem write failure",
			output:        "some data",
			fsError:       true,
			expectedError: "error when writing ipset to file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup Fake Executor
			fakeExec := &testingexec.FakeExec{
				CommandScript: []testingexec.FakeCommandAction{
					func(cmd string, args ...string) exec.Cmd {
						return &testingexec.FakeCmd{
							CombinedOutputScript: []testingexec.FakeAction{
								func() ([]byte, []byte, error) {
									// Returns: stdout, stderr, error
									return []byte(tt.output), nil, tt.execError
								},
							},
						}
					},
				},
			}

			// Setup Filesystem
			var fs afero.Fs = afero.NewMemMapFs()
			if tt.fsError {
				fs = afero.NewReadOnlyFs(fs)
			}

			d := &agentDumper{
				executor: fakeExec,
				fs:       fs,
			}

			err := d.dumpIPSets("testdir")
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				if len(tt.output) > 0 {
					exists, _ := afero.Exists(fs, "testdir/ipset")
					assert.True(t, exists)
				}
			}
		})
	}
}
