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

	ipsettest "antrea.io/antrea/v2/pkg/agent/util/ipset/testing"
	"antrea.io/antrea/v2/pkg/util/logdir"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
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

func TestDumpIPSet(t *testing.T) {
	const ipsetOutput = `create ANTREA-POD-IP hash:net family inet hashsize 1024 maxelem 65536 bucketsize 12 initval 0xaff5135c
add ANTREA-POD-IP 10.244.0.0/24
add ANTREA-POD-IP 10.244.1.0/24
add ANTREA-POD-IP 10.244.2.0/24
create ANTREA-POD-IP6 hash:net family inet6 hashsize 1024 maxelem 65536 bucketsize 12 initval 0xf621d31a
add ANTREA-POD-IP6 fd00:10:244:2::/64
add ANTREA-POD-IP6 fd00:10:244:1::/64
add ANTREA-POD-IP6 fd00:10:244::/64
`
	tests := []struct {
		name            string
		expectedCalls   func(mockIPSet *ipsettest.MockInterfaceMockRecorder)
		expectedContent string
		expectFile      bool
		expectedErr     string
	}{
		{
			name: "dump succeeds",
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.Save().Return([]byte(ipsetOutput), nil)
			},
			expectedContent: ipsetOutput,
			expectFile:      true,
		},
		{
			name: "dump fails",
			expectedCalls: func(mockIPSet *ipsettest.MockInterfaceMockRecorder) {
				mockIPSet.Save().Return(nil, fmt.Errorf("error saving ipset: error, output: output"))
			},
			expectedErr: "error saving ipset: error, output: output",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			fs.MkdirAll(baseDir, os.ModePerm)

			ctrl := gomock.NewController(t)
			mockIPSet := ipsettest.NewMockInterface(ctrl)

			dumper := &agentDumper{
				fs:          fs,
				ipsetClient: mockIPSet,
			}

			tc.expectedCalls(mockIPSet.EXPECT())
			err := dumper.dumpIPSet(baseDir)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}

			filePath := filepath.Join(baseDir, "ipset")
			ok, err := afero.Exists(fs, filePath)
			require.NoError(t, err)
			assert.Equal(t, tc.expectFile, ok, "Expected ipset file existence to be %t", tc.expectFile)

			if tc.expectFile {
				content, err := afero.ReadFile(fs, filePath)
				require.NoError(t, err)
				assert.Equal(t, tc.expectedContent, string(content), "File content does not match")
			}
		})
	}
}

func TestDumpIPToolInfo(t *testing.T) {
	successAction := func() ([]byte, []byte, error) {
		return []byte("output"), nil, nil
	}
	errorAction := func() ([]byte, []byte, error) {
		return nil, nil, fmt.Errorf("exec error")
	}

	type commandCall struct {
		cmd  string
		args []string
	}

	// wantCalls is the exact sequence of ip sub-commands that dumpIPToolInfo must invoke.
	// A typo in any command name or argument would cause these assertions to fail.
	wantCalls := []commandCall{
		{cmd: "ip", args: []string{"rule"}},
		{cmd: "ip", args: []string{"route"}},
		{cmd: "ip", args: []string{"link"}},
		{cmd: "ip", args: []string{"address"}},
		{cmd: "ip", args: []string{"route", "show", "table", "all"}},
	}
	allFiles := []string{"rule", "route", "link", "address", "route-table-all"}

	tests := []struct {
		name          string
		failFirst     bool
		expectedFiles []string
		expectedErr   string
	}{
		{
			name:          "all commands succeed",
			expectedFiles: allFiles,
		},
		{
			name:        "first command fails returns error",
			failFirst:   true,
			expectedErr: "error when dumping ip rule",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			fs.MkdirAll(baseDir, os.ModePerm)

			var gotCalls []commandCall
			var commandScript []testingexec.FakeCommandAction
			for i := range wantCalls {
				i := i
				action := successAction
				if tc.failFirst && i == 0 {
					action = errorAction
				}
				commandScript = append(commandScript, func(cmd string, args ...string) exec.Cmd {
					gotCalls = append(gotCalls, commandCall{cmd: cmd, args: args})
					return &testingexec.FakeCmd{
						CombinedOutputScript: []testingexec.FakeAction{action},
					}
				})
			}

			fakeExecutor := &testingexec.FakeExec{}
			fakeExecutor.CommandScript = commandScript

			dumper := &agentDumper{
				fs:       fs,
				executor: fakeExecutor,
			}

			err := dumper.dumpIPToolInfo(baseDir)

			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
				// Only the first command should have been invoked.
				require.Len(t, gotCalls, 1)
				assert.Equal(t, wantCalls[0], gotCalls[0])
			} else {
				require.NoError(t, err)
				assert.Equal(t, wantCalls, gotCalls)
				for _, name := range tc.expectedFiles {
					ok, err := afero.Exists(fs, filepath.Join(baseDir, name))
					require.NoError(t, err)
					assert.True(t, ok, "expected file %q to exist", name)
				}
			}
		})
	}
}
