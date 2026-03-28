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
	makeAction := func(output []byte) testingexec.FakeAction {
		return func() ([]byte, []byte, error) { return output, nil, nil }
	}
	errorAction := func() ([]byte, []byte, error) { return nil, nil, fmt.Errorf("ip error") }

	tests := []struct {
		name           string
		commandActions []testingexec.FakeCommandAction
		expectFiles    map[string]string
		expectedErr    string
	}{
		{
			name: "all ip subcommands succeed and output files are created",
			commandActions: []testingexec.FakeCommandAction{
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{CombinedOutputScript: []testingexec.FakeAction{makeAction([]byte("route output\n"))}}
				},
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{CombinedOutputScript: []testingexec.FakeAction{makeAction([]byte("link output\n"))}}
				},
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{CombinedOutputScript: []testingexec.FakeAction{makeAction([]byte("address output\n"))}}
				},
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{CombinedOutputScript: []testingexec.FakeAction{makeAction([]byte("rule output\n"))}}
				},
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{CombinedOutputScript: []testingexec.FakeAction{makeAction([]byte("route-all output\n"))}}
				},
			},
			expectFiles: map[string]string{
				"route":            "route output\n",
				"link":             "link output\n",
				"address":          "address output\n",
				"rule":             "rule output\n",
				"route-all-tables": "route-all output\n",
			},
		},
		{
			name: "ip rule command failure returns error",
			commandActions: []testingexec.FakeCommandAction{
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{CombinedOutputScript: []testingexec.FakeAction{makeAction([]byte("route output\n"))}}
				},
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{CombinedOutputScript: []testingexec.FakeAction{makeAction([]byte("link output\n"))}}
				},
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{CombinedOutputScript: []testingexec.FakeAction{makeAction([]byte("address output\n"))}}
				},
				func(cmd string, args ...string) exec.Cmd {
					return &testingexec.FakeCmd{CombinedOutputScript: []testingexec.FakeAction{errorAction}}
				},
			},
			expectedErr: "error when dumping ip rule",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			fs.MkdirAll(baseDir, os.ModePerm)
			fakeExecutor := &testingexec.FakeExec{}
			fakeExecutor.CommandScript = tc.commandActions
			dumper := &agentDumper{fs: fs, executor: fakeExecutor}
			err := dumper.dumpIPToolInfo(baseDir)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
				return
			}
			require.NoError(t, err)
			for fileName, expectedContent := range tc.expectFiles {
				filePath := filepath.Join(baseDir, fileName)
				content, readErr := afero.ReadFile(fs, filePath)
				require.NoError(t, readErr, "expected file %s to exist", fileName)
				assert.Equal(t, expectedContent, string(content))
			}
		})
	}
}

func TestDumpSysctlNetIF(t *testing.T) {
	const confDir = "/proc/sys/net/ipv4/conf"
	tests := []struct {
		name            string
		setupFS         func(fs afero.Fs)
		expectedContent string
		expectFile      bool
	}{
		{
			name:       "conf dir absent returns nil without error",
			setupFS:    func(fs afero.Fs) {},
			expectFile: false,
		},
		{
			name: "populates sysctl file for each interface in alphabetical order",
			setupFS: func(fs afero.Fs) {
				for _, iface := range []string{"eth0", "lo"} {
					for param, val := range map[string]string{
						"rp_filter":    "1",
						"arp_ignore":   "0",
						"arp_announce": "2",
					} {
						p := filepath.Join(confDir, iface, param)
						fs.MkdirAll(filepath.Dir(p), os.ModePerm)
						afero.WriteFile(fs, p, []byte(val), 0644)
					}
				}
			},
			expectedContent: "net.ipv4.conf.eth0.rp_filter = 1\n" +
				"net.ipv4.conf.eth0.arp_ignore = 0\n" +
				"net.ipv4.conf.eth0.arp_announce = 2\n" +
				"net.ipv4.conf.lo.rp_filter = 1\n" +
				"net.ipv4.conf.lo.arp_ignore = 0\n" +
				"net.ipv4.conf.lo.arp_announce = 2\n",
			expectFile: true,
		},
		{
			name: "missing param file is skipped gracefully",
			setupFS: func(fs afero.Fs) {
				p := filepath.Join(confDir, "eth0", "rp_filter")
				fs.MkdirAll(filepath.Dir(p), os.ModePerm)
				afero.WriteFile(fs, p, []byte("1"), 0644)
			},
			expectedContent: "net.ipv4.conf.eth0.rp_filter = 1\n",
			expectFile:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			fs.MkdirAll(baseDir, os.ModePerm)
			tc.setupFS(fs)
			dumper := &agentDumper{fs: fs}
			err := dumper.dumpSysctlNetIF(baseDir)
			require.NoError(t, err)
			filePath := filepath.Join(baseDir, "sysctl-net-ipv4-conf")
			ok, err := afero.Exists(fs, filePath)
			require.NoError(t, err)
			assert.Equal(t, tc.expectFile, ok)
			if tc.expectFile {
				content, err := afero.ReadFile(fs, filePath)
				require.NoError(t, err)
				assert.Equal(t, tc.expectedContent, string(content))
			}
		})
	}
}
