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

package ipset

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/exec"
	exectesting "k8s.io/utils/exec/testing"
)

var testIPSetName = "test-ipset"

func TestCreateIPSet(t *testing.T) {
	tests := []struct {
		name              string
		setType           SetType
		isIPv6            bool
		err               error
		output            string
		expectedArgs      []string
		expectedErrOutput string
	}{
		{
			name:         "Create IPv4 hash:net set successfully",
			setType:      HashNet,
			expectedArgs: []string{"ipset", "create", testIPSetName, string(HashNet), "-exist"},
		},
		{
			name:         "Create IPv6 hash:ip set successfully",
			setType:      HashIP,
			isIPv6:       true,
			expectedArgs: []string{"ipset", "create", testIPSetName, string(HashIP), "family", "inet6", "-exist"},
		},
		{
			name:              "Create IPv4 set with error",
			setType:           HashIPPort,
			err:               errors.New("some errors"),
			output:            "error output",
			expectedArgs:      []string{"ipset", "create", testIPSetName, string(HashIPPort), "-exist"},
			expectedErrOutput: fmt.Sprintf("error creating ipset %s, err: some errors, output: error output", testIPSetName),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fcmd := exectesting.FakeCmd{
				CombinedOutputScript: []exectesting.FakeAction{func() ([]byte, []byte, error) { return []byte(tt.output), nil, tt.err }},
			}
			fakeExec := &exectesting.FakeExec{
				CommandScript: []exectesting.FakeCommandAction{
					func(cmd string, args ...string) exec.Cmd { return exectesting.InitFakeCmd(&fcmd, cmd, args...) },
				},
			}
			c := &Client{exec: fakeExec}
			err := c.CreateIPSet(testIPSetName, tt.setType, tt.isIPv6)
			require.Equal(t, 1, fcmd.CombinedOutputCalls)
			assert.Equal(t, tt.expectedArgs, fcmd.CombinedOutputLog[0])
			if tt.expectedErrOutput != "" {
				assert.EqualError(t, err, tt.expectedErrOutput)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDestroyIPSet(t *testing.T) {
	tests := []struct {
		name              string
		err               error
		output            string
		expectedErrOutput string
	}{
		{
			name: "Destroy set successfully",
		},
		{
			name:   "Destroy non-existent set, no error",
			output: "The set with the given name does not exist",
			err:    errors.New("exit status 1"),
		},
		{
			name:              "Destroy set with error",
			err:               errors.New("some errors"),
			output:            "error output",
			expectedErrOutput: fmt.Sprintf("error destroying ipset %s, err: some errors, output: error output", testIPSetName),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fcmd := exectesting.FakeCmd{
				CombinedOutputScript: []exectesting.FakeAction{func() ([]byte, []byte, error) { return []byte(tt.output), nil, tt.err }},
			}
			fakeExec := &exectesting.FakeExec{
				CommandScript: []exectesting.FakeCommandAction{
					func(cmd string, args ...string) exec.Cmd { return exectesting.InitFakeCmd(&fcmd, cmd, args...) },
				},
			}
			c := &Client{exec: fakeExec}
			err := c.DestroyIPSet(testIPSetName)
			require.Equal(t, 1, fcmd.CombinedOutputCalls)
			assert.Equal(t, []string{"ipset", "destroy", testIPSetName}, fcmd.CombinedOutputLog[0])
			if tt.expectedErrOutput != "" {
				assert.EqualError(t, err, tt.expectedErrOutput)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAddEntry(t *testing.T) {
	tests := []struct {
		name              string
		entry             string
		err               error
		output            string
		expectedErrOutput string
	}{
		{
			name:  "Add entry successfully",
			entry: "1.2.3.4",
		},
		{
			name:              "Add entry with error",
			entry:             "1..2.3.4",
			err:               errors.New("some errors"),
			output:            "error output",
			expectedErrOutput: fmt.Sprintf("error adding entry 1..2.3.4 to ipset %s, err: some errors, output: error output", testIPSetName),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fcmd := exectesting.FakeCmd{
				CombinedOutputScript: []exectesting.FakeAction{func() ([]byte, []byte, error) { return []byte(tt.output), nil, tt.err }},
			}
			fakeExec := &exectesting.FakeExec{
				CommandScript: []exectesting.FakeCommandAction{
					func(cmd string, args ...string) exec.Cmd { return exectesting.InitFakeCmd(&fcmd, cmd, args...) },
				},
			}
			c := &Client{exec: fakeExec}
			err := c.AddEntry(testIPSetName, tt.entry)
			require.Equal(t, 1, fcmd.CombinedOutputCalls)
			assert.Equal(t, []string{"ipset", "add", testIPSetName, tt.entry, "-exist"}, fcmd.CombinedOutputLog[0])
			if tt.expectedErrOutput != "" {
				assert.EqualError(t, err, tt.expectedErrOutput)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDelEntry(t *testing.T) {
	tests := []struct {
		name              string
		entry             string
		err               error
		output            string
		expectedErrOutput string
	}{
		{
			name:  "Delete entry successfully",
			entry: "1.2.3.4",
		},
		{
			name:              "Delete entry with error",
			entry:             "1..2.3.4",
			err:               errors.New("some errors"),
			output:            "error output",
			expectedErrOutput: fmt.Sprintf("error deleting entry 1..2.3.4 from ipset %s, err: some errors, output: error output", testIPSetName),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fcmd := exectesting.FakeCmd{
				CombinedOutputScript: []exectesting.FakeAction{func() ([]byte, []byte, error) { return []byte(tt.output), nil, tt.err }},
			}
			fakeExec := &exectesting.FakeExec{
				CommandScript: []exectesting.FakeCommandAction{
					func(cmd string, args ...string) exec.Cmd { return exectesting.InitFakeCmd(&fcmd, cmd, args...) },
				},
			}
			c := &Client{exec: fakeExec}
			err := c.DelEntry(testIPSetName, tt.entry)
			require.Equal(t, 1, fcmd.CombinedOutputCalls)
			assert.Equal(t, []string{"ipset", "del", testIPSetName, tt.entry, "-exist"}, fcmd.CombinedOutputLog[0])
			if tt.expectedErrOutput != "" {
				assert.EqualError(t, err, tt.expectedErrOutput)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestListEntries(t *testing.T) {
	tests := []struct {
		name              string
		err               error
		output            string
		expectedEntries   []string
		expectedErrOutput string
	}{
		{
			name:            "List entries successfully",
			output:          "1.1.1.1\n2.2.2.2",
			expectedEntries: []string{"1.1.1.1", "2.2.2.2"},
		},
		{
			name:              "List entries with error",
			err:               errors.New("some errors"),
			output:            "error output",
			expectedErrOutput: fmt.Sprintf("error listing ipset %s, err: some errors, output: error output", testIPSetName),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fcmd := exectesting.FakeCmd{
				CombinedOutputScript: []exectesting.FakeAction{func() ([]byte, []byte, error) { return []byte(tt.output), nil, tt.err }},
			}
			fakeExec := &exectesting.FakeExec{
				CommandScript: []exectesting.FakeCommandAction{
					func(cmd string, args ...string) exec.Cmd { return exectesting.InitFakeCmd(&fcmd, cmd, args...) },
				},
			}
			c := &Client{exec: fakeExec}
			entries, err := c.ListEntries(testIPSetName)
			require.Equal(t, 1, fcmd.CombinedOutputCalls)
			assert.Equal(t, []string{"ipset", "list", testIPSetName}, fcmd.CombinedOutputLog[0])
			if tt.expectedErrOutput != "" {
				assert.EqualError(t, err, tt.expectedErrOutput)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, []string{"1.1.1.1", "2.2.2.2"}, entries)
			}
		})
	}
}
