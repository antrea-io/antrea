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
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/utils/exec"
	exectesting "k8s.io/utils/exec/testing"
)

func generateFakeOutputFn(stdout, stderr []byte, err error) exectesting.FakeAction {
	return func() ([]byte, []byte, error) {
		return stdout, stderr, err
	}
}

func assertFakeCmdCall(t *testing.T, outputFn exectesting.FakeAction, expectedCommand string, expectedArgs ...string) exectesting.FakeCommandAction {
	if outputFn == nil {
		outputFn = func() ([]byte, []byte, error) {
			return nil, nil, nil
		}
	}
	return func(cmd string, args ...string) exec.Cmd {
		if expectedCommand != cmd {
			t.Errorf("Wrong cmd called: got %v, expected: %v", cmd, expectedCommand)
		}
		if !slices.Equal(args, expectedArgs) {
			t.Errorf("Wrong args: got %v, expected %v", args, expectedArgs)
		}
		fakeCmd := &exectesting.FakeCmd{
			Argv:                 args,
			CombinedOutputScript: []exectesting.FakeAction{outputFn},
		}
		return fakeCmd
	}
}

func TestClient_CreateIPSet(t *testing.T) {
	tests := []struct {
		name                   string
		setType                SetType
		isIPv6                 bool
		expectedCommandActions []exectesting.FakeCommandAction
		wantErr                bool
		errMsg                 string
	}{
		{
			name:    "Create IPv4 hash:net set",
			setType: HashNet,
			isIPv6:  false,
			expectedCommandActions: []exectesting.FakeCommandAction{
				assertFakeCmdCall(t, nil, "ipset", "create", "test", string(HashNet), "-exist"),
			},
			wantErr: false,
		},
		{
			name:    "Create IPv6 hash:ip set",
			setType: HashIP,
			isIPv6:  true,
			expectedCommandActions: []exectesting.FakeCommandAction{
				assertFakeCmdCall(t, nil, "ipset", "create", "test", string(HashIP), "family", "inet6", "-exist"),
			},
			wantErr: false,
		},
		{
			name:    "Create IPv4 set with error",
			setType: HashIPPort,
			isIPv6:  false,
			expectedCommandActions: []exectesting.FakeCommandAction{
				assertFakeCmdCall(t, generateFakeOutputFn([]byte("error output"), nil, errors.New("some errors")), "ipset", "create", "test", string(HashIPPort), "-exist"),
			},
			wantErr: true,
			errMsg:  "error creating ipset test, err: some errors, output: error output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeExec := &exectesting.FakeExec{CommandScript: tt.expectedCommandActions}
			c := &Client{exec: fakeExec}
			err := c.CreateIPSet("test", tt.setType, tt.isIPv6)
			if tt.wantErr {
				assert.EqualError(t, err, tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestClient_DestroyIPSet(t *testing.T) {
	tests := []struct {
		name                   string
		expectedCommandActions []exectesting.FakeCommandAction
		wantErr                bool
		errMsg                 string
	}{
		{
			name: "Destroy set successfully",
			expectedCommandActions: []exectesting.FakeCommandAction{
				assertFakeCmdCall(t, nil, "ipset", "destroy", "test"),
			},
			wantErr: false,
		},
		{
			name: "Destroy non-existent set, no error",
			expectedCommandActions: []exectesting.FakeCommandAction{
				assertFakeCmdCall(t, generateFakeOutputFn(nil, nil, errors.New("The set with the given name does not exist")), "ipset", "destroy", "test"),
			},
			wantErr: false,
		},
		{
			name: "Destroy set with other error",
			expectedCommandActions: []exectesting.FakeCommandAction{
				assertFakeCmdCall(t, generateFakeOutputFn([]byte("error output"), nil, errors.New("some errors")), "ipset", "destroy", "test"),
			},
			wantErr: true,
			errMsg:  "error destroying ipset test, err: some errors, output: error output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeExec := &exectesting.FakeExec{CommandScript: tt.expectedCommandActions}
			c := &Client{exec: fakeExec}
			err := c.DestroyIPSet("test")
			if tt.wantErr {
				assert.EqualError(t, err, tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestClient_AddEntry(t *testing.T) {
	fakeExec := &exectesting.FakeExec{
		CommandScript: []exectesting.FakeCommandAction{
			assertFakeCmdCall(t, generateFakeOutputFn([]byte("error output"), nil, errors.New("some errors")), "ipset", "add", "test", "1..2.3.4", "-exist"),
			assertFakeCmdCall(t, nil, "ipset", "add", "test", "1.2.3.4", "-exist"),
		},
	}
	c := &Client{exec: fakeExec}
	err := c.AddEntry("test", "1..2.3.4")
	assert.EqualError(t, err, "error adding entry 1..2.3.4 to ipset test, err: some errors, output: error output")
	err = c.AddEntry("test", "1.2.3.4")
	assert.NoError(t, err)
}

func TestClient_DelEntry(t *testing.T) {
	fakeExec := &exectesting.FakeExec{
		CommandScript: []exectesting.FakeCommandAction{
			assertFakeCmdCall(t, generateFakeOutputFn([]byte("error output"), nil, errors.New("some errors")), "ipset", "del", "test", "1..2.3.4", "-exist"),
			assertFakeCmdCall(t, nil, "ipset", "del", "test", "1.2.3.4", "-exist"),
		},
	}
	c := &Client{exec: fakeExec}
	err := c.DelEntry("test", "1..2.3.4")
	assert.EqualError(t, err, "error deleting entry 1..2.3.4 from ipset test, err: some errors, output: error output")
	err = c.DelEntry("test", "1.2.3.4")
	assert.NoError(t, err)
}

func TestClient_ListEntries(t *testing.T) {
	fakeOutput1 := generateFakeOutputFn([]byte("error output"), nil, errors.New("some errors"))
	expectedEntries := []string{"1.1.1.1", "2.2.2.2"}
	fakeOutput2 := generateFakeOutputFn([]byte("1.1.1.1\n2.2.2.2"), nil, nil)
	fakeExec := &exectesting.FakeExec{
		CommandScript: []exectesting.FakeCommandAction{
			assertFakeCmdCall(t, fakeOutput1, "ipset", "list", "test"),
			assertFakeCmdCall(t, fakeOutput2, "ipset", "list", "test"),
		},
	}
	c := &Client{exec: fakeExec}
	entries, err := c.ListEntries("test")
	assert.EqualError(t, err, "error listing ipset test, err: some errors, output: error output")
	assert.Nil(t, entries)
	entries, err = c.ListEntries("test")
	assert.NoError(t, err)
	assert.True(t, slices.Equal(expectedEntries, entries))
}
