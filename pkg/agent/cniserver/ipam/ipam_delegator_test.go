// Copyright 2022 Antrea Authors
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

package ipam

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/stretchr/testify/assert"

	argtypes "antrea.io/antrea/pkg/agent/cniserver/types"
)

type mockPluginInfo struct{}

func (m *mockPluginInfo) Encode(io.Writer) error {
	return nil
}

func (m *mockPluginInfo) SupportedVersions() []string {
	return []string{}
}

type mockExec struct{}

func (m *mockExec) ExecPlugin(ctx context.Context, pluginPath string, stdinData []byte, environ []string) ([]byte, error) {
	return []byte{}, nil
}

func (m *mockExec) FindInPath(plugin string, paths []string) (string, error) {
	return "", nil
}

func (m *mockExec) Decode(jsonBytes []byte) (version.PluginInfo, error) {
	return &mockPluginInfo{}, nil
}

var (
	fakeExecWithResultReturnErr = func(ctx context.Context, pluginPath string, netconf []byte, args invoke.CNIArgs, exec invoke.Exec) (types.Result, error) {
		return &current.Result{
			CNIVersion: testCNIVersion,
		}, fmt.Errorf("error")
	}
)

func TestAdd(t *testing.T) {
	defaultExec = &mockExec{}
	defer func() {
		defaultExec = &invoke.DefaultExec{
			RawExec: &invoke.RawExec{Stderr: os.Stderr},
		}
	}()
	testCases := []struct {
		name               string
		args               invoke.Args
		k8sArgs            argtypes.K8sArgs
		execWithResultFunc func(ctx context.Context, pluginPath string, netconf []byte, args invoke.CNIArgs, exec invoke.Exec) (types.Result, error)
		execNoResultFunc   func(ctx context.Context, pluginPath string, netconf []byte, args invoke.CNIArgs, exec invoke.Exec) error
		expectedRes        error
	}{
		{
			name:               "Test Add",
			args:               invoke.Args{Path: defaultCNIPath},
			execWithResultFunc: fakeExecWithResult,
			execNoResultFunc:   fakeExecNoResult,
			expectedRes:        nil,
		},
		{
			name:               "Test Add no success",
			args:               invoke.Args{Path: defaultCNIPath},
			execWithResultFunc: fakeExecWithResultReturnErr,
			execNoResultFunc:   fakeExecNoResult,
			expectedRes:        fmt.Errorf("error"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			execPluginWithResultFunc = testCase.execWithResultFunc
			execPluginNoResultFunc = testCase.execNoResultFunc
			defer func() {
				execPluginWithResultFunc = invoke.ExecPluginWithResult
				execPluginNoResultFunc = invoke.ExecPluginWithoutResult
			}()
			d := &IPAMDelegator{pluginType: ipamHostLocal}
			_, _, err := d.Add(&testCase.args, &testCase.k8sArgs, testNetworkConfig)
			assert.Equal(t, testCase.expectedRes, err)
		})
	}
}

func TestDel(t *testing.T) {
	defaultExec = &mockExec{}
	defer func() {
		defaultExec = &invoke.DefaultExec{
			RawExec: &invoke.RawExec{Stderr: os.Stderr},
		}
	}()
	testCases := []struct {
		name        string
		args        invoke.Args
		k8sArgs     argtypes.K8sArgs
		expectedRes error
	}{
		{
			name:        "Test Del",
			args:        invoke.Args{Path: defaultCNIPath},
			expectedRes: nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			execPluginWithResultFunc = fakeExecWithResult
			execPluginNoResultFunc = fakeExecNoResult
			defer func() {
				execPluginWithResultFunc = invoke.ExecPluginWithResult
				execPluginNoResultFunc = invoke.ExecPluginWithoutResult
			}()
			d := &IPAMDelegator{pluginType: ipamHostLocal}
			_, err := d.Del(&testCase.args, &testCase.k8sArgs, testNetworkConfig)
			assert.Equal(t, testCase.expectedRes, err)
		})
	}
}

func TestCheck(t *testing.T) {
	defaultExec = &mockExec{}
	defer func() {
		defaultExec = &invoke.DefaultExec{
			RawExec: &invoke.RawExec{Stderr: os.Stderr},
		}
	}()
	testCases := []struct {
		name        string
		args        invoke.Args
		k8sArgs     argtypes.K8sArgs
		expectedRes error
	}{
		{
			name:        "Test Check",
			args:        invoke.Args{Path: defaultCNIPath},
			expectedRes: nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			execPluginWithResultFunc = fakeExecWithResult
			execPluginNoResultFunc = fakeExecNoResult
			defer func() {
				execPluginWithResultFunc = invoke.ExecPluginWithResult
				execPluginNoResultFunc = invoke.ExecPluginWithoutResult
			}()
			d := &IPAMDelegator{pluginType: ipamHostLocal}
			_, err := d.Check(&testCase.args, &testCase.k8sArgs, testNetworkConfig)
			assert.Equal(t, testCase.expectedRes, err)
		})
	}
}

func TestDelegateWithResult(t *testing.T) {
	defaultExec = &mockExec{}
	defer func() {
		defaultExec = &invoke.DefaultExec{
			RawExec: &invoke.RawExec{Stderr: os.Stderr},
		}
	}()
	testCases := []struct {
		name        string
		args        invoke.Args
		expectedRes error
	}{
		{
			name:        "Test delegateWithResult",
			args:        invoke.Args{Path: defaultCNIPath},
			expectedRes: nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			execPluginWithResultFunc = fakeExecWithResult
			defer func() {
				execPluginWithResultFunc = invoke.ExecPluginWithResult
			}()
			_, err := delegateWithResult(ipamHostLocal, testNetworkConfig, &testCase.args)
			assert.Equal(t, testCase.expectedRes, err)
		})
	}
}

func TestDelegateNoResult(t *testing.T) {
	defaultExec = &mockExec{}
	defer func() {
		defaultExec = &invoke.DefaultExec{
			RawExec: &invoke.RawExec{Stderr: os.Stderr},
		}
	}()
	testCases := []struct {
		name        string
		args        invoke.Args
		expectedRes error
	}{
		{
			name:        "Test delegateNoResult",
			args:        invoke.Args{Path: defaultCNIPath},
			expectedRes: nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			execPluginNoResultFunc = fakeExecNoResult
			defer func() {
				execPluginNoResultFunc = invoke.ExecPluginWithoutResult
			}()
			assert.Equal(t, testCase.expectedRes, delegateNoResult(ipamHostLocal, testNetworkConfig, &testCase.args))
		})
	}
}
