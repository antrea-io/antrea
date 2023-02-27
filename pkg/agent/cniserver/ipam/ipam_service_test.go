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
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/stretchr/testify/assert"

	argtypes "antrea.io/antrea/pkg/agent/cniserver/types"
	cnipb "antrea.io/antrea/pkg/apis/cni/v1beta1"
)

type networkConf struct {
	CNIVersion string `json:"cniVersion"`
}

var (
	testNetworkConfig, _ = json.Marshal(networkConf{CNIVersion: testCNIVersion})
	fakeExecWithResult   = func(ctx context.Context, pluginPath string, netconf []byte, args invoke.CNIArgs, exec invoke.Exec) (types.Result, error) {
		return &current.Result{
			CNIVersion: testCNIVersion,
		}, nil
	}
	fakeExecNoResult = func(ctx context.Context, pluginPath string, netconf []byte, args invoke.CNIArgs, exec invoke.Exec) error {
		return nil
	}
)

func TestArgsFromEnv(t *testing.T) {
	testCases := []struct {
		name        string
		cniArgs     *cnipb.CniCmdArgs
		exceptedRes *invoke.Args
	}{
		{
			name: "Test argsFromEnv",
			cniArgs: &cnipb.CniCmdArgs{
				ContainerId: "container-id",
				Netns:       "net-ns",
				Ifname:      "if-name",
				Path:        "path",
			},
			exceptedRes: &invoke.Args{
				ContainerID: "container-id",
				NetNS:       "net-ns",
				IfName:      "if-name",
				Path:        "path",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, *tt.exceptedRes, *argsFromEnv(tt.cniArgs))
		})
	}
}

func TestGetIPFromCache(t *testing.T) {
	testCases := []struct {
		name        string
		resultKey   string
		result      *IPAMResult
		exceptedRes *IPAMResult
	}{
		{
			name:      "Test ipamResults is not empty",
			resultKey: "key",
			result: &IPAMResult{
				Result: current.Result{
					CNIVersion: testCNIVersion,
				},
				VLANID: 0,
			},
			exceptedRes: &IPAMResult{
				Result: current.Result{
					CNIVersion: testCNIVersion,
				},
				VLANID: 0,
			},
		},
		{
			name:      "Test ipamResults is empty",
			resultKey: "emptyKey",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.result != nil {
				ipamResults.Store(tt.resultKey, tt.result)
			}

			res, _ := GetIPFromCache(tt.resultKey)
			assert.Equal(t, tt.exceptedRes, res)
		})
	}
}

func TestGetAntreaIPAMDriver(t *testing.T) {
	testCases := []struct {
		name        string
		antreaIPAM  *AntreaIPAM
		expectedRes *AntreaIPAM
	}{
		{
			name: "Get the AntreaIPAM",
			antreaIPAM: &AntreaIPAM{
				controller: &AntreaIPAMController{},
			},
			expectedRes: &AntreaIPAM{
				controller: &AntreaIPAMController{},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.antreaIPAM != nil {
				ipamDrivers[AntreaIPAMType] = []IPAMDriver{tt.antreaIPAM}
			}
			assert.Equal(t, *tt.expectedRes.controller, *getAntreaIPAMDriver().controller)
		})
	}
}

func TestExecIPAMAdd(t *testing.T) {
	defaultExec = &mockExec{}
	defer func() {
		defaultExec = &invoke.DefaultExec{
			RawExec: &invoke.RawExec{Stderr: os.Stderr},
		}
	}()
	testCases := []struct {
		name        string
		cniArgs     *cnipb.CniCmdArgs
		k8sArgs     *argtypes.K8sArgs
		ipamType    string
		resultKey   string
		exceptedRes error
	}{
		{
			name:        "No suitable IPAM driver found",
			cniArgs:     &cnipb.CniCmdArgs{},
			k8sArgs:     &argtypes.K8sArgs{},
			ipamType:    "",
			resultKey:   "",
			exceptedRes: fmt.Errorf("No suitable IPAM driver found"),
		},
		{
			name: "Exec successfully",
			cniArgs: &cnipb.CniCmdArgs{
				ContainerId:          "container-id",
				Netns:                "net-ns",
				Ifname:               "if-name",
				Path:                 "path",
				NetworkConfiguration: testNetworkConfig,
			},
			k8sArgs:     &argtypes.K8sArgs{},
			ipamType:    ipamHostLocal,
			resultKey:   "",
			exceptedRes: nil,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			RegisterIPAMDriver(ipamHostLocal, &IPAMDelegator{pluginType: ipamHostLocal})
			execPluginWithResultFunc = fakeExecWithResult
			_, err := ExecIPAMAdd(tt.cniArgs, tt.k8sArgs, tt.ipamType, tt.resultKey)
			assert.Equal(t, tt.exceptedRes, err)
		})
	}
}

func TestExecIPAMDelete(t *testing.T) {
	defaultExec = &mockExec{}
	defer func() {
		defaultExec = &invoke.DefaultExec{
			RawExec: &invoke.RawExec{Stderr: os.Stderr},
		}
	}()
	testCases := []struct {
		name        string
		cniArgs     *cnipb.CniCmdArgs
		k8sArgs     *argtypes.K8sArgs
		ipamType    string
		resultKey   string
		exceptedRes error
	}{
		{
			name:        "No suitable IPAM driver found",
			cniArgs:     &cnipb.CniCmdArgs{},
			k8sArgs:     &argtypes.K8sArgs{},
			ipamType:    "",
			resultKey:   "",
			exceptedRes: fmt.Errorf("No suitable IPAM driver found"),
		},
		{
			name: "Exec successfully",
			cniArgs: &cnipb.CniCmdArgs{
				ContainerId:          "container-id",
				Netns:                "net-ns",
				Ifname:               "if-name",
				Path:                 "path",
				NetworkConfiguration: testNetworkConfig,
			},
			k8sArgs:     &argtypes.K8sArgs{},
			ipamType:    ipamHostLocal,
			resultKey:   "",
			exceptedRes: nil,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			RegisterIPAMDriver(ipamHostLocal, &IPAMDelegator{pluginType: ipamHostLocal})
			execPluginNoResultFunc = fakeExecNoResult
			err := ExecIPAMDelete(tt.cniArgs, tt.k8sArgs, tt.ipamType, tt.resultKey)
			assert.Equal(t, tt.exceptedRes, err)
		})
	}
}

func TestExecIPAMCheck(t *testing.T) {
	defaultExec = &mockExec{}
	defer func() {
		defaultExec = &invoke.DefaultExec{
			RawExec: &invoke.RawExec{Stderr: os.Stderr},
		}
	}()
	testCases := []struct {
		name        string
		cniArgs     *cnipb.CniCmdArgs
		k8sArgs     *argtypes.K8sArgs
		ipamType    string
		exceptedRes error
	}{
		{
			name:        "No suitable IPAM driver found",
			cniArgs:     &cnipb.CniCmdArgs{},
			k8sArgs:     &argtypes.K8sArgs{},
			ipamType:    "",
			exceptedRes: fmt.Errorf("No suitable IPAM driver found"),
		},
		{
			name: "Exec successfully",
			cniArgs: &cnipb.CniCmdArgs{
				ContainerId:          "container-id",
				Netns:                "net-ns",
				Ifname:               "if-name",
				Path:                 "path",
				NetworkConfiguration: testNetworkConfig,
			},
			k8sArgs:     &argtypes.K8sArgs{},
			ipamType:    ipamHostLocal,
			exceptedRes: nil,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			RegisterIPAMDriver(ipamHostLocal, &IPAMDelegator{pluginType: ipamHostLocal})
			execPluginNoResultFunc = fakeExecNoResult
			err := ExecIPAMCheck(tt.cniArgs, tt.k8sArgs, tt.ipamType)
			assert.Equal(t, tt.exceptedRes, err)
		})
	}
}

func TestIsIPAMTypeValid(t *testing.T) {
	testCases := []struct {
		name         string
		existingType string
		ipamType     string
		exceptedRes  bool
	}{
		{
			"Test valid ipam type",
			"existingType",
			"existingType",
			true,
		},
		{
			"Test invalid ipam type",
			"",
			"invalidType",
			false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.existingType != "" {
				ipamDrivers[tt.existingType] = []IPAMDriver{}
			}
			assert.Equal(t, tt.exceptedRes, IsIPAMTypeValid(tt.ipamType))
		})
	}
}
