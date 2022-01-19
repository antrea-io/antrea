// Copyright 2021 Antrea Authors
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
	"os"
	"path/filepath"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"k8s.io/klog/v2"
)

const (
	ipamWhereabouts = "whereabouts"
	defaultCNIPath  = "/opt/cni/bin"
)

func GetIPAMSubnetAddress(netConfig []byte, cmdArgs *invoke.Args) (*current.Result, error) {
	var success = false
	defer func() {
		if !success {
			// Rollback to delete assigned network configuration for failed to execute Add operation
			cmdArgs.Command = "DEL"
			if err := delegateNoResult(ipamWhereabouts, netConfig, cmdArgs); err != nil {
				klog.ErrorS(err, "Failed to network delete configuration ", string(netConfig), err)
			}
		}
	}()

	r, err := delegateWithResult(ipamWhereabouts, netConfig, cmdArgs)
	if err != nil {
		klog.ErrorS(err, "Failed whereabouts: ", err)
		return nil, err
	}

	ipamResult, err := current.NewResultFromResult(r)
	if err != nil {
		return nil, err
	}
	success = true
	return ipamResult, nil
}

func DelIPAMSubnetAddress(netConfig []byte, cmdArgs *invoke.Args) error {
	cmdArgs.Command = "DEL"
	if err := delegateNoResult(ipamWhereabouts, netConfig, cmdArgs); err != nil {
		return err
	}
	return nil
}

var defaultExec = &invoke.DefaultExec{
	RawExec: &invoke.RawExec{Stderr: os.Stderr},
}

func delegateCommon(delegatePlugin string, exec invoke.Exec, cniPath string) (string, invoke.Exec, error) {
	// The CNI searching paths passed from kubelet.
	configuredPaths := filepath.SplitList(cniPath)
	paths := make([]string, len(configuredPaths)+1)
	paths[0] = defaultCNIPath
	copy(paths[1:], configuredPaths)

	pluginPath, err := exec.FindInPath(delegatePlugin, paths)
	if err != nil {
		return "", nil, err
	}

	return pluginPath, exec, nil
}

func delegateWithResult(delegatePlugin string, networkConfig []byte, args *invoke.Args) (types.Result, error) {
	ctx := context.TODO()
	pluginPath, realExec, err := delegateCommon(delegatePlugin, defaultExec, args.Path)
	if err != nil {
		return nil, err
	}

	return invoke.ExecPluginWithResult(ctx, pluginPath, networkConfig, args, realExec)
}

func delegateNoResult(delegatePlugin string, networkConfig []byte, args *invoke.Args) error {
	ctx := context.TODO()
	pluginPath, realExec, err := delegateCommon(delegatePlugin, defaultExec, args.Path)
	if err != nil {
		return err
	}

	return invoke.ExecPluginWithoutResult(ctx, pluginPath, networkConfig, args, realExec)
}
