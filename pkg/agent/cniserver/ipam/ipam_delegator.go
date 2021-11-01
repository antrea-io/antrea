// Copyright 2019 Antrea Authors
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

	argtypes "antrea.io/antrea/pkg/agent/cniserver/types"
)

const (
	ipamHostLocal  = "host-local"
	defaultCNIPath = "/opt/cni/bin"
)

type IPAMDelegator struct {
	pluginType string
}

func (d *IPAMDelegator) Add(args *invoke.Args, k8sArgs *argtypes.K8sArgs, networkConfig []byte) (bool, *current.Result, error) {
	var success = false
	defer func() {
		if !success {
			// Rollback to delete assigned network configuration for failed to execute Add operation
			args.Command = "DEL"
			if err := delegateNoResult(d.pluginType, networkConfig, args); err != nil {
				klog.Errorf("Failed to roll back to delete configuration %s, %v", string(networkConfig), err)
			}
		}
	}()
	args.Command = "ADD"
	r, err := delegateWithResult(d.pluginType, networkConfig, args)
	if err != nil {
		return true, nil, err
	}

	ipamResult, err := current.NewResultFromResult(r)
	if err != nil {
		return true, nil, err
	}
	success = true
	// IPAM Delegator always owns the request
	return true, ipamResult, nil
}

func (d *IPAMDelegator) Del(args *invoke.Args, k8sArgs *argtypes.K8sArgs, networkConfig []byte) (bool, error) {
	args.Command = "DEL"
	if err := delegateNoResult(d.pluginType, networkConfig, args); err != nil {
		return true, err
	}

	// IPAM Delegator always owns the request
	return true, nil
}

func (d *IPAMDelegator) Check(args *invoke.Args, k8sArgs *argtypes.K8sArgs, networkConfig []byte) (bool, error) {
	args.Command = "CHECK"
	if err := delegateNoResult(d.pluginType, networkConfig, args); err != nil {
		return true, err
	}
	return true, nil
}

var defaultExec = &invoke.DefaultExec{
	RawExec: &invoke.RawExec{Stderr: os.Stderr},
}

func delegateCommon(delegatePlugin string, exec invoke.Exec, cniPath string) (string, invoke.Exec, error) {
	// The CNI searching paths passed from kubelet.
	configuredPaths := filepath.SplitList(cniPath)
	paths := make([]string, len(configuredPaths)+1)
	// When Antrea agent runs as a Pod, the IPAM plugin is always installed in
	// defaultCNIPath, but kubelet can be configured to use different paths to
	// search for CNI plugins. So here we always add defaultCNIPath to the CNI
	// plugin searching paths to make sure the IPAM plugin installed in the agent
	// Pod can be found.
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

func init() {
	if err := RegisterIPAMDriver(ipamHostLocal, &IPAMDelegator{pluginType: ipamHostLocal}); err != nil {
		klog.Errorf("Failed to register IPAM plugin on type %s", ipamHostLocal)
	}
}
