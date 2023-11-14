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
	current "github.com/containernetworking/cni/pkg/types/100"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/cniserver/ipam/hostlocal"
	argtypes "antrea.io/antrea/pkg/agent/cniserver/types"
)

const (
	ipamHostLocal  = "host-local"
	defaultCNIPath = "/opt/cni/bin"
)

type IPAMDelegator struct {
	pluginType string
}

var (
	// Declare these two functions as variable for test
	execPluginWithResultFunc = invoke.ExecPluginWithResult
	execPluginNoResultFunc   = invoke.ExecPluginWithoutResult
)

func (d *IPAMDelegator) Add(args *invoke.Args, k8sArgs *argtypes.K8sArgs, networkConfig []byte) (bool, *IPAMResult, error) {
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
	return true, &IPAMResult{Result: *ipamResult}, nil
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

// GarbageCollectContainerIPs will release IPs allocated by the delegated IPAM
// plugin that are no longer in-use (if there is any). It should be called on an
// agent restart to provide garbage collection for IPs, and to avoid IP leakage
// in case of missed CNI DEL events. Normally, it is not Antrea's responsibility
// to implement this, as the above layers should ensure that there is always one
// successful CNI DEL for every corresponding CNI ADD. However, we include this
// support to increase robustness in case of a container runtime bug.
// Only the host-local plugin is supported.
func GarbageCollectContainerIPs(network string, desiredIPs sets.Set[string]) error {
	return hostlocal.GarbageCollectContainerIPs(network, desiredIPs)
}

var defaultExec invoke.Exec = &invoke.DefaultExec{
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

	return execPluginWithResultFunc(ctx, pluginPath, networkConfig, args, realExec)
}

func delegateNoResult(delegatePlugin string, networkConfig []byte, args *invoke.Args) error {
	ctx := context.TODO()
	pluginPath, realExec, err := delegateCommon(delegatePlugin, defaultExec, args.Path)
	if err != nil {
		return err
	}

	return execPluginNoResultFunc(ctx, pluginPath, networkConfig, args, realExec)
}

func init() {
	RegisterIPAMDriver(ipamHostLocal, &IPAMDelegator{pluginType: ipamHostLocal})
}
