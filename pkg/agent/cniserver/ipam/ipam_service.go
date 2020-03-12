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
	"fmt"
	"sync"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/types/current"
	cnipb "github.com/vmware-tanzu/antrea/pkg/apis/cni/v1beta1"
)

var ipamDrivers map[string]IPAMDriver

type IPAMConfig struct {
	Type    string `json:"type,omitempty"`
	Subnet  string `json:"subnet,omitempty"`
	Gateway string `json:"gateway,omitempty"`
}

type IPAMDriver interface {
	Add(args *invoke.Args, networkConfig []byte) (*current.Result, error)
	Del(args *invoke.Args, networkConfig []byte) error
	Check(args *invoke.Args, networkConfig []byte) error
}

var ipamResults = sync.Map{}

func RegisterIPAMDriver(ipamType string, ipamDriver IPAMDriver) error {
	if ipamDrivers == nil {
		ipamDrivers = make(map[string]IPAMDriver)
	}
	if _, existed := ipamDrivers[ipamType]; existed {
		return fmt.Errorf("Already registered IPAM with type %s", ipamType)
	}
	ipamDrivers[ipamType] = ipamDriver
	return nil
}

func argsFromEnv(cniArgs *cnipb.CniCmdArgs) *invoke.Args {
	return &invoke.Args{
		ContainerID: cniArgs.ContainerId,
		NetNS:       cniArgs.Netns,
		IfName:      cniArgs.Ifname,
		Path:        cniArgs.Path,
	}
}

func ExecIPAMAdd(cniArgs *cnipb.CniCmdArgs, ipamType string, resultKey string) (*current.Result, error) {
	// Return the cached IPAM result for the same Pod. This cache helps to ensure CNIAdd is idempotent. There are two
	// usages of CNIAdd message on Windows: 1) add container network configuration, and 2) query Pod network status.
	// kubelet on Windows sends CNIAdd messages to query Pod status periodically before the sandbox container is ready.
	// The cache here is to ensure only one IP address is allocated to one Pod.
	// TODO: A risk of IP re-allocation exists if agent restarts before kubelet queries Pod status and after the
	//       container networking configurations is added.
	obj, ok := ipamResults.Load(resultKey)
	if ok {
		result := obj.(*current.Result)
		return result, nil
	}

	args := argsFromEnv(cniArgs)
	driver := ipamDrivers[ipamType]
	result, err := driver.Add(args, cniArgs.NetworkConfiguration)
	if err != nil {
		return nil, err
	}
	ipamResults.Store(resultKey, result)
	return result, nil
}

func ExecIPAMDelete(cniArgs *cnipb.CniCmdArgs, ipamType string, resultKey string) error {
	_, ok := ipamResults.Load(resultKey)
	if !ok {
		return nil
	}
	args := argsFromEnv(cniArgs)
	driver := ipamDrivers[ipamType]
	err := driver.Del(args, cniArgs.NetworkConfiguration)
	if err != nil {
		return err
	}
	ipamResults.Delete(resultKey)
	return nil
}

func ExecIPAMCheck(cniArgs *cnipb.CniCmdArgs, ipamType string) error {
	args := argsFromEnv(cniArgs)
	driver := ipamDrivers[ipamType]
	return driver.Check(args, cniArgs.NetworkConfiguration)
}

func IsIPAMTypeValid(ipamType string) bool {
	_, valid := ipamDrivers[ipamType]
	return valid
}
