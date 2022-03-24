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

	argtypes "antrea.io/antrea/pkg/agent/cniserver/types"
	cnipb "antrea.io/antrea/pkg/apis/cni/v1beta1"
)

// List of ordered IPAM drivers
// The first driver in list that claims to own this request will proceed to
// handle allocation/release
// This model is useful for antrea IPAM feature that should trigger antrea
// IPAM only if corresponding annotation is specified for Pod/Namespace
// Otherwise IPAM should be handled by host-local plugin.
var ipamDrivers map[string][]IPAMDriver

type Range struct {
	Subnet  string `json:"subnet"`
	Gateway string `json:"gateway,omitempty"`
}

type RangeSet []Range

type IPAMConfig struct {
	Type   string     `json:"type,omitempty"`
	Ranges []RangeSet `json:"ranges,omitempty"`
}

type IPAMResult struct {
	current.Result
	VLANID uint16
}

type IPAMDriver interface {
	Add(args *invoke.Args, k8sArgs *argtypes.K8sArgs, networkConfig []byte) (bool, *IPAMResult, error)
	Del(args *invoke.Args, k8sArgs *argtypes.K8sArgs, networkConfig []byte) (bool, error)
	Check(args *invoke.Args, k8sArgs *argtypes.K8sArgs, networkConfig []byte) (bool, error)
}

var ipamResults = sync.Map{}

func RegisterIPAMDriver(ipamType string, ipamDriver IPAMDriver) error {
	if ipamDrivers == nil {
		ipamDrivers = make(map[string][]IPAMDriver)
	}
	ipamDrivers[ipamType] = append(ipamDrivers[ipamType], ipamDriver)
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

func ExecIPAMAdd(cniArgs *cnipb.CniCmdArgs, k8sArgs *argtypes.K8sArgs, ipamType string, resultKey string) (*IPAMResult, error) {
	// Return the cached IPAM result for the same Pod. This cache helps to ensure CNIAdd is idempotent. There are two
	// usages of CNIAdd message on Windows: 1) add container network configuration, and 2) query Pod network status.
	// kubelet on Windows sends CNIAdd messages to query Pod status periodically before the sandbox container is ready.
	// The cache here is to ensure only one IP address is allocated to one Pod.
	// TODO: A risk of IP re-allocation exists if agent restarts before kubelet queries Pod status and after the
	//       container networking configurations is added.
	obj, ok := GetIPFromCache(resultKey)
	if ok {
		return obj, nil
	}

	args := argsFromEnv(cniArgs)

	drivers := ipamDrivers[ipamType]
	for _, driver := range drivers {
		owns, result, err := driver.Add(args, k8sArgs, cniArgs.NetworkConfiguration)
		if !owns {
			// the driver does not own this request - continue to next one
			continue
		}
		if err != nil {
			return nil, err
		}
		ipamResults.Store(resultKey, result)
		return result, nil
	}

	return nil, fmt.Errorf("No suitable IPAM driver found")
}

func ExecIPAMDelete(cniArgs *cnipb.CniCmdArgs, k8sArgs *argtypes.K8sArgs, ipamType string, resultKey string) error {
	args := argsFromEnv(cniArgs)
	drivers := ipamDrivers[ipamType]
	for _, driver := range drivers {
		owns, err := driver.Del(args, k8sArgs, cniArgs.NetworkConfiguration)
		if !owns {
			// the driver does not own this request - continue to next one
			continue
		}
		if err != nil {
			return err
		}
		ipamResults.Delete(resultKey)
		return nil
	}
	return fmt.Errorf("No suitable IPAM driver found")
}

func ExecIPAMCheck(cniArgs *cnipb.CniCmdArgs, k8sArgs *argtypes.K8sArgs, ipamType string) error {
	args := argsFromEnv(cniArgs)
	drivers := ipamDrivers[ipamType]
	for _, driver := range drivers {
		owns, err := driver.Check(args, k8sArgs, cniArgs.NetworkConfiguration)
		if !owns {
			// the driver does not own this request - continue to next one
			continue
		}

		return err

	}
	return fmt.Errorf("No suitable IPAM driver found")
}

func GetIPFromCache(resultKey string) (*IPAMResult, bool) {
	obj, ok := ipamResults.Load(resultKey)
	if ok {
		result := obj.(*IPAMResult)
		return result, ok
	}
	return nil, ok
}

func IsIPAMTypeValid(ipamType string) bool {
	_, valid := ipamDrivers[ipamType]
	return valid
}
