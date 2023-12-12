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
	current "github.com/containernetworking/cni/pkg/types/100"

	"antrea.io/antrea/pkg/agent/cniserver/types"
	cnipb "antrea.io/antrea/pkg/apis/cni/v1beta1"
)

// Ordered list of IPAM drivers.
// The first driver in list that claims to own this request will proceed to
// handle allocation/release. This model is useful for antrea IPAM feature that
// should trigger Antrea IPAM only if a corresponding annotation is specified
// for Pod/Namespace; otherwise IPAM should be handled by the host-local plugin.
var ipamDrivers map[string][]IPAMDriver

// A cache of IPAM results.
// TODO: We should get rid of using global variables to store status, which makes testing complicated.
var ipamResults = sync.Map{}

type IPAMResult struct {
	current.Result
	VLANID uint16
}

type IPAMDriver interface {
	Add(args *invoke.Args, k8sArgs *types.K8sArgs, networkConfig []byte) (bool, *IPAMResult, error)
	Del(args *invoke.Args, k8sArgs *types.K8sArgs, networkConfig []byte) (bool, error)
	Check(args *invoke.Args, k8sArgs *types.K8sArgs, networkConfig []byte) (bool, error)
}

func RegisterIPAMDriver(ipamType string, ipamDriver IPAMDriver) {
	if ipamDrivers == nil {
		ipamDrivers = make(map[string][]IPAMDriver)
	}
	ipamDrivers[ipamType] = append(ipamDrivers[ipamType], ipamDriver)
}

func ResetIPAMDrivers(ipamType string) {
	if ipamDrivers != nil {
		delete(ipamDrivers, ipamType)
	}
}

func ResetIPAMResults() {
	ipamResults = sync.Map{}
}

func argsFromEnv(cniArgs *cnipb.CniCmdArgs) *invoke.Args {
	return &invoke.Args{
		ContainerID: cniArgs.ContainerId,
		NetNS:       cniArgs.Netns,
		IfName:      cniArgs.Ifname,
		Path:        cniArgs.Path,
	}
}

func ExecIPAMAdd(cniArgs *cnipb.CniCmdArgs, k8sArgs *types.K8sArgs, ipamType string, resultKey string) (*IPAMResult, error) {
	// Return the cached IPAM result for the same Pod. This cache helps to ensure CNI ADD is
	// idempotent. There are two usages of CNI ADD on Windows: 1) add container network
	// configuration, and 2) query Pod network status. kubelet on Windows excutess CNI ADD
	// to query Pod status periodically before the sandbox container is ready. The cache here
	// is to ensure only one IP address is allocated to one Pod.
	// TODO: A risk of IP re-allocation exists if agent restarts before kubelet queries Pod
	// status and after the container network configuration is added.
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

func ExecIPAMDelete(cniArgs *cnipb.CniCmdArgs, k8sArgs *types.K8sArgs, ipamType string, resultKey string) error {
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

func ExecIPAMCheck(cniArgs *cnipb.CniCmdArgs, k8sArgs *types.K8sArgs, ipamType string) error {
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

// Antrea IPAM for secondary network.
func SecondaryNetworkAdd(cniArgs *cnipb.CniCmdArgs, k8sArgs *types.K8sArgs, networkConfig *types.NetworkConfig) (*current.Result, error) {
	args := argsFromEnv(cniArgs)
	ipamResult, err := getAntreaIPAMDriver().secondaryNetworkAdd(args, k8sArgs, networkConfig)
	if err != nil {
		return nil, err
	}
	return &ipamResult.Result, nil

}

func SecondaryNetworkDel(cniArgs *cnipb.CniCmdArgs, k8sArgs *types.K8sArgs, networkConfig *types.NetworkConfig) error {
	args := argsFromEnv(cniArgs)
	return getAntreaIPAMDriver().secondaryNetworkDel(args, k8sArgs, networkConfig)

}

func SecondaryNetworkCheck(cniArgs *cnipb.CniCmdArgs, k8sArgs *types.K8sArgs, networkConfig *types.NetworkConfig) error {
	args := argsFromEnv(cniArgs)
	return getAntreaIPAMDriver().secondaryNetworkCheck(args, k8sArgs, networkConfig)

}

func getAntreaIPAMDriver() *AntreaIPAM {
	drivers, ok := ipamDrivers[AntreaIPAMType]
	if !ok {
		return nil
	}
	return drivers[0].(*AntreaIPAM)
}

// The following functions are only for testing.
func ResetIPAMDriver(ipamType string, driver IPAMDriver) {
	ipamDrivers[ipamType] = []IPAMDriver{driver}
}

func AddIPAMResult(key string, result *IPAMResult) {
	ipamResults.Store(key, result)
}

// GetSecondaryNetworkAllocator returns the Antrea IPAM driver as the
// SecondaryNetworkIPAMAllocator implementation.
func GetSecondaryNetworkAllocator() *AntreaIPAM {
	return getAntreaIPAMDriver()
}
