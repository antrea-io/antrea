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
	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/types/current"
	"k8s.io/klog/v2"

	argtypes "antrea.io/antrea/pkg/agent/cniserver/types"
)

const (
	ipamAntrea = "antrea-ipam"
)

// Antrea IPAM driver would allocate IP addresses according to object IPAM annotation,
// if present. If annotation is not present, the driver will delegate functionality
// to traditional IPAM driver specified in pluginType
type AntreaIPAM struct {
	ipPoolName string
}

func (d *AntreaIPAM) Add(args *invoke.Args, networkConfig []byte) (*current.Result, error) {
	// TODO - read the pool and allocate IP address
	return nil, nil
}

func (d *AntreaIPAM) Del(args *invoke.Args, networkConfig []byte) error {
	// TODO - read the pool and release IP address
	return nil
}

func (d *AntreaIPAM) Check(args *invoke.Args, networkConfig []byte) error {
	// TODO - read the pool and verify IP address
	return nil
}

func (d *AntreaIPAM) Owns(args *invoke.Args, k8sArgs *argtypes.K8sArgs, networkConfig []byte) bool {
	// TODO - read namespace based on k8sArgs and check ipam annotation
	// If present, set ipPoolName and return true
	return false
}

func init() {
	// Antrea driver must come first
	if err := RegisterIPAMDriver(ipamAntrea, &AntreaIPAM{}); err != nil {
		klog.Errorf("Failed to register IPAM plugin on type %s", ipamAntrea)
	}

	// Host local plugin is fallback driver
	if err := RegisterIPAMDriver(ipamAntrea, &IPAMDelegator{pluginType: ipamHostLocal}); err != nil {
		klog.Errorf("Failed to register IPAM plugin on type %s", ipamHostLocal)
	}
}
