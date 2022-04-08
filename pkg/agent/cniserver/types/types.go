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

package types

import (
	cnitypes "github.com/containernetworking/cni/pkg/types"
)

type K8sArgs struct {
	cnitypes.CommonArgs
	K8S_POD_NAME               cnitypes.UnmarshallableString
	K8S_POD_NAMESPACE          cnitypes.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID cnitypes.UnmarshallableString
}

type RuntimeDNS struct {
	Nameservers []string `json:"servers,omitempty"`
	Search      []string `json:"searches,omitempty"`
}

type RuntimeConfig struct {
	DNS RuntimeDNS `json:"dns"`
}

type Range struct {
	Subnet  string `json:"subnet"`
	Gateway string `json:"gateway,omitempty"`
}

type RangeSet []Range

type IPAMConfig struct {
	Type string `json:"type"`
	// IP ranges for NodeIPAM. Can include both v4 and v6 ranges.
	Ranges []RangeSet        `json:"ranges,omitempty"`
	Routes []*cnitypes.Route `json:"routes,omitempty"`
	DNS    cnitypes.DNS      `json:"dns,omitempty"`
	// Antrea IPPool names for Antrea IPAM.
	IPPools []string `json:"ippools,omitempty"`
	// Other NodeIPAM config parameters (ResolvConf, IPArgs) are not supported.
}

type NetworkConfig struct {
	CNIVersion string       `json:"cniVersion"`
	Name       string       `json:"name"`
	Type       string       `json:"type"`
	DeviceID   string       `json:"deviceID,omitempty"` // PCI address of a VF
	MTU        int          `json:"mtu,omitempty"`
	DNS        cnitypes.DNS `json:"dns,omitempty"`
	IPAM       *IPAMConfig  `json:"ipam,omitempty"`
	// Options to be passed in by the runtime.
	RuntimeConfig RuntimeConfig          `json:"runtimeConfig,omitempty"`
	RawPrevResult map[string]interface{} `json:"prevResult,omitempty"`
	PrevResult    cnitypes.Result        `json:"-"`
}
