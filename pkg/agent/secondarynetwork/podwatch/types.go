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

package podwatch

import (
	"antrea.io/antrea/pkg/agent/cniserver/types"
)

type networkType string

const (
	sriovNetworkType networkType = "sriov"
	vlanNetworkType  networkType = "vlan"
)

type SecondaryNetworkConfig struct {
	types.NetworkConfig
	NetworkType networkType `json:"networkType,omitempty"`
	// VLAN ID of the OVS port. Applicable only to the VLAN network type. If a
	// non-zero VLAN is specified, it will override the VLAN in the Antrea
	// IPAM IPPool subnet.
	VLAN int32 `json:"vlan,omitempty"`
}
