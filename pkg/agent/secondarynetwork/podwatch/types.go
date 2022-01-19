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

type RouteInfo struct {
	Dst string `json:"dst,omitempty"`
}

type IPAMConfig struct {
	Type       string    `json:"type,omitempty"`
	Subnet     string    `json:"subnet,omitempty"`
	RangeStart string    `json:"rangeStart,omitempty"`
	RangeEnd   string    `json:"rangeEnd,omitempty"`
	Routes     RouteInfo `json:"routes,omitempty"`
	Gateway    string    `json:"gateway,omitempty"`
}

type SecondaryNetworkConfig struct {
	CNIVersion string     `json:"cniVersion,omitempty"`
	Name       string     `json:"name,omitempty"`
	Type       string     `json:"type,omitempty"`
	IPAM       IPAMConfig `json:"ipam,omitempty"`
}

type SecondaryNetworkObject struct {
	NetworkName   string `json:"name,omitempty"`
	InterfaceName string `json:"interface,omitempty"`
	InterfaceType string `json:"type"`
}
