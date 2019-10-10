// Copyright 2019 OKN Authors
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

package ovsconfig

const (
	GENEVE_TUNNEL = "geneve"
	VXLAN_TUNNEL  = "vxlan"
)

type OVSBridgeClient interface {
	Create() Error
	Delete() Error
	CreatePort(name, ifDev string, externalIDs map[string]interface{}) (string, Error)
	CreateGenevePort(name string, ofPortRequest int32, remoteIP string) (string, Error)
	CreateInternalPort(name string, ofPortRequest int32, externalIDs map[string]interface{}) (string, Error)
	CreateVXLANPort(name string, ofPortRequest int32, remoteIP string) (string, Error)
	DeletePort(portUUID string) Error
	DeletePorts(portUUIDList []string) Error
	GetOFPort(ifName string) (int32, Error)
	GetPortData(portUUID, ifName string) (*OVSPortData, Error)
	GetPortList() ([]OVSPortData, Error)
}
