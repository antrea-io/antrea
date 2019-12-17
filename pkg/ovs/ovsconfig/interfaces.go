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

package ovsconfig

type TunnelType string

const (
	VXLANTunnel  = "vxlan"
	GeneveTunnel = "geneve"
	GRETunnel    = "gre"
	STTTunnel    = "stt"

	OVSDatapathSystem = "system"
	OVSDatapathNetdev = "netdev"
)

//go:generate mockgen -copyright_file ../../../hack/boilerplate/license_header.raw.txt -destination testing/mock_ovsconfig.go -package=testing github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig OVSBridgeClient

type OVSBridgeClient interface {
	Create() Error
	Delete() Error
	GetExternalIDs() (map[string]string, Error)
	SetExternalIDs(externalIDs map[string]interface{}) Error
	CreatePort(name, ifDev string, externalIDs map[string]interface{}) (string, Error)
	CreateInternalPort(name string, ofPortRequest int32, externalIDs map[string]interface{}) (string, Error)
	CreateTunnelPort(name string, tunnelType TunnelType, ofPortRequest int32) (string, Error)
	CreateTunnelPortExt(name string, tunnelType TunnelType, ofPortRequest int32, remoteIP string, psk string, externalIDs map[string]interface{}) (string, Error)
	DeletePort(portUUID string) Error
	DeletePorts(portUUIDList []string) Error
	GetOFPort(ifName string) (int32, Error)
	GetPortData(portUUID, ifName string) (*OVSPortData, Error)
	GetPortList() ([]OVSPortData, Error)
	SetInterfaceMTU(name string, MTU int) error
	GetOVSVersion() (string, Error)
}
