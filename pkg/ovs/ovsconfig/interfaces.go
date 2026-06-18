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

import (
	"net"
	"time"
)

type TunnelType string

type OVSDatapathType string

const (
	GeneveTunnel = "geneve"
	VXLANTunnel  = "vxlan"
	GRETunnel    = "gre"
	STTTunnel    = "stt"
	ERSPANTunnel = "erspan"

	OVSDatapathSystem OVSDatapathType = "system"

	OVSOtherConfigDatapathIDKey string = "datapath-id"

	// Valid ofport_request values are in the range 1 to 65,279. For ofport_request value not in
	// this range, OVS ignores it and automatically assigns a port number.
	// Here we use invalid port number "0" to explicitly request automatic port allocation.
	AutoAssignedOFPort = 0
	// Open vSwitch limits the port numbers that it automatically assigns to the range 1 through
	// 32,767, inclusive. Controllers therefore have free use of ports 32,768 and up.
	// When requesting a specific port number with ofport_request, it is better to use one of
	// these "controller ports", to avoid unexpected ofport changes.
	FirstControllerOFPort = 32768
	// 0xfffffffe (OFPP_LOCAL) is a reserved port number in OpenFlow protocol, which is reserved
	// for the Bridge interface.
	// In OVS, it is equivalent to 0xfffe / 65534.
	BridgeOFPort = 0xfffffffe
)

type OVSBridgeClient interface {
	Create() error
	Delete() error
	GetExternalIDs() (map[string]string, error)
	SetExternalIDs(externalIDs map[string]string) error
	GetDatapathID() (string, error)
	WaitForDatapathID(timeout time.Duration) (string, error)
	SetDatapathID(datapathID string) error
	GetInterfaceOptions(name string) (map[string]string, error)
	SetInterfaceOptions(name string, options map[string]string) error
	CreatePort(name, ifDev string, externalIDs map[string]string) (string, error)
	CreateAccessPort(name, ifDev string, externalIDs map[string]string, vlanID uint16) (string, error)
	CreateInternalPort(name string, ofPortRequest int32, mac string, externalIDs map[string]string) (string, error)
	CreateTunnelPortExt(name string, tunnelType TunnelType, ofPortRequest int32, csum bool, localIP string, remoteIP string, remoteName string, psk string, extraOptions map[string]string, externalIDs map[string]string) (string, error)
	CreateUplinkPort(name string, ofPortRequest int32, externalIDs map[string]string) (string, error)
	DeletePort(portUUID string) error
	GetOFPort(ifName string) (int32, error)
	GetPortData(portUUID, ifName string) (*OVSPortData, error)
	GetPortList() ([]OVSPortData, error)
	SetInterfaceMTU(name string, MTU int) error
	GetOVSVersion() (string, error)
	GetOVSOtherConfig() (map[string]string, error)
	UpdateOVSOtherConfig(configs map[string]string) error
	DeleteOVSOtherConfig(keys []string) error
	GetBridgeName() string
	IsHardwareOffloadEnabled() bool
	GetOVSDatapathType() OVSDatapathType
	SetInterfaceType(name, ifType string) error
	SetPortExternalIDs(portName string, externalIDs map[string]string) error
	GetPortExternalIDs(portName string) (map[string]string, error)
	SetInterfaceMAC(name string, mac net.HardwareAddr) error
}
