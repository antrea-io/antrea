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

// table names in Open_vSwitch schema.
const (
	TableNameOpenVSwitch = "Open_vSwitch"
	TableNameBridge      = "Bridge"
	TableNamePort        = "Port"
	TableNameInterface   = "Interface"
)

// OpenvSwitch defines an object in Open_vSwitch table
type OpenvSwitch struct {
	UUID            string            `ovsdb:"_uuid"`
	Bridges         []string          `ovsdb:"bridges"`
	CurCfg          int               `ovsdb:"cur_cfg"`
	DatapathTypes   []string          `ovsdb:"datapath_types"`
	Datapaths       map[string]string `ovsdb:"datapaths"`
	DbVersion       *string           `ovsdb:"db_version"`
	DpdkInitialized bool              `ovsdb:"dpdk_initialized"`
	DpdkVersion     *string           `ovsdb:"dpdk_version"`
	ExternalIDs     map[string]string `ovsdb:"external_ids"`
	IfaceTypes      []string          `ovsdb:"iface_types"`
	ManagerOptions  []string          `ovsdb:"manager_options"`
	NextCfg         int               `ovsdb:"next_cfg"`
	OtherConfig     map[string]string `ovsdb:"other_config"`
	OVSVersion      *string           `ovsdb:"ovs_version"`
	SSL             *string           `ovsdb:"ssl"`
	Statistics      map[string]string `ovsdb:"statistics"`
	SystemType      *string           `ovsdb:"system_type"`
	SystemVersion   *string           `ovsdb:"system_version"`
}

type (
	BridgeFailMode  = string
	BridgeProtocols = string
)

var (
	BridgeFailModeSecure      BridgeFailMode  = "secure"
	BridgeFailModeStandalone  BridgeFailMode  = "standalone"
	BridgeProtocolsOpenflow10 BridgeProtocols = "OpenFlow10"
	BridgeProtocolsOpenflow11 BridgeProtocols = "OpenFlow11"
	BridgeProtocolsOpenflow12 BridgeProtocols = "OpenFlow12"
	BridgeProtocolsOpenflow13 BridgeProtocols = "OpenFlow13"
	BridgeProtocolsOpenflow14 BridgeProtocols = "OpenFlow14"
	BridgeProtocolsOpenflow15 BridgeProtocols = "OpenFlow15"
)

// Bridge defines an object in Bridge table
type Bridge struct {
	UUID                string            `ovsdb:"_uuid"`
	AutoAttach          *string           `ovsdb:"auto_attach"`
	Controller          []string          `ovsdb:"controller"`
	DatapathID          *string           `ovsdb:"datapath_id"`
	DatapathType        string            `ovsdb:"datapath_type"`
	DatapathVersion     string            `ovsdb:"datapath_version"`
	ExternalIDs         map[string]string `ovsdb:"external_ids"`
	FailMode            *BridgeFailMode   `ovsdb:"fail_mode"`
	FloodVLANs          []int             `ovsdb:"flood_vlans"`
	FlowTables          map[int]string    `ovsdb:"flow_tables"`
	IPFIX               *string           `ovsdb:"ipfix"`
	McastSnoopingEnable bool              `ovsdb:"mcast_snooping_enable"`
	Mirrors             []string          `ovsdb:"mirrors"`
	Name                string            `ovsdb:"name"`
	Netflow             *string           `ovsdb:"netflow"`
	OtherConfig         map[string]string `ovsdb:"other_config"`
	Ports               []string          `ovsdb:"ports"`
	Protocols           []BridgeProtocols `ovsdb:"protocols"`
	RSTPEnable          bool              `ovsdb:"rstp_enable"`
	RSTPStatus          map[string]string `ovsdb:"rstp_status"`
	Sflow               *string           `ovsdb:"sflow"`
	Status              map[string]string `ovsdb:"status"`
	STPEnable           bool              `ovsdb:"stp_enable"`
}
type (
	PortBondMode = string
	PortLACP     = string
	PortVLANMode = string
)

var (
	PortBondModeActiveBackup   PortBondMode = "active-backup"
	PortBondModeBalanceSLB     PortBondMode = "balance-slb"
	PortBondModeBalanceTCP     PortBondMode = "balance-tcp"
	PortLACPActive             PortLACP     = "active"
	PortLACPOff                PortLACP     = "off"
	PortLACPPassive            PortLACP     = "passive"
	PortVLANModeAccess         PortVLANMode = "access"
	PortVLANModeDot1qTunnel    PortVLANMode = "dot1q-tunnel"
	PortVLANModeNativeTagged   PortVLANMode = "native-tagged"
	PortVLANModeNativeUntagged PortVLANMode = "native-untagged"
	PortVLANModeTrunk          PortVLANMode = "trunk"
)

// Port defines an object in Port table
type Port struct {
	UUID            string            `ovsdb:"_uuid"`
	BondActiveSlave *string           `ovsdb:"bond_active_slave"`
	BondDowndelay   int               `ovsdb:"bond_downdelay"`
	BondFakeIface   bool              `ovsdb:"bond_fake_iface"`
	BondMode        *PortBondMode     `ovsdb:"bond_mode"`
	BondUpdelay     int               `ovsdb:"bond_updelay"`
	CVLANs          []int             `ovsdb:"cvlans"`
	ExternalIDs     map[string]string `ovsdb:"external_ids"`
	FakeBridge      bool              `ovsdb:"fake_bridge"`
	Interfaces      []string          `ovsdb:"interfaces"`
	LACP            *PortLACP         `ovsdb:"lacp"`
	MAC             *string           `ovsdb:"mac"`
	Name            string            `ovsdb:"name"`
	OtherConfig     map[string]string `ovsdb:"other_config"`
	Protected       bool              `ovsdb:"protected"`
	QOS             *string           `ovsdb:"qos"`
	RSTPStatistics  map[string]int    `ovsdb:"rstp_statistics"`
	RSTPStatus      map[string]string `ovsdb:"rstp_status"`
	Statistics      map[string]int    `ovsdb:"statistics"`
	Status          map[string]string `ovsdb:"status"`
	Tag             *int              `ovsdb:"tag"`
	Trunks          []int             `ovsdb:"trunks"`
	VLANMode        *PortVLANMode     `ovsdb:"vlan_mode"`
}

type AccessPort struct {
	Port
	Tag uint32 `json:"tag"`
}

type (
	InterfaceAdminState       = string
	InterfaceCFMRemoteOpstate = string
	InterfaceDuplex           = string
	InterfaceLinkState        = string
)

var (
	InterfaceAdminStateDown       InterfaceAdminState       = "down"
	InterfaceAdminStateUp         InterfaceAdminState       = "up"
	InterfaceCFMRemoteOpstateDown InterfaceCFMRemoteOpstate = "down"
	InterfaceCFMRemoteOpstateUp   InterfaceCFMRemoteOpstate = "up"
	InterfaceDuplexFull           InterfaceDuplex           = "full"
	InterfaceDuplexHalf           InterfaceDuplex           = "half"
	InterfaceLinkStateDown        InterfaceLinkState        = "down"
	InterfaceLinkStateUp          InterfaceLinkState        = "up"
)

// Interface defines an object in Interface table
type Interface struct {
	UUID                      string                     `ovsdb:"_uuid"`
	AdminState                *InterfaceAdminState       `ovsdb:"admin_state"`
	BFD                       map[string]string          `ovsdb:"bfd"`
	BFDStatus                 map[string]string          `ovsdb:"bfd_status"`
	CFMFault                  *bool                      `ovsdb:"cfm_fault"`
	CFMFaultStatus            []string                   `ovsdb:"cfm_fault_status"`
	CFMFlapCount              *int                       `ovsdb:"cfm_flap_count"`
	CFMHealth                 *int                       `ovsdb:"cfm_health"`
	CFMMpid                   *int                       `ovsdb:"cfm_mpid"`
	CFMRemoteMpids            []int                      `ovsdb:"cfm_remote_mpids"`
	CFMRemoteOpstate          *InterfaceCFMRemoteOpstate `ovsdb:"cfm_remote_opstate"`
	Duplex                    *InterfaceDuplex           `ovsdb:"duplex"`
	Error                     *string                    `ovsdb:"error"`
	ExternalIDs               map[string]string          `ovsdb:"external_ids"`
	Ifindex                   *int                       `ovsdb:"ifindex"`
	IngressPolicingBurst      int                        `ovsdb:"ingress_policing_burst"`
	IngressPolicingKpktsBurst int                        `ovsdb:"ingress_policing_kpkts_burst"`
	IngressPolicingKpktsRate  int                        `ovsdb:"ingress_policing_kpkts_rate"`
	IngressPolicingRate       int                        `ovsdb:"ingress_policing_rate"`
	LACPCurrent               *bool                      `ovsdb:"lacp_current"`
	LinkResets                *int                       `ovsdb:"link_resets"`
	LinkSpeed                 *int                       `ovsdb:"link_speed"`
	LinkState                 *InterfaceLinkState        `ovsdb:"link_state"`
	LLDP                      map[string]string          `ovsdb:"lldp"`
	MAC                       *string                    `ovsdb:"mac"`
	MACInUse                  *string                    `ovsdb:"mac_in_use"`
	MTU                       *int                       `ovsdb:"mtu"`
	MTURequest                *int                       `ovsdb:"mtu_request"`
	Name                      string                     `ovsdb:"name"`
	Ofport                    *int                       `ovsdb:"ofport"`
	OfportRequest             *int                       `ovsdb:"ofport_request"`
	Options                   map[string]string          `ovsdb:"options"`
	OtherConfig               map[string]string          `ovsdb:"other_config"`
	Statistics                map[string]int             `ovsdb:"statistics"`
	Status                    map[string]string          `ovsdb:"status"`
	Type                      string                     `ovsdb:"type"`
}
