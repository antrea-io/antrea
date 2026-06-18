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

type Bridge struct {
	UUID                string            `ovsdb:"_uuid"`
	Name                string            `ovsdb:"name"`
	Protocols           []string          `ovsdb:"protocols"`
	DatapathType        string            `ovsdb:"datapath_type"`
	DatapathID          *string           `ovsdb:"datapath_id"`
	McastSnoopingEnable bool              `ovsdb:"mcast_snooping_enable"`
	OtherConfig         map[string]string `ovsdb:"other_config"`
	ExternalIDs         map[string]string `ovsdb:"external_ids"`
	Ports               []string          `ovsdb:"ports"`
}

type Port struct {
	UUID        string            `ovsdb:"_uuid"`
	Name        string            `ovsdb:"name"`
	Interfaces  []string          `ovsdb:"interfaces"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Tag         *int              `ovsdb:"tag"`
	Status      map[string]string `ovsdb:"status"`
	Statistics  map[string]int    `ovsdb:"statistics"`
	MAC         *string           `ovsdb:"mac"`
}

type OpenvSwitch struct {
	UUID        string            `ovsdb:"_uuid"`
	OvsVersion  *string           `ovsdb:"ovs_version"`
	OtherConfig map[string]string `ovsdb:"other_config"`
	Bridges     []string          `ovsdb:"bridges"`
}

type Interface struct {
	UUID          string            `ovsdb:"_uuid"`
	Name          string            `ovsdb:"name"`
	Type          string            `ovsdb:"type"`
	OFPortRequest *int              `ovsdb:"ofport_request"`
	Options       map[string]string `ovsdb:"options"`
	MAC           *string           `ovsdb:"mac"`
	OFPort        *int              `ovsdb:"ofport"`
	MTURequest    *int              `ovsdb:"mtu_request"`
	AdminState    *string           `ovsdb:"admin_state"`
	LinkState     *string           `ovsdb:"link_state"`
	LinkResets    *int              `ovsdb:"link_resets"`
	LinkSpeed     *int              `ovsdb:"link_speed"`
	MACInUse      *string           `ovsdb:"mac_in_use"`
	MTU           *int              `ovsdb:"mtu"`
	IfIndex       *int              `ovsdb:"ifindex"`
	Status        map[string]string `ovsdb:"status"`
	Statistics    map[string]int    `ovsdb:"statistics"`
	Error         *string           `ovsdb:"error"`
	Duplex        *string           `ovsdb:"duplex"`
}
