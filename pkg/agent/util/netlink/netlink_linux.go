// Copyright 2022 Antrea Authors
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

package netlink

import (
	"net"

	"github.com/vishvananda/netlink"
)

// Interface is created to allow testing.
type Interface interface {
	RuleAdd(rule *netlink.Rule) error

	RuleDel(rule *netlink.Rule) error

	RuleList(family int) ([]netlink.Rule, error)

	RouteReplace(route *netlink.Route) error

	RouteList(link netlink.Link, family int) ([]netlink.Route, error)

	RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)

	RouteDel(route *netlink.Route) error

	AddrAdd(link netlink.Link, addr *netlink.Addr) error

	AddrList(link netlink.Link, family int) ([]netlink.Addr, error)

	AddrReplace(link netlink.Link, addr *netlink.Addr) error

	AddrDel(link netlink.Link, addr *netlink.Addr) error

	NeighList(linkIndex, family int) ([]netlink.Neigh, error)

	NeighSet(neigh *netlink.Neigh) error

	NeighDel(neigh *netlink.Neigh) error

	LinkByName(name string) (netlink.Link, error)

	LinkByIndex(index int) (netlink.Link, error)

	LinkSetNsFd(link netlink.Link, fd int) error

	LinkSetMTU(link netlink.Link, mtu int) error

	LinkSetDown(link netlink.Link) error

	LinkSetHardwareAddr(link netlink.Link, hwaddr net.HardwareAddr) error

	LinkSetName(link netlink.Link, name string) error

	LinkSetUp(link netlink.Link) error

	ConntrackDeleteFilter(table netlink.ConntrackTableType, family netlink.InetFamily, filter netlink.CustomConntrackFilter) (uint, error)
}
