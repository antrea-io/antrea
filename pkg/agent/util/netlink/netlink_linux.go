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

import "github.com/vishvananda/netlink"

// Interface is created to allow testing.
type Interface interface {
	RouteReplace(route *netlink.Route) error

	RouteList(link netlink.Link, family int) ([]netlink.Route, error)

	RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)

	RouteDel(route *netlink.Route) error

	AddrList(link netlink.Link, family int) ([]netlink.Addr, error)

	AddrReplace(link netlink.Link, addr *netlink.Addr) error

	AddrDel(link netlink.Link, addr *netlink.Addr) error

	NeighList(linkIndex, family int) ([]netlink.Neigh, error)

	NeighSet(neigh *netlink.Neigh) error

	NeighDel(neigh *netlink.Neigh) error

	LinkByName(name string) (netlink.Link, error)
}

type Client struct{}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) RouteReplace(route *netlink.Route) error {
	return netlink.RouteReplace(route)
}

func (c *Client) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	return netlink.RouteList(link, family)
}

func (c *Client) RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return netlink.RouteListFiltered(family, filter, filterMask)
}

func (c *Client) RouteDel(route *netlink.Route) error {
	return netlink.RouteDel(route)
}

func (c *Client) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return netlink.AddrList(link, family)
}

func (c *Client) AddrReplace(link netlink.Link, addr *netlink.Addr) error {
	return netlink.AddrReplace(link, addr)
}

func (c *Client) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	return netlink.AddrDel(link, addr)
}

func (c *Client) NeighList(linkIndex, family int) ([]netlink.Neigh, error) {
	return netlink.NeighList(linkIndex, family)
}

func (c *Client) NeighSet(neigh *netlink.Neigh) error {
	return netlink.NeighSet(neigh)
}

func (c *Client) NeighDel(neigh *netlink.Neigh) error {
	return netlink.NeighDel(neigh)
}

func (c *Client) LinkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}
