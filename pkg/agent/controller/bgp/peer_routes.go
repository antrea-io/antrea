// Copyright 2026 Antrea Authors
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

package bgp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"antrea.io/antrea/v2/pkg/agent/bgp"
)

// ErrBGPPeerNotFound is returned by GetBGPPeerRoutes when the effective BGPPolicy has no BGP peer with the given address.
var ErrBGPPeerNotFound = errors.New("BGP peer not found")

// GetBGPPeerRoutes returns the routes that the BGP server sent to the BGP peer with the given address, after export
// policy, or the routes that it received from the peer when received is true. The routes sent to the peer carry the
// metadata of the controller. The received routes carry none.
func (c *Controller) GetBGPPeerRoutes(ctx context.Context, peerAddress string, received bool) (map[bgp.Route]RouteMetadata, error) {
	addr, err := netip.ParseAddr(peerAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid BGP peer address %q: %w", peerAddress, err)
	}

	c.bgpPolicyStateMutex.RLock()
	if c.bgpPolicyState == nil {
		err := c.noBGPServerError()
		c.bgpPolicyStateMutex.RUnlock()
		return nil, err
	}
	// goBGP knows a peer by its address as written in the BGPPolicy, while an IPv6 address can be written in several
	// ways. The addresses are therefore compared as IPs.
	var configuredAddress string
	for _, peerConfig := range c.bgpPolicyState.peerConfigs {
		if configuredAddr, err := netip.ParseAddr(peerConfig.Address); err == nil && configuredAddr.Unmap() == addr.Unmap() {
			configuredAddress = peerConfig.Address
			break
		}
	}
	bgpServer := c.bgpPolicyState.bgpServer
	var routeMetadata map[netip.Prefix]RouteMetadata
	if !received {
		routeMetadata = make(map[netip.Prefix]RouteMetadata, len(c.bgpPolicyState.routes))
		for route, metadata := range c.bgpPolicyState.routes {
			if prefix, err := netip.ParsePrefix(route.Prefix); err == nil {
				routeMetadata[prefix.Masked()] = metadata
			}
		}
	}
	c.bgpPolicyStateMutex.RUnlock()

	if configuredAddress == "" {
		return nil, fmt.Errorf("%w: %s", ErrBGPPeerNotFound, peerAddress)
	}
	routeType := bgp.RouteAdvertised
	if received {
		routeType = bgp.RouteReceived
	}
	routes, err := bgpServer.GetRoutes(ctx, routeType, configuredAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get the routes of BGP peer %s: %w", peerAddress, err)
	}
	peerRoutes := make(map[bgp.Route]RouteMetadata, len(routes))
	for _, route := range routes {
		var metadata RouteMetadata
		// The prefixes are compared as prefixes, as goBGP may write a prefix differently from the object it comes from.
		if prefix, err := netip.ParsePrefix(route.Prefix); err == nil {
			metadata = routeMetadata[prefix.Masked()]
		}
		peerRoutes[route] = metadata
	}
	return peerRoutes, nil
}
