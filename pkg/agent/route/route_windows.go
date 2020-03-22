// +build windows

// Copyright 2020 Antrea Authors
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

package route

import (
	"net"
	"sync"

	"github.com/rakelkar/gonetsh/netroute"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
)

type Client struct {
	nr          netroute.Interface
	nodeConfig  *config.NodeConfig
	serviceCIDR *net.IPNet
	hostRoutes  *sync.Map
}

// NewClient returns a route client.
func NewClient(hostGateway string, serviceCIDR *net.IPNet, encapMode config.TrafficEncapModeType) (*Client, error) {
	nr := netroute.New()
	return &Client{
		nr:          nr,
		serviceCIDR: serviceCIDR,
		hostRoutes:  &sync.Map{},
	}, nil
}

// Initialize sets nodeConfig on Window.
// Service LoadBalancing is provided by OpenFlow.
func (c *Client) Initialize(nodeConfig *config.NodeConfig) error {
	c.nodeConfig = nodeConfig
	return nil
}

// Reconcile removes the orphaned routes and related configuration based on the desired podCIDRs. Only the route
// entries on the host gateway interface are stored in the cache.
func (c *Client) Reconcile(podCIDRs []string) error {
	desiredPodCIDRs := sets.NewString(podCIDRs...)
	routes, err := c.listRoutes()
	if err != nil {
		return err
	}
	for dst, rt := range routes {
		if desiredPodCIDRs.Has(dst) {
			c.hostRoutes.Store(dst, rt)
			continue
		}
		err := c.nr.RemoveNetRoute(rt.LinkIndex, rt.DestinationSubnet, rt.GatewayAddress)
		if err != nil {
			return err
		}
	}
	return nil
}

// AddRoutes adds routes to the provided podCIDR.
// It overrides the routes if they already exist, without error.
func (c *Client) AddRoutes(podCIDR *net.IPNet, peerNodeIP, peerGwIP net.IP) error {
	obj, found := c.hostRoutes.Load(podCIDR.String())
	if found {
		rt := obj.(*netroute.Route)
		if rt.GatewayAddress.Equal(peerGwIP) {
			klog.V(4).Infof("Route with destination %s already exists", podCIDR.String())
			return nil
		}
		// Remove the existing route entry if the gateway address is not as expected.
		if err := c.nr.RemoveNetRoute(rt.LinkIndex, rt.DestinationSubnet, rt.GatewayAddress); err != nil {
			klog.Errorf("Failed to delete existing route entry with destination %s gateway %s", podCIDR.String(), peerGwIP.String())
			return err
		}
	}
	if err := c.nr.NewNetRoute(c.nodeConfig.GatewayConfig.LinkIndex, podCIDR, peerGwIP); err != nil {
		return err
	}
	c.hostRoutes.Store(podCIDR.String(), &netroute.Route{
		LinkIndex:         c.nodeConfig.GatewayConfig.LinkIndex,
		DestinationSubnet: podCIDR,
		GatewayAddress:    peerGwIP,
	})
	klog.V(2).Infof("Added route with destination %s via %s on host gateway", podCIDR.String(), peerGwIP.String())
	return nil
}

// DeleteRoutes deletes routes to the provided podCIDR.
// It does nothing if the routes don't exist, without error.
func (c *Client) DeleteRoutes(podCIDR *net.IPNet) error {
	obj, found := c.hostRoutes.Load(podCIDR.String())
	if !found {
		klog.V(2).Infof("Route with destination %s not exists", podCIDR.String())
		return nil
	}

	rt := obj.(*netroute.Route)
	if err := c.nr.RemoveNetRoute(rt.LinkIndex, rt.DestinationSubnet, rt.GatewayAddress); err != nil {
		return err
	}
	c.hostRoutes.Delete(podCIDR.String())
	klog.V(2).Infof("Deleted route with destination %s from host gateway", podCIDR.String())
	return nil
}

func (c *Client) listRoutes() (map[string]*netroute.Route, error) {
	routes, err := c.nr.GetNetRoutesAll()
	if err != nil {
		return nil, err
	}
	rtMap := make(map[string]*netroute.Route)
	for idx := range routes {
		rt := routes[idx]
		if rt.LinkIndex != c.nodeConfig.GatewayConfig.LinkIndex {
			continue
		}
		if rt.DestinationSubnet.IP.IsLoopback() {
			continue
		}
		rtMap[rt.DestinationSubnet.String()] = &rt
	}
	return rtMap, nil
}
