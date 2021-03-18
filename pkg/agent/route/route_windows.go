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
	"errors"
	"net"
	"sync"

	"github.com/rakelkar/gonetsh/netroute"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/agent/util/winfirewall"
)

const (
	inboundFirewallRuleName  = "Antrea: accept packets from local Pods"
	outboundFirewallRuleName = "Antrea: accept packets to local Pods"
)

type Client struct {
	nr          netroute.Interface
	nodeConfig  *config.NodeConfig
	serviceCIDR *net.IPNet
	hostRoutes  *sync.Map
	fwClient    *winfirewall.Client
}

// NewClient returns a route client.
// Todo: remove param serviceCIDR after kube-proxy is replaced by Antrea Proxy completely.
func NewClient(serviceCIDR *net.IPNet, networkConfig *config.NetworkConfig, noSNAT bool) (*Client, error) {
	nr := netroute.New()
	return &Client{
		nr:          nr,
		serviceCIDR: serviceCIDR,
		hostRoutes:  &sync.Map{},
		fwClient:    winfirewall.NewClient(),
	}, nil
}

// Initialize sets nodeConfig on Window.
// Service LoadBalancing is provided by OpenFlow.
func (c *Client) Initialize(nodeConfig *config.NodeConfig, done func()) error {
	c.nodeConfig = nodeConfig
	if err := c.initFwRules(); err != nil {
		return err
	}
	// Enable IP-Forwarding on the host gateway interface, thus the host networking stack can be used to forward the
	// SNAT packet from local Pods. The SNAT packet is leaving the OVS pipeline with the Node's IP as the source IP,
	// the external address as the destination IP, and the antrea-gw0's MAC as the dst MAC. Then it will be forwarded
	// to the host network stack from the host gateway interface, and its dst MAC could be resolved to the right one.
	// At last, the packet is sent back to OVS from the bridge Interface, and the OpenFlow entries will output it to
	// the uplink interface directly.
	if err := util.EnableIPForwarding(nodeConfig.GatewayConfig.Name); err != nil {
		return err
	}
	done()
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

// MigrateRoutesToGw is not supported on Windows.
func (c *Client) MigrateRoutesToGw(linkName string) error {
	return errors.New("MigrateRoutesToGw is unsupported on Windows")
}

// UnMigrateRoutesFromGw is not supported on Windows.
func (c *Client) UnMigrateRoutesFromGw(route *net.IPNet, linkName string) error {
	return errors.New("UnMigrateRoutesFromGw is unsupported on Windows")
}

// Run is not supported on Windows and returns immediately.
func (c *Client) Run(stopCh <-chan struct{}) {
	return
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
		// Only process IPv4 route entries in the loop.
		if rt.DestinationSubnet.IP.To4() == nil {
			continue
		}
		// Retrieve the route entries that use global unicast IP address as the destination. "GetNetRoutesAll" also
		// returns the entries of loopback, broadcast, and multicast, which are added by the system when adding a new IP
		// on the interface. Since removing those route entries might introduce the host networking issues, ignore them
		// from the list.
		if !rt.DestinationSubnet.IP.IsGlobalUnicast() {
			continue
		}
		// Windows adds an active route entry for the local broadcast address automatically when a new IP address
		// is configured on the interface. This route entry should be ignored in the list.
		if rt.DestinationSubnet.IP.Equal(util.GetLocalBroadcastIP(rt.DestinationSubnet)) {
			continue
		}
		// Skip Service corresponding routes. These route entries are added by kube-proxy. If these route entries
		// are removed in Reconcile, the host can't access the Service.
		if c.serviceCIDR.Contains(rt.DestinationSubnet.IP) {
			continue
		}
		rtMap[rt.DestinationSubnet.String()] = &rt
	}
	return rtMap, nil
}

// initFwRules adds Windows Firewall rules to accept the traffic that is sent to or from local Pods.
func (c *Client) initFwRules() error {
	err := c.fwClient.AddRuleAllowIP(inboundFirewallRuleName, winfirewall.FWRuleIn, c.nodeConfig.PodIPv4CIDR)
	if err != nil {
		return err
	}
	err = c.fwClient.AddRuleAllowIP(outboundFirewallRuleName, winfirewall.FWRuleOut, c.nodeConfig.PodIPv4CIDR)
	if err != nil {
		return err
	}
	return nil
}
