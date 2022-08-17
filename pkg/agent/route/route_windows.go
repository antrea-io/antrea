//go:build windows
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
	"fmt"
	"net"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/util/winfirewall"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	iputil "antrea.io/antrea/pkg/util/ip"
)

const (
	inboundFirewallRuleName  = "Antrea: accept packets from local Pods"
	outboundFirewallRuleName = "Antrea: accept packets to local Pods"

	antreaNatNodePort = "antrea-nat-nodeport"
)

var (
	antreaNat                  = util.AntreaNatName
	virtualServiceIPv4Net      = util.NewIPNet(config.VirtualServiceIPv4)
	virtualNodePortDNATIPv4Net = util.NewIPNet(config.VirtualNodePortDNATIPv4)
	PodCIDRIPv4                *net.IPNet
)

type Client struct {
	nodeConfig     *config.NodeConfig
	networkConfig  *config.NetworkConfig
	hostRoutes     *sync.Map
	fwClient       *winfirewall.Client
	bridgeInfIndex int
	noSNAT         bool
	proxyAll       bool
}

// NewClient returns a route client.
func NewClient(networkConfig *config.NetworkConfig, noSNAT, proxyAll, connectUplinkToBridge, multicastEnabled bool) (*Client, error) {
	return &Client{
		networkConfig: networkConfig,
		hostRoutes:    &sync.Map{},
		fwClient:      winfirewall.NewClient(),
		noSNAT:        noSNAT,
		proxyAll:      proxyAll,
	}, nil
}

// Initialize sets nodeConfig on Window.
// Service LoadBalancing is provided by OpenFlow.
func (c *Client) Initialize(nodeConfig *config.NodeConfig, done func()) error {
	c.nodeConfig = nodeConfig
	PodCIDRIPv4 = nodeConfig.PodIPv4CIDR
	bridgeInf, err := net.InterfaceByName(nodeConfig.OVSBridge)
	if err != nil {
		return fmt.Errorf("failed to find the interface %s: %v", nodeConfig.OVSBridge, err)
	}
	c.bridgeInfIndex = bridgeInf.Index
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
	if !c.noSNAT {
		err := util.NewNetNat(antreaNat, nodeConfig.PodIPv4CIDR)
		if err != nil {
			return err
		}
	}

	if c.proxyAll {
		if err := c.initServiceIPRoutes(); err != nil {
			return fmt.Errorf("failed to initialize Service IP routes: %v", err)
		}
	}
	done()

	return nil
}

func (c *Client) initServiceIPRoutes() error {
	if c.networkConfig.IPv4Enabled {
		if err := c.addVirtualServiceIPRoute(false); err != nil {
			return err
		}
	}
	if c.networkConfig.IPv6Enabled {
		return fmt.Errorf("IPv6 is not supported on Windows")
	}
	return nil
}

// Reconcile removes the orphaned routes and related configuration based on the desired podCIDRs and Service IPs. Only
// the route entries on the host gateway interface are stored in the cache.
func (c *Client) Reconcile(podCIDRs []string, svcIPs map[string]bool) error {
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
		if _, ok := svcIPs[dst]; ok {
			c.hostRoutes.Store(dst, rt)
			continue
		}
		err := util.RemoveNetRoute(rt)
		if err != nil {
			return err
		}
	}
	return nil
}

// AddRoutes adds routes to the provided podCIDR.
// It overrides the routes if they already exist, without error.
func (c *Client) AddRoutes(podCIDR *net.IPNet, nodeName string, peerNodeIP, peerGwIP net.IP) error {
	obj, found := c.hostRoutes.Load(podCIDR.String())
	route := &util.Route{
		DestinationSubnet: podCIDR,
		RouteMetric:       util.MetricDefault,
	}
	if c.networkConfig.NeedsTunnelToPeer(peerNodeIP, c.nodeConfig.NodeTransportIPv4Addr) {
		route.LinkIndex = c.nodeConfig.GatewayConfig.LinkIndex
		route.GatewayAddress = peerGwIP
	} else if c.networkConfig.NeedsDirectRoutingToPeer(peerNodeIP, c.nodeConfig.NodeTransportIPv4Addr) {
		// NoEncap traffic to Node on the same subnet.
		// Set the peerNodeIP as next hop.
		route.LinkIndex = c.bridgeInfIndex
		route.GatewayAddress = peerNodeIP
	}
	// NoEncap traffic to Node on the different subnet needs underlying routing support.
	// Use host default route inside the Node.

	if found {
		existingRoute := obj.(*util.Route)
		if existingRoute.GatewayAddress.Equal(route.GatewayAddress) {
			klog.V(4).Infof("Route with destination %s already exists on %s (%s)", podCIDR.String(), nodeName, peerNodeIP)
			return nil
		}
		// Remove the existing route entry if the gateway address is not as expected.
		if err := util.RemoveNetRoute(existingRoute); err != nil {
			klog.Errorf("Failed to delete existing route entry with destination %s gateway %s on %s (%s)", podCIDR.String(), peerGwIP.String(), nodeName, peerNodeIP)
			return err
		}
	}

	if route.GatewayAddress == nil {
		return nil
	}

	if err := util.ReplaceNetRoute(route); err != nil {
		return err
	}

	c.hostRoutes.Store(podCIDR.String(), route)
	klog.V(2).Infof("Added route with destination %s via %s on host gateway on %s (%s)", podCIDR.String(), peerGwIP.String(), nodeName, peerNodeIP)
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

	rt := obj.(*util.Route)
	if err := util.RemoveNetRoute(rt); err != nil {
		return err
	}
	c.hostRoutes.Delete(podCIDR.String())
	klog.V(2).Infof("Deleted route with destination %s from host gateway", podCIDR.String())
	return nil
}

// addVirtualServiceIPRoute adds routes on a Windows Node for redirecting ClusterIP and NodePort
// Service traffic from host network to OVS via antrea-gw0.
func (c *Client) addVirtualServiceIPRoute(isIPv6 bool) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex

	// This route is for 2 purposes:
	// - If for each ClusterIP Service, a route is installed to direct traffic to antrea-gw0, there will be too many
	//   neighbor cache entries. While with one virtual IP to antrea-gw0 and ClusterIP Services to the virtual IP,
	//   there will be only one neighbor cache entry.
	// - For ClusterIP Service requests from host, reply traffic needs a route entry to route packet to VirtualServiceIPv4
	//   via antrea-gw0. If the NextHop of a route is antrea-gw0, then set it as 0.0.0.0. As a result, on-link/0.0.0.0
	//   is in PersistentStore.
	// - For NodePort Service, it is the same.
	vRoute := &util.Route{
		LinkIndex:         linkIndex,
		DestinationSubnet: virtualServiceIPv4Net,
		GatewayAddress:    net.IPv4zero,
		RouteMetric:       util.MetricHigh,
	}
	if err := util.ReplaceNetRoute(vRoute); err != nil {
		return err
	}
	klog.InfoS("Added virtual Service IP route", "route", vRoute)

	// Service replies will be sent to OVS bridge via openflow.GlobalVirtualMAC. This NetNeighbor is for
	// creating a neighbor cache entry to config.VirtualServiceIPv4.
	vNeighbor := &util.Neighbor{
		LinkIndex:        linkIndex,
		IPAddress:        config.VirtualServiceIPv4,
		LinkLayerAddress: openflow.GlobalVirtualMAC,
		State:            "Permanent",
	}
	if err := util.ReplaceNetNeighbor(vNeighbor); err != nil {
		return err
	}
	klog.InfoS("Added virtual Service IP neighbor", "neighbor", vNeighbor)

	if err := c.addServiceRoute(config.VirtualNodePortDNATIPv4); err != nil {
		return err
	}
	// For NodePort Service, a new NetNat for NetNatStaticMapping is needed.
	err := util.NewNetNat(antreaNatNodePort, virtualNodePortDNATIPv4Net)
	if err != nil {
		return err
	}

	return nil
}

// TODO: Follow the code style in Linux that maintains one Service CIDR.
func (c *Client) addServiceRoute(svcIP net.IP) error {
	obj, found := c.hostRoutes.Load(svcIP.String())
	svcIPNet := util.NewIPNet(svcIP)

	// Route: Service IP -> VirtualServiceIPv4 (169.254.0.253)
	route := &util.Route{
		LinkIndex:         c.nodeConfig.GatewayConfig.LinkIndex,
		DestinationSubnet: svcIPNet,
		GatewayAddress:    config.VirtualServiceIPv4,
		RouteMetric:       util.MetricHigh,
	}
	if found {
		existingRoute := obj.(*util.Route)
		if existingRoute.GatewayAddress.Equal(route.GatewayAddress) && existingRoute.RouteMetric == route.RouteMetric {
			klog.V(2).InfoS("Service route already exists", "DestinationIP", route.DestinationSubnet,
				"Gateway", route.GatewayAddress, "RouteMetric", route.RouteMetric)
			return nil
		}
		// Remove the existing route if gateway or metric is not as expected.
		if err := util.RemoveNetRoute(existingRoute); err != nil {
			return fmt.Errorf("failed to delete existing Service route entry, DestinationIP: %s, Gateway: %s, RouteMetric: %d, err: %v",
				existingRoute.DestinationSubnet, existingRoute.GatewayAddress, existingRoute.RouteMetric, err)
		}
	}

	if err := util.ReplaceNetRoute(route); err != nil {
		return err
	}

	c.hostRoutes.Store(route.DestinationSubnet.String(), route)
	klog.V(2).InfoS("Added Service route", "ServiceIP", route.DestinationSubnet, "GatewayIP", route.GatewayAddress)
	return nil
}

func (c *Client) deleteServiceRoute(svcIP net.IP) error {
	svcIPNet := util.NewIPNet(svcIP)
	obj, found := c.hostRoutes.Load(svcIPNet.String())
	if !found {
		klog.V(2).InfoS("Service route does not exist", "DestinationIP", svcIP)
		return nil
	}

	rt := obj.(*util.Route)
	if err := util.RemoveNetRoute(rt); err != nil {
		return err
	}
	c.hostRoutes.Delete(svcIP.String())
	klog.V(2).InfoS("Deleted Service route from host gateway", "DestinationIP", svcIP)
	return nil
}

func (c *Client) AddClusterIPRoute(svcIP net.IP) error {
	return c.addServiceRoute(svcIP)
}

func (c *Client) DeleteClusterIPRoute(svcIP net.IP) error {
	return c.deleteServiceRoute(svcIP)
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
}

func (c *Client) listRoutes() (map[string]*util.Route, error) {
	routes, err := util.GetNetRoutesAll()
	if err != nil {
		return nil, err
	}
	rtMap := make(map[string]*util.Route)
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
		if !rt.GatewayAddress.Equal(config.VirtualServiceIPv4) && rt.DestinationSubnet.IP.Equal(iputil.GetLocalBroadcastIP(rt.DestinationSubnet)) {
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

func (c *Client) AddSNATRule(snatIP net.IP, mark uint32) error {
	return nil
}

func (c *Client) DeleteSNATRule(mark uint32) error {
	return nil
}

// TODO: nodePortAddresses is not supported currently.
func (c *Client) AddNodePort(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error {
	return util.ReplaceNetNatStaticMapping(antreaNatNodePort, "0.0.0.0", port, config.VirtualNodePortDNATIPv4.String(), port, string(protocol))
}

func (c *Client) DeleteNodePort(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error {
	return util.RemoveNetNatStaticMapping(antreaNatNodePort, "0.0.0.0", port, string(protocol))
}

func (c *Client) AddLoadBalancer(externalIPs []string) error {
	for _, svcIPStr := range externalIPs {
		if err := c.addServiceRoute(net.ParseIP(svcIPStr)); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) DeleteLoadBalancer(externalIPs []string) error {
	for _, svcIPStr := range externalIPs {
		if err := c.deleteServiceRoute(net.ParseIP(svcIPStr)); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) AddLocalAntreaFlexibleIPAMPodRule(podAddresses []net.IP) error {
	return nil
}

func (c *Client) DeleteLocalAntreaFlexibleIPAMPodRule(podAddresses []net.IP) error {
	return nil
}
