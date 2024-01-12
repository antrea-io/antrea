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
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/servicecidr"
	"antrea.io/antrea/pkg/agent/util"
	antreasyscall "antrea.io/antrea/pkg/agent/util/syscall"
	"antrea.io/antrea/pkg/agent/util/winfirewall"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	iputil "antrea.io/antrea/pkg/util/ip"
)

const (
	inboundFirewallRuleName  = "Antrea: accept packets from local Pods"
	outboundFirewallRuleName = "Antrea: accept packets to local Pods"

	antreaNatNodePort = "antrea-nat-nodeport"

	serviceIPv4CIDRKey = "serviceIPv4CIDRKey"
)

var (
	antreaNat                  = util.AntreaNatName
	virtualServiceIPv4Net      = util.NewIPNet(config.VirtualServiceIPv4)
	virtualNodePortDNATIPv4Net = util.NewIPNet(config.VirtualNodePortDNATIPv4)
	PodCIDRIPv4                *net.IPNet
)

type Client struct {
	nodeConfig    *config.NodeConfig
	networkConfig *config.NetworkConfig
	// nodeRoutes caches ip routes to remote Pods. It's a map of podCIDR to routes.
	nodeRoutes *sync.Map
	// serviceRoutes caches ip routes about Services.
	serviceRoutes *sync.Map
	// netNatStaticMappings caches Windows NetNat for NodePort.
	netNatStaticMappings *sync.Map
	fwClient             *winfirewall.Client
	bridgeInfIndex       int
	noSNAT               bool
	proxyAll             bool
	// The latest calculated Service CIDRs can be got from serviceCIDRProvider.
	serviceCIDRProvider servicecidr.Interface
}

// NewClient returns a route client.
func NewClient(networkConfig *config.NetworkConfig,
	noSNAT bool,
	proxyAll bool,
	connectUplinkToBridge bool,
	nodeNetworkPolicyEnabled bool,
	multicastEnabled bool,
	serviceCIDRProvider servicecidr.Interface) (*Client, error) {
	return &Client{
		networkConfig:        networkConfig,
		nodeRoutes:           &sync.Map{},
		serviceRoutes:        &sync.Map{},
		netNatStaticMappings: &sync.Map{},
		fwClient:             winfirewall.NewClient(),
		noSNAT:               noSNAT,
		proxyAll:             proxyAll,
		serviceCIDRProvider:  serviceCIDRProvider,
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
		// For NodePort Service, a NetNatStaticMapping is needed.
		if err := util.NewNetNat(antreaNatNodePort, virtualNodePortDNATIPv4Net); err != nil {
			return err
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
		if err := c.addVirtualNodePortDNATIPRoute(false); err != nil {
			return err
		}
	}
	if c.networkConfig.IPv6Enabled {
		return fmt.Errorf("IPv6 is not supported on Windows")
	}
	c.serviceCIDRProvider.AddEventHandler(func(serviceCIDRs []*net.IPNet) {
		for _, serviceCIDR := range serviceCIDRs {
			if err := c.addServiceCIDRRoute(serviceCIDR); err != nil {
				klog.ErrorS(err, "Failed to install route for Service CIDR", "ServiceCIDR", serviceCIDR)
			}
		}
	})
	return nil
}

// Reconcile removes the orphaned routes and related configuration based on the desired podCIDRs and Service IPs. Only
// the route entries on the host gateway interface are stored in the cache.
func (c *Client) Reconcile(podCIDRs []string) error {
	desiredPodCIDRs := sets.New[string](podCIDRs...)
	routes, err := c.listIPRoutesOnGW()
	if err != nil {
		return err
	}
	for i := range routes {
		// Don't remove the route entry that does not use global unicast IP address as destination, like multicast, IPv6
		// link local or loopback.
		if !routes[i].DestinationSubnet.IP.IsGlobalUnicast() {
			continue
		}
		// When configuring an IP address to an interface on Windows, three route entries will be automatically added.
		// For example, if the IP address is 10.10.0.1/24, the following three routes will be created:
		// Network Destination   Netmask          Gateway  Interface  Metric
		// 10.10.0.1             255.255.255.255  On-link  10.10.0.1  281
		// 10.10.0.0             255.255.255.0    On-link  10.10.0.1  281
		// 10.10.0.255           255.255.255.255  On-link  10.10.0.1  281
		// The host (10.10.0.1) and broadcast (10.10.0.255) routes should be ignored since they are not supposed to be
		// managed by Antrea. We can ignore them by comparing them to the calculated broadcast IP. Don't remove them since
		// removing those route entries might introduce host networking issues.
		if routes[i].DestinationSubnet.IP.Equal(iputil.GetLocalBroadcastIP(routes[i].DestinationSubnet)) {
			continue
		}
		// Don't remove the route entry that uses local Pod CIDR as destination.
		if iputil.IPNetEqual(routes[i].DestinationSubnet, c.nodeConfig.PodIPv4CIDR) {
			continue
		}
		// Don't remove the route entry whose destination is included in the desired Pod CIDRs.
		if desiredPodCIDRs.Has(routes[i].DestinationSubnet.String()) {
			continue
		}
		// Don't remove the route entries which are added by AntreaProxy when proxyAll is enabled.
		if c.proxyAll && c.isServiceRoute(&routes[i]) {
			continue
		}
		err = util.RemoveNetRoute(&routes[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// AddRoutes adds routes to the provided podCIDR.
// It overrides the routes if they already exist, without error.
func (c *Client) AddRoutes(podCIDR *net.IPNet, nodeName string, peerNodeIP, peerGwIP net.IP) error {
	obj, found := c.nodeRoutes.Load(podCIDR.String())
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

	c.nodeRoutes.Store(podCIDR.String(), route)
	klog.V(2).Infof("Added route with destination %s via %s on host gateway on %s (%s)", podCIDR.String(), peerGwIP.String(), nodeName, peerNodeIP)
	return nil
}

// DeleteRoutes deletes routes to the provided podCIDR.
// It does nothing if the routes don't exist, without error.
func (c *Client) DeleteRoutes(podCIDR *net.IPNet) error {
	obj, found := c.nodeRoutes.Load(podCIDR.String())
	if !found {
		klog.V(2).Infof("Route with destination %s not exists", podCIDR.String())
		return nil
	}

	rt := obj.(*util.Route)
	if err := util.RemoveNetRoute(rt); err != nil {
		return err
	}
	c.nodeRoutes.Delete(podCIDR.String())
	klog.V(2).Infof("Deleted route with destination %s from host gateway", podCIDR.String())
	return nil
}

// addVirtualServiceIPRoute is used to add a route for a virtual IP. The virtual IP is used as the next hop IP for ClusterIP,
// NodePort and LoadBalancer routes. Without this route, routes for Service cannot be installed on Windows host.
func (c *Client) addVirtualServiceIPRoute(isIPv6 bool) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	svcIP := config.VirtualServiceIPv4

	neigh := generateNeigh(svcIP, linkIndex)
	if err := util.ReplaceNetNeighbor(neigh); err != nil {
		return fmt.Errorf("failed to add new IP neighbour for %s: %w", svcIP, err)
	}
	klog.InfoS("Added virtual Service IP neighbor", "neighbor", neigh)

	route := generateRoute(virtualServiceIPv4Net, net.IPv4zero, linkIndex, util.MetricHigh)
	if err := util.ReplaceNetRoute(route); err != nil {
		return fmt.Errorf("failed to install route for virtual Service IP %s: %w", svcIP.String(), err)
	}
	c.serviceRoutes.Store(svcIP.String(), route)
	klog.InfoS("Added virtual Service IP route", "route", route)

	return nil
}

func (c *Client) addServiceCIDRRoute(serviceCIDR *net.IPNet) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	gw := config.VirtualServiceIPv4
	metric := util.MetricHigh

	oldServiceCIDRRoute, serviceCIDRRouteExists := c.serviceRoutes.Load(serviceIPv4CIDRKey)
	// Generate a route with the new ClusterIP CIDR and install it.
	route := generateRoute(serviceCIDR, gw, linkIndex, metric)
	if err := util.ReplaceNetRoute(route); err != nil {
		return fmt.Errorf("failed to install a new Service CIDR route: %w", err)
	}

	// Store the new ClusterIP CIDR and the new generated route to serviceRoutes. Then the calculated route can be restored
	// when it was deleted since members of serviceRoutes are synchronized periodically.
	c.serviceRoutes.Store(serviceIPv4CIDRKey, route)

	// Collect stale routes.
	var staleRoutes []*util.Route
	// If current destination CIDR is not nil, the route with current destination CIDR should be uninstalled since
	// a new route with a newly calculated destination CIDR has been installed.
	if serviceCIDRRouteExists {
		staleRoutes = append(staleRoutes, oldServiceCIDRRoute.(*util.Route))
	} else {
		routes, err := c.listIPRoutesOnGW()
		if err != nil {
			return fmt.Errorf("error listing ip routes: %w", err)
		}
		for i := range routes {
			if !routes[i].GatewayAddress.Equal(gw) {
				continue
			}
			// It's the latest route we just installed.
			if iputil.IPNetEqual(routes[i].DestinationSubnet, serviceCIDR) {
				continue
			}
			// The route covers the desired route. It was installed when the calculated ServiceCIDR is larger than the current one, which could happen after some Services are deleted.
			if iputil.IPNetContains(routes[i].DestinationSubnet, serviceCIDR) {
				staleRoutes = append(staleRoutes, &routes[i])
			}
			// The desired route covers the route. It was either installed when the calculated ServiceCIDR is smaller than the current one, or a per-IP route generated before v1.12.0.
			if iputil.IPNetContains(serviceCIDR, routes[i].DestinationSubnet) {
				staleRoutes = append(staleRoutes, &routes[i])
			}
		}
	}

	// Remove stale routes.
	for _, rt := range staleRoutes {
		if err := util.RemoveNetRoute(rt); err != nil {
			return fmt.Errorf("failed to delete stale Service CIDR route %s: %w", rt.String(), err)
		} else {
			klog.V(4).InfoS("Deleted stale Service CIDR route successfully", "route", rt)
		}
	}

	return nil
}

// addVirtualNodePortDNATIPRoute is used to add a route which is used to route DNATed NodePort traffic to Antrea gateway.
func (c *Client) addVirtualNodePortDNATIPRoute(isIPv6 bool) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	vIP := config.VirtualNodePortDNATIPv4
	gw := config.VirtualServiceIPv4

	route := generateRoute(virtualNodePortDNATIPv4Net, gw, linkIndex, util.MetricHigh)
	if err := util.ReplaceNetRoute(route); err != nil {
		return fmt.Errorf("failed to install route for NodePort DNAT IP %s: %w", vIP.String(), err)
	}
	c.serviceRoutes.Store(vIP.String(), route)
	klog.InfoS("Added NodePort DNAT IP route", "route", route)

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

// Run periodically syncs netNatStaticMapping and route. It will not return until stopCh is closed.
func (c *Client) Run(stopCh <-chan struct{}) {
	klog.InfoS("Starting netNatStaticMapping and route sync", "interval", SyncInterval)
	wait.Until(c.syncIPInfra, SyncInterval, stopCh)
}

// syncIPInfra is idempotent and can be safely called on every sync operation.
func (c *Client) syncIPInfra() {
	if err := c.syncRoute(); err != nil {
		klog.ErrorS(err, "Failed to sync route")
	}

	if c.proxyAll {
		if err := c.syncNetNatStaticMapping(); err != nil {
			klog.ErrorS(err, "Failed to sync netNatStaticMapping")
		}
	}
	klog.V(3).Info("Successfully synced netNatStaticMapping and route")
}

func (c *Client) syncRoute() error {
	restoreRoute := func(route *util.Route) bool {
		if err := util.ReplaceNetRoute(route); err != nil {
			klog.ErrorS(err, "Failed to sync route", "Route", route)
			return false
		}
		return true
	}
	c.nodeRoutes.Range(func(_, v interface{}) bool {
		route := v.(*util.Route)
		return restoreRoute(route)
	})
	if c.proxyAll {
		c.serviceRoutes.Range(func(_, v interface{}) bool {
			route := v.(*util.Route)
			return restoreRoute(route)
		})
	}
	// The route is installed automatically by the kernel when the address is configured on the interface. If the route
	// is deleted manually by mistake, we restore it.
	gwAutoconfRoute := &util.Route{
		LinkIndex:         c.nodeConfig.GatewayConfig.LinkIndex,
		DestinationSubnet: c.nodeConfig.PodIPv4CIDR,
		GatewayAddress:    net.IPv4zero,
		RouteMetric:       util.MetricDefault,
	}
	restoreRoute(gwAutoconfRoute)

	return nil
}

func (c *Client) syncNetNatStaticMapping() error {
	if err := util.NewNetNat(antreaNatNodePort, virtualNodePortDNATIPv4Net); err != nil {
		return err
	}

	c.netNatStaticMappings.Range(func(_, v interface{}) bool {
		mapping := v.(*util.NetNatStaticMapping)
		if err := util.ReplaceNetNatStaticMapping(mapping); err != nil {
			klog.ErrorS(err, "Failed to add netNatStaticMapping", "netNatStaticMapping", mapping)
			return false
		}
		return true
	})

	return nil
}

func (c *Client) isServiceRoute(route *util.Route) bool {
	// If the gateway IP or the destination IP is the virtual Service IP, then it is a route added by AntreaProxy.
	if route.DestinationSubnet != nil && route.DestinationSubnet.IP.Equal(config.VirtualServiceIPv4) ||
		route.GatewayAddress != nil && route.GatewayAddress.Equal(config.VirtualServiceIPv4) {
		return true
	}
	return false
}

func (c *Client) listIPRoutesOnGW() ([]util.Route, error) {
	family := antreasyscall.AF_INET
	filter := &util.Route{LinkIndex: c.nodeConfig.GatewayConfig.LinkIndex}
	return util.RouteListFiltered(family, filter, util.RT_FILTER_IF)
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
	netNatStaticMapping := &util.NetNatStaticMapping{
		Name:         antreaNatNodePort,
		ExternalIP:   net.ParseIP("0.0.0.0"),
		ExternalPort: port,
		InternalIP:   config.VirtualNodePortDNATIPv4,
		InternalPort: port,
		Protocol:     protocol,
	}
	if err := util.ReplaceNetNatStaticMapping(netNatStaticMapping); err != nil {
		return err
	}
	c.netNatStaticMappings.Store(fmt.Sprintf("%d-%s", port, protocol), netNatStaticMapping)
	klog.V(4).InfoS("Added NetNatStaticMapping for NodePort", "NetNatStaticMapping", netNatStaticMapping)
	return nil
}

func (c *Client) DeleteNodePort(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error {
	key := fmt.Sprintf("%d-%s", port, protocol)
	obj, found := c.netNatStaticMappings.Load(key)
	if !found {
		klog.V(2).InfoS("Didn't find corresponding NetNatStaticMapping for NodePort", "port", port, "protocol", protocol)
		return nil
	}
	netNatStaticMapping := obj.(*util.NetNatStaticMapping)
	if err := util.RemoveNetNatStaticMapping(netNatStaticMapping); err != nil {
		return err
	}
	c.netNatStaticMappings.Delete(key)
	klog.V(4).InfoS("Deleted NetNatStaticMapping for NodePort", "NetNatStaticMapping", netNatStaticMapping)
	return nil
}

// AddExternalIPRoute adds a route entry that forwards traffic destined for the external IP to the Antrea gateway interface.
func (c *Client) AddExternalIPRoute(externalIP net.IP) error {
	externalIPStr := externalIP.String()
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	gw := config.VirtualServiceIPv4
	metric := util.MetricHigh
	svcIPNet := util.NewIPNet(externalIP)

	route := generateRoute(svcIPNet, gw, linkIndex, metric)
	if err := util.ReplaceNetRoute(route); err != nil {
		return fmt.Errorf("failed to install route for external IP %s: %w", externalIPStr, err)
	}
	c.serviceRoutes.Store(externalIPStr, route)
	klog.V(4).InfoS("Added route for external IP", "IP", externalIPStr)
	return nil
}

// DeleteExternalIPRoute deletes the route entry for the external IP.
func (c *Client) DeleteExternalIPRoute(externalIP net.IP) error {
	externalIPStr := externalIP.String()
	route, found := c.serviceRoutes.Load(externalIPStr)
	if !found {
		klog.V(2).InfoS("Didn't find route for external IP", "IP", externalIPStr)
		return nil
	}
	if err := util.RemoveNetRoute(route.(*util.Route)); err != nil {
		return fmt.Errorf("failed to delete route for external IP %s: %w", externalIPStr, err)
	}
	c.serviceRoutes.Delete(externalIPStr)
	klog.V(4).InfoS("Deleted route for external IP", "IP", externalIPStr)
	return nil
}

func (c *Client) AddLocalAntreaFlexibleIPAMPodRule(podAddresses []net.IP) error {
	return nil
}

func (c *Client) DeleteLocalAntreaFlexibleIPAMPodRule(podAddresses []net.IP) error {
	return nil
}

func generateRoute(ipNet *net.IPNet, gw net.IP, linkIndex int, metric int) *util.Route {
	return &util.Route{
		DestinationSubnet: ipNet,
		GatewayAddress:    gw,
		RouteMetric:       metric,
		LinkIndex:         linkIndex,
	}
}

func generateNeigh(ip net.IP, linkIndex int) *util.Neighbor {
	return &util.Neighbor{
		LinkIndex:        linkIndex,
		IPAddress:        ip,
		LinkLayerAddress: openflow.GlobalVirtualMAC,
		State:            "Permanent",
	}
}

func (c *Client) AddRouteForLink(dstCIDR *net.IPNet, linkIndex int) error {
	return errors.New("AddRouteForLink is not implemented on Windows")
}

func (c *Client) DeleteRouteForLink(dstCIDR *net.IPNet, linkIndex int) error {
	return errors.New("DeleteRouteForLink is not implemented on Windows")
}

func (c *Client) ClearConntrackEntryForService(svcIP net.IP, svcPort uint16, endpointIP net.IP, protocol binding.Protocol) error {
	return errors.New("ClearConntrackEntryForService is not implemented on Windows")
}

func (c *Client) RestoreEgressRoutesAndRules(minTableID, maxTableID int) error {
	return errors.New("RestoreEgressRoutesAndRules is not implemented on Windows")
}

func (c *Client) AddEgressRoutes(tableID uint32, dev int, gateway net.IP, prefixLength int) error {
	return errors.New("AddEgressRoutes is not implemented on Windows")
}

func (c *Client) DeleteEgressRoutes(tableID uint32) error {
	return errors.New("DeleteEgressRoutes is not implemented on Windows")
}

func (c *Client) AddEgressRule(tableID uint32, mark uint32) error {
	return errors.New("AddEgressRule is not implemented on Windows")
}

func (c *Client) DeleteEgressRule(tableID uint32, mark uint32) error {
	return errors.New("DeleteEgressRule is not implemented on Windows")
}

func (c *Client) AddOrUpdateNodeNetworkPolicyIPSet(ipsetName string, ipsetEntries sets.Set[string], isIPv6 bool) error {
	return errors.New("AddOrUpdateNodeNetworkPolicyIPSet is not implemented on Windows")
}

func (c *Client) DeleteNodeNetworkPolicyIPSet(ipsetName string, isIPv6 bool) error {
	return errors.New("DeleteNodeNetworkPolicyIPSet is not implemented on Windows")
}

func (c *Client) AddOrUpdateNodeNetworkPolicyIPTables(iptablesChains []string, iptablesRules [][]string, isIPv6 bool) error {
	return errors.New("AddOrUpdateNodeNetworkPolicyIPTables is not implemented on Windows")
}

func (c *Client) DeleteNodeNetworkPolicyIPTables(iptablesChains []string, isIPv6 bool) error {
	return errors.New("DeleteNodeNetworkPolicyIPTables is not implemented on Windows")
}
