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
	"bytes"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/util/ipset"
	"antrea.io/antrea/pkg/agent/util/iptables"
	"antrea.io/antrea/pkg/agent/util/sysctl"
	"antrea.io/antrea/pkg/agent/util/tc"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/env"
)

const (
	vxlanPort  = 4789
	genevePort = 6081

	// Antrea managed ipset.
	// antreaPodIPSet contains all Pod CIDRs of this cluster.
	antreaPodIPSet = "ANTREA-POD-IP"
	// antreaPodIP6Set contains all IPv6 Pod CIDRs of this cluster.
	antreaPodIP6Set = "ANTREA-POD-IP6"

	// Antrea managed iptables chains.
	antreaForwardChain     = "ANTREA-FORWARD"
	antreaPreRoutingChain  = "ANTREA-PREROUTING"
	antreaPostRoutingChain = "ANTREA-POSTROUTING"
	antreaOutputChain      = "ANTREA-OUTPUT"
	antreaMangleChain      = "ANTREA-MANGLE"

	clusterIPv4FromNodeRouteKey = "ClusterIPv4FromNodeRoute"
	clusterIPv6FromNodeRouteKey = "ClusterIPv6FromNodeRoute"

	defaultRouteTable = 0

	ipv4AddrLength = 32
	ipv6AddrLength = 128
)

// Client implements Interface.
var _ Interface = &Client{}

var (
	// globalVMAC is used in the IPv6 neighbor configuration to advertise ND solicitation for the IPv6 address of the
	// host gateway interface on other Nodes.
	globalVMAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")
	// IPTablesSyncInterval is exported so that sync interval can be configured for running integration test with
	// smaller values. It is meant to be used internally by Run.
	IPTablesSyncInterval = 60 * time.Second

	serviceGWHairpinIPv4 = net.ParseIP("169.254.169.253")
	serviceGWHairpinIPv6 = net.ParseIP("fc01::aabb:ccdd:eeff")
)

// Client takes care of routing container packets in host network, coordinating ip route, ip rule, iptables and ipset.
type Client struct {
	nodeConfig    *config.NodeConfig
	networkConfig *config.NetworkConfig
	noSNAT        bool
	serviceCIDR   *net.IPNet
	ipt           *iptables.Client
	// nodeRoutes caches ip routes to remote Pods. It's a map of podCIDR to routes.
	nodeRoutes sync.Map
	// nodeNeighbors caches IPv6 Neighbors to remote host gateway
	nodeNeighbors sync.Map
	// markToSNATIP caches marks to SNAT IPs. It's used in Egress feature.
	markToSNATIP sync.Map
	// iptablesInitialized is used to notify when iptables initialization is done.
	iptablesInitialized      chan struct{}
	tcClient                 *tc.Client
	defaultRouteInterfaceMap map[int]int
	proxyFull                bool
}

// NewClient returns a route client.
// TODO: remove param serviceCIDR after kube-proxy is replaced by Antrea Proxy. This param is not used in this file;
// leaving it here is to be compatible with the implementation on Windows.
func NewClient(serviceCIDR *net.IPNet, networkConfig *config.NetworkConfig, noSNAT, proxyFull bool) (*Client, error) {
	defaultRouteMap, err := util.GetDefaultRouteInterfaces()
	if err != nil {
		return nil, err
	}
	return &Client{
		serviceCIDR:              serviceCIDR,
		networkConfig:            networkConfig,
		noSNAT:                   noSNAT,
		tcClient:                 tc.NewTcClient(),
		defaultRouteInterfaceMap: defaultRouteMap,
		proxyFull:                proxyFull,
	}, nil
}

// Initialize initializes all infrastructures required to route container packets in host network.
// It is idempotent and can be safely called on every startup.
func (c *Client) Initialize(nodeConfig *config.NodeConfig, done func()) error {
	c.nodeConfig = nodeConfig
	c.iptablesInitialized = make(chan struct{})

	// Sets up the ipset that will be used in iptables.
	if err := c.syncIPSet(); err != nil {
		return fmt.Errorf("failed to initialize ipset: %v", err)
	}

	// Sets up the iptables infrastructure required to route packets in host network.
	// It's called in a goroutine because xtables lock may not be acquired immediately.
	go func() {
		defer done()
		defer close(c.iptablesInitialized)
		var backoffTime = 2 * time.Second
		for {
			if err := c.syncIPTables(); err != nil {
				klog.Errorf("Failed to initialize iptables: %v - will retry in %v", err, backoffTime)
				time.Sleep(backoffTime)
				continue
			}
			break
		}
		klog.Info("Initialized iptables")
	}()

	// Sets up the IP routes and IP rule required to route packets in host network.
	if err := c.initIPRoutes(); err != nil {
		return fmt.Errorf("failed to initialize ip routes: %v", err)
	}

	return nil
}

// Run waits for iptables initialization, then periodically syncs iptables rules.
// It will not return until stopCh is closed.
func (c *Client) Run(stopCh <-chan struct{}) {
	<-c.iptablesInitialized
	klog.Infof("Starting iptables sync, with sync interval %v", IPTablesSyncInterval)
	wait.Until(c.syncIPInfra, IPTablesSyncInterval, stopCh)
}

// syncIPInfra is idempotent and can be safely called on every sync operation.
func (c *Client) syncIPInfra() {
	// Sync ipset before syncing iptables rules
	if err := c.syncIPSet(); err != nil {
		klog.Errorf("Failed to sync ipset: %v", err)
		return
	}
	if err := c.syncIPTables(); err != nil {
		klog.Errorf("Failed to sync iptables: %v", err)
		return
	}
	if err := c.syncRoutes(); err != nil {
		klog.Errorf("Failed to sync routes: %v", err)
	}
	klog.V(3).Infof("Successfully synced node iptables and routes")
}

func (c *Client) syncRoutes() error {
	routeList, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	routeMap := make(map[string]*netlink.Route)
	for i := range routeList {
		r := &routeList[i]
		if r.Dst == nil {
			continue
		}
		routeMap[r.Dst.String()] = r
	}
	c.nodeRoutes.Range(func(_, v interface{}) bool {
		for _, route := range v.([]*netlink.Route) {
			r, ok := routeMap[route.Dst.String()]
			if ok && routeEqual(route, r) {
				continue
			}
			if err := netlink.RouteReplace(route); err != nil {
				klog.Errorf("Failed to add route to the gateway: %v", err)
				return false
			}
		}
		return true
	})
	return nil
}

func routeEqual(x, y *netlink.Route) bool {
	if x == nil || y == nil {
		return false
	}
	return x.LinkIndex == y.LinkIndex &&
		x.Dst.IP.Equal(y.Dst.IP) &&
		bytes.Equal(x.Dst.Mask, y.Dst.Mask) &&
		x.Gw.Equal(y.Gw)
}

// syncIPSet ensures that the required ipset exists and it has the initial members.
func (c *Client) syncIPSet() error {
	// In policy-only mode, Node Pod CIDR is undefined.
	if c.networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		return nil
	}
	if err := ipset.CreateIPSet(antreaPodIPSet, ipset.HashNet, false); err != nil {
		return err
	}
	if err := ipset.CreateIPSet(antreaPodIP6Set, ipset.HashNet, true); err != nil {
		return err
	}

	// Loop all valid PodCIDR and add into the corresponding ipset.
	for _, podCIDR := range []*net.IPNet{c.nodeConfig.PodIPv4CIDR, c.nodeConfig.PodIPv6CIDR} {
		if podCIDR != nil {
			ipsetName := getIPSetName(podCIDR.IP)
			if err := ipset.AddEntry(ipsetName, podCIDR.String()); err != nil {
				return err
			}
		}
	}
	return nil
}

func getIPSetName(ip net.IP) string {
	if ip.To4() == nil {
		return antreaPodIP6Set
	}
	return antreaPodIPSet
}

// writeEKSMangleRule writes an additional iptables mangle rule to the
// iptablesData buffer, which is required to ensure that the reverse path for
// NodePort Service traffic is correct on EKS.
// See https://github.com/antrea-io/antrea/issues/678.
func (c *Client) writeEKSMangleRule(iptablesData *bytes.Buffer) {
	// TODO: the following should be taking into account:
	//   1) AWS_VPC_CNI_NODE_PORT_SUPPORT may be set to false (by default is
	//   true), in which case we do not need to install the rule.
	//   2) this option is not documented but the mark value can be
	//   configured with AWS_VPC_K8S_CNI_CONNMARK.
	// We could look for the rule added by AWS VPC CNI to the mangle
	// table. If it does not exist, we do not need to install this rule. If
	// it does exist we can scan for the mark value and use that in our
	// rule.
	klog.V(2).Infof("Add iptable mangle rule for EKS to ensure correct reverse path for NodePort Service traffic")
	writeLine(iptablesData, []string{
		"-A", antreaMangleChain,
		"-m", "comment", "--comment", `"Antrea: AWS, primary ENI"`,
		"-i", c.nodeConfig.GatewayConfig.Name, "-j", "CONNMARK",
		"--restore-mark", "--nfmask", "0x80", "--ctmask", "0x80",
	}...)
}

// syncIPTables ensure that the iptables infrastructure we use is set up.
// It's idempotent and can safely be called on every startup.
func (c *Client) syncIPTables() error {
	var err error
	v4Enabled := config.IsIPv4Enabled(c.nodeConfig, c.networkConfig.TrafficEncapMode)
	v6Enabled := config.IsIPv6Enabled(c.nodeConfig, c.networkConfig.TrafficEncapMode)
	c.ipt, err = iptables.New(v4Enabled, v6Enabled)
	if err != nil {
		return fmt.Errorf("error creating IPTables instance: %v", err)
	}
	// Create the antrea managed chains and link them to built-in chains.
	// We cannot use iptables-restore for these jump rules because there
	// are non antrea managed rules in built-in chains.
	jumpRules := []struct{ table, srcChain, dstChain, comment string }{
		{iptables.RawTable, iptables.PreRoutingChain, antreaPreRoutingChain, "Antrea: jump to Antrea prerouting rules"},
		{iptables.RawTable, iptables.OutputChain, antreaOutputChain, "Antrea: jump to Antrea output rules"},
		{iptables.FilterTable, iptables.ForwardChain, antreaForwardChain, "Antrea: jump to Antrea forwarding rules"},
		{iptables.NATTable, iptables.PostRoutingChain, antreaPostRoutingChain, "Antrea: jump to Antrea postrouting rules"},
		{iptables.MangleTable, iptables.PreRoutingChain, antreaMangleChain, "Antrea: jump to Antrea mangle rules"}, // TODO: unify the chain naming style
		{iptables.MangleTable, iptables.OutputChain, antreaOutputChain, "Antrea: jump to Antrea output rules"},
	}
	for _, rule := range jumpRules {
		if err := c.ipt.EnsureChain(rule.table, rule.dstChain); err != nil {
			return err
		}
		ruleSpec := []string{"-j", rule.dstChain, "-m", "comment", "--comment", rule.comment}
		if err := c.ipt.EnsureRule(rule.table, rule.srcChain, ruleSpec); err != nil {
			return err
		}
	}

	snatMarkToIPv4 := map[uint32]net.IP{}
	snatMarkToIPv6 := map[uint32]net.IP{}
	c.markToSNATIP.Range(func(key, value interface{}) bool {
		snatMark := key.(uint32)
		snatIP := value.(net.IP)
		if snatIP.To4() != nil {
			snatMarkToIPv4[snatMark] = snatIP
		} else {
			snatMarkToIPv6[snatMark] = snatIP
		}
		return true
	})
	// Use iptables-restore to configure IPv4 settings.
	if v4Enabled {
		iptablesData := c.restoreIptablesData(c.nodeConfig.PodIPv4CIDR, antreaPodIPSet, snatMarkToIPv4)
		// Setting --noflush to keep the previous contents (i.e. non antrea managed chains) of the tables.
		if err := c.ipt.Restore(iptablesData.Bytes(), false, false); err != nil {
			return err
		}
	}

	// Use ip6tables-restore to configure IPv6 settings.
	if v6Enabled {
		iptablesData := c.restoreIptablesData(c.nodeConfig.PodIPv6CIDR, antreaPodIP6Set, snatMarkToIPv6)
		// Setting --noflush to keep the previous contents (i.e. non antrea managed chains) of the tables.
		if err := c.ipt.Restore(iptablesData.Bytes(), false, true); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) restoreIptablesData(podCIDR *net.IPNet, podIPSet string, snatMarkToIP map[uint32]net.IP) *bytes.Buffer {
	// Create required rules in the antrea chains.
	// Use iptables-restore as it flushes the involved chains and creates the desired rules
	// with a single call, instead of string matching to clean up stale rules.
	iptablesData := bytes.NewBuffer(nil)
	// Write head lines anyway so the undesired rules can be deleted when changing encap mode.
	writeLine(iptablesData, "*raw")
	writeLine(iptablesData, iptables.MakeChainLine(antreaPreRoutingChain))
	writeLine(iptablesData, iptables.MakeChainLine(antreaOutputChain))
	if c.networkConfig.TrafficEncapMode.SupportsEncap() {
		// For Geneve and VXLAN encapsulation packets, the request and response packets don't belong to a UDP connection
		// so tracking them doesn't give the normal benefits of conntrack. Besides, kube-proxy may install great number
		// of iptables rules in nat table. The first encapsulation packets of connections would have to go through all
		// of the rules which wastes CPU and increases packet latency.
		udpPort := 0
		if c.networkConfig.TunnelType == ovsconfig.GeneveTunnel {
			udpPort = genevePort
		} else if c.networkConfig.TunnelType == ovsconfig.VXLANTunnel {
			udpPort = vxlanPort
		}
		if udpPort > 0 {
			writeLine(iptablesData, []string{
				"-A", antreaPreRoutingChain,
				"-m", "comment", "--comment", `"Antrea: do not track incoming encapsulation packets"`,
				"-m", "udp", "-p", "udp", "--dport", strconv.Itoa(udpPort),
				"-m", "addrtype", "--dst-type", "LOCAL",
				"-j", iptables.NoTrackTarget,
			}...)
			writeLine(iptablesData, []string{
				"-A", antreaOutputChain,
				"-m", "comment", "--comment", `"Antrea: do not track outgoing encapsulation packets"`,
				"-m", "udp", "-p", "udp", "--dport", strconv.Itoa(udpPort),
				"-m", "addrtype", "--src-type", "LOCAL",
				"-j", iptables.NoTrackTarget,
			}...)
		}
	}
	writeLine(iptablesData, "COMMIT")

	// Write head lines anyway so the undesired rules can be deleted when noEncap -> encap.
	writeLine(iptablesData, "*mangle")
	writeLine(iptablesData, iptables.MakeChainLine(antreaMangleChain))
	writeLine(iptablesData, iptables.MakeChainLine(antreaOutputChain))

	// When Antrea is used to enforce NetworkPolicies in EKS, an additional iptables
	// mangle rule is required. See https://github.com/antrea-io/antrea/issues/678.
	if env.IsCloudEKS() {
		c.writeEKSMangleRule(iptablesData)
	}

	// To make liveness/readiness probe traffic bypass ingress rules of Network Policies, mark locally generated packets
	// that will be sent to OVS so we can identify them later in the OVS pipeline.
	// It must match source address because kube-proxy ipvs mode will redirect ingress packets to output chain, and they
	// will have non local source addresses.
	writeLine(iptablesData, []string{
		"-A", antreaOutputChain,
		"-m", "comment", "--comment", `"Antrea: mark LOCAL output packets"`,
		"-m", "addrtype", "--src-type", "LOCAL",
		"-o", c.nodeConfig.GatewayConfig.Name,
		"-j", iptables.MarkTarget, "--or-mark", fmt.Sprintf("%#08x", types.HostLocalSourceMark),
	}...)
	writeLine(iptablesData, "COMMIT")

	writeLine(iptablesData, "*filter")
	writeLine(iptablesData, iptables.MakeChainLine(antreaForwardChain))
	writeLine(iptablesData, []string{
		"-A", antreaForwardChain,
		"-m", "comment", "--comment", `"Antrea: accept packets from local Pods"`,
		"-i", c.nodeConfig.GatewayConfig.Name,
		"-j", iptables.AcceptTarget,
	}...)
	writeLine(iptablesData, []string{
		"-A", antreaForwardChain,
		"-m", "comment", "--comment", `"Antrea: accept packets to local Pods"`,
		"-o", c.nodeConfig.GatewayConfig.Name,
		"-j", iptables.AcceptTarget,
	}...)
	writeLine(iptablesData, "COMMIT")

	writeLine(iptablesData, "*nat")
	writeLine(iptablesData, iptables.MakeChainLine(antreaPostRoutingChain))
	// Egress rules must be inserted before the default masquerade rule.
	for snatMark, snatIP := range snatMarkToIP {
		// Cannot reuse snatRuleSpec to generate the rule as it doesn't have "`" in the comment.
		writeLine(iptablesData, []string{
			"-A", antreaPostRoutingChain,
			"-m", "comment", "--comment", `"Antrea: SNAT Pod to external packets"`,
			"!", "-o", c.nodeConfig.GatewayConfig.Name,
			"-m", "mark", "--mark", fmt.Sprintf("%#08x/%#08x", snatMark, types.SNATIPMarkMask),
			"-j", iptables.SNATTarget, "--to", snatIP.String(),
		}...)
	}

	if !c.noSNAT {
		writeLine(iptablesData, []string{
			"-A", antreaPostRoutingChain,
			"-m", "comment", "--comment", `"Antrea: masquerade Pod to external packets"`,
			"-s", podCIDR.String(), "-m", "set", "!", "--match-set", podIPSet, "dst",
			"-j", iptables.MasqueradeTarget,
		}...)
	}

	// For local traffic going out of the gateway interface, if the source IP does not match any
	// of the gateway's IP addresses, the traffic needs to be masqueraded. Otherwise, we observe
	// that ARP requests may advertise a different source IP address, in which case they will be
	// dropped by the SpoofGuard table in the OVS pipeline. See description for the arp_announce
	// sysctl parameter.
	writeLine(iptablesData, []string{
		"-A", antreaPostRoutingChain,
		"-m", "comment", "--comment", `"Antrea: masquerade LOCAL traffic"`,
		"-o", c.nodeConfig.GatewayConfig.Name,
		"-m", "addrtype", "!", "--src-type", "LOCAL", "--limit-iface-out",
		"-m", "addrtype", "--src-type", "LOCAL",
		"-j", iptables.MasqueradeTarget, "--random-fully",
	}...)

	if c.proxyFull {
		if podCIDR.IP.To4() != nil {
			writeLine(iptablesData, []string{
				"-A", antreaPostRoutingChain,
				"-m", "comment", "--comment", `"Antrea: masquerade Service host network Endpoint traffic"`,
				"-s", serviceGWHairpinIPv4.String(),
				"-j", iptables.MasqueradeTarget,
			}...)
		} else {
			writeLine(iptablesData, []string{
				"-A", antreaPostRoutingChain,
				"-m", "comment", "--comment", `"Antrea: masquerade Service host network Endpoint traffic"`,
				"-s", serviceGWHairpinIPv6.String(),
				"-j", iptables.MasqueradeTarget,
			}...)
		}
	}

	writeLine(iptablesData, "COMMIT")
	return iptablesData
}

func (c *Client) initIPRoutes() error {
	if c.networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		gwLink := util.GetNetLink(c.nodeConfig.GatewayConfig.Name)
		_, gwIP, _ := net.ParseCIDR(fmt.Sprintf("%s/32", c.nodeConfig.NodeTransportIPAddr.IP.String()))
		if err := netlink.AddrReplace(gwLink, &netlink.Addr{IPNet: gwIP}); err != nil {
			return fmt.Errorf("failed to add address %s to gw %s: %v", gwIP, gwLink.Attrs().Name, err)
		}
	}
	return nil
}

// Reconcile removes orphaned podCIDRs from ipset and removes routes to orphaned podCIDRs
// based on the desired podCIDRs.
func (c *Client) Reconcile(podCIDRs []string) error {
	desiredPodCIDRs := sets.NewString(podCIDRs...)

	// Remove orphaned podCIDRs from ipset.
	for _, ipsetName := range []string{antreaPodIPSet, antreaPodIP6Set} {
		entries, err := ipset.ListEntries(ipsetName)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if desiredPodCIDRs.Has(entry) {
				continue
			}
			klog.Infof("Deleting orphaned PodIP %s from ipset and route table", entry)
			if err := ipset.DelEntry(ipsetName, entry); err != nil {
				return err
			}
			_, cidr, err := net.ParseCIDR(entry)
			if err != nil {
				return err
			}
			route := &netlink.Route{Dst: cidr}
			if err := netlink.RouteDel(route); err != nil && err != unix.ESRCH {
				return err
			}
		}
	}

	// Remove any unknown routes on Antrea gateway.
	routes, err := c.listIPRoutesOnGW()
	if err != nil {
		return fmt.Errorf("error listing ip routes: %v", err)
	}
	for i := range routes {
		route := routes[i]
		if reflect.DeepEqual(route.Dst, c.nodeConfig.PodIPv4CIDR) || reflect.DeepEqual(route.Dst, c.nodeConfig.PodIPv6CIDR) {
			continue
		}
		if desiredPodCIDRs.Has(route.Dst.String()) {
			continue
		}
		// Don't delete the virtual Service IP route which is added by AntreaProxy.
		if route.Gw.To4() != nil && route.Gw.Equal(serviceGWHairpinIPv4) ||
			route.Gw.To16() != nil && route.Gw.Equal(serviceGWHairpinIPv6) ||
			route.Dst.IP.To16() != nil && route.Dst.IP.Equal(serviceGWHairpinIPv6) {
			continue
		}
		klog.Infof("Deleting unknown route %v", route)
		if err := netlink.RouteDel(&route); err != nil && err != unix.ESRCH {
			return err
		}
	}

	// Remove any unknown IPv6 neighbors on Antrea gateway.
	desiredGWs := getIPv6Gateways(podCIDRs)
	// Return immediately if there is no IPv6 gateway address configured on the Nodes.
	if desiredGWs.Len() == 0 {
		return nil
	}
	// Remove orphaned IPv6 Neighbors from host network.
	actualNeighbors, err := c.listIPv6NeighborsOnGateway()
	if err != nil {
		return err
	}
	for neighIP, actualNeigh := range actualNeighbors {
		if desiredGWs.Has(neighIP) {
			continue
		}
		// Don't delete the virtual Service IP neigh which is added by AntreaProxy.
		if actualNeigh.IP.Equal(serviceGWHairpinIPv6) {
			continue
		}
		klog.V(4).Infof("Deleting orphaned IPv6 neighbor %v", actualNeigh)
		if err := netlink.NeighDel(actualNeigh); err != nil {
			return err
		}
	}
	return nil
}

// listIPRoutes returns list of routes on Antrea gateway.
func (c *Client) listIPRoutesOnGW() ([]netlink.Route, error) {
	filter := &netlink.Route{
		LinkIndex: c.nodeConfig.GatewayConfig.LinkIndex}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_OIF)
	if err != nil {
		return nil, err
	}
	ipv6Routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, filter, netlink.RT_FILTER_OIF)
	if err != nil {
		return nil, err
	}
	routes = append(routes, ipv6Routes...)
	return routes, nil
}

// getIPv6Gateways returns the IPv6 gateway addresses of the given CIDRs.
func getIPv6Gateways(podCIDRs []string) sets.String {
	ipv6GWs := sets.NewString()
	for _, podCIDR := range podCIDRs {
		peerPodCIDRAddr, _, _ := net.ParseCIDR(podCIDR)
		if peerPodCIDRAddr.To4() != nil {
			continue
		}
		peerGatewayIP := ip.NextIP(peerPodCIDRAddr)
		ipv6GWs.Insert(peerGatewayIP.String())
	}
	return ipv6GWs
}

func (c *Client) listIPv6NeighborsOnGateway() (map[string]*netlink.Neigh, error) {
	neighs, err := netlink.NeighList(c.nodeConfig.GatewayConfig.LinkIndex, netlink.FAMILY_V6)
	if err != nil {
		return nil, err
	}
	neighMap := make(map[string]*netlink.Neigh)
	for i := range neighs {
		if neighs[i].IP == nil {
			continue
		}
		neighMap[neighs[i].IP.String()] = &neighs[i]
	}
	return neighMap, nil
}

// AddRoutes adds routes to a new podCIDR. It overrides the routes if they already exist.
func (c *Client) AddRoutes(podCIDR *net.IPNet, nodeName string, nodeIP, nodeGwIP net.IP) error {
	podCIDRStr := podCIDR.String()
	ipsetName := getIPSetName(podCIDR.IP)
	// Add this podCIDR to antreaPodIPSet so that packets to them won't be masqueraded when they leave the host.
	if err := ipset.AddEntry(ipsetName, podCIDRStr); err != nil {
		return err
	}
	// Install routes to this Node.
	route := &netlink.Route{
		Dst: podCIDR,
	}
	var routes []*netlink.Route
	if c.networkConfig.TrafficEncapMode.NeedsEncapToPeer(nodeIP, c.nodeConfig.NodeTransportIPAddr) {
		if podCIDR.IP.To4() == nil {
			// "on-link" is not identified in IPv6 route entries, so split the configuration into 2 entries.
			routes = []*netlink.Route{
				{
					Dst:       &net.IPNet{IP: nodeGwIP, Mask: net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
					LinkIndex: c.nodeConfig.GatewayConfig.LinkIndex,
				},
			}
		} else {
			route.Flags = int(netlink.FLAG_ONLINK)
		}
		route.LinkIndex = c.nodeConfig.GatewayConfig.LinkIndex
		route.Gw = nodeGwIP
	} else if c.networkConfig.TrafficEncapMode.NeedsDirectRoutingToPeer(nodeIP, c.nodeConfig.NodeTransportIPAddr) {
		// NoEncap traffic to Node on the same subnet.
		// Set the peerNodeIP as next hop.
		route.Gw = nodeIP
	} else {
		// NoEncap traffic to Node on the same subnet. It is handled by host default route.
		return nil
	}
	routes = append(routes, route)

	for _, route := range routes {
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("failed to install route to peer %s (%s) with netlink. Route config: %s. Error: %v", nodeName, nodeIP, route.String(), err)
		}
	}

	if podCIDR.IP.To4() == nil {
		// Add IPv6 neighbor if the given podCIDR is using IPv6 address.
		neigh := &netlink.Neigh{
			LinkIndex:    c.nodeConfig.GatewayConfig.LinkIndex,
			Family:       netlink.FAMILY_V6,
			State:        netlink.NUD_PERMANENT,
			IP:           nodeGwIP,
			HardwareAddr: globalVMAC,
		}
		if err := netlink.NeighSet(neigh); err != nil {
			return fmt.Errorf("failed to add neigh %v to gw %s: %v", neigh, c.nodeConfig.GatewayConfig.Name, err)
		}
		c.nodeNeighbors.Store(podCIDRStr, neigh)
	}

	c.nodeRoutes.Store(podCIDRStr, routes)
	return nil
}

// DeleteRoutes deletes routes to a PodCIDR. It does nothing if the routes doesn't exist.
func (c *Client) DeleteRoutes(podCIDR *net.IPNet) error {
	podCIDRStr := podCIDR.String()
	ipsetName := getIPSetName(podCIDR.IP)
	// Delete this podCIDR from antreaPodIPSet as the CIDR is no longer for Pods.
	if err := ipset.DelEntry(ipsetName, podCIDRStr); err != nil {
		return err
	}

	routes, exists := c.nodeRoutes.Load(podCIDRStr)
	if exists {
		c.nodeRoutes.Delete(podCIDRStr)
		for _, r := range routes.([]*netlink.Route) {
			klog.V(4).Infof("Deleting route %v", r)
			if err := netlink.RouteDel(r); err != nil && err != unix.ESRCH {
				c.nodeRoutes.Store(podCIDRStr, routes)
				return err
			}
		}
	}
	if podCIDR.IP.To4() == nil {
		neigh, exists := c.nodeNeighbors.Load(podCIDRStr)
		if exists {
			if err := netlink.NeighDel(neigh.(*netlink.Neigh)); err != nil {
				return err
			}
			c.nodeNeighbors.Delete(podCIDRStr)
		}
	}
	return nil
}

// Join all words with spaces, terminate with newline and write to buf.
func writeLine(buf *bytes.Buffer, words ...string) {
	// We avoid strings.Join for performance reasons.
	for i := range words {
		buf.WriteString(words[i])
		if i < len(words)-1 {
			buf.WriteByte(' ')
		} else {
			buf.WriteByte('\n')
		}
	}
}

// MigrateRoutesToGw moves routes (including assigned IP addresses if any) from link linkName to
// host gateway.
func (c *Client) MigrateRoutesToGw(linkName string) error {
	gwLink := util.GetNetLink(c.nodeConfig.GatewayConfig.Name)
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", linkName, err)
	}

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		// Swap route first then address, otherwise route gets removed when address is removed.
		routes, err := netlink.RouteList(link, family)
		if err != nil {
			return fmt.Errorf("failed to get routes for link %s: %w", linkName, err)
		}
		for i := range routes {
			route := routes[i]
			route.LinkIndex = gwLink.Attrs().Index
			if err = netlink.RouteReplace(&route); err != nil {
				return fmt.Errorf("failed to add route %v to link %s: %w", &route, gwLink.Attrs().Name, err)
			}
		}

		// Swap address if any.
		addrs, err := netlink.AddrList(link, family)
		if err != nil {
			return fmt.Errorf("failed to get addresses for %s: %w", linkName, err)
		}
		for i := range addrs {
			addr := addrs[i]
			if addr.IP.IsLinkLocalMulticast() || addr.IP.IsLinkLocalUnicast() {
				continue
			}
			if err = netlink.AddrDel(link, &addr); err != nil {
				klog.Errorf("failed to delete addr %v from %s: %v", addr, link, err)
			}
			tmpAddr := &netlink.Addr{IPNet: addr.IPNet}
			if err = netlink.AddrReplace(gwLink, tmpAddr); err != nil {
				return fmt.Errorf("failed to add addr %v to gw %s: %w", addr, gwLink.Attrs().Name, err)
			}
		}
	}
	return nil
}

// UnMigrateRoutesFromGw moves route from gw to link linkName if provided; otherwise route is deleted
func (c *Client) UnMigrateRoutesFromGw(route *net.IPNet, linkName string) error {
	gwLink := util.GetNetLink(c.nodeConfig.GatewayConfig.Name)
	var link netlink.Link = nil
	var err error
	if len(linkName) > 0 {
		link, err = netlink.LinkByName(linkName)
		if err != nil {
			return fmt.Errorf("failed to get link %s: %w", linkName, err)
		}
	}
	routes, err := netlink.RouteList(gwLink, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to get routes for link %s: %w", gwLink.Attrs().Name, err)
	}
	for i := range routes {
		rt := routes[i]
		if route.String() == rt.Dst.String() {
			if link != nil {
				rt.LinkIndex = link.Attrs().Index
				return netlink.RouteReplace(&rt)
			}
			return netlink.RouteDel(&rt)
		}
	}
	return nil
}

func (c *Client) snatRuleSpec(snatIP net.IP, snatMark uint32) []string {
	return []string{
		"-m", "comment", "--comment", "Antrea: SNAT Pod to external packets",
		// The condition is needed to prevent the rule from being applied to local out packets destined for Pods, which
		// have "0x1/0x1" mark.
		"!", "-o", c.nodeConfig.GatewayConfig.Name,
		"-m", "mark", "--mark", fmt.Sprintf("%#08x/%#08x", snatMark, types.SNATIPMarkMask),
		"-j", iptables.SNATTarget, "--to", snatIP.String(),
	}
}

func (c *Client) AddSNATRule(snatIP net.IP, mark uint32) error {
	protocol := iptables.ProtocolIPv4
	if snatIP.To4() == nil {
		protocol = iptables.ProtocolIPv6
	}
	c.markToSNATIP.Store(mark, snatIP)
	return c.ipt.InsertRule(protocol, iptables.NATTable, antreaPostRoutingChain, c.snatRuleSpec(snatIP, mark))
}

func (c *Client) DeleteSNATRule(mark uint32) error {
	value, ok := c.markToSNATIP.Load(mark)
	if !ok {
		klog.Warningf("Didn't find SNAT rule with mark %#x", mark)
		return nil
	}
	c.markToSNATIP.Delete(mark)
	snatIP := value.(net.IP)
	return c.ipt.DeleteRule(iptables.NATTable, antreaPostRoutingChain, c.snatRuleSpec(snatIP, mark))
}

// cleanStaleGatewayRoutes is used to clean ClusterIP/LoadBalancer route entries on host. If Node routes are created,
// this function will delete them. Since this function only runs once, and Node route controller can restore the Node
// routes.
func (c *Client) cleanStaleGatewayRoutes() error {
	routes, err := c.listIPRoutesOnGW()
	if err != nil {
		return fmt.Errorf("error listing ip routes: %v", err)
	}
	for i := range routes {
		route := routes[i]
		// Don't delete the route of local pod CIDR. Node route controller cannot restore this routing entry.
		if route.Dst.Contains(c.nodeConfig.GatewayConfig.IPv4) || route.Dst.Contains(c.nodeConfig.GatewayConfig.IPv6) {
			continue
		}
		klog.Infof("Deleting unknown route %v", route)
		if err = netlink.RouteDel(&route); err != nil && err != unix.ESRCH {
			return err
		}
	}
	return nil
}

func (c *Client) addServiceOnlinkRoute(svcIP *net.IP, isIPv6 bool) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	var gw *net.IP
	var mask int
	if !isIPv6 {
		gw = &serviceGWHairpinIPv4
		mask = ipv4AddrLength
	} else {
		gw = &serviceGWHairpinIPv6
		mask = ipv6AddrLength
	}

	route, err := generateOnlinkRoute(svcIP, mask, gw, linkIndex, defaultRouteTable)
	if err != nil {
		return fmt.Errorf("failed to generate route for Service IP %s: %w", svcIP.String(), err)
	}
	if err = netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("failed to install route for Service IP %s: %w", svcIP.String(), err)
	}
	klog.V(4).Infof("Adding Service IP route %v", route)
	c.nodeRoutes.Store(svcIP.String(), []*netlink.Route{route})

	return nil
}

func (c *Client) addVirtualServiceIPRoute(isIPv6 bool) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	var svcIP *net.IP
	var route *netlink.Route
	var neigh *netlink.Neigh
	var err error
	if !isIPv6 {
		svcIP = &serviceGWHairpinIPv4
		route, err = generateOnlinkRoute(svcIP, ipv4AddrLength, svcIP, linkIndex, defaultRouteTable)
		if err != nil {
			return fmt.Errorf("failed to generate route for virtual Service IP %s: %w", svcIP.String(), err)
		}
	} else {
		svcIP = &serviceGWHairpinIPv6
		route, neigh, err = generateIPv6RouteAndNeigh(svcIP, linkIndex)
		if err != nil {
			return fmt.Errorf("failed to generate route and neigh for virtual Service IP %s: %w", svcIP.String(), err)
		}
	}

	if isIPv6 {
		if err = netlink.NeighSet(neigh); err != nil {
			return fmt.Errorf("failed to add new Cluster route neighbor %v to gw %s: %v", neigh, c.nodeConfig.GatewayConfig.Name, err)
		}
		c.nodeNeighbors.Store(svcIP.String(), neigh)
	}

	if err = netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("failed to install route for Service IP %s: %w", svcIP.String(), err)
	}
	klog.Infof("Adding virtual Service IP route %v", route)
	c.nodeRoutes.Store(svcIP.String(), []*netlink.Route{route})

	return nil
}

func (c *Client) deleteServiceOnlinkRoute(svcIP *net.IP, isIPv6 bool) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	var gw *net.IP
	var mask int
	if !isIPv6 {
		gw = &serviceGWHairpinIPv4
		mask = 32
	} else {
		gw = &serviceGWHairpinIPv6
		mask = 128
	}

	route, err := generateOnlinkRoute(svcIP, mask, gw, linkIndex, defaultRouteTable)
	if err != nil {
		return fmt.Errorf("failed to generate route for Service IP %s: %w", svcIP.String(), err)
	}
	if err = netlink.RouteDel(route); err != nil {
		return fmt.Errorf("failed to delete route for Service IP %s: %w", svcIP.String(), err)
	}
	klog.V(4).Infof("Deleting Service IP route %v", route)
	c.nodeRoutes.Delete(svcIP.String())

	return nil
}

func (c *Client) InitService(nodePortIPMap map[int][]net.IP, isIPv6 bool) error {
	if err := setupSysctlParameters(); err != nil {
		return err
	}

	l3ProtocolVal := unix.IPPROTO_IP
	if isIPv6 {
		l3ProtocolVal = unix.IPPROTO_IPV6
	}
	if err := c.cleanStaleGatewayRoutes(); err != nil {
		return err
	}
	if err := c.addVirtualServiceIPRoute(isIPv6); err != nil {
		return err
	}

	// Add a ingress qdisc to every interface which has available NodePort IP addresses. When a NodePort Service is
	// created, for every interface which has available NodePort IP addresses, a filter matching destination IP address
	// (NodePort IP address) and destination protocol/port(NodePort protocol/port) will be created and attached to
	// the ingress qdisc, and its action is redirecting matched traffic to antrea gateway's egress. Note that, this
	// filter is used to match NodePort request traffic.
	gatewayIPv4 := c.nodeConfig.GatewayConfig.IPv4
	gatewayIPv6 := c.nodeConfig.GatewayConfig.IPv6
	gatewayIfIndex := util.GetIndexByName(c.nodeConfig.GatewayConfig.Name)

	// If current proxy is an IPv4 proxy, create the TC qdisc.
	// If current proxy is an IPv6 proxy and IPv4 is enabled, don't create TC qdisc.
	// If current proxy is an IPv6 Proxy and IPv4 is not enabled, create the TC qdisc.
	if gatewayIPv4 != nil && !isIPv6 ||
		gatewayIPv4 == nil && gatewayIPv6 != nil && isIPv6 {

		for ifIndex := range nodePortIPMap {
			handle := tc.QdiscHandleIngress
			if ifIndex == tc.LoopbackIfIndex {
				handle = tc.QdiscHandleEgress
			}
			// Clean left qdisc and create new qidsc for the interface.
			c.tcClient.QdiscDel(handle, ifIndex)
			if err := c.tcClient.QdiscAdd(handle, ifIndex); err != nil {
				return err
			}
		}
		// Clean left qdisc and create new qidsc for the interface.
		c.tcClient.QdiscDel(tc.QdiscHandleIngress, gatewayIfIndex)
		if err := c.tcClient.QdiscAdd(tc.QdiscHandleIngress, gatewayIfIndex); err != nil {
			return err
		}
	}

	// If current proxy is an IPv6 proxy and the qdiscs are created by IPv4 proxy, before creating basic filters
	// for Antrea gateway, make sure that the qdisc has been created.
	err := wait.PollImmediate(200*time.Millisecond, 10*time.Second, func() (exist bool, err error) {
		return c.tcClient.QdiscCheck(tc.QdiscHandleIngress, gatewayIfIndex)
	})
	if err != nil {
		return fmt.Errorf("failed to check that if TC qdisc is ready for Antrea gateway: %w", err)
	}

	// The design of filter for Antrea gateway is hierarchic. Here add basic filters to Antrea gateway. Note that, these
	// filters are used to match NodePort response traffic. These filters are used to distribute packets to different sub filter
	// chains according to their source IP Addresses(NodePort IP addresses). When a NodePort Service is created, a filter
	// matching source IP address (NodePort IP address) and source protocol/port(NodePort protocol/port) will created and
	// attached to every sub filter chain, and its action is redirecting matched traffic to an interface's egress.
	for dstIfIndex, addrs := range nodePortIPMap {
		err = c.tcClient.GatewayBasicFiltersAdd(gatewayIfIndex, dstIfIndex, l3ProtocolVal, addrs)
		if err != nil {
			c.tcClient.QdiscDel(tc.QdiscHandleIngress, gatewayIfIndex)
			return err
		}
	}

	return nil
}

func (c *Client) AddNodePort(nodePortIPMap map[int][]net.IP, port uint16, protocol binding.Protocol) error {
	l3ProtocolVal, l4ProtocolVal := getProtocolVal(protocol)
	gateway := c.nodeConfig.GatewayConfig.Name
	gatewayMAC := c.nodeConfig.GatewayConfig.MAC.String()

	for ifIndex, addrs := range nodePortIPMap {
		err := c.tcClient.GatewayFilterAddOnSubChain(ifIndex, l3ProtocolVal, l4ProtocolVal, port, gateway)
		if err != nil {
			return err
		}

		err = c.tcClient.InterfaceFiltersAdd(ifIndex, l3ProtocolVal, l4ProtocolVal, port, addrs, gateway)
		if err != nil {
			return err
		}

		err = c.tcClient.LoopbackFiltersAdd(l3ProtocolVal, l4ProtocolVal, port, addrs, gateway, gatewayMAC)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) DeleteNodePort(nodePortIPMap map[int][]net.IP, port uint16, protocol binding.Protocol) error {
	l3ProtocolVal, l4ProtocolVal := getProtocolVal(protocol)
	gateway := c.nodeConfig.GatewayConfig.Name

	for ifIndex, addrs := range nodePortIPMap {
		err := c.tcClient.GatewayFilterDelOnSubChain(ifIndex, l3ProtocolVal, l4ProtocolVal, port, gateway)
		if err != nil {
			return err
		}

		err = c.tcClient.InterfaceFiltersDel(ifIndex, l3ProtocolVal, l4ProtocolVal, port, addrs)
		if err != nil {
			return err
		}

		err = c.tcClient.LoopbackFiltersDel(l3ProtocolVal, l4ProtocolVal, port, addrs)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) AddClusterIPRoute(svcIP net.IP, isIPv6 bool) error {
	routeKey := clusterIPv4FromNodeRouteKey
	if isIPv6 {
		routeKey = clusterIPv6FromNodeRouteKey
	}

	routeVal, exist := c.nodeRoutes.Load(routeKey)
	if exist {
		curRoute := routeVal.([]*netlink.Route)[0]
		// If the route exists, check that whether the route can cover the ClusterIP.
		if !curRoute.Dst.Contains(svcIP) {
			// If not, generate a new destination ipNet.
			newDst, err := util.ExtendCIDRWithIP(curRoute.Dst, svcIP)
			if err != nil {
				return fmt.Errorf("extend destination route CIDR with error: %v", err)
			}

			// Generate a new route with new destination ipNet.
			networkMaskPrefix, _ := newDst.Mask.Size()
			newRoute, err := generateOnlinkRoute(&newDst.IP, networkMaskPrefix, &curRoute.Gw, curRoute.LinkIndex, defaultRouteTable)
			if err != nil {
				return fmt.Errorf("failed to generate new route %s", svcIP.String())
			}
			// Install new route first.
			if err = netlink.RouteReplace(newRoute); err != nil {
				return fmt.Errorf("failed to install new route: %w", err)
			}
			// Remote old route.
			if err = netlink.RouteDel(curRoute); err != nil {
				return fmt.Errorf("failed to uninstall old route: %w", err)
			}

			klog.V(4).Infof("Create route %s to route ClusterIP %v to Antrea gateway", newRoute.Dst.String(), svcIP)
			c.nodeRoutes.Store(routeKey, []*netlink.Route{newRoute})
		} else {
			klog.V(4).Infof("Current route can route ClusterIP %v to Antrea gateway", svcIP)
		}
	} else {
		// The route doesn't exist, create one.
		var mask int
		var gw *net.IP
		if isIPv6 {
			mask = ipv6AddrLength
			gw = &serviceGWHairpinIPv6
		} else {
			mask = ipv4AddrLength
			gw = &serviceGWHairpinIPv4
		}

		linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
		route, err := generateOnlinkRoute(&svcIP, mask, gw, linkIndex, defaultRouteTable)
		if err != nil {
			return fmt.Errorf("failed to generate new route %s", svcIP.String())
		}
		if err = netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("failed to install new ClusterIP route: %w", err)
		}

		c.nodeRoutes.Store(routeKey, []*netlink.Route{route})
	}

	return nil
}

func (c *Client) AddLoadBalancer(port uint16, protocol binding.Protocol, externalIPs []string, isIPv6 bool) error {
	gateway := c.nodeConfig.GatewayConfig.Name
	gatewayIP := c.nodeConfig.GatewayConfig.IPv4
	l3ProtocolVal, l4ProtocolVal := getProtocolVal(protocol)
	ifIndex := c.defaultRouteInterfaceMap[netlink.FAMILY_V4]
	if isIPv6 {
		ifIndex = c.defaultRouteInterfaceMap[netlink.FAMILY_V6]
		gatewayIP = c.nodeConfig.GatewayConfig.IPv6
	}
	var svcIPs []net.IP
	for _, svcIPStr := range externalIPs {
		svcIPs = append(svcIPs, net.ParseIP(svcIPStr))
	}

	if err := c.tcClient.InterfaceFiltersAdd(ifIndex, l3ProtocolVal, l4ProtocolVal, port, svcIPs, gateway); err != nil {
		return err
	}
	if err := c.tcClient.GatewayFiltersAdd(util.GetIndexByName(gateway), l3ProtocolVal, l4ProtocolVal, port, svcIPs, gatewayIP, util.GetNameByIndex(ifIndex)); err != nil {
		return err
	}
	for i := range svcIPs {
		if err := c.addServiceOnlinkRoute(&svcIPs[i], isIPv6); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) DeleteLoadBalancer(port uint16, protocol binding.Protocol, externalIPs []string, isIPv6 bool) error {
	gateway := c.nodeConfig.GatewayConfig.Name
	l3ProtocolVal, l4ProtocolVal := getProtocolVal(protocol)
	ifIndex := c.defaultRouteInterfaceMap[netlink.FAMILY_V4]
	if isIPv6 {
		ifIndex = c.defaultRouteInterfaceMap[netlink.FAMILY_V6]
	}
	var svcIPs []net.IP
	for _, svcIPStr := range externalIPs {
		svcIPs = append(svcIPs, net.ParseIP(svcIPStr))
	}

	if err := c.tcClient.InterfaceFiltersDel(ifIndex, l3ProtocolVal, l4ProtocolVal, port, svcIPs); err != nil {
		return err
	}
	if err := c.tcClient.GatewayFiltersDel(util.GetIndexByName(gateway), l3ProtocolVal, l4ProtocolVal, port, svcIPs); err != nil {
		return err
	}
	for i := range svcIPs {
		if err := c.deleteServiceOnlinkRoute(&svcIPs[i], isIPv6); err != nil {
			return err
		}
	}

	return nil
}

func getProtocolVal(protocol binding.Protocol) (int, int) {
	if protocol == binding.ProtocolTCP {
		return unix.IPPROTO_IP, unix.IPPROTO_TCP
	} else if protocol == binding.ProtocolUDP {
		return unix.IPPROTO_IP, unix.IPPROTO_UDP
	} else if protocol == binding.ProtocolSCTP {
		return unix.IPPROTO_IP, unix.IPPROTO_SCTP
	} else if protocol == binding.ProtocolTCPv6 {
		return unix.IPPROTO_IPV6, unix.IPPROTO_TCP
	} else if protocol == binding.ProtocolUDPv6 {
		return unix.IPPROTO_IPV6, unix.IPPROTO_UDP
	} else if protocol == binding.ProtocolSCTPv6 {
		return unix.IPPROTO_IPV6, unix.IPPROTO_SCTP
	}
	return -1, -1
}

func generateOnlinkRoute(ip *net.IP, mask int, gw *net.IP, linkIndex int, table int) (*netlink.Route, error) {
	addrBits := ipv4AddrLength
	if ip.To4() != nil {
		if gw.To4() == nil {
			return nil, fmt.Errorf("gateway %s is not an valid IPv4 address", gw.String())
		}
		if mask > ipv4AddrLength {
			return nil, fmt.Errorf("network mask should be less or equal to 32 as %s is an IPv4 address", ip.String())
		}
	} else {
		if mask > ipv6AddrLength {
			return nil, fmt.Errorf("network mask should be less or equal to 32 as %s is an IPv6 address", ip.String())
		}
		addrBits = ipv6AddrLength
	}

	route := &netlink.Route{
		Dst: &net.IPNet{
			IP:   *ip,
			Mask: net.CIDRMask(mask, addrBits),
		},
		Gw:        *gw,
		Flags:     int(netlink.FLAG_ONLINK),
		LinkIndex: linkIndex,
		Table:     table,
	}
	return route, nil
}

func generateIPv6RouteAndNeigh(ip *net.IP, linkIndex int) (*netlink.Route, *netlink.Neigh, error) {
	if ip.To16() == nil {
		return nil, nil, fmt.Errorf("%s is not an IPv6 address", ip.String())
	}
	route := &netlink.Route{
		Dst: &net.IPNet{
			IP:   *ip,
			Mask: net.CIDRMask(ipv6AddrLength, ipv6AddrLength),
		},
		LinkIndex: linkIndex,
	}
	neigh := &netlink.Neigh{
		LinkIndex:    linkIndex,
		Family:       netlink.FAMILY_V6,
		State:        netlink.NUD_PERMANENT,
		IP:           *ip,
		HardwareAddr: globalVMAC,
	}
	return route, neigh, nil
}

func setupSysctlParameters() error {
	parametersWithErrors := []string{}
	loRouteLocalnetStr := "ipv4/conf/lo/route_localnet"
	loAcceptLocalStr := "ipv4/conf/lo/accept_local"
	loRpFilterStr := "ipv4/conf/lo/rp_filter"

	// The request NodePort traffic from localhost is from loopback, the response will be dropped if route_localnet/accept_local
	// of loopback is not 1.
	if sysctl.EnsureSysctlNetValue(loRouteLocalnetStr, 1) != nil {
		parametersWithErrors = append(parametersWithErrors, loRouteLocalnetStr)
	}
	if sysctl.EnsureSysctlNetValue(loAcceptLocalStr, 1) != nil {
		parametersWithErrors = append(parametersWithErrors, loAcceptLocalStr)
	}
	if sysctl.EnsureSysctlNetValue(loRpFilterStr, 2) != nil {
		parametersWithErrors = append(parametersWithErrors, loRpFilterStr)
	}

	if len(parametersWithErrors) > 0 {
		return fmt.Errorf("the following kernel parameters could not be verified / set: %v", parametersWithErrors)
	}
	return nil
}
