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
	"context"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/knftables"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/servicecidr"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/util/ipset"
	"antrea.io/antrea/pkg/agent/util/iptables"
	utilnetlink "antrea.io/antrea/pkg/agent/util/netlink"
	"antrea.io/antrea/pkg/agent/util/nftables"
	"antrea.io/antrea/pkg/agent/util/sysctl"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/env"
	utilip "antrea.io/antrea/pkg/util/ip"
)

const (
	vxlanPort  = 4789
	genevePort = 6081

	// Antrea managed ipset.
	// antreaPodIPSet contains all Per-Node IPAM Pod CIDRs of this cluster.
	antreaPodIPSet = "ANTREA-POD-IP"
	// antreaPodIP6Set contains all Per-Node IPAM IPv6 Pod CIDRs of this cluster.
	antreaPodIP6Set = "ANTREA-POD-IP6"

	// Antrea managed ipset. Max name length is 31 chars.
	// localAntreaFlexibleIPAMPodIPSet contains all AntreaFlexibleIPAM Pod IPs of this Node.
	localAntreaFlexibleIPAMPodIPSet = "LOCAL-FLEXIBLE-IPAM-POD-IP"
	// localAntreaFlexibleIPAMPodIP6Set contains all AntreaFlexibleIPAM Pod IPv6s of this Node.
	localAntreaFlexibleIPAMPodIP6Set = "LOCAL-FLEXIBLE-IPAM-POD-IP6"
	// clusterNodeIPSet contains all other Node IPs in the cluster.
	clusterNodeIPSet = "CLUSTER-NODE-IP"
	// clusterNodeIP6Set contains all other Node IP6s in the cluster.
	clusterNodeIP6Set = "CLUSTER-NODE-IP6"

	// Antrea managed ipsets for different types of Service IP addresses and ports.
	antreaNodePortIPSet    = "ANTREA-NODEPORT-IP"
	antreaNodePortIP6Set   = "ANTREA-NODEPORT-IP6"
	antreaExternalIPIPSet  = "ANTREA-EXTERNAL-IP"
	antreaExternalIPIP6Set = "ANTREA-EXTERNAL-IP6"

	// Antrea managed iptables chains.
	antreaForwardChain     = "ANTREA-FORWARD"
	antreaPreRoutingChain  = "ANTREA-PREROUTING"
	antreaPostRoutingChain = "ANTREA-POSTROUTING"
	antreaInputChain       = "ANTREA-INPUT"
	antreaOutputChain      = "ANTREA-OUTPUT"

	kubeProxyServiceChain = "KUBE-SERVICES"

	serviceIPv4CIDRKey = "serviceIPv4CIDRKey"
	serviceIPv6CIDRKey = "serviceIPv6CIDRKey"

	preNodeNetworkPolicyIngressRulesChain = "ANTREA-POL-PRE-INGRESS-RULES"
	preNodeNetworkPolicyEgressRulesChain  = "ANTREA-POL-PRE-EGRESS-RULES"

	// All the chains/sets/flowables are created inside our table, so they don't need any "antrea-" prefix of their own.

	// Flowtable and offload chains
	antreaNFTablesFlowtable           = "fastpath"
	antreaNFTablesChainForwardOffload = "forward-offload"
	antreaNFTablesSetPeerPodCIDR      = "peer-pod-cidr"

	// Raw chains for proxyAll
	antreaNFTablesRawChainPreroutingProxyAll = "raw-prerouting-proxy-all"
	antreaNFTablesRawChainOutputProxyAll     = "raw-output-proxy-all"

	// NAT chains for proxyAll
	antreaNFTablesNatChainPreroutingProxyAll  = "nat-prerouting-proxy-all"
	antreaNFTablesNatChainOutputProxyAll      = "nat-output-proxy-all"
	antreaNFTablesNatChainPostroutingProxyAll = "nat-postrouting-proxy-all"

	// NodePort and ExternalIP sets
	antreaNFTablesSetNodePort    = "nodeport"
	antreaNFTablesSetNodePort6   = "nodeport-6"
	antreaNFTablesSetExternalIP  = "externalip"
	antreaNFTablesSetExternalIP6 = "externalip-6"
)

// Client implements Interface.
var _ Interface = &Client{}

var (
	// globalVMAC is used in the IPv6 neighbor configuration to advertise ND solicitation for the IPv6 address of the
	// host gateway interface on other Nodes.
	globalVMAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")

	// The system auto-generated IPv6 link-local route always uses "fe80::/64" as the destination regardless of the
	// interface's global address's mask.
	_, llrCIDR, _ = net.ParseCIDR("fe80::/64")
)

// jumpToAntreaChainPattern matches iptables jump rules that have a comment enclosed in double quotes and target
// Antrea-managed chains.
var jumpToAntreaChainPattern = regexp.MustCompile(`--comment\s+"(Antrea:[^"]+)"\s+-j\s+(ANTREA-[A-Z0-9-]+)`)

// Client takes care of routing container packets in host network, coordinating ip route, ip rule, iptables and ipset.
type Client struct {
	nodeConfig             *config.NodeConfig
	networkConfig          *config.NetworkConfig
	noSNAT                 bool
	nodeSNATRandomFully    bool
	egressSNATRandomFully  bool
	iptablesHasRandomFully bool
	iptables               iptables.Interface
	nftables               *nftables.Client
	ipset                  ipset.Interface
	netlink                utilnetlink.Interface
	// nodeRoutes caches ip routes to remote Pods. It's a map of podCIDR to routes.
	nodeRoutes sync.Map
	// nodeNeighbors caches IPv6 Neighbors to remote host gateway
	nodeNeighbors sync.Map
	// markToSNATIP caches marks to SNAT IPs. It's used in Egress feature.
	markToSNATIP sync.Map
	// iptablesInitialized is used to notify when iptables initialization is done.
	iptablesInitialized chan struct{}
	proxyAll            bool
	// hostNetworkNFTables is only applicable to proxyAll for now.
	hostNetworkNFTables            bool
	connectUplinkToBridge          bool
	multicastEnabled               bool
	isCloudEKS                     bool
	nodeNetworkPolicyEnabled       bool
	nodeLatencyMonitorEnabled      bool
	egressEnabled                  bool
	hostNetworkAccelerationEnabled bool
	// serviceRoutes caches ip routes about Services.
	serviceRoutes sync.Map
	// serviceExternalIPReferences tracks the references of Service IP. The key is the Service IP and the value is
	// the set of ServiceInfo strings. Because a Service could have multiple ports and each port will generate a
	// ServicePort (which is the unit of the processing), a Service IP route may be required by several ServicePorts.
	// With the references, we install the configurations for a Service IP exactly once as long as it's used by any
	// ServicePorts and uninstall it exactly once when it's no longer used by any ServicePorts.
	// It applies to externalIP and LoadBalancerIP.
	serviceExternalIPReferences map[string]sets.Set[string]
	// serviceNeighbors caches neighbors.
	serviceNeighbors sync.Map
	// serviceIPSets caches ipsets about Services.
	serviceIPSets map[string]*sync.Map
	// serviceIPSets caches nftables sets about Services.
	serviceNFTablesSets map[string]*sync.Map
	// clusterNodeIPs stores the IPv4 of all other Nodes in the cluster
	clusterNodeIPs sync.Map
	// clusterNodeIP6s stores the IPv6 address of all other Nodes in the cluster. It is maintained but not consumed
	// until Multicast supports IPv6.
	clusterNodeIP6s sync.Map
	// egressRoutes caches ip routes about Egresses.
	egressRoutes sync.Map
	// egressRules caches ip rules about Egresses.
	egressRules sync.Map
	// egressNeighbors caches neighbors installed for Egress.
	egressNeighbors sync.Map
	// The latest calculated Service CIDRs can be got from serviceCIDRProvider.
	serviceCIDRProvider servicecidr.Interface
	// nodeNetworkPolicyIPSetsIPv4 caches all existing IPv4 ipsets for NodeNetworkPolicy.
	nodeNetworkPolicyIPSetsIPv4 sync.Map
	// nodeNetworkPolicyIPSetsIPv6 caches all existing IPv6 ipsets for NodeNetworkPolicy.
	nodeNetworkPolicyIPSetsIPv6 sync.Map
	// nodeNetworkPolicyIPTablesIPv4 caches all existing IPv4 iptables chains and rules for NodeNetworkPolicy.
	nodeNetworkPolicyIPTablesIPv4 sync.Map
	// nodeNetworkPolicyIPTablesIPv6 caches all existing IPv6 iptables chains and rules for NodeNetworkPolicy.
	nodeNetworkPolicyIPTablesIPv6 sync.Map
	// wireguardIPTablesIPv4 caches all existing IPv4 iptables chains and rules for WireGuard.
	wireguardIPTablesIPv4 sync.Map
	// wireguardIPTablesIPv6 caches all existing IPv6 iptables chains and rules for WireGuard.
	wireguardIPTablesIPv6 sync.Map
	// nodeLatencyMonitorIPTablesIPv4 caches all existing IPv4 iptables chains and rules for NodeLatencyMonitor.
	nodeLatencyMonitorIPTablesIPv4 sync.Map
	// nodeLatencyMonitorIPTablesIPv6 caches all existing IPv6 iptables chains and rules for NodeLatencyMonitor.
	nodeLatencyMonitorIPTablesIPv6 sync.Map
	// podCIDRNFTablesSetIPv4 caches all existing IPv4 Pod CIDRs stored in antreaNFTablesSetPeerPodCIDR.
	podCIDRNFTablesSetIPv4 sync.Map
	// podCIDRNFTablesSetIPv6 caches all existing IPv6 Pod CIDRs stored in antreaNFTablesSetPeerPodCIDR.
	podCIDRNFTablesSetIPv6 sync.Map
	// deterministic represents whether to write iptables chains and rules for NodeNetworkPolicy deterministically when
	// syncIPTables is called. Enabling it may carry a performance impact. It's disabled by default and should only be
	// used in testing.
	deterministic bool
	// wireguardPort is the port used for the WireGuard UDP tunnels. When WireGuard is enabled (used as the encryption
	// mode), we add iptables rules to the filter table to accept input and output UDP traffic destined to this port.
	wireguardPort int
}

// NewClient returns a route client.
func NewClient(networkConfig *config.NetworkConfig,
	noSNAT bool,
	proxyAll bool,
	connectUplinkToBridge bool,
	nodeNetworkPolicyEnabled bool,
	nodeLatencyMonitorEnabled bool,
	multicastEnabled bool,
	egressEnabled bool,
	nodeSNATRandomFully bool,
	egressSNATRandomFully bool,
	serviceCIDRProvider servicecidr.Interface,
	wireguardPort int) (*Client, error) {
	return &Client{
		networkConfig:               networkConfig,
		noSNAT:                      noSNAT,
		nodeSNATRandomFully:         nodeSNATRandomFully,
		egressSNATRandomFully:       egressSNATRandomFully,
		proxyAll:                    proxyAll,
		multicastEnabled:            multicastEnabled,
		connectUplinkToBridge:       connectUplinkToBridge,
		nodeNetworkPolicyEnabled:    nodeNetworkPolicyEnabled,
		nodeLatencyMonitorEnabled:   nodeLatencyMonitorEnabled,
		egressEnabled:               egressEnabled,
		ipset:                       ipset.NewClient(),
		netlink:                     &netlink.Handle{},
		isCloudEKS:                  env.IsCloudEKS(),
		serviceCIDRProvider:         serviceCIDRProvider,
		serviceExternalIPReferences: make(map[string]sets.Set[string]),
		wireguardPort:               wireguardPort,
	}, nil
}

// Initialize initializes all infrastructures required to route container packets in host network.
// It is idempotent and can be safely called on every startup.
func (c *Client) Initialize(nodeConfig *config.NodeConfig, done func()) error {
	c.nodeConfig = nodeConfig

	encapMode := c.networkConfig.TrafficEncapMode
	c.hostNetworkAccelerationEnabled = c.networkConfig.EnableHostNetworkAcceleration &&
		(encapMode == config.TrafficEncapModeNoEncap || encapMode == config.TrafficEncapModeHybrid)

	c.hostNetworkNFTables = c.networkConfig.HostNetworkMode == config.HostNetworkModeNFTables

	if c.proxyAll {
		if c.hostNetworkNFTables {
			c.serviceNFTablesSets = map[string]*sync.Map{
				antreaNFTablesSetNodePort:    {},
				antreaNFTablesSetNodePort6:   {},
				antreaNFTablesSetExternalIP:  {},
				antreaNFTablesSetExternalIP6: {},
			}
		} else {
			c.serviceIPSets = map[string]*sync.Map{
				antreaNodePortIPSet:    {},
				antreaNodePortIP6Set:   {},
				antreaExternalIPIPSet:  {},
				antreaExternalIPIP6Set: {},
			}
		}
	}

	c.iptablesInitialized = make(chan struct{})
	var err error
	// Sets up the ipset that will be used in iptables.
	if err = c.syncIPSet(); err != nil {
		return fmt.Errorf("failed to initialize ipset: %v", err)
	}

	c.iptables, err = iptables.New(c.networkConfig.IPv4Enabled, c.networkConfig.IPv6Enabled)
	if err != nil {
		return fmt.Errorf("error creating IPTables instance: %v", err)
	}
	c.iptablesHasRandomFully = c.iptables.HasRandomFully()
	if (c.nodeSNATRandomFully || c.egressSNATRandomFully) && !c.iptablesHasRandomFully {
		return fmt.Errorf("iptables does not support --random-fully for SNAT / MASQUERADE rules")
	}

	// Sets up the iptables infrastructure required to route packets in host network.
	// It's called in a goroutine because xtables lock may not be acquired immediately.
	go func() {
		klog.Info("Initializing iptables")
		defer done()
		defer close(c.iptablesInitialized)
		var backoffTime = 2 * time.Second
		for {
			if err := c.syncIPTables(true); err != nil {
				klog.Errorf("Failed to initialize iptables: %v - will retry in %v", err, backoffTime)
				time.Sleep(backoffTime)
				continue
			}
			break
		}
		klog.Info("Initialized iptables")
	}()

	if c.hostNetworkAccelerationEnabled || c.hostNetworkNFTables && c.proxyAll {
		nftables, err := nftables.New(c.networkConfig.IPv4Enabled, c.networkConfig.IPv6Enabled)
		if err != nil {
			if c.proxyAll && c.hostNetworkNFTables {
				// ProxyAll depends on nftables; fail if unavailable.
				return fmt.Errorf("failed to create nftables instance: %w", err)
			}
			// Host-network acceleration is optional; skip gracefully.
			if c.hostNetworkAccelerationEnabled {
				klog.ErrorS(err, "Failed to create nftables instance, skipping host network acceleration")
			}
		} else {
			c.nftables = nftables
			if err := c.syncNFTables(context.TODO()); err != nil {
				return fmt.Errorf("failed to initialize nftables: %w", err)
			}
		}
	}

	// Sets up the IP routes and IP rule required to route packets in host network.
	if err := c.initIPRoutes(); err != nil {
		return fmt.Errorf("failed to initialize ip routes: %v", err)
	}

	// Ensure IPv4 forwarding is enabled if it is a dual-stack or IPv4-only cluster.
	if c.nodeConfig.NodeIPv4Addr != nil {
		if err := sysctl.EnsureSysctlNetValue("ipv4/ip_forward", 1); err != nil {
			return fmt.Errorf("failed to enable IPv4 forwarding: %w", err)
		}
	}

	// Ensure IPv6 forwarding is enabled if it is a dual-stack or IPv6-only cluster.
	if c.nodeConfig.NodeIPv6Addr != nil {
		if err := sysctl.EnsureSysctlNetValue("ipv6/conf/all/forwarding", 1); err != nil {
			return fmt.Errorf("failed to enable IPv6 forwarding: %w", err)
		}
	}

	// In hybrid mode, traffic originating from remote Pod CIDRs is forwarded like this:
	//     remote Pods -> tunnel (remote Node OVS) -> tunnel (local Node OVS) -> antrea-gw0 (local Node) -> external network.
	//
	// To ensure reply packets follow a symmetric path, Antrea uses policy routing on the local Node. However, the
	// kernel's strict RPF check only validates source paths against the main routing table. Since the transport
	// interface (not antrea‑gw0) is listed as the next-hop for these routes, strict RPF drops the reply packets
	// (because policy routing is ignored by rp_filter). As a result, we set its rp_filter to loose mode (2).
	if c.egressEnabled && c.networkConfig.TrafficEncapMode == config.TrafficEncapModeHybrid {
		if err := util.EnsureRPFilterOnInterface(c.nodeConfig.GatewayConfig.Name, 2); err != nil {
			return fmt.Errorf("failed to set %s rp_filter to 2 (loose mode): %w", c.nodeConfig.GatewayConfig.Name, err)
		}
		klog.InfoS("Set Antrea gateway interface rp_filter to 2 (loose mode)", "interface", c.nodeConfig.GatewayConfig.Name)
	}

	// Set up the IP routes and sysctl parameters to support all Services in AntreaProxy.
	if c.proxyAll {
		if err := c.initServiceIPRoutes(); err != nil {
			return fmt.Errorf("failed to initialize Service IP routes: %v", err)
		}
	}
	// Set up the policy routing ip rule to support Egress in hybrid mode.
	if c.egressEnabled && c.networkConfig.TrafficEncapMode == config.TrafficEncapModeHybrid {
		if err := c.initEgressIPRules(); err != nil {
			return fmt.Errorf("failed to initialize ip rules for Egress in hybrid mode: %w", err)
		}
		if err := c.initEgressIPRoutes(); err != nil {
			return fmt.Errorf("failed to initialize IP routes for Egress in hybrid mode: %w", err)
		}
	}
	// Build static iptables rules for NodeNetworkPolicy.
	if c.nodeNetworkPolicyEnabled {
		c.initNodeNetworkPolicy()
	}
	if c.networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeWireGuard {
		c.initWireguard()
	}
	if c.nodeLatencyMonitorEnabled {
		c.initNodeLatencyRules()
	}

	return nil
}

// Run waits for iptables initialization, then periodically syncs ipsets, iptables/nftables, routes, neighbors, and
// policy rules. It will not return until ctx is cancelled.
func (c *Client) Run(ctx context.Context) {
	<-c.iptablesInitialized
	klog.InfoS("Starting host network configuration sync", "interval", SyncInterval)
	wait.UntilWithContext(ctx, c.syncNetworkConfig, SyncInterval)
}

// syncNetworkConfig is idempotent and can be safely called on every sync operation.
func (c *Client) syncNetworkConfig(ctx context.Context) {
	// Sync ipset before syncing iptables rules
	if err := c.syncIPSet(); err != nil {
		klog.ErrorS(err, "Failed to sync ipset")
		return
	}
	if err := c.syncIPTables(false); err != nil {
		klog.ErrorS(err, "Failed to sync iptables")
		return
	}
	if c.nftables != nil {
		if err := c.syncNFTables(ctx); err != nil {
			klog.ErrorS(err, "Failed to sync nftables")
		}
	}
	if err := c.syncRoute(); err != nil {
		klog.ErrorS(err, "Failed to sync route")
	}
	if err := c.syncNeighbor(); err != nil {
		klog.ErrorS(err, "Failed to sync neighbor")
	}
	if err := c.syncIPRule(); err != nil {
		klog.ErrorS(err, "Failed to sync ip rule")
	}

	klog.V(3).Info("Successfully synced network configuration")
}

type routeKey struct {
	linkIndex int
	dst       string
	gw        string
	tableID   int
}

func (c *Client) syncRoute() error {
	routeList, err := c.netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	routeKeys := sets.New[routeKey]()
	for i := range routeList {
		r := &routeList[i]
		if r.Dst == nil || r.Dst.IP.IsUnspecified() {
			continue
		}
		routeKeys.Insert(routeKey{
			linkIndex: r.LinkIndex,
			dst:       r.Dst.String(),
			gw:        r.Gw.String(),
			tableID:   r.Table,
		})
	}
	restoreRoute := func(route *netlink.Route) bool {
		if routeKeys.Has(routeKey{
			linkIndex: route.LinkIndex,
			dst:       route.Dst.String(),
			gw:        route.Gw.String(),
			tableID:   route.Table,
		}) {
			return true
		}
		if err := c.netlink.RouteReplace(route); err != nil {
			klog.ErrorS(err, "Failed to sync route", "Route", route)
			return false
		}
		return true
	}
	c.nodeRoutes.Range(func(_, v interface{}) bool {
		for _, route := range v.([]*netlink.Route) {
			if !restoreRoute(route) {
				return false
			}
		}
		return true
	})
	if c.proxyAll {
		c.serviceRoutes.Range(func(_, v interface{}) bool {
			route := v.(*netlink.Route)
			return restoreRoute(route)
		})
	}
	c.egressRoutes.Range(func(_, v any) bool {
		for _, route := range v.([]*netlink.Route) {
			if !restoreRoute(route) {
				return false
			}
		}
		return true
	})
	// These routes are installed automatically by the kernel when the address is configured on
	// the interface (with "proto kernel"). If these routes are deleted manually by mistake, we
	// restore them as part of this sync (without "proto kernel"). An alternative would be to
	// flap the interface, but this seems like a better approach.
	gwAutoconfRoutes := []*netlink.Route{}
	if c.nodeConfig.PodIPv4CIDR != nil {
		gwAutoconfRoutes = append(gwAutoconfRoutes, &netlink.Route{
			LinkIndex: c.nodeConfig.GatewayConfig.LinkIndex,
			Dst:       c.nodeConfig.PodIPv4CIDR,
			Src:       c.nodeConfig.GatewayConfig.IPv4,
			Scope:     netlink.SCOPE_LINK,
		})
	}
	if c.nodeConfig.PodIPv6CIDR != nil {
		// Here we assume the IPv6 link-local address always exists on antrea-gw0
		// to avoid unexpected issues in the IPv6 forwarding.
		gwAutoconfRoutes = append(gwAutoconfRoutes, &netlink.Route{
			LinkIndex: c.nodeConfig.GatewayConfig.LinkIndex,
			Dst:       c.nodeConfig.PodIPv6CIDR,
			Src:       c.nodeConfig.GatewayConfig.IPv6,
			Scope:     netlink.SCOPE_LINK,
		},
			// Restore the IPv6 link-local route.
			&netlink.Route{
				LinkIndex: c.nodeConfig.GatewayConfig.LinkIndex,
				Dst:       llrCIDR,
				Scope:     netlink.SCOPE_LINK,
			},
		)
	}
	for _, route := range gwAutoconfRoutes {
		restoreRoute(route)
	}
	return nil
}

type neighborKey struct {
	ip  string
	mac string
}

// syncNeighbor ensures that necessary neighbors exist on the Antrea gateway interface, as some routes managed by Antrea
// depend on these neighbors.
func (c *Client) syncNeighbor() error {
	msg := netlink.Ndmsg{
		Family: netlink.FAMILY_ALL,
		Index:  uint32(c.nodeConfig.GatewayConfig.LinkIndex),
		State:  netlink.NUD_PERMANENT,
	}
	neighborList, err := c.netlink.NeighListExecute(msg)
	if err != nil {
		return err
	}
	neighborKeys := sets.New[neighborKey]()
	for i := range neighborList {
		n := neighborList[i]
		neighborKeys.Insert(neighborKey{
			ip:  n.IP.String(),
			mac: n.HardwareAddr.String(),
		})
	}
	restoreNeighbor := func(neighbor *netlink.Neigh) bool {
		if neighborKeys.Has(neighborKey{
			ip:  neighbor.IP.String(),
			mac: neighbor.HardwareAddr.String(),
		}) {
			return true
		}
		if err := c.netlink.NeighSet(neighbor); err != nil {
			klog.ErrorS(err, "failed to sync neighbor", "Neighbor", neighbor)
			return false
		}
		return true
	}
	c.nodeNeighbors.Range(func(_, v interface{}) bool {
		return restoreNeighbor(v.(*netlink.Neigh))
	})
	if c.proxyAll {
		c.serviceNeighbors.Range(func(_, v interface{}) bool {
			return restoreNeighbor(v.(*netlink.Neigh))
		})
	}
	if c.egressEnabled && c.networkConfig.TrafficEncapMode == config.TrafficEncapModeHybrid {
		c.egressNeighbors.Range(func(_, v interface{}) bool {
			return restoreNeighbor(v.(*netlink.Neigh))
		})
	}

	return nil
}

type ruleKey struct {
	table  int
	mark   uint32
	mask   uint32
	family int
}

func generateRuleKey(rule *netlink.Rule) ruleKey {
	var mask uint32
	if rule.Mask != nil {
		mask = *rule.Mask
	} else {
		mask = ^uint32(0)
	}
	return ruleKey{
		table:  rule.Table,
		mark:   rule.Mark,
		mask:   mask,
		family: rule.Family,
	}
}

// syncIPRule ensures that the necessary ip rules required by Antrea exist.
func (c *Client) syncIPRule() error {
	ruleList, err := c.netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	ruleKeys := sets.New[ruleKey]()
	for i := range ruleList {
		rule := ruleList[i]
		ruleKeys.Insert(generateRuleKey(&rule))
	}
	restoreRule := func(rule *netlink.Rule) bool {
		if ruleKeys.Has(generateRuleKey(rule)) {
			return true
		}
		if err := c.netlink.RuleAdd(rule); err != nil {
			klog.ErrorS(err, "Failed to sync ip rule", "rule", rule)
			return false
		}
		return true
	}
	c.egressRules.Range(func(_, v interface{}) bool {
		return restoreRule(v.(*netlink.Rule))
	})

	return nil
}

// syncIPSet ensures that the required ipset exists, and it has the initial members.
func (c *Client) syncIPSet() error {
	// Create the ipsets to store all Pod CIDRs for constructing full-mesh routing in encap/noEncap/hybrid modes. In
	// networkPolicyOnly mode, Antrea is not responsible for IPAM, so CIDRs are not available and the ipsets should not
	// be created.
	if !c.networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		if err := c.ipset.CreateIPSet(antreaPodIPSet, ipset.HashNet, false); err != nil {
			return err
		}
		if err := c.ipset.CreateIPSet(antreaPodIP6Set, ipset.HashNet, true); err != nil {
			return err
		}
		// Loop all valid Pod CIDRs and add them into the corresponding ipset.
		for _, podCIDR := range []*net.IPNet{c.nodeConfig.PodIPv4CIDR, c.nodeConfig.PodIPv6CIDR} {
			if podCIDR != nil {
				ipsetName := getIPSetName(podCIDR.IP)
				if err := c.ipset.AddEntry(ipsetName, podCIDR.String()); err != nil {
					return err
				}
			}
		}
	}

	// AntreaProxy proxyAll is available in all traffic modes. If proxyAll is enabled, create the ipsets to store the
	// pairs of Node IP and NodePort.
	if c.proxyAll && !c.hostNetworkNFTables {
		for ipsetName, ipsetEntries := range c.serviceIPSets {
			isIPv6 := ipsetName == antreaNodePortIP6Set || ipsetName == antreaExternalIPIP6Set

			var ipsetType ipset.SetType
			if ipsetName == antreaNodePortIP6Set || ipsetName == antreaNodePortIPSet {
				ipsetType = ipset.HashIPPort
			} else {
				ipsetType = ipset.HashIP
			}

			if err := c.ipset.CreateIPSet(ipsetName, ipsetType, isIPv6); err != nil {
				return err
			}
			ipsetEntries.Range(func(k, _ interface{}) bool {
				ipsetEntry := k.(string)
				if err := c.ipset.AddEntry(ipsetName, ipsetEntry); err != nil {
					return false
				}
				return true
			})
		}
	}

	// AntreaIPAM is available in noEncap mode. There is a validation in Antrea configuration about this traffic mode
	// when AntreaIPAM is enabled.
	if c.connectUplinkToBridge {
		if err := c.ipset.CreateIPSet(localAntreaFlexibleIPAMPodIPSet, ipset.HashIP, false); err != nil {
			return err
		}
		if err := c.ipset.CreateIPSet(localAntreaFlexibleIPAMPodIP6Set, ipset.HashIP, true); err != nil {
			return err
		}
	}

	// Multicast is available in encap/noEncap/hybrid mode, and the ipsets are consumed in encap mode.
	if c.multicastEnabled && c.networkConfig.TrafficEncapMode.SupportsEncap() {
		if err := c.ipset.CreateIPSet(clusterNodeIPSet, ipset.HashIP, false); err != nil {
			return err
		}
		if err := c.ipset.CreateIPSet(clusterNodeIP6Set, ipset.HashIP, true); err != nil {
			return err
		}
		c.clusterNodeIPs.Range(func(_, v interface{}) bool {
			ipsetEntry := v.(string)
			if err := c.ipset.AddEntry(clusterNodeIPSet, ipsetEntry); err != nil {
				return false
			}
			return true
		})
		c.clusterNodeIP6s.Range(func(_, v interface{}) bool {
			ipSetEntry := v.(string)
			if err := c.ipset.AddEntry(clusterNodeIP6Set, ipSetEntry); err != nil {
				return false
			}
			return true
		})
	}

	// NodeNetworkPolicy is available in all traffic modes.
	if c.nodeNetworkPolicyEnabled {
		c.nodeNetworkPolicyIPSetsIPv4.Range(func(key, value any) bool {
			ipsetName := key.(string)
			ipsetEntries := value.(sets.Set[string])
			if err := c.ipset.CreateIPSet(ipsetName, ipset.HashNet, false); err != nil {
				return false
			}
			for ipsetEntry := range ipsetEntries {
				if err := c.ipset.AddEntry(ipsetName, ipsetEntry); err != nil {
					return false
				}
			}
			return true
		})
		c.nodeNetworkPolicyIPSetsIPv6.Range(func(key, value any) bool {
			ipsetName := key.(string)
			ipsetEntries := value.(sets.Set[string])
			if err := c.ipset.CreateIPSet(ipsetName, ipset.HashNet, true); err != nil {
				return false
			}
			for ipsetEntry := range ipsetEntries {
				if err := c.ipset.AddEntry(ipsetName, ipsetEntry); err != nil {
					return false
				}
			}
			return true
		})
	}

	return nil
}

func getIPSetName(ip net.IP) string {
	if ip.To4() == nil {
		return antreaPodIP6Set
	}
	return antreaPodIPSet
}

func getNodePortIPSetName(isIPv6 bool) string {
	if isIPv6 {
		return antreaNodePortIP6Set
	} else {
		return antreaNodePortIPSet
	}
}

func getExternalIPIPSetName(isIPv6 bool) string {
	if isIPv6 {
		return antreaExternalIPIP6Set
	} else {
		return antreaExternalIPIPSet
	}
}

func getNodePortNFTablesSet(isIPv6 bool) string {
	if isIPv6 {
		return antreaNFTablesSetNodePort6
	} else {
		return antreaNFTablesSetNodePort
	}
}

func getExternalIPNFTablesSet(isIPv6 bool) string {
	if isIPv6 {
		return antreaNFTablesSetExternalIP6
	} else {
		return antreaNFTablesSetExternalIP
	}
}

func getLocalAntreaFlexibleIPAMPodIPSetName(isIPv6 bool) string {
	if isIPv6 {
		return localAntreaFlexibleIPAMPodIP6Set
	} else {
		return localAntreaFlexibleIPAMPodIPSet
	}
}

// writeEKSMangleRules writes an additional iptables mangle rule to the
// iptablesData buffer, to set the traffic mark to the connection mark for
// traffic coming out of the gateway. This rule is needed for 2 cases:
//   - for the reverse path for NodePort Service traffic (see
//     https://github.com/antrea-io/antrea/issues/678).
//   - for Pod-to-external traffic that needs to be SNATed (see
//     https://github.com/antrea-io/antrea/issues/3946).
func (c *Client) writeEKSMangleRules(iptablesData *bytes.Buffer) {
	// TODO: the following should be taking into account:
	//   1) this rule is only needed if AWS_VPC_CNI_NODE_PORT_SUPPORT is set
	//   to true (which is the default) or if AWS_VPC_K8S_CNI_EXTERNALSNAT
	//   is set to false (which is also the default). If both settings are
	//   changed, we do not need to install the rule.
	//   2) this option is not documented but the mark value can be
	//   configured with AWS_VPC_K8S_CNI_CONNMARK.
	// While we do not have access to these environment variables, we could
	// look for existing rules installed by the AWS VPC CNI, and determine
	// whether we need to install this rule.
	klog.V(2).InfoS("Add iptables mangle rules for EKS")
	writeLine(iptablesData, []string{
		"-A", antreaPreRoutingChain,
		"-m", "comment", "--comment", `"Antrea: AWS, primary ENI"`,
		"-i", c.nodeConfig.GatewayConfig.Name, "-j", "CONNMARK",
		"--restore-mark", "--nfmask", "0x80", "--ctmask", "0x80",
	}...)
}

// writeEKSNATRules writes additional iptables nat rules to the iptablesData
// buffer. The first rule sets the connection mark for Pod-to-external traffic
// that needs to be SNATed. Without the mark, this traffic is not routed using
// the correct route table for Pods getting an IP address from a secondary
// network interface (ENI). The second rule restores the packet mark from the
// connection mark. That rule will only apply to the first packet of the
// connection. For subsequent packets, the rule installed buy writeEKSMangleRule
// will take care of restoring the mark. We need that rule because the mangle
// table is traversed before the nat table.
// See https://docs.aws.amazon.com/eks/latest/userguide/external-snat.html and
// https://github.com/antrea-io/antrea/issues/3946 for more details.
func (c *Client) writeEKSNATRules(iptablesData *bytes.Buffer) {
	// TODO: just like for writeEKSMangleRule, these rules should ideally be
	// installed conditionally, when AWS_VPC_K8S_CNI_EXTERNALSNAT is set to
	// false (which is the default value).
	klog.V(2).InfoS("Add iptables nat rules for EKS")
	writeLine(iptablesData, []string{
		"-A", antreaPreRoutingChain,
		"-i", c.nodeConfig.GatewayConfig.Name,
		"-m", "comment", "--comment", `"Antrea: AWS, outbound connections"`,
		"-j", "AWS-CONNMARK-CHAIN-0",
	}...)
	// The AWS VPC CNI already installs the same rule in the PREROUTING
	// chain. However, that rule will typically be visited before the
	// ANTREA-PREROUTING chain, hence we need to install our own copy of the
	// rule.
	writeLine(iptablesData, []string{
		"-A", antreaPreRoutingChain,
		"-m", "comment", "--comment", `"Antrea: AWS, CONNMARK (first packet)"`,
		"-j", "CONNMARK", "--restore-mark", "--nfmask", "0x80", "--ctmask", "0x80",
	}...)
}

func (c *Client) getIPProtocol() iptables.Protocol {
	switch {
	case c.networkConfig.IPv4Enabled && c.networkConfig.IPv6Enabled:
		return iptables.ProtocolDual
	case c.networkConfig.IPv6Enabled:
		return iptables.ProtocolIPv6
	default:
		return iptables.ProtocolIPv4
	}
}

// Create the antrea managed chains and link them to built-in chains.
// We cannot use iptables-restore for these jump rules because there
// are non antrea managed rules in built-in chains.
type jumpRule struct {
	table    string
	srcChain string
	dstChain string
	comment  string
	insert   bool
}

type jumpRuleKey struct {
	table    string
	srcChain string
	dstChain string
	comment  string
}

func (j *jumpRule) getKey() jumpRuleKey {
	return jumpRuleKey{
		table:    j.table,
		srcChain: j.srcChain,
		dstChain: j.dstChain,
		comment:  j.comment,
	}
}

func (c *Client) removeUnexpectedAntreaJumpRule(protocol iptables.Protocol, jumpRule jumpRule) error {
	// List all the existing rules of the table and the chain where the Antrea jump rule will be added.
	allExistingRules, err := c.iptables.ListRules(protocol, jumpRule.table, jumpRule.srcChain)
	if err != nil {
		return err
	}

	// Construct keywords to identify Antrea and kube-proxy jump rules.
	antreaJumpRuleKeyword := fmt.Sprintf("-j %s", jumpRule.dstChain)
	kubeProxyJumpRuleKeyword := fmt.Sprintf("-j %s", kubeProxyServiceChain)

	for ipProtocol, rules := range allExistingRules {
		var antreaJumpRuleIndex, kubeProxyJumpRuleIndex = -1, -1

		for index, rule := range rules {
			// Check if the current rule is the Antrea jump rule to be added.
			if strings.Contains(rule, antreaJumpRuleKeyword) {
				antreaJumpRuleIndex = index
				// Check if the current rule is the kube-proxy jump rule.
			} else if strings.Contains(rule, kubeProxyJumpRuleKeyword) {
				kubeProxyJumpRuleIndex = index
			}
		}
		// If the Antrea jump rule is installed after the kube-proxy jump rule, which is not expected, delete the
		// existing Antrea jump rule to ensure that a new one will be installed before the kube-proxy one when syncing iptables.
		if antreaJumpRuleIndex != -1 && kubeProxyJumpRuleIndex != -1 && antreaJumpRuleIndex > kubeProxyJumpRuleIndex {
			ruleSpec := []string{"-j", jumpRule.dstChain, "-m", "comment", "--comment", jumpRule.comment}
			if err := c.iptables.DeleteRule(ipProtocol, jumpRule.table, jumpRule.srcChain, ruleSpec); err != nil {
				return err
			}
		}
	}
	return nil
}

// syncIPTables ensure that the iptables infrastructure we use is set up.
// It's idempotent and can safely be called on every startup.
func (c *Client) syncIPTables(cleanupStaleJumpRules bool) error {
	ipProtocol := c.getIPProtocol()
	jumpRules := []jumpRule{
		{iptables.RawTable, iptables.PreRoutingChain, antreaPreRoutingChain, "Antrea: jump to Antrea prerouting rules", false},
		{iptables.RawTable, iptables.OutputChain, antreaOutputChain, "Antrea: jump to Antrea output rules", false},
		{iptables.FilterTable, iptables.ForwardChain, antreaForwardChain, "Antrea: jump to Antrea forwarding rules", false},
		{iptables.NATTable, iptables.PostRoutingChain, antreaPostRoutingChain, "Antrea: jump to Antrea postrouting rules", false},
		{iptables.MangleTable, iptables.PreRoutingChain, antreaPreRoutingChain, "Antrea: jump to Antrea prerouting rules", false},
		{iptables.MangleTable, iptables.OutputChain, antreaOutputChain, "Antrea: jump to Antrea output rules", false},
	}
	if c.proxyAll && !c.hostNetworkNFTables || c.isCloudEKS {
		jumpRules = append(jumpRules, jumpRule{iptables.NATTable, iptables.PreRoutingChain, antreaPreRoutingChain, "Antrea: jump to Antrea prerouting rules", c.proxyAll})
	}
	if c.proxyAll && !c.hostNetworkNFTables {
		jumpRules = append(jumpRules, jumpRule{iptables.NATTable, iptables.OutputChain, antreaOutputChain, "Antrea: jump to Antrea output rules", true})
	}
	if c.nodeNetworkPolicyEnabled || c.networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeWireGuard {
		jumpRules = append(jumpRules, jumpRule{iptables.FilterTable, iptables.InputChain, antreaInputChain, "Antrea: jump to Antrea input rules", false})
		jumpRules = append(jumpRules, jumpRule{iptables.FilterTable, iptables.OutputChain, antreaOutputChain, "Antrea: jump to Antrea output rules", false})
	}
	if c.egressEnabled && c.networkConfig.TrafficEncapMode == config.TrafficEncapModeHybrid {
		jumpRules = append(jumpRules, jumpRule{iptables.MangleTable, iptables.PostRoutingChain, antreaPostRoutingChain, "Antrea: jump to Antrea postrouting rules", false})
	}

	jumpRuleKeys := sets.New[jumpRuleKey]()
	for _, rule := range jumpRules {
		if err := c.iptables.EnsureChain(ipProtocol, rule.table, rule.dstChain); err != nil {
			return err
		}
		ruleSpec := []string{"-j", rule.dstChain, "-m", "comment", "--comment", rule.comment}
		if rule.insert {
			if err := c.removeUnexpectedAntreaJumpRule(ipProtocol, rule); err != nil {
				return err
			}
			if err := c.iptables.InsertRule(ipProtocol, rule.table, rule.srcChain, ruleSpec); err != nil {
				return err
			}
		} else {
			if err := c.iptables.AppendRule(ipProtocol, rule.table, rule.srcChain, ruleSpec); err != nil {
				return err
			}
		}
		if cleanupStaleJumpRules {
			jumpRuleKeys.Insert(rule.getKey())
		}
	}

	if cleanupStaleJumpRules {
		existingJumpRuleKeys := c.getJumpRuleKeys(ipProtocol)
		for key := range existingJumpRuleKeys {
			if !jumpRuleKeys.Has(key) {
				err := c.iptables.DeleteRule(ipProtocol, key.table, key.srcChain, []string{"-j", key.dstChain, "-m", "comment", "--comment", key.comment})
				if err != nil {
					klog.ErrorS(err, "Failed to delete orphan jump rule", "table", key.table, "srcChain", key.srcChain, "dstChain", key.dstChain)
				}
				err = c.iptables.DeleteChain(ipProtocol, key.table, key.dstChain)
				if err != nil {
					klog.ErrorS(err, "Failed to delete orphan chain", "table", key.table, "dstChain", key.dstChain)
				}
			}
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

	addFilterRulesToChain := func(iptablesRulesByChain map[string][]string, m *sync.Map) {
		m.Range(func(key, value interface{}) bool {
			chain := key.(string)
			rules := value.([]string)
			iptablesRulesByChain[chain] = append(iptablesRulesByChain[chain], rules...)
			return true
		})
	}

	iptablesFilterRulesByChainV4 := make(map[string][]string)
	// Install the static rules (WireGuard + NodeLatencyMonitor) before the dynamic rules (e.g., NodeNetworkPolicy)
	// for performance reasons.
	addFilterRulesToChain(iptablesFilterRulesByChainV4, &c.nodeLatencyMonitorIPTablesIPv4)
	addFilterRulesToChain(iptablesFilterRulesByChainV4, &c.wireguardIPTablesIPv4)
	addFilterRulesToChain(iptablesFilterRulesByChainV4, &c.nodeNetworkPolicyIPTablesIPv4)

	iptablesFilterRulesByChainV6 := make(map[string][]string)
	addFilterRulesToChain(iptablesFilterRulesByChainV6, &c.nodeLatencyMonitorIPTablesIPv6)
	addFilterRulesToChain(iptablesFilterRulesByChainV6, &c.wireguardIPTablesIPv6)
	addFilterRulesToChain(iptablesFilterRulesByChainV6, &c.nodeNetworkPolicyIPTablesIPv6)

	// Use iptables-restore to configure IPv4 settings.
	if c.networkConfig.IPv4Enabled {
		iptablesData := c.restoreIptablesData(c.nodeConfig.PodIPv4CIDR,
			antreaPodIPSet,
			localAntreaFlexibleIPAMPodIPSet,
			antreaNodePortIPSet,
			antreaExternalIPIPSet,
			clusterNodeIPSet,
			config.VirtualNodePortDNATIPv4,
			config.VirtualServiceIPv4,
			snatMarkToIPv4,
			iptablesFilterRulesByChainV4,
			false)

		// Setting --noflush to keep the previous contents (i.e. non antrea managed chains) of the tables.
		if err := c.iptables.Restore(iptablesData.String(), false, false); err != nil {
			return err
		}
	}

	// Use ip6tables-restore to configure IPv6 settings.
	if c.networkConfig.IPv6Enabled {
		iptablesData := c.restoreIptablesData(c.nodeConfig.PodIPv6CIDR,
			antreaPodIP6Set,
			localAntreaFlexibleIPAMPodIP6Set,
			antreaNodePortIP6Set,
			antreaExternalIPIP6Set,
			clusterNodeIP6Set,
			config.VirtualNodePortDNATIPv6,
			config.VirtualServiceIPv6,
			snatMarkToIPv6,
			iptablesFilterRulesByChainV6,
			true)
		// Setting --noflush to keep the previous contents (i.e. non antrea managed chains) of the tables.
		if err := c.iptables.Restore(iptablesData.String(), false, true); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) getJumpRuleKeys(ipProtocol iptables.Protocol) sets.Set[jumpRuleKey] {
	allChains := map[string][]string{
		iptables.RawTable:    {iptables.PreRoutingChain, iptables.OutputChain},
		iptables.MangleTable: {iptables.PreRoutingChain, iptables.InputChain, iptables.ForwardChain, iptables.OutputChain, iptables.PostRoutingChain},
		iptables.NATTable:    {iptables.PreRoutingChain, iptables.InputChain, iptables.OutputChain, iptables.PostRoutingChain},
		iptables.FilterTable: {iptables.InputChain, iptables.ForwardChain, iptables.OutputChain},
	}
	jumpRuleKeys := sets.New[jumpRuleKey]()

	for table, chains := range allChains {
		for _, chain := range chains {
			allRules, err := c.iptables.ListRules(ipProtocol, table, chain)
			if err != nil {
				klog.ErrorS(err, "Failed to list rules", "table", table, "chain", chain)
				continue
			}
			for _, rules := range allRules {
				for _, rule := range rules {
					matches := jumpToAntreaChainPattern.FindStringSubmatch(rule)
					if len(matches) > 2 {
						key := jumpRuleKey{
							table:    table,
							srcChain: chain,
							dstChain: matches[2],
							comment:  matches[1],
						}
						jumpRuleKeys.Insert(key)
					}
				}
			}
		}
	}
	return jumpRuleKeys
}

func (c *Client) restoreIptablesData(podCIDR *net.IPNet,
	podIPSet,
	localAntreaFlexibleIPAMPodIPSet,
	nodePortIPSet,
	externalIPSet,
	clusterNodeIPSet string,
	nodePortDNATVirtualIP,
	serviceVirtualIP net.IP,
	snatMarkToIP map[uint32]net.IP,
	iptablesFiltersRuleByChain map[string][]string,
	isIPv6 bool) *bytes.Buffer {
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
		switch c.networkConfig.TunnelType {
		case ovsconfig.GeneveTunnel:
			udpPort = genevePort
		case ovsconfig.VXLANTunnel:
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

		// Note: Multicast can only work with IPv4 for now. Remove condition "!isIPv6" in the future after
		// IPv6 is supported.
		if c.multicastEnabled && !isIPv6 && c.networkConfig.TrafficEncapMode.SupportsEncap() {
			// Drop the multicast packets forwarded from other Nodes in the cluster. This is because
			// the packet sent out from the sender Pod is already received via tunnel port with encap mode,
			// and the one forwarded via the underlay network is to send to external receivers
			writeLine(iptablesData, []string{
				"-A", antreaPreRoutingChain,
				"-m", "comment", "--comment", `"Antrea: drop Pod multicast traffic forwarded via underlay network"`,
				"-m", "set", "--match-set", clusterNodeIPSet, "src",
				"-d", types.McastCIDR.String(),
				"-j", iptables.DropTarget,
			}...)
		}
	}

	if c.proxyAll && !c.hostNetworkNFTables {
		// This rule is to bypass conntrack for packets sourced from external and destined to externalIPs, which also
		// results in bypassing the chains managed by Antrea Proxy and kube-proxy in nat table.
		writeLine(iptablesData, []string{
			"-A", antreaPreRoutingChain,
			"-m", "comment", "--comment", `"Antrea: do not track request packets destined to external IPs"`,
			"-m", "set", "--match-set", externalIPSet, "dst",
			"-j", iptables.NotrackTarget,
		}...)
		// This rule is to bypass conntrack for packets sourced from externalIPs, which also results in bypassing the
		// chains managed by Antrea Proxy and kube-proxy in nat table.
		writeLine(iptablesData, []string{
			"-A", antreaPreRoutingChain,
			"-m", "comment", "--comment", `"Antrea: do not track reply packets sourced from external IPs"`,
			"-m", "set", "--match-set", externalIPSet, "src",
			"-j", iptables.NotrackTarget,
		}...)
		// This rule is to bypass conntrack for packets sourced from local and destined to externalIPs, which also
		// results in bypassing the chains managed by Antrea Proxy and kube-proxy in nat table.
		writeLine(iptablesData, []string{
			"-A", antreaOutputChain,
			"-m", "comment", "--comment", `"Antrea: do not track request packets destined to external IPs"`,
			"-m", "set", "--match-set", externalIPSet, "dst",
			"-j", iptables.NotrackTarget,
		}...)
	}
	writeLine(iptablesData, "COMMIT")

	// Write head lines anyway so the undesired rules can be deleted when noEncap -> encap.
	writeLine(iptablesData, "*mangle")
	writeLine(iptablesData, iptables.MakeChainLine(antreaPreRoutingChain))
	writeLine(iptablesData, iptables.MakeChainLine(antreaOutputChain))
	if c.egressEnabled && c.networkConfig.TrafficEncapMode == config.TrafficEncapModeHybrid {
		writeLine(iptablesData, iptables.MakeChainLine(antreaPostRoutingChain))
	}

	// When Antrea is used to enforce NetworkPolicies in EKS, additional iptables
	// mangle rules are required. See https://github.com/antrea-io/antrea/issues/678.
	// These rules are only needed for IPv4.
	if c.isCloudEKS && !isIPv6 {
		c.writeEKSMangleRules(iptablesData)
	}

	if c.egressEnabled && c.networkConfig.TrafficEncapMode == config.TrafficEncapModeHybrid {
		writeLine(iptablesData, []string{
			"-A", antreaPreRoutingChain,
			"-m", "comment", "--comment", `"Antrea: restore fwmark from connmark for reply Egress packets to remote Pods"`,
			"-m", "conntrack", "--ctstate", "ESTABLISHED", // Match packets from established connections.
			"-m", "conntrack", "--ctdir", "REPLY", // Match reply packets.
			// Match packets with conntrack mark.
			"-m", "connmark", "--mark", fmt.Sprintf("%#08x/%#08x", types.EgressNoEncapReturnToRemoteMark, types.EgressNoEncapReturnToRemoteMark),
			// Restore fwmark from the conntrack mark.
			"-j", "CONNMARK", "--restore-mark", "--nfmask", fmt.Sprintf("%#08x", types.EgressNoEncapReturnToRemoteMark), "--ctmask", fmt.Sprintf("%#08x", types.EgressNoEncapReturnToRemoteMark),
		}...)
		writeLine(iptablesData, []string{
			"-A", antreaPreRoutingChain,
			"-m", "comment", "--comment", `"Antrea: persist connmark for the first request Egress packet from remote Pods"`,
			"-i", c.nodeConfig.GatewayConfig.Name,
			"!", "-s", podCIDR.String(), // Don't match packets from local Pods.
			"-m", "conntrack", "--ctstate", "NEW", // Match the first packet.
			// Match packets whose fwmark value (0–7) is non-zero. In the OVS pipeline, this mark is set for Egress connections.
			"-m", "mark", "!", "--mark", fmt.Sprintf("%#08x/%#08x", 0, types.SNATIPMarkMask),
			// Load EgressNoEncapReturnToRemoteMark into the conntrack mark so it persists for the lifetime of the Egress connection.
			"-j", "CONNMARK", "--set-mark", fmt.Sprintf("%#08x/%#08x", types.EgressNoEncapReturnToRemoteMark, types.EgressNoEncapReturnToRemoteMark),
		}...)
		writeLine(iptablesData, []string{
			"-A", antreaPostRoutingChain,
			"-m", "comment", "--comment", `"Antrea: clear fwmark from reply Egress packets to remote Pods"`,
			"-m", "conntrack", "--ctstate", "ESTABLISHED", // Match packets from established connections.
			"-m", "conntrack", "--ctdir", "REPLY", // Match reply packets.
			// Clear the fwmark EgressNoEncapReturnToRemoteMark from the packet to avoid that the fwmark mark may
			// interfere with source IP selection when the packets are encapsulated by OVS flow-based tunnel.
			"-j", "MARK", "--set-xmark", fmt.Sprintf("0x0/%#08x", types.EgressNoEncapReturnToRemoteMark),
		}...)
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
	if c.connectUplinkToBridge {
		writeLine(iptablesData, []string{
			"-A", antreaOutputChain,
			"-m", "comment", "--comment", `"Antrea: mark LOCAL output packets"`,
			"-m", "addrtype", "--src-type", "LOCAL",
			"-o", c.nodeConfig.OVSBridge,
			"-j", iptables.MarkTarget, "--or-mark", fmt.Sprintf("%#08x", types.HostLocalSourceMark),
		}...)
	}
	if c.egressEnabled && c.networkConfig.TrafficEncapMode == config.TrafficEncapModeHybrid {
		writeLine(iptablesData, []string{
			"-A", antreaOutputChain,
			"-m", "comment", "--comment", `"Antrea: restore fwmark from connmark for reply Egress packets to remote Pods"`,
			"-m", "conntrack", "--ctstate", "ESTABLISHED", // Match packets from established connections.
			"-m", "conntrack", "--ctdir", "REPLY", // Match reply packets.
			// Match packets with conntrack mark.
			"-m", "connmark", "--mark", fmt.Sprintf("%#08x/%#08x", types.EgressNoEncapReturnToRemoteMark, types.EgressNoEncapReturnToRemoteMark),
			// Restore fwmark from the conntrack mark.
			"-j", "CONNMARK", "--restore-mark", "--nfmask", fmt.Sprintf("%#08x", types.EgressNoEncapReturnToRemoteMark), "--ctmask", fmt.Sprintf("%#08x", types.EgressNoEncapReturnToRemoteMark),
		}...)
	}
	writeLine(iptablesData, "COMMIT")

	writeLine(iptablesData, "*filter")
	writeLine(iptablesData, iptables.MakeChainLine(antreaForwardChain))

	var nodeNetworkPolicyIPTablesChains []string
	for chain := range iptablesFiltersRuleByChain {
		nodeNetworkPolicyIPTablesChains = append(nodeNetworkPolicyIPTablesChains, chain)
	}
	if c.deterministic {
		sort.Strings(nodeNetworkPolicyIPTablesChains)
	}
	for _, chain := range nodeNetworkPolicyIPTablesChains {
		writeLine(iptablesData, iptables.MakeChainLine(chain))
	}

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
	if c.connectUplinkToBridge {
		// Add accept rules for local AntreaFlexibleIPAM
		// AntreaFlexibleIPAM Pods -> HostPort Pod
		// AntreaFlexibleIPAM Pods -> NodePort Service -> Backend Pod
		writeLine(iptablesData, []string{
			"-A", antreaForwardChain,
			"-m", "comment", "--comment", `"Antrea: accept packets from local AntreaFlexibleIPAM Pods"`,
			"-m", "set", "--match-set", localAntreaFlexibleIPAMPodIPSet, "src",
			"-j", iptables.AcceptTarget,
		}...)
		writeLine(iptablesData, []string{
			"-A", antreaForwardChain,
			"-m", "comment", "--comment", `"Antrea: accept packets to local AntreaFlexibleIPAM Pods"`,
			"-m", "set", "--match-set", localAntreaFlexibleIPAMPodIPSet, "dst",
			"-j", iptables.AcceptTarget,
		}...)
	}
	for _, chain := range nodeNetworkPolicyIPTablesChains {
		for _, rule := range iptablesFiltersRuleByChain[chain] {
			writeLine(iptablesData, rule)
		}
	}
	writeLine(iptablesData, "COMMIT")

	writeLine(iptablesData, "*nat")
	if c.proxyAll && !c.hostNetworkNFTables || c.isCloudEKS {
		writeLine(iptablesData, iptables.MakeChainLine(antreaPreRoutingChain))
	}
	if c.proxyAll && !c.hostNetworkNFTables {
		writeLine(iptablesData, []string{
			"-A", antreaPreRoutingChain,
			"-m", "comment", "--comment", `"Antrea: DNAT external to NodePort packets"`,
			"-m", "set", "--match-set", nodePortIPSet, "dst,dst",
			"-j", iptables.DNATTarget,
			"--to-destination", nodePortDNATVirtualIP.String(),
		}...)
		writeLine(iptablesData, iptables.MakeChainLine(antreaOutputChain))
		writeLine(iptablesData, []string{
			"-A", antreaOutputChain,
			"-m", "comment", "--comment", `"Antrea: DNAT local to NodePort packets"`,
			"-m", "set", "--match-set", nodePortIPSet, "dst,dst",
			"-j", iptables.DNATTarget,
			"--to-destination", nodePortDNATVirtualIP.String(),
		}...)
	}
	writeLine(iptablesData, iptables.MakeChainLine(antreaPostRoutingChain))
	// The masqueraded multicast traffic will become unicast so we
	// stop traversing this antreaPostRoutingChain for multicast traffic.
	// Note: Multicast can only work with IPv4 for now. Remove condition "!isIPv6" in the future after
	// IPv6 is supported.
	if c.multicastEnabled && !isIPv6 && c.networkConfig.TrafficEncapMode.SupportsNoEncap() {
		writeLine(iptablesData, []string{
			"-A", antreaPostRoutingChain,
			"-m", "comment", "--comment", `"Antrea: skip masquerade for multicast traffic"`,
			"-s", podCIDR.String(),
			"-d", types.McastCIDR.String(),
			"-j", iptables.ReturnTarget,
		}...)
	}
	// Egress rules must be inserted before the default masquerade rule.
	for snatMark, snatIP := range snatMarkToIP {
		// Cannot reuse snatRuleSpec to generate the rule as it doesn't have "`" in the comment.
		rule := []string{
			"-A", antreaPostRoutingChain,
			"-m", "comment", "--comment", `"Antrea: SNAT Pod to external packets"`,
			"!", "-o", c.nodeConfig.GatewayConfig.Name,
			"-m", "mark", "--mark", fmt.Sprintf("%#08x/%#08x", snatMark, types.SNATIPMarkMask),
			"-j", iptables.SNATTarget, "--to", snatIP.String(),
		}
		if c.egressSNATRandomFully {
			rule = append(rule, "--random-fully")
		}
		writeLine(iptablesData, rule...)
	}
	if !c.noSNAT {
		rule := []string{
			"-A", antreaPostRoutingChain,
			"-m", "comment", "--comment", `"Antrea: masquerade Pod to external packets"`,
			"-s", podCIDR.String(), "-m", "set", "!", "--match-set", podIPSet, "dst",
			"!", "-o", c.nodeConfig.GatewayConfig.Name,
			"-j", iptables.MasqueradeTarget,
		}
		if c.nodeSNATRandomFully {
			rule = append(rule, "--random-fully")
		}
		writeLine(iptablesData, rule...)
	}

	// For local traffic going out of the gateway interface, if the source IP does not match any
	// of the gateway's IP addresses, the traffic needs to be masqueraded. Otherwise, we observe
	// that ARP requests may advertise a different source IP address, in which case they will be
	// dropped by the SpoofGuard table in the OVS pipeline. See description for the arp_announce
	// sysctl parameter.
	rule := []string{
		"-A", antreaPostRoutingChain,
		"-m", "comment", "--comment", `"Antrea: masquerade LOCAL traffic"`,
		"-o", c.nodeConfig.GatewayConfig.Name,
		"-m", "addrtype", "!", "--src-type", "LOCAL", "--limit-iface-out",
		"-m", "addrtype", "--src-type", "LOCAL",
		"-j", iptables.MasqueradeTarget,
	}
	if c.iptablesHasRandomFully {
		rule = append(rule, "--random-fully")
	}
	writeLine(iptablesData, rule...)

	// If AntreaProxy full support is enabled, it SNATs the packets whose source IP is VirtualServiceIPv4/VirtualServiceIPv6
	// so the packets can be routed back to this Node.
	if c.proxyAll && !c.hostNetworkNFTables {
		writeLine(iptablesData, []string{
			"-A", antreaPostRoutingChain,
			"-m", "comment", "--comment", `"Antrea: masquerade OVS virtual source IP"`,
			"-s", serviceVirtualIP.String(),
			"-j", iptables.MasqueradeTarget,
		}...)
	}

	// This generates the rule to masquerade the packets destined for a hostPort whose backend is an AntreaIPAM VLAN Pod.
	// For simplicity, in the following descriptions:
	//   - per-Node IPAM Pod is referred to as regular Pod.
	//   - AntreaIPAM Pod without VLAN is referred to as AntreaIPAM Pod.
	//   - AntreaIPAM Pod with VLAN is referred to as AntreaIPAM VLAN Pod.
	// The common conditions are:
	//   - AntreaIPAM VLAN Pod exposes hostPort.
	//   - hostPort traffic is sent to underlay gateway after Node DNATed the traffic.
	//   - underlay gateway sends traffic back with a vlan tag.
	//   - SNAT is required to guarantee the reply traffic can be sent to Node to de-DNAT.
	// Corresponding traffic models are:
	//   01. Regular Pod (remote)     -- hostPort [request]              --> AntreaIPAM VLAN Pod
	//   02. AntreaIPAM Pod           -- hostPort [request]              --> AntreaIPAM VLAN Pod
	//   03. AntreaIPAM VLAN Pod      -- hostPort [request]              --> AntreaIPAM VLAN Pod (different subnet/VLAN)
	//   04. External                 -- hostPort [request]              --> AntreaIPAM VLAN Pod
	// Below traffic models are already covered by portmap CNI:
	//   01. AntreaIPAM VLAN Pod      -- hostPort [request]              --> AntreaIPAM VLAN Pod (same subnet)
	//   02. Regular Pod (local)      -- hostPort [request]              --> AntreaIPAM VLAN Pod
	if c.connectUplinkToBridge {
		// We do not use --random-fully for this rule for consistency with the portmap CNI plugin.
		// https://github.com/containernetworking/plugins/blob/c29dc79f96cd50452a247a4591443d2aac033429/plugins/meta/portmap/portmap.go#L321-L345
		writeLine(iptablesData, []string{
			"-A", antreaPostRoutingChain,
			"-m", "comment", "--comment", `"Antrea: masquerade traffic to local AntreaIPAM hostPort Pod"`,
			"!", "-s", podCIDR.String(),
			"-m", "set", "--match-set", localAntreaFlexibleIPAMPodIPSet, "dst",
			"-j", iptables.MasqueradeTarget,
		}...)
	}

	// When Antrea is used to enforce NetworkPolicies in EKS, additional iptables
	// nat rules are required. See https://github.com/antrea-io/antrea/issues/3946.
	// These rules are only needed for IPv4.
	if c.isCloudEKS && !isIPv6 {
		c.writeEKSNATRules(iptablesData)
	}

	writeLine(iptablesData, "COMMIT")
	return iptablesData
}

func (c *Client) initIPRoutes() error {
	if c.networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		gwLink, err := c.netlink.LinkByName(c.nodeConfig.GatewayConfig.Name)
		if err != nil {
			return fmt.Errorf("error getting link %s: %v", c.nodeConfig.GatewayConfig.Name, err)
		}
		if c.nodeConfig.NodeTransportIPv4Addr != nil {
			_, gwIP, _ := net.ParseCIDR(fmt.Sprintf("%s/32", c.nodeConfig.NodeTransportIPv4Addr.IP.String()))
			if err := c.netlink.AddrReplace(gwLink, &netlink.Addr{IPNet: gwIP}); err != nil {
				return fmt.Errorf("failed to add address %s to gw %s: %v", gwIP, gwLink.Attrs().Name, err)
			}
		}
		if c.nodeConfig.NodeTransportIPv6Addr != nil {
			_, gwIP, _ := net.ParseCIDR(fmt.Sprintf("%s/128", c.nodeConfig.NodeTransportIPv6Addr.IP.String()))
			if err := c.netlink.AddrReplace(gwLink, &netlink.Addr{IPNet: gwIP}); err != nil {
				return fmt.Errorf("failed to add address %s to gw %s: %v", gwIP, gwLink.Attrs().Name, err)
			}
		}
	}
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
		if err := c.addVirtualServiceIPRoute(true); err != nil {
			return err
		}
		if err := c.addVirtualNodePortDNATIPRoute(true); err != nil {
			return err
		}
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

func (c *Client) initNodeNetworkPolicy() {
	antreaInputChainRules := []string{
		iptables.NewRuleBuilder(antreaInputChain).
			SetComment("Antrea: jump to static ingress NodeNetworkPolicy rules").
			SetTarget(preNodeNetworkPolicyIngressRulesChain).
			Done().
			GetRule(),
		iptables.NewRuleBuilder(antreaInputChain).
			SetComment("Antrea: jump to ingress NodeNetworkPolicy rules").
			SetTarget(config.NodeNetworkPolicyIngressRulesChain).
			Done().
			GetRule(),
	}
	antreaOutputChainRules := []string{
		iptables.NewRuleBuilder(antreaOutputChain).
			SetComment("Antrea: jump to static egress NodeNetworkPolicy rules").
			SetTarget(preNodeNetworkPolicyEgressRulesChain).
			Done().
			GetRule(),
		iptables.NewRuleBuilder(antreaOutputChain).
			SetComment("Antrea: jump to egress NodeNetworkPolicy rules").
			SetTarget(config.NodeNetworkPolicyEgressRulesChain).
			Done().
			GetRule(),
	}
	preIngressChainRules := []string{
		iptables.NewRuleBuilder(preNodeNetworkPolicyIngressRulesChain).
			MatchEstablishedOrRelated().
			SetComment("Antrea: allow ingress established or related packets").
			SetTarget(iptables.AcceptTarget).
			Done().
			GetRule(),
		iptables.NewRuleBuilder(preNodeNetworkPolicyIngressRulesChain).
			MatchInputInterface("lo").
			SetComment("Antrea: allow ingress packets from loopback").
			SetTarget(iptables.AcceptTarget).
			Done().
			GetRule(),
	}
	preEgressChainRules := []string{
		iptables.NewRuleBuilder(preNodeNetworkPolicyEgressRulesChain).
			MatchEstablishedOrRelated().
			SetComment("Antrea: allow egress established or related packets").
			SetTarget(iptables.AcceptTarget).
			Done().
			GetRule(),
		iptables.NewRuleBuilder(preNodeNetworkPolicyEgressRulesChain).
			MatchOutputInterface("lo").
			SetComment("Antrea: allow egress packets to loopback").
			SetTarget(iptables.AcceptTarget).
			Done().
			GetRule(),
	}

	if c.networkConfig.IPv6Enabled {
		c.nodeNetworkPolicyIPTablesIPv6.Store(antreaInputChain, antreaInputChainRules)
		c.nodeNetworkPolicyIPTablesIPv6.Store(antreaOutputChain, antreaOutputChainRules)
		c.nodeNetworkPolicyIPTablesIPv6.Store(preNodeNetworkPolicyIngressRulesChain, preIngressChainRules)
		c.nodeNetworkPolicyIPTablesIPv6.Store(preNodeNetworkPolicyEgressRulesChain, preEgressChainRules)
		c.nodeNetworkPolicyIPTablesIPv6.Store(config.NodeNetworkPolicyIngressRulesChain, []string{})
		c.nodeNetworkPolicyIPTablesIPv6.Store(config.NodeNetworkPolicyEgressRulesChain, []string{})
	}
	if c.networkConfig.IPv4Enabled {
		c.nodeNetworkPolicyIPTablesIPv4.Store(antreaInputChain, antreaInputChainRules)
		c.nodeNetworkPolicyIPTablesIPv4.Store(antreaOutputChain, antreaOutputChainRules)
		c.nodeNetworkPolicyIPTablesIPv4.Store(preNodeNetworkPolicyIngressRulesChain, preIngressChainRules)
		c.nodeNetworkPolicyIPTablesIPv4.Store(preNodeNetworkPolicyEgressRulesChain, preEgressChainRules)
		c.nodeNetworkPolicyIPTablesIPv4.Store(config.NodeNetworkPolicyIngressRulesChain, []string{})
		c.nodeNetworkPolicyIPTablesIPv4.Store(config.NodeNetworkPolicyEgressRulesChain, []string{})
	}
}

func (c *Client) initWireguard() {
	wireguardPort := intstr.FromInt(c.wireguardPort)
	antreaInputChainRules := []string{
		iptables.NewRuleBuilder(antreaInputChain).
			SetComment("Antrea: allow WireGuard input packets").
			MatchTransProtocol(iptables.ProtocolUDP).
			MatchPortDst(&wireguardPort, nil).
			SetTarget(iptables.AcceptTarget).
			Done().
			GetRule(),
	}
	antreaOutputChainRules := []string{
		iptables.NewRuleBuilder(antreaOutputChain).
			SetComment("Antrea: allow WireGuard output packets").
			MatchTransProtocol(iptables.ProtocolUDP).
			MatchPortDst(&wireguardPort, nil).
			SetTarget(iptables.AcceptTarget).
			Done().
			GetRule(),
	}

	if c.networkConfig.IPv6Enabled {
		c.wireguardIPTablesIPv6.Store(antreaInputChain, antreaInputChainRules)
		c.wireguardIPTablesIPv6.Store(antreaOutputChain, antreaOutputChainRules)
	}
	if c.networkConfig.IPv4Enabled {
		c.wireguardIPTablesIPv4.Store(antreaInputChain, antreaInputChainRules)
		c.wireguardIPTablesIPv4.Store(antreaOutputChain, antreaOutputChainRules)
	}
}

func (c *Client) initNodeLatencyRules() {
	// the interface on which ICMP probes are sent / received is the Antrea gateway interface, except
	// in networkPolicyOnly mode, for which it is the Node's transport interface.
	iface := c.nodeConfig.GatewayConfig.Name
	if c.networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		iface = c.networkConfig.TransportIface
	}

	buildInputRule := func(ipProtocol iptables.Protocol, icmpType int32) string {
		return iptables.NewRuleBuilder(antreaInputChain).
			MatchInputInterface(iface).
			MatchICMP(&icmpType, nil, ipProtocol).
			SetComment("Antrea: allow ICMP probes from NodeLatencyMonitor").
			SetTarget(iptables.AcceptTarget).
			Done().
			GetRule()
	}
	buildOutputRule := func(ipProtocol iptables.Protocol, icmpType int32) string {
		return iptables.NewRuleBuilder(antreaOutputChain).
			MatchOutputInterface(iface).
			MatchICMP(&icmpType, nil, ipProtocol).
			SetComment("Antrea: allow ICMP probes from NodeLatencyMonitor").
			SetTarget(iptables.AcceptTarget).
			Done().
			GetRule()
	}

	if c.networkConfig.IPv6Enabled {
		c.nodeLatencyMonitorIPTablesIPv6.Store(antreaInputChain, []string{
			buildInputRule(iptables.ProtocolIPv6, int32(ipv6.ICMPTypeEchoRequest)),
			buildInputRule(iptables.ProtocolIPv6, int32(ipv6.ICMPTypeEchoReply)),
		})
		c.nodeLatencyMonitorIPTablesIPv6.Store(antreaOutputChain, []string{
			buildOutputRule(iptables.ProtocolIPv6, int32(ipv6.ICMPTypeEchoRequest)),
			buildOutputRule(iptables.ProtocolIPv6, int32(ipv6.ICMPTypeEchoReply)),
		})
	}
	if c.networkConfig.IPv4Enabled {
		c.nodeLatencyMonitorIPTablesIPv4.Store(antreaInputChain, []string{
			buildInputRule(iptables.ProtocolIPv4, int32(ipv4.ICMPTypeEcho)),
			buildInputRule(iptables.ProtocolIPv4, int32(ipv4.ICMPTypeEchoReply)),
		})
		c.nodeLatencyMonitorIPTablesIPv4.Store(antreaOutputChain, []string{
			buildOutputRule(iptables.ProtocolIPv4, int32(ipv4.ICMPTypeEcho)),
			buildOutputRule(iptables.ProtocolIPv4, int32(ipv4.ICMPTypeEchoReply)),
		})
	}
}

func (c *Client) initEgressIPRules() error {
	rules, err := c.netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for i := range rules {
		rule := rules[i]
		if rule.Table != types.ReplyEgressRouteTable {
			continue
		}
		// Delete all rules whose target table is ReplyEgressRouteTable on startup. These rules will be reinstalled
		// each time after restart. This implementation was inspired by the implementation of RestoreEgressRoutesAndRules.
		c.netlink.RuleDel(&rule)
	}

	if c.networkConfig.IPv6Enabled {
		rule := generateRule(types.ReplyEgressRouteTable, types.EgressNoEncapReturnToRemoteMark, &types.EgressNoEncapReturnToRemoteMark, netlink.FAMILY_V6)
		if err := c.netlink.RuleAdd(rule); err != nil {
			return fmt.Errorf("error adding ip rule %v: %w", rule, err)
		}
		c.egressRules.Store(generateRuleKey(rule), rule)
	}
	if c.networkConfig.IPv4Enabled {
		rule := generateRule(types.ReplyEgressRouteTable, types.EgressNoEncapReturnToRemoteMark, &types.EgressNoEncapReturnToRemoteMark, netlink.FAMILY_V4)
		if err := c.netlink.RuleAdd(rule); err != nil {
			return fmt.Errorf("error adding ip rule %v: %w", rule, err)
		}
		c.egressRules.Store(generateRuleKey(rule), rule)
	}
	return nil
}

func (c *Client) initEgressIPRoutes() error {
	if c.networkConfig.IPv4Enabled {
		if err := c.addEgressReplyDefaultPolicyIPRoute(false); err != nil {
			return err
		}
	}
	if c.networkConfig.IPv6Enabled {
		if err := c.addEgressReplyDefaultPolicyIPRoute(true); err != nil {
			return err
		}
	}
	return nil
}

// Reconcile removes orphaned podCIDRs from ipset and removes routes to orphaned podCIDRs
// based on the desired podCIDRs.
func (c *Client) Reconcile(podCIDRs []string) error {
	desiredPodCIDRs := sets.New[string](podCIDRs...)
	// Get the peer IPv6 gateways from pod CIDRs
	desiredIPv6GWs := getIPv6Gateways(podCIDRs)

	// Remove orphaned podCIDRs from ipset.
	for _, ipsetName := range []string{antreaPodIPSet, antreaPodIP6Set} {
		entries, err := c.ipset.ListEntries(ipsetName)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if desiredPodCIDRs.Has(entry) {
				continue
			}
			klog.Infof("Deleting orphaned Pod IP %s from ipset and route table", entry)
			if err := c.ipset.DelEntry(ipsetName, entry); err != nil {
				return err
			}
			_, cidr, err := net.ParseCIDR(entry)
			if err != nil {
				return err
			}
			route := &netlink.Route{Dst: cidr}
			if err := c.netlink.RouteDel(route); err != nil && err != unix.ESRCH {
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
		// The route to the IPv6 link-local CIDR is always auto-generated by the system along with
		// a link-local address, which is not configured by Antrea and should therefore to be ignored
		// in the "deletion" list. Such routes are useful in some cases, e.g., IPv6 NDP.
		if route.Dst.IP.IsLinkLocalUnicast() && utilnet.IsIPv6CIDR(route.Dst) {
			continue
		}
		// IPv6 doesn't support "on-link" route, routes to the peer IPv6 gateways need to
		// be added separately. So don't delete such routes.
		if desiredIPv6GWs.Has(route.Dst.IP.String()) {
			continue
		}
		// Don't delete the routes which are added by AntreaProxy when proxyAll is enabled.
		if c.proxyAll && c.isServiceRoute(&route) {
			continue
		}

		klog.Infof("Deleting unknown route %v", route)
		if err := c.netlink.RouteDel(&route); err != nil && err != unix.ESRCH {
			return err
		}
	}

	// Return immediately if there is no IPv6 gateway address configured on the Nodes.
	if desiredIPv6GWs.Len() == 0 {
		return nil
	}
	// Remove orphaned IPv6 Neighbors from host network.
	actualNeighbors, err := c.listIPv6NeighborsOnGateway()
	if err != nil {
		return err
	}
	// Remove any unknown IPv6 neighbors on Antrea gateway.
	for neighIP, actualNeigh := range actualNeighbors {
		if desiredIPv6GWs.Has(neighIP) {
			continue
		}
		// Don't delete the virtual Service IP neighbor which is added by AntreaProxy.
		if actualNeigh.IP.Equal(config.VirtualServiceIPv6) {
			continue
		}
		klog.V(4).Infof("Deleting orphaned IPv6 neighbor %v", actualNeigh)
		if err := c.netlink.NeighDel(actualNeigh); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) isServiceRoute(route *netlink.Route) bool {
	// If the gateway IP or the destination IP is the virtual Service IP, then it is a route added by AntreaProxy.
	if route.Dst != nil && (route.Dst.IP.Equal(config.VirtualServiceIPv6) || route.Dst.IP.Equal(config.VirtualServiceIPv4)) ||
		route.Gw != nil && (route.Gw.Equal(config.VirtualServiceIPv6) || route.Gw.Equal(config.VirtualServiceIPv4)) {
		return true
	}
	return false
}

// listIPRoutes returns list of routes on Antrea gateway.
func (c *Client) listIPRoutesOnGW() ([]netlink.Route, error) {
	filter := &netlink.Route{
		LinkIndex: c.nodeConfig.GatewayConfig.LinkIndex}
	routes, err := c.netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_OIF)
	if err != nil {
		return nil, err
	}
	ipv6Routes, err := c.netlink.RouteListFiltered(netlink.FAMILY_V6, filter, netlink.RT_FILTER_OIF)
	if err != nil {
		return nil, err
	}
	routes = append(routes, ipv6Routes...)
	return routes, nil
}

// RestoreEgressRoutesAndRules simply deletes all IP routes and rules created for Egresses for now.
// It may be better to keep the ones whose Egress IPs are still on this Node, but it's a bit hard to achieve it at the
// moment because the marks are not permanent and could change upon restart.
func (c *Client) RestoreEgressRoutesAndRules(minTableID, maxTableID int) error {
	klog.InfoS("Restoring IP routes and rules for Egress")
	routes, err := c.netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for i := range routes {
		route := routes[i]
		// Not routes created for Egress.
		if route.Table < minTableID || route.Table > maxTableID {
			continue
		}
		c.netlink.RouteDel(&route)
	}
	rules, err := c.netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for i := range rules {
		rule := rules[i]
		// Not rules created for Egress.
		if rule.Table < minTableID || rule.Table > maxTableID {
			continue
		}
		c.netlink.RuleDel(&rule)
	}
	return nil
}

// getIPv6Gateways returns the IPv6 gateway addresses of the given CIDRs.
func getIPv6Gateways(podCIDRs []string) sets.Set[string] {
	ipv6GWs := sets.New[string]()
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
	neighs, err := c.netlink.NeighList(c.nodeConfig.GatewayConfig.LinkIndex, netlink.FAMILY_V6)
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
	var nodeTransportIPAddr *net.IPNet
	isIPv6 := utilnet.IsIPv6CIDR(podCIDR)
	if isIPv6 {
		nodeTransportIPAddr = c.nodeConfig.NodeTransportIPv6Addr
	} else {
		nodeTransportIPAddr = c.nodeConfig.NodeTransportIPv4Addr
	}

	podCIDRStr := podCIDR.String()
	ipsetName := getIPSetName(podCIDR.IP)
	// Add this podCIDR to antreaPodIPSet so that packets to them won't be masqueraded when they leave the host.
	if err := c.ipset.AddEntry(ipsetName, podCIDRStr); err != nil {
		return err
	}
	// Install routes to this Node.
	podCIDRRoute := &netlink.Route{
		Dst: podCIDR,
	}
	var routes []*netlink.Route
	requireNodeGwIPv6RouteAndNeigh := false
	// If WireGuard is enabled, create a route via WireGuard device regardless of the traffic encapsulation modes.
	if c.networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeWireGuard {
		podCIDRRoute.LinkIndex = c.nodeConfig.WireGuardConfig.LinkIndex
		podCIDRRoute.Scope = netlink.SCOPE_LINK
		if isIPv6 {
			podCIDRRoute.Src = c.nodeConfig.GatewayConfig.IPv6
		} else {
			podCIDRRoute.Src = c.nodeConfig.GatewayConfig.IPv4
		}
		routes = append(routes, podCIDRRoute)
	} else if c.networkConfig.NeedsTunnelToPeer(nodeIP, nodeTransportIPAddr) {
		if utilnet.IsIPv6CIDR(podCIDR) {
			requireNodeGwIPv6RouteAndNeigh = true
			// "on-link" is not identified in IPv6 route entries, so split the configuration into 2 entries.
			// TODO: Kernel >= 4.16 supports adding IPv6 route with onlink flag. Delete this route after Kernel version
			//       requirement bump in future.
			routes = append(routes, &netlink.Route{
				Dst:       &net.IPNet{IP: nodeGwIP, Mask: net.CIDRMask(128, 128)},
				LinkIndex: c.nodeConfig.GatewayConfig.LinkIndex,
			})
		} else {
			podCIDRRoute.Flags = int(netlink.FLAG_ONLINK)
		}
		podCIDRRoute.LinkIndex = c.nodeConfig.GatewayConfig.LinkIndex
		podCIDRRoute.Gw = nodeGwIP
		routes = append(routes, podCIDRRoute)
	} else if c.networkConfig.NeedsDirectRoutingToPeer(nodeIP, nodeTransportIPAddr) {
		// NoEncap traffic to Node on the same subnet.
		// Set the peerNodeIP as next hop.
		podCIDRRoute.Gw = nodeIP
		routes = append(routes, podCIDRRoute)
		// Update the nftables set that contains all peer PodCIDRs.
		if c.nftables != nil {
			if err := c.addPeerPodCIDRToNFTablesSet(podCIDR); err != nil {
				return err
			}
		}
	} else {
		// NetworkPolicyOnly mode or NoEncap traffic to a Node on a different subnet.
		// Routing should be handled by a route which is already present on the host.
		klog.InfoS("Skip adding routes to peer", "node", nodeName, "ip", nodeIP, "podCIDR", podCIDR)
	}
	for _, route := range routes {
		if err := c.netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("failed to install route to peer %s (%s) with netlink. Route config: %s. Error: %v", nodeName, nodeIP, route.String(), err)
		}
	}
	// Delete stale route and neigh to peer gateway.
	if !requireNodeGwIPv6RouteAndNeigh && utilnet.IsIPv6(nodeGwIP) {
		routeToNodeGwIPNetv6 := &netlink.Route{
			Dst: &net.IPNet{IP: nodeGwIP, Mask: net.CIDRMask(128, 128)},
		}
		if err := c.netlink.RouteDel(routeToNodeGwIPNetv6); err == nil {
			klog.InfoS("Deleted route to peer gateway", "node", nodeName, "nodeIP", nodeIP, "nodeGatewayIP", nodeGwIP)
		} else if err != unix.ESRCH {
			return fmt.Errorf("failed to delete route to peer gateway on Node %s (%s) with netlink. Route config: %s. Error: %v",
				nodeName, nodeIP, routeToNodeGwIPNetv6, err)
		}
		neigh := &netlink.Neigh{
			LinkIndex: c.nodeConfig.GatewayConfig.LinkIndex,
			Family:    netlink.FAMILY_V6,
			IP:        nodeGwIP,
		}
		if err := c.netlink.NeighDel(neigh); err == nil {
			klog.InfoS("Deleted neigh to peer gateway", "node", nodeName, "nodeIP", nodeIP, "nodeGatewayIP", nodeGwIP)
			c.nodeNeighbors.Delete(podCIDRStr)
		} else if err != unix.ENOENT {
			return fmt.Errorf("failed to delete neigh %v to gw %s: %v", neigh, c.nodeConfig.GatewayConfig.Name, err)
		}
	}
	// Add IPv6 neighbor if the given podCIDR is using IPv6 address.
	if requireNodeGwIPv6RouteAndNeigh && utilnet.IsIPv6(nodeGwIP) {
		neigh := &netlink.Neigh{
			LinkIndex:    c.nodeConfig.GatewayConfig.LinkIndex,
			Family:       netlink.FAMILY_V6,
			State:        netlink.NUD_PERMANENT,
			IP:           nodeGwIP,
			HardwareAddr: globalVMAC,
		}
		if err := c.netlink.NeighSet(neigh); err != nil {
			return fmt.Errorf("failed to add neigh %v to gw %s: %v", neigh, c.nodeConfig.GatewayConfig.Name, err)
		}
		c.nodeNeighbors.Store(podCIDRStr, neigh)
	}

	if err := c.addNodeIP(podCIDR, nodeIP); err != nil {
		return err
	}

	c.nodeRoutes.Store(podCIDRStr, routes)
	return nil
}

// DeleteRoutes deletes routes to a PodCIDR. It does nothing if the routes doesn't exist.
func (c *Client) DeleteRoutes(podCIDR *net.IPNet) error {
	isIPv6 := utilnet.IsIPv6CIDR(podCIDR)
	podCIDRStr := podCIDR.String()
	ipsetName := getIPSetName(podCIDR.IP)
	// Delete this podCIDR from antreaPodIPSet as the CIDR is no longer for Pods.
	if err := c.ipset.DelEntry(ipsetName, podCIDRStr); err != nil {
		return err
	}

	routes, exists := c.nodeRoutes.Load(podCIDRStr)
	if exists {
		c.nodeRoutes.Delete(podCIDRStr)
		for _, r := range routes.([]*netlink.Route) {
			klog.V(4).Infof("Deleting route %v", r)
			if err := c.netlink.RouteDel(r); err != nil && err != unix.ESRCH {
				c.nodeRoutes.Store(podCIDRStr, routes)
				return err
			}
		}
		if err := c.deleteNodeIP(podCIDR); err != nil {
			return err
		}
	}
	if isIPv6 {
		neigh, exists := c.nodeNeighbors.Load(podCIDRStr)
		if exists {
			if err := c.netlink.NeighDel(neigh.(*netlink.Neigh)); err != nil {
				return err
			}
			c.nodeNeighbors.Delete(podCIDRStr)
		}
	}
	if c.nftables != nil {
		if err := c.deletePeerPodCIDRFromNFTablesSet(podCIDR); err != nil {
			return err
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
	gwLink, err := c.netlink.LinkByName(c.nodeConfig.GatewayConfig.Name)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", c.nodeConfig.GatewayConfig.Name, err)
	}
	link, err := c.netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", linkName, err)
	}

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		// Swap route first then address, otherwise route gets removed when address is removed.
		routes, err := c.netlink.RouteList(link, family)
		if err != nil {
			return fmt.Errorf("failed to get routes for link %s: %w", linkName, err)
		}
		for i := range routes {
			route := routes[i]
			route.LinkIndex = gwLink.Attrs().Index
			if err = c.netlink.RouteReplace(&route); err != nil {
				return fmt.Errorf("failed to add route %v to link %s: %w", &route, gwLink.Attrs().Name, err)
			}
		}

		// Swap address if any.
		addrs, err := c.netlink.AddrList(link, family)
		if err != nil {
			return fmt.Errorf("failed to get addresses for %s: %w", linkName, err)
		}
		for i := range addrs {
			addr := addrs[i]
			if addr.IP.IsLinkLocalMulticast() || addr.IP.IsLinkLocalUnicast() {
				continue
			}
			if err = c.netlink.AddrDel(link, &addr); err != nil {
				klog.Errorf("failed to delete addr %v from %s: %v", addr, link, err)
			}
			tmpAddr := &netlink.Addr{IPNet: addr.IPNet}
			if err = c.netlink.AddrReplace(gwLink, tmpAddr); err != nil {
				return fmt.Errorf("failed to add addr %v to gw %s: %w", addr, gwLink.Attrs().Name, err)
			}
		}
	}
	return nil
}

// UnMigrateRoutesFromGw moves route from gw to link linkName if provided; otherwise route is deleted
func (c *Client) UnMigrateRoutesFromGw(route *net.IPNet, linkName string) error {
	gwLink, err := c.netlink.LinkByName(c.nodeConfig.GatewayConfig.Name)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", c.nodeConfig.GatewayConfig.Name, err)
	}
	var link netlink.Link
	if len(linkName) > 0 {
		link, err = c.netlink.LinkByName(linkName)
		if err != nil {
			return fmt.Errorf("failed to get link %s: %w", linkName, err)
		}
	}
	routes, err := c.netlink.RouteList(gwLink, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to get routes for link %s: %w", gwLink.Attrs().Name, err)
	}
	for i := range routes {
		rt := routes[i]
		if route.String() == rt.Dst.String() {
			if link != nil {
				rt.LinkIndex = link.Attrs().Index
				return c.netlink.RouteReplace(&rt)
			}
			return c.netlink.RouteDel(&rt)
		}
	}
	return nil
}

func (c *Client) snatRuleSpec(snatIP net.IP, snatMark uint32) []string {
	rule := []string{
		"-m", "comment", "--comment", "Antrea: SNAT Pod to external packets",
		// The condition is needed to prevent the rule from being applied to local out packets destined for Pods, which
		// have "0x1/0x1" mark.
		"!", "-o", c.nodeConfig.GatewayConfig.Name,
		"-m", "mark", "--mark", fmt.Sprintf("%#08x/%#08x", snatMark, types.SNATIPMarkMask),
		"-j", iptables.SNATTarget, "--to", snatIP.String(),
	}
	if c.egressSNATRandomFully {
		rule = append(rule, "--random-fully")
	}
	return rule
}

func (c *Client) AddSNATRule(snatIP net.IP, mark uint32) error {
	protocol := iptables.ProtocolIPv4
	if snatIP.To4() == nil {
		protocol = iptables.ProtocolIPv6
	}
	c.markToSNATIP.Store(mark, snatIP)
	return c.iptables.InsertRule(protocol, iptables.NATTable, antreaPostRoutingChain, c.snatRuleSpec(snatIP, mark))
}

func (c *Client) DeleteSNATRule(mark uint32) error {
	value, ok := c.markToSNATIP.Load(mark)
	if !ok {
		klog.Warningf("Didn't find SNAT rule with mark %#x", mark)
		return nil
	}
	c.markToSNATIP.Delete(mark)
	snatIP := value.(net.IP)
	protocol := iptables.ProtocolIPv4
	if snatIP.To4() == nil {
		protocol = iptables.ProtocolIPv6
	}
	return c.iptables.DeleteRule(protocol, iptables.NATTable, antreaPostRoutingChain, c.snatRuleSpec(snatIP, mark))
}

func (c *Client) AddEgressRoutes(tableID uint32, dev int, gateway net.IP, prefixLength int) error {
	var dst *net.IPNet
	if gateway.To4() != nil {
		mask := net.CIDRMask(prefixLength, 32)
		dst = &net.IPNet{
			IP:   gateway.To4().Mask(mask),
			Mask: mask,
		}
	} else {
		mask := net.CIDRMask(prefixLength, 128)
		dst = &net.IPNet{
			IP:   gateway.Mask(mask),
			Mask: mask,
		}
	}
	// Install routes for the subnet, for example:
	// tableID=101, dev=eth.10, gateway=172.20.10.1, prefixLength=24
	// $ ip route show table 101
	// 172.20.10.0/24 dev eth0.10 table 101
	// default via 172.20.10.1 dev eth0.10 table 101
	localRoute := &netlink.Route{
		Scope:     netlink.SCOPE_LINK,
		Dst:       dst,
		LinkIndex: dev,
		Table:     int(tableID),
	}
	defaultRoute := &netlink.Route{
		LinkIndex: dev,
		Gw:        gateway,
		Table:     int(tableID),
	}
	if err := c.netlink.RouteReplace(localRoute); err != nil {
		return err
	}
	if err := c.netlink.RouteReplace(defaultRoute); err != nil {
		return err
	}
	c.egressRoutes.Store(tableID, []*netlink.Route{localRoute, defaultRoute})
	return nil
}

func (c *Client) DeleteEgressRoutes(tableID uint32) error {
	value, exists := c.egressRoutes.Load(tableID)
	if !exists {
		return nil
	}
	routes := value.([]*netlink.Route)
	for _, route := range routes {
		if err := c.netlink.RouteDel(route); err != nil {
			if err.Error() != "no such process" {
				return err
			}
		}
	}
	c.egressRoutes.Delete(tableID)
	return nil
}

func (c *Client) AddEgressRule(tableID uint32, mark uint32, isIPv6 bool) error {
	family := netlink.FAMILY_V4
	if isIPv6 {
		family = netlink.FAMILY_V6
	}

	rule := generateRule(int(tableID), mark, ptr.To(types.SNATIPMarkMask), family)
	if err := c.netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("error adding ip rule %v: %w", rule, err)
	}
	c.egressRules.Store(generateRuleKey(rule), rule)
	return nil
}

func (c *Client) DeleteEgressRule(tableID uint32, mark uint32, isIPv6 bool) error {
	family := netlink.FAMILY_V4
	if isIPv6 {
		family = netlink.FAMILY_V6
	}

	rule := generateRule(int(tableID), mark, ptr.To(types.SNATIPMarkMask), family)
	if err := c.netlink.RuleDel(rule); err != nil {
		if err.Error() != "no such process" {
			return fmt.Errorf("error deleting ip rule %v: %w", rule, err)
		}
	}
	c.egressRules.Delete(generateRuleKey(rule))
	return nil
}

// addVirtualServiceIPRoute is used to add a route which is used to route the packets whose destination IP is a virtual
// IP to Antrea gateway.
func (c *Client) addVirtualServiceIPRoute(isIPv6 bool) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	svcIP := config.VirtualServiceIPv4
	mask := net.IPv4len * 8
	if isIPv6 {
		svcIP = config.VirtualServiceIPv6
		mask = net.IPv6len * 8
	}

	neigh := generateNeigh(svcIP, linkIndex)
	if err := c.netlink.NeighSet(neigh); err != nil {
		return fmt.Errorf("failed to add new IP neighbour for %s: %w", svcIP, err)
	}
	c.serviceNeighbors.Store(svcIP.String(), neigh)

	route := generateRoute(svcIP, mask, nil, linkIndex, netlink.SCOPE_LINK, nil, nil)
	if err := c.netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("failed to install route for virtual Service IP %s: %w", svcIP.String(), err)
	}
	c.serviceRoutes.Store(svcIP.String(), route)
	klog.InfoS("Added virtual Service IP route", "route", route)

	return nil
}

// addEgressReplyDefaultPolicyIPRoute is used to add a default route to policy-routing table ReplyEgressRouteTable when traffic
// mode is hybrid. The route is to route the reply Egress packets originated from remote Nodes to Antrea gateway,
// avoiding the packets to be matched by the routes in main route table. This ensures that the reply Egress packets
// can be forwarded back to the remote Nodes through OVS flow-based tunnel.
func (c *Client) addEgressReplyDefaultPolicyIPRoute(isIPv6 bool) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	nextHopIP := config.VirtualReplyEgressRouteNextHopIPv4
	ip := net.IPv4zero
	if isIPv6 {
		nextHopIP = config.VirtualReplyEgressRouteNextHopIPv6
		ip = net.IPv6zero
	}

	neigh := generateNeigh(nextHopIP, linkIndex)
	if err := c.netlink.NeighSet(neigh); err != nil {
		return fmt.Errorf("failed to add IP neighbour for %s: %w", nextHopIP, err)
	}
	c.egressNeighbors.Store(ip.String(), neigh)

	route := generateRoute(ip, 0, nextHopIP, linkIndex, netlink.SCOPE_UNIVERSE, ptr.To(types.ReplyEgressRouteTable), ptr.To(int(netlink.FLAG_ONLINK)))
	if err := c.netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("failed to install default route to Egress policy-routing table %d: %w", types.ReplyEgressRouteTable, err)
	}
	c.egressRoutes.Store(ip.String(), []*netlink.Route{route})
	klog.InfoS("Added default route to Egress policy-routing table", "table", types.ReplyEgressRouteTable, "route", route)

	return nil
}

// AddNodePortConfigs adds tuples of `IP, protocol, port` for every NodePort IP to the target set. The set is used by
// netfilter rules in the Node's host network as the destination, which directs the traffic to the OVS pipeline via
// Antrea gateway interface for further processing, bypassing kube-proxy processing.
func (c *Client) AddNodePortConfigs(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error {
	if c.hostNetworkNFTables {
		return c.addNodePortConfigsNFTables(nodePortAddresses, port, protocol)
	}
	return c.addNodePortConfigsIPsets(nodePortAddresses, port, protocol)
}

// DeleteNodePortConfigs deletes corresponding tuples from the target set when a NodePort Service is deleted.
func (c *Client) DeleteNodePortConfigs(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error {
	if c.hostNetworkNFTables {
		return c.deleteNodePortConfigsNFTables(nodePortAddresses, port, protocol)
	}
	return c.deleteNodePortConfigsIPsets(nodePortAddresses, port, protocol)
}

func (c *Client) addServiceCIDRRoute(serviceCIDR *net.IPNet) error {
	isIPv6 := utilnet.IsIPv6(serviceCIDR.IP)
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	scope := netlink.SCOPE_UNIVERSE
	serviceCIDRKey := serviceIPv4CIDRKey
	gw := config.VirtualServiceIPv4
	if isIPv6 {
		serviceCIDRKey = serviceIPv6CIDRKey
		gw = config.VirtualServiceIPv6
	}

	oldServiceCIDRRoute, serviceCIDRRouteExists := c.serviceRoutes.Load(serviceCIDRKey)
	// Generate a route with the new Service CIDR and install it.
	serviceCIDRMask, _ := serviceCIDR.Mask.Size()
	route := generateRoute(serviceCIDR.IP, serviceCIDRMask, gw, linkIndex, scope, nil, nil)
	if err := c.netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("failed to install a new Service CIDR route: %w", err)
	}

	// Store the new Service CIDR.
	c.serviceRoutes.Store(serviceCIDRKey, route)

	// Collect stale routes.
	var staleRoutes []*netlink.Route
	if serviceCIDRRouteExists {
		// If current destination CIDR is not nil, the route with current destination CIDR should be uninstalled.
		staleRoutes = []*netlink.Route{oldServiceCIDRRoute.(*netlink.Route)}
	} else {
		// If current destination CIDR is nil, which means that Antrea Agent has just started, then all existing routes
		// whose destination CIDR contains the first ClusterIP should be uninstalled, except the newly installed route.
		// Note that, there may be multiple stale routes prior to this commit. When upgrading, all stale routes will be
		// collected. After this commit, there will be only one stale route after Antrea Agent started.
		routes, err := c.listIPRoutesOnGW()
		if err != nil {
			return fmt.Errorf("error listing ip routes: %w", err)
		}
		for i := 0; i < len(routes); i++ {
			// Not the routes we are interested in.
			if !routes[i].Gw.Equal(gw) {
				continue
			}
			// It's the latest route we just installed.
			if utilip.IPNetEqual(routes[i].Dst, serviceCIDR) {
				continue
			}
			// The route covers the desired route. It was installed when the calculated ServiceCIDR was larger than the
			// current one, which could happen after some Services are deleted.
			if utilip.IPNetContains(routes[i].Dst, serviceCIDR) {
				staleRoutes = append(staleRoutes, &routes[i])
			}
			// The desired route covers the route. It was installed when the calculated ServiceCIDR was smaller than the
			// current one, which could happen after some Services are added.
			if utilip.IPNetContains(serviceCIDR, routes[i].Dst) {
				staleRoutes = append(staleRoutes, &routes[i])
			}
		}
	}

	// Remove stale routes.
	for _, rt := range staleRoutes {
		if err := c.netlink.RouteDel(rt); err != nil {
			if err.Error() == "no such process" {
				klog.InfoS("Failed to delete stale Service CIDR route since the route has been deleted", "route", rt)
			} else {
				return fmt.Errorf("failed to delete stale Service CIDR route %s: %w", rt.String(), err)
			}
		} else {
			klog.V(4).InfoS("Deleted stale Service CIDR route successfully", "route", rt)
		}
	}

	return nil
}

func (c *Client) addVirtualNodePortDNATIPRoute(isIPv6 bool) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	vIP := config.VirtualNodePortDNATIPv4
	gw := config.VirtualServiceIPv4
	mask := net.IPv4len * 8
	if isIPv6 {
		vIP = config.VirtualNodePortDNATIPv6
		gw = config.VirtualServiceIPv6
		mask = net.IPv6len * 8
	}
	route := generateRoute(vIP, mask, gw, linkIndex, netlink.SCOPE_UNIVERSE, nil, nil)
	if err := c.netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("failed to install route for NodePort DNAT IP %s: %w", vIP.String(), err)
	}
	klog.V(4).InfoS("Added NodePort DNAT IP route", "route", route)
	c.serviceRoutes.Store(vIP.String(), route)

	return nil
}

// AddExternalIPConfigs adds a route entry to forward traffic destined for the external Service IP to the Antrea
// gateway interface. Additionally, it adds the IP to the target set. The set is used by netfilter rules in the
// Node's host network as the destination, skipping conntrack and bypassing kube-proxy processing.
func (c *Client) AddExternalIPConfigs(svcInfoStr string, externalIP net.IP) error {
	externalIPStr := externalIP.String()
	references, exists := c.serviceExternalIPReferences[externalIPStr]
	if exists {
		references.Insert(svcInfoStr)
		return nil
	}

	if err := c.addExternalIPConfigsRoute(externalIP); err != nil {
		return err
	}

	var err error
	if c.hostNetworkNFTables {
		err = c.addExternalIPConfigsNFTables(externalIP)
	} else {
		err = c.addExternalIPConfigsIPsets(externalIP)
	}
	if err != nil {
		return err
	}

	references = sets.New[string](svcInfoStr)
	c.serviceExternalIPReferences[externalIPStr] = references
	return nil
}

// DeleteExternalIPConfigs deletes the route entry to forward traffic destined for the external Service IP to the Antrea
// gateway interface. Additionally, it removes the IP from the target set.
func (c *Client) DeleteExternalIPConfigs(svcInfoStr string, externalIP net.IP) error {
	externalIPStr := externalIP.String()
	references, exists := c.serviceExternalIPReferences[externalIPStr]
	if !exists || !references.Has(svcInfoStr) {
		return nil
	}
	if references.Len() > 1 {
		references.Delete(svcInfoStr)
		return nil
	}

	if err := c.deleteExternalIPConfigsRoute(externalIP); err != nil {
		return err
	}

	var err error
	if c.hostNetworkNFTables {
		err = c.deleteExternalIPConfigsNFTables(externalIP)
	} else {
		err = c.deleteExternalIPConfigsIPsets(externalIP)
	}
	if err != nil {
		return err
	}

	delete(c.serviceExternalIPReferences, externalIPStr)
	return nil
}

// AddLocalAntreaFlexibleIPAMPodRule is used to add IP to target ip set when an AntreaFlexibleIPAM Pod is added. An entry is added
// for every Pod IP.
func (c *Client) AddLocalAntreaFlexibleIPAMPodRule(podAddresses []net.IP) error {
	if !c.connectUplinkToBridge {
		return nil
	}
	for i := range podAddresses {
		isIPv6 := podAddresses[i].To4() == nil
		// Skip Per-Node IPAM Pod
		if isIPv6 {
			if c.nodeConfig.PodIPv6CIDR.Contains(podAddresses[i]) {
				continue
			}
		} else {
			if c.nodeConfig.PodIPv4CIDR.Contains(podAddresses[i]) {
				continue
			}
		}
		ipSetEntry := podAddresses[i].String()
		ipSetName := getLocalAntreaFlexibleIPAMPodIPSetName(isIPv6)
		if err := c.ipset.AddEntry(ipSetName, ipSetEntry); err != nil {
			return err
		}
	}
	return nil
}

// DeleteLocalAntreaFlexibleIPAMPodRule is used to delete related IP set entries when an AntreaFlexibleIPAM Pod is deleted.
func (c *Client) DeleteLocalAntreaFlexibleIPAMPodRule(podAddresses []net.IP) error {
	if !c.connectUplinkToBridge {
		return nil
	}
	for i := range podAddresses {
		isIPv6 := podAddresses[i].To4() == nil
		ipSetEntry := podAddresses[i].String()
		ipSetName := getLocalAntreaFlexibleIPAMPodIPSetName(isIPv6)
		if err := c.ipset.DelEntry(ipSetName, ipSetEntry); err != nil {
			return err
		}
	}
	return nil
}

// addNodeIP adds nodeIP into the ipset when a new Node joins the cluster.
// The ipset is consumed with encap mode when multicast is enabled.
func (c *Client) addNodeIP(podCIDR *net.IPNet, nodeIP net.IP) error {
	if !c.multicastEnabled || !c.networkConfig.TrafficEncapMode.SupportsEncap() {
		return nil
	}
	if nodeIP == nil {
		return nil
	}
	ipSetEntry := nodeIP.String()
	if nodeIP.To4() != nil {
		if err := c.ipset.AddEntry(clusterNodeIPSet, ipSetEntry); err != nil {
			return err
		}
		c.clusterNodeIPs.Store(podCIDR.String(), ipSetEntry)
	} else {
		if err := c.ipset.AddEntry(clusterNodeIP6Set, ipSetEntry); err != nil {
			return err
		}
		c.clusterNodeIP6s.Store(podCIDR.String(), ipSetEntry)
	}
	return nil
}

// deleteNodeIP deletes NodeIPs from the ipset when a Node leaves the cluster.
// The ipset is consumed with encap mode when multicast is enabled.
func (c *Client) deleteNodeIP(podCIDR *net.IPNet) error {
	if !c.multicastEnabled || !c.networkConfig.TrafficEncapMode.SupportsEncap() {
		return nil
	}

	podCIDRStr := podCIDR.String()
	if utilnet.IsIPv4CIDR(podCIDR) {
		obj, exists := c.clusterNodeIPs.Load(podCIDRStr)
		if !exists {
			return nil
		}
		ipSetEntry := obj.(string)
		if err := c.ipset.DelEntry(clusterNodeIPSet, ipSetEntry); err != nil {
			return err
		}
		c.clusterNodeIPs.Delete(podCIDRStr)
	} else {
		obj, exists := c.clusterNodeIP6s.Load(podCIDRStr)
		if !exists {
			return nil
		}
		ipSetEntry := obj.(string)
		if err := c.ipset.DelEntry(clusterNodeIP6Set, ipSetEntry); err != nil {
			return err
		}
		c.clusterNodeIP6s.Delete(podCIDRStr)
	}
	return nil
}

func (c *Client) AddRouteForLink(cidr *net.IPNet, linkIndex int) error {
	route := &netlink.Route{
		Scope:     netlink.SCOPE_LINK,
		Dst:       cidr,
		LinkIndex: linkIndex,
	}

	return c.netlink.RouteReplace(route)
}

func (c *Client) DeleteRouteForLink(cidr *net.IPNet, linkIndex int) error {
	route := &netlink.Route{
		Scope:     netlink.SCOPE_LINK,
		Dst:       cidr,
		LinkIndex: linkIndex,
	}

	if err := c.netlink.RouteDel(route); err != nil {
		if err.Error() == "no such process" {
			klog.V(2).InfoS("Failed to delete WireGuard CIDR route since the route does not exist", "route", route)
			return nil
		}
		return err
	}
	return nil
}

func (c *Client) ClearConntrackEntryForService(svcIP net.IP, svcPort uint16, endpointIP net.IP, protocol binding.Protocol) error {
	var protoVar uint8
	var ipFamilyVar uint8
	var zone uint16
	switch protocol {
	case binding.ProtocolTCP:
		ipFamilyVar = unix.AF_INET
		protoVar = unix.IPPROTO_TCP
		zone = openflow.CtZone
	case binding.ProtocolTCPv6:
		ipFamilyVar = unix.AF_INET6
		protoVar = unix.IPPROTO_TCP
		zone = openflow.CtZoneV6
	case binding.ProtocolUDP:
		ipFamilyVar = unix.AF_INET
		protoVar = unix.IPPROTO_UDP
		zone = openflow.CtZone
	case binding.ProtocolUDPv6:
		ipFamilyVar = unix.AF_INET6
		protoVar = unix.IPPROTO_UDP
		zone = openflow.CtZoneV6
	case binding.ProtocolSCTP:
		ipFamilyVar = unix.AF_INET
		protoVar = unix.IPPROTO_SCTP
		zone = openflow.CtZone
	case binding.ProtocolSCTPv6:
		ipFamilyVar = unix.AF_INET6
		protoVar = unix.IPPROTO_SCTP
		zone = openflow.CtZoneV6
	}
	filter := &netlink.ConntrackFilter{}
	filter.AddProtocol(protoVar)
	filter.AddZone(zone)
	if svcIP != nil {
		filter.AddIP(netlink.ConntrackOrigDstIP, svcIP)
	}
	if svcPort != 0 {
		filter.AddPort(netlink.ConntrackOrigDstPort, svcPort)
	}
	if endpointIP != nil {
		filter.AddIP(netlink.ConntrackReplySrcIP, endpointIP)
	}
	_, err := c.netlink.ConntrackDeleteFilter(netlink.ConntrackTableType(netlink.ConntrackTable), netlink.InetFamily(ipFamilyVar), filter)
	return err
}

func getTransProtocolStr(protocol binding.Protocol) string {
	switch protocol {
	case binding.ProtocolTCP, binding.ProtocolTCPv6:
		return "tcp"
	case binding.ProtocolUDP, binding.ProtocolUDPv6:
		return "udp"
	case binding.ProtocolSCTP, binding.ProtocolSCTPv6:
		return "sctp"
	}
	return ""
}

func isIPv6Protocol(protocol binding.Protocol) bool {
	if protocol == binding.ProtocolTCPv6 || protocol == binding.ProtocolUDPv6 || protocol == binding.ProtocolSCTPv6 {
		return true
	}
	return false
}

func generateRule(table int, mark uint32, mask *uint32, family int) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Table = table
	rule.Mark = mark
	rule.Mask = mask
	rule.Family = family
	return rule
}

func generateRoute(ip net.IP,
	mask int,
	gw net.IP,
	linkIndex int,
	scope netlink.Scope,
	table *int,
	flags *int) *netlink.Route {
	addrBits := net.IPv4len * 8
	if ip.To4() == nil {
		addrBits = net.IPv6len * 8
	}

	route := &netlink.Route{
		Dst: &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(mask, addrBits),
		},
		Gw:        gw,
		Scope:     scope,
		LinkIndex: linkIndex,
	}
	if table != nil {
		route.Table = *table
	}
	if flags != nil {
		route.Flags = *flags
	}
	return route
}

func generateNeigh(ip net.IP, linkIndex int) *netlink.Neigh {
	family := netlink.FAMILY_V4
	if utilnet.IsIPv6(ip) {
		family = netlink.FAMILY_V6
	}
	return &netlink.Neigh{
		LinkIndex:    linkIndex,
		Family:       family,
		State:        netlink.NUD_PERMANENT,
		IP:           ip,
		HardwareAddr: globalVMAC,
	}
}

func (c *Client) AddOrUpdateNodeNetworkPolicyIPSet(ipsetName string, ipsetEntries sets.Set[string], isIPv6 bool) error {
	var prevIPSetEntries sets.Set[string]
	if isIPv6 {
		if value, ok := c.nodeNetworkPolicyIPSetsIPv6.Load(ipsetName); ok {
			prevIPSetEntries = value.(sets.Set[string])
		}
	} else {
		if value, ok := c.nodeNetworkPolicyIPSetsIPv4.Load(ipsetName); ok {
			prevIPSetEntries = value.(sets.Set[string])
		}
	}
	ipsetEntriesToAdd := ipsetEntries.Difference(prevIPSetEntries)
	ipsetEntriesToDelete := prevIPSetEntries.Difference(ipsetEntries)

	if err := c.ipset.CreateIPSet(ipsetName, ipset.HashNet, isIPv6); err != nil {
		return err
	}
	for ipsetEntry := range ipsetEntriesToAdd {
		if err := c.ipset.AddEntry(ipsetName, ipsetEntry); err != nil {
			return err
		}
	}
	for ipsetEntry := range ipsetEntriesToDelete {
		if err := c.ipset.DelEntry(ipsetName, ipsetEntry); err != nil {
			return err
		}
	}

	if isIPv6 {
		c.nodeNetworkPolicyIPSetsIPv6.Store(ipsetName, ipsetEntries)
	} else {
		c.nodeNetworkPolicyIPSetsIPv4.Store(ipsetName, ipsetEntries)
	}
	return nil
}

func (c *Client) DeleteNodeNetworkPolicyIPSet(ipsetName string, isIPv6 bool) error {
	if err := c.ipset.DestroyIPSet(ipsetName); err != nil {
		return err
	}
	if isIPv6 {
		c.nodeNetworkPolicyIPSetsIPv6.Delete(ipsetName)
	} else {
		c.nodeNetworkPolicyIPSetsIPv4.Delete(ipsetName)
	}
	return nil
}

func (c *Client) AddOrUpdateNodeNetworkPolicyIPTables(iptablesChains []string, iptablesRules [][]string, isIPv6 bool) error {
	iptablesData := bytes.NewBuffer(nil)

	writeLine(iptablesData, "*filter")
	for _, iptablesChain := range iptablesChains {
		writeLine(iptablesData, iptables.MakeChainLine(iptablesChain))
	}
	for _, rules := range iptablesRules {
		for _, rule := range rules {
			writeLine(iptablesData, rule)
		}
	}
	writeLine(iptablesData, "COMMIT")

	if err := c.iptables.Restore(iptablesData.String(), false, isIPv6); err != nil {
		return err
	}

	for index, iptablesChain := range iptablesChains {
		if isIPv6 {
			c.nodeNetworkPolicyIPTablesIPv6.Store(iptablesChain, iptablesRules[index])
		} else {
			c.nodeNetworkPolicyIPTablesIPv4.Store(iptablesChain, iptablesRules[index])
		}
	}
	return nil
}

func (c *Client) DeleteNodeNetworkPolicyIPTables(iptablesChains []string, isIPv6 bool) error {
	ipProtocol := iptables.ProtocolIPv4
	if isIPv6 {
		ipProtocol = iptables.ProtocolIPv6
	}

	for _, iptablesChain := range iptablesChains {
		if err := c.iptables.DeleteChain(ipProtocol, iptables.FilterTable, iptablesChain); err != nil {
			return err
		}
	}

	for _, iptablesChain := range iptablesChains {
		if isIPv6 {
			c.nodeNetworkPolicyIPTablesIPv6.Delete(iptablesChain)
		} else {
			c.nodeNetworkPolicyIPTablesIPv4.Delete(iptablesChain)
		}
	}

	return nil
}

func (c *Client) nftablesProxyAll(tx *knftables.Transaction, ipProtocol knftables.Family) {
	tx.Add(&knftables.Chain{
		Name:     antreaNFTablesRawChainPreroutingProxyAll,
		Type:     ptr.To(knftables.FilterType),
		Hook:     ptr.To(knftables.PreroutingHook),
		Priority: ptr.To(knftables.RawPriority),
		Comment:  ptr.To("Raw prerouting for proxyAll"),
	})
	tx.Add(&knftables.Chain{
		Name:     antreaNFTablesRawChainOutputProxyAll,
		Type:     ptr.To(knftables.FilterType),
		Hook:     ptr.To(knftables.OutputHook),
		Priority: ptr.To(knftables.RawPriority),
		Comment:  ptr.To("Raw output for proxyAll"),
	})
	tx.Add(&knftables.Chain{
		Name: antreaNFTablesNatChainPreroutingProxyAll,
		Type: ptr.To(knftables.NATType),
		Hook: ptr.To(knftables.PreroutingHook),
		// The priority ensures that Antrea takes precedence over kube-proxy when matching Service traffic originating
		// from external hosts.
		Priority: ptr.To(knftables.DNATPriority + "-1"),
		Comment:  ptr.To("NAT prerouting for proxyAll"),
	})
	tx.Add(&knftables.Chain{
		Name: antreaNFTablesNatChainOutputProxyAll,
		Type: ptr.To(knftables.NATType),
		Hook: ptr.To(knftables.OutputHook),
		// The priority ensures that Antrea takes precedence over kube-proxy when matching Service traffic originating
		// from the local Node.
		Priority: ptr.To(knftables.DNATPriority + "-1"),
		Comment:  ptr.To("NAT output for proxyAll"),
	})
	tx.Add(&knftables.Chain{
		Name:     antreaNFTablesNatChainPostroutingProxyAll,
		Type:     ptr.To(knftables.NATType),
		Hook:     ptr.To(knftables.PostroutingHook),
		Priority: ptr.To(knftables.SNATPriority),
		Comment:  ptr.To("NAT postrouting for proxyAll"),
	})
	for _, chain := range []string{
		antreaNFTablesRawChainPreroutingProxyAll,
		antreaNFTablesRawChainOutputProxyAll,
		antreaNFTablesNatChainPreroutingProxyAll,
		antreaNFTablesNatChainOutputProxyAll,
		antreaNFTablesNatChainPostroutingProxyAll,
	} {
		tx.Flush(&knftables.Chain{
			Name: chain,
		})
	}
	var ipAddr string
	var ip string
	var protocol string
	var nodePortDNATVIP string
	var svcSNATVIP string
	var nodePortSet string
	var externalIPSet string

	switch ipProtocol {
	case knftables.IPv4Family:
		ipAddr = "ipv4_addr"
		ip = "ip"
		protocol = "protocol"
		nodePortDNATVIP = config.VirtualNodePortDNATIPv4.String()
		svcSNATVIP = config.VirtualServiceIPv4.String()
		nodePortSet = antreaNFTablesSetNodePort
		externalIPSet = antreaNFTablesSetExternalIP
	case knftables.IPv6Family:
		ipAddr = "ipv6_addr"
		ip = "ip6"
		protocol = "nexthdr"
		nodePortDNATVIP = config.VirtualNodePortDNATIPv6.String()
		svcSNATVIP = config.VirtualServiceIPv6.String()
		nodePortSet = antreaNFTablesSetNodePort6
		externalIPSet = antreaNFTablesSetExternalIP6
	}

	tx.Add(&knftables.Set{
		Name:    nodePortSet,
		Type:    ipAddr + " . inet_proto . inet_service",
		Comment: ptr.To("Set containing NodePort tuples (ip, protocol, port)"),
	})
	tx.Add(&knftables.Set{
		Name:    externalIPSet,
		Type:    ipAddr,
		Comment: ptr.To("Set containing external IPs"),
	})
	for _, set := range []string{nodePortSet, externalIPSet} {
		// Flush the sets if it exists.
		tx.Flush(&knftables.Set{
			Name: set,
		})
		// Restore the elements.
		c.serviceNFTablesSets[set].Range(func(_, value any) bool {
			elements := value.([]*knftables.Element)
			for _, element := range elements {
				tx.Add(element)
			}
			return true
		})
	}

	tx.Add(&knftables.Rule{
		Chain: antreaNFTablesRawChainPreroutingProxyAll,
		Rule: knftables.Concat(
			ip, "daddr", "@", externalIPSet,
			"counter",
			"notrack",
		),
		Comment: ptr.To("Do not track request packets destined to external IPs"),
	})
	tx.Add(&knftables.Rule{
		Chain: antreaNFTablesRawChainPreroutingProxyAll,
		Rule: knftables.Concat(
			ip, "saddr", "@", externalIPSet,
			"counter",
			"notrack",
		),
		Comment: ptr.To("Do not track reply packets sourced from external IPs"),
	})
	tx.Add(&knftables.Rule{
		Chain: antreaNFTablesRawChainOutputProxyAll,
		Rule: knftables.Concat(
			ip, "daddr", "@", externalIPSet,
			"counter",
			"notrack",
		),
		Comment: ptr.To("Do not track request packets destined to external IPs"),
	})

	tx.Add(&knftables.Rule{
		Chain: antreaNFTablesNatChainPreroutingProxyAll,
		Rule: knftables.Concat(
			ip, "daddr", ".", ip, protocol, ".", "th dport", "@", nodePortSet,
			"counter",
			"dnat", "to", nodePortDNATVIP,
		),
		Comment: ptr.To("DNAT external to NodePort packets"),
	})
	tx.Add(&knftables.Rule{
		Chain: antreaNFTablesNatChainOutputProxyAll,
		Rule: knftables.Concat(
			ip, "daddr", ".", ip, protocol, ".", "th dport", "@", nodePortSet,
			"counter",
			"dnat", "to", nodePortDNATVIP,
		),
		Comment: ptr.To("DNAT local to NodePort packets"),
	})
	tx.Add(&knftables.Rule{
		Chain: antreaNFTablesNatChainPostroutingProxyAll,
		Rule: knftables.Concat(
			ip, "saddr", svcSNATVIP,
			"counter",
			"masquerade",
		),
		Comment: ptr.To("Masquerade OVS virtual source IP"),
	})
}

func (c *Client) nftablesTrafficAcceleration(tx *knftables.Transaction, ipProtocol knftables.Family) {
	// Add the flowtable for accelerating matched connections.
	tx.Add(&knftables.Flowtable{
		Name:     antreaNFTablesFlowtable,
		Priority: ptr.To(knftables.FilterIngressPriority),
		Devices:  []string{c.nodeConfig.GatewayConfig.Name, c.nodeConfig.NodeTransportInterfaceName},
	})
	// Add a forward hook chain to contain the rules for matching connections which are eligible for flowtable acceleration.
	tx.Add(&knftables.Chain{
		Name:     antreaNFTablesChainForwardOffload,
		Type:     ptr.To(knftables.FilterType),
		Hook:     ptr.To(knftables.ForwardHook),
		Priority: ptr.To(knftables.FilterPriority),
		Comment:  ptr.To("Forward chain containing rules to match connections eligible for flowtable acceleration"),
	})
	// Flush the chain if it already exists. This is safe because the entire transaction is applied atomically:
	// nftables builds the new config in memory and swaps it in one step, so there is never a moment when rules are
	// partially removed or missing. See: https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement
	tx.Flush(&knftables.Chain{
		Name: antreaNFTablesChainForwardOffload,
	})
	if ipProtocol == knftables.IPv4Family {
		// Add the set to contain peer Pod IPv4 CIDRs.
		tx.Add(&knftables.Set{
			Name:    antreaNFTablesSetPeerPodCIDR,
			Type:    "ipv4_addr",
			Flags:   []knftables.SetFlag{knftables.IntervalFlag},
			Comment: ptr.To("Set containing IPv4 peer Pods CIDRs"),
		})
		// Flush the set if it exists.
		tx.Flush(&knftables.Set{
			Name: antreaNFTablesSetPeerPodCIDR,
		})
		// Restore existing IPv4 peer Pod CIDRs into the set.
		c.podCIDRNFTablesSetIPv4.Range(func(_, v interface{}) bool {
			return func(element *knftables.Element) bool {
				tx.Add(element)
				return true
			}(v.(*knftables.Element))
		})
		// Add rules to accelerate Pod-to-Pod IPv4 connections via flowtable.
		tx.Add(&knftables.Rule{
			Chain: antreaNFTablesChainForwardOffload,
			Rule: knftables.Concat(
				"iif", c.nodeConfig.GatewayConfig.Name,
				"ip", "saddr", c.nodeConfig.PodIPv4CIDR.String(),
				"oif", c.nodeConfig.NodeTransportInterfaceName,
				"ip", "daddr", "@", antreaNFTablesSetPeerPodCIDR,
				"flow", "add", "@", antreaNFTablesFlowtable,
				"counter",
			),
			Comment: ptr.To("Accelerate IPv4 connections: local Pod CIDR to remote Pod CIDRs"),
		})
		tx.Add(&knftables.Rule{
			Chain: antreaNFTablesChainForwardOffload,
			Rule: knftables.Concat(
				"iif", c.nodeConfig.NodeTransportInterfaceName,
				"ip", "saddr", "@", antreaNFTablesSetPeerPodCIDR,
				"oif", c.nodeConfig.GatewayConfig.Name,
				"ip", "daddr", c.nodeConfig.PodIPv4CIDR.String(),
				"flow", "add", "@", antreaNFTablesFlowtable,
				"counter",
			),
			Comment: ptr.To("Accelerate IPv4 connections: remote Pod CIDRs to local Pod CIDR"),
		})
	}
	if ipProtocol == knftables.IPv6Family {
		// Add the nft set to contain peer Pod IPv6 CIDRs.
		tx.Add(&knftables.Set{
			Name:    antreaNFTablesSetPeerPodCIDR,
			Type:    "ipv6_addr",
			Flags:   []knftables.SetFlag{knftables.IntervalFlag},
			Comment: ptr.To("Set containing IPv6 peer Pods CIDRs"),
		})
		// Flush the set if it exists.
		tx.Flush(&knftables.Set{
			Name: antreaNFTablesSetPeerPodCIDR,
		})
		// Restore existing IPv6 peer Pod CIDRs into the set.
		c.podCIDRNFTablesSetIPv6.Range(func(_, v interface{}) bool {
			return func(element *knftables.Element) bool {
				tx.Add(element)
				return true
			}(v.(*knftables.Element))
		})
		// Add rules to accelerate Pod-to-Pod IPv6 connections via flowtable.
		tx.Add(&knftables.Rule{
			Chain: antreaNFTablesChainForwardOffload,
			Rule: knftables.Concat(
				"iif", c.nodeConfig.GatewayConfig.Name,
				"ip6", "saddr", c.nodeConfig.PodIPv6CIDR.String(),
				"oif", c.nodeConfig.NodeTransportInterfaceName,
				"ip6", "daddr", "@", antreaNFTablesSetPeerPodCIDR,
				"flow", "add", "@", antreaNFTablesFlowtable,
				"counter",
			),
			Comment: ptr.To("Accelerate IPv6 connections: local Pod CIDR to remote Pod CIDRs"),
		})
		tx.Add(&knftables.Rule{
			Chain: antreaNFTablesChainForwardOffload,
			Rule: knftables.Concat(
				"iif", c.nodeConfig.NodeTransportInterfaceName,
				"ip6", "saddr", "@", antreaNFTablesSetPeerPodCIDR,
				"oif", c.nodeConfig.GatewayConfig.Name,
				"ip6", "daddr", c.nodeConfig.PodIPv6CIDR.String(),
				"flow", "add", "@", antreaNFTablesFlowtable,
				"counter",
			),
			Comment: ptr.To("Accelerate IPv6 connections: remote Pod CIDRs to local Pod CIDR"),
		})
	}
}

func (c *Client) syncNFTables(ctx context.Context) error {
	for ipProtocol, nft := range c.nftables.All() {
		tx := nft.NewTransaction()
		// Add the table whose name is defined when initializing nftables instance.
		tx.Add(&knftables.Table{
			Comment: ptr.To("Rules for Antrea"),
		})

		if c.hostNetworkAccelerationEnabled {
			c.nftablesTrafficAcceleration(tx, ipProtocol)
		}
		if c.proxyAll && c.hostNetworkNFTables {
			c.nftablesProxyAll(tx, ipProtocol)
		}

		if err := nft.Run(ctx, tx); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) addPeerPodCIDRToNFTablesSet(podCIDR *net.IPNet) error {
	var nft knftables.Interface
	isIPv6 := utilnet.IsIPv6(podCIDR.IP)
	if isIPv6 {
		nft = c.nftables.IPv6
	} else {
		nft = c.nftables.IPv4
	}

	tx := nft.NewTransaction()
	element := &knftables.Element{
		Set: antreaNFTablesSetPeerPodCIDR,
		Key: []string{podCIDR.String()},
	}
	tx.Add(element)
	if err := nft.Run(context.TODO(), tx); err != nil {
		return err
	}

	if isIPv6 {
		c.podCIDRNFTablesSetIPv6.Store(podCIDR.String(), element)
	} else {
		c.podCIDRNFTablesSetIPv4.Store(podCIDR.String(), element)
	}

	return nil
}

func (c *Client) deletePeerPodCIDRFromNFTablesSet(podCIDR *net.IPNet) error {
	var nft knftables.Interface
	isIPv6 := utilnet.IsIPv6(podCIDR.IP)
	if isIPv6 {
		nft = c.nftables.IPv6
	} else {
		nft = c.nftables.IPv4
	}

	tx := nft.NewTransaction()
	element := &knftables.Element{
		Set: antreaNFTablesSetPeerPodCIDR,
		Key: []string{podCIDR.String()},
	}
	tx.Delete(element)
	if err := nft.Run(context.TODO(), tx); err != nil {
		return err
	}

	if isIPv6 {
		c.podCIDRNFTablesSetIPv6.Delete(podCIDR.String())
	} else {
		c.podCIDRNFTablesSetIPv4.Delete(podCIDR.String())
	}

	return nil
}

func (c *Client) getNFT(isIPv6 bool) knftables.Interface {
	if isIPv6 {
		return c.nftables.IPv6
	}
	return c.nftables.IPv4
}

func (c *Client) addNodePortConfigsNFTables(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error {
	isIPv6 := isIPv6Protocol(protocol)
	transProtocol := getTransProtocolStr(protocol)
	setName := getNodePortNFTablesSet(isIPv6)
	nft := c.getNFT(isIPv6)

	tx := nft.NewTransaction()
	setElements := make([]*knftables.Element, 0, len(nodePortAddresses))
	for i := range nodePortAddresses {
		key := fmt.Sprintf("%s . %s . %d", nodePortAddresses[i], transProtocol, port)
		elem := &knftables.Element{
			Set: setName,
			Key: []string{key},
		}
		tx.Add(elem)
		setElements = append(setElements, elem)
	}
	if err := nft.Run(context.TODO(), tx); err != nil {
		return fmt.Errorf("failed to add NodePort entries to nftables set %s: %w", setName, err)
	}
	c.serviceNFTablesSets[setName].Store(fmt.Sprintf("%s-%d", protocol, port), setElements)

	klog.V(4).InfoS("Added NodePort entries to nftables set", "set", setName, "addresses", nodePortAddresses, "port", port, "protocol", protocol)
	return nil
}

func (c *Client) addNodePortConfigsIPsets(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error {
	isIPv6 := isIPv6Protocol(protocol)
	transProtocol := getTransProtocolStr(protocol)
	setName := getNodePortIPSetName(isIPv6)

	for i := range nodePortAddresses {
		entry := fmt.Sprintf("%s,%s:%d", nodePortAddresses[i], transProtocol, port)
		if err := c.ipset.AddEntry(setName, entry); err != nil {
			return err
		}
		c.serviceIPSets[setName].Store(entry, struct{}{})
		klog.V(4).InfoS("Added ipset entry for NodePort", "set", setName, "address", nodePortAddresses[i], "port", port, "protocol", protocol)
	}
	return nil
}

func (c *Client) deleteNodePortConfigsNFTables(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error {
	isIPv6 := isIPv6Protocol(protocol)
	transProtocol := getTransProtocolStr(protocol)
	setName := getNodePortNFTablesSet(isIPv6)
	nft := c.getNFT(isIPv6)

	tx := nft.NewTransaction()
	for i := range nodePortAddresses {
		key := fmt.Sprintf("%s . %s . %d", nodePortAddresses[i], transProtocol, port)
		elem := &knftables.Element{
			Set: setName,
			Key: []string{key},
		}
		tx.Delete(elem)
	}
	if err := nft.Run(context.TODO(), tx); err != nil {
		return fmt.Errorf("failed to delete NodePort entries from nftables set %s: %w", setName, err)
	}

	c.serviceNFTablesSets[setName].Delete(fmt.Sprintf("%s-%d", protocol, port))
	klog.V(4).InfoS("Deleted NodePort entries from nftables set", "set", setName, "addresses", nodePortAddresses, "port", port, "protocol", protocol)
	return nil
}

func (c *Client) deleteNodePortConfigsIPsets(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error {
	isIPv6 := isIPv6Protocol(protocol)
	transProtocol := getTransProtocolStr(protocol)
	setName := getNodePortIPSetName(isIPv6)

	for i := range nodePortAddresses {
		entry := fmt.Sprintf("%s,%s:%d", nodePortAddresses[i], transProtocol, port)
		if err := c.ipset.DelEntry(setName, entry); err != nil {
			return err
		}
		c.serviceIPSets[setName].Delete(entry)
		klog.V(4).InfoS("Deleted ipset entry for NodePort IP", "set", setName, "address", nodePortAddresses[i], "port", port, "protocol", protocol)
	}
	return nil
}

// addExternalIPConfigsRoute is idempotent. If the route has already been added, it returns no error. This ensures
// correctness when addExternalIPConfigsRoute calls it even after a prior partial cleanup or failure.
func (c *Client) addExternalIPConfigsRoute(externalIP net.IP) error {
	externalIPStr := externalIP.String()
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	var gw net.IP
	var mask int
	if utilnet.IsIPv4(externalIP) {
		gw = config.VirtualServiceIPv4
		mask = net.IPv4len * 8
	} else {
		gw = config.VirtualServiceIPv6
		mask = net.IPv6len * 8
	}
	route := generateRoute(externalIP, mask, gw, linkIndex, netlink.SCOPE_UNIVERSE, nil, nil)
	if err := c.netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("failed to add route for externalIP %s: %w", externalIPStr, err)
	}
	klog.V(4).InfoS("Added route for externalIP", "externalIP", externalIPStr)
	c.serviceRoutes.Store(externalIPStr, route)
	return nil
}

func (c *Client) addExternalIPConfigsNFTables(externalIP net.IP) error {
	isIPv6 := utilnet.IsIPv6(externalIP)
	externalIPStr := externalIP.String()
	nft := c.getNFT(isIPv6)
	tx := nft.NewTransaction()
	setName := getExternalIPNFTablesSet(isIPv6)

	element := &knftables.Element{
		Set: setName,
		Key: []string{externalIPStr},
	}
	tx.Add(element)
	if err := nft.Run(context.TODO(), tx); err != nil {
		return fmt.Errorf("failed to add externalIP %s to nftables set %s", externalIPStr, setName)
	}
	klog.V(4).InfoS("Added externalIP to nftables set", "set", setName, "externalIP", externalIPStr)

	c.serviceNFTablesSets[setName].Store(externalIPStr, []*knftables.Element{element})
	return nil
}

func (c *Client) addExternalIPConfigsIPsets(externalIP net.IP) error {
	isIPv6 := utilnet.IsIPv6(externalIP)
	externalIPStr := externalIP.String()
	setName := getExternalIPIPSetName(isIPv6)

	if err := c.ipset.AddEntry(setName, externalIPStr); err != nil {
		return fmt.Errorf("failed to add %s to ipset %s", externalIPStr, setName)
	}
	klog.V(4).InfoS("Added externalIP to ipset", "set", setName, "externalIP", externalIPStr)

	c.serviceIPSets[setName].Store(externalIPStr, struct{}{})
	return nil
}

// deleteExternalIPConfigsRoute is idempotent. If the route has already been deleted, it returns no error. This ensures
// correctness when DeleteExternalIPConfigs calls it even after a prior partial cleanup or failure.
func (c *Client) deleteExternalIPConfigsRoute(externalIP net.IP) error {
	externalIPStr := externalIP.String()

	route, found := c.serviceRoutes.Load(externalIPStr)
	if !found {
		klog.V(2).InfoS("Didn't find route for externalIP", "externalIP", externalIPStr)
		return nil
	}
	if err := c.netlink.RouteDel(route.(*netlink.Route)); err != nil {
		if err.Error() == "no such process" {
			klog.InfoS("Failed to delete route for externalIP since it doesn't exist", "externalIP", externalIPStr)
		} else {
			return fmt.Errorf("failed to delete route for externalIP %s: %w", externalIPStr, err)
		}
	}
	klog.V(4).InfoS("Deleted route for externalIP", "externalIP", externalIPStr)
	c.serviceRoutes.Delete(externalIPStr)
	return nil
}

func (c *Client) deleteExternalIPConfigsNFTables(externalIP net.IP) error {
	externalIPStr := externalIP.String()
	isIPv6 := utilnet.IsIPv6(externalIP)
	nft := c.getNFT(isIPv6)
	tx := nft.NewTransaction()
	setName := getExternalIPNFTablesSet(isIPv6)

	element := &knftables.Element{
		Set: setName,
		Key: []string{externalIPStr},
	}
	tx.Delete(element)
	if err := nft.Run(context.TODO(), tx); err != nil {
		return fmt.Errorf("failed to delete externalIP %s from nftables set %s", externalIPStr, setName)
	}

	klog.V(4).InfoS("Deleted externalIP from nftables set", "set", setName, "externalIP", externalIPStr)
	c.serviceNFTablesSets[setName].Delete(externalIPStr)
	return nil
}

func (c *Client) deleteExternalIPConfigsIPsets(externalIP net.IP) error {
	externalIPStr := externalIP.String()
	isIPv6 := utilnet.IsIPv6(externalIP)
	setName := getExternalIPIPSetName(isIPv6)
	if err := c.ipset.DelEntry(setName, externalIPStr); err != nil {
		return err
	}

	klog.V(4).InfoS("Deleted external IP from ipset", "set", setName, "externalIP", externalIPStr)
	c.serviceIPSets[setName].Delete(externalIPStr)
	return nil
}
