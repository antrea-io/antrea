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
	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/util/ipset"
	"antrea.io/antrea/pkg/agent/util/iptables"
	"antrea.io/antrea/pkg/agent/util/sysctl"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/env"
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

	// Antrea proxy NodePort IP
	antreaNodePortIPSet  = "ANTREA-NODEPORT-IP"
	antreaNodePortIP6Set = "ANTREA-NODEPORT-IP6"

	// Antrea managed iptables chains.
	antreaForwardChain     = "ANTREA-FORWARD"
	antreaPreRoutingChain  = "ANTREA-PREROUTING"
	antreaPostRoutingChain = "ANTREA-POSTROUTING"
	antreaOutputChain      = "ANTREA-OUTPUT"
	antreaMangleChain      = "ANTREA-MANGLE"

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
)

// Client takes care of routing container packets in host network, coordinating ip route, ip rule, iptables and ipset.
type Client struct {
	nodeConfig    *config.NodeConfig
	networkConfig *config.NetworkConfig
	noSNAT        bool
	ipt           *iptables.Client
	// nodeRoutes caches ip routes to remote Pods. It's a map of podCIDR to routes.
	nodeRoutes sync.Map
	// nodeNeighbors caches IPv6 Neighbors to remote host gateway
	nodeNeighbors sync.Map
	// markToSNATIP caches marks to SNAT IPs. It's used in Egress feature.
	markToSNATIP sync.Map
	// iptablesInitialized is used to notify when iptables initialization is done.
	iptablesInitialized   chan struct{}
	proxyAll              bool
	connectUplinkToBridge bool
	multicastEnabled      bool
	// serviceRoutes caches ip routes about Services.
	serviceRoutes sync.Map
	// serviceNeighbors caches neighbors.
	serviceNeighbors sync.Map
	// nodePortsIPv4 caches all existing IPv4 NodePorts.
	nodePortsIPv4 sync.Map
	// nodePortsIPv6 caches all existing IPv6 NodePorts.
	nodePortsIPv6 sync.Map
	// clusterIPv4CIDR stores the calculated ClusterIP CIDR for IPv4.
	clusterIPv4CIDR *net.IPNet
	// clusterIPv6CIDR stores the calculated ClusterIP CIDR for IPv6.
	clusterIPv6CIDR *net.IPNet
}

// NewClient returns a route client.
func NewClient(networkConfig *config.NetworkConfig, noSNAT, proxyAll, connectUplinkToBridge, multicastEnabled bool) (*Client, error) {
	return &Client{
		networkConfig:         networkConfig,
		noSNAT:                noSNAT,
		proxyAll:              proxyAll,
		multicastEnabled:      multicastEnabled,
		connectUplinkToBridge: connectUplinkToBridge,
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

	// Ensure IPv6 forwarding is enabled if it is a dual-stack or IPv6-only cluster.
	if c.nodeConfig.NodeIPv6Addr != nil {
		sysctlFilename := "ipv6/conf/all/forwarding"
		v, err := sysctl.GetSysctlNet(sysctlFilename)
		if err != nil {
			return fmt.Errorf("failed to read value of sysctl file: %s", sysctlFilename)
		}
		if v != 1 {
			return fmt.Errorf("IPv6 forwarding is not enabled")
		}
	}

	// Set up the IP routes and sysctl parameters to support all Services in AntreaProxy.
	if c.proxyAll {
		if err := c.initServiceIPRoutes(); err != nil {
			return fmt.Errorf("failed to initialize Service IP routes: %v", err)
		}
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
	restoreRoute := func(route *netlink.Route) bool {
		r, ok := routeMap[route.Dst.String()]
		if ok && routeEqual(route, r) {
			return true
		}
		if err := netlink.RouteReplace(route); err != nil {
			klog.Errorf("Failed to add route to the gateway: %v", err)
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
		gwAutoconfRoutes = append(gwAutoconfRoutes, &netlink.Route{
			LinkIndex: c.nodeConfig.GatewayConfig.LinkIndex,
			Dst:       c.nodeConfig.PodIPv6CIDR,
			Src:       c.nodeConfig.GatewayConfig.IPv6,
			Scope:     netlink.SCOPE_LINK,
		})
	}
	for _, route := range gwAutoconfRoutes {
		restoreRoute(route)
	}
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

	// If proxy full is enabled, create NodePort ipset.
	if c.proxyAll {
		if err := ipset.CreateIPSet(antreaNodePortIPSet, ipset.HashIPPort, false); err != nil {
			return err
		}
		if err := ipset.CreateIPSet(antreaNodePortIP6Set, ipset.HashIPPort, true); err != nil {
			return err
		}

		c.nodePortsIPv4.Range(func(k, _ interface{}) bool {
			ipSetEntry := k.(string)
			if err := ipset.AddEntry(antreaNodePortIPSet, ipSetEntry); err != nil {
				return false
			}
			return true
		})
		c.nodePortsIPv6.Range(func(k, _ interface{}) bool {
			ipSetEntry := k.(string)
			if err := ipset.AddEntry(antreaNodePortIP6Set, ipSetEntry); err != nil {
				return false
			}
			return true
		})
	}

	if c.connectUplinkToBridge {
		if err := ipset.CreateIPSet(localAntreaFlexibleIPAMPodIPSet, ipset.HashIP, false); err != nil {
			return err
		}
		if err := ipset.CreateIPSet(localAntreaFlexibleIPAMPodIP6Set, ipset.HashIP, true); err != nil {
			return err
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

func getNodePortIPSetName(isIPv6 bool) string {
	if isIPv6 {
		return antreaNodePortIP6Set
	} else {
		return antreaNodePortIPSet
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
//  * for the reverse path for NodePort Service traffic (see
//    https://github.com/antrea-io/antrea/issues/678).
//  * for Pod-to-external traffic that needs to be SNATed (see
//    https://github.com/antrea-io/antrea/issues/3946).
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
		"-A", antreaMangleChain,
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

// syncIPTables ensure that the iptables infrastructure we use is set up.
// It's idempotent and can safely be called on every startup.
func (c *Client) syncIPTables() error {
	var err error

	c.ipt, err = iptables.New(c.networkConfig.IPv4Enabled, c.networkConfig.IPv6Enabled)
	if err != nil {
		return fmt.Errorf("error creating IPTables instance: %v", err)
	}
	// Create the antrea managed chains and link them to built-in chains.
	// We cannot use iptables-restore for these jump rules because there
	// are non antrea managed rules in built-in chains.
	type jumpRule struct {
		table    string
		srcChain string
		dstChain string
		comment  string
	}
	jumpRules := []jumpRule{
		{iptables.RawTable, iptables.PreRoutingChain, antreaPreRoutingChain, "Antrea: jump to Antrea prerouting rules"},
		{iptables.RawTable, iptables.OutputChain, antreaOutputChain, "Antrea: jump to Antrea output rules"},
		{iptables.FilterTable, iptables.ForwardChain, antreaForwardChain, "Antrea: jump to Antrea forwarding rules"},
		{iptables.NATTable, iptables.PostRoutingChain, antreaPostRoutingChain, "Antrea: jump to Antrea postrouting rules"},
		{iptables.MangleTable, iptables.PreRoutingChain, antreaMangleChain, "Antrea: jump to Antrea mangle rules"}, // TODO: unify the chain naming style
		{iptables.MangleTable, iptables.OutputChain, antreaOutputChain, "Antrea: jump to Antrea output rules"},
	}
	if c.proxyAll || env.IsCloudEKS() {
		jumpRules = append(jumpRules, jumpRule{iptables.NATTable, iptables.PreRoutingChain, antreaPreRoutingChain, "Antrea: jump to Antrea prerouting rules"})
	}
	if c.proxyAll {
		jumpRules = append(jumpRules, jumpRule{iptables.NATTable, iptables.OutputChain, antreaOutputChain, "Antrea: jump to Antrea output rules"})
	}
	for _, rule := range jumpRules {
		if err := c.ipt.EnsureChain(iptables.ProtocolDual, rule.table, rule.dstChain); err != nil {
			return err
		}
		ruleSpec := []string{"-j", rule.dstChain, "-m", "comment", "--comment", rule.comment}
		if err := c.ipt.AppendRule(iptables.ProtocolDual, rule.table, rule.srcChain, ruleSpec); err != nil {
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
	if c.networkConfig.IPv4Enabled {
		iptablesData := c.restoreIptablesData(c.nodeConfig.PodIPv4CIDR,
			antreaPodIPSet,
			localAntreaFlexibleIPAMPodIPSet,
			antreaNodePortIPSet,
			config.VirtualNodePortDNATIPv4,
			config.VirtualServiceIPv4,
			snatMarkToIPv4,
			false)

		// Setting --noflush to keep the previous contents (i.e. non antrea managed chains) of the tables.
		if err := c.ipt.Restore(iptablesData.Bytes(), false, false); err != nil {
			return err
		}
	}

	// Use ip6tables-restore to configure IPv6 settings.
	if c.networkConfig.IPv6Enabled {
		iptablesData := c.restoreIptablesData(c.nodeConfig.PodIPv6CIDR,
			antreaPodIP6Set,
			localAntreaFlexibleIPAMPodIP6Set,
			antreaNodePortIP6Set,
			config.VirtualNodePortDNATIPv6,
			config.VirtualServiceIPv6,
			snatMarkToIPv6,
			true)
		// Setting --noflush to keep the previous contents (i.e. non antrea managed chains) of the tables.
		if err := c.ipt.Restore(iptablesData.Bytes(), false, true); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) restoreIptablesData(podCIDR *net.IPNet,
	podIPSet,
	localAntreaFlexibleIPAMPodIPSet,
	nodePortIPSet string,
	nodePortDNATVirtualIP,
	serviceVirtualIP net.IP,
	snatMarkToIP map[uint32]net.IP,
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

	// When Antrea is used to enforce NetworkPolicies in EKS, additional iptables
	// mangle rules are required. See https://github.com/antrea-io/antrea/issues/678.
	// These rules are only needed for IPv4.
	if env.IsCloudEKS() && !isIPv6 {
		c.writeEKSMangleRules(iptablesData)
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
	writeLine(iptablesData, "COMMIT")

	writeLine(iptablesData, "*nat")
	if c.proxyAll || env.IsCloudEKS() {
		writeLine(iptablesData, iptables.MakeChainLine(antreaPreRoutingChain))
	}
	if c.proxyAll {
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
	if c.multicastEnabled && c.networkConfig.TrafficEncapMode.SupportsNoEncap() {
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
			"!", "-o", c.nodeConfig.GatewayConfig.Name,
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

	// If AntreaProxy full support is enabled, it SNATs the packets whose source IP is VirtualServiceIPv4/VirtualServiceIPv6
	// so the packets can be routed back to this Node.
	if c.proxyAll {
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
	//   01. Regular Pod              -- hostPort [request]              --> AntreaIPAM VLAN Pod
	//   02. AntreaIPAM Pod           -- hostPort [request]              --> AntreaIPAM VLAN Pod
	//   03. AntreaIPAM VLAN Pod      -- hostPort [request]              --> AntreaIPAM VLAN Pod (different subnet/VLAN)
	//   04. External                 -- hostPort [request]              --> AntreaIPAM VLAN Pod
	// Below traffic models are already covered by portmap CNI:
	//   01. AntreaIPAM VLAN Pod      -- hostPort [request]              --> AntreaIPAM VLAN Pod (same subnet)
	if c.connectUplinkToBridge {
		writeLine(iptablesData, []string{
			"-A", antreaPostRoutingChain,
			"-m", "comment", "--comment", `"Antrea: masquerade traffic to local AntreaIPAM hostPort Pod"`,
			"-m", "set", "--match-set", localAntreaFlexibleIPAMPodIPSet, "dst",
			"-j", iptables.MasqueradeTarget,
		}...)
	}

	// When Antrea is used to enforce NetworkPolicies in EKS, additional iptables
	// nat rules are required. See https://github.com/antrea-io/antrea/issues/3946.
	// These rules are only needed for IPv4.
	if env.IsCloudEKS() && !isIPv6 {
		c.writeEKSNATRules(iptablesData)
	}

	writeLine(iptablesData, "COMMIT")
	return iptablesData
}

func (c *Client) initIPRoutes() error {
	if c.networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		gwLink := util.GetNetLink(c.nodeConfig.GatewayConfig.Name)
		if c.nodeConfig.NodeTransportIPv4Addr != nil {
			_, gwIP, _ := net.ParseCIDR(fmt.Sprintf("%s/32", c.nodeConfig.NodeTransportIPv4Addr.IP.String()))
			if err := netlink.AddrReplace(gwLink, &netlink.Addr{IPNet: gwIP}); err != nil {
				return fmt.Errorf("failed to add address %s to gw %s: %v", gwIP, gwLink.Attrs().Name, err)
			}
		}
		if c.nodeConfig.NodeTransportIPv6Addr != nil {
			_, gwIP, _ := net.ParseCIDR(fmt.Sprintf("%s/128", c.nodeConfig.NodeTransportIPv6Addr.IP.String()))
			if err := netlink.AddrReplace(gwLink, &netlink.Addr{IPNet: gwIP}); err != nil {
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
	return nil
}

// Reconcile removes orphaned podCIDRs from ipset and removes routes to orphaned podCIDRs
// based on the desired podCIDRs. svcIPs are used for Windows only.
func (c *Client) Reconcile(podCIDRs []string, svcIPs map[string]bool) error {
	desiredPodCIDRs := sets.NewString(podCIDRs...)
	// Get the peer IPv6 gateways from pod CIDRs
	desiredIPv6GWs := getIPv6Gateways(podCIDRs)

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
			klog.Infof("Deleting orphaned Pod IP %s from ipset and route table", entry)
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
		if err := netlink.RouteDel(&route); err != nil && err != unix.ESRCH {
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
		if err := netlink.NeighDel(actualNeigh); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) isServiceRoute(route *netlink.Route) bool {
	// If the destination IP or gateway IP is virtual Service IP , then it is a route which is added by AntreaProxy.
	if route.Dst.IP.Equal(config.VirtualServiceIPv6) || route.Dst.IP.Equal(config.VirtualServiceIPv4) ||
		route.Gw.Equal(config.VirtualServiceIPv6) || route.Gw.Equal(config.VirtualServiceIPv4) {
		return true
	}
	return false
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
	var nodeTransportIPAddr *net.IPNet
	if podCIDR.IP.To4() == nil {
		nodeTransportIPAddr = c.nodeConfig.NodeTransportIPv6Addr
	} else {
		nodeTransportIPAddr = c.nodeConfig.NodeTransportIPv4Addr
	}

	podCIDRStr := podCIDR.String()
	ipsetName := getIPSetName(podCIDR.IP)
	// Add this podCIDR to antreaPodIPSet so that packets to them won't be masqueraded when they leave the host.
	if err := ipset.AddEntry(ipsetName, podCIDRStr); err != nil {
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
		if podCIDR.IP.To4() != nil {
			podCIDRRoute.Src = c.nodeConfig.GatewayConfig.IPv4
		} else {
			podCIDRRoute.Src = c.nodeConfig.GatewayConfig.IPv6
		}
		routes = append(routes, podCIDRRoute)
	} else if c.networkConfig.NeedsTunnelToPeer(nodeIP, nodeTransportIPAddr) {
		if podCIDR.IP.To4() == nil {
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
	} else {
		// NetworkPolicyOnly mode or NoEncap traffic to a Node on a different subnet.
		// Routing should be handled by a route which is already present on the host.
		klog.InfoS("Skip adding routes to peer", "node", nodeName, "ip", nodeIP, "podCIDR", podCIDR)
	}
	for _, route := range routes {
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("failed to install route to peer %s (%s) with netlink. Route config: %s. Error: %v", nodeName, nodeIP, route.String(), err)
		}
	}
	// Delete stale route and neigh to peer gateway.
	if !requireNodeGwIPv6RouteAndNeigh && utilnet.IsIPv6(nodeGwIP) {
		routeToNodeGwIPNetv6 := &netlink.Route{
			Dst: &net.IPNet{IP: nodeGwIP, Mask: net.CIDRMask(128, 128)},
		}
		if err := netlink.RouteDel(routeToNodeGwIPNetv6); err == nil {
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
		if err := netlink.NeighDel(neigh); err == nil {
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

func (c *Client) DeleteClusterIPRoute(svcIP net.IP) error {
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
	var link netlink.Link
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
	protocol := iptables.ProtocolIPv4
	if snatIP.To4() == nil {
		protocol = iptables.ProtocolIPv6
	}
	return c.ipt.DeleteRule(protocol, iptables.NATTable, antreaPostRoutingChain, c.snatRuleSpec(snatIP, mark))
}

// addVirtualServiceIPRoute is used to add routing entry which is used to forward the packets whose destination IP is
// virtual Service IP back to Antrea gateway on host.
func (c *Client) addVirtualServiceIPRoute(isIPv6 bool) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	svcIP := config.VirtualServiceIPv4
	mask := ipv4AddrLength
	if isIPv6 {
		svcIP = config.VirtualServiceIPv6
		mask = ipv6AddrLength
	}

	neigh := generateNeigh(svcIP, linkIndex)
	if err := netlink.NeighSet(neigh); err != nil {
		return fmt.Errorf("failed to add new IP neighbour for %s: %w", svcIP, err)
	}
	c.serviceNeighbors.Store(svcIP.String(), neigh)

	route := generateRoute(svcIP, mask, nil, linkIndex, netlink.SCOPE_LINK)
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("failed to install route for virtual Service IP %s: %w", svcIP.String(), err)
	}
	c.serviceRoutes.Store(svcIP.String(), route)
	klog.InfoS("Added virtual Service IP route", "route", route)

	return nil
}

// AddNodePort is used to add IP,port:protocol entries to target ip set when a NodePort Service is added. An entry is added
// for every NodePort IP.
func (c *Client) AddNodePort(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error {
	isIPv6 := isIPv6Protocol(protocol)
	transProtocol := getTransProtocolStr(protocol)
	ipSetName := getNodePortIPSetName(isIPv6)

	for i := range nodePortAddresses {
		ipSetEntry := fmt.Sprintf("%s,%s:%d", nodePortAddresses[i], transProtocol, port)
		if err := ipset.AddEntry(ipSetName, ipSetEntry); err != nil {
			return err
		}
		if isIPv6 {
			c.nodePortsIPv6.Store(ipSetEntry, struct{}{})
		} else {
			c.nodePortsIPv4.Store(ipSetEntry, struct{}{})
		}
	}

	return nil
}

// DeleteNodePort is used to delete related IP set entries when a NodePort Service is deleted.
func (c *Client) DeleteNodePort(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error {
	isIPv6 := isIPv6Protocol(protocol)
	transProtocol := getTransProtocolStr(protocol)
	ipSetName := getNodePortIPSetName(isIPv6)

	for i := range nodePortAddresses {
		ipSetEntry := fmt.Sprintf("%s,%s:%d", nodePortAddresses[i], transProtocol, port)
		if err := ipset.DelEntry(ipSetName, ipSetEntry); err != nil {
			return err
		}
		if isIPv6 {
			c.nodePortsIPv6.Delete(ipSetEntry)
		} else {
			c.nodePortsIPv4.Delete(ipSetEntry)
		}
	}

	return nil
}

// AddClusterIPRoute is used to add or update a routing entry which is used to route ClusterIP traffic to Antrea gateway.
func (c *Client) AddClusterIPRoute(svcIP net.IP) error {
	isIPv6 := utilnet.IsIPv6(svcIP)
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	scope := netlink.SCOPE_UNIVERSE
	curClusterIPCIDR := c.clusterIPv4CIDR
	mask := ipv4AddrLength
	gw := config.VirtualServiceIPv4
	if isIPv6 {
		curClusterIPCIDR = c.clusterIPv6CIDR
		mask = ipv6AddrLength
		gw = config.VirtualServiceIPv6
	}

	// If the route exists and its destination CIDR contains the ClusterIP, there is no need to update the route.
	if curClusterIPCIDR != nil && curClusterIPCIDR.Contains(svcIP) {
		klog.V(4).InfoS("Route with current ClusterIP CIDR can route the ClusterIP to Antrea gateway", "ClusterIP CIDR", curClusterIPCIDR, "ClusterIP", svcIP)
		return nil
	}

	var newClusterIPCIDR *net.IPNet
	var err error
	if curClusterIPCIDR != nil {
		// If the route exists and its destination CIDR doesn't contain the ClusterIP, generate a new destination CIDR by
		// enlarging the current destination CIDR with the ClusterIP.
		if newClusterIPCIDR, err = util.ExtendCIDRWithIP(curClusterIPCIDR, svcIP); err != nil {
			return fmt.Errorf("enlarge the destination CIDR with an error: %w", err)
		}
	} else {
		// If the route doesn't exist, generate a new destination CIDR with the ClusterIP. Note that, this is the first
		// ClusterIP since the route doesn't exist.
		newClusterIPCIDR = &net.IPNet{IP: svcIP, Mask: net.CIDRMask(mask, mask)}
	}

	// Generate a route with the new destination CIDR and install it.
	newClusterIPCIDRMask, _ := newClusterIPCIDR.Mask.Size()
	route := generateRoute(newClusterIPCIDR.IP, newClusterIPCIDRMask, gw, linkIndex, scope)
	if err = netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("failed to install new ClusterIP route: %w", err)
	}
	// Store the new destination CIDR.
	if isIPv6 {
		c.clusterIPv6CIDR = route.Dst
	} else {
		c.clusterIPv4CIDR = route.Dst
	}
	klog.V(4).InfoS("Created a route to route the ClusterIP to Antrea gateway", "route", route, "ClusterIP", svcIP)

	// Collect stale routes.
	var staleRoutes []*netlink.Route
	if curClusterIPCIDR != nil {
		// If current destination CIDR is not nil, the route with current destination CIDR should be uninstalled.
		route.Dst = curClusterIPCIDR
		staleRoutes = []*netlink.Route{route}
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
			if routes[i].Gw.Equal(gw) && !routes[i].Dst.IP.Equal(svcIP) && routes[i].Dst.Contains(svcIP) {
				staleRoutes = append(staleRoutes, &routes[i])
			}
		}
	}

	// Remove stale routes.
	for _, rt := range staleRoutes {
		if err = netlink.RouteDel(rt); err != nil {
			return fmt.Errorf("failed to uninstall stale ClusterIP route %s: %w", rt.String(), err)
		}
		klog.V(4).InfoS("Uninstalled stale ClusterIP route successfully", "stale route", rt)
	}

	return nil
}

func (c *Client) addVirtualNodePortDNATIPRoute(isIPv6 bool) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	vIP := config.VirtualNodePortDNATIPv4
	gw := config.VirtualServiceIPv4
	mask := ipv4AddrLength
	if isIPv6 {
		vIP = config.VirtualNodePortDNATIPv6
		gw = config.VirtualServiceIPv6
		mask = ipv6AddrLength
	}
	route := generateRoute(vIP, mask, gw, linkIndex, netlink.SCOPE_UNIVERSE)
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("failed to install routing entry for virtual NodePort DNAT IP %s: %w", vIP.String(), err)
	}
	klog.V(4).InfoS("Added virtual NodePort DNAT IP route", "route", route)
	c.serviceRoutes.Store(vIP.String(), route)

	return nil
}

// addLoadBalancerIngressIPRoute is used to add routing entry which is used to route LoadBalancer ingress IP to Antrea
// gateway on host.
func (c *Client) addLoadBalancerIngressIPRoute(svcIPStr string) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	svcIP := net.ParseIP(svcIPStr)
	isIPv6 := utilnet.IsIPv6(svcIP)
	var gw net.IP
	var mask int
	if !isIPv6 {
		gw = config.VirtualServiceIPv4
		mask = ipv4AddrLength
	} else {
		gw = config.VirtualServiceIPv6
		mask = ipv6AddrLength
	}

	route := generateRoute(svcIP, mask, gw, linkIndex, netlink.SCOPE_UNIVERSE)
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("failed to install routing entry for LoadBalancer ingress IP %s: %w", svcIP.String(), err)
	}
	klog.V(4).InfoS("Added LoadBalancer ingress IP route", "route", route)
	c.serviceRoutes.Store(svcIP.String(), route)

	return nil
}

// deleteLoadBalancerIngressIPRoute is used to delete routing entry which is used to route LoadBalancer ingress IP to Antrea
// gateway on host.
func (c *Client) deleteLoadBalancerIngressIPRoute(svcIPStr string) error {
	linkIndex := c.nodeConfig.GatewayConfig.LinkIndex
	svcIP := net.ParseIP(svcIPStr)
	isIPv6 := utilnet.IsIPv6(svcIP)
	var gw net.IP
	var mask int
	if !isIPv6 {
		gw = config.VirtualServiceIPv4
		mask = ipv4AddrLength
	} else {
		gw = config.VirtualServiceIPv6
		mask = ipv6AddrLength
	}

	route := generateRoute(svcIP, mask, gw, linkIndex, netlink.SCOPE_UNIVERSE)
	if err := netlink.RouteDel(route); err != nil {
		if err.Error() == "no such process" {
			klog.InfoS("Failed to delete LoadBalancer ingress IP route since the route has been deleted", "route", route)
		} else {
			return fmt.Errorf("failed to delete routing entry for LoadBalancer ingress IP %s: %w", svcIP.String(), err)
		}
	}
	klog.V(4).InfoS("Deleted LoadBalancer ingress IP route", "route", route)
	c.serviceRoutes.Delete(svcIP.String())

	return nil
}

// AddLoadBalancer is used to add routing entries when a LoadBalancer Service is added.
func (c *Client) AddLoadBalancer(externalIPs []string) error {
	for _, svcIPStr := range externalIPs {
		if err := c.addLoadBalancerIngressIPRoute(svcIPStr); err != nil {
			return err
		}
	}

	return nil
}

// DeleteLoadBalancer is used to delete routing entries when a LoadBalancer Service is deleted.
func (c *Client) DeleteLoadBalancer(externalIPs []string) error {
	for _, svcIPStr := range externalIPs {
		if err := c.deleteLoadBalancerIngressIPRoute(svcIPStr); err != nil {
			return err
		}
	}

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
		if err := ipset.AddEntry(ipSetName, ipSetEntry); err != nil {
			return err
		}
	}
	return nil
}

// DeletLocaleAntreaFlexibleIPAMPodRule is used to delete related IP set entries when an AntreaFlexibleIPAM Pod is deleted.
func (c *Client) DeleteLocalAntreaFlexibleIPAMPodRule(podAddresses []net.IP) error {
	if !c.connectUplinkToBridge {
		return nil
	}
	for i := range podAddresses {
		isIPv6 := podAddresses[i].To4() == nil
		ipSetEntry := podAddresses[i].String()
		ipSetName := getLocalAntreaFlexibleIPAMPodIPSetName(isIPv6)
		if err := ipset.DelEntry(ipSetName, ipSetEntry); err != nil {
			return err
		}
	}
	return nil
}

func getTransProtocolStr(protocol binding.Protocol) string {
	if protocol == binding.ProtocolTCP || protocol == binding.ProtocolTCPv6 {
		return "tcp"
	} else if protocol == binding.ProtocolUDP || protocol == binding.ProtocolUDPv6 {
		return "udp"
	} else if protocol == binding.ProtocolSCTP || protocol == binding.ProtocolSCTPv6 {
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

func generateRoute(ip net.IP, mask int, gw net.IP, linkIndex int, scope netlink.Scope) *netlink.Route {
	addrBits := ipv4AddrLength
	if ip.To4() == nil {
		addrBits = ipv6AddrLength
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
