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
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	proxytypes "github.com/vmware-tanzu/antrea/pkg/agent/proxy/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/agent/util/ipset"
	"github.com/vmware-tanzu/antrea/pkg/agent/util/iptables"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	"github.com/vmware-tanzu/antrea/pkg/util/env"
)

const (
	vxlanPort  = 4789
	genevePort = 6081

	// Antrea managed ipset.
	// antreaPodIPSet contains all Pod CIDRs of this cluster.
	antreaPodIPSet = "ANTREA-POD-IP"
	// antreaPodIP6Set contains all IPv6 Pod CIDRs of this cluster.
	antreaPodIP6Set = "ANTREA-POD-IP6"
	// antreaNodePortClusterSet contains all Cluster type NodePort Services Addresses.
	antreaNodePortClusterSet  = "ANTREA-SVC-NP-CLUSTER"
	antreaNodePortClusterSet6 = "ANTREA-SVC-NP-CLUSTER6"
	antreaNodePortLocalSet    = "ANTREA-SVC-NP-LOCAL"
	antreaNodePortLocalSet6   = "ANTREA-SVC-NP-LOCAL6"

	// Antrea managed iptables chains.
	antreaForwardChain          = "ANTREA-FORWARD"
	antreaPreRoutingChain       = "ANTREA-PREROUTING"
	antreaNodePortServicesChain = "ANTREA-SVC-NP"
	antreaServicesMasqChain     = "ANTREA-SVC-MASQ"
	antreaPostRoutingChain      = "ANTREA-POSTROUTING"
	antreaOutputChain           = "ANTREA-OUTPUT"
	antreaMangleChain           = "ANTREA-MANGLE"

	localNodePortMark   = "0xf0"
	clusterNodePortMark = "0xf1"
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
	serviceCIDR   *net.IPNet
	ipt           *iptables.Client
	// nodeRoutes caches ip routes to remote Pods. It's a map of podCIDR to routes.
	nodeRoutes sync.Map
	// nodeNeighbors caches IPv6 Neighbors to remote host gateway
	nodeNeighbors                          sync.Map
	nodePortVirtualIP, nodePortVirtualIPv6 net.IP
	nodeportSupport                        bool
	// iptablesInitialized is used to notify when iptables initialization is done.
	iptablesInitialized chan struct{}
}

// NewClient returns a route client.
// TODO: remove param serviceCIDR after kube-proxy is replaced by Antrea Proxy. This param is not used in this file;
// leaving it here is to be compatible with the implementation on Windows.
func NewClient(
	nodePortVirtualIP net.IP,
	nodePortVirtualIPv6 net.IP,
	serviceCIDR *net.IPNet,
	networkConfig *config.NetworkConfig,
	noSNAT bool,
	nodeportSupport bool,
) (*Client, error) {
	return &Client{
		nodePortVirtualIP:   nodePortVirtualIP,
		nodePortVirtualIPv6: nodePortVirtualIPv6,
		serviceCIDR:         serviceCIDR,
		networkConfig:       networkConfig,
		noSNAT:              noSNAT,
		nodeportSupport:     nodeportSupport,
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
	klog.V(3).Infof("Successfully synced node iptables")
}

// syncIPSet ensures that the required ipset exists and it has the initial members.
func (c *Client) syncIPSet() error {
	if c.nodeportSupport {
		if err := ipset.CreateIPSet(antreaNodePortClusterSet, ipset.HashIPPort, false); err != nil {
			return err
		}
		if err := ipset.CreateIPSet(antreaNodePortLocalSet, ipset.HashIPPort, false); err != nil {
			return err
		}
		if err := ipset.CreateIPSet(antreaNodePortClusterSet6, ipset.HashIPPort, true); err != nil {
			return err
		}
		if err := ipset.CreateIPSet(antreaNodePortLocalSet6, ipset.HashIPPort, true); err != nil {
			return err
		}
	}
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
// See https://github.com/vmware-tanzu/antrea/issues/678.
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
	jumpRules := []struct {
		need                               bool
		table, srcChain, dstChain, comment string
		prepend                            bool
	}{
		{true, iptables.RawTable, iptables.PreRoutingChain, antreaPreRoutingChain, "Antrea: jump to Antrea prerouting rules", false},
		{true, iptables.RawTable, iptables.OutputChain, antreaOutputChain, "Antrea: jump to Antrea output rules", false},
		{true, iptables.FilterTable, iptables.ForwardChain, antreaForwardChain, "Antrea: jump to Antrea forwarding rules", false},
		{true, iptables.NATTable, iptables.PostRoutingChain, antreaPostRoutingChain, "Antrea: jump to Antrea postrouting rules", false},
		{true, iptables.MangleTable, iptables.PreRoutingChain, antreaMangleChain, "Antrea: jump to Antrea mangle rules", false},
		{true, iptables.MangleTable, iptables.OutputChain, antreaOutputChain, "Antrea: jump to Antrea output rules", false},
		{c.nodeportSupport, iptables.NATTable, iptables.PreRoutingChain, antreaNodePortServicesChain, "Antrea: jump to Antrea NodePort Service rules", true},
		{c.nodeportSupport, iptables.NATTable, iptables.OutputChain, antreaNodePortServicesChain, "Antrea: jump to Antrea NodePort Service rules", true},
		{c.nodeportSupport, iptables.NATTable, iptables.PostRoutingChain, antreaServicesMasqChain, "Antrea: jump to Antrea NodePort Service masquerade rules", true},
	}
	for _, rule := range jumpRules {
		ruleSpec := []string{
			"-j", rule.dstChain,
			"-m", "comment", "--comment", rule.comment,
		}
		if !rule.need {
			_ = c.ipt.DeleteChain(rule.table, rule.dstChain)
			_ = c.ipt.DeleteRule(rule.table, rule.srcChain, ruleSpec)
			continue
		}
		if err := c.ipt.EnsureChain(rule.table, rule.dstChain); err != nil {
			return err
		}
		if err := c.ipt.EnsureRule(rule.table, rule.srcChain, ruleSpec, rule.prepend); err != nil {
			return err
		}
	}

	// Use iptables-restore to configure IPv4 settings.
	if v4Enabled {
		iptablesData := c.restoreIptablesData(c.nodeConfig.PodIPv4CIDR, antreaPodIPSet)
		// Setting --noflush to keep the previous contents (i.e. non antrea managed chains) of the tables.
		if err := c.ipt.Restore(iptablesData.Bytes(), false, false); err != nil {
			return err
		}
	}

	// Use ip6tables-restore to configure IPv6 settings.
	if v6Enabled {
		iptablesData := c.restoreIptablesData(c.nodeConfig.PodIPv6CIDR, antreaPodIP6Set)
		// Setting --noflush to keep the previous contents (i.e. non antrea managed chains) of the tables.
		if err := c.ipt.Restore(iptablesData.Bytes(), false, true); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) restoreNodePortIptablesData(hostGateway string, isIPv6 bool) *bytes.Buffer {
	localSet := antreaNodePortLocalSet
	clusterSet := antreaNodePortClusterSet
	loopbackAddr := "127.0.0.1"
	nodePortVirtualIP := c.nodePortVirtualIP.String()
	if isIPv6 {
		localSet = antreaNodePortLocalSet6
		clusterSet = antreaNodePortClusterSet6
		loopbackAddr = net.IPv6loopback.String()
		nodePortVirtualIP = c.nodePortVirtualIPv6.String()
	}
	iptablesData := new(bytes.Buffer)
	writeLine(iptablesData, []string{
		"-A", antreaNodePortServicesChain,
		"-m", "set", "--match-set", localSet, "dst,dst",
		"-j", iptables.MarkTarget, "--set-mark", localNodePortMark,
	}...)
	writeLine(iptablesData, []string{
		"-A", antreaNodePortServicesChain,
		"-m", "set", "--match-set", clusterSet, "dst,dst",
		"-j", iptables.MarkTarget, "--set-mark", clusterNodePortMark,
	}...)
	writeLine(iptablesData, []string{
		"-A", antreaNodePortServicesChain,
		"-m", "mark", "--mark", localNodePortMark,
		"-j", iptables.DNATTarget, "--to-destination", nodePortVirtualIP,
	}...)
	writeLine(iptablesData, []string{
		"-A", antreaNodePortServicesChain,
		"-m", "mark", "--mark", clusterNodePortMark,
		"-j", iptables.DNATTarget, "--to-destination", nodePortVirtualIP,
	}...)
	writeLine(iptablesData,
		"-A", antreaServicesMasqChain,
		"-m", "comment", "--comment", `"Antrea: Masquerade NodePort packets with a loopback address"`,
		"-s", loopbackAddr,
		"-d", nodePortVirtualIP,
		"-o", hostGateway,
		"-j", iptables.MasqueradeTarget,
	)
	writeLine(iptablesData,
		"-A", antreaServicesMasqChain,
		"-m", "comment", "--comment", `"Antrea: Masquerade NodePort packets which target Service with Local externalTrafficPolicy"`,
		"-m", "mark", "--mark", clusterNodePortMark,
		"-d", nodePortVirtualIP,
		"-o", hostGateway,
		"-j", iptables.MasqueradeTarget,
	)
	return iptablesData
}

func (c *Client) restoreIptablesData(podCIDR *net.IPNet, podIPSet string) *bytes.Buffer {
	// Create required rules in the antrea chains.
	// Use iptables-restore as it flushes the involved chains and creates the desired rules
	// with a single call, instead of string matching to clean up stale rules.
	iptablesData := bytes.NewBuffer(nil)
	// Determined which version of IP is being processed by podCIDR.
	isIPv6 := true
	if podCIDR.IP.To4() != nil {
		isIPv6 = false
	}
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
	hostGateway := c.nodeConfig.GatewayConfig.Name
	// When Antrea is used to enforce NetworkPolicies in EKS, an additional iptables
	// mangle rule is required. See https://github.com/vmware-tanzu/antrea/issues/678.
	if env.IsCloudEKS() {
		c.writeEKSMangleRule(iptablesData)
	}

	// To make liveness/readiness probe traffic bypass ingress rules of Network Policies, mark locally generated packets
	// that will be sent to OVS so we can identify them later in the OVS pipeline.
	// It must match source address because kube-proxy ipvs mode will redirect ingress packets to output chain, and they
	// will have non local source addresses.
	writeLine(iptablesData, []string{
		"-A", antreaOutputChain,
		"-m", "comment", "--comment", `"Antrea: mark local output packets"`,
		"-m", "addrtype", "--src-type", "LOCAL",
		"-o", c.nodeConfig.GatewayConfig.Name,
		"-j", iptables.MarkTarget, "--or-mark", fmt.Sprintf("%#08x", types.HostLocalSourceMark),
	}...)
	writeLine(iptablesData, "COMMIT")

	writeLine(iptablesData, "*filter")
	writeLine(iptablesData, iptables.MakeChainLine(antreaForwardChain))
	writeLine(iptablesData, []string{
		"-A", antreaForwardChain,
		"-m", "comment", "--comment", `"Antrea: accept packets from local pods"`,
		"-i", hostGateway,
		"-j", iptables.AcceptTarget,
	}...)
	writeLine(iptablesData, []string{
		"-A", antreaForwardChain,
		"-m", "comment", "--comment", `"Antrea: accept packets to local pods"`,
		"-o", hostGateway,
		"-j", iptables.AcceptTarget,
	}...)
	writeLine(iptablesData, "COMMIT")

	writeLine(iptablesData, "*nat")
	writeLine(iptablesData, iptables.MakeChainLine(antreaPostRoutingChain))
	if !c.noSNAT {
		writeLine(iptablesData, []string{
			"-A", antreaPostRoutingChain,
			"-m", "comment", "--comment", `"Antrea: masquerade pod to external packets"`,
			"-s", podCIDR.String(), "-m", "set", "!", "--match-set", podIPSet, "dst",
			"-j", iptables.MasqueradeTarget,
		}...)
	}
	if c.nodeportSupport {
		writeLine(iptablesData, iptables.MakeChainLine(antreaNodePortServicesChain))
		writeLine(iptablesData, iptables.MakeChainLine(antreaServicesMasqChain))
		io.Copy(iptablesData, c.restoreNodePortIptablesData(hostGateway, isIPv6))
	}
	writeLine(iptablesData, "COMMIT")
	return iptablesData
}

func (c *Client) initIPRoutes() error {
	if c.networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		gwLink := util.GetNetLink(c.nodeConfig.GatewayConfig.Name)
		_, gwIP, _ := net.ParseCIDR(fmt.Sprintf("%s/32", c.nodeConfig.NodeIPAddr.IP.String()))
		if err := netlink.AddrReplace(gwLink, &netlink.Addr{IPNet: gwIP}); err != nil {
			return fmt.Errorf("failed to add address %s to gw %s: %v", gwIP, gwLink.Attrs().Name, err)
		}
	}
	return nil
}

func generateNodePortIPSETEntries(nodeIP net.IP, isIPv6 bool, svcInfos []*proxytypes.ServiceInfo) sets.String {
	stringSet := sets.NewString()
	for _, svcInfo := range svcInfos {
		if svcInfo.NodePort() > 0 {
			protocolPort := fmt.Sprintf("%s:%d", strings.ToLower(string(svcInfo.Protocol())), svcInfo.NodePort())
			stringSet.Insert(fmt.Sprintf("%s,%s", nodeIP.String(), protocolPort))
			if isIPv6 {
				stringSet.Insert(fmt.Sprintf("%s,%s", net.IPv6loopback.String(), protocolPort))
			} else {
				stringSet.Insert(fmt.Sprintf("127.0.0.1,%s", protocolPort))
			}
		}
	}
	return stringSet
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

	// Remove any unknown routes on antrea-gw0.
	routes, err := c.listIPRoutesOnGW()
	if err != nil {
		return fmt.Errorf("error listing ip routes: %v", err)
	}
	for i := range routes {
		route := routes[i]
		if reflect.DeepEqual(route.Dst, c.nodeConfig.PodIPv4CIDR) || reflect.DeepEqual(route.Dst, c.nodeConfig.PodIPv6CIDR) {
			continue
		}
		if c.nodeportSupport && route.Dst != nil && (route.Dst.Contains(c.nodePortVirtualIP) || route.Dst.Contains(c.nodePortVirtualIPv6)) {
			continue
		}
		if route.Dst != nil && desiredPodCIDRs.Has(route.Dst.String()) {
			continue
		}
		klog.Infof("Deleting unknown route %v", route)
		if err := netlink.RouteDel(&route); err != nil && err != unix.ESRCH {
			return err
		}
	}

	// Remove any unknown IPv6 neighbors on antrea-gw0.
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
		if c.nodeportSupport && c.nodePortVirtualIPv6 != nil && c.nodePortVirtualIPv6.String() == neighIP {
			continue
		}
		klog.V(4).Infof("Deleting orphaned IPv6 neighbor %v", actualNeigh)
		if err := netlink.NeighDel(actualNeigh); err != nil {
			return err
		}
	}
	return nil
}

// listIPRoutes returns list of routes on antrea-gw0.
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
func (c *Client) AddRoutes(podCIDR *net.IPNet, nodeIP, nodeGwIP net.IP) error {
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
	if c.networkConfig.TrafficEncapMode.NeedsEncapToPeer(nodeIP, c.nodeConfig.NodeIPAddr) {
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
	} else if !c.networkConfig.TrafficEncapMode.NeedsRoutingToPeer(nodeIP, c.nodeConfig.NodeIPAddr) {
		// NoEncap traffic need routing help.
		route.Gw = nodeIP
	} else {
		// NoEncap traffic to Node on the same subnet. It is handled by host default route.
		return nil
	}
	routes = append(routes, route)

	for _, route := range routes {
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("failed to install route to peer %s with netlink: %v", nodeIP, err)
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
		for _, r := range routes.([]*netlink.Route) {
			klog.V(4).Infof("Deleting route %v", r)
			if err := netlink.RouteDel(r); err != nil && err != unix.ESRCH {
				return err
			}
		}
		c.nodeRoutes.Delete(podCIDRStr)
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

func (c *Client) ReconcileNodePort(nodeIPs []net.IP, svcEntries []*proxytypes.ServiceInfo) error {
	var cluster, local []*proxytypes.ServiceInfo
	for _, entry := range svcEntries {
		if entry.OnlyNodeLocalEndpoints() {
			local = append(local, entry)
		} else {
			cluster = append(cluster, entry)
		}
	}
	reconcile := func(setName string, isIPv6 bool, desiredSvcEntries []*proxytypes.ServiceInfo) error {
		existEntries, err := ipset.ListEntries(setName)
		if err != nil {
			return err
		}
		desiredEntries := sets.NewString()
		for _, nodeIP := range nodeIPs {
			desiredEntries.Insert(generateNodePortIPSETEntries(nodeIP, isIPv6, svcEntries).List()...)
		}
		for _, entry := range existEntries {
			if desiredEntries.Has(entry) {
				continue
			}
			klog.Infof("Deleting an orphaned NodePort Service entry %s from ipset", entry)
			if err := ipset.DelEntry(setName, entry); err != nil {
				return err
			}
		}
		return nil
	}
	if err := reconcile(antreaNodePortLocalSet, false, local); err != nil {
		return err
	}
	if err := reconcile(antreaNodePortClusterSet, false, cluster); err != nil {
		return err
	}
	if err := reconcile(antreaNodePortLocalSet6, true, local); err != nil {
		return err
	}
	if err := reconcile(antreaNodePortClusterSet6, true, cluster); err != nil {
		return err
	}
	return nil
}

func (c *Client) AddNodePortRoute(isIPv6 bool) error {
	var route *netlink.Route
	var nodeportIP *net.IP
	if !isIPv6 {
		nodeportIP = &c.nodePortVirtualIP
		route = &netlink.Route{
			Dst: &net.IPNet{
				IP:   *nodeportIP,
				Mask: net.IPv4Mask(255, 255, 255, 255),
			},
			Gw:    *nodeportIP,
			Flags: int(netlink.FLAG_ONLINK),
		}
		route.LinkIndex = c.nodeConfig.GatewayConfig.LinkIndex
	} else {
		nodeportIP = &c.nodePortVirtualIPv6
		route = &netlink.Route{
			Dst: &net.IPNet{
				IP:   *nodeportIP,
				Mask: net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			},
			LinkIndex: c.nodeConfig.GatewayConfig.LinkIndex,
		}
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("failed to install NodePort route: %w", err)
	}
	if isIPv6 {
		neigh := &netlink.Neigh{
			LinkIndex:    c.nodeConfig.GatewayConfig.LinkIndex,
			Family:       netlink.FAMILY_V6,
			State:        netlink.NUD_PERMANENT,
			IP:           *nodeportIP,
			HardwareAddr: globalVMAC,
		}
		if err := netlink.NeighSet(neigh); err != nil {
			return fmt.Errorf("failed to add nodeport neighbor %v to gw %s: %v", neigh, c.nodeConfig.GatewayConfig.Name, err)
		}
		c.nodeNeighbors.Store(nodeportIP.String(), neigh)
	}
	c.nodeRoutes.Store(nodeportIP.String(), route)
	return nil
}

func (c *Client) AddNodePort(nodeIPs []net.IP, svcInfo *proxytypes.ServiceInfo, isIPv6 bool) error {
	setName := antreaNodePortClusterSet
	if isIPv6 {
		setName = antreaNodePortClusterSet6
	}
	if svcInfo.OnlyNodeLocalEndpoints() {
		if isIPv6 {
			setName = antreaNodePortLocalSet6
		} else {
			setName = antreaNodePortLocalSet
		}
	}
	for _, nodeIP := range nodeIPs {
		if err := ipset.AddEntry(setName, fmt.Sprintf("%s,%s:%d", nodeIP, strings.ToLower(string(svcInfo.Protocol())), svcInfo.NodePort())); err != nil {
			klog.Errorf("Error when adding NodePort to ipset %s: %v", setName, err)
		}
	}
	loopbackIP := "127.0.0.1"
	if isIPv6 {
		loopbackIP = net.IPv6loopback.String()
	}
	if err := ipset.AddEntry(setName, fmt.Sprintf("%s,%s:%d", loopbackIP, strings.ToLower(string(svcInfo.Protocol())), svcInfo.NodePort())); err != nil {
		klog.Errorf("Error when adding NodePort to ipset %s: %v", setName, err)
	}
	return nil
}

func (c *Client) DeleteNodePort(nodeIPs []net.IP, svcInfo *proxytypes.ServiceInfo, isIPv6 bool) error {
	setName := antreaNodePortClusterSet
	if isIPv6 {
		setName = antreaNodePortClusterSet6
	}
	if svcInfo.OnlyNodeLocalEndpoints() {
		if isIPv6 {
			setName = antreaNodePortLocalSet6
		} else {
			setName = antreaNodePortLocalSet
		}
	}
	for _, nodeIP := range nodeIPs {
		if err := ipset.DelEntry(setName, fmt.Sprintf("%s,%s:%d", nodeIP, strings.ToLower(string(svcInfo.Protocol())), svcInfo.NodePort())); err != nil {
			klog.Errorf("Error when removing NodePort from ipset %s: %v", setName, err)
		}
	}
	loopbackIP := "127.0.0.1"
	if isIPv6 {
		loopbackIP = net.IPv6loopback.String()
	}
	if err := ipset.DelEntry(setName, fmt.Sprintf("%s,%s:%d", loopbackIP, strings.ToLower(string(svcInfo.Protocol())), svcInfo.NodePort())); err != nil {
		klog.Errorf("Error when removing NodePort from ipset %s: %v", setName, err)
	}
	return nil
}
