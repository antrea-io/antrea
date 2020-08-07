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
	"os/exec"
	"reflect"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/agent/util/ipset"
	"github.com/vmware-tanzu/antrea/pkg/agent/util/iptables"
	"github.com/vmware-tanzu/antrea/pkg/util/env"
)

const (
	// Antrea managed ipset.
	// antreaPodIPSet contains all Pod CIDRs of this cluster.
	antreaPodIPSet = "ANTREA-POD-IP"

	// Antrea managed iptables chains.
	antreaForwardChain     = "ANTREA-FORWARD"
	antreaPostRoutingChain = "ANTREA-POSTROUTING"
	antreaMangleChain      = "ANTREA-MANGLE"
)

// Client implements Interface.
var _ Interface = &Client{}

// Client takes care of routing container packets in host network, coordinating ip route, ip rule, iptables and ipset.
type Client struct {
	nodeConfig  *config.NodeConfig
	encapMode   config.TrafficEncapModeType
	serviceCIDR *net.IPNet
	ipt         *iptables.Client
	// nodeRoutes caches ip routes to remote Pods. It's a map of podCIDR to routes.
	nodeRoutes sync.Map
}

// NewClient returns a route client.
func NewClient(serviceCIDR *net.IPNet, encapMode config.TrafficEncapModeType) (*Client, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("error creating IPTables instance: %v", err)
	}

	return &Client{
		serviceCIDR: serviceCIDR,
		encapMode:   encapMode,
		ipt:         ipt,
	}, nil
}

// Initialize initializes all infrastructures required to route container packets in host network.
// It is idempotent and can be safely called on every startup.
func (c *Client) Initialize(nodeConfig *config.NodeConfig) error {
	c.nodeConfig = nodeConfig

	// Sets up the ipset that will be used in iptables.
	if err := c.initIPSet(); err != nil {
		return fmt.Errorf("failed to initialize ipset: %v", err)
	}

	// Sets up the iptables infrastructure required to route packets in host network.
	if err := c.initIPTables(); err != nil {
		return fmt.Errorf("failed to initialize iptables: %v", err)
	}

	// Sets up the IP routes and IP rule required to route packets in host network.
	if err := c.initIPRoutes(); err != nil {
		return fmt.Errorf("failed to initialize ip routes: %v", err)
	}

	// send_redirects must be disabled because packets from hostGateway are
	// routed back to it. Otherwise redirect packets will be sent to source
	// Pods.
	// send_redirects for the interface will be enabled if at least one of
	// conf/{all,interface}/send_redirects is set to TRUE, so "all" and the
	// interface must be disabled together.
	// See https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt.
	if err := disableICMPSendRedirects("all"); err != nil {
		return err
	}
	if err := disableICMPSendRedirects(nodeConfig.GatewayConfig.Name); err != nil {
		return err
	}

	return nil
}

// initIPSet ensures that the required ipset exists and it has the initial members.
func (c *Client) initIPSet() error {
	// In policy-only mode, Node Pod CIDR is undefined.
	if c.encapMode.IsNetworkPolicyOnly() {
		return nil
	}
	if err := ipset.CreateIPSet(antreaPodIPSet, ipset.HashNet); err != nil {
		return err
	}
	// Ensure its own PodCIDR is in it.
	if err := ipset.AddEntry(antreaPodIPSet, c.nodeConfig.PodCIDR.String()); err != nil {
		return err
	}
	return nil
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

// initIPTables ensure that the iptables infrastructure we use is set up.
// It's idempotent and can safely be called on every startup.
func (c *Client) initIPTables() error {
	// Create the antrea managed chains and link them to built-in chains.
	// We cannot use iptables-restore for these jump rules because there
	// are non antrea managed rules in built-in chains.
	jumpRules := []struct{ table, srcChain, dstChain, comment string }{
		{iptables.FilterTable, iptables.ForwardChain, antreaForwardChain, "Antrea: jump to Antrea forwarding rules"},
		{iptables.NATTable, iptables.PostRoutingChain, antreaPostRoutingChain, "Antrea: jump to Antrea postrouting rules"},
		{iptables.MangleTable, iptables.PreRoutingChain, antreaMangleChain, "Antrea: jump to Antrea mangle rules"},
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

	// Create required rules in the antrea chains.
	// Use iptables-restore as it flushes the involved chains and creates the desired rules
	// with a single call, instead of string matching to clean up stale rules.
	iptablesData := bytes.NewBuffer(nil)
	// Write head lines anyway so the undesired rules can be deleted when noEncap -> encap.
	writeLine(iptablesData, "*mangle")
	writeLine(iptablesData, iptables.MakeChainLine(antreaMangleChain))
	hostGateway := c.nodeConfig.GatewayConfig.Name
	// When Antrea is used to enforce NetworkPolicies in EKS, an additional iptables
	// mangle rule is required. See https://github.com/vmware-tanzu/antrea/issues/678.
	if env.IsCloudEKS() {
		c.writeEKSMangleRule(iptablesData)
	}
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

	// In policy-only mode, masquerade is managed by primary CNI.
	// Antrea should not get involved.
	writeLine(iptablesData, "*nat")
	writeLine(iptablesData, iptables.MakeChainLine(antreaPostRoutingChain))
	if !c.encapMode.IsNetworkPolicyOnly() {
		writeLine(iptablesData, []string{
			"-A", antreaPostRoutingChain,
			"-m", "comment", "--comment", `"Antrea: masquerade pod to external packets"`,
			"-s", c.nodeConfig.PodCIDR.String(), "-m", "set", "!", "--match-set", antreaPodIPSet, "dst",
			"-j", iptables.MasqueradeTarget,
		}...)
	}
	writeLine(iptablesData, "COMMIT")

	// Setting --noflush to keep the previous contents (i.e. non antrea managed chains) of the tables.
	if err := c.ipt.Restore(iptablesData.Bytes(), false); err != nil {
		return err
	}
	return nil
}

func (c *Client) initIPRoutes() error {
	if c.encapMode.IsNetworkPolicyOnly() {
		gwLink := util.GetNetLink(c.nodeConfig.GatewayConfig.Name)
		_, gwIP, _ := net.ParseCIDR(fmt.Sprintf("%s/32", c.nodeConfig.NodeIPAddr.IP.String()))
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

	// Remove orphaned podCIDRs from antreaPodIPSet.
	entries, err := ipset.ListEntries(antreaPodIPSet)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if desiredPodCIDRs.Has(entry) {
			continue
		}
		klog.Infof("Deleting orphaned PodIP %s from ipset and route table", entry)
		if err := ipset.DelEntry(antreaPodIPSet, entry); err != nil {
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

	// Remove any unknown routes on antrea-gw0.
	routes, err := c.listIPRoutesOnGW()
	if err != nil {
		return fmt.Errorf("error listing ip routes: %v", err)
	}
	for _, route := range routes {
		if reflect.DeepEqual(route.Dst, c.nodeConfig.PodCIDR) {
			continue
		}
		if desiredPodCIDRs.Has(route.Dst.String()) {
			continue
		}
		klog.Infof("Deleting unknown route %v", route)
		if err := netlink.RouteDel(&route); err != nil && err != unix.ESRCH {
			return err
		}
	}
	return nil
}

// listIPRoutes returns list of routes on antrea-gw0.
func (c *Client) listIPRoutesOnGW() ([]netlink.Route, error) {
	filter := &netlink.Route{
		LinkIndex: c.nodeConfig.GatewayConfig.LinkIndex}
	return netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_OIF)
}

// AddRoutes adds routes to a new podCIDR. It overrides the routes if they already exist.
func (c *Client) AddRoutes(podCIDR *net.IPNet, nodeIP, nodeGwIP net.IP) error {
	podCIDRStr := podCIDR.String()
	// Add this podCIDR to antreaPodIPSet so that packets to them won't be masqueraded when they leave the host.
	if err := ipset.AddEntry(antreaPodIPSet, podCIDRStr); err != nil {
		return err
	}
	// Install routes to this Node.
	route := &netlink.Route{
		Dst: podCIDR,
	}
	if c.encapMode.NeedsEncapToPeer(nodeIP, c.nodeConfig.NodeIPAddr) {
		route.Flags = int(netlink.FLAG_ONLINK)
		route.LinkIndex = c.nodeConfig.GatewayConfig.LinkIndex
		route.Gw = nodeGwIP
	} else if !c.encapMode.NeedsRoutingToPeer(nodeIP, c.nodeConfig.NodeIPAddr) {
		// NoEncap traffic need routing help.
		route.Gw = nodeIP
	} else {
		// NoEncap traffic to Node on the same subnet. It is handled by host default route.
		return nil
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("failed to install route to peer %s with netlink: %v", nodeIP, err)
	}
	c.nodeRoutes.Store(podCIDRStr, route)
	return nil
}

// DeleteRoutes deletes routes to a PodCIDR. It does nothing if the routes doesn't exist.
func (c *Client) DeleteRoutes(podCIDR *net.IPNet) error {
	podCIDRStr := podCIDR.String()
	// Delete this podCIDR from antreaPodIPSet as the CIDR is no longer for Pods.
	if err := ipset.DelEntry(antreaPodIPSet, podCIDRStr); err != nil {
		return err
	}

	i, exists := c.nodeRoutes.Load(podCIDRStr)
	if !exists {
		return nil
	}
	r := i.(*netlink.Route)
	klog.V(4).Infof("Deleting route %v", r)
	if err := netlink.RouteDel(r); err != nil && err != unix.ESRCH {
		return err
	}
	c.nodeRoutes.Delete(podCIDRStr)
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

func disableICMPSendRedirects(intfName string) error {
	cmdStr := fmt.Sprintf("echo 0 > /proc/sys/net/ipv4/conf/%s/send_redirects", intfName)
	cmd := exec.Command("/bin/sh", "-c", cmdStr)
	if err := cmd.Run(); err != nil {
		klog.Errorf("Failed to disable send_redirect for interface %s: %v", intfName, err)
		return err
	}
	return nil
}

// MigrateRoutesToGw moves routes (including assigned IP addresses if any) from link linkName to
// host gateway.
func (c *Client) MigrateRoutesToGw(linkName string) error {
	gwLink := util.GetNetLink(c.nodeConfig.GatewayConfig.Name)
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", linkName, err)
	}

	// Swap route first then address, otherwise route gets removed when address is removed.
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to get routes for link %s: %w", linkName, err)
	}
	for _, route := range routes {
		route.LinkIndex = gwLink.Attrs().Index
		if err = netlink.RouteReplace(&route); err != nil {
			return fmt.Errorf("failed to add route %v to link %s: %w", &route, gwLink.Attrs().Name, err)
		}
	}

	// Swap address if any.
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to get addresses for %s: %w", linkName, err)
	}
	for _, addr := range addrs {
		if err = netlink.AddrDel(link, &addr); err != nil {
			klog.Errorf("failed to delete addr %v from %s: %v", addr, link, err)
		}
		tmpAddr := &netlink.Addr{IPNet: addr.IPNet}
		if err = netlink.AddrReplace(gwLink, tmpAddr); err != nil {
			return fmt.Errorf("failed to add addr %v to gw %s: %w", addr, gwLink.Attrs().Name, err)
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
	for _, rt := range routes {
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
