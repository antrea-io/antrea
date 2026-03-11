//go:build !windows
// +build !windows

// Copyright 2025 Antrea Authors
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

package rules

import (
	"context"
	"fmt"

	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/knftables"
)

const (
	antreaTable                = "antrea"
	nftablesNPLChainPrerouting = "nat-prerouting-npl"
	nftablesNPLChainOutput     = "nat-output-npl"
	nftablesNPLChain           = "nat-npl"
)

// nftablesRules implements PodPortRules using nftables for NodePortLocal when HostNetworkMode is nftables.
type nftablesRules struct {
	nft    knftables.Interface
	isIPv6 bool
	// ip is the nftables family-specific prefix for logging ("ip" vs "ip6").
	ip string
}

// NewNFTablesRules returns a new instance of nftablesRules for the given IP family.
// It uses the same "antrea" table as the route client; the table must already exist
// (e.g. created by the route client when hostNetworkMode is nftables).
func NewNFTablesRules(isIPv6 bool) (*nftablesRules, error) {
	family := knftables.IPv4Family
	ip := "ip"
	if isIPv6 {
		family = knftables.IPv6Family
		ip = "ip6"
	}
	nft, err := knftables.New(family, antreaTable)
	if err != nil {
		return nil, fmt.Errorf("failed to create nftables instance for NPL: %w", err)
	}
	return &nftablesRules{
		nft:    nft,
		isIPv6: isIPv6,
		ip:     ip,
	}, nil
}

// Init creates the NPL chains and jump rules in the nat table.
func (n *nftablesRules) Init() error {
	tx := n.nft.NewTransaction()

	// Base chain for prerouting: match dst local, jump to NPL chain.
	tx.Add(&knftables.Chain{
		Name:     nftablesNPLChainPrerouting,
		Type:     ptr.To(knftables.NATType),
		Hook:     ptr.To(knftables.PreroutingHook),
		Priority: ptr.To(knftables.DNATPriority + "-1"),
		Comment:  ptr.To("NAT prerouting for NodePortLocal"),
	})
	// Base chain for output: match dst local, jump to NPL chain.
	tx.Add(&knftables.Chain{
		Name:     nftablesNPLChainOutput,
		Type:     ptr.To(knftables.NATType),
		Hook:     ptr.To(knftables.OutputHook),
		Priority: ptr.To(knftables.DNATPriority + "-1"),
		Comment:  ptr.To("NAT output for NodePortLocal"),
	})
	// Regular chain holding the actual DNAT rules.
	tx.Add(&knftables.Chain{
		Name:    nftablesNPLChain,
		Comment: ptr.To("NodePortLocal DNAT rules"),
	})

	// Jump to NPL chain for traffic to local addresses.
	jumpRule := knftables.Concat("fib", "daddr", "type", "local", "jump", nftablesNPLChain)
	tx.Add(&knftables.Rule{
		Chain:   nftablesNPLChainPrerouting,
		Rule:    jumpRule,
		Comment: ptr.To("Jump to NPL for prerouting"),
	})
	tx.Add(&knftables.Rule{
		Chain:   nftablesNPLChainOutput,
		Rule:    jumpRule,
		Comment: ptr.To("Jump to NPL for output"),
	})

	if err := n.nft.Run(context.TODO(), tx); err != nil {
		return fmt.Errorf("initialization of NPL nftables rules failed: %w", err)
	}
	klog.InfoS("Initialized NPL nftables rules", "ipFamily", n.ip)
	return nil
}

// AddRule adds a DNAT rule for the given nodePort -> podIP:podPort.
func (n *nftablesRules) AddRule(nodePort int, podIP string, podPort int, protocol string) error {
	rule := n.buildDNATRule(nodePort, podIP, podPort, protocol)
	tx := n.nft.NewTransaction()
	tx.Add(rule)
	if err := n.nft.Run(context.TODO(), tx); err != nil {
		return err
	}
	klog.InfoS("Successfully added NPL DNAT rule (nftables)", "podIP", podIP, "podPort", podPort, "nodePort", nodePort, "protocol", protocol, "ipFamily", n.ip)
	return nil
}

// DeleteRule removes the DNAT rule for the given nodePort -> podIP:podPort.
func (n *nftablesRules) DeleteRule(nodePort int, podIP string, podPort int, protocol string) error {
	rule := n.buildDNATRule(nodePort, podIP, podPort, protocol)
	tx := n.nft.NewTransaction()
	tx.Delete(rule)
	if err := n.nft.Run(context.TODO(), tx); err != nil {
		return err
	}
	klog.InfoS("Successfully deleted NPL DNAT rule (nftables)", "podIP", podIP, "podPort", podPort, "nodePort", nodePort, "protocol", protocol, "ipFamily", n.ip)
	return nil
}

// AddAllRules flushes the NPL chain and adds all given rules.
func (n *nftablesRules) AddAllRules(nplList []PodNodePort) error {
	tx := n.nft.NewTransaction()
	tx.Flush(&knftables.Chain{Name: nftablesNPLChain})
	for _, npl := range nplList {
		tx.Add(n.buildDNATRule(npl.NodePort, npl.PodIP, npl.PodPort, npl.Protocol))
	}
	return n.nft.Run(context.TODO(), tx)
}

// DeleteAllRules removes the jump rules from the base chains and flushes the NPL chain.
func (n *nftablesRules) DeleteAllRules() error {
	tx := n.nft.NewTransaction()
	tx.Flush(&knftables.Chain{Name: nftablesNPLChain})
	tx.Flush(&knftables.Chain{Name: nftablesNPLChainPrerouting})
	tx.Flush(&knftables.Chain{Name: nftablesNPLChainOutput})
	if err := n.nft.Run(context.TODO(), tx); err != nil {
		return err
	}
	klog.InfoS("Deleted all NPL nftables rules", "ipFamily", n.ip)
	return nil
}

func (n *nftablesRules) buildDNATRule(nodePort int, podIP string, podPort int, protocol string) *knftables.Rule {
	// e.g. "tcp dport 30000 dnat to 10.0.0.1:80"
	dest := fmt.Sprintf("%s:%d", podIP, podPort)
	rule := knftables.Concat(protocol, "dport", fmt.Sprint(nodePort), "dnat", "to", dest)
	return &knftables.Rule{
		Chain: nftablesNPLChain,
		Rule:  rule,
	}
}
