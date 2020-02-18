// Copyright 2019 Antrea Authors
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

package iptables

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
)

const (
	NATTable    = "nat"
	FilterTable = "filter"
	MangleTable = "mangle"
	RawTable    = "raw"

	AcceptTarget     = "ACCEPT"
	MasqueradeTarget = "MASQUERADE"
	MarkTarget       = "MARK"
	ConnTrackTarget  = "CT"

	PreRoutingChain        = "PREROUTING"
	ForwardChain           = "FORWARD"
	PostRoutingChain       = "POSTROUTING"
	AntreaForwardChain     = "ANTREA-FORWARD"
	AntreaPostRoutingChain = "ANTREA-POSTROUTING"
	AntreaMangleChain      = "ANTREA-MANGLE"
	AntreaRawChain         = "ANTREA-RAW"
)

var (
	// The bit of the mark space to mark packets requiring SNAT. It must be within the
	// range [0, 31] and be different from other mark bits that are used by Kubernetes.
	// Kubernetes uses 14th for SNAT and 15th for dropping by default.
	// Antrea uses 10th for SNAT.
	masqueradeBit   = uint(10)
	masqueradeValue = 1 << masqueradeBit
	masqueradeMark  = fmt.Sprintf("%#x/%#x", masqueradeValue, masqueradeValue)

	// RtTblSelectorValue selects which route table to use to forward service traffic back to host gateway gw0.
	RtTblSelectorValue = 1 << 11
	rtTblSelectorMark  = fmt.Sprintf("%#x/%#x", RtTblSelectorValue, RtTblSelectorValue)
)

// Client knows how to set up host iptables rules Antrea requires.
type Client struct {
	hostGateway string
	serviceCIDR *net.IPNet
	encapMode   config.TrafficEncapModeType
	nodeConfig  *config.NodeConfig
	ipt         *iptables.IPTables
	store       *sync.Map
}

// key is chain name, value [][]string is rules in the chain. The first slice is rules in
// the chain, the second slice represents tokens within the rule.
type chainRules map[string][][]string

// rule is a generic struct that describes an iptables rule.
type rule struct {
	// The table of this rule.
	table string
	// The chain of this rule.
	chain string
	// The parameters that make up a rule specification, e.g. "-i name", "-o name", "-p tcp".
	parameters []string
	// The target of this rule, could be a chain or an action e.g. "ACCEPT", "MARK".
	target string
	// The extra options of the target, for example, "MARK" has extra options "--set-xmark value".
	targetOptions []string
	// The comment of this rule.
	comment string
}

// NewClient constructs a Client instance for iptables operations.
func NewClient(hostGateway string, serviceCIDR *net.IPNet, encapMode config.TrafficEncapModeType) *Client {
	return &Client{
		hostGateway: hostGateway,
		serviceCIDR: serviceCIDR,
		encapMode:   encapMode,
		store:       &sync.Map{}}
}

// Initialize sets up internal variables and ensures the iptables rules Antrea requires are set up.
// It's idempotent and can be safely called on every startup.
func (c *Client) Initialize(nodeConfig *config.NodeConfig) error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("error creating IPTables instance: %v", err)
	}

	c.ipt = ipt
	c.nodeConfig = nodeConfig

	rules := []rule{
		// Append ANTREA-FORWARD chain which contains Antrea related forwarding rules to FORWARD chain.
		{FilterTable, ForwardChain, nil, AntreaForwardChain, nil, "Antrea: jump to Antrea forwarding rules"},
		// Accept inter-Pod traffic which is received and sent via host gateway interface.
		// Note: Since L3 forwarding flows are installed, direct inter-Pod traffic won't go through host gateway interface,
		// only Pod-Service-Pod traffic will go through it.
		{FilterTable, AntreaForwardChain, []string{"-i", c.hostGateway, "-o", c.hostGateway}, AcceptTarget, nil, "Antrea: accept inter pod traffic"},
		// Accept external-to-Pod traffic. This allows NodePort traffic to be forwarded even if the default FORWARD policy is DROP.
		{FilterTable, AntreaForwardChain, []string{"!", "-i", c.hostGateway, "-o", c.hostGateway}, AcceptTarget, nil, "Antrea: accept external to pod traffic"},
		// Mark Pod-to-external traffic which are received via host gateway interface but not sent via it for later masquerading in NAT table.
		{FilterTable, AntreaForwardChain, []string{"-i", c.hostGateway, "!", "-o", c.hostGateway}, MarkTarget, []string{"--set-xmark", masqueradeMark}, "Antrea: mark pod to external traffic"},
		// Accept Pod-to-external traffic which are received via host gateway interface but not sent via it.
		{FilterTable, AntreaForwardChain, []string{"-i", c.hostGateway, "!", "-o", c.hostGateway}, AcceptTarget, nil, "Antrea: accept pod to external traffic"},
		// Append ANTREA-POSTROUTING chain which contains Antrea related postrouting rules to POSTROUTING chain.
		{NATTable, PostRoutingChain, nil, AntreaPostRoutingChain, nil, "Antrea: jump to Antrea postrouting rules"},
		// Masquerade traffic requiring SNAT (has masqueradeMark set).
		{NATTable, AntreaPostRoutingChain, []string{"-m", "mark", "--mark", masqueradeMark}, MasqueradeTarget, nil, "Antrea: masquerade traffic requiring SNAT"},
	}

	if c.encapMode.SupportsNoEncap() {
		rules = append(rules,
			// 	Creates AntreaMangle chain in mangle table PREROUTING chain.
			rule{table: MangleTable, chain: PreRoutingChain, parameters: nil, target: AntreaMangleChain, targetOptions: nil, comment: "Antrea: jump to Antrea mangle rule"},
			//  Marks service traffic in PREROUTING chain so that service traffic may use ip rule to pick up the service route table.
			rule{table: MangleTable, chain: AntreaMangleChain, parameters: []string{"-i", c.hostGateway, "-d", c.serviceCIDR.String()},
				target: MarkTarget, targetOptions: []string{"--set-xmark", rtTblSelectorMark}, comment: "Antrea: mark service traffic"},
			// 	Creates AntreaRaw chain in raw table PREROUTING chain.
			rule{table: RawTable, chain: PreRoutingChain, parameters: nil, target: AntreaRawChain, targetOptions: nil, comment: "Antrea: jump to Antrea raw rule"},
			//  Allows re-entering Pod-to-Pod traffic identified by src-mac=ReentraceMAC to bypass conntrack.
			rule{table: RawTable, chain: AntreaRawChain, parameters: []string{"-i", c.hostGateway, "-m", "mac", "--mac-source", openflow.ReentranceMAC.String()}, target: ConnTrackTarget, targetOptions: []string{"--notrack"}, comment: "Antrea: reentry pod traffic skip conntrack"})
	}

	// Ensure all the chains involved exist.
	for _, rule := range rules {
		if err := c.ensureChain(rule.table, rule.chain); err != nil {
			return err
		}
	}

	// Ensure all the rules exist.
	for _, rule := range rules {
		var ruleSpec []string
		ruleSpec = append(ruleSpec, rule.parameters...)
		ruleSpec = append(ruleSpec, "-j", rule.target)
		ruleSpec = append(ruleSpec, rule.targetOptions...)
		ruleSpec = append(ruleSpec, "-m", "comment", "--comment", rule.comment)
		if err := c.ensureRule(rule.table, rule.chain, ruleSpec); err != nil {
			return err
		}
		c.storeRule(rule.table, rule.chain, ruleSpec)
	}
	return nil
}

// AddPeerCIDR adds iptables rules relevant to peerPodCIDR
// It's idempotent and can be safely called on every startup.
func (c *Client) AddPeerCIDR(peerPodCIDR *net.IPNet, peerNodeIP net.IP) error {
	if !c.encapMode.NeedsEncapToPeer(peerNodeIP, c.nodeConfig.NodeIPAddr) {
		// The default masquerading rule is all traffic in-port=gw0, out-port!=gw0. The rule
		// should excludes to all traffic destined for peer Pod CIDRs.
		// It would be better if agent knows cluster CIDR, then a single rule is needed at
		// agent initialization.
		ruleSpec := []string{
			"-i", c.hostGateway, "!", "-o", c.hostGateway,
			"-d", peerPodCIDR.String(), "-s", c.nodeConfig.PodCIDR.String(), "-j", AcceptTarget,
			"-m", "comment", "--comment", "Antrea: skip masquerade marking"}
		exist, err := c.ipt.Exists(FilterTable, AntreaForwardChain, ruleSpec...)
		if err != nil {
			return fmt.Errorf("AddPeerCIDR Check %s: %w", ruleSpec, err)
		}

		if exist {
			return nil
		}
		if err := c.ipt.Insert(FilterTable, AntreaForwardChain, 1, ruleSpec...); err != nil {
			return fmt.Errorf("AddPeerCIDR Insert %s: %w", ruleSpec, err)
		}
		c.storeRule(FilterTable, AntreaForwardChain, ruleSpec)
	}
	return nil
}

// Reconcile removes stale antrea rules
func (c *Client) Reconcile() error {
	var antreaRules []struct {
		table, chain, ruleStr string
	}
	antreaChains := make(map[string]map[string]interface{})

	// collect antrea rules from system
	for _, table := range []string{NATTable, FilterTable, MangleTable, RawTable} {
		chains, err := c.ipt.ListChains(table)
		if err != nil {
			return fmt.Errorf("iptables list chain for %s: %w", table, err)
		}
		for _, chain := range chains {
			isAntreaChain := false
			if strings.HasPrefix(chain, "ANTREA") {
				isAntreaChain = true
				if _, ok := antreaChains[table]; !ok {
					antreaChains[table] = make(map[string]interface{})
				}
				antreaChains[table][chain] = nil
			}
			ruleStrs, err := c.ipt.List(table, chain)
			if err != nil {
				return fmt.Errorf("iptables list for %s %s: %w", table, chain, err)
			}
			// skip first,  it is for the chain
			for _, ruleStr := range ruleStrs[1:] {
				if strings.Contains(ruleStr, "-j ANTREA") || isAntreaChain {
					antreaRules = append(antreaRules, struct {
						table, chain, ruleStr string
					}{table: table, chain: chain, ruleStr: ruleStr})
				}
			}
		}
	}

	for _, item := range antreaRules {
		table := item.table
		chain := item.chain
		ruleStr := item.ruleStr
		var ruleSpec []string
		inQuote := false

		for {
			idx := strings.Index(ruleStr, "\"")
			if idx == -1 {
				ruleSpec = append(ruleSpec, strings.Split(ruleStr, " ")...)
				break
			}
			if !inQuote {
				curStr := ruleStr[:idx]
				ruleSpec = append(ruleSpec, strings.Split(curStr, " ")...)
			} else {
				ruleSpec = append(ruleSpec, ruleStr[:idx])
			}
			inQuote = !inQuote
			ruleStr = ruleStr[idx+1:]
		}
		// take care of empty strings on array
		finalRuleSpec := make([]string, 0, 2)
		for _, item := range ruleSpec {
			if len(item) == 0 {
				continue
			}
			finalRuleSpec = append(finalRuleSpec, item)
		}
		// skip -A chain
		finalRuleSpec = finalRuleSpec[2:]
		if !c.IsInRuleStore(table, chain, finalRuleSpec) {
			if err := c.ipt.Delete(table, chain, finalRuleSpec...); err != nil {
				return fmt.Errorf("ip rule delete %s: %w", finalRuleSpec, err)
			}
		}
	}

	// remove empty antrea chains if possible
	for table, chains := range antreaChains {
		for chain := range chains {
			rules, err := c.ipt.List(table, chain)
			if err != nil {
				return fmt.Errorf("iptables list chain %s %s: %w", table, chain, err)
			}
			if len(rules) > 1 {
				continue
			}
			// chain is empty
			if err := c.ipt.DeleteChain(table, chain); err != nil {
				return fmt.Errorf("iptables delete chain %s, %s: %w", table, chain, err)
			}
		}
	}
	return nil
}

// ensureChain checks if target chain already exists, creates it if not.
func (c *Client) ensureChain(table string, chain string) error {
	oriChains, err := c.ipt.ListChains(table)
	if err != nil {
		return fmt.Errorf("error listing existing chains in table %s: %v", table, err)
	}
	if contains(oriChains, chain) {
		return nil
	}
	if err := c.ipt.NewChain(table, chain); err != nil {
		return fmt.Errorf("error creating chain %s in table %s: %v", chain, table, err)
	}
	klog.V(2).Infof("Created chain %s in table %s", chain, table)
	return nil
}

// ensureRule checks if target rule already exists, appends it if not.
func (c *Client) ensureRule(table string, chain string, ruleSpec []string) error {
	exist, err := c.ipt.Exists(table, chain, ruleSpec...)
	if err != nil {
		return fmt.Errorf("error checking if rule %v exists in table %s chain %s: %v", ruleSpec, table, chain, err)
	}
	if exist {
		return nil
	}
	if err := c.ipt.Append(table, chain, ruleSpec...); err != nil {
		return fmt.Errorf("error appending rule %v to table %s chain %s: %v", ruleSpec, table, chain, err)
	}
	klog.V(2).Infof("Appended rule %v to table %s chain %s", ruleSpec, table, chain)
	return nil
}

// storeRule saves rule for reconcile
func (c *Client) storeRule(table string, chain string, ruleSpec []string) {
	var chains chainRules = nil
	if val, ok := c.store.Load(table); !ok {
		chains = make(map[string][][]string)
	} else {
		chains = val.(chainRules)
	}
	if _, ok := chains[chain]; !ok {
		chains[chain] = nil
	}
	chains[chain] = append(chains[chain], ruleSpec)
	c.store.Store(table, chains)
}

// PrintStoredRules dumps stored ip rules for debugging.
func (c *Client) PrintStoredRules() string {
	tables := []string{
		NATTable,
		FilterTable,
		MangleTable,
		RawTable,
	}
	wr := bytes.NewBuffer(nil)
	for _, table := range tables {
		wr.Write([]byte(table + ":\n"))
		val, ok := c.store.Load(table)
		if !ok {
			wr.Write([]byte("not found\n"))
			continue
		}
		chains := val.(chainRules)
		wr.Write([]byte(fmt.Sprintf("size: %d\n", len(chains))))
		for chain, ruleSpecs := range chains {
			wr.Write([]byte(chain + ":\n"))
			for _, ruleSpec := range ruleSpecs {
				wr.Write([]byte(fmt.Sprintf("len=%d ", len(ruleSpec))))
				wr.Write([]byte(strings.Join(ruleSpec, " ") + "\n"))
			}
			wr.Write([]byte("\n"))
		}
	}
	return wr.String()
}

// compareRuleSpec returns true if two rule spec are the same.
func compareRuleSpec(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	// by content
	visited := make(map[string]interface{}, len(a))
	for _, s := range a {
		visited[strings.ToLower(s)] = nil
	}
	for _, s := range b {
		if _, ok := visited[strings.ToLower(s)]; !ok {
			return false
		}
	}
	return true
}

// IsInRuleStore returns true if rule is in rule store.
func (c *Client) IsInRuleStore(table string, chain string, ruleSpec []string) bool {
	var chains chainRules = nil
	val, ok := c.store.Load(table)
	if !ok {
		return false
	}
	chains = val.(chainRules)
	if _, ok := chains[chain]; !ok {
		return false
	}

	for _, storeRule := range chains[chain] {
		if compareRuleSpec(storeRule, ruleSpec) {
			return true
		}
	}
	return false
}

func contains(chains []string, targetChain string) bool {
	for _, val := range chains {
		if val == targetChain {
			return true
		}
	}
	return false
}
