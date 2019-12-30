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
	"fmt"

	"github.com/coreos/go-iptables/iptables"
	"k8s.io/klog"
)

const (
	NATTable    = "nat"
	FilterTable = "filter"

	AcceptTarget     = "ACCEPT"
	MasqueradeTarget = "MASQUERADE"
	MarkTarget       = "MARK"

	ForwardChain           = "FORWARD"
	PostRoutingChain       = "POSTROUTING"
	AntreaForwardChain     = "ANTREA-FORWARD"
	AntreaPostRoutingChain = "ANTREA-POSTROUTING"
)

var (
	// The bit of the mark space to mark packets requiring SNAT. It must be within the
	// range [0, 31] and be different from other mark bits that are used by Kubernetes.
	// Kubernetes uses 14th for SNAT and 15th for dropping by default.
	// Antrea uses 10th for SNAT.
	masqueradeBit   = uint(10)
	masqueradeValue = 1 << masqueradeBit
	masqueradeMark  = fmt.Sprintf("%#08x/%#08x", masqueradeValue, masqueradeValue)
)

// Client knows how to set up host iptables rules Antrea requires.
type Client struct {
	ipt         *iptables.IPTables
	hostGateway string
}

// NewClient constructs a Client instance for iptables operations.
func NewClient(hostGateway string) (*Client, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("error creating IPTables instance: %v", err)
	}
	return &Client{
		ipt:         ipt,
		hostGateway: hostGateway,
	}, nil
}

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

// SetupRules ensures the iptables rules Antrea requires are set up.
// It's idempotent and can be safely called on every startup.
func (c *Client) SetupRules() error {
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

func contains(chains []string, targetChain string) bool {
	for _, val := range chains {
		if val == targetChain {
			return true
		}
	}
	return false
}
