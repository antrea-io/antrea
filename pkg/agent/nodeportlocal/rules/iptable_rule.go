//go:build !windows
// +build !windows

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

package rules

import (
	"bytes"
	"fmt"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/util/iptables"
)

// InitRules initializes rules based on the underlying implementation
func InitRules(isIPv6 bool) PodPortRules {
	// This can be extended based on the system capability.
	return NewIPTableRules(isIPv6)
}

// NodePortLocalChain is the name of the chain in IPTABLES for Node Port Local
const NodePortLocalChain = "ANTREA-NODE-PORT-LOCAL"

// IPTableRules provides a client to perform IPTABLES operations
type iptablesRules struct {
	table    iptables.Interface
	isIPv6   bool
	protocol iptables.Protocol
}

// NewIPTableRules retruns a new instance of IPTableRules
func NewIPTableRules(isIPv6 bool) *iptablesRules {
	ipv4Enabled := !isIPv6
	ipv6Enabled := isIPv6
	iptInstance, _ := iptables.New(ipv4Enabled, ipv6Enabled)
	protocol := iptables.ProtocolIPv4
	if isIPv6 {
		protocol = iptables.ProtocolIPv6
	}
	iptRule := iptablesRules{
		table:    iptInstance,
		isIPv6:   isIPv6,
		protocol: protocol,
	}
	return &iptRule
}

// Init initializes IPTABLES rules for NPL. Currently it deletes existing rules to ensure that no stale entries are present.
func (ipt *iptablesRules) Init() error {
	if err := ipt.initRules(); err != nil {
		return fmt.Errorf("initialization of NPL iptables rules failed: %v", err)
	}
	return nil
}

// initRules creates the NPL chain and links it to the PREROUTING (for incoming
// traffic) and OUTPUT chain (for locally-generated traffic). All NPL DNAT rules
// will be added to this chain.
func (ipt *iptablesRules) initRules() error {
	if err := ipt.table.EnsureChain(ipt.protocol, iptables.NATTable, NodePortLocalChain); err != nil {
		return err
	}
	ruleSpec := []string{
		"-p", "all", "-m", "addrtype", "--dst-type", "LOCAL", "-j", NodePortLocalChain,
	}
	if err := ipt.table.AppendRule(ipt.protocol, iptables.NATTable, iptables.PreRoutingChain, ruleSpec); err != nil {
		return err
	}
	if err := ipt.table.AppendRule(ipt.protocol, iptables.NATTable, iptables.OutputChain, ruleSpec); err != nil {
		return err
	}
	return nil
}

func buildRuleForPod(port int, podIP, protocol string) []string {
	return []string{
		"-p", protocol, "-m", protocol, "--dport", fmt.Sprint(port),
		"-j", "DNAT", "--to-destination", podIP,
	}
}

// AddRule appends a DNAT rule in NodePortLocalChain chain of NAT table.
func (ipt *iptablesRules) AddRule(nodePort int, podIP string, podPort int, protocol string) error {
	podAddr := fmt.Sprintf("%s:%d", podIP, podPort)
	rule := buildRuleForPod(nodePort, podAddr, protocol)
	if err := ipt.table.AppendRule(ipt.protocol, iptables.NATTable, NodePortLocalChain, rule); err != nil {
		return err
	}
	klog.InfoS("Successfully added DNAT rule", "podAddr", podAddr, "nodePort", nodePort, "protocol", protocol, "ipFamily", ipt.protocol)
	return nil
}

// AddAllRules constructs a list of iptables rules for the NPL chain and performs a
// iptables-restore on this chain. It uses --no-flush to keep the previous rules intact.
func (ipt *iptablesRules) AddAllRules(nplList []PodNodePort) error {
	iptablesData := bytes.NewBuffer(nil)
	writeLine(iptablesData, "*nat")
	writeLine(iptablesData, iptables.MakeChainLine(NodePortLocalChain))

	for _, nplData := range nplList {
		destination := nplData.PodIP + ":" + fmt.Sprint(nplData.PodPort)
		rule := buildRuleForPod(nplData.NodePort, destination, nplData.Protocol)
		ruleWithChain := append([]string{"-A", NodePortLocalChain}, rule...)
		writeLine(iptablesData, ruleWithChain...)
	}

	writeLine(iptablesData, "COMMIT")
	return ipt.table.Restore(iptablesData.String(), false, ipt.isIPv6)
}

// DeleteRule deletes a specific NPL rule from NodePortLocalChain chain
func (ipt *iptablesRules) DeleteRule(nodePort int, podIP string, podPort int, protocol string) error {
	podAddr := fmt.Sprintf("%s:%d", podIP, podPort)
	rule := buildRuleForPod(nodePort, podAddr, protocol)
	if err := ipt.table.DeleteRule(ipt.protocol, iptables.NATTable, NodePortLocalChain, rule); err != nil {
		return err
	}
	klog.InfoS("Successfully deleted DNAT rule", "podAddr", podAddr, "nodePort", nodePort, "protocol", protocol, "ipFamily", ipt.protocol)
	return nil
}

// DeleteAllRules deletes all NPL rules programmed in the node
func (ipt *iptablesRules) DeleteAllRules() error {
	exists, err := ipt.table.ChainExists(ipt.protocol, iptables.NATTable, NodePortLocalChain)
	if err != nil {
		return fmt.Errorf("failed to check if NodePortLocal chain exists in NAT table: %w", err)
	}
	if !exists {
		return nil
	}
	ruleSpec := []string{
		"-p", "all", "-m", "addrtype", "--dst-type", "LOCAL", "-j", NodePortLocalChain,
	}

	if err := ipt.table.DeleteRule(ipt.protocol, iptables.NATTable, iptables.PreRoutingChain, ruleSpec); err != nil {
		return err
	}
	if err := ipt.table.DeleteRule(ipt.protocol, iptables.NATTable, iptables.OutputChain, ruleSpec); err != nil {
		return err
	}
	if err := ipt.table.DeleteChain(ipt.protocol, iptables.NATTable, NodePortLocalChain); err != nil {
		return err
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
