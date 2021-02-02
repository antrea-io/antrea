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

	"github.com/vmware-tanzu/antrea/pkg/agent/util/iptables"

	"k8s.io/klog"
)

// NodePortLocalChain is the name of the chain in IPTABLES for Node Port Local
const NodePortLocalChain = "ANTREA-NODE-PORT-LOCAL"

// PodNodePort contains the Node Port, Pod Port and the Pod IP.
type PodNodePort struct {
	NodePort int
	PodPort  int
	PodIP    string
}

// IPTableRules provides a client to perform IPTABLES operations
type iptablesRules struct {
	name  string
	table *iptables.Client
}

// NewIPTableRules retruns a new instance of IPTableRules
func NewIPTableRules() *iptablesRules {
	iptInstance, _ := iptables.New(true, false)
	iptRule := iptablesRules{
		name:  "NPL",
		table: iptInstance,
	}
	return &iptRule
}

// Init initializes IPTABLES rules for NPL. Currently it deletes existing rules to ensure that no stale entries are present.
func (ipt *iptablesRules) Init() error {
	return ipt.CreateChains()
}

// CreateChains creates the chain NodePortLocalChain in NAT table.
// All DNAT rules for NPL would be added in this chain.
func (ipt *iptablesRules) CreateChains() error {
	err := ipt.table.EnsureChain(iptables.NATTable, NodePortLocalChain)
	if err != nil {
		return fmt.Errorf("IPTABLES chain creation in NAT table failed for NPL with error: %v", err)
	}
	ruleSpec := []string{
		"-p", "tcp", "-j", NodePortLocalChain,
	}
	err = ipt.table.EnsureRule(iptables.NATTable, iptables.PreRoutingChain, ruleSpec)
	if err != nil {
		return fmt.Errorf("IPTABLES rule creation in NAT table failed for NPL with error: %v", err)
	}
	return nil
}

// AddRule appends a DNAT rule in NodePortLocalChain chain of NAT table
func (ipt *iptablesRules) AddRule(port int, podIP string) error {
	ruleSpec := []string{
		"-p", "tcp", "-m", "tcp", "--dport",
		fmt.Sprint(port), "-j", "DNAT", "--to-destination", podIP,
	}
	err := ipt.table.EnsureRule(iptables.NATTable, NodePortLocalChain, ruleSpec)
	if err != nil {
		return fmt.Errorf("IPTABLES rule creation failed for NPL with error: %v", err)
	}
	klog.Infof("successfully added rule for Pod %s: %d", podIP, port)
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
		writeLine(iptablesData, []string{
			"-A", NodePortLocalChain,
			"-p", "tcp",
			"-m", "tcp",
			"--dport", fmt.Sprint(nplData.NodePort),
			"-j", "DNAT",
			"--to-destination", destination,
		}...)
	}
	writeLine(iptablesData, "COMMIT")
	if err := ipt.table.Restore(iptablesData.Bytes(), false, false); err != nil {
		return err
	}
	return nil
}

// DeleteRule deletes a specific NPL rule from NodePortLocalChain chain
func (ipt *iptablesRules) DeleteRule(port int, podip string) error {
	klog.Infof("Deleting rule with port %v and podip %v", port, podip)
	ruleSpec := []string{
		"-p", "tcp", "-m", "tcp", "--dport",
		fmt.Sprint(port), "-j", "DNAT", "--to-destination", podip,
	}
	err := ipt.table.DeleteRule(iptables.NATTable, NodePortLocalChain, ruleSpec)
	if err != nil {
		return fmt.Errorf("failed to delete IPTABLES rule for NPL: %v", err)
	}
	return nil
}

// DeleteAllRules deletes all NPL rules programmed in the node
func (ipt *iptablesRules) DeleteAllRules() error {
	exists, err := ipt.table.ChainExists(iptables.NATTable, NodePortLocalChain)
	if err != nil {
		return fmt.Errorf("failed to check if NodePortLocal chain exists in NAT table: %v", err)
	}
	if !exists {
		return nil
	}
	ruleSpec := []string{
		"-p", "tcp", "-j", NodePortLocalChain,
	}
	err = ipt.table.DeleteRule(iptables.NATTable, iptables.PreRoutingChain, ruleSpec)
	if err != nil {
		return fmt.Errorf("failed to delete rule from prerouting chain for NPL: %v", err)
	}

	err = ipt.table.DeleteChain(iptables.NATTable, NodePortLocalChain)
	if err != nil {
		return fmt.Errorf("failed to delete NodePortLocal Chain from NAT table: %v", err)
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
