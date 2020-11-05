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
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/vmware-tanzu/antrea/pkg/agent/util/iptables"
	"k8s.io/klog"
)

const NodePortLocalChain = "ANTREA-NODE-PORT-LOCAL"

type IPTableRules struct {
	name  string
	table *iptables.Client
}

func NewIPTableRules() *IPTableRules {
	iptInstance, _ := iptables.New(true, false)
	iptRule := IPTableRules{
		name:  "NPL",
		table: iptInstance,
	}
	return &iptRule
}

var once sync.Once

func (ipt *IPTableRules) Init() bool {
	if !ipt.DeleteAllRules() {
		return false
	}
	return ipt.CreateChains()
}

// CreateChains : Create the chain NodePortLocalChain in NAT table
// All DNAT rules for NPL would be added in this chain
func (ipt *IPTableRules) CreateChains() bool {
	ipt.table.EnsureChain(iptables.NATTable, NodePortLocalChain)
	ruleSpec := []string{
		"-p", "tcp", "-j", NodePortLocalChain,
	}
	ipt.table.EnsureRule(iptables.NATTable, iptables.PreRoutingChain, ruleSpec)
	return true
}

// AddRule : Appends a DNAT rule in NodePortLocalChain chain of NAT table
func (ipt *IPTableRules) AddRule(port int, podip string) bool {
	ruleSpec := []string{
		"-p", "tcp", "-m", "tcp", "--dport",
		fmt.Sprint(port), "-j", "DNAT", "--to-destination", podip,
	}
	err := ipt.table.EnsureRule(iptables.NATTable, NodePortLocalChain, ruleSpec)
	if err != nil {
		klog.Warningf("IPTABLES rule creation in failed for NPL with error: %v", err)
		return false
	}
	klog.Infof("successfully added rule for pod %s: %d", podip, port)
	return true
}

// DeleteRule : Delete a specific NPL rule from NodePortLocalChain chain
func (ipt *IPTableRules) DeleteRule(port int, podip string) bool {
	klog.Infof("Deleting rule with port %v and podip %v", port, podip)
	ruleSpec := []string{
		"-p", "tcp", "-m", "tcp", "--dport",
		fmt.Sprint(port), "-j", "DNAT", "--to-destination", podip,
	}
	err := ipt.table.DeleteRule(iptables.NATTable, NodePortLocalChain, ruleSpec)

	if err != nil {
		klog.Infof("Failed to delete IPTABLES rule for NPL: %v", err)
		return false
	}
	return true
}

// GetAllRules : Get list of all NPL rules progammed in the node
func (ipt *IPTableRules) GetAllRules(podPort map[int]string) bool {
	rules, err := ipt.table.ListRules(iptables.NATTable, NodePortLocalChain)
	if err != nil {
		klog.Warningf("Failed to list IPTABLES rules for NPL: %v", err)
		return false
	}
	m := make(map[int]string)
	for i := range rules {
		splitRule := strings.Fields(rules[i])
		// A rule has details about the node port, port ip and port number.
		// e.g.:  -A NODE-PORT-LOCAL -p tcp -m tcp --dport 45000 -j DNAT --to-destination 10.244.0.43:8080
		if len(splitRule) != 12 {
			continue
		}
		port, err := strconv.Atoi(splitRule[7])
		if err != nil {
			klog.Warningf("Failed to convert port string to int: %v", err)
			continue
		}
		nodeipPort := strings.Split(splitRule[11], ":")
		if len(nodeipPort) != 2 {
			continue
		}
		//TODO: Need to check whether it's a proper ip:port combination
		m[port] = splitRule[11]
	}
	podPort = m
	return true
}

// DeleteAllRules : Delete all NPL rules progammed in the node
func (ipt *IPTableRules) DeleteAllRules() bool {
	ruleSpec := []string{
		"-p", "tcp", "-j", NodePortLocalChain,
	}
	err := ipt.table.DeleteRule(iptables.NATTable, iptables.PreRoutingChain, ruleSpec)
	if err != nil {
		klog.Warningf("Failed to delete rule from prerouting chain for NPL: %v", err)
		return false
	}

	err = ipt.table.DeleteChain(iptables.NATTable, NodePortLocalChain)
	if err != nil {
		klog.Warningf("Failed to delete NodePortLocal Chain from NAT table: %v", err)
		return false
	}
	return true
}
