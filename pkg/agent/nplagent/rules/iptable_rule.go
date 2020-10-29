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
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"k8s.io/klog"
)

type IPTableRule struct {
	name  string
	table *iptables.IPTables
}

var once sync.Once

func (ipt *IPTableRule) Init() (bool, error) {
	_, err := iptables.New()
	if err != nil {
		klog.Infof("init iptable for NPL failed: %v\n", err)
		return false, errors.New("iptable init failed")
	}
	return true, nil
}

// CreateChains : Create the chain NODE-PORT-LOCAL in NAT table
// All DNAT rules for NPL would be added in this chain
func (ipt *IPTableRule) CreateChains() error {
	exists, err := ipt.table.Exists("nat", "NODE-PORT-LOCAL")
	if err != nil {
		klog.Warningf("check for NODE-PORT-LOCAL chain in iptable failed with error: %v", err)
		return err
	}
	if !exists {
		err = ipt.table.NewChain("nat", "NODE-PORT-LOCAL")
		if err != nil {
			klog.Warningf("IPtable chain creation failed for NPL with error: %v", err)
			return err
		}
	}

	exists, err = ipt.table.Exists("nat", "PREROUTING", "-p", "tcp", "-j", "NODE-PORT-LOCAL")
	if err != nil {
		klog.Warningf("check for NODE-PORT-LOCAL chain in iptable failed with error: %v", err)
		return err
	}
	if !exists {
		err = ipt.table.Append("nat", "PREROUTING", "-p", "tcp", "-j", "NODE-PORT-LOCAL")
		if err != nil {
			klog.Warningf("IPtable rule creation in PREROUTING chain failed for NPL with error: %v", err)
			return err
		}
	}
	return nil
}

// AddRule : Appends a DNAT rule in NODE-PORT-LOCAL chain of NAT table
func (ipt *IPTableRule) AddRule(port int, podip string) (bool, error) {
	exists, err := ipt.table.Exists("nat", "NODE-PORT-LOCAL", "-p", "tcp", "-m", "tcp", "--dport",
		fmt.Sprint(port), "-j", "DNAT", "--to-destination", podip)
	if err != nil {
		klog.Warningf("check for NODE-PORT-LOCAL chain in iptable failed with error: %v", err)
		return false, err
	}
	if !exists {
		err := ipt.table.Append("nat", "NODE-PORT-LOCAL", "-p", "tcp", "-m", "tcp", "--dport",
			fmt.Sprint(port), "-j", "DNAT", "--to-destination", podip)

		if err != nil {
			klog.Warningf("IPtable rule creation in failed for NPL with error: %v", err)
			return false, err
		}
	}

	return true, nil
}

// DeleteRule : Delete a specific NPL rule from NODE-PORT-LOCAL chain
func (ipt *IPTableRule) DeleteRule(port int, podip string) (bool, error) {
	klog.Infof("Deleting rule with port %v and podip %v", port, podip)
	err := ipt.table.Delete("nat", "NODE-PORT-LOCAL", "-p", "tcp", "-m", "tcp", "--dport",
		fmt.Sprint(port), "-j", "DNAT", "--to-destination", podip)

	if err != nil {
		klog.Infof("%v", err)
		return false, err
	}
	return true, nil
}

// SyncState : To Do - Compare existing rules with expected rules for all pods
// and make sure that correct rules are programmed correctly
func (ipt *IPTableRule) SyncState(podPort map[int]string) bool {
	m := make(map[int]string)
	var success = false
	for port, node := range podPort {
		success, _ = ipt.AddRule(port, node)
		if success == false {
			m[port] = node
			klog.Warningf("Adding iptables failed for port %d and node %s", port, node)
			return false
		}
	}
	podPort = m
	return true
}

// GetAllRules : Get list of all NPL rules progammed in the node
func (ipt *IPTableRule) GetAllRules(podPort map[int]string) (bool, error) {
	rules, err := ipt.table.List("nat", "NODE-PORT-LOCAL")
	if err != nil {
		klog.Warningf("Failed to list IPtable rules for NPL: %v", err)
		return false, err
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
	return true, nil
}

// DeleteAllRules : Delete all NPL rules progammed in the node
func (ipt *IPTableRule) DeleteAllRules() (bool, error) {
	err := ipt.table.Delete("nat", "PREROUTING", "-p", "tcp", "-j", "NODE-PORT-LOCAL")
	if err != nil {
		klog.Warningf("Failed to delete rule from PREROUTING chain for NPL: %v\n", err)
		return false, err
	}
	err = ipt.table.ClearChain("nat", "NODE-PORT-LOCAL")
	if err != nil {
		klog.Warningf("Failed to clear chain for NPL: %v\n", err)
		return false, err
	}
	err = ipt.table.DeleteChain("nat", "NODE-PORT-LOCAL")
	if err != nil {
		klog.Warningf("Failed to delete chain for NPL: %v\n", err)
		return false, err
	}
	return true, nil
}
