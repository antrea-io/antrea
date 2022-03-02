//go:build linux
// +build linux

// Copyright 2022 Antrea Authors
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

package agent

import (
	"testing"
	"time"

	nplcontroller "antrea.io/antrea/pkg/agent/nodeportlocal/k8s"
	portcache "antrea.io/antrea/pkg/agent/nodeportlocal/portcache"
	rules "antrea.io/antrea/pkg/agent/nodeportlocal/rules"
	iptables "antrea.io/antrea/pkg/agent/util/iptables"
)

func TestNPLIptablesRestore(t *testing.T) {
	portTable, err := portcache.NewPortTable(61000, 62000)
	if err != nil {
		t.Fatalf("Failed to initialize porttable: %v", err)
	}
	// get testing NPLController
	synced := make(chan struct{})
	nplCtrl := nplcontroller.NewTestingNPLController(portTable, 1*time.Second)
	// add the static rules
	err = portTable.PodPortRules.SyncFixedRules()
	if err != nil {
		t.Fatalf("Failed to add static rules: %v", err)
	}
	defer func() {
		err := portTable.PodPortRules.DeleteAllRules()
		if err != nil {
			t.Fatalf("Failed to delete iptables rules: %v", err)
		}
	}()
	// add some initial iptables rules from some fake pod data
	allNPLPorts := []rules.PodNodePort{
		{
			NodePort:  61001,
			PodPort:   80,
			PodIP:     "20.0.0.1",
			Protocols: []string{"tcp"},
		},
		{
			NodePort:  61002,
			PodPort:   80,
			PodIP:     "21.0.0.2",
			Protocols: []string{"tcp", "udp"},
		},
	}
	err = portTable.RestoreRules(allNPLPorts, synced)
	if err != nil {
		t.Fatalf("Failed to add iptables rules %v", err)
	}
	t.Logf("Waiting for portTable to set NPL iptables rules")
	<-synced
	t.Logf("Success set NPL iptables rules")
	// delete iptables rules including the static rules
	err = portTable.PodPortRules.DeleteAllRules()
	if err != nil {
		t.Fatalf("Failed to delete iptables rules: %v", err)
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go nplCtrl.SyncRules(stopCh)
	t.Logf("Waiting for NPLController to recover NPL iptables rules")
	time.Sleep(nplCtrl.SyncRuleInterval + 1*time.Second)
	t.Logf("Checking if NPL iptables rules are recovered")
	// check if NPL chain is present.
	ipt, err := iptables.New(true, false)
	exists, err := ipt.ChainExists(iptables.ProtocolIPv4, iptables.NATTable, rules.NodePortLocalChain)
	if exists {
		t.Logf("NPL chain exists in nat table.")
	} else {
		t.Fatalf("error checking if  NPL chain  exists in nat table ")
	}

	//Check if static rules are restored.
	rulespec := []string{
		"-p", "all", "-m", "addrtype", "--dst-type", "LOCAL", "-j", rules.NodePortLocalChain,
	}
	exists, err = ipt.Exists(iptables.ProtocolIPv4, iptables.NATTable, iptables.PreRoutingChain, rulespec)
	if exists {
		t.Logf("Static rules successfully restored in PreRouting chain")
	} else {
		t.Fatalf("Failed to restore static rules in PreRouting Chain ")
	}

	exists, err = ipt.Exists(iptables.ProtocolIPv4, iptables.NATTable, iptables.OutputChain, rulespec)
	if exists {
		t.Logf("Static rules successfully restored in Output chain")
	} else {
		t.Fatalf("Failed to restore static rules in Output Chain ")
	}

	//Check if dynamic rules are restored.
	ruleSpecs := [][]string{
		{
			"-p", "tcp", "-m", "tcp", "--dport", "61001",
			"-j", "DNAT", "--to-destination", "20.0.0.1:80",
		},
		{
			"-p", "tcp", "-m", "tcp", "--dport", "61002",
			"-j", "DNAT", "--to-destination", "21.0.0.2:80",
		},
		{
			"-p", "udp", "-m", "udp", "--dport", "61002",
			"-j", "DNAT", "--to-destination", "21.0.0.2:80",
		},
	}
	for n, ruleSpec := range ruleSpecs {
		exists, err = ipt.Exists(iptables.ProtocolIPv4, iptables.NATTable, rules.NodePortLocalChain, ruleSpec)
		if exists {
			t.Logf("Dynamic rule %d successfully restored in NPL chain", n)
		} else {
			t.Fatalf("Failed to restore dynamic rule %d in NPL Chain ", n)
		}
	}
}
