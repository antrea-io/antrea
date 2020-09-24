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

package iptables

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"github.com/blang/semver"
	"github.com/coreos/go-iptables/iptables"
	"k8s.io/klog"
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
	DNATTarget       = "DNAT"
	NoTrackTarget    = "NOTRACK"

	PreRoutingChain  = "PREROUTING"
	ForwardChain     = "FORWARD"
	PostRoutingChain = "POSTROUTING"
	OutputChain      = "OUTPUT"

	waitSeconds              = 10
	waitIntervalMicroSeconds = 200000
)

// https://netfilter.org/projects/iptables/files/changes-iptables-1.6.2.txt:
// iptables-restore: support acquiring the lock.
var restoreWaitSupportedMinVersion = semver.Version{Major: 1, Minor: 6, Patch: 2}

type Client struct {
	ipts []*iptables.IPTables
	// restoreWaitSupported indicates whether iptables-restore (or ip6tables-restore) supports --wait flag.
	restoreWaitSupported bool
}

func New(enableIPV4, enableIPV6 bool) (*Client, error) {
	var ipts []*iptables.IPTables
	var restoreWaitSupported bool
	if enableIPV4 {
		ipt, err := iptables.New()
		if err != nil {
			return nil, fmt.Errorf("error creating IPTables instance: %v", err)
		}
		ipts = append(ipts, ipt)
		restoreWaitSupported = isRestoreWaitSupported(ipt)
	}
	if enableIPV6 {
		ip6t, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return nil, fmt.Errorf("error creating IPTables instance for IPv6: %v", err)
		}
		ipts = append(ipts, ip6t)
		if !restoreWaitSupported {
			restoreWaitSupported = isRestoreWaitSupported(ip6t)
		}
	}
	return &Client{ipts: ipts, restoreWaitSupported: restoreWaitSupported}, nil
}

func isRestoreWaitSupported(ipt *iptables.IPTables) bool {
	major, minor, patch := ipt.GetIptablesVersion()
	version := semver.Version{Major: uint64(major), Minor: uint64(minor), Patch: uint64(patch)}
	return version.GE(restoreWaitSupportedMinVersion)
}

// EnsureChain checks if target chain already exists, creates it if not.
func (c *Client) EnsureChain(table string, chain string) error {
	for idx := range c.ipts {
		ipt := c.ipts[idx]
		oriChains, err := ipt.ListChains(table)
		if err != nil {
			return fmt.Errorf("error listing existing chains in table %s: %v", table, err)
		}
		if contains(oriChains, chain) {
			return nil
		}
		if err := ipt.NewChain(table, chain); err != nil {
			return fmt.Errorf("error creating chain %s in table %s: %v", chain, table, err)
		}
		klog.V(2).Infof("Created chain %s in table %s", chain, table)
	}
	return nil
}

// ChainExists checks if a chain already exists in a table
func (c *Client) ChainExists(table string, chain string) (bool, error) {
	for idx := range c.ipts {
		allChains, err := c.ipts[idx].ListChains(table)
		if err != nil {
			return false, fmt.Errorf("error listing existing chains in table %s: %v", table, err)
		}
		if contains(allChains, chain) {
			return true, nil
		}
	}
	return false, nil
}

// EnsureRule checks if target rule already exists, add it if not. If prepend is true, the rule will be added to the top
// of the chain. Otherwise, the rule will be appended to the chain.
func (c *Client) EnsureRule(table string, chain string, ruleSpec []string, prepend bool) error {
	for idx := range c.ipts {
		ipt := c.ipts[idx]
		exist, err := ipt.Exists(table, chain, ruleSpec...)
		if err != nil {
			return fmt.Errorf("error checking if rule %v exists in table %s chain %s: %v", ruleSpec, table, chain, err)
		}
		if exist {
			return nil
		}
		var f func() error
		if !prepend {
			f = func() error { return ipt.Append(table, chain, ruleSpec...) }
		} else {
			f = func() error { return ipt.Insert(table, chain, 1, ruleSpec...) }
		}
		if err := f(); err != nil {
			return fmt.Errorf("error appending rule %v to table %s chain %s: %v", ruleSpec, table, chain, err)
		}
	}
	klog.V(2).Infof("Appended rule %v to table %s chain %s", ruleSpec, table, chain)
	return nil
}

// DeleteRule checks if target rule already exists, deletes the rule if found.
func (c *Client) DeleteRule(table string, chain string, ruleSpec []string) error {
	for idx := range c.ipts {
		exist, err := c.ipts[idx].Exists(table, chain, ruleSpec...)
		if err != nil {
			return fmt.Errorf("error checking if rule %v exists in table %s chain %s: %v", ruleSpec, table, chain, err)
		}
		if !exist {
			return nil
		}
		if err := c.ipts[idx].Delete(table, chain, ruleSpec...); err != nil {
			return fmt.Errorf("error deleting rule %v from table %s chain %s: %v", ruleSpec, table, chain, err)
		}
		klog.V(2).Infof("Deleted rule %v from table %s chain %s", ruleSpec, table, chain)
	}
	return nil
}

// DeleteChain deletes all rules from a chain in a table and then delete the chain
func (c *Client) DeleteChain(table string, chain string) error {
	for idx := range c.ipts {
		err := c.ipts[idx].ClearChain(table, chain)
		if err != nil {
			return fmt.Errorf("error clearing rules from table %s chain %s: %v", table, chain, err)
		}
		err = c.ipts[idx].DeleteChain(table, chain)
		if err != nil {
			return fmt.Errorf("error deleting chain %s from table %s: %v", chain, table, err)
		}
		klog.V(2).Infof("Deleted chain %s from table %s", chain, table)
	}
	return nil
}

// ListRules lists all rules from a chain in a table
func (c *Client) ListRules(table string, chain string) ([]string, error) {
	var allRules []string
	for idx := range c.ipts {
		rules, err := c.ipts[idx].List(table, chain)
		if err != nil {
			return rules, fmt.Errorf("error getting rules from table %s chain %s: %v", table, chain, err)
		}
		allRules = append(allRules, rules...)
	}
	return allRules, nil
}

// Restore calls iptable-restore to restore iptables with the provided content.
// If flush is true, all previous contents of the respective tables will be flushed.
// Otherwise only involved chains will be flushed. Restore supports "ip6tables-restore" for IPv6.
func (c *Client) Restore(data []byte, flush bool, useIPv6 bool) error {
	var args []string
	if !flush {
		args = append(args, "--noflush")
	}
	iptablesCmd := "iptables-restore"
	if useIPv6 {
		iptablesCmd = "ip6tables-restore"
	}
	cmd := exec.Command(iptablesCmd, args...)
	cmd.Stdin = bytes.NewBuffer(data)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	// We acquire xtables lock for iptables-restore to prevent it from conflicting
	// with iptables/iptables-restore which might being called by kube-proxy.
	// iptables supports "--wait" option and go-iptables has enabled it.
	// iptables-restore doesn't support the option until 1.6.2. We use "-w" if the
	// detected version is greater than or equal to 1.6.2, otherwise we acquire the
	// file lock explicitly.
	// Note that we cannot just acquire the file lock explicitly for all cases because
	// iptables-restore will try acquiring the lock with or without "-w" provided since 1.6.2.
	if c.restoreWaitSupported {
		cmd.Args = append(cmd.Args, "-w", strconv.Itoa(waitSeconds), "-W", strconv.Itoa(waitIntervalMicroSeconds))
	} else {
		unlockFunc, err := Lock(XtablesLockFilePath, waitSeconds*time.Second)
		if err != nil {
			return err
		}
		defer unlockFunc()
	}
	if err := cmd.Run(); err != nil {
		klog.Errorf("Failed to execute %s: %v\nstdin:\n%s\nstderr:\n%s", iptablesCmd, err, data, stderr)
		return fmt.Errorf("error executing %s: %v", iptablesCmd, err)
	}
	return nil
}

// Save calls iptables-saves to dump chains and tables in iptables.
func (c *Client) Save() ([]byte, error) {
	var output []byte
	for idx := range c.ipts {
		var cmd string
		ipt := c.ipts[idx]
		switch ipt.Proto() {
		case iptables.ProtocolIPv6:
			cmd = "ip6tables-save"
		default:
			cmd = "iptables-save"
		}
		data, err := exec.Command(cmd, "-c").CombinedOutput()
		if err != nil {
			return nil, err
		}
		output = append(output, data...)
	}
	return output, nil
}

func contains(chains []string, targetChain string) bool {
	for _, val := range chains {
		if val == targetChain {
			return true
		}
	}
	return false
}

func MakeChainLine(chain string) string {
	return fmt.Sprintf(":%s - [0:0]", chain)
}
