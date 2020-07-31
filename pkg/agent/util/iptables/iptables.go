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
	"k8s.io/klog/v2"
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

	PreRoutingChain  = "PREROUTING"
	ForwardChain     = "FORWARD"
	PostRoutingChain = "POSTROUTING"

	waitSeconds              = 10
	waitIntervalMicroSeconds = 200000
)

// https://netfilter.org/projects/iptables/files/changes-iptables-1.6.2.txt:
// iptables-restore: support acquiring the lock.
var restoreWaitSupportedMinVersion = semver.Version{Major: 1, Minor: 6, Patch: 2}

type Client struct {
	ipt *iptables.IPTables
	// restoreWaitSupported indicates whether iptables-restore supports --wait flag.
	restoreWaitSupported bool
}

func New() (*Client, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("error creating IPTables instance: %v", err)
	}
	return &Client{ipt: ipt, restoreWaitSupported: isRestoreWaitSupported(ipt)}, nil
}

func isRestoreWaitSupported(ipt *iptables.IPTables) bool {
	major, minor, patch := ipt.GetIptablesVersion()
	version := semver.Version{Major: uint64(major), Minor: uint64(minor), Patch: uint64(patch)}
	return version.GE(restoreWaitSupportedMinVersion)
}

// ensureChain checks if target chain already exists, creates it if not.
func (c *Client) EnsureChain(table string, chain string) error {
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
func (c *Client) EnsureRule(table string, chain string, ruleSpec []string) error {
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

// Restore calls iptable-restore to restore iptables with the provided content.
// If flush is true, all previous contents of the respective tables will be flushed.
// Otherwise only involved chains will be flushed.
func (c *Client) Restore(data []byte, flush bool) error {
	var args []string
	if !flush {
		args = append(args, "--noflush")
	}
	cmd := exec.Command("iptables-restore", args...)
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
		unlockFunc, err := lock(xtablesLockFilePath, waitSeconds*time.Second)
		if err != nil {
			return err
		}
		defer unlockFunc()
	}
	if err := cmd.Run(); err != nil {
		klog.Errorf("Failed to execute iptables-restore: %v\nstdin:\n%s\nstderr:\n%s", err, data, stderr)
		return fmt.Errorf("error executing iptables-restore: %v", err)
	}
	return nil
}

// Save calls iptables-saves to dump chains and tables in iptables.
func (c *Client) Save() ([]byte, error) {
	return exec.Command("iptables-save", "-c").CombinedOutput()
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
