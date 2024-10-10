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

package iptables

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"github.com/blang/semver"
	"github.com/coreos/go-iptables/iptables"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/util/ipset"
)

const (
	NATTable    = "nat"
	FilterTable = "filter"
	MangleTable = "mangle"
	RawTable    = "raw"

	AcceptTarget     = "ACCEPT"
	DropTarget       = "DROP"
	MasqueradeTarget = "MASQUERADE"
	MarkTarget       = "MARK"
	ReturnTarget     = "RETURN"
	ConnTrackTarget  = "CT"
	NoTrackTarget    = "NOTRACK"
	SNATTarget       = "SNAT"
	DNATTarget       = "DNAT"
	RejectTarget     = "REJECT"
	NotrackTarget    = "NOTRACK"
	LOGTarget        = "LOG"

	PreRoutingChain  = "PREROUTING"
	InputChain       = "INPUT"
	ForwardChain     = "FORWARD"
	PostRoutingChain = "POSTROUTING"
	OutputChain      = "OUTPUT"

	waitSeconds              = 10
	waitIntervalMicroSeconds = 200000
)

type Protocol byte

var protocolStrMap = map[Protocol]string{
	ProtocolIPv4: "IPv4",
	ProtocolIPv6: "IPv6",
}

func (p Protocol) String() string {
	return protocolStrMap[p]
}

const (
	ProtocolDual Protocol = iota
	ProtocolIPv4
	ProtocolIPv6
)

const (
	ProtocolTCP    = "tcp"
	ProtocolUDP    = "udp"
	ProtocolSCTP   = "sctp"
	ProtocolICMP   = "icmp"
	ProtocolICMPv6 = "icmp6"
)

var (
	// https://netfilter.org/projects/iptables/files/changes-iptables-1.6.2.txt:
	// iptables-restore: support acquiring the lock.
	restoreWaitSupportedMinVersion = semver.Version{Major: 1, Minor: 6, Patch: 2}

	// https://netfilter.org/projects/iptables/files/changes-iptables-1.6.0.txt:
	// iptables: snat: add randomize-full support
	// https://netfilter.org/projects/iptables/files/changes-iptables-1.6.2.txt:
	// iptables: masquerade: add randomize-full support
	// In our case, we do not differentiate between SNAT and MASQUERADE support for the option,
	// and we use 1.6.2 as the common minimum version number.
	randomFullySupportedMinVersion = semver.Version{Major: 1, Minor: 6, Patch: 2}
)

type Interface interface {
	EnsureChain(protocol Protocol, table string, chain string) error

	ChainExists(protocol Protocol, table string, chain string) (bool, error)

	AppendRule(protocol Protocol, table string, chain string, ruleSpec []string) error

	InsertRule(protocol Protocol, table string, chain string, ruleSpec []string) error

	DeleteRule(protocol Protocol, table string, chain string, ruleSpec []string) error

	DeleteChain(protocol Protocol, table string, chain string) error

	ListRules(protocol Protocol, table string, chain string) (map[Protocol][]string, error)

	Restore(data string, flush bool, useIPv6 bool) error

	Save() ([]byte, error)

	HasRandomFully() bool
}

type IPTablesRuleBuilder interface {
	MatchCIDRSrc(cidr string) IPTablesRuleBuilder
	MatchCIDRDst(cidr string) IPTablesRuleBuilder
	MatchIPSetSrc(ipset string, ipsetType ipset.SetType) IPTablesRuleBuilder
	MatchIPSetDst(ipset string, ipsetType ipset.SetType) IPTablesRuleBuilder
	MatchTransProtocol(protocol string) IPTablesRuleBuilder
	MatchPortDst(port *intstr.IntOrString, endPort *int32) IPTablesRuleBuilder
	MatchPortSrc(port, endPort *int32) IPTablesRuleBuilder
	MatchICMP(icmpType, icmpCode *int32, ipProtocol Protocol) IPTablesRuleBuilder
	MatchEstablishedOrRelated() IPTablesRuleBuilder
	MatchInputInterface(interfaceName string) IPTablesRuleBuilder
	MatchOutputInterface(interfaceName string) IPTablesRuleBuilder
	SetLogPrefix(prefix string) IPTablesRuleBuilder
	SetTarget(target string) IPTablesRuleBuilder
	SetTargetDNATToDst(dnatIP string, dnatPort *int32) IPTablesRuleBuilder
	SetComment(comment string) IPTablesRuleBuilder
	CopyBuilder() IPTablesRuleBuilder
	Done() IPTablesRule
}

type IPTablesRule interface {
	GetRule() string
}

type Client struct {
	ipts map[Protocol]*iptables.IPTables
	// restoreWaitSupported indicates whether iptables-restore (or ip6tables-restore) supports --wait flag.
	restoreWaitSupported bool
	// randomFullySupported indicates whether --random-fully is supported for SNAT and MASQUERADE rules.
	randomFullySupported bool
}

func New(enableIPV4, enableIPV6 bool) (*Client, error) {
	ipts := make(map[Protocol]*iptables.IPTables)
	var restoreWaitSupported, randomFullySupported bool
	if enableIPV4 || enableIPV6 {
		restoreWaitSupported = true
		randomFullySupported = true
	}
	if enableIPV4 {
		ipt, err := iptables.New()
		if err != nil {
			return nil, fmt.Errorf("error creating IPTables instance: %v", err)
		}
		ipts[ProtocolIPv4] = ipt
		restoreWaitSupported = restoreWaitSupported && isRestoreWaitSupported(ipt)
		randomFullySupported = randomFullySupported && isRandomFullySupported(ipt)
	}
	if enableIPV6 {
		ip6t, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return nil, fmt.Errorf("error creating IPTables instance for IPv6: %v", err)
		}
		ipts[ProtocolIPv6] = ip6t
		restoreWaitSupported = restoreWaitSupported && isRestoreWaitSupported(ip6t)
		randomFullySupported = randomFullySupported && isRandomFullySupported(ip6t)
	}
	return &Client{ipts: ipts, restoreWaitSupported: restoreWaitSupported, randomFullySupported: randomFullySupported}, nil
}

func isRestoreWaitSupported(ipt *iptables.IPTables) bool {
	major, minor, patch := ipt.GetIptablesVersion()
	version := semver.Version{Major: uint64(major), Minor: uint64(minor), Patch: uint64(patch)}
	return version.GE(restoreWaitSupportedMinVersion)
}

func isRandomFullySupported(ipt *iptables.IPTables) bool {
	// Note that even if the iptables version supports it, the kernel version may not.
	// For SNAT rules, kernel >= 3.14 is required. For MASQUERADE rules, kernel >= 3.13 is required.
	// Given how old these kernel releases are, we do not check the version here. This is
	// consistent with how K8s checks for --random-fully support:
	// https://github.com/kubernetes/kubernetes/blob/60c4c2b2521fb454ce69dee737e3eb91a25e0535/pkg/util/iptables/iptables.go#L239
	major, minor, patch := ipt.GetIptablesVersion()
	version := semver.Version{Major: uint64(major), Minor: uint64(minor), Patch: uint64(patch)}
	return version.GE(randomFullySupportedMinVersion)
}

// EnsureChain checks if target chain already exists, creates it if not.
func (c *Client) EnsureChain(protocol Protocol, table string, chain string) error {
	for p := range c.ipts {
		ipt := c.ipts[p]
		if !matchProtocol(ipt, protocol) {
			continue
		}
		exists, err := ipt.ChainExists(table, chain)
		if err != nil {
			return fmt.Errorf("error checking if chain %s exists in table %s: %v", chain, table, err)
		}
		if exists {
			continue
		}
		if err := ipt.NewChain(table, chain); err != nil {
			return fmt.Errorf("error creating chain %s in table %s: %v", chain, table, err)
		}
		klog.V(2).InfoS("Created a chain", "chain", chain, "table", table, "protocol", p)
	}
	return nil
}

// ChainExists checks if target chain already exists in a table
func (c *Client) ChainExists(protocol Protocol, table string, chain string) (bool, error) {
	for p := range c.ipts {
		ipt := c.ipts[p]
		if !matchProtocol(ipt, protocol) {
			continue
		}
		exists, err := ipt.ChainExists(table, chain)
		if err != nil {
			return false, fmt.Errorf("error checking if chain %s exists in table %s: %v", chain, table, err)
		}
		if !exists {
			return false, nil
		}
		klog.V(2).InfoS("A chain exists", "chain", chain, "table", table, "protocol", p)
	}
	return true, nil
}

// AppendRule checks if target rule already exists with the protocol, appends it if not.
func (c *Client) AppendRule(protocol Protocol, table string, chain string, ruleSpec []string) error {
	for p := range c.ipts {
		ipt := c.ipts[p]
		if !matchProtocol(ipt, protocol) {
			continue
		}
		exist, err := ipt.Exists(table, chain, ruleSpec...)
		if err != nil {
			return fmt.Errorf("error checking if rule %v exists in table %s chain %s: %v", ruleSpec, table, chain, err)
		}
		if exist {
			continue
		}
		if err := ipt.Append(table, chain, ruleSpec...); err != nil {
			return fmt.Errorf("error appending rule %v to table %s chain %s: %v", ruleSpec, table, chain, err)
		}
		klog.V(2).InfoS("Appended a rule", "rule", ruleSpec, "table", table, "chain", chain, "protocol", p)
	}
	return nil
}

// InsertRule checks if target rule already exists, inserts it at the beginning of the chain if not.
func (c *Client) InsertRule(protocol Protocol, table string, chain string, ruleSpec []string) error {
	for p := range c.ipts {
		ipt := c.ipts[p]
		if !matchProtocol(ipt, protocol) {
			continue
		}
		exist, err := ipt.Exists(table, chain, ruleSpec...)
		if err != nil {
			return fmt.Errorf("error checking if rule %v exists in table %s chain %s: %v", ruleSpec, table, chain, err)
		}
		if exist {
			continue
		}
		if err := ipt.Insert(table, chain, 1, ruleSpec...); err != nil {
			return fmt.Errorf("error inserting rule %v to table %s chain %s: %v", ruleSpec, table, chain, err)
		}
		klog.V(2).InfoS("Inserted a rule", "rule", ruleSpec, "table", table, "chain", chain, "index", 1)
	}
	return nil
}

func matchProtocol(ipt *iptables.IPTables, protocol Protocol) bool {
	switch protocol {
	case ProtocolDual:
		return true
	case ProtocolIPv4:
		return ipt.Proto() == iptables.ProtocolIPv4
	case ProtocolIPv6:
		return ipt.Proto() == iptables.ProtocolIPv6
	}
	return false
}

// DeleteRule checks if target rule already exists, deletes the rule if found.
func (c *Client) DeleteRule(protocol Protocol, table string, chain string, ruleSpec []string) error {
	for p := range c.ipts {
		ipt := c.ipts[p]
		if !matchProtocol(ipt, protocol) {
			continue
		}
		exist, err := ipt.Exists(table, chain, ruleSpec...)
		if err != nil {
			return fmt.Errorf("error checking if rule %v exists in table %s chain %s: %v", ruleSpec, table, chain, err)
		}
		if !exist {
			continue
		}
		if err := ipt.Delete(table, chain, ruleSpec...); err != nil {
			return fmt.Errorf("error deleting rule %v from table %s chain %s: %v", ruleSpec, table, chain, err)
		}
		klog.V(2).InfoS("Deleted a rule", "rule", ruleSpec, "table", table, "chain", chain, "protocol", p)
	}
	return nil
}

// DeleteChain deletes all rules from a chain in a table and then delete the chain.
func (c *Client) DeleteChain(protocol Protocol, table string, chain string) error {
	for p := range c.ipts {
		ipt := c.ipts[p]
		if !matchProtocol(ipt, protocol) {
			continue
		}
		exists, err := ipt.ChainExists(table, chain)
		if err != nil {
			return fmt.Errorf("error checking if chain %s exists in table %s: %v", chain, table, err)
		}
		if !exists {
			continue
		}
		if err = ipt.ClearChain(table, chain); err != nil {
			return fmt.Errorf("error clearing rules from table %s chain %s: %v", table, chain, err)
		}
		if err = ipt.DeleteChain(table, chain); err != nil {
			return fmt.Errorf("error deleting chain %s from table %s: %v", chain, table, err)
		}
		klog.V(2).InfoS("Deleted a chain", "chain", chain, "table", table, "protocol", p)
	}
	return nil
}

// ListRules lists all rules from a chain in a table.
func (c *Client) ListRules(protocol Protocol, table string, chain string) (map[Protocol][]string, error) {
	allRules := make(map[Protocol][]string)
	for p := range c.ipts {
		ipt := c.ipts[p]
		if !matchProtocol(ipt, protocol) {
			continue
		}
		rules, err := ipt.List(table, chain)
		if err != nil {
			return nil, fmt.Errorf("error getting rules from table %s chain %s protocol %s: %v", table, chain, p, err)
		}
		allRules[p] = rules
	}
	return allRules, nil
}

// Restore calls iptable-restore to restore iptables with the provided content.
// If flush is true, all previous contents of the respective tables will be flushed.
// Otherwise only involved chains will be flushed. Restore supports "ip6tables-restore" for IPv6.
func (c *Client) Restore(data string, flush bool, useIPv6 bool) error {
	var args []string
	if !flush {
		args = append(args, "--noflush")
	}
	iptablesCmd := "iptables-restore"
	if useIPv6 {
		iptablesCmd = "ip6tables-restore"
	}
	cmd := exec.Command(iptablesCmd, args...)
	cmd.Stdin = bytes.NewBuffer([]byte(data))
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
		klog.ErrorS(err, "Failed to execute iptables command", "iptablesCmd", iptablesCmd, "stdin", data, "stderr", stderr)
		return fmt.Errorf("error executing %s: %v", iptablesCmd, err)
	}
	return nil
}

// Save calls iptables-saves to dump chains and tables in iptables.
func (c *Client) Save() ([]byte, error) {
	var output []byte
	for p := range c.ipts {
		var cmd string
		ipt := c.ipts[p]
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

// HasRandomFully returns true if the iptables version supports --random-fully for SNAT and
// MASQUERADE rules.
func (c *Client) HasRandomFully() bool {
	return c.randomFullySupported
}

func MakeChainLine(chain string) string {
	return fmt.Sprintf(":%s - [0:0]", chain)
}

func IsIPv6Protocol(protocol Protocol) bool {
	return protocol == ProtocolIPv6
}
