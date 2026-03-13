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

//go:build !windows
// +build !windows

package support

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/util/iptables"
	"antrea.io/antrea/pkg/agent/util/nftables"
	"antrea.io/antrea/pkg/util/logdir"
)

// nftablesIPv4Supported and nftablesIPv6Supported check if the kernel supports nftables.
// They initialize the client once to verify support, but the returned clients are not used.
var nftablesIPv4Supported = sync.OnceValue(func() bool {
	if _, err := nftables.New(true, false); err != nil {
		klog.InfoS("NFTables IPv4 not supported on this Node", "err", err)
		return false
	}
	return true
})

var nftablesIPv6Supported = sync.OnceValue(func() bool {
	if _, err := nftables.New(false, true); err != nil {
		klog.InfoS("NFTables IPv6 not supported on this Node", "err", err)
		return false
	}
	return true
})

func (d *agentDumper) DumpLog(basedir string) error {
	logDir := logdir.GetLogDir()
	timeFilter := timestampFilter(d.since)

	if err := directoryCopy(d.fs, path.Join(basedir, "logs", "agent"), logDir, "antrea-agent", timeFilter); err != nil {
		return err
	}
	return directoryCopy(d.fs, path.Join(basedir, "logs", "ovs"), logDir, "ovs", timeFilter)
}

func (d *agentDumper) DumpHostNetworkInfo(basedir string) error {
	if err := d.dumpIPTables(basedir); err != nil {
		return err
	}
	if err := d.dumpIPSet(basedir); err != nil {
		return err
	}
	if err := d.dumpNFTables(basedir); err != nil {
		return err
	}
	if err := d.dumpIPToolInfo(basedir); err != nil {
		return err
	}
	if err := d.dumpSysctlNetIF(basedir); err != nil {
		return err
	}
	return nil
}

func (d *agentDumper) dumpIPTables(basedir string) error {
	c, err := iptables.New(d.v4Enabled, d.v6Enabled)
	if err != nil {
		return err
	}
	data, err := c.Save()
	if err != nil {
		return err
	}
	return writeFile(d.fs, filepath.Join(basedir, "iptables"), "iptables", data)
}

func (d *agentDumper) dumpIPSet(basedir string) error {
	data, err := d.ipsetClient.Save()
	if err != nil {
		return err
	}
	return writeFile(d.fs, filepath.Join(basedir, "ipset"), "ipset", data)
}

func (d *agentDumper) dumpNFTables(basedir string) error {
	var data bytes.Buffer

	if d.v4Enabled && nftablesIPv4Supported() || d.v6Enabled && nftablesIPv6Supported() {
		output, err := d.executor.Command("nft", "list", "ruleset").CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to dump nftables: %w", err)
		}
		if len(output) == 0 {
			return nil
		}
		data.Write(output)
		data.WriteByte('\n')
	}

	fileName := "nftables"
	if err := writeFile(d.fs, filepath.Join(basedir, fileName), fileName, data.Bytes()); err != nil {
		return fmt.Errorf("failed to write nftables file: %w", err)
	}

	return nil
}

func (d *agentDumper) dumpIPToolInfo(basedir string) error {
	type ipCmd struct {
		fileName string
		args     []string
	}
	dump := func(cmd ipCmd) error {
		output, err := d.executor.Command("ip", cmd.args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("error when dumping ip %s: %w", strings.Join(cmd.args, " "), err)
		}
		return writeFile(d.fs, filepath.Join(basedir, cmd.fileName), cmd.fileName, output)
	}
	for _, item := range []ipCmd{
		{fileName: "route", args: []string{"route"}},
		{fileName: "route-all", args: []string{"route", "show", "table", "all"}},
		{fileName: "rule", args: []string{"rule"}},
		{fileName: "link", args: []string{"link"}},
		{fileName: "address", args: []string{"address"}},
	} {
		if err := dump(item); err != nil {
			return err
		}
	}
	return nil
}

// sysctlNetIPv4ConfPath is the path to the per-interface IPv4 sysctl
// parameters. It is a variable to allow overriding in tests.
var sysctlNetIPv4ConfPath = "/proc/sys/net/ipv4/conf"

// dumpSysctlNetIF reads the rp_filter, arp_ignore, and arp_announce sysctl
// parameters for all network interfaces and writes them to a file.
func (d *agentDumper) dumpSysctlNetIF(basedir string) error {
	entries, err := os.ReadDir(sysctlNetIPv4ConfPath)
	if err != nil {
		return fmt.Errorf("error when reading sysctl net IPv4 conf: %w", err)
	}
	params := []string{"rp_filter", "arp_ignore", "arp_announce"}
	var buf bytes.Buffer
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		iface := entry.Name()
		for _, param := range params {
			data, err := os.ReadFile(filepath.Join(sysctlNetIPv4ConfPath, iface, param))
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return fmt.Errorf("error when reading sysctl parameter %s for interface %s: %w", param, iface, err)
			}
			fmt.Fprintf(&buf, "net.ipv4.conf.%s.%s = %s\n", iface, param, strings.TrimSpace(string(data)))
		}
	}
	return writeFile(d.fs, filepath.Join(basedir, "sysctl-net"), "sysctl-net", buf.Bytes())
}

func (d *agentDumper) DumpMemberlist(basedir string) error {
	output, err := d.executor.Command("antctl", "-oyaml", "get", "memberlist").CombinedOutput()
	if err != nil && !strings.Contains(string(output), "memberlist is not enabled") {
		return fmt.Errorf("error when dumping memberlist: %w", err)
	}
	return writeFile(d.fs, filepath.Join(basedir, "memberlist"), "memberlist", output)
}
