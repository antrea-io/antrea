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
	"fmt"
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
	if err := d.dumpSysctlInfo(basedir); err != nil {
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
	dump := func(name string, args ...string) error {
		path := name
		if len(args) > 0 {
			path = strings.Join(append([]string{name}, args...), "_")
			// "show" and "table" are common words in ip command output, removing them to shorten the file name.
			path = strings.ReplaceAll(path, "show_", "")
			path = strings.ReplaceAll(path, "table_", "")
			path = strings.ReplaceAll(path, " ", "_")
		}
		cmdArgs := append([]string{name}, args...)
		output, err := d.executor.Command("ip", cmdArgs...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("error when dumping %s: %w", name, err)
		}
		return writeFile(d.fs, filepath.Join(basedir, path), path, output)
	}
	// "ip route show table all" gets all the routes in all the tables.
	if err := dump("route", "show", "table", "all"); err != nil {
		return err
	}
	for _, item := range []string{"link", "address", "rule"} {
		if err := dump(item); err != nil {
			return err
		}
	}
	return nil
}

func (d *agentDumper) dumpSysctlInfo(basedir string) error {
	// Dump the critical interface configurations.
	// Because sysctl does not support glob patterns in 1.25+ consistently across distros or without -r,
	// and to ensure we capture exactly what is needed without noise, we use strict patterns if possible.
	// However, sysctl -a is standard. We will use a simple command to dump everything matching the pattern.
	// Using "sysctl -a" and filtering might be heavy but "sysctl net.ipv4.conf" prints all of them.
	// Let's rely on `sysctl -a` with `grep` if possible, but `d.executor` doesn't support shell pipes directly easily.
	// Instead, we will list the specific keys we want: all interfaces.
	// Actually, `sysctl net.ipv4.conf` works to list everything under that hierarchy on most modern systems.
	cmd := d.executor.Command("sysctl", "net.ipv4.conf")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback for systems where top-level key list might fail or strict strictness:
		// Try `sysctl -a -r "net.ipv4.conf"`.
		cmd = d.executor.Command("sysctl", "-a", "-r", "net.ipv4.conf")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("error when dumping sysctl net.ipv4.conf: %w", err)
		}
	}
	return writeFile(d.fs, filepath.Join(basedir, "sysctl_net_ipv4_conf"), "sysctl_net_ipv4_conf", output)
}

func (d *agentDumper) DumpMemberlist(basedir string) error {
	output, err := d.executor.Command("antctl", "-oyaml", "get", "memberlist").CombinedOutput()
	if err != nil && !strings.Contains(string(output), "memberlist is not enabled") {
		return fmt.Errorf("error when dumping memberlist: %w", err)
	}
	return writeFile(d.fs, filepath.Join(basedir, "memberlist"), "memberlist", output)
}
