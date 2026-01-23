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
	if err := d.dumpNFTables(basedir); err != nil {
		return err
	}
	if err := d.dumpIPSets(basedir); err != nil {
		return err
	}
	if err := d.dumpIPToolInfo(basedir); err != nil {
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
func (d *agentDumper) dumpIPSets(basedir string) error {
	if d.executor == nil {
		return nil
	}
	output, err := d.executor.Command("ipset", "save").CombinedOutput()
	if err != nil {
		klog.ErrorS(err, "Failed to dump ipsets")
		return nil
	}
	if len(output) == 0 {
		return nil
	}
	return writeFile(d.fs, filepath.Join(basedir, "ipsets"), "ipsets", output)
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
	dump := func(name string) error {
		output, err := d.executor.Command("ip", name).CombinedOutput()
		if err != nil {
			return fmt.Errorf("error when dumping %s: %w", name, err)
		}
		return writeFile(d.fs, filepath.Join(basedir, name), name, output)
	}
	for _, item := range []string{"route", "link", "address"} {
		if err := dump(item); err != nil {
			return err
		}
	}
	return nil
}

func (d *agentDumper) DumpMemberlist(basedir string) error {
	output, err := d.executor.Command("antctl", "-oyaml", "get", "memberlist").CombinedOutput()
	if err != nil && !strings.Contains(string(output), "memberlist is not enabled") {
		return fmt.Errorf("error when dumping memberlist: %w", err)
	}
	return writeFile(d.fs, filepath.Join(basedir, "memberlist"), "memberlist", output)
}
