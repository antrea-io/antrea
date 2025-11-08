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
	"fmt"
	"net"
	"path"
	"path/filepath"
	"strings"

	"antrea.io/antrea/pkg/agent/util/iptables"
	"antrea.io/antrea/pkg/agent/util/sysctl"
	"antrea.io/antrea/pkg/util/logdir"
)

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
	if err := d.dumpIPToolInfo(basedir); err != nil {
		return err
	}
	if err := d.dumpInterfaceConfigs(basedir); err != nil {
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

func (d *agentDumper) dumpIPToolInfo(basedir string) error {
	dump := func(args ...string) error {
		output, err := d.executor.Command("ip", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("error when dumping %s: %w", strings.Join(args, " "), err)
		}
		return writeFile(d.fs, filepath.Join(basedir, args[0]), args[0], output)
	}
	commands := [][]string{
		{"link"},
		{"address"},
		{"rule", "show"},
		{"route", "show", "table", "all"},
	}
	for _, cmd := range commands {
		if err := dump(cmd...); err != nil {
			return err
		}
	}
	return nil
}

func (d *agentDumper) dumpInterfaceConfigs(basedir string) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("error getting network interfaces: %w", err)
	}
	hostGateway := d.aq.GetNodeConfig().GatewayConfig.Name
	var relevantIfaces []net.Interface
	for _, iface := range interfaces {
		if iface.Name == hostGateway ||
			iface.Name == "antrea-egress0" ||
			iface.Name == "antrea-ingress0" ||
			strings.HasPrefix(iface.Name, "antrea-ext.") {
			relevantIfaces = append(relevantIfaces, iface)
		}
	}
	params := []string{"rp_filter", "arp_ignore", "arp_announce"}
	var output strings.Builder
	for _, iface := range relevantIfaces {
		output.WriteString(fmt.Sprintf("%s\n", iface.Name))
		for _, param := range params {
			value, err := sysctl.GetSysctlNet(fmt.Sprintf("ipv4/conf/%s/%s", iface.Name, param))
			if err != nil {
				continue
			}
			output.WriteString(fmt.Sprintf("%s=%d\n", param, value))
		}
		output.WriteString("\n")
	}
	return writeFile(d.fs, filepath.Join(basedir, "interface-config"), "interface-config", []byte(output.String()))
}

func (d *agentDumper) DumpMemberlist(basedir string) error {
	output, err := d.executor.Command("antctl", "-oyaml", "get", "memberlist").CombinedOutput()
	if err != nil && !strings.Contains(string(output), "memberlist is not enabled") {
		return fmt.Errorf("error when dumping memberlist: %w", err)
	}
	return writeFile(d.fs, filepath.Join(basedir, "memberlist"), "memberlist", output)
}
