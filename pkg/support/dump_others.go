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
	"path"
	"path/filepath"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/util/iptables"
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
	return nil
}

func (d *agentDumper) dumpIPTables(basedir string) error {
	nodeConfig := d.aq.GetNodeConfig()
	networkConfig := d.aq.GetNetworkConfig()
	v4Enabled := config.IsIPv4Enabled(nodeConfig, networkConfig.TrafficEncapMode)
	v6Enabled := config.IsIPv6Enabled(nodeConfig, networkConfig.TrafficEncapMode)
	c, err := iptables.New(v4Enabled, v6Enabled)
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
