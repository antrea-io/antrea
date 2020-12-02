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

// +build !windows

package support

import (
	"flag"
	"fmt"
	"path"
	"path/filepath"

	"github.com/vmware-tanzu/antrea/pkg/agent/util/iptables"
)

func (d *agentDumper) DumpLog(basedir string) error {
	logDirFlag := flag.CommandLine.Lookup("log_dir")
	var logDir string
	if logDirFlag == nil {
		logDir = antreaLinuxWellKnownLogDir
	} else if len(logDirFlag.Value.String()) == 0 {
		logDir = logDirFlag.DefValue
	} else {
		logDir = logDirFlag.Value.String()
	}
	if err := fileCopy(d.fs, path.Join(basedir, "logs", "agent"), logDir, "antrea-agent"); err != nil {
		return err
	}
	return fileCopy(d.fs, path.Join(basedir, "logs", "ovs"), logDir, "ovs")
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
	c, err := iptables.New(nodeConfig.PodIPv4CIDR != nil, nodeConfig.PodIPv6CIDR != nil)
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
