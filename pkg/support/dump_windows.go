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

// +build windows

package support

import (
	"flag"
	"fmt"
	"path"
	"path/filepath"
)

const (
	antreaWindowsWellKnownLogDir = `C:\k\antrea\logs`
	antreaWindowsOVSLogDir       = `C:\openvswitch\var\log\openvswitch`
	antreaWindowsKubeletLogDir   = `C:\var\log\kubelet`
)

// Todo: Logs for OVS and kubelet are collected from the fixed path currently, more enhancements are needed to support
// collecting them from a configurable path in the future.
func (d *agentDumper) DumpLog(basedir string) error {
	logDirFlag := flag.CommandLine.Lookup("log_dir")
	var logDir string
	if logDirFlag == nil {
		logDir = antreaWindowsWellKnownLogDir
	} else if len(logDirFlag.Value.String()) == 0 {
		logDir = logDirFlag.DefValue
	} else {
		logDir = logDirFlag.Value.String()
	}
	if err := fileCopy(d.fs, path.Join(basedir, "logs", "agent"), logDir, "rancher-wins-antrea-agent"); err != nil {
		return err
	}
	// Dump OVS logs.
	if err := fileCopy(d.fs, path.Join(basedir, "logs", "ovs"), antreaWindowsOVSLogDir, "ovs"); err != nil {
		return err
	}
	// Dump kubelet logs.
	if err := fileCopy(d.fs, path.Join(basedir, "logs", "kubelet"), antreaWindowsKubeletLogDir, "kubelet"); err != nil {
		return err
	}
	return nil
}

func (d *agentDumper) DumpHostNetworkInfo(basedir string) error {
	if err := d.dumpNetworkConfig(basedir); err != nil {
		return err
	}
	if err := d.dumpHNSResources(basedir); err != nil {
		return err
	}
	return nil
}

func (d *agentDumper) dumpNetworkConfig(basedir string) error {
	type netResource struct {
		name      string
		psCommand string
	}
	netFunc := func(nr *netResource) error {
		output, err := d.executor.Command("powershell.exe", nr.psCommand).CombinedOutput()
		if err != nil {
			return fmt.Errorf("error when dumping %s: %w", nr.name, err)
		}
		return writeFile(d.fs, filepath.Join(basedir, nr.name), nr.name, output)
	}

	for _, nr := range []*netResource{
		{name: "network-adapters", psCommand: "Get-NetAdapter"},
		{name: "ipconfig", psCommand: "ipconfig /all"},
		{name: "routes", psCommand: "route print"},
	} {
		if err := netFunc(nr); err != nil {
			return err
		}
	}
	return nil
}

func (d *agentDumper) dumpHNSResources(basedir string) error {
	hnsDumper := func(hnsResource string) error {
		output, err := d.executor.Command("powershell.exe", fmt.Sprintf("Get-%s", hnsResource)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("error when dumping %s: %w", hnsResource, err)
		}
		return writeFile(d.fs, filepath.Join(basedir, hnsResource), hnsResource, output)
	}

	for _, res := range []string{"HNSNetwork", "HNSEndpoint"} {
		if err := hnsDumper(res); err != nil {
			return err
		}
	}
	return nil
}
