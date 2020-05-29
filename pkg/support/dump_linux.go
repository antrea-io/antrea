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

// +build linux

package support

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
	"k8s.io/utils/exec"

	"github.com/vmware-tanzu/antrea/pkg/agent/util/iptables"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
)

type agentDumper struct {
	fs           afero.Fs
	executor     exec.Interface
	ovsCtlClient ovsctl.OVSCtlClient
}

func (d *agentDumper) DumpAgentInfo(basedir string) error {
	return dumpAntctlGet(d.fs, d.executor, "agentinfo", basedir)
}

func (d *agentDumper) DumpNetworkPolicyResources(basedir string) error {
	return dumpNetworkPolicyResources(d.fs, d.executor, basedir)
}

func (d *agentDumper) DumpLog(basedir string) error {
	if err := fileCopy(d.fs, path.Join(basedir, "logs", "agent"), "/var/log/antrea", "antrea-agent"); err != nil {
		return err
	}
	return fileCopy(d.fs, path.Join(basedir, "logs", "ovs"), "/var/log/antrea", "ovs")
}

func (d *agentDumper) DumpFlows(basedir string) error {
	flows, err := d.ovsCtlClient.DumpFlows()
	if err != nil {
		return fmt.Errorf("error when dumping flows: %w", err)
	}
	err = afero.WriteFile(d.fs, filepath.Join(basedir, "flows"), []byte(strings.Join(flows, "\n")), 0644)
	if err != nil {
		return fmt.Errorf("error when creating flows output file: %w", err)
	}
	return nil
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
	c, err := iptables.New()
	if err != nil {
		return err
	}
	data, err := c.Save()
	if err != nil {
		return err
	}
	err = afero.WriteFile(d.fs, filepath.Join(basedir, "iptables"), data, 0644)
	if err != nil {
		return fmt.Errorf("error when writing iptables dumps: %w", err)
	}
	return nil
}

func (d *agentDumper) dumpIPToolInfo(basedir string) error {
	dump := func(name string) error {
		output, err := d.executor.Command("ip", name).CombinedOutput()
		if err != nil {
			return fmt.Errorf("error when dumping %s: %w", name, err)
		}
		err = afero.WriteFile(d.fs, filepath.Join(basedir, name), output, 0644)
		if err != nil {
			return fmt.Errorf("error when writing %s: %w", name, err)
		}
		return nil
	}
	for _, item := range []string{"route", "link", "address"} {
		if err := dump(item); err != nil {
			return err
		}
	}
	return nil
}

func NewAgentDumper(fs afero.Fs, executor exec.Interface, client ovsctl.OVSCtlClient) AgentDumper {
	return &agentDumper{
		ovsCtlClient: client,
		fs:           fs,
		executor:     executor,
	}
}
