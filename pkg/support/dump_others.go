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

// +build !linux

package support

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
	"k8s.io/utils/exec"

	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
)

// TODO: Implement it when antrea on windows is ready and antctl installation .
type agentDumper struct {
	fs           afero.Fs
	executor     exec.Interface
	ovsCtlClient ovsctl.OVSCtlClient
}

func (d *agentDumper) DumpAgentInfo(basedir string) error {
	return nil
}

func (d *agentDumper) DumpNetworkPolicyResources(basedir string) error {
	return nil
}

func (d *agentDumper) DumpLog(basedir string) error {
	return nil
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
	return nil
}

func NewAgentDumper(fs afero.Fs, executor exec.Interface, ovsCtlClient ovsctl.OVSCtlClient) AgentDumper {
	return &agentDumper{
		fs:           fs,
		executor:     executor,
		ovsCtlClient: ovsCtlClient,
	}
}
