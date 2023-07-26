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

package ovsctl

import (
	"context"
	"os/exec"
)

type ovsOfctlRunner struct {
	bridge string
}

func (r *ovsOfctlRunner) RunOfctlCmd(cmd string, args ...string) ([]byte, error) {
	return runOfctlCmd(context.TODO(), true, cmd, r.bridge, args...)
}

func runOfctlCmd(ctx context.Context, openflow15 bool, cmd string, bridge string, args ...string) ([]byte, error) {
	cmdArgs := append([]string{cmd, bridge}, args...)
	if openflow15 {
		cmdArgs = append(cmdArgs, "-O", "Openflow15")
	}
	ovsCmd := exec.CommandContext(ctx, "ovs-ofctl", cmdArgs...)
	return ovsCmd.Output()
}
