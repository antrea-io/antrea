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
	"fmt"
	"strings"
)

type ovsOfctlRunner struct {
	bridge string
}

func (r *ovsOfctlRunner) RunOfctlCmd(cmd string, args ...string) ([]byte, error) {
	return runOfctlCmd(true, cmd, r.bridge, args...)
}

func runOfctlCmd(openflow15 bool, cmd string, bridge string, args ...string) ([]byte, error) {
	cmdStr := fmt.Sprintf("ovs-ofctl %s %s", cmd, bridge)
	cmdStr = cmdStr + " " + strings.Join(args, " ")
	if openflow15 {
		cmdStr += " -O Openflow15"
	}
	out, err := getOVSCommand(cmdStr).Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}
