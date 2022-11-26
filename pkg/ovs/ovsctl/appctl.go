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

type ovsAppctlRunner struct {
	bridge string
}

func (r *ovsAppctlRunner) RunAppctlCmd(cmd string, needsBridge bool, args ...string) ([]byte, *ExecError) {
	// Use the control UNIX domain socket to connect to ovs-vswitchd, as Agent can
	// run in a different PID namespace from ovs-vswitchd. Relying on ovs-appctl to
	// determine the control socket based on the pidfile will then give a "stale
	// pidfile" error, as it tries to validate that the PID read from the pidfile
	// corresponds to a valid process in the current PID namespace.
	var cmdStr string
	if needsBridge {
		cmdStr = fmt.Sprintf("ovs-appctl -t %s %s %s", ovsVSwitchdUDS(), cmd, r.bridge)
	} else {
		cmdStr = fmt.Sprintf("ovs-appctl -t %s %s", ovsVSwitchdUDS(), cmd)
	}
	cmdStr = cmdStr + " " + strings.Join(args, " ")
	out, err := getOVSCommand(cmdStr).CombinedOutput()
	if err != nil {
		return nil, newExecError(err, string(out))
	}
	return out, nil
}
