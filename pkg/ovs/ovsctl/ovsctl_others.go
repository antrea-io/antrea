// +build !windows

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
	"os"
	"os/exec"

	"k8s.io/klog/v2"
)

const ovsVSwitchdPIDFile = "/var/run/openvswitch/ovs-vswitchd.pid"

func readOVSVSwitchdPID() (int, error) {
	pidFile, err := os.Open(ovsVSwitchdPIDFile)
	if err != nil {
		return -1, fmt.Errorf("cannot open ovs-vswitchd pidfile '%s': %v", ovsVSwitchdPIDFile, err)
	}
	defer pidFile.Close()
	// probably the simplest way to read a single integer from a file
	var pid int
	if _, err := fmt.Fscanf(pidFile, "%d", &pid); err != nil {
		return -1, fmt.Errorf("cannot read PID from ovs-vswitchd pidfile '%s': %v", ovsVSwitchdPIDFile, err)
	}
	return pid, nil
}

// ovsVSwitchdUDS returns the file path of the ovs-vswitchd control UNIX domain socket.
func ovsVSwitchdUDS() string {
	// It is a bit sub-optimal to read the PID every time we need it, but ovs-vswitchd restarts
	// are possible. Besides, this value is only used when invoking ovs-appctl (as a new
	// process) at the moment, so the overhead of reading the PID from file should not be a
	// concern.
	pid, err := readOVSVSwitchdPID()
	if err != nil {
		klog.ErrorS(err, "Failed to read ovs-vswitchd PID")
		// that seems like a reasonable value to return if we cannot read the PID
		return "/var/run/openvswitch/ovs-vswitchd.*.ctl"
	}
	return fmt.Sprintf("/var/run/openvswitch/ovs-vswitchd.%d.ctl", pid)
}

func getOVSCommand(cmdStr string) *exec.Cmd {
	return exec.Command("/bin/sh", "-c", cmdStr) // lgtm[go/command-injection]
}
