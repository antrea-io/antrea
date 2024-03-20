//go:build !windows
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
	"context"
	"fmt"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
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
func ovsVSwitchdUDS(ctx context.Context) (string, error) {
	// It is a bit sub-optimal to read the PID every time we need it, but ovs-vswitchd restarts
	// are possible. Besides, this value is only used when invoking ovs-appctl (as a new
	// process) at the moment, so the overhead of reading the PID from file should not be a
	// concern.
	var pid int
	var readErr error
	startTime := time.Now()
	hasFailure := false
	err := wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		pid, readErr = readOVSVSwitchdPID()
		if readErr != nil {
			hasFailure = true
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to read ovs-vswitchd PID: %w", readErr)
	}
	if hasFailure {
		klog.V(2).InfoS("Waited for ovs-vswitchd PID to be ready", "duration", time.Since(startTime))
	}
	return fmt.Sprintf("/var/run/openvswitch/ovs-vswitchd.%d.ctl", pid), nil
}
