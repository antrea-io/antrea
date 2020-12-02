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

package iptables

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	XtablesLockFilePath       = "/var/run/xtables.lock"
	xtablesLockFilePermission = 0600
)

// Lock acquires the provided file lock. It's thread-safe.
// It will block until the lock is acquired or the timeout is reached.
func Lock(lockFilePath string, timeout time.Duration) (func() error, error) {
	lockFile, err := os.OpenFile(lockFilePath, os.O_CREATE, xtablesLockFilePermission)
	if err != nil {
		return nil, fmt.Errorf("error opening xtables lock file: %v", err)
	}

	// Check whether the lock is available every 200ms.
	if err := wait.PollImmediate(waitIntervalMicroSeconds*time.Microsecond, timeout, func() (bool, error) {
		if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return false, nil
		}
		return true, nil
	}); err != nil {
		lockFile.Close()
		return nil, fmt.Errorf("error acquiring xtables lock: %v", err)
	}
	return lockFile.Close, nil
}
