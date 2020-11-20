// Copyright 2019 Antrea Authors
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

package util

import (
	"golang.org/x/sys/unix"
	"k8s.io/klog"
)

// IsPortAvailable checks if a port is free or being used by any other process.
func IsPortAvailable(mPort int) bool {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		klog.Warningf("unix socket creation failed with error: %v", err)
		return false
	}
	defer unix.Close(fd)

	err = unix.Bind(fd, &unix.SockaddrInet4{
		Port: mPort,
		Addr: [4]byte{0, 0, 0, 0},
	})

	if err != nil {
		return false
	}

	return true
}
