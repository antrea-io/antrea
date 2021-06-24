// Copyright 2021 Antrea Authors
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

package runtime

import (
	"bytes"
	"fmt"

	"github.com/blang/semver"
	"golang.org/x/sys/unix"
)

func parseKernelVersionStr(kernelVersionStr string) (semver.Version, error) {
	// "5.4.0-72-generic" is parsed successfully to:
	// Major: 5
	// Minor: 4
	// Patch: 0
	// Pre: [72-generic]
	// Build: []
	return semver.Parse(kernelVersionStr)
}

// GetKernelVersion returns the Linux kernel version for the current host.
func GetKernelVersion() (semver.Version, error) {
	var unameBuf unix.Utsname
	if err := unix.Uname(&unameBuf); err != nil {
		return semver.Version{}, err
	}
	// unameBuf.Release is a fixed-size 65-byte array, we need to remove the trailing null
	// characters from it first.
	kernelVersionStr := string(bytes.TrimRight(unameBuf.Release[:], "\x00"))
	v, err := parseKernelVersionStr(kernelVersionStr)
	if err != nil {
		return semver.Version{}, fmt.Errorf("error when parsing Linux kernel version string: %v", err)
	}
	return v, nil
}
