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
	"strings"

	"golang.org/x/mod/semver"
	"golang.org/x/sys/unix"
)

func parseKernelVersionStr(kernelVersionStr string) (string, error) {
	// "5.4.0-72-generic" is parsed successfully to "v5.4.0-72-generic".
	// "4.13.18-300.el7.x86_64" is reduced to its first three dot-separated
	// components ("4.13.18-300") before being returned as "v4.13.18-300".
	verStrs := strings.Split(kernelVersionStr, ".")
	if len(verStrs) < 2 {
		return "", fmt.Errorf("unable to get kernel version from %q", kernelVersionStr)
	}
	if len(verStrs) > 3 {
		verStrs = verStrs[:3]
	}
	v := semver.Canonical("v" + strings.Join(verStrs, "."))
	if v == "" {
		return "", fmt.Errorf("unable to parse kernel version from %q", kernelVersionStr)
	}
	return v, nil
}

// GetKernelVersion returns the Linux kernel version for the current host as a
// canonical semver string (e.g. "v5.4.0").
func GetKernelVersion() (string, error) {
	var unameBuf unix.Utsname
	if err := unix.Uname(&unameBuf); err != nil {
		return "", err
	}
	// unameBuf.Release is a fixed-size 65-byte array, we need to remove the trailing null
	// characters from it first.
	kernelVersionStr := string(bytes.TrimRight(unameBuf.Release[:], "\x00"))
	v, err := parseKernelVersionStr(kernelVersionStr)
	if err != nil {
		return "", fmt.Errorf("error when parsing Linux kernel version string: %v", err)
	}
	return v, nil
}
