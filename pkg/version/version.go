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

package version

import (
	"fmt"
	"runtime"

	"github.com/blang/semver"
)

// These variables are set at build-time.
var (
	// Must follow the rules in https://semver.org/
	// Does not include git / build information
	Version = ""
	// Empty if git not available
	GitSHA = ""
	// Can be "dirty", "clean" or empty (if git not available)
	GitTreeState = ""
	// Can be "unreleased" or "released"; if it is "unreleased" then we add build information to
	// the version in GetFullVersion
	ReleaseStatus = "unreleased"
)

func GetVersion() semver.Version {
	v, _ := semver.Parse(Version[1:])
	return v
}

func GetGitSHA() string {
	return GitSHA
}

// GetFullVersion returns the version string to be displayed by Antrea binaries. It will look like
// "<major>.<minor>.<patch>" for released versions and "<major>.<minor>.<patch>-<SHA>[.dirty]" for
// unreleased versions.
func GetFullVersion() string {
	if Version == "" {
		return "UNKNOWN"
	}
	if ReleaseStatus == "released" {
		return Version
	}
	// add build information
	if GitSHA == "" {
		return fmt.Sprintf("%s-unknown", Version)
	}
	if GitTreeState == "dirty" {
		return fmt.Sprintf("%s-%s.dirty", Version, GitSHA)
	}
	return fmt.Sprintf("%s-%s", Version, GitSHA)
}

// GetFullVersionWithRuntimeInfo returns the same version string as GetFullVersion but appends
// "<GOOS>/<GOARCH>", where GOOS is the running program's operating system target (e.g. darwin,
// linux) and GOARCH is the the running program's architecture target (e.g. amd64).
func GetFullVersionWithRuntimeInfo() string {
	return fmt.Sprintf("%s %s/%s", GetFullVersion(), runtime.GOOS, runtime.GOARCH)
}
