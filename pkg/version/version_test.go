// Copyright 2022 Antrea Authors
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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetFullVersion(t *testing.T) {
	testCases := []struct {
		name            string
		Version         string
		ReleaseStatus   string
		GitSHA          string
		GitTreeState    string
		expectedVersion string
	}{
		{
			name:            "Unknown version",
			expectedVersion: "UNKNOWN",
		},
		{
			name:            "Released version",
			Version:         "1.9",
			ReleaseStatus:   "released",
			expectedVersion: "1.9",
		},
		{
			name:            "Unreleased version",
			Version:         "1.10",
			ReleaseStatus:   "unreleased",
			expectedVersion: "1.10-unknown",
		},
		{
			name:            "Unreleased version with GitTreeState dirty",
			Version:         "1.10",
			ReleaseStatus:   "unreleased",
			GitSHA:          "abc",
			GitTreeState:    "dirty",
			expectedVersion: "1.10-abc.dirty",
		},
		{
			name:            "Unreleased version with GitTreeState empty",
			Version:         "1.10",
			ReleaseStatus:   "unreleased",
			GitSHA:          "abc",
			GitTreeState:    "",
			expectedVersion: "1.10-abc",
		},
		{
			name:            "Unreleased version with GitTreeState clean",
			Version:         "1.10",
			ReleaseStatus:   "unreleased",
			GitSHA:          "abc",
			GitTreeState:    "clean",
			expectedVersion: "1.10-abc",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			Version = tc.Version
			ReleaseStatus = tc.ReleaseStatus
			GitSHA = tc.GitSHA
			GitTreeState = tc.GitTreeState
			gotVersion := GetFullVersion()
			Version = ""
			ReleaseStatus = ""
			GitSHA = ""
			GitTreeState = "unreleased"
			assert.Equal(t, tc.expectedVersion, gotVersion)
		})
	}
}

func TestGetFullVersionWithRuntimeInfo(t *testing.T) {
	gotVersion := GetFullVersionWithRuntimeInfo()
	assert.Equal(t, fmt.Sprintf("UNKNOWN %s/%s %s", runtime.GOOS, runtime.GOARCH, runtime.Version()), gotVersion)
}
