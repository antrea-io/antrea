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

package support

import (
	"fmt"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"k8s.io/utils/exec"
)

func TestDumpLog(t *testing.T) {

	fs := afero.NewOsFs()
	basedir := "dir1/dir2"
	since := "6s"

	varr := NewAgentDumper(fs, nil, nil, nil, nil, since, true, true)
	err := varr.DumpLog(basedir)
	fmt.Printf("error in testdumplog %v", err)
	fmt.Println()
	assert.NoError(t, err)

}
func TestDumpHostNetworkInfo(t *testing.T) {

	tcs := []struct {
		name        string
		v4Enabled   bool
		v6Enabled   bool
		basedir     string
		since       string
		expectedErr string
	}{
		{
			name:      "v4 and v6 both are enabled",
			v4Enabled: true,
			v6Enabled: true,
			basedir:   "dir1/dir2",
			since:     "5s",
		},
		{
			name:      "v4 and v6 both are disabled",
			v4Enabled: false,
			v6Enabled: false,
			basedir:   "dir1/dir2",
			since:     "8s",
		},
		{
			name:      "v4 is enabled, v6 is diabled",
			v4Enabled: true,
			v6Enabled: false,
			basedir:   "dir1/dir2",
			since:     "2s",
		},
		{
			name:      "v4  is disabled, v6 is enabled",
			v4Enabled: false,
			v6Enabled: true,
			basedir:   "dir1/dir2",
			since:     "3s",
		},
	}

	fs := afero.NewOsFs()
	exe := exec.New()
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			varr := NewAgentDumper(fs, exe, nil, nil, nil, tc.since, tc.v4Enabled, tc.v6Enabled)
			err := varr.DumpHostNetworkInfo(tc.basedir)
			if tc.expectedErr != "" {
				assert.Contains(t, err.Error(), tc.expectedErr)
			} else {
				assert.NoError(t, err)
			}

		})
	}

}
