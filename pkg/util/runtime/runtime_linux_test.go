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
	"fmt"
	"testing"

	"github.com/blang/semver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKernelVersion(t *testing.T) {
	testcases := []struct {
		// input
		kernelString string
		// expectations
		expectedKernelVersion semver.Version
		expectedError         error
	}{
		{
			kernelString:          "4.10",
			expectedKernelVersion: semver.MustParse("4.10.0"),
			expectedError:         nil,
		},
		{
			kernelString:          "4.10.3",
			expectedKernelVersion: semver.MustParse("4.10.3"),
			expectedError:         nil,
		},
		{
			kernelString:          "4.12.17-040917-generic",
			expectedKernelVersion: semver.MustParse("4.12.17-040917-generic"),
			expectedError:         nil,
		},
		{
			kernelString:          "4.13.18-300.el7.x86_64",
			expectedKernelVersion: semver.MustParse("4.13.18-300"),
			expectedError:         nil,
		},
		{
			kernelString:          "5",
			expectedKernelVersion: semver.Version{},
			expectedError:         fmt.Errorf("unable to get kernel version from \"5\""),
		},
	}
	for _, tc := range testcases {
		parsedKernelVersion, err := parseKernelVersionStr(tc.kernelString)
		if tc.expectedError != nil {
			assert.Equal(t, tc.expectedError, err)
		} else {
			require.Nil(t, err)
			assert.Equal(t, tc.expectedKernelVersion, parsedKernelVersion)
		}

	}
}
