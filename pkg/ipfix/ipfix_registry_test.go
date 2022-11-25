// Copyright 2023 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipfix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetInfoElement(t *testing.T) {
	tc := []struct {
		testname          string
		name              string
		enterpriseID      uint32
		expectedElementID uint16
		expectedError     string
	}{
		{
			testname:      "Invalid enterpriseID",
			name:          "sourcePodNamespace",
			enterpriseID:  1,
			expectedError: "Registry with EnterpriseID 1 is not supported.",
		},
		{
			testname:          "Information element with given enterpriseID and name exists in registry",
			name:              "sourcePodNamespace",
			enterpriseID:      56506,
			expectedElementID: 100,
			expectedError:     "",
		},
		{
			testname:      "Information element with given name does not exist in registry",
			name:          "sourcePod",
			enterpriseID:  0,
			expectedError: "Information element with name sourcePod in registry with enterpriseID 0 cannot be found.",
		},
	}
	for _, tt := range tc {
		t.Run(tt.testname, func(t *testing.T) {
			reg := NewIPFIXRegistry()
			reg.LoadRegistry()
			element, err := reg.GetInfoElement(tt.name, tt.enterpriseID)
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedElementID, element.ElementId)
			}
		})
	}
}
