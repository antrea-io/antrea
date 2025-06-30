// Copyright 2025 Antrea Authors
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

package validation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidatePortString(t *testing.T) {
	tests := []struct {
		name        string
		port        string
		expectedErr string
	}{
		{
			name:        "invalid port 0",
			port:        "0",
			expectedErr: "port 0 is out of range, valid range is 1-65535",
		},
		{
			name:        "invalid port 70000",
			port:        "70000",
			expectedErr: "port 70000 is out of range, valid range is 1-65535",
		},
		{
			name:        "valid port",
			port:        "65500",
			expectedErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ValidatePortString(tc.port)
			if tc.expectedErr == "" {
				require.NoError(t, result)
			} else {
				assert.EqualError(t, result, tc.expectedErr)
			}
		})
	}
}
