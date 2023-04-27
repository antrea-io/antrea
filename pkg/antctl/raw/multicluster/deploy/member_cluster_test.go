// Copyright 2023 Antrea Authors
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

package deploy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMemberValidateAndComplete(t *testing.T) {
	tests := []struct {
		name            string
		namespace       string
		version         string
		expectedVersion string
		expectedErr     string
	}{
		{
			name:        "empty Namesapace",
			expectedErr: "Namespace must be specified",
		},
		{
			name:            "set version",
			namespace:       "default",
			version:         "1.10",
			expectedVersion: "1.10",
		},
		{
			name:            "not set version",
			namespace:       "default",
			expectedVersion: "latest",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &leaderClusterOptions{
				namespace:     tt.namespace,
				antreaVersion: tt.version,
			}
			gotErr := opts.validateAndComplete()
			if gotErr != nil {
				assert.Equal(t, tt.expectedErr, gotErr.Error())
			} else {
				assert.Equal(t, tt.expectedVersion, opts.antreaVersion)
			}
		})
	}
}

func TestNewMemberClusterCmd(t *testing.T) {
	cmd := NewMemberClusterCmd()
	assert.Equal(t, cmd.Use, "membercluster")
	assert.NotNil(t, cmd.Flags().Lookup("namespace"))
	assert.NotNil(t, cmd.Flags().Lookup("antrea-version"))
	assert.NotNil(t, cmd.Flags().Lookup("manifest-file"))
}
