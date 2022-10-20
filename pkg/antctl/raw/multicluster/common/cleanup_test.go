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

package common

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestValidation(t *testing.T) {
	tests := []struct {
		name           string
		expectedOutput string
		opts           *CleanOptions
	}{
		{
			name:           "empty ClusterSet",
			expectedOutput: "ClusterSet must be provided",
			opts:           &CleanOptions{},
		},
		{
			name:           "empty Namespace",
			expectedOutput: "Namespace must be specified",
			opts:           &CleanOptions{ClusterSet: "test"},
		},
	}

	cmd := &cobra.Command{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.validate(cmd)
			if err != nil {
				assert.Equal(t, tt.expectedOutput, err.Error())
			} else {
				t.Error("Expected to get error but got nil")
			}
		})
	}
}
