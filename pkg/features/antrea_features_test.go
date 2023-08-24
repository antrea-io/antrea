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

package features

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/component-base/featuregate"
)

func TestSupportedOnWindows(t *testing.T) {
	tcs := []struct {
		name     string
		feature  featuregate.Feature
		expected bool
	}{
		{
			name:     "Feature supported on Windows Node",
			feature:  AntreaPolicy,
			expected: true,
		},
		{
			name:     "Feature unsupported on Windows Node",
			feature:  Egress,
			expected: false,
		},
		{
			name:     "Feature does not exist",
			feature:  "Unsupported",
			expected: false,
		},
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			actual := SupportedOnWindows(tt.feature)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestSupportedOnExternalNode(t *testing.T) {
	tcs := []struct {
		name     string
		feature  featuregate.Feature
		expected bool
	}{
		{
			name:     "Feature supported on External Node",
			feature:  ExternalNode,
			expected: true,
		},
		{
			name:     "Feature unsupported on External Node",
			feature:  NodePortLocal,
			expected: false,
		},
		{
			name:     "Feature does not exist",
			feature:  "Unsupported",
			expected: false,
		},
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			actual := SupportedOnExternalNode(tt.feature)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestDefaultAntreaFeatureGates(t *testing.T) {
	for df := range DefaultAntreaFeatureGates {
		if !AgentGates.Has(df) && !ControllerGates.Has(df) {
			t.Errorf("Feature gate %s is not present in AgentGates and ControllerGates", df)
		}
	}
}
