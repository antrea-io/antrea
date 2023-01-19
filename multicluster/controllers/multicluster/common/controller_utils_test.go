/*
Copyright 2022 Antrea Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package common

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestDiscoverServiceCIDRByInvalidServiceCreation(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(TestScheme).Build()
	_, err := DiscoverServiceCIDRByInvalidServiceCreation(context.Background(), fakeClient, "default")
	if err != nil {
		assert.Contains(t, err.Error(), "expected a specific error but none was returned")
	}
}

func TestParseServiceCIDRFromError(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedCIDR  string
		expectedError string
	}{
		{
			name:         "parse successfully with correct error message",
			input:        "The Service \"invalid-svc\" is invalid: spec.clusterIPs: Invalid value: []string{\"0.0.0.0\"}: failed to allocate IP 0.0.0.0: provided IP is not in the valid range. The range of valid IPs is 10.19.0.0/18",
			expectedCIDR: "10.19.0.0/18",
		},
		{
			name:  "failed to parse with incorrect error message",
			input: "The range of valid IPs are 10.19.0.0/18",
			expectedError: "could not determine the ClusterIP range via Service creation - the expected error " +
				"was not returned. The actual error was",
		},
	}

	for _, tt := range tests {
		cidr, err := parseServiceCIDRFromError(tt.input)
		if err != nil {
			assert.Contains(t, err.Error(), tt.expectedError)
		}
		assert.Equal(t, cidr, tt.expectedCIDR)
	}
}
