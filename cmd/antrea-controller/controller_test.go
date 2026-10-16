// Copyright 2026 Antrea Authors
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

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/path"
)

func TestAllowedPathsAuthorizer(t *testing.T) {
	auth, err := path.NewAuthorizer(allowedPaths)
	require.NoError(t, err, "failed to create authorizer with allowedPaths")

	tests := []struct {
		name             string
		path             string
		resourceRequest  bool
		expectedDecision authorizer.Decision
	}{
		{
			name:             "healthz endpoint",
			path:             "/healthz",
			expectedDecision: authorizer.DecisionAllow,
		},
		{
			name:             "livez endpoint",
			path:             "/livez",
			expectedDecision: authorizer.DecisionAllow,
		},
		{
			name:             "readyz endpoint",
			path:             "/readyz",
			expectedDecision: authorizer.DecisionAllow,
		},
		{
			name:             "mutating webhook arbitrary resource",
			path:             "/mutate/customresource",
			expectedDecision: authorizer.DecisionAllow,
		},
		{
			name:             "validating webhook arbitrary resource",
			path:             "/validate/customresource",
			expectedDecision: authorizer.DecisionAllow,
		},
		{
			name:             "crd conversion webhook arbitrary resource",
			path:             "/convert/customresource",
			expectedDecision: authorizer.DecisionAllow,
		},
		{
			name:             "unauthorized root path",
			path:             "/",
			expectedDecision: authorizer.DecisionNoOpinion,
		},
		{
			name:             "unauthorized generic path",
			path:             "/unauthorized",
			expectedDecision: authorizer.DecisionNoOpinion,
		},
		{
			name:             "bare validate path without subpath",
			path:             "/validate",
			expectedDecision: authorizer.DecisionNoOpinion,
		},
		{
			name:             "bare mutate path without subpath",
			path:             "/mutate",
			expectedDecision: authorizer.DecisionNoOpinion,
		},
		{
			name:             "bare convert path without subpath",
			path:             "/convert",
			expectedDecision: authorizer.DecisionNoOpinion,
		},
		{
			name:             "path with prefix elsewhere in url",
			path:             "/other/validate/resource",
			expectedDecision: authorizer.DecisionNoOpinion,
		},
		{
			name:             "control plane resource request with allowed path",
			path:             "/validate/customresource",
			resourceRequest:  true,
			expectedDecision: authorizer.DecisionNoOpinion,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs := authorizer.AttributesRecord{
				Path:            tc.path,
				ResourceRequest: tc.resourceRequest,
			}
			decision, reason, err := auth.Authorize(context.Background(), attrs)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedDecision, decision, "unexpected authorization decision, reason: %s", reason)
		})
	}
}
