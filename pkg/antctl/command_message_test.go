// Copyright 2020 Antrea Authors
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

package antctl

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/errors"

	"antrea.io/antrea/pkg/apis/controlplane"
)

func TestGenerateMessage(t *testing.T) {
	for _, tc := range []struct {
		name            string
		cd              *commandDefinition
		args            map[string]string
		resourceRequest bool
		requestErr      error
		expected        string
	}{
		{
			name:            "no error",
			cd:              &commandDefinition{},
			args:            map[string]string{},
			resourceRequest: true,
			requestErr:      nil,
			expected:        "",
		},
		{
			name: "not found error",
			cd: &commandDefinition{
				use: "addressgroup",
			},
			args: map[string]string{
				"name": "ag",
			},
			resourceRequest: true,
			requestErr:      errors.NewNotFound(controlplane.Resource("addressgroup"), "ag"),
			expected:        "addressgroup.controlplane.antrea.io \"ag\" not found",
		},
		{
			name: "internal error",
			cd: &commandDefinition{
				use: "addressgroup",
			},
			args: map[string]string{
				"name": "ag",
			},
			resourceRequest: true,
			requestErr:      errors.NewInternalError(fmt.Errorf("failed to marshal")),
			expected:        "Internal error occurred: failed to marshal",
		},
		{
			name: "bad request error",
			cd: &commandDefinition{
				use: "addressgroup",
			},
			args:            map[string]string{},
			resourceRequest: true,
			requestErr:      errors.NewBadRequest("missing name arg"),
			expected:        "missing name arg",
		},
		{
			name: "generic bad request error",
			cd: &commandDefinition{
				use: "addressgroup",
			},
			args:            map[string]string{},
			resourceRequest: false,
			// This mimics how the rest client builds errors for "raw" requests:
			// https://github.com/kubernetes/client-go/blob/9081272f7fb25cc1a05429611675f82ce03ebce0/rest/request.go#L1264
			requestErr: errors.NewGenericServerResponse(http.StatusBadRequest, "get", controlplane.Resource("addressgroup"), "", "missing name arg", 0, true),
			expected:   "Bad Request: missing name arg",
		},
		{
			name: "generic forbidden error",
			cd: &commandDefinition{
				use: "addressgroup",
			},
			args: map[string]string{
				"name": "ag",
			},
			resourceRequest: false,
			requestErr:      errors.NewGenericServerResponse(http.StatusForbidden, "get", controlplane.Resource("addressgroup"), "ag", "bad credentials", 0, true),
			expected:        "Forbidden: bad credentials",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := generateMessage(tc.cd, tc.args, tc.resourceRequest, tc.requestErr)
			if tc.expected == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.expected)
			}
		})
	}
}
