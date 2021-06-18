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
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerate(t *testing.T) {
	for _, tc := range []struct {
		cd       *commandDefinition
		args     map[string]string
		code     int
		expected string
	}{
		{
			cd: &commandDefinition{
				use: "foo",
			},
			args: map[string]string{
				"name": "bar",
			},
			code:     http.StatusNotFound,
			expected: "NotFound: foo \"bar\" not found",
		},
		{
			cd: &commandDefinition{
				use: "foo",
			},
			args:     map[string]string{},
			code:     http.StatusInternalServerError,
			expected: "InternalServerError: Encoding response failed for foo",
		},
		{
			cd:       &commandDefinition{},
			args:     map[string]string{},
			code:     http.StatusOK,
			expected: "Unknown error",
		},
		{
			cd: &commandDefinition{
				use: "foo",
			},
			args: map[string]string{
				"name": "bar",
			},
			code:     http.StatusBadRequest,
			expected: `BadRequest: Please check the args for foo`,
		},
	} {
		generated := generate(tc.cd, tc.args, tc.code, "")
		assert.Equal(t, tc.expected, generated.Error())
	}
}
