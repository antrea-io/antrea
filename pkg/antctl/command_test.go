// Copyright 2019 Antrea Authors
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
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

type FooResponse struct {
	Bar string
}

func TestGenerateExample(t *testing.T) {
	testcases := map[string]struct {
		use       string
		cmdChain  string
		key       *ArgOption
		singleton bool
		expect    string
	}{
		"singleton": {
			use:       "test",
			cmdChain:  "first second third",
			singleton: true,
			expect:    "  Get the foo\n  $ first second third test\n",
		},
		"non-key list": {
			use:      "test",
			cmdChain: "first second third",
			expect:   "  Get the list of foo\n  $ first second third test\n",
		},
		"key list": {
			use:      "test",
			cmdChain: "first second third",
			key: &ArgOption{
				Name:      "bar",
				FieldName: "Bar",
				Usage:     "",
				Key:       true,
			},
			expect: "  Get a foo\n  $ first second third test [bar]\n  Get the list of foo\n  $ first second third test\n",
		},
	}

	for _, tc := range testcases {
		cmd := new(cobra.Command)
		for _, seg := range strings.Split(tc.cmdChain, " ") {
			cmd.Use = seg
			tmp := new(cobra.Command)
			cmd.AddCommand(tmp)
			cmd = tmp
		}
		cmd.Use = tc.use

		co := &CommandOption{Singleton: tc.singleton, ResponseStruct: new(FooResponse)}
		assert.Equal(t, tc.expect, co.GenerateExample(cmd, tc.key))
	}
}
