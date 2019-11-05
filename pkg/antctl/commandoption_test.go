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
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

type FooResponse struct {
	Bar string
}

func TestCommandOptionFormat(t *testing.T) {
	for _, tc := range []struct {
		name           string
		plainText      bool
		singleton      bool
		single         bool
		transform      func(reader io.Reader, single bool) (interface{}, error)
		responseData   interface{}
		responseStruct interface{}
		expected       string
	}{
		{
			name:           "StructureData-NoTransform-List",
			responseData:   []struct{ Foo string }{{Foo: "foo"}},
			responseStruct: &struct{ Foo string }{},
			expected:       "- foo: foo\n",
		},
		{
			name:           "StructureData-NoTransform-Single",
			single:         true,
			responseData:   &struct{ Foo string }{Foo: "foo"},
			responseStruct: &struct{ Foo string }{},
			expected:       "foo: foo\n",
		},
		{
			name:   "StructureData-Transform-Single",
			single: true,
			transform: func(reader io.Reader, single bool) (i interface{}, err error) {
				foo := &struct{ Foo string }{}
				err = json.NewDecoder(reader).Decode(foo)
				return &struct{ Bar string }{Bar: foo.Foo}, err
			},
			responseData:   &struct{ Foo string }{Foo: "foo"},
			responseStruct: &struct{ Bar string }{},
			expected:       "bar: foo\n",
		},
		{
			name:         "PlainText-NonTransform",
			single:       true,
			plainText:    true,
			responseData: "foo",
			expected:     "foo\n",
		},
		{
			name:   "PlainText-Transform",
			single: true,
			transform: func(reader io.Reader, single bool) (i interface{}, err error) {
				foo := &struct{ Foo string }{}
				err = json.NewDecoder(reader).Decode(foo)
				return foo.Foo, err
			},
			responseData: &struct{ Foo string }{Foo: "foo"},
			expected:     "foo\n",
		},
	} {
		testCmd := new(cobra.Command)
		testCmd.Flags().String("output", "yaml", "")
		t.Run(tc.name, func(t *testing.T) {
			opt := &CommandOption{
				Singleton:      tc.singleton,
				PlainText:      tc.plainText,
				ResponseStruct: tc.responseStruct,
				AddonTransform: tc.transform,
			}
			data, err := json.Marshal(tc.responseData)
			assert.Nil(t, err)
			var outputBuf bytes.Buffer
			err = opt.format(testCmd, bytes.NewBuffer(data), &outputBuf, tc.single)
			assert.Nil(t, err)
			assert.Equal(t, tc.expected, outputBuf.String())
		})
	}
}

func TestCommandOptionGenerateExample(t *testing.T) {
	for k, tc := range map[string]struct {
		use       string
		cmdChain  string
		key       *ArgOption
		singleton bool
		expect    string
	}{
		"Singleton": {
			use:       "test",
			cmdChain:  "first second third",
			singleton: true,
			expect:    "  Get the foo\n  $ first second third test\n",
		},
		"NoneKeyList": {
			use:      "test",
			cmdChain: "first second third",
			expect:   "  Get the list of foo\n  $ first second third test\n",
		},
		"KeyList": {
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
	} {
		t.Run(k, func(t *testing.T) {
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
		})
	}
}
