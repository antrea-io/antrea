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
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

type FooResponse struct {
	Bar string
}

// TestFormat ensures the formatter and AddonTransform works as expected.
func TestFormat(t *testing.T) {
	// TODO: Add table formatter tests after implementing table formatter
	for _, tc := range []struct {
		name            string
		singleton       bool
		single          bool
		transform       func(reader io.Reader, single bool) (interface{}, error)
		rawResponseData interface{}
		responseStruct  reflect.Type
		expected        string
		formatter       formatterType
	}{
		{
			name:            "StructureData-NoTransform-List",
			rawResponseData: []struct{ Foo string }{{Foo: "foo"}},
			responseStruct:  reflect.TypeOf(struct{ Foo string }{}),
			expected:        "- foo: foo\n",
			formatter:       yamlFormatter,
		},
		{
			name:            "StructureData-NoTransform-Single",
			single:          true,
			rawResponseData: &struct{ Foo string }{Foo: "foo"},
			responseStruct:  reflect.TypeOf(struct{ Foo string }{}),
			expected:        "foo: foo\n",
			formatter:       yamlFormatter,
		},
		{
			name:   "StructureData-Transform-Single",
			single: true,
			transform: func(reader io.Reader, single bool) (i interface{}, err error) {
				foo := &struct{ Foo string }{}
				err = json.NewDecoder(reader).Decode(foo)
				return &struct{ Bar string }{Bar: foo.Foo}, err
			},
			rawResponseData: &struct{ Foo string }{Foo: "foo"},
			responseStruct:  reflect.TypeOf(struct{ Bar string }{}),
			expected:        "bar: foo\n",
			formatter:       yamlFormatter,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opt := &commandDefinition{
				SingleObject:        tc.singleton,
				TransformedResponse: tc.responseStruct,
				AddonTransform:      tc.transform,
			}
			var responseData []byte
			responseData, err := json.Marshal(tc.rawResponseData)
			assert.Nil(t, err)
			var outputBuf bytes.Buffer
			err = opt.output(bytes.NewBuffer(responseData), &outputBuf, tc.formatter, tc.single)
			assert.Nil(t, err)
			assert.Equal(t, tc.expected, outputBuf.String())
		})
	}
}

// TestCommandDefinitionGenerateExample checks example strings are generated as
// expected.
func TestCommandDefinitionGenerateExample(t *testing.T) {
	for k, tc := range map[string]struct {
		use       string
		cmdChain  string
		key       *argOption
		singleton bool
		expect    string
	}{
		"SingleObject": {
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
			key: &argOption{
				name:      "bar",
				fieldName: "Bar",
				usage:     "",
				key:       true,
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

			co := &commandDefinition{SingleObject: tc.singleton, TransformedResponse: reflect.TypeOf(FooResponse{})}
			co.applyExampleToCommand(cmd, tc.key)
			assert.Equal(t, tc.expect, cmd.Example)
		})
	}
}
