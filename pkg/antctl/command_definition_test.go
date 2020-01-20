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

type Foobar struct {
	Foo string
}

// TestFormat ensures the formatter and AddonTransform works as expected.
func TestFormat(t *testing.T) {
	for _, tc := range []struct {
		name            string
		single          bool
		transform       func(reader io.Reader, single bool) (interface{}, error)
		rawResponseData interface{}
		responseStruct  reflect.Type
		expected        string
		formatter       formatterType
	}{
		{
			name:            "StructureData-NoTransform-List-Yaml",
			rawResponseData: []Foobar{{Foo: "foo"}},
			responseStruct:  reflect.TypeOf(Foobar{}),
			expected:        "- foo: foo\n",
			formatter:       yamlFormatter,
		},
		{
			name:            "StructureData-NoTransform-Single-Yaml",
			single:          true,
			rawResponseData: &Foobar{Foo: "foo"},
			responseStruct:  reflect.TypeOf(Foobar{}),
			expected:        "foo: foo\n",
			formatter:       yamlFormatter,
		},
		{
			name:   "StructureData-Transform-Single-Yaml",
			single: true,
			transform: func(reader io.Reader, single bool) (i interface{}, err error) {
				foo := &Foobar{}
				err = json.NewDecoder(reader).Decode(foo)
				return &struct{ Bar string }{Bar: foo.Foo}, err
			},
			rawResponseData: &Foobar{Foo: "foo"},
			responseStruct:  reflect.TypeOf(struct{ Bar string }{}),
			expected:        "bar: foo\n",
			formatter:       yamlFormatter,
		},
		{
			name:            "StructureData-NoTransform-List-Table",
			rawResponseData: []Foobar{{Foo: "foo"}, {Foo: "bar"}},
			responseStruct:  reflect.TypeOf(Foobar{}),
			expected:        "Foo            \nfoo            \nbar            \n",
			formatter:       tableFormatter,
		},
		{
			name:            "StructureData-NoTransform-List-Table-Struct",
			rawResponseData: []struct{ Foo Foobar }{{Foo: Foobar{"foo"}}, {Foo: Foobar{"bar"}}},
			responseStruct:  reflect.TypeOf(struct{ Foo Foobar }{}),
			expected:        "Foo            \n{\"Foo\":\"foo\"}  \n{\"Foo\":\"bar\"}  \n",
			formatter:       tableFormatter,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opt := &commandDefinition{
				transformedResponse: tc.responseStruct,
				controllerEndpoint:  &endpoint{addonTransform: tc.transform},
				agentEndpoint:       &endpoint{addonTransform: tc.transform},
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
	runtimeComponent = componentAgent
	for k, tc := range map[string]struct {
		use          string
		cmdChain     string
		singleObject bool
		expect       string
	}{
		"SingleObject": {
			use:          "test",
			cmdChain:     "first second third",
			singleObject: true,
			expect:       "  Get the test\n  $ first second third test\n",
		},
		"KeyList": {
			use:      "test",
			cmdChain: "first second third",
			expect:   "  Get a test\n  $ first second third test [name]\n  Get the list of test\n  $ first second third test\n",
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

			co := &commandDefinition{
				use:           tc.use,
				agentEndpoint: &endpoint{nonResourceEndpoint: &nonResourceEndpoint{isSingle: tc.singleObject}},
			}
			co.applyExampleToCommand(cmd)
			assert.Equal(t, tc.expect, cmd.Example)
		})
	}
}
