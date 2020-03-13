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
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/addressgroup"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/appliedtogroup"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/common"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/rule"
	networkingv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
)

type Foobar struct {
	Foo string
}

func TestCommandList_tableOutputForGetCommands(t *testing.T) {
	for _, tc := range []struct {
		name            string
		rawResponseData interface{}
		expected        string
	}{
		{
			name:            "StructureData-NonTableOutput-Single",
			rawResponseData: Foobar{Foo: "foo"},
			expected: `Foo            
foo            
`,
		},
		{
			name: "StructureData-NonTableOutput-List",
			rawResponseData: []Foobar{
				{Foo: "foo1"},
				{Foo: "foo2"},
			},
			expected: `Foo            
foo1           
foo2           
`,
		},
		{
			name: "StructureData-NetworkPolicy-List-HasSummary-RandomFieldOrder",
			rawResponseData: []networkpolicy.Response{
				{
					Name:            "GroupName2",
					AppliedToGroups: []string{"32ef631b-6817-5a18-86eb-93f4abf0467c", "c4c59cfe-9160-5de5-a85b-01a58d11963e"},
					Rules: []rule.Response{
						{
							Direction: "In",
							Services:  nil,
						},
					},
				},
				{
					Rules: []rule.Response{
						{
							Direction: "In",
							Services:  nil,
						},
						{
							Direction: "In",
							Services:  nil,
						},
					},
					AppliedToGroups: []string{"32ef631b-6817-5a18-86eb-93f4abf0467c"},
					Name:            "GroupName1",
				},
			},
			expected: `NAME       APPLIED-TO                                       RULES
GroupName1 32ef631b-6817-5a18-86eb-93f4abf0467c             2    
GroupName2 32ef631b-6817-5a18-86eb-93f4abf0467c + 1 more... 1    
`,
		},
		{
			name: "StructureData-AddressGroup-List-HasSummary-HasEmpty",
			rawResponseData: []addressgroup.Response{
				{
					Name: "GroupName1",
					Pods: []common.GroupMemberPod{
						{IP: "127.0.0.1"}, {IP: "192.168.0.1"}, {IP: "127.0.0.2"},
						{IP: "127.0.0.3"}, {IP: "10.0.0.3"}, {IP: "127.0.0.5"}, {IP: "127.0.0.6"},
					},
				},
				{
					Name: "GroupName2",
					Pods: []common.GroupMemberPod{},
				},
			},
			expected: `NAME       POD-IPS                                           
GroupName1 10.0.0.3,127.0.0.1,127.0.0.2,127.0.0.3 + 2 more...
GroupName2 <NONE>                                            
`,
		},
		{
			name: "StructureData-AppliedToGroup-Single-NoSummary",
			rawResponseData: appliedtogroup.Response{
				Name: "GroupName",
				Pods: []common.GroupMemberPod{
					{Pod: &networkingv1beta1.PodReference{
						Name:      "nginx-6db489d4b7-324rc",
						Namespace: "PodNamespace",
					}},
					{Pod: &networkingv1beta1.PodReference{
						Name:      "nginx-6db489d4b7-vgv7v",
						Namespace: "PodNamespace",
					}},
				},
			},
			expected: `NAME      PODS                                           
GroupName PodNamespace/nginx-6db489d4b7-324rc + 1 more...
`,
		},
		{
			name:            "StructureData-NetworkPolicy-List-EmptyRespCase",
			rawResponseData: []networkpolicy.Response{},
			expected:        "\n",
		},
		{
			name: "StructureData-AppliedToGroup-Single-EmptyRespCase",
			rawResponseData: appliedtogroup.Response{
				Name: "GroupName",
				Pods: []common.GroupMemberPod{},
			},
			expected: `NAME      PODS  
GroupName <NONE>
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opt := &commandDefinition{}
			var outputBuf bytes.Buffer
			err := opt.tableOutputForGetCommands(tc.rawResponseData, &outputBuf)
			fmt.Println(outputBuf.String())
			assert.Nil(t, err)
			assert.Equal(t, tc.expected, outputBuf.String())
		})
	}
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
		use        string
		cmdChain   string
		outputType OutputType
		expect     string
	}{
		"SingleObject": {
			use:        "test",
			cmdChain:   "first second third",
			outputType: single,
			expect:     "  Get the test\n  $ first second third test\n",
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
				agentEndpoint: &endpoint{nonResourceEndpoint: &nonResourceEndpoint{outputType: tc.outputType}},
			}
			co.applyExampleToCommand(cmd)
			assert.Equal(t, tc.expect, cmd.Example)
		})
	}
}
