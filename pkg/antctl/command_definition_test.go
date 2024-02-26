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

	"antrea.io/antrea/pkg/antctl/runtime"
	"antrea.io/antrea/pkg/antctl/transform/version"
)

type Foobar struct {
	Foo string `json:"foo"`
}

// TestFormat ensures the formatter and AddonTransform works as expected.
func TestFormat(t *testing.T) {
	for _, tc := range []struct {
		name            string
		single          bool
		transform       func(reader io.Reader, single bool, opts map[string]string) (interface{}, error)
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
			transform: func(reader io.Reader, single bool, opts map[string]string) (i interface{}, err error) {
				foo := &Foobar{}
				err = json.NewDecoder(reader).Decode(foo)
				return &struct{ Bar string }{Bar: foo.Foo}, err
			},
			rawResponseData: &Foobar{Foo: "foo"},
			responseStruct:  reflect.TypeOf(struct{ Bar string }{}),
			expected:        "Bar: foo\n",
			formatter:       yamlFormatter,
		},
		{
			name:            "StructureData-NoTransform-List-Table",
			rawResponseData: []Foobar{{Foo: "foo"}, {Foo: "bar"}},
			responseStruct:  reflect.TypeOf(Foobar{}),
			expected:        "foo            \nfoo            \nbar            \n",
			formatter:       tableFormatter,
		},
		{
			name:            "StructureData-NoTransform-List-Table-Struct",
			rawResponseData: []struct{ Foo Foobar }{{Foo: Foobar{"foo"}}, {Foo: Foobar{"bar"}}},
			responseStruct:  reflect.TypeOf(struct{ Foo Foobar }{}),
			expected:        "Foo            \n{\"foo\":\"foo\"}  \n{\"foo\":\"bar\"}  \n",
			formatter:       tableFormatter,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opt := &commandDefinition{
				transformedResponse:    tc.responseStruct,
				controllerEndpoint:     &endpoint{addonTransform: tc.transform},
				agentEndpoint:          &endpoint{addonTransform: tc.transform},
				flowAggregatorEndpoint: &endpoint{addonTransform: tc.transform},
			}
			var responseData []byte
			responseData, err := json.Marshal(tc.rawResponseData)
			assert.Nil(t, err)
			var outputBuf bytes.Buffer
			err = opt.output(bytes.NewBuffer(responseData), &outputBuf, tc.formatter, tc.single, map[string]string{})
			assert.Nil(t, err)
			assert.Equal(t, tc.expected, outputBuf.String())
		})
	}
}

// TestCommandDefinitionGenerateExample checks example strings are generated as
// expected.
func TestCommandDefinitionGenerateExample(t *testing.T) {
	runtime.Mode = runtime.ModeAgent
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

func TestNamespaced(t *testing.T) {
	tc := []struct {
		name     string
		mode     string
		cd       *commandDefinition
		expected bool
	}{
		{
			name:     "Command with no supported component",
			mode:     "",
			cd:       &commandDefinition{},
			expected: false,
		},
		{
			name: "Command for agent defines resource endpoint",
			mode: "agent",
			cd: &commandDefinition{
				agentEndpoint: &endpoint{
					resourceEndpoint: &resourceEndpoint{
						namespaced: true,
					},
				},
			},
			expected: true,
		},
		{
			name: "Command for agent defines non-resource endpoint",
			mode: "agent",
			cd: &commandDefinition{
				agentEndpoint: &endpoint{
					nonResourceEndpoint: &nonResourceEndpoint{
						path: "/version",
					},
				},
			},
			expected: false,
		},
		{
			name: "Command for controller defines resource endpoint",
			mode: "controller",
			cd: &commandDefinition{
				controllerEndpoint: &endpoint{
					resourceEndpoint: &resourceEndpoint{
						namespaced: true,
					},
				},
			},
			expected: true,
		},
		{
			name: "Command for controller defines non-resource endpoint",
			mode: "controller",
			cd: &commandDefinition{
				controllerEndpoint: &endpoint{
					nonResourceEndpoint: &nonResourceEndpoint{
						path: "/version",
					},
				},
			},
			expected: false,
		},
		{
			name: "Command for flow aggregator defines resource endpoint",
			mode: "flowaggregator",
			cd: &commandDefinition{
				flowAggregatorEndpoint: &endpoint{
					resourceEndpoint: &resourceEndpoint{
						namespaced: true,
					},
				},
			},
			expected: true,
		},
		{
			name: "Command for flow aggregator defines non-resource endpoint",
			mode: "flowaggregator",
			cd: &commandDefinition{
				flowAggregatorEndpoint: &endpoint{
					nonResourceEndpoint: &nonResourceEndpoint{
						path: "/version",
					},
				},
			},
			expected: false,
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			runtime.Mode = tt.mode
			actualValue := tt.cd.namespaced()
			assert.Equal(t, tt.expected, actualValue)
		})
	}
}

func TestAddonTransform(t *testing.T) {
	tc := []struct {
		name             string
		cd               *commandDefinition
		mode             string
		rawResponseData  map[string]string
		expectedResponse *version.Response
	}{
		{
			name: "Antctl running against agent mode",
			mode: "agent",
			cd: &commandDefinition{
				agentEndpoint: &endpoint{
					addonTransform: version.AgentTransform,
				},
			},
			rawResponseData:  map[string]string{"GitVersion": "v1.11.0+d4cacc0"},
			expectedResponse: &version.Response{AgentVersion: "v1.11.0+d4cacc0", ControllerVersion: "", FlowAggregatorVersion: "", AntctlVersion: "UNKNOWN"},
		},
		{
			name: "Antctl running against controller mode",
			mode: "controller",
			cd: &commandDefinition{
				controllerEndpoint: &endpoint{
					addonTransform: version.ControllerTransform,
				},
			},
			rawResponseData:  map[string]string{"Version": "v1.11.0+d4cacc0"},
			expectedResponse: &version.Response{AgentVersion: "", ControllerVersion: "v1.11.0+d4cacc0", FlowAggregatorVersion: "", AntctlVersion: "UNKNOWN"},
		},
		{
			name: "Antctl running against flowaggregator mode",
			mode: "flowaggregator",
			cd: &commandDefinition{
				flowAggregatorEndpoint: &endpoint{
					addonTransform: version.FlowAggregatorTransform,
				},
			},
			rawResponseData:  map[string]string{"GitVersion": "v1.11.0+d4cacc0"},
			expectedResponse: &version.Response{AgentVersion: "", ControllerVersion: "", FlowAggregatorVersion: "v1.11.0+d4cacc0", AntctlVersion: "UNKNOWN"},
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			runtime.Mode = tt.mode
			addonTransform := tt.cd.getAddonTransform()
			responseData, _ := json.Marshal(tt.rawResponseData)
			obj, err := addonTransform(bytes.NewBuffer(responseData), true, map[string]string{})
			assert.Nil(t, err)
			assert.Equal(t, tt.expectedResponse, obj)
		})
	}
}

func TestValidate(t *testing.T) {
	tc := []struct {
		name           string
		cd             *commandDefinition
		expectedErrors []string
		mode           string
	}{
		{
			name: "Command with no name and supported component",
			cd: &commandDefinition{
				use: "",
			},
			expectedErrors: []string{
				"the command does not have name",
				": command does not define output struct",
				": command does not define any supported component",
			},
		},
		{
			name: "Command with name and aliases",
			cd: &commandDefinition{
				use:     "controllerinfo",
				aliases: []string{"controllerinfo", "controllerinfos", "ci", "controllerinfos"},
			},
			expectedErrors: []string{
				"controllerinfo: command alias is the same with use of the command",
				"controllerinfo: command alias is provided twice: controllerinfos",
				"controllerinfo: command does not define output struct",
				"controllerinfo: command does not define any supported component",
			},
		},
		{
			name: "Command for supported components defines both endpoints",
			cd: &commandDefinition{
				use: "networkpolicy",
				controllerEndpoint: &endpoint{
					resourceEndpoint:    &resourceEndpoint{},
					nonResourceEndpoint: &nonResourceEndpoint{},
				},
				agentEndpoint: &endpoint{
					nonResourceEndpoint: &nonResourceEndpoint{},
					resourceEndpoint:    &resourceEndpoint{},
				},
				flowAggregatorEndpoint: &endpoint{
					nonResourceEndpoint: &nonResourceEndpoint{},
					resourceEndpoint:    &resourceEndpoint{},
				},
			},
			expectedErrors: []string{
				"networkpolicy: command does not define output struct",
				"networkpolicy: command for agent can only define one endpoint",
				"networkpolicy: command for controller can only define one endpoint",
				"networkpolicy: command for flow aggregator can only define one endpoint",
			},
		},
		{
			name: "Command for controller defines non-resource endpoint",
			cd: &commandDefinition{
				use: "log-level",
				controllerEndpoint: &endpoint{
					nonResourceEndpoint: &nonResourceEndpoint{
						params: []flagInfo{
							{
								name:  "",
								usage: "Empty flag",
								arg:   true,
							},
							{
								name:      "namespace",
								usage:     "Get log-evel from specific Namespace.",
								shorthand: "na",
							},
							{
								name:      "output",
								usage:     "used to display output",
								shorthand: "out",
							},
						},
					},
				},
				agentEndpoint:          &endpoint{},
				flowAggregatorEndpoint: &endpoint{},
			},
			mode: "controller",
			expectedErrors: []string{
				"log-level: command does not define output struct",
				"log-level: command for agent must define one endpoint",
				"log-level: command for flow aggregator must define one endpoint",
				"log-level: flag name cannot be empty",
				"log-level: length of a flag shorthand cannot be larger than 1: na",
				"log-level: flag redefined: output",
				"log-level: length of a flag shorthand cannot be larger than 1: out",
			},
		},
		{
			name: "Command for controller defines resource endpoint",
			cd: &commandDefinition{
				use: "networkpolicy",
				controllerEndpoint: &endpoint{
					resourceEndpoint: &resourceEndpoint{
						namespaced: true,
					},
				},
				agentEndpoint:          &endpoint{},
				flowAggregatorEndpoint: &endpoint{},
			},
			mode: "controller",
			expectedErrors: []string{
				"networkpolicy: command does not define output struct",
				"networkpolicy: command for agent must define one endpoint",
				"networkpolicy: command for flow aggregator must define one endpoint",
			},
		},
		{
			name: "Command for agent defines non-resource endpoint",
			cd: &commandDefinition{
				use: "log-level",
				agentEndpoint: &endpoint{
					nonResourceEndpoint: &nonResourceEndpoint{
						params: []flagInfo{
							{
								name:  "",
								usage: "Empty flag",
								arg:   true,
							},
							{
								name:      "namespace",
								usage:     "Get log-level Statistics from specific Namespace.",
								shorthand: "na",
							},
							{
								name:      "output",
								usage:     "used to display output",
								shorthand: "out",
							},
						},
					},
				},
				controllerEndpoint:     &endpoint{},
				flowAggregatorEndpoint: &endpoint{},
			},
			mode: "agent",
			expectedErrors: []string{
				"log-level: command does not define output struct",
				"log-level: command for controller must define one endpoint",
				"log-level: command for flow aggregator must define one endpoint",
				"log-level: flag name cannot be empty",
				"log-level: length of a flag shorthand cannot be larger than 1: na",
				"log-level: flag redefined: output",
				"log-level: length of a flag shorthand cannot be larger than 1: out",
			},
		},
		{
			name: "Command for agent defines resource endpoint",
			cd: &commandDefinition{
				use: "podmulticasts",
				agentEndpoint: &endpoint{
					resourceEndpoint: &resourceEndpoint{
						namespaced: true,
					},
				},
				controllerEndpoint:     &endpoint{},
				flowAggregatorEndpoint: &endpoint{},
			},
			mode: "agent",
			expectedErrors: []string{
				"podmulticasts: command does not define output struct",
				"podmulticasts: command for controller must define one endpoint",
				"podmulticasts: command for flow aggregator must define one endpoint",
			},
		},
		{
			name: "Command for flowaggregator defines non-resource endpoint",
			cd: &commandDefinition{
				use: "log-level",
				flowAggregatorEndpoint: &endpoint{
					nonResourceEndpoint: &nonResourceEndpoint{
						params: []flagInfo{
							{
								name:  "",
								usage: "Empty flag",
								arg:   true,
							},
							{
								name:      "namespace",
								usage:     "Get log-level from specific Namespace.",
								shorthand: "na",
							},
							{
								name:      "output",
								usage:     "used to display output",
								shorthand: "out",
							},
						},
					},
				},
				controllerEndpoint: &endpoint{},
				agentEndpoint:      &endpoint{},
			},
			mode: "flowaggregator",
			expectedErrors: []string{
				"log-level: command does not define output struct",
				"log-level: command for agent must define one endpoint",
				"log-level: command for controller must define one endpoint",
				"log-level: flag name cannot be empty",
				"log-level: length of a flag shorthand cannot be larger than 1: na",
				"log-level: flag redefined: output",
				"log-level: length of a flag shorthand cannot be larger than 1: out",
			},
		},
		{
			name: "Command for flowaggregator defines resource endpoint",
			cd: &commandDefinition{
				use: "podmulticasts",
				flowAggregatorEndpoint: &endpoint{
					resourceEndpoint: &resourceEndpoint{
						namespaced: true,
					},
				},
				controllerEndpoint: &endpoint{},
				agentEndpoint:      &endpoint{},
			},
			mode: "flowaggregator",
			expectedErrors: []string{
				"podmulticasts: command does not define output struct",
				"podmulticasts: command for agent must define one endpoint",
				"podmulticasts: command for controller must define one endpoint",
			},
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			runtime.Mode = tt.mode
			errs := tt.cd.validate()
			strErrors := make([]string, len(errs))
			for i, err := range errs {
				strErrors[i] = err.Error()
			}
			assert.Equal(t, tt.expectedErrors, strErrors)
		})
	}
}

func TestGetRequestErrorFallback(t *testing.T) {
	tc := []struct {
		name string
		cd   *commandDefinition
		mode string
	}{
		{
			name: "Antctl running against agent mode",
			mode: "agent",
			cd: &commandDefinition{
				agentEndpoint: &endpoint{
					requestErrorFallback: func() (io.Reader, error) {
						return strings.NewReader("agent"), nil
					},
				},
			},
		},
		{
			name: "Antctl running against controller mode",
			mode: "controller",
			cd: &commandDefinition{
				controllerEndpoint: &endpoint{
					requestErrorFallback: func() (io.Reader, error) {
						return strings.NewReader("controller"), nil
					},
				},
			},
		},
		{
			name: "Antctl running against flowaggregator mode",
			mode: "flowaggregator",
			cd: &commandDefinition{
				flowAggregatorEndpoint: &endpoint{
					requestErrorFallback: func() (io.Reader, error) {
						return strings.NewReader("flowaggregator"), nil
					},
				},
			},
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			runtime.Mode = tt.mode
			fallback := tt.cd.getRequestErrorFallback()
			reader, err := fallback()
			assert.Nil(t, err)
			b := make([]byte, len(tt.mode))
			_, err = reader.Read(b)
			assert.Nil(t, err)
			assert.Equal(t, tt.mode, string(b))
		})
	}
}

func TestCollectFlags(t *testing.T) {
	tc := []struct {
		name          string
		cd            *commandDefinition
		expected      map[string]string
		expectedError string
		mode          string
		args          []string
	}{
		{
			name: "Command for agent defines non-resource endpoint",
			cd: &commandDefinition{
				use: "ovsflows",
				agentEndpoint: &endpoint{
					nonResourceEndpoint: &nonResourceEndpoint{
						params: []flagInfo{
							{
								name:         "namespace",
								defaultValue: "default",
								usage:        "Namespace of the entity",
								shorthand:    "n",
								arg:          true,
							},
							{
								name:         "pod",
								defaultValue: "Pod",
								usage:        "Name of a local Pod. If present, Namespace must be provided.",
								shorthand:    "p",
							},
							{
								name:         "service",
								defaultValue: "Service",
								usage:        "Name of a Service. If present, Namespace must be provided.",
								shorthand:    "S",
							},
							{
								name:         "networkpolicy",
								defaultValue: "NetworkPolicy",
								usage:        "NetworkPolicy name. If present, Namespace must be provided.",
								shorthand:    "N",
							},
							{
								name:         "table",
								defaultValue: "Table",
								usage:        "Comma separated Antrea OVS flow table names or numbers",
								shorthand:    "T",
							},
							{
								name:   "table-names-only",
								usage:  "Print all Antrea OVS flow table names only, and nothing else",
								isBool: true,
							},
							{
								name:         "groups",
								defaultValue: "Groups",
								usage:        "Comma separated OVS group IDs. Use 'all' to dump all groups",
								shorthand:    "G",
							},
						},
					},
				},
			},
			expected: map[string]string{"groups": "Groups", "namespace": "test1", "networkpolicy": "NetworkPolicy", "pod": "Pod", "service": "Service", "table": "Table"},
			mode:     "agent",
			args:     []string{"test1", "test2"},
		},
		{
			name: "Command for flowaggregator defines resource endpoint",
			cd: &commandDefinition{
				use: "podmulticasts",
				flowAggregatorEndpoint: &endpoint{
					resourceEndpoint: &resourceEndpoint{
						namespaced: true,
					},
				},
				controllerEndpoint: &endpoint{},
				agentEndpoint:      &endpoint{},
			},
			mode:     "flowaggregator",
			expected: map[string]string{"name": "test1", "namespace": ""},
			args:     []string{"test1", "test2"},
		},
		{
			name: "Command for controller defines non-resource endpoint",
			mode: "controller",
			cd: &commandDefinition{
				use: "endpoint",
				controllerEndpoint: &endpoint{
					nonResourceEndpoint: &nonResourceEndpoint{
						params: []flagInfo{
							{
								name:            "namespace",
								defaultValue:    "default",
								supportedValues: []string{"default", "ns1", "ns2"},
								usage:           "Namespace of the endpoint (defaults to 'default')",
								shorthand:       "n",
							},
							{
								name:            "pod",
								defaultValue:    "Pod",
								supportedValues: []string{"pod1", "pod2", "pod3"},
								usage:           "Name of a Pod endpoint",
								shorthand:       "p",
							},
						},
					},
				},
			},
			expected:      map[string]string(nil),
			expectedError: "unsupported value Pod for flag pod",
			args:          []string{"test1", "test2"},
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			runtime.Mode = tt.mode
			cmd := &cobra.Command{
				Use: tt.cd.use,
			}
			tt.cd.applyFlagsToCommand(cmd)
			argMap, err := tt.cd.collectFlags(cmd, tt.args)
			if err != nil {
				assert.Equal(t, tt.expectedError, err.Error())
			} else {
				assert.Equal(t, tt.expected, argMap)
			}
		})
	}
}
