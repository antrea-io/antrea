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
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/agent/apiserver/handlers/agentinfo"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/podinterface"
	"antrea.io/antrea/pkg/antctl/output"
	"antrea.io/antrea/pkg/antctl/runtime"
	"antrea.io/antrea/pkg/antctl/transform/addressgroup"
	"antrea.io/antrea/pkg/antctl/transform/appliedtogroup"
	"antrea.io/antrea/pkg/antctl/transform/common"
	"antrea.io/antrea/pkg/antctl/transform/controllerinfo"
	"antrea.io/antrea/pkg/antctl/transform/networkpolicy"
	"antrea.io/antrea/pkg/antctl/transform/version"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	controllernetworkpolicy "antrea.io/antrea/pkg/controller/networkpolicy"
)

type Foobar struct {
	Foo string `json:"foo"`
}

var (
	AntreaPolicyTierPriority = int32(250)
	AntreaPolicyPriority     = float64(1.0)
)

func TestCommandList_tableOutputForGetCommands(t *testing.T) {
	for _, tc := range []struct {
		name            string
		rawResponseData interface{}
		expected        string
	}{
		{
			name: "StructureData-ControllerInfo-Single",
			rawResponseData: controllerinfo.Response{
				Version: "v0.4.0",
				PodRef: v1.ObjectReference{
					Kind:      "Pod",
					Namespace: "kube-system",
					Name:      "antrea-controller-55b9bcd59f-h9ll4",
				},
				NodeRef: v1.ObjectReference{
					Kind: "Node",
					Name: "node-control-plane",
				},
				ServiceRef: v1.ObjectReference{
					Kind: "Service",
					Name: "antrea",
				},
				NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{
					NetworkPolicyNum:  1,
					AddressGroupNum:   1,
					AppliedToGroupNum: 2,
				},
				ConnectedAgentNum: 2,
				ControllerConditions: []v1beta1.ControllerCondition{
					{
						Type:              "ControllerHealthy",
						Status:            "True",
						LastHeartbeatTime: metav1.NewTime(time.Now()),
					},
				},
			},
			expected: `POD                                            NODE               STATUS  NETWORK-POLICIES ADDRESS-GROUPS APPLIED-TO-GROUPS CONNECTED-AGENTS
kube-system/antrea-controller-55b9bcd59f-h9ll4 node-control-plane Healthy 1                1              2                 2               
`,
		},
		{
			name: "StructureData-AgentInfo-Single",
			rawResponseData: agentinfo.AntreaAgentInfoResponse{
				Version: "v0.4.0",
				PodRef: v1.ObjectReference{
					Kind:      "Pod",
					Namespace: "kube-system",
					Name:      "antrea-agent-0",
				},
				NodeRef: v1.ObjectReference{
					Kind: "Node",
					Name: "node-worker",
				},
				NodeSubnets: []string{"192.168.1.0/24", "192.168.1.1/24"},
				OVSInfo: v1beta1.OVSInfo{
					Version:    "1.0",
					BridgeName: "br-int",
					FlowTable: map[string]int32{
						"0":  5,
						"10": 7,
					},
				},
				NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{
					NetworkPolicyNum:  1,
					AddressGroupNum:   1,
					AppliedToGroupNum: 2,
				},
				LocalPodNum: 3,
				AgentConditions: []v1beta1.AgentCondition{
					{
						Type:              "AgentHealthy",
						Status:            "True",
						LastHeartbeatTime: metav1.NewTime(time.Now()),
					},
				},
			},
			expected: `POD                        NODE        STATUS  NODE-SUBNET                   NETWORK-POLICIES ADDRESS-GROUPS APPLIED-TO-GROUPS LOCAL-PODS
kube-system/antrea-agent-0 node-worker Healthy 192.168.1.0/24,192.168.1.1/24 1                1              2                 3         
`,
		},
		{
			name:            "StructureData-NonTableOutput-Single",
			rawResponseData: Foobar{Foo: "foo"},
			expected: `foo            
foo            
`,
		},
		{
			name: "StructureData-NonTableOutput-List",
			rawResponseData: []Foobar{
				{Foo: "foo1"},
				{Foo: "foo2"},
			},
			expected: `foo            
foo1           
foo2           
`,
		},
		{
			name: "StructureData-NetworkPolicy-List-HasSummary-RandomFieldOrder",
			rawResponseData: []networkpolicy.Response{
				{
					NetworkPolicy: &cpv1beta.NetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name: "6001549b-ba63-4752-8267-30f52b4332db",
						},
						AppliedToGroups: []string{"32ef631b-6817-5a18-86eb-93f4abf0467c", "c4c59cfe-9160-5de5-a85b-01a58d11963e"},
						Rules: []cpv1beta.NetworkPolicyRule{
							{
								Direction: "In",
								Services:  nil,
							},
						},
						SourceRef: &cpv1beta.NetworkPolicyReference{
							Type:      cpv1beta.K8sNetworkPolicy,
							Namespace: "default",
							Name:      "allow-all",
							UID:       "6001549b-ba63-4752-8267-30f52b4332db",
						},
					},
				},
				{
					NetworkPolicy: &cpv1beta.NetworkPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name: "880db7e8-fc2a-4030-aefe-09afc5f341ad",
						},
						TierPriority:    &AntreaPolicyTierPriority,
						Priority:        &AntreaPolicyPriority,
						AppliedToGroups: []string{"32ef631b-6817-5a18-86eb-93f4abf0467c"},
						Rules: []cpv1beta.NetworkPolicyRule{
							{
								Direction: "In",
								Services:  nil,
							},
							{
								Direction: "In",
								Services:  nil,
							},
						},
						SourceRef: &cpv1beta.NetworkPolicyReference{
							Type:      cpv1beta.AntreaNetworkPolicy,
							Namespace: "default",
							Name:      "allow-all",
							UID:       "880db7e8-fc2a-4030-aefe-09afc5f341ad",
						},
					},
				},
			},
			expected: `NAME                                 APPLIED-TO                                       RULES SOURCE                                TIER-PRIORITY PRIORITY
6001549b-ba63-4752-8267-30f52b4332db 32ef631b-6817-5a18-86eb-93f4abf0467c + 1 more... 1     K8sNetworkPolicy:default/allow-all    <NONE>        <NONE>  
880db7e8-fc2a-4030-aefe-09afc5f341ad 32ef631b-6817-5a18-86eb-93f4abf0467c             2     AntreaNetworkPolicy:default/allow-all 250           1       
`,
		},
		{
			name: "StructureData-AddressGroup-List-HasSummary-HasEmpty",
			rawResponseData: []addressgroup.Response{
				{
					Name: "GroupName1",
					Pods: []common.GroupMember{
						{IP: "127.0.0.1"}, {IP: "192.168.0.1"}, {IP: "127.0.0.2"},
						{IP: "127.0.0.3"}, {IP: "10.0.0.3"}, {IP: "127.0.0.5"}, {IP: "127.0.0.6"},
					},
				},
				{
					Name: "GroupName2",
					Pods: []common.GroupMember{},
				},
			},
			expected: `NAME       POD-IPS                                            NODE-IPS
GroupName1 10.0.0.3,127.0.0.1,127.0.0.2,127.0.0.3 + 2 more... <NONE>  
GroupName2 <NONE>                                             <NONE>  
`,
		},
		{
			name: "StructureData-AddressGroup-HasNode",
			rawResponseData: []addressgroup.Response{
				{
					Name: "AddressGroupNameHasNode",
					Nodes: []common.GroupMember{
						{IP: "127.0.0.1"}, {IP: "192.168.0.1"}, {IP: "10.176.27.105"}, {IP: "127.0.0.3"},
					},
				},
				{
					Name: "AddressGroupNameHasPod",
					Pods: []common.GroupMember{
						{IP: "127.0.0.1"}, {IP: "192.168.0.1"}, {IP: "127.0.0.2"},
						{IP: "127.0.0.3"}, {IP: "10.0.0.3"}, {IP: "127.0.0.5"}, {IP: "127.0.0.6"},
					},
				},
				{
					Name: "AddressGroupNameNone",
					Pods: []common.GroupMember{},
				},
			},
			expected: `NAME                    POD-IPS                                            NODE-IPS                                     
AddressGroupNameHasNode <NONE>                                             10.176.27.105,127.0.0.1,127.0.0.3,192.168.0.1
AddressGroupNameHasPod  10.0.0.3,127.0.0.1,127.0.0.2,127.0.0.3 + 2 more... <NONE>                                       
AddressGroupNameNone    <NONE>                                             <NONE>                                       
`,
		},
		{
			name: "StructureData-AppliedToGroup-Single-NoSummary",
			rawResponseData: appliedtogroup.Response{
				Name: "GroupName",
				Pods: []common.GroupMember{
					{Pod: &cpv1beta.PodReference{
						Name:      "nginx-6db489d4b7-324rc",
						Namespace: "PodNamespace",
					}},
					{Pod: &cpv1beta.PodReference{
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
				Pods: []common.GroupMember{},
			},
			expected: `NAME      PODS  
GroupName <NONE>
`,
		},
		{
			name: "StructureData-PodInterface-List",
			rawResponseData: []podinterface.Response{
				{
					PodName:       "nginx-6db489d4b7-vgv7v",
					PodNamespace:  "default",
					InterfaceName: "Interface",
					IPs:           []string{"127.0.0.1"},
					MAC:           "07-16-76-00-02-86",
					PortUUID:      "portuuid0",
					OFPort:        80,
					ContainerID:   "dve7a2d6c224otm9m0eas8dtwr78",
				},
				{
					PodName:       "nginx-32b489d4b7-vgv7v",
					PodNamespace:  "default",
					InterfaceName: "Interface2",
					IPs:           []string{"127.0.0.2"},
					MAC:           "07-16-76-00-02-87",
					PortUUID:      "portuuid1",
					OFPort:        35572,
					ContainerID:   "uci2ucsd6dx87dasuk232312csse",
				},
			},
			expected: `NAMESPACE NAME                   INTERFACE-NAME IP        MAC               PORT-UUID OF-PORT CONTAINER-ID
default   nginx-32b489d4b7-vgv7v Interface2     127.0.0.2 07-16-76-00-02-87 portuuid1 35572   uci2ucsd6dx 
default   nginx-6db489d4b7-vgv7v Interface      127.0.0.1 07-16-76-00-02-86 portuuid0 80      dve7a2d6c22 
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var outputBuf bytes.Buffer
			err := output.TableOutputForGetCommands(tc.rawResponseData, &outputBuf)
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

func TestTableOutputForQueryEndpoint(t *testing.T) {
	policyRef0 := controllernetworkpolicy.PolicyRef{Namespace: "testNamespace", Name: "test-ingress-egress", UID: "uid-1"}
	policyRef1 := controllernetworkpolicy.PolicyRef{Namespace: "testNamespace", Name: "default-deny-egress", UID: "uid-2"}
	tc := []struct {
		name            string
		rawResponseData interface{}
		expected        string
	}{
		{
			name: "Pod selected by no policy",
			rawResponseData: &controllernetworkpolicy.EndpointQueryResponse{
				Endpoints: []controllernetworkpolicy.Endpoint{
					{Namespace: "testNamespace", Name: "podA", Policies: []controllernetworkpolicy.Policy{}, Rules: []controllernetworkpolicy.Rule{}},
				},
			},
			expected: `Endpoint testNamespace/podA
Applied Policies: None

Egress Rules: None

Ingress Rules: None

`,
		},
		{
			name: "Pod selected by 1 policy",
			rawResponseData: &controllernetworkpolicy.EndpointQueryResponse{
				Endpoints: []controllernetworkpolicy.Endpoint{
					{
						Namespace: "testNamespace",
						Name:      "podA",
						Policies:  []controllernetworkpolicy.Policy{{PolicyRef: policyRef0}},
						Rules: []controllernetworkpolicy.Rule{
							{PolicyRef: policyRef0, Direction: cpv1beta.DirectionOut, RuleIndex: 0},
							{PolicyRef: policyRef0, Direction: cpv1beta.DirectionIn, RuleIndex: 0},
						},
					},
				},
			},
			expected: `Endpoint testNamespace/podA
Applied Policies:
Name                Namespace     UID  
test-ingress-egress testNamespace uid-1

Egress Rules:
Name                Namespace     Index UID  
test-ingress-egress testNamespace 0     uid-1

Ingress Rules:
Name                Namespace     Index UID  
test-ingress-egress testNamespace 0     uid-1

`,
		},
		{
			name: "Pod selected by 2 different policies",
			rawResponseData: &controllernetworkpolicy.EndpointQueryResponse{
				Endpoints: []controllernetworkpolicy.Endpoint{
					{
						Namespace: "testNamespace",
						Name:      "podA",
						Policies: []controllernetworkpolicy.Policy{
							{PolicyRef: policyRef0},
							{PolicyRef: policyRef1},
						},
						Rules: []controllernetworkpolicy.Rule{
							{PolicyRef: policyRef0, Direction: cpv1beta.DirectionOut, RuleIndex: 0},
							{PolicyRef: policyRef0, Direction: cpv1beta.DirectionIn, RuleIndex: 0},
						},
					},
				},
			},
			expected: `Endpoint testNamespace/podA
Applied Policies:
Name                Namespace     UID  
default-deny-egress testNamespace uid-2
test-ingress-egress testNamespace uid-1

Egress Rules:
Name                Namespace     Index UID  
test-ingress-egress testNamespace 0     uid-1

Ingress Rules:
Name                Namespace     Index UID  
test-ingress-egress testNamespace 0     uid-1

`,
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			cd := &commandDefinition{}
			var outputBuf bytes.Buffer
			err := cd.tableOutputForQueryEndpoint(tt.rawResponseData, &outputBuf)
			assert.Nil(t, err)
			assert.Equal(t, tt.expected, outputBuf.String())
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
