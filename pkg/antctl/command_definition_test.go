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

	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers/agentinfo"
	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers/podinterface"
	"github.com/vmware-tanzu/antrea/pkg/antctl/runtime"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/addressgroup"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/appliedtogroup"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/common"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/controllerinfo"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/networkpolicy"
	cpv1beta "github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
	"github.com/vmware-tanzu/antrea/pkg/apis/crd/v1beta1"
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
			expected: `NAME       POD-IPS                                           
GroupName1 10.0.0.3,127.0.0.1,127.0.0.2,127.0.0.3 + 2 more...
GroupName2 <NONE>                                            
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
				transformedResponse: tc.responseStruct,
				controllerEndpoint:  &endpoint{addonTransform: tc.transform},
				agentEndpoint:       &endpoint{addonTransform: tc.transform},
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
