// Copyright 2024 Antrea Authors
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

package output

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	agentapis "antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/antctl/transform/addressgroup"
	"antrea.io/antrea/pkg/antctl/transform/appliedtogroup"
	"antrea.io/antrea/pkg/antctl/transform/common"
	"antrea.io/antrea/pkg/antctl/transform/controllerinfo"
	"antrea.io/antrea/pkg/antctl/transform/networkpolicy"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/apiserver/apis"
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
			rawResponseData: agentapis.AntreaAgentInfoResponse{
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
			rawResponseData: []agentapis.PodInterfaceResponse{
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
		{
			name: "StructuredData-Memberlist-State",
			rawResponseData: []agentapis.MemberlistResponse{
				{
					NodeName: "node1",
					IP:       "192.168.1.2",
					Status:   "Alive",
				},
				{
					NodeName: "node2",
					IP:       "192.168.1.3",
					Status:   "Dead",
				},
			},
			expected: `NODE  IP          STATUS
node1 192.168.1.2 Alive 
node2 192.168.1.3 Dead  
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var outputBuf bytes.Buffer
			err := TableOutputForGetCommands(tc.rawResponseData, &outputBuf)
			fmt.Println(outputBuf.String())
			assert.Nil(t, err)
			assert.Equal(t, tc.expected, outputBuf.String())
		})
	}
}

func TestTableOutputForQueryEndpoint(t *testing.T) {
	policyRef0 := cpv1beta.NetworkPolicyReference{Namespace: "testNamespace", Name: "test-ingress-egress", UID: "uid-1", Type: cpv1beta.AntreaNetworkPolicy}
	policyRef1 := cpv1beta.NetworkPolicyReference{Namespace: "testNamespace", Name: "default-deny-egress", UID: "uid-2", Type: cpv1beta.AntreaNetworkPolicy}
	tc := []struct {
		name            string
		rawResponseData interface{}
		expected        string
	}{
		{
			name: "Pod selected by no policy",
			rawResponseData: &apis.EndpointQueryResponse{
				Endpoints: []apis.Endpoint{
					{Namespace: "testNamespace", Name: "podA", AppliedPolicies: []cpv1beta.NetworkPolicyReference{}, EgressDstRules: []apis.Rule{}, IngressSrcRules: []apis.Rule{}},
				},
			},
			expected: `Endpoint testNamespace/podA
Applied Policies on Endpoint: None

Egress Rules Referencing Endpoint as Destination: None

Ingress Rules Referencing Endpoint as Source: None

`,
		},
		{
			name: "Pod selected by 1 policy",
			rawResponseData: &apis.EndpointQueryResponse{
				Endpoints: []apis.Endpoint{
					{
						Namespace:       "testNamespace",
						Name:            "podA",
						AppliedPolicies: []cpv1beta.NetworkPolicyReference{policyRef0},
						EgressDstRules: []apis.Rule{
							{PolicyRef: policyRef0, Direction: cpv1beta.DirectionOut, RuleIndex: 0},
						},
						IngressSrcRules: []apis.Rule{
							{PolicyRef: policyRef0, Direction: cpv1beta.DirectionIn, RuleIndex: 0},
						},
					},
				},
			},
			expected: `Endpoint testNamespace/podA
Applied Policies on Endpoint:
Name                Namespace     UID  
test-ingress-egress testNamespace uid-1

Egress Rules Referencing Endpoint as Destination:
Name                Namespace     Index UID  
test-ingress-egress testNamespace 0     uid-1

Ingress Rules Referencing Endpoint as Source:
Name                Namespace     Index UID  
test-ingress-egress testNamespace 0     uid-1

`,
		},
		{
			name: "Pod selected by 2 different policies",
			rawResponseData: &apis.EndpointQueryResponse{
				Endpoints: []apis.Endpoint{
					{
						Namespace: "testNamespace",
						Name:      "podA",
						AppliedPolicies: []cpv1beta.NetworkPolicyReference{
							policyRef0, policyRef1,
						},
						EgressDstRules: []apis.Rule{
							{PolicyRef: policyRef0, Direction: cpv1beta.DirectionOut, RuleIndex: 0},
						},
						IngressSrcRules: []apis.Rule{
							{PolicyRef: policyRef0, Direction: cpv1beta.DirectionIn, RuleIndex: 0},
						},
					},
				},
			},
			expected: `Endpoint testNamespace/podA
Applied Policies on Endpoint:
Name                Namespace     UID  
default-deny-egress testNamespace uid-2
test-ingress-egress testNamespace uid-1

Egress Rules Referencing Endpoint as Destination:
Name                Namespace     Index UID  
test-ingress-egress testNamespace 0     uid-1

Ingress Rules Referencing Endpoint as Source:
Name                Namespace     Index UID  
test-ingress-egress testNamespace 0     uid-1

`,
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			var outputBuf bytes.Buffer
			err := TableOutputForQueryEndpoint(tt.rawResponseData, &outputBuf)
			assert.Nil(t, err)
			assert.Equal(t, tt.expected, outputBuf.String())
		})
	}
}
