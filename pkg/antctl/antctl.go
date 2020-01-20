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
	"reflect"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers/agentinfo"

	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/addressgroup"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/appliedtogroup"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/version"
	clusterinfov1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/v1beta1"
	networkingv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/scheme"
)

// CommandList defines all commands that could be used in the antctl for both agents
// and controller. The unit test "TestCommandListValidation" ensures it to be valid.
var CommandList = &commandList{
	definitions: []commandDefinition{
		{
			use:          "version",
			short:        "Print version information",
			long:         "Print version information of the antctl and the ${component}",
			commandGroup: flat,
			controllerEndpoint: &endpoint{
				resourceEndpoint: &resourceEndpoint{
					resourceName: "antrea-controller",
					groupVersionResource: &schema.GroupVersionResource{
						Group:    clusterinfov1beta1.SchemeGroupVersion.Group,
						Version:  clusterinfov1beta1.SchemeGroupVersion.Version,
						Resource: "antreacontrollerinfos",
					},
				},
				addonTransform: version.ControllerTransform,
			},
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/version",
				},
				addonTransform: version.AgentTransform,
			},
			transformedResponse: reflect.TypeOf(version.Response{}),
		},
		{
			use:          "network-policy",
			short:        "Print network policies",
			long:         "Print network policies in ${component}",
			commandGroup: get,
			controllerEndpoint: &endpoint{
				resourceEndpoint: &resourceEndpoint{
					groupVersionResource: &schema.GroupVersionResource{
						Group:    networkingv1beta1.SchemeGroupVersion.Group,
						Version:  networkingv1beta1.SchemeGroupVersion.Version,
						Resource: "networkpolicies",
					},
				},
				addonTransform: networkpolicy.Transform,
			},
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/networkpolicies",
					params: []flagInfo{
						{
							name:  "name",
							usage: "Retrieve resource by name",
							arg:   true,
						},
					},
				},
				addonTransform: networkpolicy.Transform,
			},
			transformedResponse: reflect.TypeOf(networkpolicy.Response{}),
		},
		{
			use:          "applied-to-group",
			short:        "Print applied-to-groups",
			long:         "Print applied-to-groups in ${component}",
			commandGroup: get,
			controllerEndpoint: &endpoint{
				resourceEndpoint: &resourceEndpoint{
					groupVersionResource: &schema.GroupVersionResource{
						Group:    networkingv1beta1.SchemeGroupVersion.Group,
						Version:  networkingv1beta1.SchemeGroupVersion.Version,
						Resource: "appliedtogroups",
					},
				},
				addonTransform: appliedtogroup.Transform,
			},
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/appliedtogroups",
					params: []flagInfo{
						{
							usage: "Retrieve resource by name",
							name:  "name",
							arg:   true,
						},
					},
				},
				addonTransform: appliedtogroup.Transform,
			},
			transformedResponse: reflect.TypeOf(appliedtogroup.Response{}),
		},
		{
			use:          "address-group",
			short:        "Print address groups",
			long:         "Print address groups in ${component}",
			commandGroup: get,
			controllerEndpoint: &endpoint{
				resourceEndpoint: &resourceEndpoint{
					groupVersionResource: &schema.GroupVersionResource{
						Group:    networkingv1beta1.SchemeGroupVersion.Group,
						Version:  networkingv1beta1.SchemeGroupVersion.Version,
						Resource: "addressgroups",
					},
				},
				addonTransform: addressgroup.Transform,
			},
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/addressgroups",
					params: []flagInfo{
						{
							usage: "Retrieve resource by name",
							name:  "name",
							arg:   true,
						},
					},
				},
				addonTransform: addressgroup.Transform,
			},
			transformedResponse: reflect.TypeOf(addressgroup.Response{}),
		},
		{
			use:   "agent-info",
			short: "Print agent's basic information",
			long:  "Print agent's basic information including version, node subnet, OVS info, AgentConditions, etc.",
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path:     "/agentinfo",
					isSingle: true,
				},
			},
			commandGroup:        flat,
			transformedResponse: reflect.TypeOf(agentinfo.AntreaAgentInfoResponse{}),
		},
	},
	codec: scheme.Codecs,
}
