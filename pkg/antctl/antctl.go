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
	"fmt"
	"reflect"

	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers/agentinfo"
	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers/ovsflows"
	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers/podinterface"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/addressgroup"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/appliedtogroup"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/controllerinfo"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/version"
	networkingv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
	systemv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/system/v1beta1"
	controllerinforest "github.com/vmware-tanzu/antrea/pkg/apiserver/registry/system/controllerinfo"
	"github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/scheme"
)

// CommandList defines all commands that could be used in the antctl for both agents
// and controller. The unit test "TestCommandListValidation" ensures it to be valid.
var CommandList = &commandList{
	definitions: []commandDefinition{
		{
			use:          "version",
			short:        "Print version information",
			long:         "Print version information of antctl and ${component}",
			commandGroup: flat,
			controllerEndpoint: &endpoint{
				resourceEndpoint: &resourceEndpoint{
					resourceName:         controllerinforest.ControllerInfoResourceName,
					groupVersionResource: &systemv1beta1.ControllerInfoVersionResource,
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
			use:     "networkpolicy",
			aliases: []string{"networkpolicies", "netpol"},
			short:   "Print NetworkPolicies",
			long:    "Print NetworkPolicies in ${component}. \"namespace\" is required if \"name\" is provided.",
			example: `  Get a specific NetworkPolicy
  $ antctl get networkpolicy np1 -n ns1
  Get the list of NetworkPolicies in a Namespace
  $ antctl get networkpolicy -n ns1
  Get the list of NetworkPolicies in all Namespaces
  $ antctl get networkpolicy
  Get the list of NetworkPolicies applied to a Pod (supported by agent only)
  $ antctl get networkpolicy -p pod1 -n ns1`,
			commandGroup: get,
			controllerEndpoint: &endpoint{
				resourceEndpoint: &resourceEndpoint{
					groupVersionResource: &networkingv1beta1.NetworkPolicyVersionResource,
					resourceName:         "",
					namespaced:           true,
				},
				addonTransform: networkpolicy.Transform,
			},
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/networkpolicies",
					params: []flagInfo{
						{
							name:  "name",
							usage: "Get NetworkPolicy by name. If present, Namespace must be provided.",
							arg:   true,
						},
						{
							name:      "namespace",
							usage:     "Get Networkpolicies from specific Namespace",
							shorthand: "n",
						},
						{
							name:      "pod",
							usage:     "Get NetworkPolicies applied to the Pod. If present, Namespace must be provided.",
							shorthand: "p",
						},
					},
				},
				addonTransform: networkpolicy.Transform,
			},
			transformedResponse: reflect.TypeOf(networkpolicy.Response{}),
		},
		{
			use:          "appliedtogroup",
			aliases:      []string{"appliedtogroups", "atg"},
			short:        "Print appliedto groups",
			long:         "Print appliedto groups in ${component}",
			commandGroup: get,
			controllerEndpoint: &endpoint{
				resourceEndpoint: &resourceEndpoint{
					groupVersionResource: &networkingv1beta1.AppliedToGroupVersionResource,
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
			use:          "addressgroup",
			aliases:      []string{"addressgroups", "ag"},
			short:        "Print address groups",
			long:         "Print address groups in ${component}",
			commandGroup: get,
			controllerEndpoint: &endpoint{
				resourceEndpoint: &resourceEndpoint{
					groupVersionResource: &networkingv1beta1.AddressGroupVersionResource,
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
			use:     "controllerinfo",
			aliases: []string{"controllerinfos", "ci"},
			short:   "Print Antrea controller's basic information",
			long:    "Print Antrea controller's basic information including version, deployment, NetworkPolicy controller, ControllerConditions, etc.",
			controllerEndpoint: &endpoint{
				resourceEndpoint: &resourceEndpoint{
					resourceName:         controllerinforest.ControllerInfoResourceName,
					groupVersionResource: &systemv1beta1.ControllerInfoVersionResource,
				},
				addonTransform: controllerinfo.Transform,
			},
			commandGroup:        get,
			transformedResponse: reflect.TypeOf(controllerinfo.Response{}),
		},
		{
			use:     "agentinfo",
			aliases: []string{"agentinfos", "ai"},
			short:   "Print agent's basic information",
			long:    "Print agent's basic information including version, deployment, Node subnet, OVS info, AgentConditions, etc.",
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path:       "/agentinfo",
					outputType: single,
				},
			},
			commandGroup:        get,
			transformedResponse: reflect.TypeOf(agentinfo.AntreaAgentInfoResponse{}),
		},
		{
			use:     "podinterface",
			aliases: []string{"podinterfaces", "pi"},
			short:   "Print Pod's network interface information",
			long:    "Print information about the network interface(s) created by the Antrea agent for the specified Pod.",
			example: `  Get a pod-interface
  $ antctl get podinterface pod1 -n ns1
  Get the list of podinterfaces in a Namespace
  $ antctl get podinterface -n ns1
  Get the list of podinterfaces whose names match in all Namespaces
  $ antctl get podinterface pod1
  Get the list of podinterfaces in all Namespaces
  $ antctl get podinterface`,
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/podinterfaces",
					params: []flagInfo{
						{
							name:  "name",
							usage: "Retrieve Pod interface by name. If present, Namespace must be provided.",
							arg:   true,
						},
						{
							name:      "namespace",
							usage:     "Get Pod interfaces from specific Namespace",
							shorthand: "n",
						},
					},
					outputType: multiple,
				},
			},
			commandGroup:        get,
			transformedResponse: reflect.TypeOf(podinterface.Response{}),
		},
		{
			use:     "ovsflows",
			aliases: []string{"of"},
			short:   "Dump OVS flows",
			long:    "Dump all the OVS flows or the flows installed for the specified entity.",
			example: `  Dump all OVS flows
  $ antctl get ovsflows
  Dump OVS flows of a local Pod
  $ antctl get ovsflows -p pod1 -n ns1
  Dump OVS flows of a NetworkPolicy
  $ antctl get ovsflows --networkpolicy np1 -n ns1
  Dump OVS flows of a flow Table
  $ antctl get ovsflows -t IngressRule

  Antrea OVS Flow Tables:` + generateFlowTableHelpMsg(),
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/ovsflows",
					params: []flagInfo{
						{
							name:      "namespace",
							usage:     "Namespace of the entity",
							shorthand: "n",
						},
						{
							name:      "pod",
							usage:     "Name of a local Pod. If present, Namespace must be provided.",
							shorthand: "p",
						},
						{
							name:  "networkpolicy",
							usage: "NetworkPolicy name. If present, Namespace must be provided.",
						},
						{
							name:      "table",
							usage:     "Antrea OVS flow table name or number",
							shorthand: "T",
						},
					},
					outputType: multiple,
				},
			},
			commandGroup:        get,
			transformedResponse: reflect.TypeOf(ovsflows.Response{}),
		},
	},
	codec: scheme.Codecs,
}

func generateFlowTableHelpMsg() string {
	msg := ""
	for _, t := range openflow.FlowTables {
		msg += fmt.Sprintf("\n  %d\t%s", uint32(t.Number), t.Name)
	}
	return msg
}
