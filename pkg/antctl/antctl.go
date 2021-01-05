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
	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers/ovstracing"
	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers/podinterface"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/antctl/raw/proxy"
	"github.com/vmware-tanzu/antrea/pkg/antctl/raw/supportbundle"
	"github.com/vmware-tanzu/antrea/pkg/antctl/raw/traceflow"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/addressgroup"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/appliedtogroup"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/controllerinfo"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/version"
	cpv1beta "github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
	systemv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/system/v1beta1"
	controllerinforest "github.com/vmware-tanzu/antrea/pkg/apiserver/registry/system/controllerinfo"
	"github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/scheme"
	controllernetworkpolicy "github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy"
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
			use:   "log-level",
			short: "Show or set log verbosity level",
			long:  "Show or set the log verbosity level of ${component}",
			example: `  Show the current log verbosity level
  $ antctl log-level
  Set the log verbosity level to 2
  $ antctl log-level 2`,
			commandGroup: flat,
			controllerEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/loglevel",
					params: []flagInfo{
						{
							name:  "level",
							usage: "The integer log verbosity level to set",
							arg:   true,
						},
					},
					outputType: single,
				},
			},
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/loglevel",
					params: []flagInfo{
						{
							name:  "level",
							usage: "The integer log verbosity level to set",
							arg:   true,
						},
					},
					outputType: single,
				},
			},
			transformedResponse: reflect.TypeOf(0),
		},
		{
			use:     "networkpolicy",
			aliases: []string{"networkpolicies", "netpol"},
			short:   "Print control plane NetworkPolicies",
			long:    "Print control plane NetworkPolicies in ${component}. 'namespace' is required if 'pod' is provided.",
			example: `  Get a specific control plane NetworkPolicy
  $ antctl get networkpolicy 6001549b-ba63-4752-8267-30f52b4332db
  Get the list of all control plane NetworkPolicies
  $ antctl get networkpolicy
  Get the list of all control plane NetworkPolicies, sorted by the order in which the policies are evaluated.
  $ antctl get networkpolicy --sort-by=effectivePriority
  Get the control plane NetworkPolicy with a specific source (supported by agent only)
  $ antctl get networkpolicy -S allow-http -n ns1
  Get the list of control plane NetworkPolicies whose source NetworkPolicies are in a Namespace (supported by agent only)
  $ antctl get networkpolicy -n ns1
  Get the list of control plane NetworkPolicies with a specific source Type (supported by agent only)
  $ antctl get networkpolicy -T acnp
  Get the list of control plane NetworkPolicies applied to a Pod (supported by agent only)
  $ antctl get networkpolicy -p pod1 -n ns1`,
			commandGroup: get,
			controllerEndpoint: &endpoint{
				resourceEndpoint: &resourceEndpoint{
					groupVersionResource: &cpv1beta.NetworkPolicyVersionResource,
				},
				addonTransform: networkpolicy.Transform,
			},
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/networkpolicies",
					params: []flagInfo{
						{
							name:  "name",
							usage: "Get NetworkPolicy by name.",
							arg:   true,
						},
						{
							name:      "source",
							usage:     "Get NetworkPolicies for which the source has the provided name. The source of a control plane NetworkPolicy is the original policy resource (K8s NetworkPolicy or Antrea-native Policy) from which the control plane NetworkPolicy was derived.",
							shorthand: "S",
						},
						{
							name:      "namespace",
							usage:     "Get Networkpolicies from specific Namespace.",
							shorthand: "n",
						},
						{
							name:      "pod",
							usage:     "Get NetworkPolicies applied to the Pod. If present, Namespace must be provided.",
							shorthand: "p",
						},
						{
							name:      "type",
							usage:     "Get NetworkPolicies with specific type. Type means the type of its source network policy: K8sNP, ACNP, ANP",
							shorthand: "T",
						},
					},
					outputType: multiple,
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
					groupVersionResource: &cpv1beta.AppliedToGroupVersionResource,
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
					groupVersionResource: &cpv1beta.AddressGroupVersionResource,
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
  $ antctl get ovsflows -T IngressRule

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
							usage:     "Comma separated Antrea OVS flow table names or numbers",
							shorthand: "T",
						},
					},
					outputType: multiple,
				},
			},
			commandGroup:        get,
			transformedResponse: reflect.TypeOf(ovsflows.Response{}),
		},
		{
			use:   "trace-packet",
			short: "OVS packet tracing",
			long:  "Trace the OVS flows the specified packet traverses, leveraging OVS 'ofproto/trace'. Check ovs-vswitchd(8) manpage for more information about 'ofproto/trace'.",
			example: `  Trace an IP packet between two Pods
  $ antctl trace-packet -S ns1/pod1 -D ns2/pod2
  Trace a TCP packet from a local Pod to a Service
  $ antctl trace-packet -S ns1/pod1 -D ns2/srv2 -f tcp,tcp_dst=80
  Trace a UDP packet from a Pod to an IP address
  $ antctl trace-packet -S ns1/pod1 -D 10.1.2.3 -f udp,udp_dst=1234
  Trace an IP packet from a Pod to gateway port
  $ antctl trace-packet -S ns1/pod1 -D antrea-gw0
  Trace a UDP packet from an IP to a Pod
  $ antctl trace-packet -D ns1/pod1 -S 10.1.2.3 -f udp,udp_src=1234
  Trace an IP packet from OVS port using a specified source IP
  $ antctl trace-packet -p port1 -S 10.1.2.3 -D ns1/pod1
  Trace an ARP packet from a local Pod
  $ antctl trace-packet -p ns1/pod1 -f arp`,
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/ovstracing",
					params: []flagInfo{
						{
							name:      "port",
							usage:     "OVS port to input the tracing packet. Can be an OVS port name, or a local Pod (specified by <Namespace>/<name>). If not specified, the input port will be automatically figured out based on the 'source', and the gateway port will be used if `source` is not specified either. If specified, the 'in_port' field should not be added in the 'flow' argument.",
							shorthand: "p",
						},
						{
							name:      "source",
							usage:     "Source of the packet. Can be an OVS port name, or a (local or remote) Pod (specified by <Namespace>/<name>), or an IP address. If specified, the source's IP address will be used as the tracing packet's source IP address, and the 'nw_src'/'ipv6_src' field should not be added in the 'flow' argument.",
							shorthand: "S",
						},
						{
							name:      "destination",
							usage:     "Destination of the packet. Can be an OVS port name, or a (local or remote) Pod or a Service (specified by <Namespace>/<name>). If there are both a Pod and a Service matching the destination name in a Namespace, the Pod will be set as the destination. It can also be an IP address. If specified, the destination's IP address (the ClusterIP for a Service) will be used as the tacing packet's destination IP address, and the 'nw_dst' field should not be added in the 'flow' argument.",
							shorthand: "D",
						},
						{
							name:      "flow",
							usage:     "Specify the flow (packet headers) of the tracing packet. Check the flow syntax descriptions in ovs-ofctl(8) manpage.",
							shorthand: "f",
						},
						{
							name:      "addressFamily",
							usage:     "Specify the address family fo the packet. Can be 4 (IPv4) or 6 (IPv6). If not specified, the addressFamily will be automatically figured out based on the 'flow'. If no IP address or address family is given in the 'flow', IPv4 is used by default.",
							shorthand: "F",
						},
					},
					outputType: single,
				},
			},
			commandGroup:        flat,
			transformedResponse: reflect.TypeOf(ovstracing.Response{}),
		},
		{ // TODO: implement as a "rawCommand" (see supportbundle) so that the command can be run out-of-cluster
			use:     "endpoint",
			aliases: []string{"endpoints"},
			short:   "Filter network policies relevant to an endpoint.",
			long:    "Filter network policies relevant to an endpoint into three categories: network policies which apply to the endpoint and policies which select the endpoint in an ingress and/or egress rule.",
			example: `  Query network policies given Pod and Namespace
  $ antctl query endpoint -p pod1 -n ns1
`,
			commandGroup: query,
			controllerEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/endpoint",
					params: []flagInfo{
						{
							name:      "namespace",
							usage:     "Namespace of the endpoint (defaults to 'default')",
							shorthand: "n",
						},
						{
							name:      "pod",
							usage:     "Name of a Pod endpoint",
							shorthand: "p",
						},
					},
					outputType: single,
				},
			},
			transformedResponse: reflect.TypeOf(controllernetworkpolicy.EndpointQueryResponse{}),
		},
	},
	rawCommands: []rawCommand{
		{
			cobraCommand:      supportbundle.Command,
			supportAgent:      true,
			supportController: true,
		},
		{
			cobraCommand:      traceflow.Command,
			supportAgent:      true,
			supportController: true,
		},
		{
			cobraCommand:      proxy.Command,
			supportAgent:      false,
			supportController: true,
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
