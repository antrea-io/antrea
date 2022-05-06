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

	"antrea.io/antrea/pkg/agent/apiserver/handlers/agentinfo"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/ovsflows"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/podinterface"
	"antrea.io/antrea/pkg/agent/apiserver/handlers/serviceexternalip"
	"antrea.io/antrea/pkg/agent/openflow"
	fallbackversion "antrea.io/antrea/pkg/antctl/fallback/version"
	"antrea.io/antrea/pkg/antctl/raw/featuregates"
	"antrea.io/antrea/pkg/antctl/raw/multicluster"
	"antrea.io/antrea/pkg/antctl/raw/proxy"
	"antrea.io/antrea/pkg/antctl/raw/supportbundle"
	"antrea.io/antrea/pkg/antctl/raw/traceflow"
	"antrea.io/antrea/pkg/antctl/transform/addressgroup"
	"antrea.io/antrea/pkg/antctl/transform/appliedtogroup"
	"antrea.io/antrea/pkg/antctl/transform/controllerinfo"
	"antrea.io/antrea/pkg/antctl/transform/networkpolicy"
	"antrea.io/antrea/pkg/antctl/transform/ovstracing"
	"antrea.io/antrea/pkg/antctl/transform/policyrecocheck"
	"antrea.io/antrea/pkg/antctl/transform/policyrecoresult"
	"antrea.io/antrea/pkg/antctl/transform/policyrecostart"
	"antrea.io/antrea/pkg/antctl/transform/version"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	systemv1beta1 "antrea.io/antrea/pkg/apis/system/v1beta1"
	controllerinforest "antrea.io/antrea/pkg/apiserver/registry/system/controllerinfo"
	"antrea.io/antrea/pkg/client/clientset/versioned/scheme"
	controllernetworkpolicy "antrea.io/antrea/pkg/controller/networkpolicy"
	"antrea.io/antrea/pkg/flowaggregator/apiserver/handlers/flowrecords"
	"antrea.io/antrea/pkg/flowaggregator/apiserver/handlers/recordmetrics"
)

// CommandList defines all commands that could be used in the antctl for agents，
// controller or flow-aggregator. The unit test "TestCommandListValidation"
// ensures it to be valid.
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
				// print the antctl client version even if request to Controller fails
				requestErrorFallback: fallbackversion.RequestErrorFallback,
			},
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/version",
				},
				addonTransform: version.AgentTransform,
				// print the antctl client version even if request to Agent fails
				requestErrorFallback: fallbackversion.RequestErrorFallback,
			},
			flowAggregatorEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/version",
				},
				addonTransform: version.FlowAggregatorTransform,
				// print the antctl client version even if request to Flow Aggregator fails
				requestErrorFallback: fallbackversion.RequestErrorFallback,
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
			flowAggregatorEndpoint: &endpoint{
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
  $ antctl get networkpolicy -p ns1/pod1`,
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
					params: append([]flagInfo{
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
							usage:     "Get NetworkPolicies applied to the Pod. Pod format is podNamespace/podName.",
							shorthand: "p",
						},
						{
							name:      "type",
							usage:     "Get NetworkPolicies with specific type. Type means the type of its source network policy: K8sNP, ACNP, ANP",
							shorthand: "T",
						},
					}, getSortByFlag()),
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
  Dump OVS flows of a Service
  $ antctl get ovsflows -S svc1 -n ns1
  Dump OVS flows of a NetworkPolicy
  $ antctl get ovsflows -N np1 -n ns1
  Dump OVS flows of a flow Table
  $ antctl get ovsflows -T IngressRule
  Dump OVS groups
  $ antctl get ovsflows -G 10,20
  Dump all OVS groups
  $ antctl get ovsflows -G all

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
							name:      "service",
							usage:     "Name of a Service. If present, Namespace must be provided.",
							shorthand: "S",
						},
						{
							name:      "networkpolicy",
							usage:     "NetworkPolicy name. If present, Namespace must be provided.",
							shorthand: "N",
						},
						{
							name:      "table",
							usage:     "Comma separated Antrea OVS flow table names or numbers",
							shorthand: "T",
						},
						{
							name:      "groups",
							usage:     "Comma separated OVS group IDs. Use 'all' to dump all groups",
							shorthand: "G",
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
  $ antctl trace-packet -S ns1/pod1 -D ns2/svc2 -f tcp,tcp_dst=80
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
				addonTransform: ovstracing.Transform,
			},
			commandGroup:        flat,
			transformedResponse: reflect.TypeOf(""),
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
		{
			use:   "flowrecords",
			short: "Print the matching flow records in the flow aggregator",
			long:  "Print the matching flow records in the flow aggregator. It supports the 5-tuple flow key or a subset of the 5-tuple as a filter.",
			example: `  Get the list of flow records with a complete filter and output in json format
  $ antctl get flowrecords --srcip 10.0.0.1 --dstip 10.0.0.2 --proto 6 --srcport 1234 --dstport 5678 -o json
  Get the list of flow records with a partial filter, e.g. source address and source port
  $ antctl get flowrecords --srcip 10.0.0.1 --srcport 1234
  Get the list of all flow records
  $ antctl get flowrecords`,
			commandGroup: get,
			flowAggregatorEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/flowrecords",
					params: []flagInfo{
						{
							name:  "srcip",
							usage: "Get flow records with the source IP address.",
						},
						{
							name:  "dstip",
							usage: "Get flow records with the destination IP address.",
						},
						{
							name:  "proto",
							usage: "Get flow records with the protocol identifier.",
						},
						{
							name:  "srcport",
							usage: "Get flow records with the source port.",
						},
						{
							name:  "dstport",
							usage: "Get flow records with the destination port.",
						},
					},
					outputType: multiple,
				},
			},
			transformedResponse: reflect.TypeOf(flowrecords.Response{}),
		},
		{
			use:          "recordmetrics",
			short:        "Print record metrics related to flow aggregator",
			long:         "Print record metrics related to flow aggregator. It includes number of records received, number of records exported, number of flows stored and number of exporters connected to the flow aggregator.",
			commandGroup: get,
			flowAggregatorEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path:       "/recordmetrics",
					outputType: single,
				},
			},
			transformedResponse: reflect.TypeOf(recordmetrics.Response{}),
		},
		{
			use:          "serviceexternalip",
			short:        "Print Service external IP status",
			long:         "Print Service external IP status. It includes the external IP, external IP pool and the assigned Node for Services with type LoadBalancer managed by Antrea",
			commandGroup: get,
			aliases:      []string{"seip", "serviceexternalips"},
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/serviceexternalip",
					params: []flagInfo{
						{
							name:  "name",
							usage: "Name of the Service; if present, Namespace must be provided as well.",
							arg:   true,
						},
						{
							name:      "namespace",
							usage:     "Only get the external IP status for Services in the provided Namespace.",
							shorthand: "n",
						},
					},
					outputType: multiple,
				},
			},
			transformedResponse: reflect.TypeOf(serviceexternalip.Response{}),
		},
		{
			use:   "start",
			short: "Start policy recommendation Spark job",
			long:  "Start a new policy recommendation Spark job. Network policies will be recommended based on the flow records sent by Flow Aggregator.",
			example: `  Start a policy recommendation spark job with default configuration
  $ antctl policyReco start
  Start an initial policy recommendation spark job with network isolation option 1 and limit on last 10k flow records
  $ antctl policyReco start --type initial --option 1 --limit 10000
  Start an initial policy recommendation spark job with network isolation option 1 and limit on flow records from 2022-01-01 00:00:00 to 2022-01-31 23:59:59.
  $ antctl policyReco start --type initial --option 1 --start_time '2022-01-01 00:00:00' --end_time '2022-01-31 23:59:59'`,
			commandGroup: policyReco,
			flowAggregatorEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/policyrecostart",
					params: []flagInfo{
						{
							name: "type",
							usage: `{initial|subsequent} Indicates this recommendation is an initial recommendion or a subsequent recommendation job.
Default value is initial.`,
						},
						{
							name: "limit",
							usage: `The limit on the number of flow records read from the database. 0 means no limit.
Default value is 0 (no limit).`,
						},
						{
							name: "option",
							usage: `Option of network isolation preference in policy recommendation.
Currently we have 3 options:
1: Recommending allow ANP/ACNP policies, with default deny rules only on applied to Pod labels which have allow rules recommended.
2: Recommending allow ANP/ACNP policies, with default deny rules for whole cluster.
3: Recommending allow K8s network policies, with no deny rules at all
Default value is 1.`,
						},
						{
							name: "start_time",
							usage: `The start time of the flow records considered for the policy recommendation. 
Format is YYYY-MM-DD hh:mm:ss in UTC timezone. 
Default value is None, which means no limit of the start time of flow records.`,
						},
						{
							name: "end_time",
							usage: `The end time of the flow records considered for the policy recommendation.
Format is YYYY-MM-DD hh:mm:ss in UTC timezone.
Default value is None, which means no limit of the end time of flow records.`,
						},
						{
							name: "ns_allow_list",
							usage: `List of default traffic allow namespaces.
Default value is a list of Antrea CNI related namespaces: ['kube-system', 'flow-aggregator', 'flow-visibility'].`,
						},
						{
							name: "rm_labels",
							usage: `{true|false} Enable this option will remove automatically generated Pod labels including 'pod-template-hash', 'controller-revision-hash', 'pod-template-generation'.
Default value is true`,
						},
						{
							name: "to_services",
							usage: `{true|false} Use the toServices feature in ANP, only works when option is 1 or 2.
Default value is true.`,
						},
						{
							name: "driver_core_request",
							usage: `Specify the cpu request for the driver pod. Values conform to the Kubernetes convention. Example values include 0.1, 500m, 1.5, 5, etc.
Default value is 200m.`,
						},
						{
							name: "driver_memory",
							usage: `Specify the memory request for the driver pod. Values conform to the Kubernetes convention. Example values include 512M, 1G, 8G, etc.
Default value is 512M.`,
						},
						{
							name: "executor_core_request",
							usage: `Specify the cpu request for each executor pod. Values conform to the Kubernetes convention. Example values include 0.1, 500m, 1.5, 5, etc.
Default value is 200m.`,
						},
						{
							name: "executor_memory",
							usage: `Specify the memory request for each executor pod. Values conform to the Kubernetes convention. Example values include 512M, 1G, 8G, etc.
Default value is 512M.`,
						},
						{
							name: "executor_instances",
							usage: `Specify the number of executors for the spark application. Example values include 1, 2, 8, etc.
Default value is 1.`,
						},
					},
					outputType: single,
				},
				addonTransform: policyrecostart.Transform,
			},
			transformedResponse: reflect.TypeOf(""),
		},
		{
			use:   "check",
			short: "Check the status of policy recommendation Spark job by ID",
			example: `  Check the status of policy recommendation Spark job by ID
  $ antctl policyReco check --id c46091dd-5d82-46aa-a216-f66e42a1d19e4h6fd
  Check the status with job ID c46091dd-5d82-46aa-a216-f66e42a1d19e4h6fd`,
			commandGroup: policyReco,
			flowAggregatorEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/policyrecocheck",
					params: []flagInfo{
						{
							name:  "id",
							usage: "recommendation Spark job ID",
						},
					},
					outputType: single,
				},
				addonTransform: policyrecocheck.Transform,
			},
			transformedResponse: reflect.TypeOf(""),
		},
		{
			use:   "result",
			short: "Get the recommendation result of policy recommendation Spark job by ID",
			example: `  Get the recommendation result of policy recommendation Spark job by ID.
  $ antctl policyReco result --id c46091dd-5d82-46aa-a216-f66e42a1d19e4h6fd
  Get the recommendation result with job ID c46091dd-5d82-46aa-a216-f66e42a1d19e4h6fd`,
			commandGroup: policyReco,
			flowAggregatorEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/policyrecoresult",
					params: []flagInfo{
						{
							name:  "id",
							usage: "recommendation Spark job ID",
						},
					},
					outputType: single,
				},
				addonTransform: policyrecoresult.Transform,
			},
			transformedResponse: reflect.TypeOf(""),
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
		{
			cobraCommand:      featuregates.Command,
			supportAgent:      true,
			supportController: true,
			commandGroup:      get,
		},
		{
			cobraCommand:      multicluster.GetCmd,
			supportAgent:      false,
			supportController: false,
			commandGroup:      mc,
		},
	},
	codec: scheme.Codecs,
}

func generateFlowTableHelpMsg() string {
	msg := ""
	for _, t := range openflow.GetTableList() {
		msg += fmt.Sprintf("\n  %d\t%s", uint32(t.GetID()), t.GetName())
	}
	return msg
}
