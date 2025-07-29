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

	agentapis "antrea.io/antrea/pkg/agent/apis"
	fallbackversion "antrea.io/antrea/pkg/antctl/fallback/version"
	checkcluster "antrea.io/antrea/pkg/antctl/raw/check/cluster"
	checkinstallation "antrea.io/antrea/pkg/antctl/raw/check/installation"
	"antrea.io/antrea/pkg/antctl/raw/featuregates"
	"antrea.io/antrea/pkg/antctl/raw/multicluster"
	"antrea.io/antrea/pkg/antctl/raw/packetcapture"
	"antrea.io/antrea/pkg/antctl/raw/proxy"
	"antrea.io/antrea/pkg/antctl/raw/set"
	"antrea.io/antrea/pkg/antctl/raw/supportbundle"
	"antrea.io/antrea/pkg/antctl/raw/traceflow"
	"antrea.io/antrea/pkg/antctl/raw/upgrade/apistorage"
	"antrea.io/antrea/pkg/antctl/transform/addressgroup"
	"antrea.io/antrea/pkg/antctl/transform/appliedtogroup"
	"antrea.io/antrea/pkg/antctl/transform/controllerinfo"
	"antrea.io/antrea/pkg/antctl/transform/networkpolicy"
	"antrea.io/antrea/pkg/antctl/transform/ovstracing"
	"antrea.io/antrea/pkg/antctl/transform/version"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	crdv1b1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	systemv1beta1 "antrea.io/antrea/pkg/apis/system/v1beta1"
	controllerapis "antrea.io/antrea/pkg/apiserver/apis"
	"antrea.io/antrea/pkg/client/clientset/versioned/scheme"
	aggregatorapis "antrea.io/antrea/pkg/flowaggregator/apis"
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
					resourceName:         crdv1b1.AntreaControllerInfoResourceName,
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
			use:   "podmulticaststats",
			short: "Show multicast statistics",
			long:  "Show multicast traffic statistics of Pods",
			example: `  Show multicast traffic statistics of all local Pods on the Node
$ antctl get podmulticaststats
Show multicast traffic statistics of a given Pod
$ antctl get podmulticaststats pod -n namespace`,
			commandGroup: get,
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path:       "/podmulticaststats",
					outputType: multiple,
					params: []flagInfo{
						{
							name:  "name",
							usage: "Retrieve Pod Multicast Statistics by name. If present, Namespace must be provided.",
							arg:   true,
						},
						{
							name:      "namespace",
							usage:     "Get Pod Multicast Statistics from specific Namespace.",
							shorthand: "n",
						},
					},
				},
			},

			transformedResponse: reflect.TypeOf(agentapis.MulticastResponse{}),
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
  Get the list of all control plane NetworkPolicies, sorted using the provided field specification.
  The list will be sorted by name if no value is provided.
  Any valid json path can be passed as an argument to the sort-by flag. E.g.: '.sourceRef.name'.
  $ antctl get networkpolicy --sort-by=''
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
					supportSorting:       true,
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
							name:            "type",
							usage:           "Get NetworkPolicies with specific type. Type refers to the type of its source NetworkPolicy: K8sNP, ACNP, ANNP, BANP or ANP",
							shorthand:       "T",
							supportedValues: []string{"K8sNP", "ACNP", "ANNP", "BANP", "ANP"},
						},
					}, getSortByFlag()),
					outputType: multiple,
				},
				addonTransform: networkpolicy.Transform,
			},
			transformedResponse: reflect.TypeOf(networkpolicy.Response{}),
		},
		{
			use:     "appliedtogroup",
			aliases: []string{"appliedtogroups", "atg"},
			short:   "Print appliedto groups",
			long:    "Print appliedto groups in ${component}",
			example: `  Get the list of all AppliedToGroups
  $ antctl get appliedtogroup
  Get the list of all control plane AppliedToGroups, sorted using the provided field specification.
  The list will be sorted by name if no value is provided.
  Any valid json path can be passed as an argument to the sort-by flag. E.g.: '.metadata.name'.
  $ antctl get appliedtogroup --sort-by=''`,
			commandGroup: get,
			controllerEndpoint: &endpoint{
				resourceEndpoint: &resourceEndpoint{
					groupVersionResource: &cpv1beta.AppliedToGroupVersionResource,
					supportSorting:       true,
				},
				addonTransform: appliedtogroup.Transform,
			},
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/appliedtogroups",
					params: append([]flagInfo{
						{
							usage: "Retrieve resource by name",
							name:  "name",
							arg:   true,
						},
					}, getSortByFlag()),
				},
				addonTransform: appliedtogroup.Transform,
			},
			transformedResponse: reflect.TypeOf(appliedtogroup.Response{}),
		},
		{
			use:     "addressgroup",
			aliases: []string{"addressgroups", "ag"},
			short:   "Print address groups",
			long:    "Print address groups in ${component}",
			example: `  Get the list of all AddressGroups
  $ antctl get addressgroup
  Get the list of all control plane AddressGroups, sorted using the provided field specification.
  The list will be sorted by name if no value is provided.
  Any valid json path can be passed as an argument to the sort-by flag. E.g.: '.metadata.name'.
  $ antctl get addressgroup --sort-by=''`,
			commandGroup: get,
			controllerEndpoint: &endpoint{
				resourceEndpoint: &resourceEndpoint{
					groupVersionResource: &cpv1beta.AddressGroupVersionResource,
					supportSorting:       true,
				},
				addonTransform: addressgroup.Transform,
			},
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/addressgroups",
					params: append([]flagInfo{
						{
							usage: "Retrieve resource by name",
							name:  "name",
							arg:   true,
						},
					}, getSortByFlag()),
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
					resourceName:         crdv1b1.AntreaControllerInfoResourceName,
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
			transformedResponse: reflect.TypeOf(agentapis.AntreaAgentInfoResponse{}),
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
			transformedResponse: reflect.TypeOf(agentapis.PodInterfaceResponse{}),
		},
		{
			use:     "ovsflows",
			aliases: []string{"of"},
			short:   "Dump OVS flows",
			long:    "Dump all the OVS flows or the flows installed for the specified entity.",
			example: `  Dump all OVS flows
  $ antctl get ovsflows
  Dump OVS table names only
  $ antctl get ovsflows --table-names-only
  Dump OVS flows of a local Pod
  $ antctl get ovsflows -p pod1 -n ns1
  Dump OVS flows of a Service
  $ antctl get ovsflows -S svc1 -n ns1
  Dump OVS flows of a NetworkPolicy
  $ antctl get ovsflows -N np1 -n ns1 --type K8sNP
  Dump OVS flows of a flow Table
  $ antctl get ovsflows -T IngressRule
  Dump OVS groups
  $ antctl get ovsflows -G 10,20
  Dump all OVS groups
  $ antctl get ovsflows -G all`,
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
							usage:     "NetworkPolicy name. Namespace must be provided for non-cluster-scoped policy types if a type is specified.",
							shorthand: "N",
						},
						{
							name:            "type",
							usage:           "NetworkPolicy type. Valid types are K8sNP, ACNP, ANNP, BANP or ANP.",
							supportedValues: []string{"K8sNP", "ACNP", "ANNP", "BANP", "ANP"},
						},
						{
							name:      "table",
							usage:     "Comma separated Antrea OVS flow table names or numbers",
							shorthand: "T",
						},
						{
							name:   "table-names-only",
							usage:  "Print all Antrea OVS flow table names only, and nothing else",
							isBool: true,
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
			transformedResponse: reflect.TypeOf(agentapis.OVSFlowResponse{}),
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
			transformedResponse: reflect.TypeOf(controllerapis.EndpointQueryResponse{}),
		},
		{
			use:     "networkpolicyevaluation",
			aliases: []string{"networkpoliciesevaluation", "networkpolicyeval", "networkpolicieseval", "netpoleval"},
			short:   "Analyze effective NetworkPolicy rules.",
			long:    "Analyze network policies in the cluster and return the rule expected to be effective on the source and destination endpoints provided.",
			example: `  Query effective NetworkPolicy rule between two Pods
  $ antctl query networkpolicyevaluation -S ns1/pod1 -D ns2/pod2
`,
			commandGroup: query,
			controllerEndpoint: &endpoint{
				resourceEndpoint: &resourceEndpoint{
					groupVersionResource: &cpv1beta.NetworkPolicyEvaluationVersionResource,
					params: []flagInfo{
						{
							name:      "source",
							usage:     "Source endpoint, specified by <Namespace>/<name>.",
							shorthand: "S",
						},
						{
							name:      "destination",
							usage:     "Destination endpoint, specified by <Namespace>/<name>.",
							shorthand: "D",
						},
					},
					parameterTransform: networkpolicy.NewNetworkPolicyEvaluation,
					restMethod:         restPost,
				},
				addonTransform: networkpolicy.EvaluationTransform,
			},
			transformedResponse: reflect.TypeOf(networkpolicy.EvaluationResponse{}),
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
			transformedResponse: reflect.TypeOf(aggregatorapis.FlowRecordsResponse{}),
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
			transformedResponse: reflect.TypeOf(aggregatorapis.RecordMetricsResponse{}),
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
			transformedResponse: reflect.TypeOf(agentapis.ServiceExternalIPInfo{}),
		},
		{
			use:          "memberlist",
			aliases:      []string{"ml"},
			short:        "Print state of memberlist cluster",
			long:         "Print state of memberlist cluster of Antrea agent",
			commandGroup: get,
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path:       "/memberlist",
					outputType: multiple,
				},
			},
			transformedResponse: reflect.TypeOf(agentapis.MemberlistResponse{}),
		},
		{
			use:   "bgppolicy",
			short: "Print effective bgppolicy information",
			long:  "Print effective bgppolicy information including name, local ASN, router ID, listen port and confederation identifier",
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path:       "/bgppolicy",
					outputType: single,
				},
			},
			commandGroup:        get,
			transformedResponse: reflect.TypeOf(agentapis.BGPPolicyResponse{}),
		},
		{
			use:     "bgppeers",
			aliases: []string{"bgppeer"},
			short:   "Print the current status of bgp peers of effective bgppolicy",
			long:    "Print the current status of bgp peers of effective bgppolicy which includes peer IP address with port, asn and state",
			example: `  Get the list of all bgp peers with their current status
  $ antctl get bgppeers
  Get the list of IPv4 bgp peers with their current status
  $ antctl get bgppeers --ipv4-only
  Get the list of IPv6 bgp peers with their current status
  $ antctl get bgppeers --ipv6-only
`,
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/bgppeers",
					params: []flagInfo{
						{
							name:   "ipv4-only",
							usage:  "Get IPv4 bgp peers only",
							isBool: true,
						},
						{
							name:   "ipv6-only",
							usage:  "Get IPv6 bgp peers only",
							isBool: true,
						},
					},
					outputType: multiple,
				},
			},
			commandGroup:        get,
			transformedResponse: reflect.TypeOf(agentapis.BGPPeerResponse{}),
		},
		{
			use:     "bgproutes",
			aliases: []string{"bgproute"},
			short:   "Print the advertised bgp routes.",
			long:    "Print the advertised bgp routes.",
			example: `  Get the list of all advertised bgp routes
  $ antctl get bgproutes
  Get the list of advertised IPv4 bgp routes
  $ antctl get bgproutes --ipv4-only
  Get the list of advertised IPv6 bgp routes
  $ antctl get bgproutes --ipv6-only
  Get the list of all advertised routes of a specific type
  $ antctl get bgproutes -T EgressIP
`,
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/bgproutes",
					params: []flagInfo{
						{
							name:   "ipv4-only",
							usage:  "Get advertised IPv4 bgp routes only",
							isBool: true,
						},
						{
							name:   "ipv6-only",
							usage:  "Get advertised IPv6 bgp routes only",
							isBool: true,
						},
						{
							name:            "type",
							shorthand:       "T",
							usage:           "Get advertised bgp routes of a specific type. Valid types are EgressIP, ServiceLoadBalancerIP, ServiceExternalIP, ServiceClusterIP or NodeIPAMPodCIDR.",
							supportedValues: []string{"EgressIP", "ServiceLoadBalancerIP", "ServiceExternalIP", "ServiceClusterIP", "NodeIPAMPodCIDR"},
						},
					},
					outputType: multiple,
				},
			},
			commandGroup:        get,
			transformedResponse: reflect.TypeOf(agentapis.BGPRouteResponse{}),
		},
		{
			use:   "fqdncache",
			short: "Print fqdn cache",
			long:  "Print effective fqdn cache information including fqdn name, IP addresses, and expiration time",
			example: `	Get the list of all fqdn rules currently applied
			$ antctl get fqdncache
			Get the list of all fqdn rules currently applied for a given domain name (wildcard supported)
			$ antctl get fqdncache --domain example.com
			$ antctl get fqdncache --domain *.antrea.io
			`,
			agentEndpoint: &endpoint{
				nonResourceEndpoint: &nonResourceEndpoint{
					path: "/fqdncache",
					params: []flagInfo{
						{
							name:      "domain",
							usage:     "Get fqdn cache for only a specific domain",
							shorthand: "d",
						},
					},
					outputType: multiple,
				},
			},
			commandGroup:        get,
			transformedResponse: reflect.TypeOf(agentapis.FQDNCacheResponse{}),
		},
	},
	rawCommands: []rawCommand{
		{
			cobraCommand:      checkinstallation.Command(),
			supportAgent:      false,
			supportController: false,
			commandGroup:      check,
		},
		{
			cobraCommand:      checkcluster.Command(),
			supportAgent:      false,
			supportController: false,
			commandGroup:      check,
		},
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
			cobraCommand:      packetcapture.Command,
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
		{
			cobraCommand:      multicluster.CreateCmd,
			supportAgent:      false,
			supportController: false,
			commandGroup:      mc,
		},
		{
			cobraCommand:      multicluster.DeployCmd,
			supportAgent:      false,
			supportController: false,
			commandGroup:      mc,
		},
		{
			cobraCommand:      multicluster.JoinCmd,
			supportAgent:      false,
			supportController: false,
			commandGroup:      mc,
		},
		{
			cobraCommand:      multicluster.LeaveCmd,
			supportAgent:      false,
			supportController: false,
			commandGroup:      mc,
		},
		{
			cobraCommand:      multicluster.InitCmd,
			supportAgent:      false,
			supportController: false,
			commandGroup:      mc,
		},
		{
			cobraCommand:      multicluster.DestroyCmd,
			supportAgent:      false,
			supportController: false,
			commandGroup:      mc,
		},
		{
			cobraCommand:      multicluster.DeleteCmd,
			supportAgent:      false,
			supportController: false,
			commandGroup:      mc,
		},
		{
			cobraCommand:          set.SetCmd,
			supportAgent:          false,
			supportController:     false,
			supportFlowAggregator: true,
		},
		{
			cobraCommand:      apistorage.NewCommand(),
			supportAgent:      false,
			supportController: false,
			commandGroup:      upgrade,
		},
	},
	codec: scheme.Codecs,
}
