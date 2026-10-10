// Copyright 2026 Antrea Authors
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

package flowstreamservice

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

// A flow crosses up to three segments on its way from the workload that initiated the connection to
// the one that received it. What a client may be told about the flow is decided one segment at a time.
// A segment's flow visibility grant covers the workload at its end and the policies enforced inside it:
//
//	┌────────────────────────────┐    ┌────────────────────────────┐    ┌────────────────────────────┐
//	│      SOURCE NAMESPACE      │    │          CLUSTER           │    │   DESTINATION NAMESPACE    │
//	│                            │    │                            │    │                            │
//	│ source workload            │    │ cluster-scoped policies    │    │ ingress policies           │
//	│   └▶ egress policies       │───▶│   (ACNP, K8s CNP)          │───▶│   (K8sNP, ANNP)            │
//	│      (K8sNP, ANNP)         │    │   egress, then ingress     │    │   └▶ destination workload  │
//	└────────────────────────────┘    └────────────────────────────┘    └────────────────────────────┘
//	   tier in source Namespace           tier held cluster-wide           tier in dest. Namespace
//
// Which segment a policy belongs to follows from what kind of policy it is, not from where in the
// flow it was evaluated: a namespaced policy (K8s NetworkPolicy, AntreaNetworkPolicy) belongs to the
// segment of the endpoint it selects, and a cluster-scoped one belongs to the cluster segment.
//
// disclosureTier is how much of one segment of a flow a client may be told. The two Namespace
// segments are resolved independently, so a single record commonly carries one at tierFull and the
// other at a lower tier.
type disclosureTier int

const (
	// tierFull discloses everything the record carries for the segment. It is not separately
	// grantable: it's based on client's flow visibility in the Namespace with the stream's own verb,
	// whether or not that Namespace is the one the stream was opened for.
	tierFull disclosureTier = iota
	// tierIdentity discloses the segment's workload identity (Namespace, Pod and Service) and the
	// identity of the policies enforced inside the segment, but not the workload's Node placement or
	// the Egress applied to it. It is what "get flows/identity" grants: enough to recognize the
	// workloads and to see which of its policies governed the connection, so that "which of your
	// policies dropped my traffic" is answerable between parties that have each consented to being
	// identified. Placement stays out of it: co-tenancy is not needed to author or debug a policy, so
	// granting identity does not hand a workload's Node over as a side effect. The exception is
	// co-tenancy with the *client's own* endpoint, which flow_type carries and which is deliberately
	// not redacted; see redactFlow. The cluster segment has no placement, so for it tierIdentity and
	// tierFull disclose the same.
	tierIdentity
	// tierFlow discloses only what the flow itself shows: addresses, ports, protocol, statistics,
	// timestamps, and the type and action of the policies. Whether the endpoint's Namespace is
	// disclosed too is a question about the peer, not about the segment: see redactFlow.
	tierFlow
)

// identifies reports whether the tier discloses the identity of what is inside the segment, which
// is what a policy's namespace, name, UID and rule name are.
func (t disclosureTier) identifies() bool {
	return t != tierFlow
}

// disclosure maps a tier to the marker sent to the client for that endpoint, so that a withheld
// field is never confused with one the Flow Aggregator did not have. tierFull maps to the zero
// value, which is why a record that never reached redaction reads as fully disclosed.
func (t disclosureTier) disclosure() flowpb.EndpointDisclosure {
	switch t {
	case tierIdentity:
		return flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_IDENTITY
	case tierFlow:
		return flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW
	default:
		return flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FULL
	}
}

// redactFlow returns a copy of f in which each segment is disclosed at its own tier: source and
// destination for the two Namespace segments, cluster for the cluster segment. The record itself is
// shared with every other stream, so it is copied rather than modified in place.
//
// The type and action of every policy are kept whatever the tiers. They tell the client why its
// connection failed and in which segment it was stopped, i.e. whether to look at its own policies,
// ask peer Namespace owners, or escalate to the platform team. What identifies a policy (its Namespace,
// name, UID and rule name) is disclosed only at the tier of the segment the policy belongs to.
//
// An endpoint at tierFlow loses its Pod identity but normally keeps its Namespace. The only case
// where the Namespace is withheld is for destination of a denied connection:
//
//   - When the Namespace that client opened the stream with initiated the connection, the destination
//     is an address the client chose. If a denied connection disclosed the destination's Namespace, the
//     client could probe every address in the Pod CIDR and build an IP-to-Namespace map of the cluster
//     from its own denials. An allowed connection adds nothing to that, since the Namespace is
//     discoverable through CoreDNS anyway.
//   - When a peer Namespace initiated it, authorizeFlow only lets such a record through if the
//     connection reached the client's Namespace. The client chose nothing here, and the peer's
//     Namespace is the answer to "who tried to reach my workloads".
//
// flow_type is kept even though FLOW_TYPE_INTRA_NODE tells the client that the peer shares a Node
// with its own workload. Without it, the client could not tell a genuinely external endpoint apart
// from one whose Namespace was withheld.
func redactFlow(f *flowpb.Flow, source, destination, cluster disclosureTier) *flowpb.Flow {
	// Only the Kubernetes sub-message is rewritten, so the copies share every other sub-message
	// with the original record instead of duplicating it.
	k8s := shallowCopy(f.GetK8S())

	// A policy's identity follows the segment it belongs to, which is the cluster's for a
	// cluster-scoped policy and the endpoint's it selects for a namespaced one.
	egressPolicySegment, ingressPolicySegment := source, destination
	if clusterScopedPolicy(k8s.GetEgressNetworkPolicyType()) {
		egressPolicySegment = cluster
	}
	if clusterScopedPolicy(k8s.GetIngressNetworkPolicyType()) {
		ingressPolicySegment = cluster
	}
	if !egressPolicySegment.identifies() {
		k8s.EgressNetworkPolicyNamespace = ""
		k8s.EgressNetworkPolicyName = ""
		k8s.EgressNetworkPolicyUid = ""
		k8s.EgressNetworkPolicyRuleName = ""
	}
	if !ingressPolicySegment.identifies() {
		k8s.IngressNetworkPolicyNamespace = ""
		k8s.IngressNetworkPolicyName = ""
		k8s.IngressNetworkPolicyUid = ""
		k8s.IngressNetworkPolicyRuleName = ""
	}

	if source != tierFull {
		// Node placement exposes co-tenancy, and is not needed to author a policy. The Node
		// name is what is withheld, not co-tenancy itself; see the note on flow_type above.
		k8s.SourceNodeName = ""
		k8s.SourceNodeUid = ""
		// An Egress applies to the source Pod's outbound traffic, and its IP and Node are
		// placement.
		k8s.EgressName = ""
		k8s.EgressIp = nil
		k8s.EgressNodeName = ""
		k8s.EgressNodeUid = ""
		k8s.EgressUid = ""
	}
	if source == tierFlow {
		// The source is the initiator, so its Namespace stays.
		k8s.SourcePodName = ""
		k8s.SourcePodUid = ""
		k8s.SourcePodLabels = nil
	}

	if destination != tierFull {
		k8s.DestinationNodeName = ""
		k8s.DestinationNodeUid = ""
	}
	if destination == tierFlow {
		k8s.DestinationPodName = ""
		k8s.DestinationPodUid = ""
		k8s.DestinationPodLabels = nil
		// The destination Service is identity belonging to the destination's Namespace, and a
		// ClusterIP maps back to it.
		k8s.DestinationServicePort = 0
		k8s.DestinationServicePortName = ""
		k8s.DestinationServiceUid = ""
		k8s.DestinationServiceIp = nil
		// deprecated, but must be redacted for as long as it is populated
		k8s.DestinationClusterIp = nil //nolint:staticcheck
		if !connectionAllowed(f.GetK8S()) {
			// The destination is the address the client picked, and the connection was denied.
			k8s.DestinationPodNamespace = ""
		}
	}

	k8s.SourceDisclosure = source.disclosure()
	k8s.DestinationDisclosure = destination.disclosure()

	redacted := shallowCopy(f)
	redacted.K8S = k8s
	// The IPFIX exporter IP is the Node that reported the record, which belongs to neither
	// endpoint. It is therefore disclosed only when both endpoints are, which costs the client
	// nothing, as it is export plumbing rather than user-facing data.
	if source != tierFull || destination != tierFull {
		redacted.Ipfix = nil
	}
	// proxy_snat_ip and proxy_snat_port are deliberately left alone. Only from-external correlation
	// populates them, which implies that the destination is in tierFull.
	return redacted
}

// namespacedPolicy reports whether a policy of this type lives in, and selects Pods of, a single
// Namespace: a K8s NetworkPolicy or an Antrea NetworkPolicy.
func namespacedPolicy(t flowpb.NetworkPolicyType) bool {
	return t == flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_K8S ||
		t == flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_ANP
}

// clusterScopedPolicy reports whether a policy of this type belongs to the cluster segment. A type
// that is neither unspecified (no policy was evaluated) nor known to be namespaced counts as
// cluster-scoped, which fails closed: a policy type added later is withheld from clients without a
// cluster-wide grant until it is classified here.
func clusterScopedPolicy(t flowpb.NetworkPolicyType) bool {
	return t != flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_UNSPECIFIED && !namespacedPolicy(t)
}

// clusterScopedPolicyApplied reports whether the record shows a cluster-scoped policy is hit on
// either egress or ingress side.
func clusterScopedPolicyApplied(k8s *flowpb.Kubernetes) bool {
	return clusterScopedPolicy(k8s.GetEgressNetworkPolicyType()) || clusterScopedPolicy(k8s.GetIngressNetworkPolicyType())
}

// connectionAllowed reports whether the record shows the connection as having been allowed. Anything
// other than an explicit drop or reject counts as allowed, including
// NETWORK_POLICY_RULE_ACTION_NO_ACTION, i.e. no policy applied at all: in a cluster without
// default-deny everything reads as allowed, which is acceptable, since such a cluster is not
// segmented and its Namespace names were trivially discoverable anyway.
func connectionAllowed(k8s *flowpb.Kubernetes) bool {
	return !denyAction(k8s.GetIngressNetworkPolicyRuleAction()) && !denyAction(k8s.GetEgressNetworkPolicyRuleAction())
}

func denyAction(action flowpb.NetworkPolicyRuleAction) bool {
	return action == flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP ||
		action == flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_REJECT
}

// shallowCopy returns a new message carrying every populated field of m. Sub-messages, lists and
// maps are shared with m rather than duplicated, which is what makes this far cheaper than
// proto.Clone on the redaction path: a flow record's statistics, aggregation state and Pod label
// maps are all left untouched and unduplicated.
//
// The caller may therefore only modify scalar fields of the returned message, or replace one of
// its sub-messages wholesale, and must never modify anything reachable through a sub-message it
// keeps, nor append to a list: doing so would also be modifying m, which for a flow record is
// shared with every other stream. It is implemented through protobuf reflection rather than by
// copying the fields of interest explicitly, so that a field added to the proto is carried over
// without this having to be revisited.
//
// Unknown fields are deliberately not carried over. They can only come from a producer newer than
// this build, so their contents cannot be authorized: were one of them to carry policy identity,
// it would be disclosed unredacted. Dropping them fails closed instead, and only affects the
// records that are redacted at all.
func shallowCopy[T proto.Message](m T) T {
	src := m.ProtoReflect()
	dst := src.New()
	// Range only visits populated fields, so unset scalars stay at their zero value in dst.
	src.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		dst.Set(fd, v)
		return true
	})
	return dst.Interface().(T)
}
