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

// disclosureTier is how much of one endpoint of a flow a client may be told. Each endpoint is
// resolved to a tier independently of the other, so a single record commonly carries one endpoint
// at tierFull and the other at a lower tier.
type disclosureTier int

const (
	// tierFull discloses everything the record carries for the endpoint. It is not separately
	// grantable: it rides along on flow visibility into the endpoint's Namespace.
	tierFull disclosureTier = iota
	// tierIdentity discloses the endpoint's Namespace, Pod and Service identity, and the identity
	// of the network policy evaluated on its side, but not its Node placement or the Egress applied
	// to it. It is what "get flows/identity" in the endpoint's Namespace grants: enough for someone
	// to recognize that Namespace's workloads and to see which policy governed the connection, so
	// that "which of your policies dropped my traffic" is answerable between two Namespaces that
	// have each consented to being identified. Placement stays out of it: co-tenancy is not needed
	// to author or debug a policy, so a Namespace owner granting identity does not hand it over as
	// a side effect.
	tierIdentity
	// tierFlow discloses only what the flow itself shows: addresses, ports, protocol, statistics,
	// timestamps, and the type and action of the policies evaluated on the endpoint's side. The
	// endpoint's Namespace is disclosed too, but only if the connection was allowed.
	tierFlow
)

// disclosure maps a tier to the marker sent to the client for that endpoint, so that a withheld
// field is never confused with one the Flow Aggregator did not have.
func (t disclosureTier) disclosure() flowpb.EndpointDisclosure {
	switch t {
	case tierIdentity:
		return flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_IDENTITY
	case tierFlow:
		return flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW
	default:
		return flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_UNSPECIFIED
	}
}

// redactFlow returns a copy of f holding only what a client may see of each of its endpoints. It
// must not be called with both tiers at tierFull, which needs no copy at all; the caller sends the
// record itself in that case.
//
// The copy is necessary because a record is owned by the ring buffer and broadcast to every other
// stream, so it must never be modified in place.
//
// A policy's type and action are disclosed at every tier, its identity from tierIdentity up.
// Withholding the action would lose "why did my connection fail", which is most of the
// troubleshooting value, and the outcome of the client's own connection is theirs to know. Naming
// the policy and rule that produced it is what makes the answer actionable across a Namespace
// boundary, and it is gated on that Namespace having granted identity: an endpoint left at tierFlow
// discloses only that *something* of a given type allowed or dropped the connection, so a client
// cannot map a Namespace's policy set by probing unless that Namespace consented to being
// identified.
func redactFlow(f *flowpb.Flow, source, destination disclosureTier) *flowpb.Flow {
	// Only the Kubernetes sub-message is rewritten, so the copies share every other sub-message
	// with the original record instead of duplicating it.
	k8s := shallowCopy(f.GetK8S())
	// Whether the connection was allowed is read from the original record, and decides whether an
	// unidentified endpoint's Namespace survives.
	allowed := connectionAllowed(f.GetK8S())

	if source != tierFull {
		// Node placement is withheld above tierFull: it exposes co-tenancy, which feeds
		// noisy-neighbor and side-channel work, and it is not needed to author a policy.
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
		k8s.SourcePodName = ""
		k8s.SourcePodUid = ""
		k8s.SourcePodLabels = nil
		// The egress policy is the one evaluated on the source's side, so it follows the source's
		// tier — whether the policy object itself is namespaced (K8S, ANP) or cluster-scoped
		// (ACNP, K8SCNP). Its type and action stay even here: knowing that a cluster-scoped policy
		// dropped the connection, rather than a namespaced one, tells the client whether to
		// escalate to the platform team or to the peer, without naming the policy.
		k8s.EgressNetworkPolicyNamespace = ""
		k8s.EgressNetworkPolicyName = ""
		k8s.EgressNetworkPolicyUid = ""
		k8s.EgressNetworkPolicyRuleName = ""
		if !allowed {
			// A denied connection does not reveal where it came from or where it was going. This
			// closes a Pod-CIDR enumeration oracle: without it, a client could scan the Pod CIDR,
			// read back its own denied flows, and build an IP-to-Namespace map of the whole
			// cluster — which, where Namespace names encode customer identity, is a customer
			// list. Restricting disclosure to allowed connections defeats that, since a scanner's
			// probes are denied by definition. It costs the client nothing for a connection it
			// initiated: it chose the address it failed to reach.
			k8s.SourcePodNamespace = ""
		}
	}

	if destination != tierFull {
		k8s.DestinationNodeName = ""
		k8s.DestinationNodeUid = ""
	}
	if destination == tierFlow {
		k8s.DestinationPodName = ""
		k8s.DestinationPodUid = ""
		k8s.DestinationPodLabels = nil
		// The ingress policy is the one evaluated on the destination's side.
		k8s.IngressNetworkPolicyNamespace = ""
		k8s.IngressNetworkPolicyName = ""
		k8s.IngressNetworkPolicyUid = ""
		k8s.IngressNetworkPolicyRuleName = ""
		// The destination Service is identity belonging to the destination's Namespace, and a
		// ClusterIP maps back to it.
		k8s.DestinationServicePort = 0
		k8s.DestinationServicePortName = ""
		k8s.DestinationServiceUid = ""
		k8s.DestinationServiceIp = nil
		k8s.DestinationClusterIp = nil //nolint:staticcheck // deprecated, but must be redacted for as long as it is populated
		if !allowed {
			k8s.DestinationPodNamespace = ""
		}
	}

	k8s.SourceDisclosure = source.disclosure()
	k8s.DestinationDisclosure = destination.disclosure()

	redacted := shallowCopy(f)
	redacted.K8S = k8s
	// The remaining fields cannot be attributed to one endpoint, so they are disclosed only when
	// both endpoints are: the IPFIX exporter IP is the Node that reported the record, and the
	// proxy SNAT IP is the gateway IP of whichever Node applied the SNAT. Both are placement, and
	// both would otherwise reach past the tier of the endpoint they describe. Neither is
	// user-facing data: ipfix is export plumbing.
	redacted.Ipfix = nil
	redacted.ProxySnatIp = nil
	redacted.ProxySnatPort = 0
	return redacted
}

// connectionAllowed reports whether the record shows the connection as having been allowed, which
// is what decides whether an unidentified endpoint's Namespace is disclosed. Anything other than
// an explicit drop or reject counts as allowed, including NETWORK_POLICY_RULE_ACTION_NO_ACTION,
// i.e. no policy applied at all: in a cluster without default-deny everything reads as allowed,
// which is acceptable, since such a cluster is not segmented and its Namespace names were
// trivially discoverable anyway.
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
