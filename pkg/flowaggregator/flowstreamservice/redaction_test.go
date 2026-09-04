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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

// populatedFields lists the fields of m that carry a value, which for a proto3 message means the
// ones that are not at their zero value. Asserting on this list rather than on individual fields is
// what makes these tests notice a field added to the proto: a new field shows up in the list and
// has to be classified deliberately as disclosed or withheld.
func populatedFields(m proto.Message) []string {
	var names []string
	m.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		names = append(names, string(fd.Name()))
		return true
	})
	return names
}

// fullKubernetes returns Kubernetes metadata with every field populated, so that a redaction test
// can tell a field that was withheld from one that was never set.
func fullKubernetes() *flowpb.Kubernetes {
	return &flowpb.Kubernetes{
		FlowType: flowpb.FlowType_FLOW_TYPE_INTER_NODE,

		SourcePodNamespace: "ns-a",
		SourcePodName:      "source-pod",
		SourcePodUid:       "source-pod-uid",
		SourcePodLabels:    &flowpb.Labels{Labels: map[string]string{"app": "source"}},
		SourceNodeName:     "node-1",
		SourceNodeUid:      "node-1-uid",

		DestinationPodNamespace: "ns-b",
		DestinationPodName:      "destination-pod",
		DestinationPodUid:       "destination-pod-uid",
		DestinationPodLabels:    &flowpb.Labels{Labels: map[string]string{"app": "destination"}},
		DestinationNodeName:     "node-2",
		DestinationNodeUid:      "node-2-uid",

		DestinationClusterIp:       []byte{10, 96, 0, 1},
		DestinationServiceIp:       []byte{10, 96, 0, 1},
		DestinationServicePort:     80,
		DestinationServicePortName: "ns-b/service:http",
		DestinationServiceUid:      "service-uid",

		IngressNetworkPolicyType:       flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_K8S,
		IngressNetworkPolicyNamespace:  "ns-b",
		IngressNetworkPolicyName:       "allow-source",
		IngressNetworkPolicyUid:        "ingress-policy-uid",
		IngressNetworkPolicyRuleName:   "ingress-rule",
		IngressNetworkPolicyRuleAction: flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_ALLOW,

		EgressNetworkPolicyType:       flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_ANP,
		EgressNetworkPolicyNamespace:  "ns-a",
		EgressNetworkPolicyName:       "allow-destination",
		EgressNetworkPolicyUid:        "egress-policy-uid",
		EgressNetworkPolicyRuleName:   "egress-rule",
		EgressNetworkPolicyRuleAction: flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_ALLOW,

		EgressName:     "egress-1",
		EgressIp:       []byte{192, 168, 0, 1},
		EgressNodeName: "node-3",
		EgressNodeUid:  "node-3-uid",
		EgressUid:      "egress-uid",
	}
}

// fullFlow returns a record with every sub-message populated.
func fullFlow() *flowpb.Flow {
	return &flowpb.Flow{
		Id:            "flow-1",
		Ipfix:         &flowpb.IPFIX{ExporterIp: "10.0.0.1", SequenceNumber: 7},
		StartTs:       timestamppb.New(time.Unix(1700000000, 0)),
		EndTs:         timestamppb.New(time.Unix(1700000010, 0)),
		EndReason:     flowpb.FlowEndReason_FLOW_END_REASON_END_OF_FLOW,
		Ip:            &flowpb.IP{Version: flowpb.IPVersion_IP_VERSION_4, Source: []byte{10, 1, 1, 1}, Destination: []byte{10, 2, 2, 2}},
		Transport:     &flowpb.Transport{ProtocolNumber: 6, SourcePort: 12345, DestinationPort: 80},
		K8S:           fullKubernetes(),
		Stats:         &flowpb.Stats{PacketTotalCount: 10, OctetTotalCount: 1000},
		ReverseStats:  &flowpb.Stats{PacketTotalCount: 5, OctetTotalCount: 500},
		FlowDirection: flowpb.FlowDirection_FLOW_DIRECTION_EGRESS,
		Aggregation:   &flowpb.Aggregation{Throughput: 100},
		ProxySnatIp:   []byte{10, 10, 0, 1},
		ProxySnatPort: 54321,
	}
}

func TestRedactFlow_Kubernetes(t *testing.T) {
	// The fields every tier discloses: the flow's own shape, and the type and action of the
	// policies evaluated on each side.
	flowTier := []string{
		"flow_type",
		"ingress_network_policy_type", "ingress_network_policy_rule_action",
		"egress_network_policy_type", "egress_network_policy_rule_action",
	}
	// The identity tier adds the endpoint's own identity and the identity of the policy evaluated
	// on its side; the full tier adds placement, which is what identity deliberately stops short
	// of.
	sourceIdentity := []string{
		"source_pod_namespace", "source_pod_name", "source_pod_uid", "source_pod_labels",
		"egress_network_policy_namespace", "egress_network_policy_name", "egress_network_policy_uid", "egress_network_policy_rule_name",
	}
	sourceFull := []string{
		"source_node_name", "source_node_uid",
		"egress_name", "egress_ip", "egress_node_name", "egress_node_uid", "egress_uid",
	}
	destinationIdentity := []string{
		"destination_pod_namespace", "destination_pod_name", "destination_pod_uid", "destination_pod_labels",
		"destination_cluster_ip", "destination_service_ip", "destination_service_port", "destination_service_port_name", "destination_service_uid",
		"ingress_network_policy_namespace", "ingress_network_policy_name", "ingress_network_policy_uid", "ingress_network_policy_rule_name",
	}
	destinationFull := []string{"destination_node_name", "destination_node_uid"}

	tests := []struct {
		name        string
		source      disclosureTier
		destination disclosureTier
		// denied makes the record show a dropped connection, which withholds the Namespace of an
		// unidentified endpoint on top of everything else.
		denied bool
		want   []string
	}{
		{
			name:        "identity on both endpoints",
			source:      tierIdentity,
			destination: tierIdentity,
			want: concat(flowTier, sourceIdentity, destinationIdentity,
				[]string{"source_disclosure", "destination_disclosure"}),
		},
		{
			name:        "neither endpoint identified, connection allowed",
			source:      tierFlow,
			destination: tierFlow,
			want: concat(flowTier,
				// A Namespace is disclosed for an allowed connection: it is already discoverable
				// through CoreDNS, and an inbound connection has no other answer to "who called
				// my service?".
				[]string{"source_pod_namespace", "destination_pod_namespace"},
				[]string{"source_disclosure", "destination_disclosure"}),
		},
		{
			name:        "neither endpoint identified, connection denied",
			source:      tierFlow,
			destination: tierFlow,
			denied:      true,
			// A denied connection reveals neither where it came from nor where it was going, which
			// is what closes the Pod-CIDR-to-Namespace enumeration oracle.
			want: concat(flowTier, []string{"source_disclosure", "destination_disclosure"}),
		},
		{
			name:        "the client's own endpoint is disclosed in full",
			source:      tierFull,
			destination: tierFlow,
			// source_disclosure stays unset at tierFull: nothing was withheld for that endpoint.
			want: concat(flowTier, sourceIdentity, sourceFull,
				[]string{"destination_pod_namespace", "destination_disclosure"}),
		},
		{
			name:        "an identifiable peer of the client's own endpoint",
			source:      tierFull,
			destination: tierIdentity,
			want: concat(flowTier, sourceIdentity, sourceFull, destinationIdentity,
				[]string{"destination_disclosure"}),
		},
		{
			name:        "an inbound flow from an unidentified source",
			source:      tierFlow,
			destination: tierFull,
			want: concat(flowTier, destinationIdentity, destinationFull,
				[]string{"source_pod_namespace", "source_disclosure"}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := fullFlow()
			if tt.denied {
				f.K8S.IngressNetworkPolicyRuleAction = flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP
			}

			redacted := redactFlow(f, tt.source, tt.destination)

			assert.ElementsMatch(t, tt.want, populatedFields(redacted.GetK8S()))
			assert.Equal(t, tt.source.disclosure(), redacted.GetK8S().GetSourceDisclosure())
			assert.Equal(t, tt.destination.disclosure(), redacted.GetK8S().GetDestinationDisclosure())
		})
	}
}

// TestRedactFlow_FullKubernetesIsExhaustive fails if a field is added to the Kubernetes message
// without fullKubernetes being extended to populate it, since the redaction cases above could then
// silently stop covering it.
func TestRedactFlow_FullKubernetesIsExhaustive(t *testing.T) {
	fields := fullKubernetes().ProtoReflect().Descriptor().Fields()
	populated := nameSet(populatedFields(fullKubernetes()))
	for i := range fields.Len() {
		name := string(fields.Get(i).Name())
		if name == "source_disclosure" || name == "destination_disclosure" {
			// Only redaction sets these.
			continue
		}
		assert.Contains(t, populated, name, "fullKubernetes must populate every field of Kubernetes")
	}
}

// recordFieldsWithheld are the fields of Flow itself that a redacted record loses, and
// recordFieldsDisclosed the ones it keeps. Splitting Flow's fields into exactly these two lists is
// what makes the tests below notice a field added to the message: a new field belongs to neither
// list, so TestRedactFlow_RecordLevelFieldsAreClassified fails until it is deliberately put in one.
var (
	// The IPFIX exporter IP is the Node that reported the record, which belongs to neither
	// endpoint, so it goes as soon as either endpoint is not fully disclosed.
	recordFieldsWithheld = []string{"ipfix"}
	// Everything else about the flow itself survives. That includes the proxy SNAT address, which
	// only a from-external record carries, and which such a record can only reach a stream authorized
	// for its destination with; see redactFlow. "k8s" is here because the sub-message survives; which
	// of *its* fields do is covered by TestRedactFlow_Kubernetes.
	recordFieldsDisclosed = []string{
		"id", "start_ts", "end_ts", "end_reason", "ip", "transport", "k8s",
		"stats", "reverse_stats", "flow_direction", "aggregation",
		"proxy_snat_ip", "proxy_snat_port",
	}
)

// TestRedactFlow_RecordLevelFields covers the fields that belong to the record rather than to
// either endpoint. The exporter IP goes even though the source here is disclosed in full, which is
// also the case where an endpoint at tierFull loses a field while its own disclosure marker stays
// unset: a marker describes an endpoint, not the record it arrives on.
func TestRedactFlow_RecordLevelFields(t *testing.T) {
	f := fullFlow()

	redacted := redactFlow(f, tierFull, tierIdentity)

	assert.ElementsMatch(t, recordFieldsDisclosed, populatedFields(redacted))
	// Spot-check that a disclosed field carries the original value rather than merely being set.
	assert.Equal(t, "flow-1", redacted.GetId())
	assert.Equal(t, f.GetStats(), redacted.GetStats())
	assert.Equal(t, f.GetAggregation(), redacted.GetAggregation())
	assert.Equal(t, f.GetProxySnatIp(), redacted.GetProxySnatIp())
}

// TestRedactFlow_RecordLevelFieldsAreClassified fails if a field is added to the Flow message
// without being classified as disclosed or withheld, so that a new record-level field carrying
// placement (the way ipfix does) cannot be disclosed unnoticed. It is the record-level counterpart
// of TestRedactFlow_FullKubernetesIsExhaustive.
func TestRedactFlow_RecordLevelFieldsAreClassified(t *testing.T) {
	classified := nameSet(concat(recordFieldsDisclosed, recordFieldsWithheld))
	for _, name := range flowFieldNames() {
		assert.Contains(t, classified, name,
			"a new field of Flow must be classified as disclosed or withheld by redactFlow")
	}
}

// TestRedactFlow_FullFlowIsExhaustive fails if a field is added to Flow without fullFlow being
// extended to populate it, since the tests above could then silently stop covering it.
func TestRedactFlow_FullFlowIsExhaustive(t *testing.T) {
	populated := nameSet(populatedFields(fullFlow()))
	for _, name := range flowFieldNames() {
		assert.Contains(t, populated, name, "fullFlow must populate every field of Flow")
	}
}

// flowFieldNames lists the fields of Flow that redaction has to have an answer for, i.e. every
// field except the ones no producer populates anymore. Those are listed by name rather than read
// from the deprecated option, so that deprecating a field is not by itself enough to drop it out of
// these tests.
func flowFieldNames() []string {
	deprecated := nameSet([]string{"app"})
	fields := (&flowpb.Flow{}).ProtoReflect().Descriptor().Fields()
	names := make([]string, 0, fields.Len())
	for i := range fields.Len() {
		name := string(fields.Get(i).Name())
		if _, ok := deprecated[name]; ok {
			continue
		}
		names = append(names, name)
	}
	return names
}

// TestRedactFlow_ClusterScopedPolicy covers the case the disclosure marker exists for: a
// cluster-scoped policy has no Namespace to begin with, so a client must be able to tell that empty
// field apart from one that was withheld.
func TestRedactFlow_ClusterScopedPolicy(t *testing.T) {
	f := fullFlow()
	f.K8S.IngressNetworkPolicyType = flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_ACNP
	f.K8S.IngressNetworkPolicyNamespace = ""
	f.K8S.IngressNetworkPolicyName = "cluster-deny"
	f.K8S.IngressNetworkPolicyRuleAction = flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP

	// The policy ran on the destination's side, so the destination's tier decides.
	redacted := redactFlow(f, tierFull, tierFlow)

	// The action and type stay: the client learns that a cluster-scoped policy dropped its
	// connection, so it knows to escalate to the platform team rather than to the peer.
	assert.Equal(t, flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_ACNP, redacted.GetK8S().GetIngressNetworkPolicyType())
	assert.Equal(t, flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP, redacted.GetK8S().GetIngressNetworkPolicyRuleAction())
	// The identity does not, and the marker says the difference is a redaction.
	assert.Empty(t, redacted.GetK8S().GetIngressNetworkPolicyName())
	assert.Empty(t, redacted.GetK8S().GetIngressNetworkPolicyNamespace())
	assert.Equal(t, flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW, redacted.GetK8S().GetDestinationDisclosure())

	// The same policy evaluated on the client's own side is disclosed in full.
	redacted = redactFlow(f, tierFull, tierFull)
	assert.Equal(t, "cluster-deny", redacted.GetK8S().GetIngressNetworkPolicyName())
}

// TestRedactFlow_EgressPolicyFollowsTheSource pins down that a policy's fields are gated by the
// endpoint whose side it was evaluated on, not by where the policy object lives.
func TestRedactFlow_EgressPolicyFollowsTheSource(t *testing.T) {
	f := fullFlow()

	// The source is disclosed, the destination is not: the egress policy, evaluated at the source,
	// survives; the ingress policy, evaluated at the destination, does not.
	redacted := redactFlow(f, tierFull, tierFlow)
	assert.Equal(t, "allow-destination", redacted.GetK8S().GetEgressNetworkPolicyName())
	assert.Empty(t, redacted.GetK8S().GetIngressNetworkPolicyName())

	// And the other way around.
	redacted = redactFlow(f, tierFlow, tierFull)
	assert.Empty(t, redacted.GetK8S().GetEgressNetworkPolicyName())
	assert.Equal(t, "allow-source", redacted.GetK8S().GetIngressNetworkPolicyName())
}

// TestRedactFlow_PolicyIdentityIsDisclosedAtTierIdentity pins down where the boundary sits: naming
// the policy that governed a connection is what "get flows/identity" in the peer's Namespace buys,
// so that "which of your policies dropped my traffic" is answerable once that Namespace has
// consented to being identified. Placement is not part of that bargain.
func TestRedactFlow_PolicyIdentityIsDisclosedAtTierIdentity(t *testing.T) {
	f := fullFlow()

	redacted := redactFlow(f, tierIdentity, tierIdentity)

	assert.Equal(t, "allow-source", redacted.GetK8S().GetIngressNetworkPolicyName())
	assert.Equal(t, "ingress-rule", redacted.GetK8S().GetIngressNetworkPolicyRuleName())
	assert.Equal(t, "allow-destination", redacted.GetK8S().GetEgressNetworkPolicyName())
	assert.Equal(t, "egress-rule", redacted.GetK8S().GetEgressNetworkPolicyRuleName())
	// Placement stays behind, on both sides, and so does the Egress applied to the source.
	assert.Empty(t, redacted.GetK8S().GetSourceNodeName())
	assert.Empty(t, redacted.GetK8S().GetDestinationNodeName())
	assert.Empty(t, redacted.GetK8S().GetEgressName())
	assert.Empty(t, redacted.GetK8S().GetEgressIp())
}

// TestRedactFlow_IntraNodeSurvivesRedaction pins down a deliberate trade rather than a mechanism:
// FLOW_TYPE_INTRA_NODE is not collapsed to FLOW_TYPE_INTER_NODE for a redacted record, so co-tenancy
// with an endpoint the client can place is disclosed even though the peer's Node name is withheld.
// redactFlow's comment says why keeping the bit is the better call; this test is here so that
// revisiting that call has to be deliberate too, and so that the docs and the code cannot drift
// apart silently.
func TestRedactFlow_IntraNodeSurvivesRedaction(t *testing.T) {
	f := fullFlow()
	f.K8S.FlowType = flowpb.FlowType_FLOW_TYPE_INTRA_NODE

	tests := []struct {
		name        string
		source      disclosureTier
		destination disclosureTier
	}{
		{name: "peer unidentified", source: tierFull, destination: tierFlow},
		{name: "peer identified", source: tierFull, destination: tierIdentity},
		{name: "neither endpoint disclosed", source: tierFlow, destination: tierFlow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redacted := redactFlow(f, tt.source, tt.destination)

			assert.Equal(t, flowpb.FlowType_FLOW_TYPE_INTRA_NODE, redacted.GetK8S().GetFlowType())
			// Which Node is what stays withheld.
			assert.Empty(t, redacted.GetK8S().GetDestinationNodeName())
			assert.Empty(t, redacted.GetK8S().GetDestinationNodeUid())
		})
	}
}

func TestConnectionAllowed(t *testing.T) {
	tests := []struct {
		name    string
		ingress flowpb.NetworkPolicyRuleAction
		egress  flowpb.NetworkPolicyRuleAction
		want    bool
	}{
		{
			name: "no policy applied at all",
			want: true,
		},
		{
			name:    "allowed on both sides",
			ingress: flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_ALLOW,
			egress:  flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_ALLOW,
			want:    true,
		},
		{
			name:    "dropped at the destination",
			ingress: flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP,
			egress:  flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_ALLOW,
		},
		{
			name:   "rejected at the source",
			egress: flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_REJECT,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8s := &flowpb.Kubernetes{
				IngressNetworkPolicyRuleAction: tt.ingress,
				EgressNetworkPolicyRuleAction:  tt.egress,
			}
			assert.Equal(t, tt.want, connectionAllowed(k8s))
		})
	}
}

func TestShallowCopy(t *testing.T) {
	original := fullFlow()

	copied := shallowCopy(original)

	assert.NotSame(t, original, copied)
	assert.True(t, proto.Equal(original, copied), "a shallow copy must carry every populated field")
	// Sub-messages are shared, not duplicated, which is what makes this cheap enough for the
	// redaction path — and why a caller may only replace one wholesale, never modify it in place.
	assert.Same(t, original.GetK8S(), copied.GetK8S())
	assert.Same(t, original.GetStats(), copied.GetStats())
}

// TestShallowCopy_DropsUnknownFields covers the deliberate choice to fail closed on a record from a
// producer newer than this build: an unknown field cannot be authorized, so it is not carried over.
func TestShallowCopy_DropsUnknownFields(t *testing.T) {
	original := &flowpb.Kubernetes{SourcePodName: "source-pod"}
	original.ProtoReflect().SetUnknown(protoreflect.RawFields([]byte{0xfa, 0x3f, 0x01, 0x42}))
	require.NotEmpty(t, original.ProtoReflect().GetUnknown())

	copied := shallowCopy(original)

	assert.Equal(t, "source-pod", copied.GetSourcePodName())
	assert.Empty(t, copied.ProtoReflect().GetUnknown())
}

// concat flattens the field-name groups a test case is built from.
func concat(groups ...[]string) []string {
	var out []string
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// nameSet turns a list of field names into a lookup set.
func nameSet(names []string) map[string]struct{} {
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		out[n] = struct{}{}
	}
	return out
}
