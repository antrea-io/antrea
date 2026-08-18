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

package observe

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

type outputFormat string

const (
	outputText  outputFormat = "text"
	outputTable outputFormat = "table"
	outputJSON  outputFormat = "json"
)

// renderer prints Flow records as they are received. render is called once per GetFlowsResponse
// batch, so records appear as the stream produces them: with --follow, there generally is no
// "once the command exits" moment to wait for and print everything at once.
type renderer interface {
	render(flows []*flowpb.Flow, droppedCount uint64) error
}

// writeBatch runs write against a buffer in front of out, and flushes it before returning. The
// output of a batch therefore reaches out in a few large writes rather than one per record, which is
// what dominates replaying a large history, while nothing is held back past the end of its batch,
// so --follow shows records as soon as the stream delivers them.
func writeBatch(out io.Writer, write func(w io.Writer) error) error {
	bw := bufio.NewWriter(out)
	if err := write(bw); err != nil {
		return err
	}
	return bw.Flush()
}

// newRenderer returns the renderer for format. Flow records are written to out; anything else the
// user should know about the stream, such as dropped flows, is written to errOut, so that it never
// mixes with the records a script is reading from out.
func newRenderer(format outputFormat, out, errOut io.Writer, humanReadableBytes bool, columns []column, noHeaders bool) renderer {
	dropped := droppedWarner{errOut: errOut}
	switch format {
	case outputJSON:
		return &jsonRenderer{out: out, dropped: dropped}
	case outputTable:
		return &tableRenderer{out: out, dropped: dropped, humanReadableBytes: humanReadableBytes, columns: columns, noHeaders: noHeaders}
	default:
		return &textRenderer{out: out, dropped: dropped, humanReadableBytes: humanReadableBytes}
	}
}

// droppedWarner tells the user that the Flow Aggregator dropped flows for this client. The count in
// each response is cumulative since the stream started, not per response, so it is reported only
// when it goes up: repeating an unchanged count on every batch would bury the records in warnings
// about something that is no longer happening.
type droppedWarner struct {
	// errOut is where the warning is written. With none, there is nowhere to warn, and nothing is.
	errOut io.Writer
	// reported is the largest count warned about so far.
	reported uint64
}

func (w *droppedWarner) warn(droppedCount uint64) error {
	if w.errOut == nil || droppedCount <= w.reported {
		return nil
	}
	w.reported = droppedCount
	_, err := fmt.Fprintf(w.errOut, "warning: %d flow(s) dropped since the stream started: this client fell behind the Flow Aggregator's ring buffer\n", droppedCount)
	return err
}

// record is a flattened, stable subset of flowpb.Flow's fields, used by both renderers. It
// deliberately does not embed the raw proto-generated struct: that struct is not meant to be
// marshaled directly with encoding/json, and a purpose-built shape keeps observe's output stable
// across proto schema changes that don't affect the fields surfaced here.
type record struct {
	EndTime                 string `json:"endTime"`
	SourceIP                string `json:"sourceIP"`
	DestinationIP           string `json:"destinationIP"`
	Protocol                uint32 `json:"protocol"`
	SourcePort              uint32 `json:"sourcePort"`
	DestinationPort         uint32 `json:"destinationPort"`
	SourcePodNamespace      string `json:"sourcePodNamespace"`
	SourcePodName           string `json:"sourcePodName"`
	DestinationPodNamespace string `json:"destinationPodNamespace"`
	DestinationPodName      string `json:"destinationPodName"`
	DestinationServiceName  string `json:"destinationServiceName"`
	FlowType                string `json:"flowType"`
	OctetTotalCount         uint64 `json:"octetTotalCount"`
	ReverseOctetTotalCount  uint64 `json:"reverseOctetTotalCount"`
	// SourceDisclosure, DestinationDisclosure and DestinationServiceDisclosure say how much of each
	// endpoint, and of the destination Service, the Flow Aggregator was allowed to tell this client
	// (see disclosureString). They are what distinguishes a field that was withheld from one that
	// never existed: redaction leaves a withheld field empty, and an empty field is also exactly what
	// an external endpoint, a cluster-scoped policy or a flow that never went through a Service looks
	// like. The Service has a marker of its own because it follows the tier of its own Namespace,
	// which is not necessarily the destination's.
	SourceDisclosure             string `json:"sourceDisclosure"`
	DestinationDisclosure        string `json:"destinationDisclosure"`
	DestinationServiceDisclosure string `json:"destinationServiceDisclosure"`

	SourcePodLabels                map[string]string `json:"sourcePodLabels"`
	DestinationPodLabels           map[string]string `json:"destinationPodLabels"`
	IngressNetworkPolicyNamespace  string            `json:"ingressNetworkPolicyNamespace"`
	IngressNetworkPolicyName       string            `json:"ingressNetworkPolicyName"`
	IngressNetworkPolicyType       string            `json:"ingressNetworkPolicyType"`
	IngressNetworkPolicyRuleName   string            `json:"ingressNetworkPolicyRuleName"`
	IngressNetworkPolicyRuleAction string            `json:"ingressNetworkPolicyRuleAction"`
	EgressNetworkPolicyNamespace   string            `json:"egressNetworkPolicyNamespace"`
	EgressNetworkPolicyName        string            `json:"egressNetworkPolicyName"`
	EgressNetworkPolicyType        string            `json:"egressNetworkPolicyType"`
	EgressNetworkPolicyRuleName    string            `json:"egressNetworkPolicyRuleName"`
	EgressNetworkPolicyRuleAction  string            `json:"egressNetworkPolicyRuleAction"`
	TCPState                       string            `json:"tcpState"`
	SourceNodeName                 string            `json:"sourceNodeName"`
	DestinationNodeName            string            `json:"destinationNodeName"`
	PacketTotalCount               uint64            `json:"packetTotalCount"`
	ReversePacketTotalCount        uint64            `json:"reversePacketTotalCount"`
	StartTime                      string            `json:"startTime"`
	EndReason                      string            `json:"endReason"`
	DestinationServiceIP           string            `json:"destinationServiceIP"`
	DestinationServicePort         uint32            `json:"destinationServicePort"`
	PacketDeltaCount               uint64            `json:"packetDeltaCount"`
	ReversePacketDeltaCount        uint64            `json:"reversePacketDeltaCount"`
	OctetDeltaCount                uint64            `json:"octetDeltaCount"`
	ReverseOctetDeltaCount         uint64            `json:"reverseOctetDeltaCount"`
	EgressName                     string            `json:"egressName"`
	EgressIP                       string            `json:"egressIP"`
	EgressNodeName                 string            `json:"egressNodeName"`
	ProxySnatIP                    string            `json:"proxySnatIP"`
	ProxySnatPort                  uint32            `json:"proxySnatPort"`
	Throughput                     uint64            `json:"throughput"`
	ReverseThroughput              uint64            `json:"reverseThroughput"`
}

// The values of record.SourceDisclosure, record.DestinationDisclosure and
// record.DestinationServiceDisclosure, one per flowpb.EndpointDisclosure.
const (
	disclosureFull     = "full"
	disclosureIdentity = "identity"
	disclosureFlow     = "flow"
)

// redactedMarker stands in, in text output, for an identity the Flow Aggregator withheld.
const redactedMarker = "<redacted>"

// disclosureString names a disclosure tier. The zero value is full, as in the protocol: a record that
// no stage redacted, which is every record on a cluster-wide stream, reads as fully disclosed.
func disclosureString(d flowpb.EndpointDisclosure) string {
	switch d {
	case flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_IDENTITY:
		return disclosureIdentity
	case flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW:
		return disclosureFlow
	default:
		return disclosureFull
	}
}

func toRecord(f *flowpb.Flow) record {
	r := record{
		Protocol:        f.GetTransport().GetProtocolNumber(),
		SourcePort:      f.GetTransport().GetSourcePort(),
		DestinationPort: f.GetTransport().GetDestinationPort(),
		TCPState:        f.GetTransport().GetTCP().GetStateName(),
		EndReason:       f.GetEndReason().String(),
		ProxySnatIP:     ipString(f.GetProxySnatIp()),
		ProxySnatPort:   f.GetProxySnatPort(),

		SourceDisclosure:             disclosureFull,
		DestinationDisclosure:        disclosureFull,
		DestinationServiceDisclosure: disclosureFull,
	}
	if ts := f.GetEndTs(); ts != nil {
		r.EndTime = ts.AsTime().Format(time.RFC3339)
	}
	if ts := f.GetStartTs(); ts != nil {
		r.StartTime = ts.AsTime().Format(time.RFC3339)
	}
	if ip := f.GetIp(); ip != nil {
		r.SourceIP = ipString(ip.GetSource())
		r.DestinationIP = ipString(ip.GetDestination())
	}
	if k8s := f.GetK8S(); k8s != nil {
		r.SourcePodNamespace = k8s.GetSourcePodNamespace()
		r.SourcePodName = k8s.GetSourcePodName()
		r.DestinationPodNamespace = k8s.GetDestinationPodNamespace()
		r.DestinationPodName = k8s.GetDestinationPodName()
		r.DestinationServiceName = k8s.GetDestinationServicePortName()
		r.FlowType = k8s.GetFlowType().String()
		r.SourceDisclosure = disclosureString(k8s.GetSourceDisclosure())
		r.DestinationDisclosure = disclosureString(k8s.GetDestinationDisclosure())
		r.DestinationServiceDisclosure = disclosureString(k8s.GetDestinationServiceDisclosure())
		r.SourcePodLabels = podLabels(k8s.GetSourcePodLabels())
		r.DestinationPodLabels = podLabels(k8s.GetDestinationPodLabels())
		r.SourceNodeName = k8s.GetSourceNodeName()
		r.DestinationNodeName = k8s.GetDestinationNodeName()
		r.DestinationServiceIP = ipString(k8s.GetDestinationServiceIp())
		r.DestinationServicePort = k8s.GetDestinationServicePort()
		r.IngressNetworkPolicyNamespace = k8s.GetIngressNetworkPolicyNamespace()
		r.IngressNetworkPolicyName = k8s.GetIngressNetworkPolicyName()
		r.IngressNetworkPolicyType = k8s.GetIngressNetworkPolicyType().String()
		r.IngressNetworkPolicyRuleName = k8s.GetIngressNetworkPolicyRuleName()
		r.IngressNetworkPolicyRuleAction = k8s.GetIngressNetworkPolicyRuleAction().String()
		r.EgressNetworkPolicyNamespace = k8s.GetEgressNetworkPolicyNamespace()
		r.EgressNetworkPolicyName = k8s.GetEgressNetworkPolicyName()
		r.EgressNetworkPolicyType = k8s.GetEgressNetworkPolicyType().String()
		r.EgressNetworkPolicyRuleName = k8s.GetEgressNetworkPolicyRuleName()
		r.EgressNetworkPolicyRuleAction = k8s.GetEgressNetworkPolicyRuleAction().String()
		r.EgressName = k8s.GetEgressName()
		r.EgressIP = ipString(k8s.GetEgressIp())
		r.EgressNodeName = k8s.GetEgressNodeName()
	}
	if stats := f.GetStats(); stats != nil {
		r.OctetTotalCount = stats.GetOctetTotalCount()
		r.PacketTotalCount = stats.GetPacketTotalCount()
		r.PacketDeltaCount = stats.GetPacketDeltaCount()
		r.OctetDeltaCount = stats.GetOctetDeltaCount()
	}
	if stats := f.GetReverseStats(); stats != nil {
		r.ReverseOctetTotalCount = stats.GetOctetTotalCount()
		r.ReversePacketTotalCount = stats.GetPacketTotalCount()
		r.ReversePacketDeltaCount = stats.GetPacketDeltaCount()
		r.ReverseOctetDeltaCount = stats.GetOctetDeltaCount()
	}
	if aggregation := f.GetAggregation(); aggregation != nil {
		r.Throughput = aggregation.GetThroughput()
		r.ReverseThroughput = aggregation.GetReverseThroughput()
	}
	return r
}

// podLabels preserves the protocol's distinction between unavailable labels (null in JSON) and
// an endpoint known to have no labels (an empty object), even when protobuf decoded an empty map as nil.
func podLabels(labels *flowpb.Labels) map[string]string {
	if labels == nil {
		return nil
	}
	if labels.Labels == nil {
		return map[string]string{}
	}
	return labels.Labels
}

func ipString(b []byte) string {
	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return ""
	}
	return addr.String()
}

func (r record) endpoint(isSource bool) string {
	namespace, name, ip := r.SourcePodNamespace, r.SourcePodName, r.SourceIP
	if !isSource {
		namespace, name, ip = r.DestinationPodNamespace, r.DestinationPodName, r.DestinationIP
	}
	if r.withheld(isSource) {
		// The address is disclosed even when the identity is not, and is all the client has to go on.
		// There is no space before it, so the cell stays a single whitespace-delimited token.
		label := redactedMarker
		if namespace != "" {
			label = namespace + "/" + label
		}
		if ip != "" {
			label += "(" + ip + ")"
		}
		return label
	}
	if name != "" {
		return fmt.Sprintf("%s/%s", namespace, name)
	}
	return placeholderIfEmpty(ip)
}

// disclosureOf returns the disclosure tier of an endpoint of this record, and the flow_type that
// marks that endpoint as external.
func (r record) disclosureOf(isSource bool) (disclosure, external string) {
	if isSource {
		return r.SourceDisclosure, flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL.String()
	}
	return r.DestinationDisclosure, flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL.String()
}

// withheld reports whether the Flow Aggregator withheld the identity of an endpoint of this record
// that is a workload in the cluster: its Pod name and labels. The disclosure tier alone cannot say:
// an external endpoint has no Namespace to authorize, so it is reported at the lowest tier although
// nothing was held back from it. flow_type is what tells the two apart, and is never redacted. The
// destination Service is not part of this: it follows the tier of its own Namespace, see
// serviceWithheld.
func (r record) withheld(isSource bool) bool {
	disclosure, external := r.disclosureOf(isSource)
	return disclosure == disclosureFlow && r.FlowType != external
}

// serviceWithheld reports whether the Flow Aggregator withheld the destination Service of this
// record: its name, address and port. The Service is withheld entirely or not at all, and a record
// that carries no Service is reported as disclosed, so unlike for an endpoint no flow_type is needed
// to tell a withheld Service from one that does not exist.
func (r record) serviceWithheld() bool {
	return r.DestinationServiceDisclosure == disclosureFlow
}

// placementWithheld reports whether the Flow Aggregator withheld where an endpoint of this record is
// placed: its Node, and for the source the Egress applied to it. Placement is withheld one tier
// before identity is, so an endpoint whose identity was disclosed may still have its placement
// withheld. As for withheld, an external endpoint has nothing to withhold.
func (r record) placementWithheld(isSource bool) bool {
	disclosure, external := r.disclosureOf(isSource)
	return (disclosure == disclosureIdentity || disclosure == disclosureFlow) && r.FlowType != external
}

// namespacedPolicyType reports whether a policy of this type, as named in record.IngressNetworkPolicyType
// and record.EgressNetworkPolicyType, belongs to the Namespace of the endpoint it selects. Any other
// type that is not unspecified counts as cluster-scoped, as it does for the Flow Aggregator.
func namespacedPolicyType(policyType string) bool {
	return policyType == flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_K8S.String() ||
		policyType == flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_ANP.String()
}

// policyWithheld reports whether the Flow Aggregator withheld the identity of the ingress or egress
// policy of this record: its Namespace, name and rule name. The type and action of a policy are never
// withheld. A namespaced policy is withheld with the endpoint it selects, the destination for an
// ingress policy and the source for an egress one, and cannot be told from its name: the implicit
// isolation drop of a Kubernetes NetworkPolicy is reported with a type and an action but no name,
// even when nothing is redacted. A cluster-scoped policy follows the cluster tier, which the record
// does not carry, but it always has a name, so an empty one is what a withheld policy looks like.
func (r record) policyWithheld(ingress bool) bool {
	policyType, name := r.EgressNetworkPolicyType, r.EgressNetworkPolicyName
	if ingress {
		policyType, name = r.IngressNetworkPolicyType, r.IngressNetworkPolicyName
	}
	switch {
	case policyType == flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_UNSPECIFIED.String():
		return false
	case namespacedPolicyType(policyType):
		return r.withheld(!ingress)
	default:
		return name == ""
	}
}

// policyNamespaceWithheld is policyWithheld for the Namespace of the policy. A cluster-scoped policy
// has none, so for one the empty Namespace is the actual value, even when its name is withheld.
func (r record) policyNamespaceWithheld(ingress bool) bool {
	policyType := r.EgressNetworkPolicyType
	if ingress {
		policyType = r.IngressNetworkPolicyType
	}
	return namespacedPolicyType(policyType) && r.policyWithheld(ingress)
}

// destinationNamespaceWithheld reports whether the Flow Aggregator withheld the Namespace of the
// destination. At the lowest tier the destination keeps its Namespace, except when the connection
// was denied: the client chose that address, and would otherwise learn the Namespace of any address
// it probes.
func (r record) destinationNamespaceWithheld() bool {
	return r.withheld(false) && r.DestinationPodNamespace == ""
}

// service is the Service of the table: a withheld Service is marked rather than left empty, which
// would read as a flow that never went through one.
func (r record) service() string {
	if r.serviceWithheld() {
		return redactedMarker
	}
	return placeholderIfEmpty(r.DestinationServiceName)
}

// textLine is the line of the text output. Its fields are separated by two spaces, and are always in
// the same order, with what a flow may not have, a Service, after what it always has, and the verdict
// of the policies last, so that the position of a field does not depend on those that follow it.
// What the Flow Aggregator withheld is marked as such, and what a flow has not got is left out, or
// is "-" or "N/A" when leaving it out would shift the rest.
func (r record) textLine(humanReadableBytes bool) string {
	fields := []string{
		r.textTime(),
		r.textEndpoint(true) + " -> " + r.textEndpoint(false),
		protocolName(r.Protocol),
		flowTypeText(r.FlowType),
	}
	if r.serviceWithheld() || r.DestinationServiceName != "" {
		fields = append(fields, "svc="+r.service())
	}
	// The first count is of the bytes sent by the source, the second of those sent back.
	count := func(n uint64) string {
		if humanReadableBytes {
			return formatBytes(n)
		}
		return strconv.FormatUint(n, 10)
	}
	fields = append(fields, "bytes="+count(r.OctetTotalCount)+"/"+count(r.ReverseOctetTotalCount))
	fields = append(fields, "Policy verdict: "+r.policyVerdict())
	return strings.Join(fields, "  ")
}

// textTime is the time at which the flow ended, in the time zone of the user, with the date since a
// history can reach back further than a day.
func (r record) textTime() string {
	t, err := time.Parse(time.RFC3339, r.EndTime)
	if err != nil {
		return placeholderIfEmpty(r.EndTime)
	}
	return t.Local().Format("Jan _2 15:04:05")
}

// textEndpoint is an endpoint with its port. A Pod is its Namespace and name followed by its address
// in parentheses, and an endpoint that is not a Pod is its address alone, in brackets if it is an IPv6
// one so that its port can be told from the rest of it. What was withheld is kept as endpoint has it.
func (r record) textEndpoint(isSource bool) string {
	ip, port, name := r.SourceIP, r.SourcePort, r.SourcePodName
	if !isSource {
		ip, port, name = r.DestinationIP, r.DestinationPort, r.DestinationPodName
	}
	label := r.endpoint(isSource)
	switch {
	case r.withheld(isSource):
		// endpoint has appended the address already.
	case name != "":
		if ip != "" {
			label += "(" + ip + ")"
		}
	case strings.Contains(ip, ":"):
		label = "[" + ip + "]"
	}
	if r.Protocol == protocolICMP || r.Protocol == protocolICMPv6 {
		// There are no ports.
		return label
	}
	return label + ":" + strconv.FormatUint(uint64(port), 10)
}

// The numbers of the protocols that observe names, or has no ports for.
const (
	protocolICMP   = 1
	protocolTCP    = 6
	protocolUDP    = 17
	protocolICMPv6 = 58
	protocolSCTP   = 132
)

// protocolName names an IP protocol, or has its number for one that is not often seen.
func protocolName(number uint32) string {
	switch number {
	case protocolICMP:
		return "ICMP"
	case protocolTCP:
		return "TCP"
	case protocolUDP:
		return "UDP"
	case protocolICMPv6:
		return "ICMPv6"
	case protocolSCTP:
		return "SCTP"
	}
	return strconv.FormatUint(uint64(number), 10)
}

// flowTypeText is a flow type as --flow-type names it.
func flowTypeText(flowType string) string {
	flowType = strings.TrimPrefix(flowType, "FLOW_TYPE_")
	if flowType == "" {
		return "-"
	}
	return strings.ToLower(strings.ReplaceAll(flowType, "_", "-"))
}

// policyVerdict is what the policies that applied to the flow made of it, followed by the policies
// that made it. A flow can have an ingress and an egress policy, each with an action of its own. The
// verdict is the worst of the two, a reject over a drop over an allow, and the policies named are
// those whose action it is: when both allow, both are named, and when one drops, only that one is.
// A flow that no policy applied to has no verdict, which is "N/A" and not nothing. The action of a
// policy is never withheld, so the verdict is known when the policy is not.
func (r record) policyVerdict() string {
	ingress, egress := ruleAction(r.IngressNetworkPolicyRuleAction), ruleAction(r.EgressNetworkPolicyRuleAction)
	for _, v := range []struct {
		action flowpb.NetworkPolicyRuleAction
		label  string
	}{
		{flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_REJECT, "REJECTED"},
		{flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP, "DROPPED"},
		{flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_ALLOW, "ALLOWED"},
	} {
		var by []string
		if egress == v.action {
			by = append(by, r.policyText(false))
		}
		if ingress == v.action {
			by = append(by, r.policyText(true))
		}
		if len(by) > 0 {
			return v.label + " " + strings.Join(by, ", ")
		}
	}
	return "N/A"
}

func ruleAction(name string) flowpb.NetworkPolicyRuleAction {
	return flowpb.NetworkPolicyRuleAction(flowpb.NetworkPolicyRuleAction_value[name])
}

// policyText names the policy of one direction: its direction, type, Namespace and name, and rule
// name. A policy has no name when it is the implicit isolation of a Kubernetes NetworkPolicy, which
// is not a withheld one (see policyWithheld), and then it is the direction and the type alone.
func (r record) policyText(ingress bool) string {
	direction, policyType, namespace, name, rule := "egress", r.EgressNetworkPolicyType, r.EgressNetworkPolicyNamespace,
		r.EgressNetworkPolicyName, r.EgressNetworkPolicyRuleName
	if ingress {
		direction, policyType, namespace, name, rule = "ingress", r.IngressNetworkPolicyType, r.IngressNetworkPolicyNamespace,
			r.IngressNetworkPolicyName, r.IngressNetworkPolicyRuleName
	}
	if policyType == flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_UNSPECIFIED.String() {
		return direction
	}
	text := direction + " " + strings.TrimPrefix(policyType, "NETWORK_POLICY_TYPE_")
	if r.policyWithheld(ingress) {
		return text + " " + redactedMarker
	}
	if name != "" {
		if namespace != "" {
			name = namespace + "/" + name
		}
		text += " " + name
	}
	if rule != "" {
		text += " (rule " + rule + ")"
	}
	return text
}

// placeholderIfEmpty substitutes "-" (kubectl's convention for "no value", e.g. <none>) for an
// empty field, so every column of the table always has a visible, whitespace-delimited token: an
// empty one is indistinguishable, positionally, from the separators around it. It is also how a value
// that does not exist is told from one that was withheld, which is redactedMarker.
func placeholderIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// jsonRenderer writes one JSON object per line (line-delimited, not a single closing array), so
// output can be consumed incrementally as the stream progresses, matching --follow's
// unbounded/indefinite nature.
//
// Every line is a record: the JSON field names are record's json tags. Dropped flows are not
// reported in the stream, since a line that is not a record would break a consumer that decodes
// every line as one; they are warned about on stderr instead (see droppedWarner).
type jsonRenderer struct {
	out     io.Writer
	dropped droppedWarner
}

func (jr *jsonRenderer) render(flows []*flowpb.Flow, droppedCount uint64) error {
	err := writeBatch(jr.out, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		for _, f := range flows {
			if err := enc.Encode(toRecord(f)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	// The records are flushed before the warning is written, so that the warning does not overtake
	// the records of its own batch when both go to the same terminal.
	return jr.dropped.warn(droppedCount)
}

// formatBytes renders n the way "ls -h"/"du -h" do: binary (1024-based) units, one decimal place
// once past whole bytes. Used only for --human-readable output; JSON output always uses the raw
// integer, since a machine consumer wants an exact number, not a string it has to re-parse.
func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	units := [...]string{"KB", "MB", "GB", "TB", "PB", "EB"}
	return fmt.Sprintf("%.1f%s", float64(n)/float64(div), units[exp])
}

// textRenderer prints one line per flow, for a person reading a terminal, as hubble observe does. The
// line is as long as what it says: nothing is padded, so that --follow has no column to widen, and
// nothing is truncated, so that a name is never cut into one that is another's. What is optional comes
// last (see record.textLine). A script should read the table or JSON output, which is meant for it.
type textRenderer struct {
	out                io.Writer
	dropped            droppedWarner
	humanReadableBytes bool
}

func (tr *textRenderer) render(flows []*flowpb.Flow, droppedCount uint64) error {
	err := writeBatch(tr.out, func(w io.Writer) error {
		for _, f := range flows {
			if _, err := fmt.Fprintln(w, toRecord(f).textLine(tr.humanReadableBytes)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tr.dropped.warn(droppedCount)
}

// tableRenderer prints one line of tab-separated columns per flow, headed by the names of the columns
// once, when the first flows arrive. It has no widths, so there is nothing to align or truncate, and
// nothing that changes as the stream goes on: that is left to the reader, for instance column -t -s$'\t'.
type tableRenderer struct {
	out                io.Writer
	dropped            droppedWarner
	humanReadableBytes bool
	columns            []column
	noHeaders          bool
	wroteHeader        bool
}

func (tr *tableRenderer) render(flows []*flowpb.Flow, droppedCount uint64) error {
	err := writeBatch(tr.out, func(w io.Writer) error {
		if !tr.wroteHeader && len(flows) > 0 {
			if !tr.noHeaders {
				if err := writeColumns(w, tr.columns, nil, tr.humanReadableBytes); err != nil {
					return err
				}
			}
			tr.wroteHeader = true
		}
		for _, f := range flows {
			r := toRecord(f)
			if err := writeColumns(w, tr.columns, &r, tr.humanReadableBytes); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tr.dropped.warn(droppedCount)
}
