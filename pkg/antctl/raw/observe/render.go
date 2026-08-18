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
	"strings"
	"time"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

type outputFormat string

const (
	outputText outputFormat = "text"
	outputJSON outputFormat = "json"
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
func newRenderer(format outputFormat, out, errOut io.Writer, humanReadableBytes bool, columns []column) renderer {
	dropped := droppedWarner{errOut: errOut}
	if format == outputJSON {
		return &jsonRenderer{out: out, dropped: dropped}
	}
	return &textRenderer{out: out, dropped: dropped, humanReadableBytes: humanReadableBytes, columns: columns}
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
	// SourceDisclosure and DestinationDisclosure say how much of each endpoint the Flow Aggregator
	// was allowed to tell this client (see disclosureString). They are what distinguishes a field
	// that was withheld from one that never existed: redaction leaves a withheld field empty, and an
	// empty field is also exactly what an external endpoint, a cluster-scoped policy or a flow that
	// never went through a Service looks like.
	SourceDisclosure      string `json:"sourceDisclosure"`
	DestinationDisclosure string `json:"destinationDisclosure"`

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

// The values of record.SourceDisclosure and record.DestinationDisclosure, one per
// flowpb.EndpointDisclosure.
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

		SourceDisclosure:      disclosureFull,
		DestinationDisclosure: disclosureFull,
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
			label = truncatePrefix(namespace, maxNamespaceDisplayLen) + "/" + label
		}
		if ip != "" {
			label += "(" + ip + ")"
		}
		return label
	}
	if name != "" {
		return fmt.Sprintf("%s/%s", truncatePrefix(namespace, maxNamespaceDisplayLen), truncateSuffix(name, maxPodNameDisplayLen))
	}
	return placeholderIfEmpty(ip)
}

// withheld reports whether the Flow Aggregator withheld the identity of an endpoint of this record
// that is a workload in the cluster. The disclosure tier alone cannot say: an external endpoint has
// no Namespace to authorize, so it is reported at the lowest tier although nothing was held back from
// it. flow_type is what tells the two apart, and is never redacted.
func (r record) withheld(isSource bool) bool {
	disclosure, external := r.SourceDisclosure, flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL
	if !isSource {
		disclosure, external = r.DestinationDisclosure, flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL
	}
	return disclosure == disclosureFlow && r.FlowType != external.String()
}

// service is the text SERVICE column. A withheld Service is marked rather than left empty, which
// would read as a flow that never went through one.
func (r record) service() string {
	if r.withheld(false) {
		return redactedMarker
	}
	return placeholderIfEmpty(truncateServiceName(r.DestinationServiceName))
}

// maxNamespaceDisplayLen and maxPodNameDisplayLen bound how much of a Namespace/Pod name
// endpoint() shows in the text table before truncating with "...", so that the SOURCE/DESTINATION
// columns stay a fixed, alignable width even for a pathologically long generated name, without
// reintroducing the old "%-30.30s" bug's silent truncation (see truncatePrefix/truncateSuffix).
// Both are comfortably above what this repo's own e2e tests generate (e.g. "testantctlobserve-"
// plus an 8-character random suffix is 26 characters), so ordinary output is never truncated —
// this only kicks in for names well beyond typical length.
//
// Namespace is truncated from the back of the budget, i.e. kept as a prefix: Namespace names are
// usually meaningful start to finish, and even generated test Namespaces put the informative part
// first, followed by a random suffix. Pod name is truncated from the front of the budget, i.e.
// kept as a suffix: Kubernetes Pod names are "<Deployment>-<ReplicaSet hash>-<random suffix>", and
// that trailing random suffix is what actually distinguishes two Pods of the same Deployment from
// each other — keeping the front instead would risk two different Pods displaying identically.
//
// maxPodNameDisplayLen is wider than maxNamespaceDisplayLen because that "<ReplicaSet hash>-<random
// suffix>" tail alone is already 16 characters, so even an ordinary, short Deployment name (e.g.
// "flow-aggregator", 15 characters) produces a 32-character Pod name — comfortably over 30 despite
// not being an outlier in any way. 40 leaves room for the hash/suffix plus a ~24-character
// Deployment name without truncating anything routine.
const (
	maxNamespaceDisplayLen = 30
	maxPodNameDisplayLen   = 40
)

// truncatePrefix keeps the first maxLen characters of s, replacing the rest with "...", so a
// truncated value is always visually distinguishable from a genuinely short one (unlike the old
// "%-30.30s", which silently produced the same output for both).
func truncatePrefix(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// truncateSuffix is truncatePrefix's mirror image: it keeps the last maxLen characters.
func truncateSuffix(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return "..." + s[len(s)-maxLen:]
}

// maxServiceNameDisplayLen bounds the "<name>:<port>" portion of a Service's
// "<namespace>/<name>:<port>" identifier (see truncateServiceName), truncated as a suffix so the
// port name survives — the same reasoning as maxPodNameDisplayLen: a Service can have several
// ports (e.g. flow-aggregator's "grpc" and "flowstream-grpc"), and the port name at the very end
// is what distinguishes flows to one from flows to the other. Unlike Pod names, Service names
// carry no Kubernetes-generated hash/suffix tax, so this does not need extra headroom for that.
const maxServiceNameDisplayLen = 30

// truncateServiceName truncates a "<namespace>/<name>:<port>" Service identifier the same way
// endpoint() truncates a Pod identifier: the Namespace is truncated as a prefix, the "<name>:<port>"
// portion as a suffix. Falls back to a plain prefix truncation of the whole string for the rare
// value with no "/" (e.g. a Service identifier without Namespace information).
func truncateServiceName(s string) string {
	namespace, rest, ok := strings.Cut(s, "/")
	if !ok {
		return truncatePrefix(s, serviceColumnWidth)
	}
	return fmt.Sprintf("%s/%s", truncatePrefix(namespace, maxNamespaceDisplayLen), truncateSuffix(rest, maxServiceNameDisplayLen))
}

// placeholderIfEmpty substitutes "-" (kubectl's convention for "no value", e.g. <none>) for an
// empty field, so every column in the text output always has a visible, whitespace-delimited
// token: a column left as pure padding is indistinguishable, positionally, from the whitespace
// between columns.
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

// textRenderer prints one fixed-width line per flow. It deliberately does not use text/tabwriter:
// tabwriter aligns columns per Flush() call, and with --follow there is no single point at which
// all rows are known, so column widths would visibly jump between batches. Fixed-width fields
// avoid that at the cost of long values (e.g. deeply-nested Namespace/Pod names) not lining up
// perfectly — the same trade-off tools like "kubectl logs -f" make for the same reason.
type textRenderer struct {
	out                io.Writer
	dropped            droppedWarner
	wroteHeader        bool
	humanReadableBytes bool
	columns            []column
}

// endpointColumnWidth accommodates both a truncated Namespace/Pod name and a truncated Namespace
// followed by <redacted>(IP). An IPv6 address can take 39 characters, including its colons.
const endpointColumnWidth = maxNamespaceDisplayLen + len("...") + len("/") +
	max(maxPodNameDisplayLen+len("..."), len(redactedMarker)+len("()")+39)

// serviceColumnWidth is the SERVICE column width, computed the same way as endpointColumnWidth
// (see truncateServiceName).
const serviceColumnWidth = maxNamespaceDisplayLen + len("...") + len("/") + maxServiceNameDisplayLen + len("...")

// flowTypeColumnWidth fits the longest of the FlowType enum's string values,
// "FLOW_TYPE_FROM_EXTERNAL", exactly. FlowType is a closed set, so unlike SOURCE/DESTINATION there
// is no truncation trade-off to make here — the column was simply too narrow (14) for its own
// possible contents.
var flowTypeColumnWidth = len(flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL.String())

// textHeaderFormat and textRowFormat share their column widths via the "*" width verb (the width
// is taken from the next argument) rather than duplicating hand-computed padding in two format
// strings, which is exactly the kind of thing that silently drifts out of alignment when a width
// changes.
const textHeaderFormat = "%-9s %-*s %-*s %-5s %-6s %-6s %-*s %-*s %s"

var textHeader = fmt.Sprintf(textHeaderFormat,
	"TIME", endpointColumnWidth, "SOURCE", endpointColumnWidth, "DESTINATION", "PROTO", "SPORT", "DPORT",
	serviceColumnWidth, "SERVICE", flowTypeColumnWidth, "FLOW_TYPE", "TOTAL BYTES")

// The final column is %s, not %d: it holds either the raw byte count or, with --human-readable,
// formatBytes' output, and which one is only known at render time (see textRenderer.render).
const textRowFormat = "%-9s %-*s %-*s %-5d %-6d %-6d %-*s %-*s %s\n"

// formatBytes renders n the way "ls -h"/"du -h" do: binary (1024-based) units, one decimal place
// once past whole bytes. Used only for --human-readable text output; JSON output always uses the
// raw integer, since a machine consumer wants an exact number, not a string it has to re-parse.
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

func (tr *textRenderer) render(flows []*flowpb.Flow, droppedCount uint64) error {
	err := writeBatch(tr.out, func(w io.Writer) error {
		if !tr.wroteHeader && len(flows) > 0 {
			if tr.columns != nil {
				if err := writeColumns(w, tr.columns, nil, tr.humanReadableBytes); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintln(w, textHeader); err != nil {
					return err
				}
			}
			tr.wroteHeader = true
		}
		for _, f := range flows {
			r := toRecord(f)
			if tr.columns != nil {
				if err := writeColumns(w, tr.columns, &r, tr.humanReadableBytes); err != nil {
					return err
				}
				continue
			}
			endTime := r.EndTime
			if len(endTime) > 8 {
				// Keep just the time-of-day portion (HH:MM:SS) for a live tail; the date is rarely
				// useful and the RFC3339 form does not fit the fixed-width column.
				if t, err := time.Parse(time.RFC3339, r.EndTime); err == nil {
					endTime = t.Local().Format("15:04:05")
				}
			}
			totalBytes := r.OctetTotalCount + r.ReverseOctetTotalCount
			bytesStr := fmt.Sprint(totalBytes)
			if tr.humanReadableBytes {
				bytesStr = formatBytes(totalBytes)
			}
			// A column left as pure padding (no visible value at all) cannot be told apart from
			// the whitespace between columns when read back positionally — by a human glancing at
			// the output, or by a script splitting on whitespace. "-" (kubectl's convention for
			// "no value", e.g. <none>) keeps every column always present.
			if _, err := fmt.Fprintf(w, textRowFormat,
				placeholderIfEmpty(endTime),
				endpointColumnWidth, r.endpoint(true), endpointColumnWidth, r.endpoint(false),
				r.Protocol, r.SourcePort, r.DestinationPort,
				serviceColumnWidth, r.service(),
				flowTypeColumnWidth, placeholderIfEmpty(r.FlowType),
				bytesStr); err != nil {
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
