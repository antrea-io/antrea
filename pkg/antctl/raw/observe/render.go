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

func newRenderer(format outputFormat, out io.Writer, humanReadableBytes bool) renderer {
	if format == outputJSON {
		return &jsonRenderer{out: out}
	}
	return &textRenderer{out: out, humanReadableBytes: humanReadableBytes}
}

// record is a flattened, stable subset of flowpb.Flow's fields, used by both renderers. It
// deliberately does not embed the raw proto-generated struct: that struct is not meant to be
// marshaled directly with encoding/json, and a purpose-built shape keeps observe's output stable
// across proto schema changes that don't affect the fields surfaced here.
type record struct {
	EndTime                 string
	SourceIP                string
	DestinationIP           string
	Protocol                uint32
	SourcePort              uint32
	DestinationPort         uint32
	SourcePodNamespace      string
	SourcePodName           string
	DestinationPodNamespace string
	DestinationPodName      string
	DestinationServiceName  string
	FlowType                string
	OctetTotalCount         uint64
	ReverseOctetTotalCount  uint64
}

func toRecord(f *flowpb.Flow) record {
	r := record{
		Protocol:        f.GetTransport().GetProtocolNumber(),
		SourcePort:      f.GetTransport().GetSourcePort(),
		DestinationPort: f.GetTransport().GetDestinationPort(),
	}
	if ts := f.GetEndTs(); ts != nil {
		r.EndTime = ts.AsTime().Format(time.RFC3339)
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
	}
	if stats := f.GetStats(); stats != nil {
		r.OctetTotalCount = stats.GetOctetTotalCount()
	}
	if stats := f.GetReverseStats(); stats != nil {
		r.ReverseOctetTotalCount = stats.GetOctetTotalCount()
	}
	return r
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
	if name != "" {
		return fmt.Sprintf("%s/%s", truncatePrefix(namespace, maxNamespaceDisplayLen), truncateSuffix(name, maxPodNameDisplayLen))
	}
	return placeholderIfEmpty(ip)
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
type jsonRenderer struct {
	out io.Writer
}

func (jr *jsonRenderer) render(flows []*flowpb.Flow, droppedCount uint64) error {
	enc := json.NewEncoder(jr.out)
	for _, f := range flows {
		if err := enc.Encode(toRecord(f)); err != nil {
			return err
		}
	}
	if droppedCount > 0 {
		if err := enc.Encode(map[string]uint64{"droppedCount": droppedCount}); err != nil {
			return err
		}
	}
	return nil
}

// textRenderer prints one fixed-width line per flow. It deliberately does not use text/tabwriter:
// tabwriter aligns columns per Flush() call, and with --follow there is no single point at which
// all rows are known, so column widths would visibly jump between batches. Fixed-width fields
// avoid that at the cost of long values (e.g. deeply-nested Namespace/Pod names) not lining up
// perfectly — the same trade-off tools like "kubectl logs -f" make for the same reason.
type textRenderer struct {
	out                io.Writer
	wroteHeader        bool
	humanReadableBytes bool
}

// endpointColumnWidth is the SOURCE/DESTINATION column width: the longest possible value from
// endpoint() is a fully-truncated Namespace (maxNamespaceDisplayLen plus the "..." marker) plus
// "/" plus a fully-truncated Pod name (maxPodNameDisplayLen plus the "..." marker).
const endpointColumnWidth = maxNamespaceDisplayLen + len("...") + len("/") + maxPodNameDisplayLen + len("...")

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
	if !tr.wroteHeader && len(flows) > 0 {
		if _, err := fmt.Fprintln(tr.out, textHeader); err != nil {
			return err
		}
		tr.wroteHeader = true
	}
	for _, f := range flows {
		r := toRecord(f)
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
		if _, err := fmt.Fprintf(tr.out, textRowFormat,
			placeholderIfEmpty(endTime),
			endpointColumnWidth, r.endpoint(true), endpointColumnWidth, r.endpoint(false),
			r.Protocol, r.SourcePort, r.DestinationPort,
			serviceColumnWidth, placeholderIfEmpty(truncateServiceName(r.DestinationServiceName)),
			flowTypeColumnWidth, placeholderIfEmpty(r.FlowType),
			bytesStr); err != nil {
			return err
		}
	}
	if droppedCount > 0 {
		if _, err := fmt.Fprintf(tr.out, "# warning: %d flow(s) dropped, consumer fell behind the ring buffer\n", droppedCount); err != nil {
			return err
		}
	}
	return nil
}
