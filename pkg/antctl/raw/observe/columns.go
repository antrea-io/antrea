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
	"fmt"
	"io"
	"strings"

	"k8s.io/apimachinery/pkg/labels"
)

// column describes a selectable table column. Widths are fixed across batches so that --follow
// keeps columns aligned. The header is the record's JSON field name, except for the three combined
// columns source, destination and totalBytes. Byte counters honor --human-readable.
type column struct {
	name  string
	width int
	bytes bool
	// keepEnd makes a value that is too wide lose its start rather than its end, for names whose
	// distinguishing part is at the end (see truncateSuffix): the random suffix of a Pod name,
	// "ingress" versus "egress" in two otherwise alike policy names, or the number of a Node
	// among the Nodes of a pool.
	keepEnd bool
	// withheld, when not nil, reports whether the Flow Aggregator withheld the value of this column
	// for the record. The text output then shows redactedMarker rather than the empty value, which
	// is also what a value that does not exist looks like. It is nil for a value that is never
	// withheld.
	withheld func(record) bool
	value    func(record) any
}

// The constructors below name the groups of columns that the Flow Aggregator withholds together
// (see redactFlow in pkg/flowaggregator/flowstreamservice/redaction.go).

// withheldIdentity is the identity of an endpoint: its Pod name and labels.
func withheldIdentity(isSource bool) func(record) bool {
	return func(r record) bool { return r.withheld(isSource) }
}

// withheldService is the destination Service: its name, address and port. It has a tier of its own.
func withheldService(r record) bool { return r.serviceWithheld() }

// withheldPlacement is the placement of an endpoint: its Node, and the Egress of the source.
func withheldPlacement(isSource bool) func(record) bool {
	return func(r record) bool { return r.placementWithheld(isSource) }
}

// withheldPolicy is the identity of a policy: its name and rule name.
func withheldPolicy(ingress bool) func(record) bool {
	return func(r record) bool { return r.policyWithheld(ingress) }
}

// withheldPolicyNamespace is the Namespace of a policy, which a cluster-scoped policy lacks.
func withheldPolicyNamespace(ingress bool) func(record) bool {
	return func(r record) bool { return r.policyNamespaceWithheld(ingress) }
}

// availableColumns is shared by flag help and validation so every documented name can be selected.
var availableColumns = []column{
	{name: "endTime", width: 20, value: func(r record) any { return r.EndTime }},
	{name: "sourceIP", width: 39, value: func(r record) any { return r.SourceIP }},
	{name: "destinationIP", width: 39, value: func(r record) any { return r.DestinationIP }},
	{name: "protocol", width: 5, value: func(r record) any { return r.Protocol }},
	{name: "sourcePort", width: 6, value: func(r record) any { return r.SourcePort }},
	{name: "destinationPort", width: 6, value: func(r record) any { return r.DestinationPort }},
	{name: "sourcePodNamespace", width: 33, value: func(r record) any { return r.SourcePodNamespace }},
	{name: "sourcePodName", width: 43, keepEnd: true, withheld: withheldIdentity(true), value: func(r record) any { return r.SourcePodName }},
	{name: "destinationPodNamespace", width: 33, withheld: record.destinationNamespaceWithheld, value: func(r record) any { return r.DestinationPodNamespace }},
	{name: "destinationPodName", width: 43, keepEnd: true, withheld: withheldIdentity(false), value: func(r record) any { return r.DestinationPodName }},
	{name: "destinationServiceName", width: serviceColumnWidth, value: func(r record) any { return r.service() }},
	{name: "flowType", width: flowTypeColumnWidth, value: func(r record) any { return r.FlowType }},
	{name: "octetTotalCount", width: 20, bytes: true, value: func(r record) any { return r.OctetTotalCount }},
	{name: "reverseOctetTotalCount", width: 20, bytes: true, value: func(r record) any { return r.ReverseOctetTotalCount }},
	{name: "sourceDisclosure", value: func(r record) any { return r.SourceDisclosure }},
	{name: "destinationDisclosure", value: func(r record) any { return r.DestinationDisclosure }},
	{name: "destinationServiceDisclosure", value: func(r record) any { return r.DestinationServiceDisclosure }},
	{name: "sourcePodLabels", width: 80, withheld: withheldIdentity(true), value: func(r record) any { return r.SourcePodLabels }},
	{name: "destinationPodLabels", width: 80, withheld: withheldIdentity(false), value: func(r record) any { return r.DestinationPodLabels }},
	{name: "ingressNetworkPolicyNamespace", width: 33, withheld: withheldPolicyNamespace(true), value: func(r record) any { return r.IngressNetworkPolicyNamespace }},
	{name: "ingressNetworkPolicyName", width: 43, keepEnd: true, withheld: withheldPolicy(true), value: func(r record) any { return r.IngressNetworkPolicyName }},
	{name: "ingressNetworkPolicyType", width: 32, value: func(r record) any { return r.IngressNetworkPolicyType }},
	{name: "ingressNetworkPolicyRuleName", width: 43, keepEnd: true, withheld: withheldPolicy(true), value: func(r record) any { return r.IngressNetworkPolicyRuleName }},
	{name: "ingressNetworkPolicyRuleAction", width: 36, value: func(r record) any { return r.IngressNetworkPolicyRuleAction }},
	{name: "egressNetworkPolicyNamespace", width: 33, withheld: withheldPolicyNamespace(false), value: func(r record) any { return r.EgressNetworkPolicyNamespace }},
	{name: "egressNetworkPolicyName", width: 43, keepEnd: true, withheld: withheldPolicy(false), value: func(r record) any { return r.EgressNetworkPolicyName }},
	{name: "egressNetworkPolicyType", width: 32, value: func(r record) any { return r.EgressNetworkPolicyType }},
	{name: "egressNetworkPolicyRuleName", width: 43, keepEnd: true, withheld: withheldPolicy(false), value: func(r record) any { return r.EgressNetworkPolicyRuleName }},
	{name: "egressNetworkPolicyRuleAction", width: 36, value: func(r record) any { return r.EgressNetworkPolicyRuleAction }},
	{name: "tcpState", width: 12, value: func(r record) any { return r.TCPState }},
	{name: "sourceNodeName", width: 43, keepEnd: true, withheld: withheldPlacement(true), value: func(r record) any { return r.SourceNodeName }},
	{name: "destinationNodeName", width: 43, keepEnd: true, withheld: withheldPlacement(false), value: func(r record) any { return r.DestinationNodeName }},
	{name: "packetTotalCount", width: 20, value: func(r record) any { return r.PacketTotalCount }},
	{name: "reversePacketTotalCount", width: 20, value: func(r record) any { return r.ReversePacketTotalCount }},
	{name: "startTime", width: 20, value: func(r record) any { return r.StartTime }},
	{name: "endReason", width: 33, value: func(r record) any { return r.EndReason }},
	{name: "destinationServiceIP", width: 39, withheld: withheldService, value: func(r record) any { return r.DestinationServiceIP }},
	{name: "destinationServicePort", width: len(redactedMarker), withheld: withheldService, value: func(r record) any { return r.DestinationServicePort }},
	{name: "packetDeltaCount", width: 20, value: func(r record) any { return r.PacketDeltaCount }},
	{name: "reversePacketDeltaCount", width: 20, value: func(r record) any { return r.ReversePacketDeltaCount }},
	{name: "octetDeltaCount", width: 20, bytes: true, value: func(r record) any { return r.OctetDeltaCount }},
	{name: "reverseOctetDeltaCount", width: 20, bytes: true, value: func(r record) any { return r.ReverseOctetDeltaCount }},
	{name: "egressName", width: 43, withheld: withheldPlacement(true), value: func(r record) any { return r.EgressName }},
	{name: "egressIP", width: 39, withheld: withheldPlacement(true), value: func(r record) any { return r.EgressIP }},
	{name: "egressNodeName", width: 43, keepEnd: true, withheld: withheldPlacement(true), value: func(r record) any { return r.EgressNodeName }},
	{name: "proxySnatIP", width: 39, value: func(r record) any { return r.ProxySnatIP }},
	{name: "proxySnatPort", width: 6, value: func(r record) any { return r.ProxySnatPort }},
	{name: "throughput", width: 20, value: func(r record) any { return r.Throughput }},
	{name: "reverseThroughput", width: 20, value: func(r record) any { return r.ReverseThroughput }},
	{name: "source", width: endpointColumnWidth, value: func(r record) any { return r.endpoint(true) }},
	{name: "destination", width: endpointColumnWidth, value: func(r record) any { return r.endpoint(false) }},
	{name: "totalBytes", width: 20, bytes: true, value: func(r record) any { return r.OctetTotalCount + r.ReverseOctetTotalCount }},
}

func columnNames() []string {
	names := make([]string, len(availableColumns))
	for i, c := range availableColumns {
		names[i] = c.name
	}
	return names
}

func parseColumns(names []string) ([]column, error) {
	if names == nil {
		return nil, nil
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("--columns requires at least one column")
	}
	byName := make(map[string]column, len(availableColumns))
	for _, c := range availableColumns {
		byName[c.name] = c
	}
	selected := make([]column, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		c, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("unknown column %q in --columns; see --help for supported columns", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate column %q in --columns", name)
		}
		seen[name] = true
		selected = append(selected, c)
	}
	return selected, nil
}

func (c column) cell(r record, humanReadableBytes bool) string {
	if c.withheld != nil && c.withheld(r) {
		return redactedMarker
	}
	value := c.value(r)
	var s string
	switch v := value.(type) {
	case map[string]string:
		switch {
		case v == nil:
			s = "-"
		case len(v) == 0:
			s = "{}"
		default:
			s = labels.Set(v).String()
		}
	case uint64:
		if c.bytes && humanReadableBytes {
			s = formatBytes(v)
		} else {
			s = fmt.Sprint(v)
		}
	default:
		s = fmt.Sprint(v)
	}
	width := max(c.width, len(c.name))
	if len(s) > width {
		if c.keepEnd {
			s = truncateSuffix(s, width-len("..."))
		} else {
			s = truncatePrefix(s, width-len("..."))
		}
	}
	return placeholderIfEmpty(s)
}

// writeColumns writes either a header (r == nil) or one record, with the same fixed widths.
// The final column is not padded, matching the default table's lack of trailing whitespace.
func writeColumns(w io.Writer, columns []column, r *record, humanReadableBytes bool) error {
	cells := make([]string, len(columns))
	for i, c := range columns {
		value := c.name
		if r != nil {
			value = c.cell(*r, humanReadableBytes)
		}
		if i < len(columns)-1 {
			value = fmt.Sprintf("%-*s", max(c.width, len(c.name)), value)
		}
		cells[i] = value
	}
	_, err := fmt.Fprintln(w, strings.Join(cells, " "))
	return err
}
