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
	"net"
	"strings"
	"time"

	timestamppb "google.golang.org/protobuf/types/known/timestamppb"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

var flowTypeValues = map[string]flowpb.FlowType{
	"intra-node":    flowpb.FlowType_FLOW_TYPE_INTRA_NODE,
	"inter-node":    flowpb.FlowType_FLOW_TYPE_INTER_NODE,
	"to-external":   flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL,
	"from-external": flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL,
}

var directionValues = map[string]flowpb.FlowFilterDirection{
	"both": flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
	"from": flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM,
	"to":   flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_TO,
}

// buildRequest translates CLI flags into a GetFlowsRequest. It validates values that are cheap to
// check client-side (unknown --direction/--flow-type, unparsable --since, malformed --ip) so the
// user gets immediate feedback instead of a round trip to the server for a mistake like a typo.
func buildRequest(o *options) (*flowpb.GetFlowsRequest, error) {
	direction, ok := directionValues[strings.ToLower(o.direction)]
	if !ok {
		return nil, fmt.Errorf("invalid --direction %q, must be one of both, from, to", o.direction)
	}

	var flowTypes []flowpb.FlowType
	for _, v := range o.flowTypes {
		ft, ok := flowTypeValues[strings.ToLower(v)]
		if !ok {
			return nil, fmt.Errorf("invalid --flow-type %q, must be one of intra-node, inter-node, to-external, from-external", v)
		}
		flowTypes = append(flowTypes, ft)
	}

	for _, ip := range o.ips {
		if strings.Contains(ip, "/") {
			if _, _, err := net.ParseCIDR(ip); err != nil {
				return nil, fmt.Errorf("invalid --ip %q: %w", ip, err)
			}
		} else if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("invalid --ip %q: not a valid IP address or CIDR", ip)
		}
	}

	filter := &flowpb.FlowFilter{
		Namespaces:       o.namespaces,
		PodNames:         o.podNames,
		PodLabelSelector: o.selector,
		ServiceNames:     o.services,
		FlowTypes:        flowTypes,
		Ips:              o.ips,
		Direction:        direction,
	}

	req := &flowpb.GetFlowsRequest{
		// A single filter, even an all-empty one, is equivalent to omitting filters entirely:
		// FlowStreamService treats an empty FlowFilter as "match everything" (no field has any
		// values to check), so there is no special case needed here for "no filters requested".
		Filters:  []*flowpb.FlowFilter{filter},
		MaxCount: o.maxCount,
		Follow:   o.follow,
	}

	if o.since != "" {
		ts, err := parseSince(o.since)
		if err != nil {
			return nil, err
		}
		req.Since = ts
	}

	return req, nil
}

// parseSince accepts either a duration relative to now (e.g. "5m", the common case for a human at
// a terminal) or an absolute RFC3339 timestamp (for scripts that want an exact, reproducible
// cutoff rather than one that depends on when the command happens to run).
func parseSince(s string) (*timestamppb.Timestamp, error) {
	if d, err := time.ParseDuration(s); err == nil {
		return timestamppb.New(time.Now().Add(-d)), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return timestamppb.New(t), nil
	}
	return nil, fmt.Errorf("invalid --since %q: must be a duration (e.g. \"5m\") or an RFC3339 timestamp", s)
}
