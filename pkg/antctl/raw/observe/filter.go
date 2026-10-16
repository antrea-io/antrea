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
	"maps"
	"net"
	"slices"
	"strings"
	"time"

	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/apimachinery/pkg/labels"

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
// check client-side (unknown --direction/--flow-type, malformed --selector/--ip, unparsable or
// meaningless --since) so the user gets immediate feedback instead of a round trip to the server
// for a mistake like a typo.
func buildRequest(o *options) (*flowpb.GetFlowsRequest, error) {
	direction, ok := directionValues[strings.ToLower(o.direction)]
	if !ok {
		return nil, fmt.Errorf("invalid --direction %q, must be one of %s", o.direction, strings.Join(slices.Sorted(maps.Keys(directionValues)), ", "))
	}

	var flowTypes []flowpb.FlowType
	for _, v := range o.flowTypes {
		ft, ok := flowTypeValues[strings.ToLower(v)]
		if !ok {
			return nil, fmt.Errorf("invalid --flow-type %q, must be one of %s", v, strings.Join(slices.Sorted(maps.Keys(flowTypeValues)), ", "))
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

	if o.selector != "" {
		// The Flow Aggregator parses the selector with the same function, and rejects what it cannot.
		if _, err := labels.Parse(o.selector); err != nil {
			return nil, fmt.Errorf("invalid --selector %q: %w", o.selector, err)
		}
	}

	filter := &flowpb.FlowFilter{
		PodNames:         o.podNames,
		PodLabelSelector: o.selector,
		ServiceNames:     o.services,
		FlowTypes:        flowTypes,
		Ips:              o.ips,
		Direction:        direction,
	}

	req := &flowpb.GetFlowsRequest{
		// no special case needed for "no filters requested"
		Filters:  []*flowpb.FlowFilter{filter},
		MaxCount: o.maxCount,
		Follow:   o.follow,
	}

	// FlowStreamService requires every request to state its scope, and authorizes it with RBAC
	// before sending anything. The scope is not a filter: FlowFilter.Namespaces only narrows a
	// scope already granted, to flows whose peer is in that Namespace, so --namespace is never sent
	// there. Without --namespace the scope is the whole cluster, which needs the permission
	// cluster-wide and is the only scope in which nothing is redacted.
	if o.namespace != "" {
		req.Namespaces = []string{o.namespace}
	} else {
		req.ClusterWide = true
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
// cutoff rather than one that depends on when the command happens to run). A duration must be
// positive, as it counts back from now: "-5m" is a mistake, not a time. A timestamp in the future
// is accepted (see futureSinceWarning).
func parseSince(s string) (*timestamppb.Timestamp, error) {
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return nil, fmt.Errorf("invalid --since %q: a duration must be positive, as it counts back from now", s)
		}
		return timestamppb.New(time.Now().Add(-d)), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return timestamppb.New(t), nil
	}
	return nil, fmt.Errorf("invalid --since %q: must be a duration (e.g. \"5m\") or an RFC3339 timestamp", s)
}

// futureSinceWarning returns a warning for a --since timestamp that is ahead of now, and "" for any
// other request. Such a request is valid, and is not refused: the Flow Aggregator applies the cutoff
// to every flow, so it asks to see nothing until that time. It is also what a wrong year or time
// zone offset looks like, and the client's clock may differ from the cluster's by a few seconds, so
// the user is told rather than stopped.
func futureSinceWarning(req *flowpb.GetFlowsRequest, since string, now time.Time) string {
	if req.GetSince() == nil || !req.GetSince().AsTime().After(now) {
		return ""
	}
	return fmt.Sprintf("warning: --since %s is in the future: no flow that has already ended can match", since)
}
