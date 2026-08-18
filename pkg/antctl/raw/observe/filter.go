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
// meaningless --since, --service with --direction from) so the user gets immediate feedback instead
// of a round trip to the server for a mistake like a typo.
func buildRequest(o *options) (*flowpb.GetFlowsRequest, error) {
	direction, ok := directionValues[strings.ToLower(o.direction)]
	if !ok {
		return nil, fmt.Errorf("invalid --direction %q, must be one of %s", o.direction, strings.Join(slices.Sorted(maps.Keys(directionValues)), ", "))
	}

	// The Flow Aggregator rejects service names with FROM, as a Service is always the destination.
	// Refusing it here names the flags, and spares discovery and connecting.
	if len(o.services) > 0 && direction == flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM {
		return nil, fmt.Errorf("--service cannot be combined with --direction from: a Service is always the destination of a flow")
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

	// The Flow Aggregator matches the directional criteria of a filter (namespaces, pod_names,
	// pod_label_selector, ips) all against the same endpoint, and a filter with none of them matches
	// either endpoint, whatever its direction. Filters are AND-ed.
	//
	// --namespace goes in the filter of the Pod criteria, so that "-n web --pod redis-0" is the Pod
	// web/redis-0 and "-n web --direction from" is what is sent from web, as kubectl users read them.
	// --ip is in a filter of its own, with the same direction: it usually names the peer, which is
	// not in --namespace, and would otherwise have to be the very endpoint that is.
	filters := []*flowpb.FlowFilter{{
		PodNames:         o.podNames,
		PodLabelSelector: o.selector,
		ServiceNames:     o.services,
		FlowTypes:        flowTypes,
		Direction:        direction,
	}}
	if o.namespace != "" {
		filters[0].Namespaces = []string{o.namespace}
	}
	if len(o.ips) > 0 {
		filters = append(filters, &flowpb.FlowFilter{Ips: o.ips, Direction: direction})
	}

	req := &flowpb.GetFlowsRequest{
		// no special case needed for "no filters requested"
		Filters:  filters,
		MaxCount: o.maxCount,
		Follow:   o.follow,
	}

	// FlowStreamService requires every request to state its scope, and authorizes it with RBAC
	// before sending anything. The scope is not a filter: it admits the flows with an endpoint in
	// the Namespace, and is what is authorized, while the filter above narrows what is returned
	// within it. Without --namespace the scope is the whole cluster, which needs the permission
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
