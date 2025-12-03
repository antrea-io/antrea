// Copyright 2022 Antrea Authors
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

package proxy

import (
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	k8sproxy "antrea.io/antrea/third_party/proxy"
)

func (p *proxier) categorizeEndpoints(endpoints map[string]k8sproxy.Endpoint, svcInfo k8sproxy.ServicePort, nodeName string, nodeLabels map[string]string) ([]k8sproxy.Endpoint, []k8sproxy.Endpoint, []k8sproxy.Endpoint) {
	var clusterEndpoints, localEndpoints, allReachableEndpoints []k8sproxy.Endpoint
	var useServingTerminatingEndpoints bool
	var topologyMode string

	// If cluster Endpoints is to be used for the Service, generate a list of cluster Endpoints.
	if svcInfo.UsesClusterEndpoints() {
		zone := nodeLabels[v1.LabelTopologyZone]
		topologyMode = p.topologyModeFromHints(svcInfo, endpoints, nodeName, zone)
		clusterEndpoints = filterEndpoints(endpoints, func(ep k8sproxy.Endpoint) bool {
			if !ep.IsReady() {
				return false
			}
			if !availableForTopology(ep, topologyMode, nodeName, zone) {
				return false
			}
			return true
		})

		// If there is no cluster Endpoint, fallback to any terminating Endpoints that are serving. When falling back to
		// terminating Endpoints, and topology aware routing is NOT considered since this is the best effort attempt to
		// avoid dropping connections.
		if len(clusterEndpoints) == 0 {
			clusterEndpoints = filterEndpoints(endpoints, func(ep k8sproxy.Endpoint) bool {
				if ep.IsServing() && ep.IsTerminating() {
					return true
				}
				return false
			})
		}
	}

	// If local Endpoints is not to be used, clusterEndpoints is just allReachableEndpoints, then only return clusterEndpoints
	// and allReachableEndpoints.
	if !svcInfo.UsesLocalEndpoints() {
		allReachableEndpoints = clusterEndpoints
		return clusterEndpoints, nil, allReachableEndpoints
	}

	// If there are any local Endpoints, use local ready Endpoints.
	localEndpoints = filterEndpoints(endpoints, func(ep k8sproxy.Endpoint) bool {
		return ep.IsReady() && ep.IsLocal()
	})
	if len(localEndpoints) == 0 {
		// If there is no local Endpoint, fallback to terminating local Endpoints that are serving. When falling back to
		// terminating Endpoints, and topology aware routing is NOT considered since this is the best effort attempt to
		// avoid dropping connections.
		useServingTerminatingEndpoints = true
		localEndpoints = filterEndpoints(endpoints, func(ep k8sproxy.Endpoint) bool {
			return ep.IsLocal() && ep.IsServing() && ep.IsTerminating()
		})
	}

	// If cluster Endpoints is not to be used, localEndpoints is just allReachableEndpoints, then only return localEndpoints
	// and allReachableEndpoints.
	if !svcInfo.UsesClusterEndpoints() {
		allReachableEndpoints = localEndpoints
		return nil, localEndpoints, allReachableEndpoints
	}

	if topologyMode == "" && !useServingTerminatingEndpoints {
		// !useServingTerminatingEndpoints means that localEndpoints contains only Ready Endpoints. topologyMode == "" means
		// that clusterEndpoints contains *every* Ready Endpoint. So clusterEndpoints must be a superset of localEndpoints.
		allReachableEndpoints = clusterEndpoints
		return clusterEndpoints, localEndpoints, allReachableEndpoints
	}

	// clusterEndpoints may contain remote Endpoints that aren't in localEndpoints, while localEndpoints may contain
	// terminating or topologically-unavailable local endpoints that aren't in clusterEndpoints. So we have to merge
	// the two lists.
	endpointsMap := make(map[string]k8sproxy.Endpoint, len(clusterEndpoints)+len(localEndpoints))
	for _, ep := range clusterEndpoints {
		endpointsMap[ep.String()] = ep
	}
	for _, ep := range localEndpoints {
		endpointsMap[ep.String()] = ep
	}
	allReachableEndpoints = make([]k8sproxy.Endpoint, 0, len(endpointsMap))
	for _, ep := range endpointsMap {
		allReachableEndpoints = append(allReachableEndpoints, ep)
	}

	return clusterEndpoints, localEndpoints, allReachableEndpoints
}

// topologyModeFromHints returns a topology mode ("", "PreferSameZone", or "PreferSameNode") based on the Endpoint hints:
//   - If the PreferSameTrafficDistribution feature gate is enabled, and every ready endpoint has a node hint, and at
//     least one endpoint is hinted for this node, then it returns "PreferSameNode".
//   - Otherwise, if every ready endpoint has a zone hint, and at least one endpoint is hinted for this node's zone,
//     then it returns "PreferSameZone".
//   - Otherwise it returns "" (meaning, no topology / default traffic distribution).
func (p *proxier) topologyModeFromHints(svcInfo k8sproxy.ServicePort, endpoints map[string]k8sproxy.Endpoint, nodeName, zone string) string {
	hasEndpointForNode := false
	allEndpointsHaveNodeHints := true
	hasEndpointForZone := false
	allEndpointsHaveZoneHints := true
	for _, endpoint := range endpoints {
		if !endpoint.IsReady() {
			continue
		}

		if endpoint.NodeHints().Len() == 0 {
			allEndpointsHaveNodeHints = false
		} else if endpoint.NodeHints().Has(nodeName) {
			hasEndpointForNode = true
		}

		if endpoint.ZoneHints().Len() == 0 {
			allEndpointsHaveZoneHints = false
		} else if endpoint.ZoneHints().Has(zone) {
			hasEndpointForZone = true
		}
	}

	if p.preferSameTrafficDistributionEnabled {
		if allEndpointsHaveNodeHints {
			if hasEndpointForNode {
				return v1.ServiceTrafficDistributionPreferSameNode
			}
			klog.V(2).InfoS("Ignoring same-node topology hints for service since no hints were provided for node", "service", svcInfo, "node", nodeName)
		} else {
			klog.V(7).InfoS("Ignoring same-node topology hints for service since one or more endpoints is missing a node hint", "service", svcInfo)
		}
	}
	if allEndpointsHaveZoneHints {
		if hasEndpointForZone {
			return v1.ServiceTrafficDistributionPreferSameZone
		}
		if zone == "" {
			klog.V(2).InfoS("Ignoring same-zone topology hints for service since node is missing label", "service", svcInfo, "label", v1.LabelTopologyZone)
		} else {
			klog.V(2).InfoS("Ignoring same-zone topology hints for service since no hints were provided for zone", "service", svcInfo, "zone", zone)
		}
	} else {
		klog.V(7).InfoS("Ignoring same-zone topology hints for service since one or more endpoints is missing a zone hint", "service", svcInfo.String())
	}

	return ""
}

// availableForTopology checks if this endpoint is available for use on this node when using the given topologyMode.
// (Note that there's no fallback here; the fallback happens when deciding which mode to use, not when applying that
// decision.)
func availableForTopology(endpoint k8sproxy.Endpoint, topologyMode, nodeName, zone string) bool {
	switch topologyMode {
	case "":
		return true
	case v1.ServiceTrafficDistributionPreferSameNode:
		return endpoint.NodeHints().Has(nodeName)
	case v1.ServiceTrafficDistributionPreferSameZone:
		return endpoint.ZoneHints().Has(zone)
	default:
		return false
	}
}

// filterEndpoints filters endpoints according to predicate
func filterEndpoints(endpoints map[string]k8sproxy.Endpoint, predicate func(k8sproxy.Endpoint) bool) []k8sproxy.Endpoint {
	filteredEndpoints := make([]k8sproxy.Endpoint, 0, len(endpoints))

	for _, ep := range endpoints {
		if predicate(ep) {
			filteredEndpoints = append(filteredEndpoints, ep)
		}
	}

	return filteredEndpoints
}
