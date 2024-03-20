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

func (p *proxier) categorizeEndpoints(endpoints map[string]k8sproxy.Endpoint, svcInfo k8sproxy.ServicePort) ([]k8sproxy.Endpoint, []k8sproxy.Endpoint, []k8sproxy.Endpoint) {
	var useTopology, useServingTerminatingEndpoints bool
	var clusterEndpoints, localEndpoints, allReachableEndpoints []k8sproxy.Endpoint

	// If cluster Endpoints is to be used for the Service, generate a list of cluster Endpoints.
	if svcInfo.UsesClusterEndpoints() {
		useTopology = p.canUseTopology(endpoints, svcInfo)
		clusterEndpoints = filterEndpoints(endpoints, func(ep k8sproxy.Endpoint) bool {
			if !ep.IsReady() {
				return false
			}
			if useTopology && !availableForTopology(ep, p.nodeLabels) {
				return false
			}
			return true
		})

		// If there is no cluster Endpoint, fallback to any terminating Endpoints that are serving. When falling back to
		// terminating Endpoints, and topology aware routing is NOT considered since this is the best effort attempt to
		// avoid dropping connections.
		if len(clusterEndpoints) == 0 && p.endpointSliceEnabled {
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

	localEndpoints = filterEndpoints(endpoints, func(ep k8sproxy.Endpoint) bool {
		if !ep.IsReady() {
			return false
		}
		if !ep.GetIsLocal() {
			return false
		}
		return true
	})

	// If there is no local Endpoint, fallback to terminating local Endpoints that are serving. When falling back to
	// terminating Endpoints, and topology aware routing is NOT considered since this is the best effort attempt to
	// avoid dropping connections.
	if len(localEndpoints) == 0 && p.endpointSliceEnabled {
		useServingTerminatingEndpoints = true
		localEndpoints = filterEndpoints(endpoints, func(ep k8sproxy.Endpoint) bool {
			if ep.GetIsLocal() && ep.IsServing() && ep.IsTerminating() {
				return true
			}
			return false
		})
	}

	// If cluster Endpoints is not to be used, localEndpoints is just allReachableEndpoints, then only return localEndpoints
	// and allReachableEndpoints.
	if !svcInfo.UsesClusterEndpoints() {
		allReachableEndpoints = localEndpoints
		return nil, localEndpoints, allReachableEndpoints
	}

	if !useTopology && !useServingTerminatingEndpoints {
		// !useServingTerminatingEndpoints means that localEndpoints contains only Ready Endpoints. !useTopology means
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

// canUseTopology returns true if topology aware routing is enabled and properly configured in this cluster. That is,
// it checks that:
// - The TopologyAwareHints feature is enabled.
// - The "service.kubernetes.io/topology-aware-hints" annotation on this Service is set to "Auto".
// - The node's labels include "topology.kubernetes.io/zone".
// - All of the Endpoints for this Service have a topology hint.
// - At least one Endpoint for this Service is hinted for this Node's zone.
func (p *proxier) canUseTopology(endpoints map[string]k8sproxy.Endpoint, svcInfo k8sproxy.ServicePort) bool {
	if !p.topologyAwareHintsEnabled {
		return false
	}
	hintsAnnotation := svcInfo.HintsAnnotation()
	if hintsAnnotation != "Auto" && hintsAnnotation != "auto" {
		if hintsAnnotation != "" && hintsAnnotation != "Disabled" && hintsAnnotation != "disabled" {
			klog.InfoS("Skipping topology aware Endpoint filtering since Service has unexpected value", "annotationTopologyAwareHints", v1.DeprecatedAnnotationTopologyAwareHints, "hints", hintsAnnotation)
		}
		return false
	}

	zone, ok := p.nodeLabels[v1.LabelTopologyZone]
	if !ok || zone == "" {
		klog.InfoS("Skipping topology aware Endpoint filtering since Node is missing label", "label", v1.LabelTopologyZone)
		return false
	}

	hasEndpointForZone := false
	for _, endpoint := range endpoints {
		if !endpoint.IsReady() {
			continue
		}
		if endpoint.GetZoneHints().Len() == 0 {
			klog.InfoS("Skipping topology aware Endpoint filtering since one or more Endpoints is missing a zone hint")
			return false
		}
		if endpoint.GetZoneHints().Has(zone) {
			hasEndpointForZone = true
		}
	}

	if !hasEndpointForZone {
		klog.InfoS("Skipping topology aware Endpoint filtering since no hints were provided for zone", "zone", zone)
		return false
	}

	return true
}

// availableForTopology checks if this endpoint is available for use on this node, given
// topology constraints. (It assumes that canUseTopology() returned true.)
func availableForTopology(endpoint k8sproxy.Endpoint, nodeLabels map[string]string) bool {
	zone := nodeLabels[v1.LabelTopologyZone]
	return endpoint.GetZoneHints().Has(zone)
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
