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

func filterEndpoints(endpoints map[string]k8sproxy.Endpoint, svcInfo k8sproxy.ServicePort, nodeLabels map[string]string) map[string]k8sproxy.Endpoint {
	if svcInfo.NodeLocalExternal() || svcInfo.NodeLocalInternal() {
		return endpoints
	}

	return filterEndpointsWithHints(endpoints, svcInfo.HintsAnnotation(), nodeLabels)
}

func filterEndpointsWithHints(endpoints map[string]k8sproxy.Endpoint, hintsAnnotation string, nodeLabels map[string]string) map[string]k8sproxy.Endpoint {
	if hintsAnnotation != "Auto" && hintsAnnotation != "auto" {
		if hintsAnnotation != "" && hintsAnnotation != "Disabled" && hintsAnnotation != "disabled" {
			klog.InfoS("Skipping topology aware Endpoint filtering since Service has unexpected value", "annotationTopologyAwareHints", v1.AnnotationTopologyAwareHints, "hints", hintsAnnotation)
		}
		return endpoints
	}

	zone, ok := nodeLabels[v1.LabelTopologyZone]
	if !ok || zone == "" {
		klog.InfoS("Skipping topology aware Endpoint filtering since Node is missing label", "label", v1.LabelTopologyZone)
		return endpoints
	}

	filteredEndpoints := make(map[string]k8sproxy.Endpoint)

	for key, endpoint := range endpoints {
		if !endpoint.IsReady() {
			continue
		}
		if endpoint.GetZoneHints().Len() == 0 {
			klog.InfoS("Skipping topology aware Endpoint filtering since one or more Endpoints is missing a zone hint")
			return endpoints
		}
		if endpoint.GetZoneHints().Has(zone) {
			filteredEndpoints[key] = endpoint
		}
	}

	if len(filteredEndpoints) == 0 {
		klog.InfoS("Skipping topology aware Endpoint filtering since no hints were provided for zone", "zone", zone)
		return endpoints
	}

	return filteredEndpoints
}
