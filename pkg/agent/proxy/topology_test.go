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
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	k8sproxy "antrea.io/antrea/third_party/proxy"
)

func TestTopologyAwareHints(t *testing.T) {
	testCases := []struct {
		name              string
		nodeLabels        map[string]string
		hintsAnnotation   string
		endpoints         map[string]k8sproxy.Endpoint
		expectedEndpoints sets.String
	}{
		{
			name:            "hints annotation == auto",
			nodeLabels:      map[string]string{v1.LabelTopologyZone: "zone-a"},
			hintsAnnotation: "auto",
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.NewString("zone-a"), Ready: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.NewString("zone-b"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.NewString("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.NewString("zone-a"), Ready: true},
			},
			expectedEndpoints: sets.NewString("10.1.2.3:80", "10.1.2.6:80"),
		},
		{
			name:            "hints annotation == disabled, hints ignored",
			nodeLabels:      map[string]string{v1.LabelTopologyZone: "zone-a"},
			hintsAnnotation: "disabled",
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.NewString("zone-a"), Ready: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.NewString("zone-b"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.NewString("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.NewString("zone-a"), Ready: true},
			},
			expectedEndpoints: sets.NewString("10.1.2.3:80", "10.1.2.4:80", "10.1.2.5:80", "10.1.2.6:80"),
		},
		{
			name:            "hints annotation == aUto (wrong capitalization), hints ignored",
			nodeLabels:      map[string]string{v1.LabelTopologyZone: "zone-a"},
			hintsAnnotation: "aUto",
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.NewString("zone-a"), Ready: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.NewString("zone-b"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.NewString("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.NewString("zone-a"), Ready: true},
			},
			expectedEndpoints: sets.NewString("10.1.2.3:80", "10.1.2.4:80", "10.1.2.5:80", "10.1.2.6:80"),
		},
		{
			name:            "hints annotation empty, hints ignored",
			nodeLabels:      map[string]string{v1.LabelTopologyZone: "zone-a"},
			hintsAnnotation: "",
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.NewString("zone-a"), Ready: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.NewString("zone-b"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.NewString("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.NewString("zone-a"), Ready: true},
			},
			expectedEndpoints: sets.NewString("10.1.2.3:80", "10.1.2.4:80", "10.1.2.5:80", "10.1.2.6:80"),
		},
		{
			name:            "empty node labels",
			nodeLabels:      nil,
			hintsAnnotation: "auto",
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.NewString("zone-a"), Ready: true},
			},
			expectedEndpoints: sets.NewString("10.1.2.3:80"),
		},
		{
			name:            "empty zone label",
			nodeLabels:      map[string]string{v1.LabelTopologyZone: ""},
			hintsAnnotation: "auto",
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.NewString("zone-a"), Ready: true},
			},
			expectedEndpoints: sets.NewString("10.1.2.3:80"),
		},
		{
			name:            "node in different zone, no endpoint filtering",
			nodeLabels:      map[string]string{v1.LabelTopologyZone: "zone-b"},
			hintsAnnotation: "auto",
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.NewString("zone-a"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.NewString("zone-c"), Ready: true},
			},
			expectedEndpoints: sets.NewString("10.1.2.3:80", "10.1.2.5:80"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			endpointsMap := filterEndpointsWithHints(tc.endpoints, tc.hintsAnnotation, tc.nodeLabels)
			endpoints := sets.NewString()
			for key := range endpointsMap {
				endpoints.Insert(key)
			}
			assert.Equal(t, tc.expectedEndpoints, endpoints)
		})
	}
}
