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
	"fmt"
	"net"
	"testing"

	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	k8sproxy "antrea.io/antrea/third_party/proxy"
)

func checkExpectedEndpoints(expected sets.Set[string], actual []k8sproxy.Endpoint) error {
	var errs []error

	expectedCopy := sets.New[string](expected.UnsortedList()...)
	for _, ep := range actual {
		if !expectedCopy.Has(ep.String()) {
			errs = append(errs, fmt.Errorf("unexpected endpoint %v", ep))
		}
		expectedCopy.Delete(ep.String())
	}
	if len(expectedCopy) > 0 {
		errs = append(errs, fmt.Errorf("missing endpoints %v", expectedCopy.UnsortedList()))
	}

	return kerrors.NewAggregate(errs)
}

func TestCategorizeEndpoints(t *testing.T) {
	testCases := []struct {
		name             string
		hintsEnabled     bool
		nodeLabels       map[string]string
		serviceInfo      k8sproxy.ServicePort
		endpoints        map[string]k8sproxy.Endpoint
		clusterEndpoints sets.Set[string]
		localEndpoints   sets.Set[string]
		allEndpoints     sets.Set[string]
	}{
		{
			name:         "hints enabled, hints annotation == auto",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, "auto"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.New[string]("zone-b"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.New[string]("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:         "hints enabled, hints annotation == disabled, hints ignored",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, "disabled"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.New[string]("zone-b"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.New[string]("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.4:80", "10.1.2.5:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:         "hints disabled, hints annotation == auto",
			hintsEnabled: false,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, "auto"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.New[string]("zone-b"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.New[string]("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.4:80", "10.1.2.5:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:         "hints enabled, hints annotation == aUto (wrong capitalization), hints ignored",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, "aUto"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.New[string]("zone-b"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.New[string]("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.4:80", "10.1.2.5:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:         "hints enabled, hints annotation empty, hints ignored",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, ""),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.New[string]("zone-b"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.New[string]("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.4:80", "10.1.2.5:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:         "eTP: Local, topology ignored for Local endpoints",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, false, nil, "auto"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: true, IsLocal: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.New[string]("zone-b"), Ready: true, IsLocal: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.New[string]("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.6:80"),
			localEndpoints:   sets.New[string]("10.1.2.3:80", "10.1.2.4:80"),
			allEndpoints:     sets.New[string]("10.1.2.3:80", "10.1.2.4:80", "10.1.2.6:80"),
		},
		{
			name:         "iTP: Local, topology ignored for Local endpoints",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, false, true, nil, "auto"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: true, IsLocal: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.New[string]("zone-b"), Ready: true, IsLocal: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.New[string]("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.6:80"),
			localEndpoints:   sets.New[string]("10.1.2.3:80", "10.1.2.4:80"),
			allEndpoints:     sets.New[string]("10.1.2.3:80", "10.1.2.4:80", "10.1.2.6:80"),
		},
		{
			name:         "empty node labels",
			hintsEnabled: true,
			nodeLabels:   nil,
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, "auto"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80"),
			localEndpoints:   nil,
		},
		{
			name:         "empty zone label",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: ""},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, "auto"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80"),
			localEndpoints:   nil,
		},
		{
			name:         "node in different zone, no endpoint filtering",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-b"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, "auto"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.New[string]("zone-c"), Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.5:80"),
			localEndpoints:   nil,
		},
		{
			name:         "normal endpoint filtering, auto annotation",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, "auto"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.New[string]("zone-b"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.New[string]("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:         "unready endpoint",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, "auto"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.New[string]("zone-b"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.New[string]("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.New[string]("zone-a"), Ready: false},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80"),
			localEndpoints:   nil,
		},
		{
			name:         "only unready endpoints in same zone (should not filter)",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, "auto"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: false},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.New[string]("zone-b"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.New[string]("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.New[string]("zone-a"), Ready: false},
			},
			clusterEndpoints: sets.New[string]("10.1.2.4:80", "10.1.2.5:80"),
			localEndpoints:   nil,
		},
		{
			name:         "normal endpoint filtering, Auto annotation",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, "Auto"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.New[string]("zone-b"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.New[string]("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:         "hintsAnnotation empty, no filtering applied",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, ""),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.New[string]("zone-b"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.New[string]("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.4:80", "10.1.2.5:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:         "hintsAnnotation disabled, no filtering applied",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, "disabled"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.New[string]("zone-b"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.New[string]("zone-c"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.4:80", "10.1.2.5:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:         "missing hints, no filtering applied",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, "auto"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.New[string]("zone-b"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: nil, Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.New[string]("zone-a"), Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.4:80", "10.1.2.5:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:         "multiple hints per endpoint, filtering includes any endpoint with zone included",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-c"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, "auto"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.3:80", ZoneHints: sets.New[string]("zone-a", "zone-b", "zone-c"), Ready: true},
				"10.1.2.4:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.4:80", ZoneHints: sets.New[string]("zone-b", "zone-c"), Ready: true},
				"10.1.2.5:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.5:80", ZoneHints: sets.New[string]("zone-b", "zone-d"), Ready: true},
				"10.1.2.6:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.1.2.6:80", ZoneHints: sets.New[string]("zone-c"), Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.4:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:         "conflicting topology and localness require merging allEndpoints",
			hintsEnabled: true,
			nodeLabels:   map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:  k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, false, true, nil, "auto"),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.0:80", ZoneHints: sets.New[string]("zone-a"), Ready: true, IsLocal: true},
				"10.0.0.1:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.1:80", ZoneHints: sets.New[string]("zone-b"), Ready: true, IsLocal: true},
				"10.0.0.2:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.2:80", ZoneHints: sets.New[string]("zone-a"), Ready: true, IsLocal: false},
				"10.0.0.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.3:80", ZoneHints: sets.New[string]("zone-b"), Ready: true, IsLocal: false},
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.2:80"),
			localEndpoints:   sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80", "10.0.0.2:80"),
		},
		{
			name:             "iTP: Local, with empty endpoints",
			serviceInfo:      k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, true, nil, ""),
			endpoints:        map[string]k8sproxy.Endpoint{},
			clusterEndpoints: nil,
			localEndpoints:   sets.New[string](),
		},

		{
			name:        "iTP: Local, but all endpoints are remote",
			serviceInfo: k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, true, nil, ""),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.0:80", Ready: true, IsLocal: false},
				"10.0.0.1:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.1:80", Ready: true, IsLocal: false},
			},
			clusterEndpoints: nil,
			localEndpoints:   sets.New[string](),
		},
		{
			name:        "iTP: Local, all endpoints are local",
			serviceInfo: k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, true, nil, ""),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.0:80", Ready: true, IsLocal: true},
				"10.0.0.1:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.1:80", Ready: true, IsLocal: true},
			},
			clusterEndpoints: nil,
			localEndpoints:   sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
		{
			name:        "iTP: Local, some endpoints are local",
			serviceInfo: k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, true, nil, ""),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.0:80", Ready: true, IsLocal: true},
				"10.0.0.1:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.1:80", Ready: true, IsLocal: false},
			},
			clusterEndpoints: nil,
			localEndpoints:   sets.New[string]("10.0.0.0:80"),
		},
		{
			name:        "Cluster traffic policy, endpoints not Ready",
			serviceInfo: k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, ""),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.0:80", Ready: false},
				"10.0.0.1:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.1:80", Ready: false},
			},
			clusterEndpoints: sets.New[string](),
			localEndpoints:   nil,
		},
		{
			name:        "Cluster traffic policy, some endpoints are Ready",
			serviceInfo: k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, ""),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.0:80", Ready: false},
				"10.0.0.1:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.1:80", Ready: true},
			},
			clusterEndpoints: sets.New[string]("10.0.0.1:80"),
			localEndpoints:   nil,
		},
		{
			name:        "Cluster traffic policy, all endpoints are terminating",
			serviceInfo: k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false, nil, ""),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.0:80", Ready: false, Serving: true, Terminating: true, IsLocal: true},
				"10.0.0.1:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.1:80", Ready: false, Serving: true, Terminating: true, IsLocal: false},
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   nil,
		},
		{
			name:        "iTP: Local, eTP: Cluster, some endpoints local",
			serviceInfo: k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, false, true, nil, ""),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.0:80", Ready: true, IsLocal: true},
				"10.0.0.1:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.1:80", Ready: true, IsLocal: false},
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   sets.New[string]("10.0.0.0:80"),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
		{
			name:        "iTP: Cluster, eTP: Local, some endpoints local",
			serviceInfo: k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, false, nil, ""),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.0:80", Ready: true, IsLocal: true},
				"10.0.0.1:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.1:80", Ready: true, IsLocal: false},
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   sets.New[string]("10.0.0.0:80"),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
		{
			name:        "iTP: Local, eTP: Local, some endpoints local",
			serviceInfo: k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, true, nil, ""),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.0:80", Ready: true, IsLocal: true},
				"10.0.0.1:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.1:80", Ready: true, IsLocal: false},
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   sets.New[string]("10.0.0.0:80"),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
		{
			name:        "iTP: Local, eTP: Local, all endpoints remote",
			serviceInfo: k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, true, nil, ""),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.0:80", Ready: true, IsLocal: false},
				"10.0.0.1:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.1:80", Ready: true, IsLocal: false},
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   sets.New[string](),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
		{
			name:        "iTP: Local, eTP: Local, all endpoints remote and terminating",
			serviceInfo: k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, true, nil, ""),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.0:80", Ready: false, Serving: true, Terminating: true, IsLocal: false},
				"10.0.0.1:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.1:80", Ready: false, Serving: true, Terminating: true, IsLocal: false},
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   sets.New[string](),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
		{
			name:        "iTP: Local, eTP: Local, all endpoints remote and terminating",
			serviceInfo: k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, true, nil, ""),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.0:80", Ready: false, Serving: true, Terminating: true, IsLocal: false},
				"10.0.0.1:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.1:80", Ready: false, Serving: true, Terminating: true, IsLocal: false},
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   sets.New[string](),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
		{
			name:        "iTP: Cluster, eTP: Local, with terminating endpoints",
			serviceInfo: k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, false, nil, ""),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.0:80", Ready: true, IsLocal: false},
				"10.0.0.1:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.1:80", Ready: false, Serving: false, IsLocal: true},
				"10.0.0.2:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.2:80", Ready: false, Serving: true, Terminating: true, IsLocal: true},
				"10.0.0.3:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.3:80", Ready: false, Serving: true, Terminating: true, IsLocal: false},
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80"),
			localEndpoints:   sets.New[string]("10.0.0.2:80"),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.2:80"),
		},
		{
			name:        "no cluster endpoints for iTP:Local internal-only service",
			serviceInfo: k8sproxy.NewBaseServiceInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, true, nil, ""),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.0:80", Ready: true, IsLocal: false},
				"10.0.0.1:80": &k8sproxy.BaseEndpointInfo{Endpoint: "10.0.0.1:80", Ready: true, IsLocal: true},
			},
			clusterEndpoints: nil,
			localEndpoints:   sets.New[string]("10.0.0.1:80"),
			allEndpoints:     sets.New[string]("10.0.0.1:80"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fp := &proxier{nodeLabels: tc.nodeLabels,
				endpointSliceEnabled:      true,
				topologyAwareHintsEnabled: tc.hintsEnabled}

			clusterEndpoints, localEndpoints, allEndpoints := fp.categorizeEndpoints(tc.endpoints, tc.serviceInfo)

			if tc.clusterEndpoints == nil && clusterEndpoints != nil {
				t.Errorf("expected no cluster endpoints but got %v", clusterEndpoints)
			} else {
				err := checkExpectedEndpoints(tc.clusterEndpoints, clusterEndpoints)
				if err != nil {
					t.Errorf("error with cluster endpoints: %v", err)
				}
			}

			if tc.localEndpoints == nil && localEndpoints != nil {
				t.Errorf("expected no local endpoints but got %v", localEndpoints)
			} else {
				err := checkExpectedEndpoints(tc.localEndpoints, localEndpoints)
				if err != nil {
					t.Errorf("error with local endpoints: %v", err)
				}
			}

			var expectedAllEndpoints sets.Set[string]
			if tc.clusterEndpoints != nil && tc.localEndpoints == nil {
				expectedAllEndpoints = tc.clusterEndpoints
			} else if tc.localEndpoints != nil && tc.clusterEndpoints == nil {
				expectedAllEndpoints = tc.localEndpoints
			} else {
				expectedAllEndpoints = tc.allEndpoints
			}
			err := checkExpectedEndpoints(expectedAllEndpoints, allEndpoints)
			if err != nil {
				t.Errorf("error with allEndpoints: %v", err)
			}

		})
	}
}
