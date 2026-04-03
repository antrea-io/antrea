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

	k8sproxy "antrea.io/antrea/v2/third_party/proxy"
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

func makeServicePortInfo(clusterIP net.IP,
	port int,
	protocol v1.Protocol,
	nodePort int,
	loadBalancerVIPs []string,
	sessionAffinityType v1.ServiceAffinity,
	stickyMaxAgeSeconds int32,
	externalIPs []string,
	loadBalancerSourceRanges []string,
	healthCheckNodePort int,
	externalPolicyLocal bool,
	internalPolicyLocal bool) k8sproxy.ServicePort {
	serviceType := v1.ServiceTypeClusterIP
	if nodePort != 0 {
		serviceType = v1.ServiceTypeNodePort
	}
	if loadBalancerVIPs != nil {
		serviceType = v1.ServiceTypeLoadBalancer
	}
	externalTrafficPolicy := v1.ServiceExternalTrafficPolicyCluster
	internalTrafficPolicy := v1.ServiceInternalTrafficPolicyCluster
	if externalPolicyLocal {
		externalTrafficPolicy = v1.ServiceExternalTrafficPolicyLocal
	}
	if internalPolicyLocal {
		internalTrafficPolicy = v1.ServiceInternalTrafficPolicyLocal
	}
	var ingress []v1.LoadBalancerIngress
	for _, ip := range loadBalancerVIPs {
		ingress = append(ingress, v1.LoadBalancerIngress{IP: ip})
	}

	service := &v1.Service{
		Spec: v1.ServiceSpec{
			ClusterIP:       clusterIP.String(),
			ClusterIPs:      []string{clusterIP.String()},
			Type:            serviceType,
			ExternalIPs:     externalIPs,
			SessionAffinity: sessionAffinityType,
			SessionAffinityConfig: &v1.SessionAffinityConfig{
				ClientIP: &v1.ClientIPConfig{
					TimeoutSeconds: &stickyMaxAgeSeconds,
				},
			},
			LoadBalancerSourceRanges: loadBalancerSourceRanges,
			ExternalTrafficPolicy:    externalTrafficPolicy,
			InternalTrafficPolicy:    &internalTrafficPolicy,
			HealthCheckNodePort:      int32(healthCheckNodePort),
		},
		Status: v1.ServiceStatus{
			LoadBalancer: v1.LoadBalancerStatus{
				Ingress: ingress,
			},
		},
	}

	servicePort := &v1.ServicePort{
		Protocol: protocol,
		Port:     int32(port),
		NodePort: int32(nodePort),
	}
	family := v1.IPv4Protocol
	if clusterIP.To4() == nil {
		family = v1.IPv6Protocol
	}
	return k8sproxy.NewBaseServiceInfo(service, family, servicePort)
}

func TestCategorizeEndpoints(t *testing.T) {
	testCases := []struct {
		name              string
		preferSameEnabled bool
		nodeName          string
		nodeLabels        map[string]string
		serviceInfo       k8sproxy.ServicePort
		endpoints         map[string]k8sproxy.Endpoint

		// We distinguish `nil` ("service doesn't use this kind of endpoints") from `sets.Set[string]()` ("service uses
		// this kind of endpoints but has no endpoints"). allEndpoints can be left unset if only one of clusterEndpoints
		// and localEndpoints is set, and allEndpoints is identical to it.
		clusterEndpoints sets.Set[string]
		localEndpoints   sets.Set[string]
		allEndpoints     sets.Set[string]
	}{
		{
			name:        "should use topology since all endpoints have hints, node has a zone label and and there are endpoints for the node's zone",
			nodeLabels:  map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": makeTestEndpointInfo("10.1.2.3", 80, false, true, true, false, sets.New[string]("zone-a"), nil),
				"10.1.2.4:80": makeTestEndpointInfo("10.1.2.4", 80, false, true, true, false, sets.New[string]("zone-b"), nil),
				"10.1.2.5:80": makeTestEndpointInfo("10.1.2.5", 80, false, true, true, false, sets.New[string]("zone-c"), nil),
				"10.1.2.6:80": makeTestEndpointInfo("10.1.2.6", 80, false, true, true, false, sets.New[string]("zone-a"), nil),
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:        "eTP: Local, topology ignored for Local endpoints",
			nodeLabels:  map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": makeTestEndpointInfo("10.1.2.3", 80, true, true, true, false, sets.New[string]("zone-a"), nil),
				"10.1.2.4:80": makeTestEndpointInfo("10.1.2.4", 80, true, true, true, false, sets.New[string]("zone-b"), nil),
				"10.1.2.5:80": makeTestEndpointInfo("10.1.2.5", 80, false, true, true, false, sets.New[string]("zone-c"), nil),
				"10.1.2.6:80": makeTestEndpointInfo("10.1.2.6", 80, false, true, true, false, sets.New[string]("zone-a"), nil),
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.6:80"),
			localEndpoints:   sets.New[string]("10.1.2.3:80", "10.1.2.4:80"),
			allEndpoints:     sets.New[string]("10.1.2.3:80", "10.1.2.4:80", "10.1.2.6:80"),
		},
		{
			name:        "iTP: Local, topology ignored for Local endpoints",
			nodeLabels:  map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, false, true),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": makeTestEndpointInfo("10.1.2.3", 80, true, true, true, false, sets.New[string]("zone-a"), nil),
				"10.1.2.4:80": makeTestEndpointInfo("10.1.2.4", 80, true, true, true, false, sets.New[string]("zone-b"), nil),
				"10.1.2.5:80": makeTestEndpointInfo("10.1.2.5", 80, false, true, true, false, sets.New[string]("zone-c"), nil),
				"10.1.2.6:80": makeTestEndpointInfo("10.1.2.6", 80, false, true, true, false, sets.New[string]("zone-a"), nil),
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.6:80"),
			localEndpoints:   sets.New[string]("10.1.2.3:80", "10.1.2.4:80"),
			allEndpoints:     sets.New[string]("10.1.2.3:80", "10.1.2.4:80", "10.1.2.6:80"),
		},
		{
			name:        "empty node labels",
			nodeLabels:  nil,
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": makeTestEndpointInfo("10.1.2.3", 80, false, true, true, false, sets.New[string]("zone-a"), nil),
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80"),
			localEndpoints:   nil,
		},
		{
			name:        "empty zone label",
			nodeLabels:  map[string]string{v1.LabelTopologyZone: ""},
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": makeTestEndpointInfo("10.1.2.3", 80, false, true, true, false, sets.New[string]("zone-a"), nil),
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80"),
			localEndpoints:   nil,
		},
		{
			name:        "node in different zone, no endpoint filtering",
			nodeLabels:  map[string]string{v1.LabelTopologyZone: "zone-b"},
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": makeTestEndpointInfo("10.1.2.3", 80, false, true, true, false, sets.New[string]("zone-a"), nil),
				"10.1.2.5:80": makeTestEndpointInfo("10.1.2.5", 80, false, true, true, false, sets.New[string]("zone-c"), nil),
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.5:80"),
			localEndpoints:   nil,
		},
		{
			name:        "unready endpoint",
			nodeLabels:  map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": makeTestEndpointInfo("10.1.2.3", 80, false, true, true, false, sets.New[string]("zone-a"), nil),
				"10.1.2.4:80": makeTestEndpointInfo("10.1.2.4", 80, false, true, true, false, sets.New[string]("zone-b"), nil),
				"10.1.2.5:80": makeTestEndpointInfo("10.1.2.5", 80, false, true, true, false, sets.New[string]("zone-c"), nil),
				"10.1.2.6:80": makeTestEndpointInfo("10.1.2.6", 80, false, false, true, false, sets.New[string]("zone-a"), nil),
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80"),
			localEndpoints:   nil,
		},
		{
			name:        "only unready endpoints in same zone (should not filter)",
			nodeLabels:  map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": makeTestEndpointInfo("10.1.2.3", 80, false, false, true, false, sets.New[string]("zone-a"), nil),
				"10.1.2.4:80": makeTestEndpointInfo("10.1.2.4", 80, false, true, true, false, sets.New[string]("zone-b"), nil),
				"10.1.2.5:80": makeTestEndpointInfo("10.1.2.5", 80, false, true, true, false, sets.New[string]("zone-c"), nil),
				"10.1.2.6:80": makeTestEndpointInfo("10.1.2.6", 80, false, false, true, false, sets.New[string]("zone-a"), nil),
			},
			clusterEndpoints: sets.New[string]("10.1.2.4:80", "10.1.2.5:80"),
			localEndpoints:   nil,
		},
		{
			name:        "missing hints, no filtering applied",
			nodeLabels:  map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": makeTestEndpointInfo("10.1.2.3", 80, false, true, true, false, sets.New[string]("zone-a"), nil),
				"10.1.2.4:80": makeTestEndpointInfo("10.1.2.4", 80, false, true, true, false, sets.New[string]("zone-b"), nil),
				"10.1.2.5:80": makeTestEndpointInfo("10.1.2.5", 80, false, true, true, false, nil, nil),
				"10.1.2.6:80": makeTestEndpointInfo("10.1.2.6", 80, false, true, true, false, sets.New[string]("zone-a"), nil),
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.4:80", "10.1.2.5:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:        "multiple hints per endpoint, filtering includes any endpoint with zone included",
			nodeLabels:  map[string]string{v1.LabelTopologyZone: "zone-c"},
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": makeTestEndpointInfo("10.1.2.3", 80, false, true, true, false, sets.New[string]("zone-a", "zone-b", "zone-c"), nil),
				"10.1.2.4:80": makeTestEndpointInfo("10.1.2.4", 80, false, true, true, false, sets.New[string]("zone-b", "zone-c"), nil),
				"10.1.2.5:80": makeTestEndpointInfo("10.1.2.5", 80, false, true, true, false, sets.New[string]("zone-b", "zone-d"), nil),
				"10.1.2.6:80": makeTestEndpointInfo("10.1.2.6", 80, false, true, true, false, sets.New[string]("zone-c"), nil),
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.4:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:              "PreferSameNode falls back to same-zone when feature gate disabled",
			preferSameEnabled: false,
			nodeName:          "node-1",
			nodeLabels:        map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:       makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": makeTestEndpointInfo("10.1.2.3", 80, false, true, true, false, sets.New[string]("zone-a"), sets.New[string]("node-1")),
				"10.1.2.4:80": makeTestEndpointInfo("10.1.2.4", 80, false, true, true, false, sets.New[string]("zone-b"), sets.New[string]("node-2")),
				"10.1.2.5:80": makeTestEndpointInfo("10.1.2.5", 80, false, true, true, false, sets.New[string]("zone-c"), sets.New[string]("node-3")),
				"10.1.2.6:80": makeTestEndpointInfo("10.1.2.6", 80, false, true, true, false, sets.New[string]("zone-a"), sets.New[string]("node-4")),
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:              "PreferSameNode available",
			preferSameEnabled: true,
			nodeName:          "node-1",
			nodeLabels:        map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:       makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": makeTestEndpointInfo("10.1.2.3", 80, false, true, true, false, sets.New[string]("zone-a"), sets.New[string]("node-1")),
				"10.1.2.4:80": makeTestEndpointInfo("10.1.2.4", 80, false, true, true, false, sets.New[string]("zone-b"), sets.New[string]("node-2")),
				"10.1.2.5:80": makeTestEndpointInfo("10.1.2.5", 80, false, true, true, false, sets.New[string]("zone-c"), sets.New[string]("node-3")),
				"10.1.2.6:80": makeTestEndpointInfo("10.1.2.6", 80, false, true, true, false, sets.New[string]("zone-a"), sets.New[string]("node-4")),
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80"),
			localEndpoints:   nil,
		},
		{
			name:              "PreferSameNode ignored if some endpoints unhinted",
			preferSameEnabled: true,
			nodeName:          "node-1",
			nodeLabels:        map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:       makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": makeTestEndpointInfo("10.1.2.3", 80, false, true, true, false, sets.New[string]("zone-a"), sets.New[string]("node-1")),
				"10.1.2.4:80": makeTestEndpointInfo("10.1.2.4", 80, false, true, true, false, nil, nil),
				"10.1.2.5:80": makeTestEndpointInfo("10.1.2.5", 80, false, true, true, false, sets.New[string]("zone-c"), sets.New[string]("node-3")),
				"10.1.2.6:80": makeTestEndpointInfo("10.1.2.6", 80, false, true, true, false, sets.New[string]("zone-a"), sets.New[string]("node-4")),
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.4:80", "10.1.2.5:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:              "PreferSameNode falls back to PreferSameZone if no endpoint for node",
			preferSameEnabled: true,
			nodeName:          "node-0",
			nodeLabels:        map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo:       makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.1.2.3:80": makeTestEndpointInfo("10.1.2.3", 80, false, true, true, false, sets.New[string]("zone-a"), sets.New[string]("node-1")),
				"10.1.2.4:80": makeTestEndpointInfo("10.1.2.4", 80, false, true, true, false, sets.New[string]("zone-b"), sets.New[string]("node-2")),
				"10.1.2.5:80": makeTestEndpointInfo("10.1.2.5", 80, false, true, true, false, sets.New[string]("zone-c"), sets.New[string]("node-3")),
				"10.1.2.6:80": makeTestEndpointInfo("10.1.2.6", 80, false, true, true, false, sets.New[string]("zone-a"), sets.New[string]("node-4")),
			},
			clusterEndpoints: sets.New[string]("10.1.2.3:80", "10.1.2.6:80"),
			localEndpoints:   nil,
		},
		{
			name:        "conflicting topology and localness require merging allEndpoints",
			nodeLabels:  map[string]string{v1.LabelTopologyZone: "zone-a"},
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, false, true),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, true, true, true, false, sets.New[string]("zone-a"), nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, true, true, true, false, sets.New[string]("zone-b"), nil),
				"10.0.0.2:80": makeTestEndpointInfo("10.0.0.2", 80, false, true, true, false, sets.New[string]("zone-a"), nil),
				"10.0.0.3:80": makeTestEndpointInfo("10.0.0.3", 80, false, true, true, false, sets.New[string]("zone-b"), nil),
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.2:80"),
			localEndpoints:   sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80", "10.0.0.2:80"),
		},
		{
			name:             "internalTrafficPolicy: Local, with empty endpoints",
			serviceInfo:      makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, true),
			endpoints:        map[string]k8sproxy.Endpoint{},
			clusterEndpoints: nil,
			localEndpoints:   sets.New[string](),
		},
		{
			name:        "internalTrafficPolicy: Local, but all endpoints are remote",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, true),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, false, true, true, false, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, false, true, true, false, nil, nil),
			},
			clusterEndpoints: nil,
			localEndpoints:   sets.New[string](),
		},
		{
			name:        "internalTrafficPolicy: Local, all endpoints are local",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, true),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, true, true, true, false, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, true, true, true, false, nil, nil),
			},
			clusterEndpoints: nil,
			localEndpoints:   sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
		{
			name:        "internalTrafficPolicy: Local, some endpoints are local",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, true),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, true, true, true, false, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, false, true, true, false, nil, nil),
			},
			clusterEndpoints: nil,
			localEndpoints:   sets.New[string]("10.0.0.0:80"),
		},
		{
			name:        "Cluster traffic policy, endpoints not Ready",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, false, false, true, false, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, false, false, true, false, nil, nil),
			},
			clusterEndpoints: sets.New[string](),
			localEndpoints:   nil,
		},
		{
			name:        "Cluster traffic policy, some endpoints are Ready",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, false, false, true, false, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, false, true, true, false, nil, nil),
			},
			clusterEndpoints: sets.New[string]("10.0.0.1:80"),
			localEndpoints:   nil,
		},
		{
			name:        "Cluster traffic policy, all endpoints are terminating",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, false, false, true, true, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, false, false, true, true, nil, nil),
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   nil,
		},
		{
			name:        "iTP: Local, eTP: Cluster, some endpoints local",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, false, true),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, true, true, true, false, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, false, true, true, false, nil, nil),
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   sets.New[string]("10.0.0.0:80"),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
		{
			name:        "iTP: Cluster, eTP: Local, some endpoints local",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, true, true, true, false, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, false, true, true, false, nil, nil),
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   sets.New[string]("10.0.0.0:80"),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
		{
			name:        "iTP: Local, eTP: Local, some endpoints local",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, true),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, true, true, true, false, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, false, true, true, false, nil, nil),
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   sets.New[string]("10.0.0.0:80"),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
		{
			name:        "iTP: Local, eTP: Local, all endpoints remote",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, true),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, false, true, true, false, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, false, true, true, false, nil, nil),
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   sets.New[string](),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
		{
			name:        "iTP: Local, eTP: Local, all endpoints remote and terminating",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, true),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, false, false, true, true, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, false, false, true, true, nil, nil),
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   sets.New[string](),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
		{
			name:        "iTP: Cluster, eTP: Local, with terminating endpoints",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, false, true, true, false, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, true, false, false, false, nil, nil),
				"10.0.0.2:80": makeTestEndpointInfo("10.0.0.2", 80, true, false, true, true, nil, nil),
				"10.0.0.3:80": makeTestEndpointInfo("10.0.0.3", 80, false, false, true, true, nil, nil),
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80"),
			localEndpoints:   sets.New[string]("10.0.0.2:80"),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.2:80"),
		},
		{
			name:        "eTP ignored if not externally accessible",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, true, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, false, true, true, false, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, true, true, true, false, nil, nil),
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   nil,
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
		{
			name:        "no cluster endpoints for iTP:Local internal-only service",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 0, nil, "", 0, nil, nil, 0, false, true),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, false, true, true, false, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, true, true, true, false, nil, nil),
			},
			clusterEndpoints: nil,
			localEndpoints:   sets.New[string]("10.0.0.1:80"),
			allEndpoints:     sets.New[string]("10.0.0.1:80"),
		},
		{
			name:             "externalTrafficPolicy: Local, externally accessible, with empty endpoints",
			serviceInfo:      makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, false),
			endpoints:        map[string]k8sproxy.Endpoint{},
			clusterEndpoints: sets.New[string](),
			localEndpoints:   sets.New[string](),
		},
		{
			name:        "externalTrafficPolicy: Local, externally accessible, but all endpoints are remote",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, false, true, true, false, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, false, true, true, false, nil, nil),
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   sets.New[string](),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
		{
			name:        "externalTrafficPolicy: Local, externally accessible, all endpoints are local",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, true, true, true, false, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, true, true, true, false, nil, nil),
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
		{
			name:        "externalTrafficPolicy: Local, externally accessible, some endpoints are local",
			serviceInfo: makeServicePortInfo(net.ParseIP("10.96.0.1"), 80, v1.ProtocolTCP, 8080, nil, "", 0, nil, nil, 0, true, false),
			endpoints: map[string]k8sproxy.Endpoint{
				"10.0.0.0:80": makeTestEndpointInfo("10.0.0.0", 80, true, true, true, false, nil, nil),
				"10.0.0.1:80": makeTestEndpointInfo("10.0.0.1", 80, false, true, true, false, nil, nil),
			},
			clusterEndpoints: sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
			localEndpoints:   sets.New[string]("10.0.0.0:80"),
			allEndpoints:     sets.New[string]("10.0.0.0:80", "10.0.0.1:80"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fp := &proxier{topologyLabels: tc.nodeLabels,
				preferSameTrafficDistributionEnabled: tc.preferSameEnabled,
			}

			clusterEndpoints, localEndpoints, allEndpoints := fp.categorizeEndpoints(tc.endpoints, tc.serviceInfo, tc.nodeName, tc.nodeLabels)

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
