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

package bgp

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/v2/pkg/agent/bgp"
	"antrea.io/antrea/v2/pkg/agent/memberlist"
	"antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
)

const testExternalIPPool = "service-external-ip-pool"

func TestGetMEDConfig(t *testing.T) {
	testCases := []struct {
		name          string
		advertisement *v1alpha1.ServiceAdvertisement
		expected      medConfig
		expectedErr   string
	}{
		{
			name:          "nil advertisement",
			advertisement: nil,
			expected:      medConfig{mode: v1alpha1.MEDModeNone, baseValue: 100, step: 100},
		},
		{
			name:          "no MED section keeps MED disabled and forbids Service overrides",
			advertisement: &v1alpha1.ServiceAdvertisement{IPTypes: []v1alpha1.ServiceIPType{v1alpha1.ServiceIPTypeLoadBalancerIP}},
			expected:      medConfig{mode: v1alpha1.MEDModeNone, baseValue: 100, step: 100},
		},
		{
			name: "empty MED section allows Service overrides",
			advertisement: &v1alpha1.ServiceAdvertisement{
				MED: &v1alpha1.MEDAdvertisement{},
			},
			expected: medConfig{mode: v1alpha1.MEDModeNone, baseValue: 100, step: 100, allowServiceOverride: true},
		},
		{
			name: "static mode with defaults",
			advertisement: &v1alpha1.ServiceAdvertisement{
				MED: &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeStatic},
			},
			expected: medConfig{mode: v1alpha1.MEDModeStatic, baseValue: 100, step: 100, allowServiceOverride: true},
		},
		{
			name: "node priority mode fully specified",
			advertisement: &v1alpha1.ServiceAdvertisement{
				MED: &v1alpha1.MEDAdvertisement{
					Mode:                 v1alpha1.MEDModeNodePriority,
					BaseValue:            ptr.To[int64](1000),
					Step:                 ptr.To[int64](50),
					MaxAdvertisingNodes:  ptr.To[int32](3),
					AllowServiceOverride: ptr.To(false),
				},
			},
			expected: medConfig{mode: v1alpha1.MEDModeNodePriority, baseValue: 1000, step: 50, maxAdvertisingNodes: 3},
		},
		{
			name: "base value of 0 disables the attribute but stays valid",
			advertisement: &v1alpha1.ServiceAdvertisement{
				MED: &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeStatic, BaseValue: ptr.To[int64](0)},
			},
			expected: medConfig{mode: v1alpha1.MEDModeStatic, baseValue: 0, step: 100, allowServiceOverride: true},
		},
		{
			name: "invalid mode",
			advertisement: &v1alpha1.ServiceAdvertisement{
				MED: &v1alpha1.MEDAdvertisement{Mode: "Lowest"},
			},
			expected:    medConfig{mode: v1alpha1.MEDModeNone},
			expectedErr: `invalid MED mode "Lowest"`,
		},
		{
			name: "base value out of range",
			advertisement: &v1alpha1.ServiceAdvertisement{
				MED: &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeStatic, BaseValue: ptr.To[int64](math.MaxUint32 + 1)},
			},
			expected:    medConfig{mode: v1alpha1.MEDModeNone},
			expectedErr: "invalid MED baseValue",
		},
		{
			name: "negative base value",
			advertisement: &v1alpha1.ServiceAdvertisement{
				MED: &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeStatic, BaseValue: ptr.To[int64](-1)},
			},
			expected:    medConfig{mode: v1alpha1.MEDModeNone},
			expectedErr: "invalid MED baseValue",
		},
		{
			name: "step of 0",
			advertisement: &v1alpha1.ServiceAdvertisement{
				MED: &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeNodePriority, Step: ptr.To[int64](0)},
			},
			expected:    medConfig{mode: v1alpha1.MEDModeNone},
			expectedErr: "invalid MED step: must be greater than 0",
		},
		{
			name: "maxAdvertisingNodes out of range",
			advertisement: &v1alpha1.ServiceAdvertisement{
				MED: &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeNodePriority, MaxAdvertisingNodes: ptr.To[int32](70000)},
			},
			expected:    medConfig{mode: v1alpha1.MEDModeNone},
			expectedErr: "invalid MED maxAdvertisingNodes",
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getMEDConfig(tt.advertisement)
			if tt.expectedErr != "" {
				require.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.expected, got)
			if tt.expectedErr != "" {
				// An invalid configuration must never advertise a MED.
				assert.True(t, got.disabled())
			}
		})
	}
}

func TestApplyServiceMEDOverrides(t *testing.T) {
	policyConf := medConfig{mode: v1alpha1.MEDModeStatic, baseValue: 100, step: 100, allowServiceOverride: true}

	testCases := []struct {
		name        string
		conf        medConfig
		annotations map[string]string
		expected    medConfig
		expectedErr string
	}{
		{
			name:     "no annotation",
			conf:     policyConf,
			expected: policyConf,
		},
		{
			name:        "override base value",
			conf:        policyConf,
			annotations: map[string]string{types.ServiceBGPMEDAnnotationKey: "4000"},
			expected:    medConfig{mode: v1alpha1.MEDModeStatic, baseValue: 4000, step: 100, allowServiceOverride: true},
		},
		{
			name:        "override mode",
			conf:        policyConf,
			annotations: map[string]string{types.ServiceBGPMEDModeAnnotationKey: string(v1alpha1.MEDModeNodePriority)},
			expected:    medConfig{mode: v1alpha1.MEDModeNodePriority, baseValue: 100, step: 100, allowServiceOverride: true},
		},
		{
			name:        "opt a Service out",
			conf:        policyConf,
			annotations: map[string]string{types.ServiceBGPMEDModeAnnotationKey: string(v1alpha1.MEDModeNone)},
			expected:    medConfig{mode: v1alpha1.MEDModeNone, baseValue: 100, step: 100, allowServiceOverride: true},
		},
		{
			name:        "overrides disabled by the BGPPolicy",
			conf:        medConfig{mode: v1alpha1.MEDModeStatic, baseValue: 100, step: 100, allowServiceOverride: false},
			annotations: map[string]string{types.ServiceBGPMEDAnnotationKey: "4000", types.ServiceBGPMEDModeAnnotationKey: "None"},
			expected:    medConfig{mode: v1alpha1.MEDModeStatic, baseValue: 100, step: 100},
		},
		{
			name:        "invalid base value keeps the BGPPolicy configuration",
			conf:        policyConf,
			annotations: map[string]string{types.ServiceBGPMEDAnnotationKey: "not-a-number"},
			expected:    policyConf,
			expectedErr: "invalid value \"not-a-number\"",
		},
		{
			name:        "out of range base value keeps the BGPPolicy configuration",
			conf:        policyConf,
			annotations: map[string]string{types.ServiceBGPMEDAnnotationKey: "4294967296"},
			expected:    policyConf,
			expectedErr: "out of the range",
		},
		{
			name:        "invalid mode keeps the BGPPolicy configuration",
			conf:        policyConf,
			annotations: map[string]string{types.ServiceBGPMEDModeAnnotationKey: "Highest"},
			expected:    policyConf,
			expectedErr: "invalid value \"Highest\"",
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			svc := &corev1.Service{}
			svc.Annotations = tt.annotations
			got, err := applyServiceMEDOverrides(tt.conf, svc)
			if tt.expectedErr != "" {
				require.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestMEDForRank(t *testing.T) {
	testCases := []struct {
		name     string
		conf     medConfig
		rank     int
		expected uint32
	}{
		{
			name:     "most preferred Node",
			conf:     medConfig{baseValue: 100, step: 100},
			rank:     0,
			expected: 100,
		},
		{
			name:     "third Node",
			conf:     medConfig{baseValue: 100, step: 100},
			rank:     2,
			expected: 300,
		},
		{
			name:     "negative rank is treated as the most preferred Node",
			conf:     medConfig{baseValue: 100, step: 100},
			rank:     -1,
			expected: 100,
		},
		{
			name:     "saturates instead of wrapping around",
			conf:     medConfig{baseValue: math.MaxUint32 - 10, step: 100},
			rank:     5,
			expected: math.MaxUint32,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.conf.medForRank(tt.rank))
		})
	}
}

// generateServiceWithPool returns a LoadBalancer Service whose external IP is allocated from an
// ExternalIPPool, with the given extra annotations.
func generateServiceWithPool(name, clusterIP, loadBalancerIP, pool string, externalTrafficPolicyLocal bool, annotations map[string]string) *corev1.Service {
	svc := generateService(name, corev1.ServiceTypeLoadBalancer, clusterIP, "", loadBalancerIP, false, externalTrafficPolicyLocal)
	svc.Annotations = map[string]string{}
	if pool != "" {
		svc.Annotations[types.ServiceExternalIPPoolAnnotationKey] = pool
	}
	for k, v := range annotations {
		svc.Annotations[k] = v
	}
	return svc
}

func TestAddServiceRoutesWithMED(t *testing.T) {
	lbPrefix := ipStrToPrefix(loadBalancerIPv4)
	clusterPrefix := ipStrToPrefix(clusterIPv4s[1])
	svcRef := getServiceName(ipv4LoadBalancerName)

	testCases := []struct {
		name string
		// med is the MED section of the BGPPolicy Service advertisement.
		med *v1alpha1.MEDAdvertisement
		// annotations are added to the LoadBalancer Service, on top of the ExternalIPPool one.
		annotations map[string]string
		// noPool removes the ExternalIPPool annotation from the Service.
		noPool bool
		// externalTrafficPolicyLocal makes the Service use `externalTrafficPolicy: Local`.
		externalTrafficPolicyLocal bool
		// rankedNodes is what the memberlist cluster returns for the LoadBalancer IP, nil means that
		// SelectNodesForIP is not expected to be called.
		rankedNodes []string
		rankErr     error
		// expectedMaxNodes is the maxNodes argument expected in the SelectNodesForIP call.
		expectedMaxNodes int
		expectedRoutes   map[string]bgp.Route
	}{
		{
			name: "no MED configuration advertises no MED attribute",
			expectedRoutes: map[string]bgp.Route{
				clusterPrefix: {Prefix: clusterPrefix},
				lbPrefix:      {Prefix: lbPrefix},
			},
		},
		{
			name: "static mode applies the base value to every Service IP",
			med:  &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeStatic, BaseValue: ptr.To[int64](500)},
			expectedRoutes: map[string]bgp.Route{
				clusterPrefix: {Prefix: clusterPrefix, MED: 500},
				lbPrefix:      {Prefix: lbPrefix, MED: 500},
			},
		},
		{
			name:             "node priority mode, local Node owns the IP",
			med:              &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeNodePriority},
			rankedNodes:      []string{localNodeName, "node2", "node3"},
			expectedMaxNodes: 0,
			expectedRoutes: map[string]bgp.Route{
				// The ClusterIP cannot be ranked and falls back to the base value.
				clusterPrefix: {Prefix: clusterPrefix, MED: 100},
				lbPrefix:      {Prefix: lbPrefix, MED: 100},
			},
		},
		{
			name:        "node priority mode, local Node is the second backup",
			med:         &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeNodePriority, BaseValue: ptr.To[int64](1000), Step: ptr.To[int64](10)},
			rankedNodes: []string{"node2", "node3", localNodeName},
			expectedRoutes: map[string]bgp.Route{
				clusterPrefix: {Prefix: clusterPrefix, MED: 1000},
				lbPrefix:      {Prefix: lbPrefix, MED: 1020},
			},
		},
		{
			name:             "node priority mode, local Node is not in the ExternalIPPool",
			med:              &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeNodePriority},
			rankedNodes:      []string{"node2", "node3"},
			expectedMaxNodes: 0,
			expectedRoutes: map[string]bgp.Route{
				// The LoadBalancer IP is not advertised at all by this Node.
				clusterPrefix: {Prefix: clusterPrefix, MED: 100},
			},
		},
		{
			name:             "node priority mode limits the number of advertising Nodes",
			med:              &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeNodePriority, MaxAdvertisingNodes: ptr.To[int32](2)},
			rankedNodes:      []string{"node2", "node3"},
			expectedMaxNodes: 2,
			expectedRoutes: map[string]bgp.Route{
				clusterPrefix: {Prefix: clusterPrefix, MED: 100},
			},
		},
		{
			name:        "node priority mode, no Node is eligible",
			med:         &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeNodePriority},
			rankErr:     memberlist.ErrNoNodeAvailable,
			rankedNodes: nil,
			expectedRoutes: map[string]bgp.Route{
				clusterPrefix: {Prefix: clusterPrefix, MED: 100},
			},
		},
		{
			name:        "node priority mode falls back to the base value when the ranking is unavailable",
			med:         &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeNodePriority},
			rankErr:     assert.AnError,
			rankedNodes: nil,
			expectedRoutes: map[string]bgp.Route{
				clusterPrefix: {Prefix: clusterPrefix, MED: 100},
				lbPrefix:      {Prefix: lbPrefix, MED: 100},
			},
		},
		{
			name:   "node priority mode without an ExternalIPPool behaves like the static mode",
			med:    &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeNodePriority},
			noPool: true,
			expectedRoutes: map[string]bgp.Route{
				clusterPrefix: {Prefix: clusterPrefix, MED: 100},
				lbPrefix:      {Prefix: lbPrefix, MED: 100},
			},
		},
		{
			name:        "the Service base value annotation shifts the whole ladder",
			med:         &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeNodePriority, Step: ptr.To[int64](10)},
			annotations: map[string]string{types.ServiceBGPMEDAnnotationKey: "2000"},
			rankedNodes: []string{"node2", localNodeName},
			expectedRoutes: map[string]bgp.Route{
				clusterPrefix: {Prefix: clusterPrefix, MED: 2000},
				lbPrefix:      {Prefix: lbPrefix, MED: 2010},
			},
		},
		{
			name:        "a Service can opt out with an annotation",
			med:         &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeNodePriority},
			annotations: map[string]string{types.ServiceBGPMEDModeAnnotationKey: string(v1alpha1.MEDModeNone)},
			expectedRoutes: map[string]bgp.Route{
				clusterPrefix: {Prefix: clusterPrefix},
				lbPrefix:      {Prefix: lbPrefix},
			},
		},
		{
			name: "a Service cannot opt out when the BGPPolicy forbids overrides",
			med: &v1alpha1.MEDAdvertisement{
				Mode:                 v1alpha1.MEDModeStatic,
				AllowServiceOverride: ptr.To(false),
			},
			annotations: map[string]string{types.ServiceBGPMEDModeAnnotationKey: string(v1alpha1.MEDModeNone)},
			expectedRoutes: map[string]bgp.Route{
				clusterPrefix: {Prefix: clusterPrefix, MED: 100},
				lbPrefix:      {Prefix: lbPrefix, MED: 100},
			},
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			pool := testExternalIPPool
			if tt.noPool {
				pool = ""
			}
			svc := generateServiceWithPool(ipv4LoadBalancerName, clusterIPv4s[1], loadBalancerIPv4, pool, tt.externalTrafficPolicyLocal, tt.annotations)
			c := newFakeController(t, []runtime.Object{svc}, nil, true, false)
			if tt.rankedNodes != nil || tt.rankErr != nil {
				c.mockCluster.EXPECT().
					SelectNodesForIP(loadBalancerIPv4, testExternalIPPool, tt.expectedMaxNodes, gomock.Any()).
					Return(tt.rankedNodes, tt.rankErr).
					MinTimes(1)
			}
			stopCh := make(chan struct{})
			defer close(stopCh)
			c.startInformers(stopCh)

			advertisement := &v1alpha1.ServiceAdvertisement{
				IPTypes: []v1alpha1.ServiceIPType{v1alpha1.ServiceIPTypeClusterIP, v1alpha1.ServiceIPTypeLoadBalancerIP},
				MED:     tt.med,
			}
			routes := make(routeSet)
			c.addServiceRoutes(advertisement, routes)

			got := make(map[string]bgp.Route, len(routes))
			for prefix, entry := range routes {
				got[prefix] = entry.route
				assert.Equal(t, svcRef, entry.metadata.K8sObjRef)
			}
			assert.Equal(t, tt.expectedRoutes, got)
		})
	}
}

// TestAddServiceRoutesMEDRankingWithLocalTrafficPolicy verifies that the Nodes without a healthy
// Endpoint are excluded from the ranking, which is what keeps the most preferred path on the Node
// that the ServiceExternalIP controller elects as the owner of the IP.
func TestAddServiceRoutesMEDRankingWithLocalTrafficPolicy(t *testing.T) {
	svc := generateServiceWithPool(ipv4LoadBalancerName, clusterIPv4s[1], loadBalancerIPv4, testExternalIPPool, true, nil)
	eps := generateEndpointSlice(ipv4LoadBalancerName, endpointSliceSuffix, true, false, endpointIPv4)
	c := newFakeController(t, []runtime.Object{svc, eps}, nil, true, false)

	var capturedFilters []func(string) bool
	c.mockCluster.EXPECT().
		SelectNodesForIP(loadBalancerIPv4, testExternalIPPool, 0, gomock.Any()).
		DoAndReturn(func(_, _ string, _ int, filters ...func(string) bool) ([]string, error) {
			capturedFilters = filters
			return []string{localNodeName}, nil
		})

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.startInformers(stopCh)

	advertisement := &v1alpha1.ServiceAdvertisement{
		IPTypes: []v1alpha1.ServiceIPType{v1alpha1.ServiceIPTypeLoadBalancerIP},
		MED:     &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeNodePriority},
	}
	routes := make(routeSet)
	c.addServiceRoutes(advertisement, routes)

	require.Len(t, capturedFilters, 1, "the Nodes must be filtered when externalTrafficPolicy is Local")
	assert.True(t, capturedFilters[0](localNodeName), "the Node hosting an Endpoint must be eligible")
	assert.False(t, capturedFilters[0]("node-without-endpoint"), "a Node without an Endpoint must be filtered out")

	assert.Equal(t, routeSet{
		ipStrToPrefix(loadBalancerIPv4): {
			route:    bgp.Route{Prefix: ipStrToPrefix(loadBalancerIPv4), MED: 100},
			metadata: RouteMetadata{Type: ServiceLoadBalancerIP, K8sObjRef: getServiceName(ipv4LoadBalancerName)},
		},
	}, routes)
}

// TestAddServiceRoutesMEDRankingAddressFamily verifies that only the EndpointSlices of the address
// family of the advertised IP are considered, so that on a dual-stack cluster a Node hosting only an
// IPv6 Endpoint is not treated as eligible for the IPv4 IP.
func TestAddServiceRoutesMEDRankingAddressFamily(t *testing.T) {
	svc := generateServiceWithPool(ipv4LoadBalancerName, clusterIPv4s[1], loadBalancerIPv4, testExternalIPPool, true, nil)
	ipv6Eps := generateEndpointSlice(ipv4LoadBalancerName, endpointSliceSuffix, true, true, endpointIPv6)
	c := newFakeController(t, []runtime.Object{svc, ipv6Eps}, nil, true, false)

	var capturedFilters []func(string) bool
	c.mockCluster.EXPECT().
		SelectNodesForIP(loadBalancerIPv4, testExternalIPPool, 0, gomock.Any()).
		DoAndReturn(func(_, _ string, _ int, filters ...func(string) bool) ([]string, error) {
			capturedFilters = filters
			return []string{localNodeName}, nil
		})

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.startInformers(stopCh)

	advertisement := &v1alpha1.ServiceAdvertisement{
		IPTypes: []v1alpha1.ServiceIPType{v1alpha1.ServiceIPTypeLoadBalancerIP},
		MED:     &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeNodePriority},
	}
	c.addServiceRoutes(advertisement, make(routeSet))

	require.Len(t, capturedFilters, 1)
	assert.False(t, capturedFilters[0](localNodeName), "an IPv6-only Endpoint must not make the Node eligible for the IPv4 IP")
}

func TestAddRoutesPrefersLowestMED(t *testing.T) {
	prefix := ipStrToPrefix(loadBalancerIPv4)
	routes := make(routeSet)

	addRoutes(routes, prefix, 300, "default/svc-a", ServiceLoadBalancerIP)
	addRoutes(routes, prefix, 100, "default/svc-b", ServiceLoadBalancerIP)
	addRoutes(routes, prefix, 200, "default/svc-c", ServiceLoadBalancerIP)

	require.Len(t, routes, 1)
	assert.Equal(t, routeEntry{
		route:    bgp.Route{Prefix: prefix, MED: 100},
		metadata: RouteMetadata{Type: ServiceLoadBalancerIP, K8sObjRef: "default/svc-b"},
	}, routes[prefix])
}

// TestReconcileBGPAdvertisementsMEDChange verifies that changing the MED of an advertised prefix
// re-advertises it in place: withdrawing it first would make the destination transiently
// unreachable through this Node.
func TestReconcileBGPAdvertisementsMEDChange(t *testing.T) {
	svc := generateServiceWithPool(ipv4LoadBalancerName, clusterIPv4s[1], loadBalancerIPv4, testExternalIPPool, false, nil)
	c := newFakeController(t, []runtime.Object{svc}, nil, true, false)
	stopCh := make(chan struct{})
	defer close(stopCh)
	c.startInformers(stopCh)

	lbPrefix := ipStrToPrefix(loadBalancerIPv4)
	clusterPrefix := ipStrToPrefix(clusterIPv4s[1])
	advertisements := v1alpha1.Advertisements{
		Service: &v1alpha1.ServiceAdvertisement{
			IPTypes: []v1alpha1.ServiceIPType{v1alpha1.ServiceIPTypeClusterIP, v1alpha1.ServiceIPTypeLoadBalancerIP},
			MED:     &v1alpha1.MEDAdvertisement{Mode: v1alpha1.MEDModeNodePriority, Step: ptr.To[int64](50)},
		},
	}
	c.bgpPolicyState = &bgpPolicyState{
		bgpServer: c.mockBGPServer,
		routes:    make(routeSet),
	}

	// The local Node initially owns the IP.
	c.mockCluster.EXPECT().SelectNodesForIP(loadBalancerIPv4, testExternalIPPool, 0).Return([]string{localNodeName, "node2"}, nil)
	c.mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{{Prefix: clusterPrefix, MED: 100}})
	c.mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{{Prefix: lbPrefix, MED: 100}})
	require.NoError(t, c.reconcileBGPAdvertisements(t.Context(), advertisements))
	assert.Equal(t, bgp.Route{Prefix: lbPrefix, MED: 100}, c.bgpPolicyState.routes[lbPrefix].route)

	// Another Node takes over: the prefix is re-advertised with a higher MED and is never withdrawn.
	c.mockCluster.EXPECT().SelectNodesForIP(loadBalancerIPv4, testExternalIPPool, 0).Return([]string{"node2", localNodeName}, nil)
	c.mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{{Prefix: lbPrefix, MED: 150}})
	require.NoError(t, c.reconcileBGPAdvertisements(t.Context(), advertisements))
	assert.Equal(t, bgp.Route{Prefix: lbPrefix, MED: 150}, c.bgpPolicyState.routes[lbPrefix].route)

	// The local Node drops out of the ExternalIPPool: now the prefix is withdrawn.
	c.mockCluster.EXPECT().SelectNodesForIP(loadBalancerIPv4, testExternalIPPool, 0).Return([]string{"node2", "node3"}, nil)
	c.mockBGPServer.EXPECT().WithdrawRoutes(gomock.Any(), []bgp.Route{{Prefix: lbPrefix, MED: 150}})
	require.NoError(t, c.reconcileBGPAdvertisements(t.Context(), advertisements))
	assert.NotContains(t, c.bgpPolicyState.routes, lbPrefix)
	assert.Contains(t, c.bgpPolicyState.routes, clusterPrefix)
}
