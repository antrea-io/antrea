// Copyright 2024 Antrea Authors
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

package bgproute

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"k8s.io/utils/net"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/agent/bgp"
	bgpcontroller "antrea.io/antrea/pkg/agent/controller/bgp"
	queriertest "antrea.io/antrea/pkg/querier/testing"
)

const (
	namespaceDefault = "default"
	ipv4Suffix       = "/32"
	ipv6Suffix       = "/128"
)

var (
	podIPv4CIDR           = "10.10.0.0/24"
	podIPv4CIDRRoute      = bgp.Route{Prefix: podIPv4CIDR}
	clusterIPv4           = "10.96.10.10"
	clusterIPv4Route      = bgp.Route{Prefix: ipStrToPrefix(clusterIPv4)}
	egressIPv4            = "10.96.11.10"
	egressIPv4Route       = bgp.Route{Prefix: ipStrToPrefix(egressIPv4)}
	loadBalancerIPv6      = "fec0::192:168:77:150"
	loadBalancerIPv6Route = bgp.Route{Prefix: ipStrToPrefix(loadBalancerIPv6)}
	egressIPv6            = "fec0::192:168:77:200"
	egressIPv6Route       = bgp.Route{Prefix: ipStrToPrefix(egressIPv6)}

	ipv4ClusterIPName    = "clusterip-4"
	ipv4EgressName       = "egress-4"
	ipv6LoadBalancerName = "loadbalancer-6"
	ipv6EgressName       = "egress-6"

	allRoutes = map[bgp.Route]bgpcontroller.RouteMetadata{
		clusterIPv4Route:      {Type: bgpcontroller.ServiceClusterIP, K8sObjRef: getServiceName(ipv4ClusterIPName)},
		egressIPv4Route:       {Type: bgpcontroller.EgressIP, K8sObjRef: ipv4EgressName},
		loadBalancerIPv6Route: {Type: bgpcontroller.ServiceLoadBalancerIP, K8sObjRef: getServiceName(ipv6LoadBalancerName)},
		egressIPv6Route:       {Type: bgpcontroller.EgressIP, K8sObjRef: ipv6EgressName},
		podIPv4CIDRRoute:      {Type: bgpcontroller.NodeIPAMPodCIDR},
	}
)

func TestBGPRouteQuery(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name             string
		url              string
		expectedCalls    func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier)
		expectedStatus   int
		expectedResponse []apis.BGPRouteResponse
	}{
		{
			name: "bgpPolicyState does not exist",
			expectedCalls: func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier) {
				mockBGPServer.EXPECT().GetBGPRoutes(context.Background()).Return(nil, bgpcontroller.ErrBGPPolicyNotFound)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "get all advertised routes",
			expectedCalls: func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier) {
				mockBGPServer.EXPECT().GetBGPRoutes(ctx).Return(allRoutes, nil)
			},
			expectedStatus: http.StatusOK,
			expectedResponse: []apis.BGPRouteResponse{
				{
					Route:     egressIPv4Route.Prefix,
					Type:      string(allRoutes[egressIPv4Route].Type),
					K8sObjRef: allRoutes[egressIPv4Route].K8sObjRef,
				},
				{
					Route: podIPv4CIDR,
					Type:  string(bgpcontroller.NodeIPAMPodCIDR),
				},
				{
					Route:     clusterIPv4Route.Prefix,
					Type:      string(allRoutes[clusterIPv4Route].Type),
					K8sObjRef: allRoutes[clusterIPv4Route].K8sObjRef,
				},
				{
					Route:     egressIPv6Route.Prefix,
					Type:      string(allRoutes[egressIPv6Route].Type),
					K8sObjRef: allRoutes[egressIPv6Route].K8sObjRef,
				},
				{
					Route:     loadBalancerIPv6Route.Prefix,
					Type:      string(allRoutes[loadBalancerIPv6Route].Type),
					K8sObjRef: allRoutes[loadBalancerIPv6Route].K8sObjRef,
				},
			},
		},
		{
			name: "get advertised ipv4 routes only",
			url:  "?ipv4-only",
			expectedCalls: func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier) {
				mockBGPServer.EXPECT().GetBGPRoutes(ctx).Return(allRoutes, nil)
			},
			expectedStatus: http.StatusOK,
			expectedResponse: []apis.BGPRouteResponse{
				{
					Route:     egressIPv4Route.Prefix,
					Type:      string(allRoutes[egressIPv4Route].Type),
					K8sObjRef: allRoutes[egressIPv4Route].K8sObjRef,
				},
				{
					Route: podIPv4CIDRRoute.Prefix,
					Type:  string(allRoutes[podIPv4CIDRRoute].Type),
				},
				{
					Route:     clusterIPv4Route.Prefix,
					Type:      string(allRoutes[clusterIPv4Route].Type),
					K8sObjRef: allRoutes[clusterIPv4Route].K8sObjRef,
				},
			},
		},
		{
			name: "get advertised ipv6 routes only",
			url:  "?ipv6-only=",
			expectedCalls: func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier) {
				mockBGPServer.EXPECT().GetBGPRoutes(ctx).Return(allRoutes, nil)
			},
			expectedStatus: http.StatusOK,
			expectedResponse: []apis.BGPRouteResponse{
				{
					Route:     egressIPv6Route.Prefix,
					Type:      string(allRoutes[egressIPv6Route].Type),
					K8sObjRef: allRoutes[egressIPv6Route].K8sObjRef,
				},
				{
					Route:     loadBalancerIPv6Route.Prefix,
					Type:      string(allRoutes[loadBalancerIPv6Route].Type),
					K8sObjRef: allRoutes[loadBalancerIPv6Route].K8sObjRef,
				},
			},
		},
		{
			name:           "flag with value",
			url:            "?ipv4-only=true",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "both flags are passed",
			url:            "?ipv4-only&ipv6-only",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "get all advertised egressIP routes",
			url:  "?type=EgressIP",
			expectedCalls: func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier) {
				mockBGPServer.EXPECT().GetBGPRoutes(ctx).Return(allRoutes, nil)
			},
			expectedStatus: http.StatusOK,
			expectedResponse: []apis.BGPRouteResponse{
				{
					Route:     egressIPv4Route.Prefix,
					Type:      string(allRoutes[egressIPv4Route].Type),
					K8sObjRef: allRoutes[egressIPv4Route].K8sObjRef,
				},
				{
					Route:     egressIPv6Route.Prefix,
					Type:      string(allRoutes[egressIPv6Route].Type),
					K8sObjRef: allRoutes[egressIPv6Route].K8sObjRef,
				},
			},
		},
		{
			name: "get advertised IPv4 egressIP routes",
			url:  "?ipv4-only&type=EgressIP",
			expectedCalls: func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier) {
				mockBGPServer.EXPECT().GetBGPRoutes(ctx).Return(allRoutes, nil)
			},
			expectedStatus: http.StatusOK,
			expectedResponse: []apis.BGPRouteResponse{
				{
					Route:     egressIPv4Route.Prefix,
					Type:      string(allRoutes[egressIPv4Route].Type),
					K8sObjRef: allRoutes[egressIPv4Route].K8sObjRef,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			q := queriertest.NewMockAgentBGPPolicyInfoQuerier(ctrl)
			if tt.expectedCalls != nil {
				tt.expectedCalls(q)
			}
			handler := HandleFunc(q)

			req, err := http.NewRequest(http.MethodGet, tt.url, nil)
			require.NoError(t, err)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			assert.Equal(t, tt.expectedStatus, recorder.Code)

			if tt.expectedStatus == http.StatusOK {
				var received []apis.BGPRouteResponse
				err = json.Unmarshal(recorder.Body.Bytes(), &received)
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResponse, received)
			}
		})
	}
}

func getServiceName(name string) string {
	return namespaceDefault + "/" + name
}

func ipStrToPrefix(ipStr string) string {
	if net.IsIPv4String(ipStr) {
		return ipStr + ipv4Suffix
	} else if net.IsIPv6String(ipStr) {
		return ipStr + ipv6Suffix
	}
	return ""
}
