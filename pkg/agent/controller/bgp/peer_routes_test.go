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
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/v2/pkg/agent/bgp"
	bgptest "antrea.io/antrea/v2/pkg/agent/bgp/testing"
	"antrea.io/antrea/v2/pkg/agent/types"
)

func TestGetBGPPeerRoutes(t *testing.T) {
	routerID := nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey]
	// The address of this peer and the route below are written differently from how they are queried and returned.
	ipv6PeerWithLongAddr := generateBGPPeer("fec0:0:0::196:168:77:251", peer1ASN, 179, 120)
	ipv6RouteWithLongPrefix := bgp.Route{Prefix: "fec0:0:0::10:96:10:10/128"}
	ipv6RouteMetadata := RouteMetadata{Type: ServiceClusterIP, K8sObjRef: getServiceName(ipv6ClusterIPName1)}
	stateWithPeers := func() *bgpPolicyState {
		state := generateBGPPolicyState(bgpPolicyName1, 179, 65000, routerID,
			[]bgp.Route{clusterIPv4Route1, podIPv4CIDRRoute},
			[]bgp.PeerConfig{ipv4Peer1Config, generateBGPPeerConfig(&ipv6PeerWithLongAddr, "")}, nil)
		state.routes[ipv6RouteWithLongPrefix] = ipv6RouteMetadata
		return state
	}

	testCases := []struct {
		name          string
		existingState *bgpPolicyState
		syncError     error
		peerAddress   string
		received      bool
		expectedCalls func(mockBGPServer *bgptest.MockInterfaceMockRecorder)
		expected      map[bgp.Route]RouteMetadata
		expectedErr   string
	}{
		{
			name:          "routes sent to a peer carry their metadata",
			existingState: stateWithPeers(),
			peerAddress:   ipv4Peer1Addr,
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.GetRoutes(gomock.Any(), bgp.RouteAdvertised, ipv4Peer1Addr).Return([]bgp.Route{clusterIPv4Route1, podIPv4CIDRRoute}, nil)
			},
			expected: map[bgp.Route]RouteMetadata{
				clusterIPv4Route1: allRoutes[clusterIPv4Route1],
				podIPv4CIDRRoute:  allRoutes[podIPv4CIDRRoute],
			},
		},
		{
			name:          "routes received from a peer carry no metadata",
			existingState: stateWithPeers(),
			peerAddress:   ipv4Peer1Addr,
			received:      true,
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.GetRoutes(gomock.Any(), bgp.RouteReceived, ipv4Peer1Addr).Return([]bgp.Route{{Prefix: "10.10.10.0/24"}}, nil)
			},
			expected: map[bgp.Route]RouteMetadata{{Prefix: "10.10.10.0/24"}: {}},
		},
		{
			name:          "IPv6 peer and route are matched whatever the way they are written",
			existingState: stateWithPeers(),
			peerAddress:   ipv6Peer1Addr,
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.GetRoutes(gomock.Any(), bgp.RouteAdvertised, "fec0:0:0::196:168:77:251").
					Return([]bgp.Route{{Prefix: "fec0::10:96:10:10/128"}}, nil)
			},
			expected: map[bgp.Route]RouteMetadata{{Prefix: "fec0::10:96:10:10/128"}: ipv6RouteMetadata},
		},
		{
			name:          "BGP server fails to list the routes",
			existingState: stateWithPeers(),
			peerAddress:   ipv4Peer1Addr,
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.GetRoutes(gomock.Any(), bgp.RouteAdvertised, ipv4Peer1Addr).Return(nil, errors.New("failed to list paths"))
			},
			expectedErr: "failed to get the routes of BGP peer 192.168.77.251: failed to list paths",
		},
		{
			name:          "peer is not a peer of the BGPPolicy",
			existingState: stateWithPeers(),
			peerAddress:   ipv4Peer2Addr,
			expectedErr:   "BGP peer not found: 192.168.77.252",
		},
		{
			name:        "no BGPPolicy selects the Node",
			peerAddress: ipv4Peer1Addr,
			expectedErr: ErrBGPPolicyNotFound.Error(),
		},
		{
			name:        "BGPPolicy could not be applied",
			syncError:   errors.New("failed to start BGP server: failed reason"),
			peerAddress: ipv4Peer1Addr,
			expectedErr: "BGPPolicy policy-1 could not be applied: failed to start BGP server: failed reason",
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, nil, nil, true, true)
			c.bgpPolicyState = tt.existingState
			if c.bgpPolicyState != nil {
				c.bgpPolicyState.bgpServer = c.mockBGPServer
			}
			if tt.syncError != nil {
				c.lastSyncPolicyName = bgpPolicyName1
				c.lastSyncError = tt.syncError
			}
			if tt.expectedCalls != nil {
				tt.expectedCalls(c.mockBGPServer.EXPECT())
			}

			routes, err := c.GetBGPPeerRoutes(context.Background(), tt.peerAddress, tt.received)
			if tt.expectedErr != "" {
				assert.EqualError(t, err, tt.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, routes)
		})
	}
}
