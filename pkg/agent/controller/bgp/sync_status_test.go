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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/v2/pkg/agent/bgp"
	bgptest "antrea.io/antrea/v2/pkg/agent/bgp/testing"
	"antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	crdv1b1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
)

// populateListers adds objects directly to the indexers of the informers of the controller, so that a sync sees them
// without the informers running.
func populateListers(t *testing.T, c *fakeController, objects ...runtime.Object) {
	t.Helper()
	for _, obj := range objects {
		var indexer cache.Indexer
		switch obj.(type) {
		case *corev1.Node:
			indexer = c.nodeInformer.GetIndexer()
		case *corev1.Service:
			indexer = c.serviceInformer.GetIndexer()
		case *discovery.EndpointSlice:
			indexer = c.endpointSliceInformer.GetIndexer()
		case *v1alpha1.BGPPolicy:
			indexer = c.bgpPolicyInformer.GetIndexer()
		case *crdv1b1.Egress:
			indexer = c.egressInformer.GetIndexer()
		default:
			t.Fatalf("Unsupported object type %T", obj)
		}
		require.NoError(t, indexer.Add(obj))
	}
}

func TestSyncResultReporting(t *testing.T) {
	policy := generateBGPPolicy(bgpPolicyName1, creationTimestamp, nodeLabels1, 179, 65000,
		false, false, false, false, true, []v1alpha1.BGPPeer{ipv4Peer1}, nil)
	routerID := nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey]
	nodeWithIPv6RouterID := generateNode(localNodeName, nodeLabels1, map[string]string{types.NodeBGPRouterIDAnnotationKey: "fec0::1"})
	errListen := errors.New("listen tcp :179: bind: address already in use")
	startErrMsg := fmt.Sprintf("failed to start BGP server: %v", errListen)

	testCases := []struct {
		name          string
		objects       []runtime.Object
		existingState *bgpPolicyState
		// existingSyncError is the error of a previous sync of the BGPPolicy.
		existingSyncError error
		expectedCalls     func(mockBGPServer *bgptest.MockInterfaceMockRecorder)
		expectedErr       string
		expectedInfo      *BGPPolicyInfo
		// expectPolicyNotApplied means that the peer and route queries report the BGPPolicy and the sync error,
		// and expectPolicyNotFound that they report the absence of a BGPPolicy.
		expectPolicyNotApplied bool
		expectPolicyNotFound   bool
	}{
		{
			name:    "BGP server fails to start",
			objects: []runtime.Object{node, policy},
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any()).Return(errListen)
			},
			expectedErr:            startErrMsg,
			expectedInfo:           &BGPPolicyInfo{BGPPolicyName: bgpPolicyName1, LastSyncError: startErrMsg},
			expectPolicyNotApplied: true,
		},
		{
			name:                   "router ID is not an IPv4 address",
			objects:                []runtime.Object{nodeWithIPv6RouterID, policy},
			expectedErr:            "BGP router ID should be an IPv4 address string",
			expectedInfo:           &BGPPolicyInfo{BGPPolicyName: bgpPolicyName1, LastSyncError: "BGP router ID should be an IPv4 address string"},
			expectPolicyNotApplied: true,
		},
		{
			name:    "routes fail to be advertised after the BGP server started",
			objects: []runtime.Object{node, policy},
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), gomock.Any())
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv4CIDRRoute}).Return(errors.New("failed to advertise routes"))
			},
			expectedErr: "failed to advertise routes",
			expectedInfo: &BGPPolicyInfo{
				BGPPolicyName: bgpPolicyName1,
				RouterID:      routerID,
				LocalASN:      65000,
				ListenPort:    179,
				LastSyncError: "failed to advertise routes",
			},
		},
		{
			name:              "sync succeeds after a failure",
			objects:           []runtime.Object{node, policy},
			existingSyncError: fmt.Errorf("failed to start BGP server: %w", errListen),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), gomock.Any())
				mockBGPServer.AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv4CIDRRoute})
			},
			expectedInfo: &BGPPolicyInfo{
				BGPPolicyName: bgpPolicyName1,
				RouterID:      routerID,
				LocalASN:      65000,
				ListenPort:    179,
			},
		},
		{
			name:          "BGP server of a deleted BGPPolicy fails to stop",
			objects:       []runtime.Object{node},
			existingState: generateBGPPolicyState(bgpPolicyName1, 179, 65000, routerID, nil, nil, nil),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Stop(gomock.Any()).Return(errors.New("failed to stop"))
			},
			expectedErr: "failed to stop",
			expectedInfo: &BGPPolicyInfo{
				BGPPolicyName: bgpPolicyName1,
				RouterID:      routerID,
				LocalASN:      65000,
				ListenPort:    179,
				LastSyncError: "failed to stop",
			},
		},
		{
			name:                 "no BGPPolicy selects the Node any more after a failure",
			objects:              []runtime.Object{node},
			existingSyncError:    fmt.Errorf("failed to start BGP server: %w", errListen),
			expectPolicyNotFound: true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			c := newFakeController(t, nil, nil, true, false)
			populateListers(t, c, tt.objects...)
			c.bgpPolicyState = tt.existingState
			if c.bgpPolicyState != nil {
				c.bgpPolicyState.bgpServer = c.mockBGPServer
			}
			if tt.existingSyncError != nil {
				c.lastSyncPolicyName = bgpPolicyName1
				c.lastSyncError = tt.existingSyncError
			}
			if tt.expectedCalls != nil {
				tt.expectedCalls(c.mockBGPServer.EXPECT())
			}

			err := c.syncBGPPolicy(ctx)
			if tt.expectedErr != "" {
				assert.EqualError(t, err, tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedInfo, c.GetBGPPolicyInfo())

			if !tt.expectPolicyNotApplied && !tt.expectPolicyNotFound {
				return
			}
			_, peersErr := c.GetBGPPeerStatus(ctx)
			_, routesErr := c.GetBGPRoutes(ctx)
			for _, queryErr := range []error{peersErr, routesErr} {
				if tt.expectPolicyNotApplied {
					var notAppliedErr *BGPPolicyNotAppliedError
					require.ErrorAs(t, queryErr, &notAppliedErr)
					assert.Equal(t, bgpPolicyName1, notAppliedErr.BGPPolicyName)
					assert.EqualError(t, queryErr, fmt.Sprintf("BGPPolicy %s could not be applied: %s", bgpPolicyName1, tt.expectedErr))
				}
				if tt.expectPolicyNotFound {
					assert.ErrorIs(t, queryErr, ErrBGPPolicyNotFound)
				}
			}
		})
	}
}
