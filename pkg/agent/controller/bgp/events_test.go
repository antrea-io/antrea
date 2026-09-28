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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"antrea.io/antrea/v2/pkg/agent/bgp"
	bgptest "antrea.io/antrea/v2/pkg/agent/bgp/testing"
	"antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
)

type recordedEvent struct {
	// regarding is the name of the object that the Event is recorded on.
	regarding string
	eventType string
	reason    string
	note      string
}

// fakeEventRecorder keeps the Events that the controller records.
type fakeEventRecorder struct {
	events []recordedEvent
}

func (r *fakeEventRecorder) Eventf(regarding runtime.Object, _ runtime.Object, eventType, reason, _, note string, args ...interface{}) {
	r.events = append(r.events, recordedEvent{
		regarding: regarding.(metav1.Object).GetName(),
		eventType: eventType,
		reason:    reason,
		note:      fmt.Sprintf(note, args...),
	})
}

func useFakeEventRecorder(c *fakeController) *fakeEventRecorder {
	recorder := &fakeEventRecorder{}
	c.eventRecorder.recorder = recorder
	return recorder
}

func TestSyncEvents(t *testing.T) {
	policy1 := generateBGPPolicy(bgpPolicyName1, creationTimestamp, nodeLabels1, 179, 65000,
		false, false, false, false, false, []v1alpha1.BGPPeer{ipv4Peer1}, nil)
	policy2 := generateBGPPolicy(bgpPolicyName2, creationTimestampAdd1s, nodeLabels1, 1179, 65000,
		false, false, false, false, false, nil, nil)
	nodeWithIPv6RouterID := generateNode(localNodeName, nodeLabels1, map[string]string{types.NodeBGPRouterIDAnnotationKey: "fec0::1"})
	routerID := nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey]
	serverStarted := recordedEvent{
		regarding: bgpPolicyName1,
		eventType: "Normal",
		reason:    "BGPServerStarted",
		note:      "Started the BGP server on Node local with router ID 192.168.77.100, local ASN 65000 and listen port 179",
	}

	testCases := []struct {
		name           string
		objects        []runtime.Object
		existingState  *bgpPolicyState
		expectedCalls  func(mockBGPServer *bgptest.MockInterfaceMockRecorder)
		expectErr      bool
		expectedEvents []recordedEvent
	}{
		{
			name:    "BGP server starts",
			objects: []runtime.Object{node, policy1},
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), gomock.Any())
			},
			expectedEvents: []recordedEvent{serverStarted},
		},
		{
			name:    "BGP server fails to start",
			objects: []runtime.Object{node, policy1},
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any()).Return(errors.New("listen tcp :179: bind: address already in use"))
			},
			expectErr: true,
			expectedEvents: []recordedEvent{{
				regarding: bgpPolicyName1,
				eventType: "Warning",
				reason:    "BGPServerStartFailed",
				note:      "Failed to apply the BGPPolicy on Node local: failed to start BGP server: listen tcp :179: bind: address already in use",
			}},
		},
		{
			name:    "BGP peer fails to be added",
			objects: []runtime.Object{node, policy1},
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), gomock.Any()).Return(errors.New("peer error"))
			},
			expectErr: true,
			expectedEvents: []recordedEvent{serverStarted, {
				regarding: bgpPolicyName1,
				eventType: "Warning",
				reason:    "BGPPeerConfigFailed",
				note:      "Failed to apply the BGPPolicy on Node local: failed to add BGP peer 192.168.77.251 with ASN 65531: peer error",
			}},
		},
		{
			name:      "router ID is not an IPv4 address",
			objects:   []runtime.Object{nodeWithIPv6RouterID, policy1},
			expectErr: true,
			expectedEvents: []recordedEvent{{
				regarding: bgpPolicyName1,
				eventType: "Warning",
				reason:    "BGPPolicySyncFailed",
				note:      "Failed to apply the BGPPolicy on Node local: BGP router ID should be an IPv4 address string",
			}},
		},
		{
			name:    "several BGPPolicies select the Node",
			objects: []runtime.Object{node, policy1, policy2},
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(gomock.Any())
				mockBGPServer.AddPeer(gomock.Any(), gomock.Any())
			},
			expectedEvents: []recordedEvent{serverStarted, {
				regarding: bgpPolicyName2,
				eventType: "Normal",
				reason:    "BGPPolicyNotEffective",
				note:      "Not applied on Node local, which applies the older BGPPolicy policy-1",
			}},
		},
		{
			name:          "BGP server of a deleted BGPPolicy fails to stop",
			objects:       []runtime.Object{node},
			existingState: generateBGPPolicyState(bgpPolicyName1, 179, 65000, routerID, nil, nil, nil),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Stop(gomock.Any()).Return(errors.New("failed to stop"))
			},
			expectErr: true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, nil, nil, true, false)
			recorder := useFakeEventRecorder(c)
			populateListers(t, c, tt.objects...)
			c.bgpPolicyState = tt.existingState
			if c.bgpPolicyState != nil {
				c.bgpPolicyState.bgpServer = c.mockBGPServer
			}
			if tt.expectedCalls != nil {
				tt.expectedCalls(c.mockBGPServer.EXPECT())
			}

			err := c.syncBGPPolicy(context.Background())
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedEvents, recorder.events)
		})
	}
}

func TestPeerSessionEvents(t *testing.T) {
	policy := generateBGPPolicy(bgpPolicyName1, creationTimestamp, nodeLabels1, 179, 65000,
		false, false, false, false, false, []v1alpha1.BGPPeer{ipv4Peer1, ipv4Peer2}, nil)
	c := newFakeController(t, nil, nil, true, false)
	recorder := useFakeEventRecorder(c)
	populateListers(t, c, node, policy)
	c.bgpPolicyState = generateBGPPolicyState(bgpPolicyName1, 179, 65000,
		nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey], nil, nil, nil)
	c.bgpPolicyState.bgpServer = c.mockBGPServer
	peer1 := func(state bgp.SessionState) bgp.PeerStatus {
		return bgp.PeerStatus{Address: ipv4Peer1Addr, ASN: peer1ASN, SessionState: state}
	}
	peer2 := func(state bgp.SessionState) bgp.PeerStatus {
		return bgp.PeerStatus{Address: ipv4Peer2Addr, ASN: peer2ASN, SessionState: state}
	}
	peer2Up := recordedEvent{
		regarding: bgpPolicyName1,
		eventType: "Normal",
		reason:    "BGPPeerUp",
		note:      "BGP session with peer 192.168.77.252 (ASN 65532) is Established on Node local",
	}

	// The steps run in order, each from the state that the previous one left.
	steps := []struct {
		name           string
		peers          []bgp.PeerStatus
		policyDeleted  bool
		expectedEvents []recordedEvent
	}{
		{
			name:           "sessions are polled for the first time",
			peers:          []bgp.PeerStatus{peer1(bgp.SessionActive), peer2(bgp.SessionEstablished)},
			expectedEvents: []recordedEvent{peer2Up},
		},
		{
			name:  "session is established",
			peers: []bgp.PeerStatus{peer1(bgp.SessionEstablished), peer2(bgp.SessionEstablished)},
			expectedEvents: []recordedEvent{{
				regarding: bgpPolicyName1,
				eventType: "Normal",
				reason:    "BGPPeerUp",
				note:      "BGP session with peer 192.168.77.251 (ASN 65531) is Established on Node local, previous state Active",
			}},
		},
		{
			name:  "session goes down",
			peers: []bgp.PeerStatus{peer1(bgp.SessionIdle), peer2(bgp.SessionEstablished)},
			expectedEvents: []recordedEvent{{
				regarding: bgpPolicyName1,
				eventType: "Warning",
				reason:    "BGPPeerDown",
				note:      "BGP session with peer 192.168.77.251 (ASN 65531) is no longer Established on Node local, current state Idle",
			}},
		},
		{
			name:  "session moves between two states other than Established",
			peers: []bgp.PeerStatus{peer1(bgp.SessionActive), peer2(bgp.SessionEstablished)},
		},
		{
			name:  "peer is removed",
			peers: []bgp.PeerStatus{peer1(bgp.SessionActive)},
		},
		{
			name:           "removed peer is added again with its session established",
			peers:          []bgp.PeerStatus{peer1(bgp.SessionActive), peer2(bgp.SessionEstablished)},
			expectedEvents: []recordedEvent{peer2Up},
		},
		{
			name:          "session is established after the BGPPolicy was deleted",
			peers:         []bgp.PeerStatus{peer1(bgp.SessionEstablished), peer2(bgp.SessionEstablished)},
			policyDeleted: true,
		},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			recorder.events = nil
			if step.policyDeleted {
				require.NoError(t, c.bgpPolicyInformer.GetIndexer().Delete(policy))
			}
			c.mockBGPServer.EXPECT().GetPeers(gomock.Any()).Return(step.peers, nil)
			c.pollPeerStatus(context.Background())
			assert.Equal(t, step.expectedEvents, recorder.events)
		})
	}
}
