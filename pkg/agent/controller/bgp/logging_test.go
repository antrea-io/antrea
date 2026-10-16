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
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/bgp"
	bgptest "antrea.io/antrea/v2/pkg/agent/bgp/testing"
	"antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/v2/pkg/util/env"
)

// captureLogs redirects the output of klog to a buffer until the end of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	klog.SetOutput(&buf)
	klog.LogToStderr(false)
	t.Cleanup(func() {
		klog.SetOutput(os.Stderr)
		klog.LogToStderr(true)
	})
	return &buf
}

func TestBGPPeerChanges(t *testing.T) {
	peerWithNewPort := generateBGPPeer(ipv4Peer1Addr, peer1ASN, 1179, 120)
	errPeer := errors.New("peer error")

	testCases := []struct {
		name          string
		existingPeers []bgp.PeerConfig
		policyPeers   []v1alpha1.BGPPeer
		expectedCalls func(mockBGPServer *bgptest.MockInterfaceMockRecorder)
		expectedErr   string
		expectedLog   string
	}{
		{
			name:        "peer is added",
			policyPeers: []v1alpha1.BGPPeer{ipv4Peer1},
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.AddPeer(gomock.Any(), gomock.Any())
			},
			expectedLog: `"Added BGP peer" peer="192.168.77.251" asn=65531`,
		},
		{
			name:          "peer is updated",
			existingPeers: []bgp.PeerConfig{generateBGPPeerConfig(&ipv4Peer1, "")},
			policyPeers:   []v1alpha1.BGPPeer{peerWithNewPort},
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.UpdatePeer(gomock.Any(), gomock.Any())
			},
			expectedLog: `"Updated BGP peer" peer="192.168.77.251" asn=65531`,
		},
		{
			name:          "peer is removed",
			existingPeers: []bgp.PeerConfig{generateBGPPeerConfig(&ipv4Peer1, "")},
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.RemovePeer(gomock.Any(), gomock.Any())
			},
			expectedLog: `"Removed BGP peer" peer="192.168.77.251" asn=65531`,
		},
		{
			name:        "peer fails to be added",
			policyPeers: []v1alpha1.BGPPeer{ipv4Peer1},
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.AddPeer(gomock.Any(), gomock.Any()).Return(errPeer)
			},
			expectedErr: "failed to add BGP peer 192.168.77.251 with ASN 65531: peer error",
		},
		{
			name:          "peer fails to be updated",
			existingPeers: []bgp.PeerConfig{generateBGPPeerConfig(&ipv4Peer1, "")},
			policyPeers:   []v1alpha1.BGPPeer{peerWithNewPort},
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.UpdatePeer(gomock.Any(), gomock.Any()).Return(errPeer)
			},
			expectedErr: "failed to update BGP peer 192.168.77.251 with ASN 65531: peer error",
		},
		{
			name:          "peer fails to be removed",
			existingPeers: []bgp.PeerConfig{generateBGPPeerConfig(&ipv4Peer1, "")},
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.RemovePeer(gomock.Any(), gomock.Any()).Return(errPeer)
			},
			expectedErr: "failed to remove BGP peer 192.168.77.251 with ASN 65531: peer error",
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)
			policy := generateBGPPolicy(bgpPolicyName1, creationTimestamp, nodeLabels1, 179, 65000,
				false, false, false, false, false, tt.policyPeers, nil)
			c := newFakeController(t, nil, nil, true, false)
			populateListers(t, c, node, policy)
			c.bgpPolicyState = generateBGPPolicyState(bgpPolicyName1, 179, 65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey], nil, tt.existingPeers, nil)
			c.bgpPolicyState.bgpServer = c.mockBGPServer
			tt.expectedCalls(c.mockBGPServer.EXPECT())

			err := c.syncBGPPolicy(context.Background())
			klog.Flush()
			if tt.expectedErr != "" {
				assert.EqualError(t, err, tt.expectedErr)
				return
			}
			assert.NoError(t, err)
			assert.Contains(t, logs.String(), tt.expectedLog)
		})
	}
}

func TestMissingBGPPeerPassword(t *testing.T) {
	peerKey := generateBGPPeerKey(ipv4Peer1Addr, peer1ASN)
	missingPasswordLog := `"The password Secret has no entry for the BGP peer, so the session is not authenticated" ` +
		`peer="192.168.77.251" asn=65531 secret="` + env.GetAntreaNamespace() + `/antrea-bgp-passwords" expectedKey="192.168.77.251-65531"`
	secret := func(data map[string][]byte) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: env.GetAntreaNamespace(), Name: types.BGPPolicySecretName},
			Data:       data,
		}
	}

	testCases := []struct {
		name             string
		secret           *corev1.Secret
		expectedPassword string
		expectLog        bool
	}{
		{
			name:      "Secret has no entry for the peer",
			secret:    secret(map[string][]byte{generateBGPPeerKey(ipv4Peer2Addr, peer2ASN): []byte(peer2AuthPassword)}),
			expectLog: true,
		},
		{
			name:      "Secret has no data",
			secret:    secret(nil),
			expectLog: true,
		},
		{
			name:             "Secret has an entry for the peer",
			secret:           secret(map[string][]byte{peerKey: []byte(peer1AuthPassword)}),
			expectedPassword: peer1AuthPassword,
		},
		{
			name: "Secret does not exist",
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)
			c := newFakeController(t, nil, nil, true, false)
			c.updateBGPPeerPasswords(tt.secret)

			peerConfigs := c.getPeerConfigs([]v1alpha1.BGPPeer{ipv4Peer1})
			klog.Flush()
			assert.Equal(t, tt.expectedPassword, peerConfigs[peerKey].Password)
			if tt.expectLog {
				assert.Contains(t, logs.String(), missingPasswordLog)
			} else {
				assert.NotContains(t, logs.String(), "The password Secret has no entry for the BGP peer")
			}
		})
	}
}
