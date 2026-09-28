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
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"k8s.io/component-base/metrics/legacyregistry"

	"antrea.io/antrea/v2/pkg/agent/bgp"
	"antrea.io/antrea/v2/pkg/agent/metrics"
	"antrea.io/antrea/v2/pkg/agent/types"
)

var registerBGPMetricsOnce sync.Once

// resetBGPMetrics registers the BGP metrics the first time it is called, and removes every series of the registered
// metrics, so that a test starts from empty metrics.
func resetBGPMetrics() {
	registerBGPMetricsOnce.Do(metrics.InitializeBGPMetrics)
	legacyregistry.Reset()
}

// gatherSeries returns the value of each series of a gauge or counter, keyed by its labels, which are written as
// name=value and joined with commas in the order of their names.
func gatherSeries(t *testing.T, name string) map[string]float64 {
	t.Helper()
	families, err := legacyregistry.DefaultGatherer.Gather()
	require.NoError(t, err)
	series := make(map[string]float64)
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			var labels []string
			for _, label := range metric.GetLabel() {
				labels = append(labels, label.GetName()+"="+label.GetValue())
			}
			series[strings.Join(labels, ",")] = metric.GetGauge().GetValue() + metric.GetCounter().GetValue()
		}
	}
	return series
}

func peerSeries(address string, asn int32) string {
	return fmt.Sprintf("asn=%d,peer=%s", asn, address)
}

func TestPeerMetrics(t *testing.T) {
	resetBGPMetrics()
	c := newFakeController(t, nil, nil, true, false)
	c.bgpPolicyState = generateBGPPolicyState(bgpPolicyName1, 179, 65000,
		nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey], nil, nil, nil)
	c.bgpPolicyState.bgpServer = c.mockBGPServer
	peer1 := peerSeries(ipv4Peer1Addr, peer1ASN)
	peer2 := peerSeries(ipv4Peer2Addr, peer2ASN)

	// The steps run in order, each from the state that the previous one left.
	steps := []struct {
		name          string
		peers         []bgp.PeerStatus
		getPeersErr   error
		noBGPServer   bool
		expectedUp    map[string]float64
		expectedState map[string]float64
		// expectedRoutes is the number of routes advertised to each peer.
		expectedRoutes map[string]float64
	}{
		{
			name: "peers are polled for the first time",
			peers: []bgp.PeerStatus{
				{Address: ipv4Peer1Addr, ASN: peer1ASN, SessionState: bgp.SessionActive},
				{Address: ipv4Peer2Addr, ASN: peer2ASN, SessionState: bgp.SessionEstablished, AdvertisedRouteCount: 2},
			},
			expectedUp:     map[string]float64{peer1: 0, peer2: 1},
			expectedState:  map[string]float64{peer1: 3, peer2: 6},
			expectedRoutes: map[string]float64{peer1: 0, peer2: 2},
		},
		{
			name: "session with a peer is established and the other peer is removed",
			peers: []bgp.PeerStatus{
				{Address: ipv4Peer1Addr, ASN: peer1ASN, SessionState: bgp.SessionEstablished, AdvertisedRouteCount: 2},
			},
			expectedUp:     map[string]float64{peer1: 1},
			expectedState:  map[string]float64{peer1: 6},
			expectedRoutes: map[string]float64{peer1: 2},
		},
		{
			name:           "BGP server fails to report the peers",
			getPeersErr:    errors.New("failed to list peers"),
			expectedUp:     map[string]float64{peer1: 1},
			expectedState:  map[string]float64{peer1: 6},
			expectedRoutes: map[string]float64{peer1: 2},
		},
		{
			name:           "BGP server is stopped",
			noBGPServer:    true,
			expectedUp:     map[string]float64{},
			expectedState:  map[string]float64{},
			expectedRoutes: map[string]float64{},
		},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			if step.noBGPServer {
				c.bgpPolicyState = nil
			} else {
				c.mockBGPServer.EXPECT().GetPeers(gomock.Any()).Return(step.peers, step.getPeersErr)
			}
			c.pollPeerStatus(context.Background())
			assert.Equal(t, step.expectedUp, gatherSeries(t, "antrea_agent_bgp_peer_up"))
			assert.Equal(t, step.expectedState, gatherSeries(t, "antrea_agent_bgp_peer_session_state"))
			assert.Equal(t, step.expectedRoutes, gatherSeries(t, "antrea_agent_bgp_peer_advertised_route_count"))
		})
	}
}

func TestRouteMetrics(t *testing.T) {
	resetBGPMetrics()
	ctx := context.Background()
	c := newFakeController(t, nil, nil, true, false)
	policy := generateBGPPolicy(bgpPolicyName1, creationTimestamp, nodeLabels1, 179, 65000,
		true, false, false, false, true, nil, nil)
	populateListers(t, c, node, policy, ipv4ClusterIP1)
	c.bgpPolicyState = generateBGPPolicyState(bgpPolicyName1, 179, 65000,
		nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey], nil, nil, nil)
	c.bgpPolicyState.bgpServer = c.mockBGPServer
	counts := func(clusterIP, podCIDR float64) map[string]float64 {
		return map[string]float64{
			"type=EgressIP":              0,
			"type=ServiceLoadBalancerIP": 0,
			"type=ServiceExternalIP":     0,
			"type=ServiceClusterIP":      clusterIP,
			"type=NodeIPAMPodCIDR":       podCIDR,
		}
	}

	// Every route type is exported before any route is advertised.
	assert.Equal(t, counts(0, 0), gatherSeries(t, "antrea_agent_bgp_route_advertisement_count"))
	assert.Equal(t, counts(0, 0), gatherSeries(t, "antrea_agent_bgp_route_withdrawal_count"))

	c.mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{clusterIPv4Route1})
	c.mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{podIPv4CIDRRoute})
	require.NoError(t, c.syncBGPPolicy(ctx))
	assert.Equal(t, counts(1, 1), gatherSeries(t, "antrea_agent_bgp_route_advertisement_count"))
	assert.Equal(t, counts(0, 0), gatherSeries(t, "antrea_agent_bgp_route_withdrawal_count"))

	require.NoError(t, c.serviceInformer.GetIndexer().Delete(ipv4ClusterIP1))
	c.mockBGPServer.EXPECT().WithdrawRoutes(gomock.Any(), []bgp.Route{clusterIPv4Route1})
	require.NoError(t, c.syncBGPPolicy(ctx))
	assert.Equal(t, counts(1, 1), gatherSeries(t, "antrea_agent_bgp_route_advertisement_count"))
	assert.Equal(t, counts(1, 0), gatherSeries(t, "antrea_agent_bgp_route_withdrawal_count"))
}

func TestEffectivePolicyMetric(t *testing.T) {
	resetBGPMetrics()
	ctx := context.Background()
	c := newFakeController(t, nil, nil, true, false)
	policy1 := generateBGPPolicy(bgpPolicyName1, creationTimestamp, nodeLabels1, 179, 65000,
		false, false, false, false, false, nil, nil)
	policy2 := generateBGPPolicy(bgpPolicyName2, creationTimestampAdd1s, nodeLabels1, 1179, 65000,
		false, false, false, false, false, nil, nil)
	populateListers(t, c, node, policy1)

	c.mockBGPServer.EXPECT().Start(gomock.Any())
	require.NoError(t, c.syncBGPPolicy(ctx))
	assert.Equal(t, map[string]float64{"policy=" + bgpPolicyName1: 1}, gatherSeries(t, "antrea_agent_bgp_effective_policy"))

	// The BGPPolicy that replaces the deleted one is reported even though its BGP server fails to start.
	require.NoError(t, c.bgpPolicyInformer.GetIndexer().Delete(policy1))
	require.NoError(t, c.bgpPolicyInformer.GetIndexer().Add(policy2))
	c.mockBGPServer.EXPECT().Stop(gomock.Any())
	c.mockBGPServer.EXPECT().Start(gomock.Any()).Return(errors.New("failed to start"))
	require.Error(t, c.syncBGPPolicy(ctx))
	assert.Equal(t, map[string]float64{"policy=" + bgpPolicyName2: 1}, gatherSeries(t, "antrea_agent_bgp_effective_policy"))

	require.NoError(t, c.bgpPolicyInformer.GetIndexer().Delete(policy2))
	require.NoError(t, c.syncBGPPolicy(ctx))
	assert.Empty(t, gatherSeries(t, "antrea_agent_bgp_effective_policy"))
}
