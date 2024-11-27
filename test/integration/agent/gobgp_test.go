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

package agent

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/agent/bgp"
	"antrea.io/antrea/pkg/agent/bgp/gobgp"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

func TestGoBGPLifecycle(t *testing.T) {
	asn1 := int32(61179)
	asn2 := int32(62179)
	routerID1 := "192.168.1.1"
	routerID2 := "192.168.1.2"
	listenPort1 := int32(1179)
	listenPort2 := int32(2179)
	server1GlobalConfig := &bgp.GlobalConfig{
		ASN:        uint32(asn1),
		RouterID:   routerID1,
		ListenPort: listenPort1,
	}
	server2GlobalConfig := &bgp.GlobalConfig{
		ASN:        uint32(asn2),
		RouterID:   routerID2,
		ListenPort: listenPort2,
	}

	var l klog.Level
	require.NoError(t, l.Set("4"))
	defer l.Set("0")

	server1 := gobgp.NewGoBGPServer(server1GlobalConfig)
	server2 := gobgp.NewGoBGPServer(server2GlobalConfig)

	ctx := context.Background()

	t.Log("Starting all BGP servers")
	require.NoError(t, server1.Start(ctx))
	require.NoError(t, server2.Start(ctx))
	t.Log("Started all BGP servers")

	server1Config := bgp.PeerConfig{
		BGPPeer: &v1alpha1.BGPPeer{
			Address:                    "127.0.0.1",
			Port:                       &listenPort1,
			ASN:                        asn1,
			MultihopTTL:                ptr.To[int32](2),
			GracefulRestartTimeSeconds: ptr.To[int32](120),
		},
	}
	server2Config := bgp.PeerConfig{
		BGPPeer: &v1alpha1.BGPPeer{
			Address:                    "127.0.0.1",
			Port:                       &listenPort2,
			ASN:                        asn2,
			MultihopTTL:                ptr.To[int32](3),
			GracefulRestartTimeSeconds: ptr.To[int32](130),
		},
	}

	t.Log("Adding BGP peers for BGP server1")
	require.NoError(t, server1.AddPeer(ctx, server2Config))
	t.Log("Added BGP peers for BGP server1")

	t.Log("Adding BGP peers for BGP server2")
	require.NoError(t, server2.AddPeer(ctx, server1Config))
	t.Log("Added BGP peers for BGP server2")

	getPeersFn := func(server bgp.Interface) sets.Set[string] {
		peerKeys := sets.New[string]()
		peers, err := server.GetPeers(ctx)
		if err != nil {
			return nil
		}
		for _, peer := range peers {
			if peer.SessionState != bgp.SessionEstablished {
				continue
			}
			peerKeys.Insert(fmt.Sprintf("%s-%d", peer.Address, peer.ASN))
		}
		return peerKeys
	}

	t.Log("Getting peers of BGP server1 and verifying them")
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		expected := sets.New[string]("127.0.0.1-62179")
		got := getPeersFn(server1)
		assert.Equal(t, expected, got)
	}, 30*time.Second, time.Second)
	t.Log("Got peers of BGP server1 and verified them")

	t.Log("Getting peers of BGP server2 and verifying them")
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		expected := sets.New[string]("127.0.0.1-61179")
		got := getPeersFn(server2)
		assert.Equal(t, expected, got)
	}, 30*time.Second, time.Second)
	t.Log("Got peers of BGP server2 and verified them")

	server1Routes := []bgp.Route{
		{Prefix: "1.1.0.0/24"},
		{Prefix: "1.2.0.0/24"},
		{Prefix: "1.3.0.0/24"},
	}
	server2Routes := []bgp.Route{
		{Prefix: "2.1.0.0/24"},
		{Prefix: "2.2.0.0/24"},
		{Prefix: "2.3.0.0/24"},
	}

	t.Log("Advertising routes on BGP server1")
	require.NoError(t, server1.AdvertiseRoutes(ctx, server1Routes))
	t.Log("Advertised routes on BGP server1")

	t.Log("Advertising routes on BGP server2")
	require.NoError(t, server2.AdvertiseRoutes(ctx, server2Routes))
	t.Log("Advertised routes on BGP server2")

	getReceivedRoutesFn := func(server bgp.Interface, peerAddress string) []bgp.Route {
		routes, err := server.GetRoutes(ctx, bgp.RouteReceived, peerAddress)
		if err != nil {
			return nil
		}
		return routes
	}

	t.Log("Getting received routes of BGP server1 and verifying them")
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		// Get the routes advertised by server2 and verify them.
		gotServer2Routes := getReceivedRoutesFn(server1, "127.0.0.1")
		assert.ElementsMatch(t, server2Routes, gotServer2Routes)
	}, 30*time.Second, time.Second)
	t.Log("Got received routes of BGP server1 and verified them")

	t.Log("Getting received routes of BGP server2 and verifying them")
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		// Get the routes advertised by server1 and verify them.
		gotServer1Routes := getReceivedRoutesFn(server2, "127.0.0.1")
		assert.ElementsMatch(t, server1Routes, gotServer1Routes)
	}, 30*time.Second, time.Second)
	t.Log("Got received routes of BGP server2 and verified them")

	updatedServer1Routes := []bgp.Route{
		{Prefix: "1.1.0.0/24"},
		{Prefix: "1.2.0.0/24"},
	}
	server1RoutesToWithdraw := []bgp.Route{
		{Prefix: "1.3.0.0/24"},
	}
	updatedServer2Routes := []bgp.Route{
		{Prefix: "2.1.0.0/24"},
		{Prefix: "2.2.0.0/24"},
	}
	server2RoutesToWithdraw := []bgp.Route{
		{Prefix: "2.3.0.0/24"},
	}

	t.Log("Withdrawing routes on BGP server1")
	require.NoError(t, server1.WithdrawRoutes(ctx, server1RoutesToWithdraw))
	t.Log("Withdrew routes on BGP server1")

	t.Log("Withdrawing routes on BGP server2")
	require.NoError(t, server2.WithdrawRoutes(ctx, server2RoutesToWithdraw))
	t.Log("Withdrew routes on BGP server2")

	t.Log("Getting received routes of BGP server1 and verifying them")
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		// Get the routes advertised by server2 and verify them.
		gotServer2Routes := getReceivedRoutesFn(server1, "127.0.0.1")
		assert.ElementsMatch(t, updatedServer2Routes, gotServer2Routes)
	}, 30*time.Second, time.Second)

	t.Log("Getting received routes of BGP server2 and verifying them")
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		// Get the routes advertised by server1 and verify them.
		gotServer1Routes := getReceivedRoutesFn(server2, "127.0.0.1")
		assert.ElementsMatch(t, updatedServer1Routes, gotServer1Routes)
	}, 30*time.Second, time.Second)
	t.Log("Got received routes of BGP server2 and verified them")

	updatedServer2Config := bgp.PeerConfig{
		BGPPeer: &v1alpha1.BGPPeer{
			Address:                    "127.0.0.1",
			Port:                       &listenPort2,
			ASN:                        asn2,
			MultihopTTL:                ptr.To[int32](1),
			GracefulRestartTimeSeconds: ptr.To[int32](180),
		},
	}
	t.Log("Updating peers of BGP server1")
	require.NoError(t, server1.UpdatePeer(ctx, updatedServer2Config))
	t.Log("Updated peers of server1")

	t.Log("Getting peers of BGP server1 and verifying them")
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		expected := sets.New[string]("127.0.0.1-62179")
		got := getPeersFn(server1)
		assert.Equal(t, expected, got)
	}, 30*time.Second, time.Second)
	t.Log("Got peers of BGP server1 and verified them")

	t.Log("Deleting peers of BGP server1")
	require.NoError(t, server1.RemovePeer(ctx, updatedServer2Config))
	t.Log("Deleted peers of BGP server1")

	t.Log("Getting peers of BGP server1 and verifying them")
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		expected := sets.New[string]()
		got := getPeersFn(server1)
		assert.Equal(t, expected, got)
	}, 30*time.Second, time.Second)
	t.Log("Got peers of BGP server1 and verified them")

	t.Log("Stopping all BGP servers")
	require.NoError(t, server1.Stop(ctx))
	require.NoError(t, server2.Stop(ctx))
	t.Log("Stopped all BGP servers")
}
