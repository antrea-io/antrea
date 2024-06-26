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
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/agent/bgp"
	"antrea.io/antrea/pkg/agent/bgp/gobgp"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

func TestGoBGPLifecycle(t *testing.T) {
	asn1 := int32(61179)
	asn2 := int32(62179)
	asn3 := int32(63179)
	routerID1 := "192.168.1.1"
	routerID2 := "192.168.1.2"
	routerID3 := "192.168.1.3"
	listenPort1 := int32(1179)
	listenPort2 := int32(2179)
	listenPort3 := int32(3179)
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
	server3GlobalConfig := &bgp.GlobalConfig{
		ASN:        uint32(asn3),
		RouterID:   routerID3,
		ListenPort: listenPort3,
	}

	server1 := gobgp.NewGoBGPServer(server1GlobalConfig)
	server2 := gobgp.NewGoBGPServer(server2GlobalConfig)
	server3 := gobgp.NewGoBGPServer(server3GlobalConfig)

	ctx := context.Background()

	t.Log("Starting all BGP servers")
	require.NoError(t, server1.Start(ctx))
	require.NoError(t, server2.Start(ctx))
	require.NoError(t, server3.Start(ctx))
	t.Log("Started all BGP servers")

	ipv4Server1Config := bgp.PeerConfig{
		BGPPeer: &v1alpha1.BGPPeer{
			Address:                    "127.0.0.1",
			Port:                       ptr.To[int32](1179),
			ASN:                        61179,
			MultihopTTL:                ptr.To[int32](2),
			GracefulRestartTimeSeconds: ptr.To[int32](120),
		},
	}
	ipv6Server1Config := bgp.PeerConfig{
		BGPPeer: &v1alpha1.BGPPeer{
			Address:                    "::1",
			Port:                       ptr.To[int32](1179),
			ASN:                        61179,
			MultihopTTL:                ptr.To[int32](2),
			GracefulRestartTimeSeconds: ptr.To[int32](120),
		},
	}
	ipv4Server2Config := bgp.PeerConfig{
		BGPPeer: &v1alpha1.BGPPeer{
			Address:                    "127.0.0.1",
			Port:                       ptr.To[int32](2179),
			ASN:                        62179,
			MultihopTTL:                ptr.To[int32](3),
			GracefulRestartTimeSeconds: ptr.To[int32](130),
		},
	}
	ipv6Server3Config := bgp.PeerConfig{
		BGPPeer: &v1alpha1.BGPPeer{
			Address:                    "::1",
			Port:                       ptr.To[int32](3179),
			ASN:                        63179,
			MultihopTTL:                ptr.To[int32](1),
			GracefulRestartTimeSeconds: ptr.To[int32](140),
		},
	}

	t.Log("Adding BGP peers for BGP server1")
	require.NoError(t, server1.AddPeer(ctx, ipv4Server2Config))
	require.NoError(t, server1.AddPeer(ctx, ipv6Server3Config))
	t.Log("Added BGP peers for BGP server1")

	t.Log("Adding BGP peers for BGP server2")
	require.NoError(t, server2.AddPeer(ctx, ipv4Server1Config))
	t.Log("Added BGP peers for BGP server2")

	t.Log("Adding BGP peers for BGP server3")
	require.NoError(t, server3.AddPeer(ctx, ipv6Server1Config))
	t.Log("Added BGP peers for BGP server3")

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
		expected := sets.New[string]("::1-63179", "127.0.0.1-62179")
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

	t.Log("Getting peers of BGP server3 and verifying them")
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		expected := sets.New[string]("::1-61179")
		got := getPeersFn(server3)
		assert.Equal(t, expected, got)
	}, 30*time.Second, time.Second)
	t.Log("Got peers of BGP server3 and verified them")

	ipv4Server1Routes := []bgp.Route{
		{Prefix: "1.1.0.0/24"},
		{Prefix: "1.2.0.0/24"},
		{Prefix: "1.3.0.0/24"},
	}
	ipv6Server1Routes := []bgp.Route{
		{Prefix: "1000:1::/64"},
		{Prefix: "1000:2::/64"},
		{Prefix: "1000:3::/64"},
	}
	ipv4Server2Routes := []bgp.Route{
		{Prefix: "2.1.0.0/24"},
		{Prefix: "2.2.0.0/24"},
		{Prefix: "2.3.0.0/24"},
	}
	ipv6Server3Routes := []bgp.Route{
		{Prefix: "3000:1::/64"},
		{Prefix: "3000:2::/64"},
		{Prefix: "3000:3::/64"},
	}

	t.Log("Advertising IPv4 and IPv6 routes on BGP server1")
	require.NoError(t, server1.AdvertiseRoutes(ctx, ipv4Server1Routes))
	require.NoError(t, server1.AdvertiseRoutes(ctx, ipv6Server1Routes))
	t.Log("Advertised IPv4 and IPv6 routes on BGP server1")

	t.Log("Advertising IPv4 routes on BGP server2")
	require.NoError(t, server2.AdvertiseRoutes(ctx, ipv4Server2Routes))
	t.Log("Advertised IPv4 routes on BGP server2")

	t.Log("Advertising IPv6 routes on BGP server3")
	require.NoError(t, server3.AdvertiseRoutes(ctx, ipv6Server3Routes))
	t.Log("Advertised IPv6 routes on server3")

	getReceivedRoutesFn := func(server bgp.Interface, peerAddress string) []bgp.Route {
		routes, err := server.GetRoutes(ctx, bgp.RouteReceived, peerAddress)
		if err != nil {
			return nil
		}
		return routes
	}

	t.Log("Getting received IPv4 and IPv6 routes of BGP server1 and verifying them")
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		// Get the IPv4 routes advertised by server2 and verify them.
		gotIPv4Server2Routes := getReceivedRoutesFn(server1, "127.0.0.1")
		assert.ElementsMatch(t, ipv4Server2Routes, gotIPv4Server2Routes)

		// Get the IPv6 routes advertised by server3 and verify them.
		gotIPv6Server3Routes := getReceivedRoutesFn(server1, "::1")
		assert.ElementsMatch(t, ipv6Server3Routes, gotIPv6Server3Routes)
	}, 30*time.Second, time.Second)
	t.Log("Got received IPv4 and IPv6 routes of BGP server1 and verified them")

	t.Log("Getting received IPv4 routes of BGP server2 and verifying them")
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		// Get the IPv4 routes advertised by server1 and verify them.
		gotIPv4Server1Routes := getReceivedRoutesFn(server2, "127.0.0.1")
		assert.ElementsMatch(t, ipv4Server1Routes, gotIPv4Server1Routes)
	}, 30*time.Second, time.Second)
	t.Log("Got received IPv4 routes of BGP server2 and verified them")

	t.Log("Getting received IPv6 routes of BGP server3 and verifying them")
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		// Get the IPv6 routes advertised by server1 and verify them.
		gotIPv6Server1Routes := getReceivedRoutesFn(server3, "::1")
		assert.ElementsMatch(t, ipv6Server1Routes, gotIPv6Server1Routes)
	}, 30*time.Second, time.Second)
	t.Log("Got received IPv6 routes of BGP server3 and verified them")

	updatedIPv4Server1Routes := []bgp.Route{
		{Prefix: "1.1.0.0/24"},
		{Prefix: "1.2.0.0/24"},
	}
	ipv4Server1RoutesToWithdraw := []bgp.Route{
		{Prefix: "1.3.0.0/24"},
	}
	updatedIPv6Server1Routes := []bgp.Route{
		{Prefix: "1000:1::/64"},
		{Prefix: "1000:2::/64"},
	}
	ipv6Server1RoutesToWithdraw := []bgp.Route{
		{Prefix: "1000:3::/64"},
	}
	updatedIPv4Server2Routes := []bgp.Route{
		{Prefix: "2.1.0.0/24"},
		{Prefix: "2.2.0.0/24"},
	}
	ipv4Server2RoutesToWithdraw := []bgp.Route{
		{Prefix: "2.3.0.0/24"},
	}
	updatedIPv6Server3Routes := []bgp.Route{
		{Prefix: "3000:1::/64"},
		{Prefix: "3000:2::/64"},
	}
	ipv6Server3RoutesToWithdraw := []bgp.Route{
		{Prefix: "3000:3::/64"},
	}

	t.Log("Withdrawing IPv4 and IPv6 routes on BGP server1")
	require.NoError(t, server1.WithdrawRoutes(ctx, ipv4Server1RoutesToWithdraw))
	require.NoError(t, server1.WithdrawRoutes(ctx, ipv6Server1RoutesToWithdraw))
	t.Log("Withdrew IPv4 and IPv6 routes on BGP server1")

	t.Log("Withdrawing IPv4 routes on BGP server2")
	require.NoError(t, server2.WithdrawRoutes(ctx, ipv4Server2RoutesToWithdraw))
	t.Log("Withdrew IPv4 routes on BGP server2")

	t.Log("Withdrawing IPv6 routes on BGP server3")
	require.NoError(t, server3.WithdrawRoutes(ctx, ipv6Server3RoutesToWithdraw))
	t.Log("Withdrew IPv6 routes on BGP server3")

	t.Log("Getting received IPv4 and IPv6 routes of BGP server1 and verifying them")
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		// Get the IPv4 routes advertised by server2 and verify them.
		gotIPv4Server2Routes := getReceivedRoutesFn(server1, "127.0.0.1")
		assert.ElementsMatch(t, updatedIPv4Server2Routes, gotIPv4Server2Routes)

		// Get the IPv6 routes advertised by server3 and verify them.
		gotIPv6Server3Routes := getReceivedRoutesFn(server1, "::1")
		assert.ElementsMatch(t, updatedIPv6Server3Routes, gotIPv6Server3Routes)
	}, 30*time.Second, time.Second)

	t.Log("Getting received IPv4 routes of BGP server2 and verifying them")
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		// Get the IPv4 routes advertised by server1 and verify them.
		gotIPv4Server1Routes := getReceivedRoutesFn(server2, "127.0.0.1")
		assert.ElementsMatch(t, updatedIPv4Server1Routes, gotIPv4Server1Routes)
	}, 30*time.Second, time.Second)
	t.Log("Got received IPv4 routes of BGP server2 and verified them")

	t.Log("Getting received IPv6 routes of BGP server3 and verifying them")
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		// Get the IPv6 routes advertised by server1 and verify them.
		gotIPv6Server1Routes := getReceivedRoutesFn(server3, "::1")
		assert.ElementsMatch(t, updatedIPv6Server1Routes, gotIPv6Server1Routes)
	}, 30*time.Second, time.Second)
	t.Log("Got received IPv6 routes of BGP server3 and verified them")

	updatedIPv4Server2Config := bgp.PeerConfig{
		BGPPeer: &v1alpha1.BGPPeer{
			Address:                    "127.0.0.1",
			Port:                       ptr.To[int32](2179),
			ASN:                        62179,
			MultihopTTL:                ptr.To[int32](1),
			GracefulRestartTimeSeconds: ptr.To[int32](180),
		},
	}
	updatedIPv6Server3Config := bgp.PeerConfig{
		BGPPeer: &v1alpha1.BGPPeer{
			Address:                    "::1",
			Port:                       ptr.To[int32](3179),
			ASN:                        63179,
			MultihopTTL:                ptr.To[int32](1),
			GracefulRestartTimeSeconds: ptr.To[int32](180),
		},
	}
	t.Log("Updating peers of BGP server1")
	require.NoError(t, server1.UpdatePeer(ctx, updatedIPv4Server2Config))
	require.NoError(t, server1.UpdatePeer(ctx, updatedIPv6Server3Config))
	t.Log("Updated peers of server1")

	t.Log("Getting peers of BGP server1 and verifying them")
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		expected := sets.New[string]("::1-63179", "127.0.0.1-62179")
		got := getPeersFn(server1)
		assert.Equal(t, expected, got)
	}, 30*time.Second, time.Second)
	t.Log("Got peers of BGP server1 and verified them")

	t.Log("Deleting peers of BGP server1")
	require.NoError(t, server1.RemovePeer(ctx, updatedIPv4Server2Config))
	require.NoError(t, server1.RemovePeer(ctx, updatedIPv6Server3Config))
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
	require.NoError(t, server3.Stop(ctx))
	t.Log("Stopped all BGP servers")
}
