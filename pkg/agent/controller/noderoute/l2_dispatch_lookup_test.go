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

package noderoute

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	utilip "antrea.io/antrea/v2/pkg/util/ip"
)

// TestGetL2DispatchPeerIndex checks that the index of a peer Node is given out only while its routing is installed,
// and that the handlers are notified when that changes.
func TestGetL2DispatchPeerIndex(t *testing.T) {
	c := newL2DispatchController(t)
	var notifiedNodes []string
	c.AddL2DispatchPeerEventHandler(func(nodeName string) {
		notifiedNodes = append(notifiedNodes, nodeName)
	})
	c.createNode(t, node1)
	remoteSubnetNode := newTestNode("remoteSubnetNode", podCIDR2, remoteSubnetNodeIP)
	c.createNode(t, remoteSubnetNode)
	require.Eventually(t, func() bool {
		_, err1 := c.nodeLister.Get(node1.Name)
		_, err2 := c.nodeLister.Get(remoteSubnetNode.Name)
		return err1 == nil && err2 == nil
	}, 5*time.Second, 10*time.Millisecond)

	// node1 is in the local subnet, but its routing is not installed yet.
	index, ok, err := c.GetL2DispatchPeerIndex(node1.Name, false)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Zero(t, index)

	// Once its routing is installed, node1 has an index and the handlers are notified.
	c.routeClient.EXPECT().AddL2DispatchPeerRoutes(uint32(1), &utilip.DualStackIPs{IPv4: nodeIP1})
	c.ofClient.EXPECT().InstallNodeFlows("node1", gomock.Any(), &dsIPs1, uint32(0), nil)
	c.routeClient.EXPECT().AddRoutes(podCIDR1, "node1", nodeIP1, podCIDR1Gateway)
	c.routeClient.EXPECT().AddRoutes(podCIDR1v6, "node1", nil, podCIDR1v6Gateway)
	c.processNextWorkItem()
	assert.Equal(t, []string{"node1"}, notifiedNodes)
	index, ok, err = c.GetL2DispatchPeerIndex(node1.Name, false)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, uint32(1), index)
	// node1 has no IPv6 transport IP.
	_, ok, err = c.GetL2DispatchPeerIndex(node1.Name, true)
	assert.ErrorContains(t, err, "the l2 dispatch cannot reach Node node1: it has no IPv6 transport IP")
	assert.False(t, ok)

	// A Node in another subnet never gets an index.
	c.ofClient.EXPECT().InstallNodeFlows("remoteSubnetNode", gomock.Any(), &utilip.DualStackIPs{IPv4: remoteSubnetNodeIP},
		uint32(0), nil)
	c.routeClient.EXPECT().AddRoutes(podCIDR2, "remoteSubnetNode", remoteSubnetNodeIP, podCIDR2Gateway)
	c.processNextWorkItem()
	assert.Equal(t, []string{"node1"}, notifiedNodes)
	_, ok, err = c.GetL2DispatchPeerIndex(remoteSubnetNode.Name, false)
	assert.ErrorContains(t, err, "the l2 dispatch cannot reach Node remoteSubnetNode: its IPv4 transport IP 10.10.20.10 "+
		"is not in the local transport subnet 10.10.10.0/24")
	assert.False(t, ok)
	_, _, err = c.GetL2DispatchPeerIndex("unknownNode", false)
	assert.ErrorContains(t, err, "failed to get Node unknownNode")

	// When node1 is deleted, the handlers are notified before its routing is removed, and it no longer has an index.
	require.NoError(t, c.clientset.CoreV1().Nodes().Delete(context.TODO(), node1.Name, metav1.DeleteOptions{}))
	c.routeClient.EXPECT().DeleteRoutes(podCIDR1)
	c.routeClient.EXPECT().DeleteRoutes(podCIDR1v6)
	c.ofClient.EXPECT().UninstallNodeFlows("node1")
	c.routeClient.EXPECT().DeleteL2DispatchPeerRoutes(uint32(1)).Do(func(uint32) {
		assert.Equal(t, []string{"node1", "node1"}, notifiedNodes,
			"The handlers must be notified before the routing is removed")
	})
	c.processNextWorkItem()
	assert.Equal(t, []string{"node1", "node1"}, notifiedNodes)
	_, ok, err = c.GetL2DispatchPeerIndex(node1.Name, false)
	assert.ErrorContains(t, err, "failed to get Node node1")
	assert.False(t, ok)
}

func TestL2DispatchPeerRoutedState(t *testing.T) {
	a := newL2DispatchPeerIndices()
	index, err := a.allocate("node1")
	require.NoError(t, err)
	_, _, routed := a.getRouted("node1")
	assert.False(t, routed, "an index is not given out before its routing is installed")

	assert.True(t, a.setRouted("node1", &utilip.DualStackIPs{IPv4: nodeIP1}))
	assert.False(t, a.setRouted("node1", &utilip.DualStackIPs{IPv4: nodeIP1}), "the routing did not change")
	assert.True(t, a.setRouted("node1", &utilip.DualStackIPs{IPv4: nodeIP1, IPv6: nodeIP2}),
		"the routing gained an IP family")
	routedIndex, peerIPs, routed := a.getRouted("node1")
	assert.True(t, routed)
	assert.Equal(t, index, routedIndex)
	assert.Equal(t, &utilip.DualStackIPs{IPv4: nodeIP1, IPv6: nodeIP2}, peerIPs)

	assert.True(t, a.clearRouted("node1"))
	assert.False(t, a.clearRouted("node1"))
	_, _, routed = a.getRouted("node1")
	assert.False(t, routed)
}
