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
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/agent/util"
	utilip "antrea.io/antrea/v2/pkg/util/ip"
)

var (
	_, podCIDR2, _  = net.ParseCIDR("1.1.2.0/24")
	podCIDR2Gateway = util.GetGatewayIPForPodCIDR(podCIDR2)
	// remoteSubnetNodeIP is outside the local transport subnet, 10.10.10.0/24.
	remoteSubnetNodeIP = net.ParseIP("10.10.20.10")
)

func newTestNode(name string, podCIDR *net.IPNet, nodeIP net.IP) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{PodCIDR: podCIDR.String(), PodCIDRs: []string{podCIDR.String()}},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: nodeIP.String()}},
		},
	}
}

// newL2DispatchController returns a controller in noEncap mode with the l2 dispatch enabled, whose Node is in the
// transport subnet 10.10.10.0/24, with its informers started.
func newL2DispatchController(t *testing.T) *fakeController {
	c := newController(t, &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeNoEncap, IPv4Enabled: true, EnableL2Dispatch: true})
	t.Cleanup(c.queue.ShutDown)
	localNodeConfig := *nodeConfig
	_, localNodeConfig.NodeTransportIPv4Addr, _ = net.ParseCIDR("10.10.10.1/24")
	c.nodeConfig = &localNodeConfig
	stopCh := make(chan struct{})
	t.Cleanup(func() { close(stopCh) })
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	return c
}

func (c *fakeController) createNode(t *testing.T, node *corev1.Node) {
	_, err := c.clientset.CoreV1().Nodes().Create(context.TODO(), node, metav1.CreateOptions{})
	require.NoError(t, err)
}

func TestL2DispatchPeerLifecycle(t *testing.T) {
	c := newL2DispatchController(t)

	// node1 is in the local transport subnet: its l2 dispatch routing is installed before its flows.
	c.createNode(t, node1)
	gomock.InOrder(
		c.routeClient.EXPECT().AddL2DispatchPeerRoutes(uint32(1), &utilip.DualStackIPs{IPv4: nodeIP1}),
		c.ofClient.EXPECT().InstallNodeFlows("node1", gomock.Any(), &dsIPs1, uint32(0), nil),
	)
	c.routeClient.EXPECT().AddRoutes(podCIDR1, "node1", nodeIP1, podCIDR1Gateway)
	c.routeClient.EXPECT().AddRoutes(podCIDR1v6, "node1", nil, podCIDR1v6Gateway)
	c.processNextWorkItem()

	// A Node in another subnet cannot be reached with the l2 dispatch, so it gets no index.
	c.createNode(t, newTestNode("remoteSubnetNode", podCIDR2, remoteSubnetNodeIP))
	c.ofClient.EXPECT().InstallNodeFlows("remoteSubnetNode", gomock.Any(), &utilip.DualStackIPs{IPv4: remoteSubnetNodeIP}, uint32(0), nil)
	c.routeClient.EXPECT().AddRoutes(podCIDR2, "remoteSubnetNode", remoteSubnetNodeIP, podCIDR2Gateway)
	c.processNextWorkItem()

	// Deleting node1 removes its routing after its flows, and frees index 1.
	require.NoError(t, c.clientset.CoreV1().Nodes().Delete(context.TODO(), node1.Name, metav1.DeleteOptions{}))
	c.routeClient.EXPECT().DeleteRoutes(podCIDR1)
	c.routeClient.EXPECT().DeleteRoutes(podCIDR1v6)
	gomock.InOrder(
		c.ofClient.EXPECT().UninstallNodeFlows("node1"),
		c.routeClient.EXPECT().DeleteL2DispatchPeerRoutes(uint32(1)),
	)
	c.processNextWorkItem()

	// The next Node in the local subnet gets index 2, not index 1, which was just freed: a feature which updates its
	// flows asynchronously may still carry index 1 for a moment.
	c.createNode(t, newTestNode("otherNode", podCIDR1, nodeIP2))
	gomock.InOrder(
		c.routeClient.EXPECT().AddL2DispatchPeerRoutes(uint32(2), &utilip.DualStackIPs{IPv4: nodeIP2}),
		c.ofClient.EXPECT().InstallNodeFlows("otherNode", gomock.Any(), &dsIPs2, uint32(0), nil),
	)
	c.routeClient.EXPECT().AddRoutes(podCIDR1, "otherNode", nodeIP2, podCIDR1Gateway)
	c.processNextWorkItem()
}

func TestL2DispatchPeerLeavesLocalSubnet(t *testing.T) {
	c := newL2DispatchController(t)
	node := newTestNode("node1", podCIDR1, nodeIP1)
	c.createNode(t, node)
	c.routeClient.EXPECT().AddL2DispatchPeerRoutes(uint32(1), &utilip.DualStackIPs{IPv4: nodeIP1})
	c.ofClient.EXPECT().InstallNodeFlows("node1", gomock.Any(), &dsIPs1, uint32(0), nil)
	c.routeClient.EXPECT().AddRoutes(podCIDR1, "node1", nodeIP1, podCIDR1Gateway)
	c.processNextWorkItem()

	// The Node moves to another subnet: its routing is removed after the flows which no longer use the index.
	node = node.DeepCopy()
	node.Status.Addresses[0].Address = remoteSubnetNodeIP.String()
	_, err := c.clientset.CoreV1().Nodes().Update(context.TODO(), node, metav1.UpdateOptions{})
	require.NoError(t, err)
	gomock.InOrder(
		c.ofClient.EXPECT().InstallNodeFlows("node1", gomock.Any(), &utilip.DualStackIPs{IPv4: remoteSubnetNodeIP}, uint32(0), nil),
		c.routeClient.EXPECT().DeleteL2DispatchPeerRoutes(uint32(1)),
	)
	c.routeClient.EXPECT().AddRoutes(podCIDR1, "node1", remoteSubnetNodeIP, podCIDR1Gateway)
	c.processNextWorkItem()
	_, hasIndex := c.l2DispatchPeers.get("node1")
	assert.False(t, hasIndex)
}

func TestL2DispatchPeerRoutingFailure(t *testing.T) {
	c := newL2DispatchController(t)

	// The routing fails to install, so the flows are not installed and the Node is retried.
	c.createNode(t, node1)
	c.routeClient.EXPECT().AddL2DispatchPeerRoutes(uint32(1), &utilip.DualStackIPs{IPv4: nodeIP1}).Return(errors.New("netlink error"))
	c.processNextWorkItem()

	// The Node is deleted before a retry succeeds: the index it got is freed and its routing is removed.
	require.NoError(t, c.clientset.CoreV1().Nodes().Delete(context.TODO(), node1.Name, metav1.DeleteOptions{}))
	c.routeClient.EXPECT().DeleteL2DispatchPeerRoutes(uint32(1))
	c.processNextWorkItem()
	_, hasIndex := c.l2DispatchPeers.get("node1")
	assert.False(t, hasIndex)
}

func TestReconcileL2DispatchPeers(t *testing.T) {
	c := newL2DispatchController(t)
	c.createNode(t, node1)
	require.Eventually(t, func() bool {
		_, err := c.nodeLister.Get(node1.Name)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)

	// Before the restart, node1 had index 4. Index 6 belonged to a Node which is gone, and index 7 has a rule but
	// no route.
	c.routeClient.EXPECT().ListL2DispatchPeers().Return(map[uint32]*utilip.DualStackIPs{
		4: {IPv4: nodeIP1},
		6: {IPv4: net.ParseIP("10.10.10.99")},
		7: {},
	}, nil)
	c.routeClient.EXPECT().DeleteL2DispatchPeerRoutes(uint32(6))
	c.routeClient.EXPECT().DeleteL2DispatchPeerRoutes(uint32(7))
	require.NoError(t, c.reconcileL2DispatchPeers())

	// node1 keeps index 4.
	gomock.InOrder(
		c.routeClient.EXPECT().AddL2DispatchPeerRoutes(uint32(4), &utilip.DualStackIPs{IPv4: nodeIP1}),
		c.ofClient.EXPECT().InstallNodeFlows("node1", gomock.Any(), &dsIPs1, uint32(0), nil),
	)
	c.routeClient.EXPECT().AddRoutes(podCIDR1, "node1", nodeIP1, podCIDR1Gateway)
	c.routeClient.EXPECT().AddRoutes(podCIDR1v6, "node1", nil, podCIDR1v6Gateway)
	c.processNextWorkItem()

	// A new Node gets the index after the highest one that the previous agent used, because the flows kept across
	// the restart may still carry the stale indices 6 and 7.
	c.createNode(t, newTestNode("otherNode", podCIDR2, nodeIP2))
	c.routeClient.EXPECT().AddL2DispatchPeerRoutes(uint32(8), &utilip.DualStackIPs{IPv4: nodeIP2})
	c.ofClient.EXPECT().InstallNodeFlows("otherNode", gomock.Any(), &dsIPs2, uint32(0), nil)
	c.routeClient.EXPECT().AddRoutes(podCIDR2, "otherNode", nodeIP2, podCIDR2Gateway)
	c.processNextWorkItem()
}

func TestL2DispatchPeerIndices(t *testing.T) {
	a := newL2DispatchPeerIndices()
	first, err := a.allocate("a")
	require.NoError(t, err)
	assert.Equal(t, uint32(1), first, "index 0 is never allocated")
	again, err := a.allocate("a")
	require.NoError(t, err)
	assert.Equal(t, first, again, "a Node keeps its index")
	second, err := a.allocate("b")
	require.NoError(t, err)
	assert.Equal(t, uint32(2), second)

	assert.True(t, a.reserve("c", 5))
	assert.False(t, a.reserve("d", 5), "the index belongs to another Node")
	assert.False(t, a.reserve("c", 6), "the Node already has an index")

	a.release("a")
	next, err := a.allocate("e")
	require.NoError(t, err)
	assert.Equal(t, uint32(3), next, "the next free index is allocated, not the index which was just released")
	next, err = a.allocate("f")
	require.NoError(t, err)
	assert.Equal(t, uint32(4), next)
	next, err = a.allocate("g")
	require.NoError(t, err)
	assert.Equal(t, uint32(6), next, "the index of another Node is skipped")
	index, exists := a.get("c")
	assert.True(t, exists)
	assert.Equal(t, uint32(5), index)
	_, exists = a.get("a")
	assert.False(t, exists)

	full := newL2DispatchPeerIndices()
	for i := 1; i <= types.MaxL2DispatchPeerIndex; i++ {
		index, err := full.allocate(fmt.Sprintf("node-%d", i))
		require.NoError(t, err)
		require.Equal(t, uint32(i), index)
	}
	_, err = full.allocate("one-too-many")
	assert.ErrorContains(t, err, "all 4095 indices of the l2 dispatch are in use")
	full.release("node-100")
	full.release("node-7")
	next, err = full.allocate("wrapped")
	require.NoError(t, err)
	assert.Equal(t, uint32(7), next, "the allocation wraps around after the last index")
	next, err = full.allocate("wrapped-again")
	require.NoError(t, err)
	assert.Equal(t, uint32(100), next)

	restarted := newL2DispatchPeerIndices()
	restarted.skip(7)
	restarted.skip(3)
	next, err = restarted.allocate("new")
	require.NoError(t, err)
	assert.Equal(t, uint32(8), next, "the indices which the previous agent used are not allocated first")
}
