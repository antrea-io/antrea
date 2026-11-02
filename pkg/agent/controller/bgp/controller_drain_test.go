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
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/v2/pkg/agent/bgp"
	"antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
)

var (
	unschedulableTaint = corev1.Taint{
		Key:    corev1.TaintNodeUnschedulable,
		Effect: corev1.TaintEffectNoSchedule,
	}
	maintenanceTaint = corev1.Taint{
		Key:    "maintenance",
		Value:  "hardware",
		Effect: corev1.TaintEffectNoExecute,
	}
	preferNoScheduleTaint = corev1.Taint{
		Key:    "maintenance",
		Value:  "hardware",
		Effect: corev1.TaintEffectPreferNoSchedule,
	}
	controlPlaneTaint = corev1.Taint{
		Key:    "node-role.kubernetes.io/control-plane",
		Effect: corev1.TaintEffectNoSchedule,
	}

	// The Service routes of the BGPPolicy returned by generateDrainBGPPolicy, in an IPv4-only cluster with
	// ipv4ClusterIP1 and ipv4LoadBalancer.
	drainServiceRoutes = []bgp.Route{clusterIPv4Route1, clusterIPv4Route2, loadBalancerIPv4Route}
	// The routes that survive draining: the Egress IP hosted by the local Node and its Pod CIDR.
	drainKeptRoutes = []bgp.Route{ipv4EgressIP1Route, podIPv4CIDRRoute}
	drainAllRoutes  = slices.Concat(drainServiceRoutes, drainKeptRoutes)
)

// generateDrainBGPPolicy returns a BGPPolicy that advertises ClusterIPs, LoadBalancerIPs, Egress IPs and the Pod CIDR,
// with the given spec.drainOnTaints block.
func generateDrainBGPPolicy(name string, creationTimestamp metav1.Time, drainOnTaints *v1alpha1.DrainOnTaints) *v1alpha1.BGPPolicy {
	policy := generateBGPPolicy(name,
		creationTimestamp,
		nodeLabels1,
		179,
		65000,
		true,
		false,
		true,
		true,
		true,
		[]v1alpha1.BGPPeer{ipv4Peer1},
		nil)
	policy.Spec.DrainOnTaints = drainOnTaints
	return policy
}

// generateTaintedNode returns the local Node carrying the given taints. Setting spec.unschedulable mirrors what
// `kubectl cordon` does, which is to set the field and let the node lifecycle controller add the matching taint.
func generateTaintedNode(unschedulable bool, taints ...corev1.Taint) *corev1.Node {
	taintedNode := generateNode(localNodeName, nodeLabels1, nodeAnnotations1)
	taintedNode.Spec.Taints = taints
	taintedNode.Spec.Unschedulable = unschedulable
	return taintedNode
}

// updateNodeAndWait updates the local Node and waits for the change to reach the Node lister. Comparing the taints is
// a reliable barrier here because every step of these tests either adds or removes exactly one taint, so the lister
// never holds an object that already matches the update.
func updateNodeAndWait(t *testing.T, c *fakeController, updatedNode *corev1.Node) {
	t.Helper()
	_, err := c.client.CoreV1().Nodes().Update(context.TODO(), updatedNode, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		got, err := c.nodeLister.Get(updatedNode.Name)
		return err == nil &&
			reflect.DeepEqual(got.Spec.Taints, updatedNode.Spec.Taints) &&
			got.Spec.Unschedulable == updatedNode.Spec.Unschedulable
	}, 5*time.Second, 10*time.Millisecond)
}

// createBGPPolicyAndWait creates a BGPPolicy and waits for it to reach the BGPPolicy lister.
func createBGPPolicyAndWait(t *testing.T, c *fakeController, policy *v1alpha1.BGPPolicy) {
	t.Helper()
	_, err := c.crdClient.CrdV1alpha1().BGPPolicies().Create(context.TODO(), policy, metav1.CreateOptions{})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		_, err := c.bgpPolicyLister.Get(policy.Name)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)
}

// assertAdvertisedRoutes asserts that the BGPPolicy state holds exactly the given routes.
func assertAdvertisedRoutes(t *testing.T, c *fakeController, expectedRoutes []bgp.Route) {
	t.Helper()
	require.NotNil(t, c.bgpPolicyState)
	assert.Equal(t, sets.New(expectedRoutes...), sets.KeySet(c.bgpPolicyState.routes))
}

func TestDrainingTaint(t *testing.T) {
	testCases := []struct {
		name          string
		taints        []corev1.Taint
		drainOnTaints *v1alpha1.DrainOnTaints
		expectedTaint *corev1.Taint
	}{
		{
			name:          "no drainOnTaints block",
			taints:        []corev1.Taint{unschedulableTaint},
			drainOnTaints: nil,
			expectedTaint: nil,
		},
		{
			name:          "disabled, with an untolerated NoSchedule taint",
			taints:        []corev1.Taint{unschedulableTaint},
			drainOnTaints: &v1alpha1.DrainOnTaints{Enabled: false},
			expectedTaint: nil,
		},
		{
			name:          "unschedulable taint, no tolerations",
			taints:        []corev1.Taint{unschedulableTaint},
			drainOnTaints: &v1alpha1.DrainOnTaints{Enabled: true},
			expectedTaint: &unschedulableTaint,
		},
		{
			name:          "custom NoExecute taint, no tolerations",
			taints:        []corev1.Taint{maintenanceTaint},
			drainOnTaints: &v1alpha1.DrainOnTaints{Enabled: true},
			expectedTaint: &maintenanceTaint,
		},
		{
			name:          "PreferNoSchedule taint only",
			taints:        []corev1.Taint{preferNoScheduleTaint},
			drainOnTaints: &v1alpha1.DrainOnTaints{Enabled: true},
			expectedTaint: nil,
		},
		{
			name:   "taint tolerated by Exists on the key",
			taints: []corev1.Taint{maintenanceTaint},
			drainOnTaints: &v1alpha1.DrainOnTaints{
				Enabled:     true,
				Tolerations: []corev1.Toleration{{Key: "maintenance", Operator: corev1.TolerationOpExists}},
			},
			expectedTaint: nil,
		},
		{
			name:   "taint tolerated by Equal with a matching value",
			taints: []corev1.Taint{maintenanceTaint},
			drainOnTaints: &v1alpha1.DrainOnTaints{
				Enabled: true,
				Tolerations: []corev1.Toleration{
					{Key: "maintenance", Operator: corev1.TolerationOpEqual, Value: "hardware"},
				},
			},
			expectedTaint: nil,
		},
		{
			name:   "Equal with a different value does not tolerate",
			taints: []corev1.Taint{maintenanceTaint},
			drainOnTaints: &v1alpha1.DrainOnTaints{
				Enabled: true,
				Tolerations: []corev1.Toleration{
					{Key: "maintenance", Operator: corev1.TolerationOpEqual, Value: "software"},
				},
			},
			expectedTaint: &maintenanceTaint,
		},
		{
			name:   "toleration for NoExecute does not tolerate a NoSchedule taint",
			taints: []corev1.Taint{unschedulableTaint},
			drainOnTaints: &v1alpha1.DrainOnTaints{
				Enabled: true,
				Tolerations: []corev1.Toleration{
					{
						Key:      corev1.TaintNodeUnschedulable,
						Operator: corev1.TolerationOpExists,
						Effect:   corev1.TaintEffectNoExecute,
					},
				},
			},
			expectedTaint: &unschedulableTaint,
		},
		{
			name:   "toleration with an empty effect matches every effect",
			taints: []corev1.Taint{unschedulableTaint},
			drainOnTaints: &v1alpha1.DrainOnTaints{
				Enabled: true,
				Tolerations: []corev1.Toleration{
					{Key: corev1.TaintNodeUnschedulable, Operator: corev1.TolerationOpExists},
				},
			},
			expectedTaint: nil,
		},
		{
			name:   "Exists with an empty key tolerates every taint",
			taints: []corev1.Taint{unschedulableTaint, maintenanceTaint},
			drainOnTaints: &v1alpha1.DrainOnTaints{
				Enabled:     true,
				Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
			},
			expectedTaint: nil,
		},
		{
			name:   "two taints, the untolerated one is returned",
			taints: []corev1.Taint{controlPlaneTaint, unschedulableTaint},
			drainOnTaints: &v1alpha1.DrainOnTaints{
				Enabled: true,
				Tolerations: []corev1.Toleration{
					{Key: "node-role.kubernetes.io/control-plane", Operator: corev1.TolerationOpExists},
				},
			},
			expectedTaint: &unschedulableTaint,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			taintedNode := generateTaintedNode(false, tt.taints...)
			policy := generateDrainBGPPolicy(bgpPolicyName1, creationTimestamp, tt.drainOnTaints)

			assert.Equal(t, tt.expectedTaint, drainingTaint(taintedNode, policy))
		})
	}
}

func TestUpdateNodeTaintChange(t *testing.T) {
	untaintedNode := generateNode(localNodeName, nodeLabels1, nodeAnnotations1)
	cordonedNode := generateTaintedNode(true, unschedulableTaint)
	nodeWithNewStatus := generateNode(localNodeName, nodeLabels1, nodeAnnotations1)
	nodeWithNewStatus.Status.Conditions = []corev1.NodeCondition{
		{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
	}
	unselectedNode := generateNode(localNodeName, nodeLabels2, nodeAnnotations1)
	cordonedUnselectedNode := generateNode(localNodeName, nodeLabels2, nodeAnnotations1)
	cordonedUnselectedNode.Spec.Taints = []corev1.Taint{unschedulableTaint}
	cordonedUnselectedNode.Spec.Unschedulable = true
	remoteNode := generateNode("remote", nodeLabels1, nodeAnnotations1)
	cordonedRemoteNode := generateNode("remote", nodeLabels1, nodeAnnotations1)
	cordonedRemoteNode.Spec.Taints = []corev1.Taint{unschedulableTaint}
	cordonedRemoteNode.Spec.Unschedulable = true

	testCases := []struct {
		name          string
		oldNode       *corev1.Node
		newNode       *corev1.Node
		expectedQueue int
	}{
		{
			name:          "cordon of the local Node selected by a BGPPolicy",
			oldNode:       untaintedNode,
			newNode:       cordonedNode,
			expectedQueue: 1,
		},
		{
			name:          "taint removed from the local Node",
			oldNode:       cordonedNode,
			newNode:       untaintedNode,
			expectedQueue: 1,
		},
		{
			name:          "only the Node status changed",
			oldNode:       untaintedNode,
			newNode:       nodeWithNewStatus,
			expectedQueue: 0,
		},
		{
			name:          "taint changed on a local Node no BGPPolicy selects",
			oldNode:       unselectedNode,
			newNode:       cordonedUnselectedNode,
			expectedQueue: 0,
		},
		{
			name:          "taint changed on another Node",
			oldNode:       remoteNode,
			newNode:       cordonedRemoteNode,
			expectedQueue: 0,
		},
	}

	policy := generateDrainBGPPolicy(bgpPolicyName1, creationTimestamp, &v1alpha1.DrainOnTaints{Enabled: true})
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// The Node is deliberately not added to the informer: updateNode only reads the Nodes passed to it and
			// the BGPPolicy lister, so leaving the Node store empty keeps the work queue empty until updateNode runs.
			c := newFakeController(t, nil, []runtime.Object{policy}, true, false)

			stopCh := make(chan struct{})
			defer close(stopCh)
			c.startInformers(stopCh)
			require.Equal(t, 0, c.queue.Len(), "the work queue should be empty before the Node update")

			c.updateNode(tt.oldNode, tt.newNode)

			assert.Equal(t, tt.expectedQueue, c.queue.Len())
		})
	}
}

func TestSyncDraining(t *testing.T) {
	objects := []runtime.Object{node, ipv4ClusterIP1, ipv4ClusterIP1Eps, ipv4LoadBalancer, ipv4LoadBalancerEps}
	untaintedNode := generateNode(localNodeName, nodeLabels1, nodeAnnotations1)
	cordonedNode := generateTaintedNode(true, unschedulableTaint)

	// startDrainController creates a controller whose only BGPPolicy is the given one, runs the initial sync and
	// asserts that every Service, Egress and Pod route is advertised.
	startDrainController := func(t *testing.T, policy *v1alpha1.BGPPolicy, stopCh chan struct{}) *fakeController {
		t.Helper()
		c := newFakeController(t, objects, []runtime.Object{policy, ipv4Egress1}, true, false)
		c.startInformers(stopCh)
		// Fake the passwords of BGP peers.
		c.bgpPeerPasswords = bgpPeerPasswords

		c.mockBGPServer.EXPECT().Start(gomock.Any())
		c.mockBGPServer.EXPECT().AddPeer(gomock.Any(), ipv4Peer1Config)
		for _, route := range drainAllRoutes {
			c.mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{route})
		}
		require.NoError(t, c.syncBGPPolicy(context.Background()))
		assertAdvertisedRoutes(t, c, drainAllRoutes)
		assert.False(t, c.GetBGPPolicyInfo().Draining)
		return c
	}

	// gomock fails the test on any call that is not expected, so the absence of RemovePeer, UpdatePeer and Stop
	// expectations below is what asserts that draining never touches the BGP sessions or the BGP server.
	t.Run("cordon withdraws the Service routes and uncordon restores them", func(t *testing.T) {
		policy := generateDrainBGPPolicy(bgpPolicyName1, creationTimestamp, &v1alpha1.DrainOnTaints{Enabled: true})
		stopCh := make(chan struct{})
		defer close(stopCh)
		c := startDrainController(t, policy, stopCh)
		ctx := context.Background()

		// Cordoning the Node withdraws exactly the Service routes.
		updateNodeAndWait(t, c, cordonedNode)
		for _, route := range drainServiceRoutes {
			c.mockBGPServer.EXPECT().WithdrawRoutes(gomock.Any(), []bgp.Route{route})
		}
		require.NoError(t, c.syncBGPPolicy(ctx))
		assertAdvertisedRoutes(t, c, drainKeptRoutes)
		assert.True(t, c.GetBGPPolicyInfo().Draining)

		// Uncordoning the Node re-advertises exactly the Service routes.
		updateNodeAndWait(t, c, untaintedNode)
		for _, route := range drainServiceRoutes {
			c.mockBGPServer.EXPECT().AdvertiseRoutes(gomock.Any(), []bgp.Route{route})
		}
		require.NoError(t, c.syncBGPPolicy(ctx))
		assertAdvertisedRoutes(t, c, drainAllRoutes)
		assert.False(t, c.GetBGPPolicyInfo().Draining)
	})

	t.Run("disabled drainOnTaints withdraws nothing", func(t *testing.T) {
		policy := generateDrainBGPPolicy(bgpPolicyName1, creationTimestamp, &v1alpha1.DrainOnTaints{Enabled: false})
		stopCh := make(chan struct{})
		defer close(stopCh)
		c := startDrainController(t, policy, stopCh)

		updateNodeAndWait(t, c, cordonedNode)
		require.NoError(t, c.syncBGPPolicy(context.Background()))
		assertAdvertisedRoutes(t, c, drainAllRoutes)
		assert.False(t, c.GetBGPPolicyInfo().Draining)
	})

	t.Run("tolerated taint withdraws nothing", func(t *testing.T) {
		policy := generateDrainBGPPolicy(bgpPolicyName1, creationTimestamp, &v1alpha1.DrainOnTaints{
			Enabled: true,
			Tolerations: []corev1.Toleration{
				{Key: corev1.TaintNodeUnschedulable, Operator: corev1.TolerationOpExists},
			},
		})
		stopCh := make(chan struct{})
		defer close(stopCh)
		c := startDrainController(t, policy, stopCh)

		updateNodeAndWait(t, c, cordonedNode)
		require.NoError(t, c.syncBGPPolicy(context.Background()))
		assertAdvertisedRoutes(t, c, drainAllRoutes)
		assert.False(t, c.GetBGPPolicyInfo().Draining)
	})

	t.Run("BGPPolicy without the block withdraws nothing", func(t *testing.T) {
		policy := generateDrainBGPPolicy(bgpPolicyName1, creationTimestamp, nil)
		stopCh := make(chan struct{})
		defer close(stopCh)
		c := startDrainController(t, policy, stopCh)

		updateNodeAndWait(t, c, cordonedNode)
		require.NoError(t, c.syncBGPPolicy(context.Background()))
		assertAdvertisedRoutes(t, c, drainAllRoutes)
		assert.False(t, c.GetBGPPolicyInfo().Draining)
	})

	t.Run("effective BGPPolicy gains the block while the Node is tainted", func(t *testing.T) {
		// policy2 has no drainOnTaints block and is the only BGPPolicy at first.
		policy2 := generateDrainBGPPolicy(bgpPolicyName2, creationTimestampAdd1s, nil)
		stopCh := make(chan struct{})
		defer close(stopCh)
		c := startDrainController(t, policy2, stopCh)
		ctx := context.Background()

		// Cordoning the Node changes nothing while policy2 is effective.
		updateNodeAndWait(t, c, cordonedNode)
		require.NoError(t, c.syncBGPPolicy(ctx))
		assertAdvertisedRoutes(t, c, drainAllRoutes)
		assert.False(t, c.GetBGPPolicyInfo().Draining)

		// policy1 is older, so it becomes the effective BGPPolicy. It has the same listen port, local ASN and BGP
		// peer, so the BGP server is not restarted and only the Service routes are withdrawn.
		policy1 := generateDrainBGPPolicy(bgpPolicyName1, creationTimestamp, &v1alpha1.DrainOnTaints{Enabled: true})
		createBGPPolicyAndWait(t, c, policy1)
		for _, route := range drainServiceRoutes {
			c.mockBGPServer.EXPECT().WithdrawRoutes(gomock.Any(), []bgp.Route{route})
		}
		require.NoError(t, c.syncBGPPolicy(ctx))
		assertAdvertisedRoutes(t, c, drainKeptRoutes)
		assert.True(t, c.GetBGPPolicyInfo().Draining)
		assert.Equal(t, bgpPolicyName1, c.GetBGPPolicyInfo().BGPPolicyName)
	})
}
