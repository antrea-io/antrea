/*
Copyright 2022 Antrea Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package member

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

var (
	node1           *corev1.Node
	node2           *corev1.Node
	node3           *corev1.Node
	node4           *corev1.Node
	updatedGateway2 *mcv1alpha1.Gateway
	gateway3        *mcv1alpha1.Gateway
)

func initializeCommonData() {
	node1 = &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
			Annotations: map[string]string{
				common.GatewayAnnotation: "true",
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeExternalIP,
					Address: "10.10.10.10",
				},
				{
					Type:    corev1.NodeInternalIP,
					Address: "172.11.10.1",
				},
			},
			Conditions: []corev1.NodeCondition{
				{
					Type:   corev1.NodeReady,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}

	node2 = node1.DeepCopy()
	node2.Name = "node-2"
	node2.Status.Addresses = []corev1.NodeAddress{
		{
			Type:    corev1.NodeExternalIP,
			Address: "10.10.10.12",
		},
		{
			Type:    corev1.NodeInternalIP,
			Address: "172.11.10.2",
		},
	}

	node3 = node1.DeepCopy()
	node3.Name = "node-3"
	node3.Status.Conditions = []corev1.NodeCondition{
		{
			Type:   corev1.NodeReady,
			Status: corev1.ConditionFalse,
		},
	}

	node4 = node1.DeepCopy()
	node4.Name = "node-4"
	node4.Annotations = map[string]string{
		common.GatewayAnnotation:   "true",
		common.GatewayIPAnnotation: "invalid-gatewayip",
	}

	updatedGateway2 = &mcv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "node-2",
			Namespace: "default",
		},
		GatewayIP:  "10.10.10.12",
		InternalIP: "172.11.10.2",
	}

	gateway3 = gwNode1.DeepCopy()
	gateway3.Name = "node-3"
}

func TestNodeReconciler(t *testing.T) {
	initializeCommonData()
	node1NoAnnotation := *node1
	node1NoAnnotation.Annotations = map[string]string{}
	node1WithIPAnnotation := *node1
	node1WithIPAnnotation.Annotations = map[string]string{
		common.GatewayAnnotation:   "true",
		common.GatewayIPAnnotation: "11.11.10.10",
	}
	gateway4 := gwNode1.DeepCopy()
	gateway4.Name = "node-4"
	newGateway1 := gwNode1.DeepCopy()
	newGateway1.GatewayIP = "172.11.10.1"
	newNode1 := node1.DeepCopy()
	newNode1.Name = "node-1"
	newNode1.Status.Addresses = []corev1.NodeAddress{
		{
			Type:    corev1.NodeHostName,
			Address: "node-1",
		},
	}

	tests := []struct {
		name          string
		nodes         []*corev1.Node
		req           reconcile.Request
		precedence    mcv1alpha1.Precedence
		existingGW    *mcv1alpha1.Gateway
		expectedGW    *mcv1alpha1.Gateway
		activeGateway string
		candidates    map[string]bool
	}{
		{
			name:       "create a Gateway successfully",
			nodes:      []*corev1.Node{node1},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Name: node1.Name}},
			expectedGW: &gwNode1,
			precedence: mcv1alpha1.PrecedencePublic,
		},
		{
			name:       "update a Gateway successfully by changing GatewayIP",
			nodes:      []*corev1.Node{&node1WithIPAnnotation},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Name: node1.Name}},
			existingGW: &gwNode1,
			expectedGW: &mcv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "node-1",
					Namespace: "default",
				},
				GatewayIP:  "11.11.10.10",
				InternalIP: "172.11.10.1",
			},
			activeGateway: "node-1",
			precedence:    mcv1alpha1.PrecedencePublic,
		},
		{
			name:          "remove a Gateway Node to delete a Gateway successfully",
			nodes:         []*corev1.Node{},
			req:           reconcile.Request{NamespacedName: types.NamespacedName{Name: node1.Name}},
			existingGW:    &gwNode1,
			activeGateway: "node-1",
			precedence:    mcv1alpha1.PrecedencePublic,
		},
		{
			name:          "remove a Gateway Node's annotation to delete a Gateway successfully",
			nodes:         []*corev1.Node{&node1NoAnnotation},
			req:           reconcile.Request{NamespacedName: types.NamespacedName{Name: node1.Name}},
			existingGW:    &gwNode1,
			activeGateway: "node-1",
			precedence:    mcv1alpha1.PrecedencePublic,
		},
		{
			name:       "remove a Gateway due to no IPs",
			nodes:      []*corev1.Node{newNode1},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Name: newNode1.Name}},
			existingGW: &gwNode1,
			precedence: mcv1alpha1.PrecedencePrivate,
		},
		{
			name:          "remove a Gateway Node to create a new Gateway from candidates successfully",
			nodes:         []*corev1.Node{node2, node4},
			req:           reconcile.Request{NamespacedName: types.NamespacedName{Name: node1.Name}},
			existingGW:    &gwNode1,
			expectedGW:    updatedGateway2,
			activeGateway: "node-1",
			precedence:    mcv1alpha1.PrecedencePublic,
		},
		{
			name:          "create a new Gateway successfully when active Gateway Node is not ready",
			nodes:         []*corev1.Node{node2, node3},
			req:           reconcile.Request{NamespacedName: types.NamespacedName{Name: node3.Name}},
			existingGW:    gateway3,
			expectedGW:    updatedGateway2,
			activeGateway: "node-3",
			precedence:    mcv1alpha1.PrecedencePublic,
		},
		{
			name:          "create a new Gateway successfully when active Gateway Node has no valid IP",
			nodes:         []*corev1.Node{node2, node4},
			req:           reconcile.Request{NamespacedName: types.NamespacedName{Name: node4.Name}},
			existingGW:    gateway4,
			expectedGW:    updatedGateway2,
			activeGateway: "node-4",
			precedence:    mcv1alpha1.PrecedencePublic,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var obj []client.Object
			for _, n := range tt.nodes {
				obj = append(obj, n)
			}
			if tt.existingGW != nil {
				obj = append(obj, tt.existingGW)
			}
			fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(obj...).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects().Build()
			commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, common.LeaderNamespace, nil)
			mcReconciler := NewMemberClusterSetReconciler(fakeClient, common.TestScheme, "default", false, false, make(chan struct{}))
			mcReconciler.SetRemoteCommonArea(commonArea)
			commonAreaGetter := mcReconciler
			r := NewNodeReconciler(fakeClient, common.TestScheme, "default", "10.100.0.0/16", tt.precedence, commonAreaGetter)
			r.activeGateway = tt.activeGateway
			if _, err := r.Reconcile(common.TestCtx, tt.req); err != nil {
				t.Errorf("Node Reconciler should handle Node events successfully but got error = %v", err)
			} else {
				newGW := &mcv1alpha1.Gateway{}
				gwNamespcedName := types.NamespacedName{Name: tt.req.Name, Namespace: "default"}
				if tt.expectedGW != nil {
					gwNamespcedName = types.NamespacedName{Name: tt.expectedGW.Name, Namespace: "default"}
				}
				err := fakeClient.Get(common.TestCtx, gwNamespcedName, newGW)
				isDelete := tt.expectedGW == nil
				if isDelete {
					if err == nil || (err != nil && !apierrors.IsNotFound(err)) {
						t.Errorf("Expected to get not found error but got err: %v", err)
					}
				} else {
					if err != nil {
						t.Errorf("Expected to get Gateway but got err: %v", err)
					} else {
						if tt.expectedGW.GatewayIP != newGW.GatewayIP || tt.expectedGW.InternalIP != newGW.InternalIP {
							t.Errorf("Expected Gateway %v but got: %v", tt.expectedGW, newGW)
						}
					}
				}
			}
		})
	}
}

func TestInitialize(t *testing.T) {
	initializeCommonData()
	node5 := node1.DeepCopy()
	node5.Name = "node-5"
	node5.Annotations = map[string]string{}
	tests := []struct {
		name                  string
		nodes                 []*corev1.Node
		req                   reconcile.Request
		existingGW            *mcv1alpha1.Gateway
		expectedActiveGateway string
		isDelete              bool
		candidatesSize        int
	}{
		{
			name:                  "initialize and set active Gateway successfully",
			nodes:                 []*corev1.Node{node1, node2, node5},
			existingGW:            &gwNode1,
			expectedActiveGateway: "node-1",
			candidatesSize:        2,
		},
		{
			name:                  "initialize successfully without Gateway",
			nodes:                 []*corev1.Node{node3, node4, node5},
			expectedActiveGateway: "",
			candidatesSize:        2,
		},
		{
			name:                  "initialize and delete Gateway successfully",
			nodes:                 []*corev1.Node{node1, node5},
			existingGW:            gateway3,
			isDelete:              true,
			expectedActiveGateway: "",
			candidatesSize:        1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var obj []client.Object
			for _, n := range tt.nodes {
				obj = append(obj, n)
			}
			if tt.existingGW != nil {
				obj = append(obj, tt.existingGW)
			}
			fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(obj...).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects().Build()
			commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, common.LeaderNamespace, nil)
			mcReconciler := NewMemberClusterSetReconciler(fakeClient, common.TestScheme, "default", false, false, make(chan struct{}))
			mcReconciler.SetRemoteCommonArea(commonArea)
			commonAreaGetter := mcReconciler
			r := NewNodeReconciler(fakeClient, common.TestScheme, "default", "10.100.0.0/16", mcv1alpha1.PrecedencePublic, commonAreaGetter)
			if err := r.initialize(); err != nil {
				t.Errorf("Expected initialize() successfully but got err: %v", err)
			} else {
				assert.Equal(t, tt.expectedActiveGateway, r.activeGateway)
				assert.Equal(t, tt.candidatesSize, len(r.gatewayCandidates))
				if tt.isDelete {
					deletedGW := &mcv1alpha1.Gateway{}
					gwNamespcedName := types.NamespacedName{Name: tt.existingGW.Name, Namespace: "default"}
					err := fakeClient.Get(common.TestCtx, gwNamespcedName, deletedGW)
					if !apierrors.IsNotFound(err) {
						t.Errorf("Expected to get not found error but got err: %v", err)
					}
				}
			}
		})
	}
}

func TestClusterSetMapFunc(t *testing.T) {
	clusterSet := &mcv1alpha2.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "clusterset-test",
		},
		Status: mcv1alpha2.ClusterSetStatus{
			Conditions: []mcv1alpha2.ClusterSetCondition{
				{
					Status: corev1.ConditionTrue,
					Type:   mcv1alpha2.ClusterSetReady,
				},
			},
		},
	}

	deletedClusterSet := &mcv1alpha2.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "clusterset-test-deleted",
		},
	}
	node1 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
			Annotations: map[string]string{
				common.GatewayAnnotation: "true",
			},
		},
	}
	expectedReqs := []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Name: node1.GetName(),
			},
		},
	}
	ctx := context.Background()

	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(clusterSet, node1).Build()
	r := NewNodeReconciler(fakeClient, common.TestScheme, "default", "10.200.1.1/16", "", nil)
	requests := r.clusterSetMapFunc(ctx, clusterSet)
	assert.Equal(t, expectedReqs, requests)

	requests = r.clusterSetMapFunc(ctx, deletedClusterSet)
	assert.Equal(t, []reconcile.Request{}, requests)

	r = NewNodeReconciler(fakeClient, common.TestScheme, "mismatch_ns", "10.200.1.1/16", "", nil)
	requests = r.clusterSetMapFunc(ctx, clusterSet)
	assert.Equal(t, []reconcile.Request{}, requests)
}

func Test_StatusPredicate(t *testing.T) {
	tests := []struct {
		name        string
		updateEvent event.UpdateEvent
		expected    bool
	}{
		{
			name: "status changed to ready",
			updateEvent: event.UpdateEvent{
				ObjectOld: &mcv1alpha2.ClusterSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-clusterset",
						Namespace: "default",
					},
				},
				ObjectNew: &mcv1alpha2.ClusterSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-clusterset",
						Namespace: "default",
					},
					Status: mcv1alpha2.ClusterSetStatus{
						Conditions: []mcv1alpha2.ClusterSetCondition{{
							Status: corev1.ConditionTrue,
						}},
					},
				},
			},
			expected: true,
		},
		{
			name: "status is changed from unknown to ready",
			updateEvent: event.UpdateEvent{
				ObjectOld: &mcv1alpha2.ClusterSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-clusterset",
						Namespace: "default",
					},
					Status: mcv1alpha2.ClusterSetStatus{
						Conditions: []mcv1alpha2.ClusterSetCondition{{
							Status: corev1.ConditionUnknown,
						}},
					},
				},
				ObjectNew: &mcv1alpha2.ClusterSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-clusterset",
						Namespace: "default",
					},
					Status: mcv1alpha2.ClusterSetStatus{
						Conditions: []mcv1alpha2.ClusterSetCondition{{
							Status: corev1.ConditionTrue,
						}},
					},
				},
			},
			expected: true,
		},
		{
			name: "status is ready but no change",
			updateEvent: event.UpdateEvent{
				ObjectOld: &mcv1alpha2.ClusterSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-clusterset",
						Namespace: "default",
					},
					Status: mcv1alpha2.ClusterSetStatus{
						Conditions: []mcv1alpha2.ClusterSetCondition{{
							Status: corev1.ConditionTrue,
						}},
					},
				},
				ObjectNew: &mcv1alpha2.ClusterSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-clusterset",
						Namespace: "default",
					},
					Status: mcv1alpha2.ClusterSetStatus{
						Conditions: []mcv1alpha2.ClusterSetCondition{{
							Status: corev1.ConditionTrue,
						}},
					},
				},
			},
			expected: false,
		},
	}
	for _, tt := range tests {
		actual := statusReadyPredicateFunc(tt.updateEvent)
		assert.Equal(t, tt.expected, actual)
	}
}
