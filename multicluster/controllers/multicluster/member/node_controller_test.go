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
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

var (
	node1           *corev1.Node
	node2           *corev1.Node
	node3           *corev1.Node
	node4           *corev1.Node
	updatedGateway2 *mcsv1alpha1.Gateway
	gateway3        *mcsv1alpha1.Gateway
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

	updatedGateway2 = &mcsv1alpha1.Gateway{
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
		precedence    mcsv1alpha1.Precedence
		existingGW    *mcsv1alpha1.Gateway
		expectedGW    *mcsv1alpha1.Gateway
		activeGateway string
		candidates    map[string]bool
		isDelete      bool
	}{
		{
			name:       "create a Gateway successfully",
			nodes:      []*corev1.Node{node1},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Name: node1.Name}},
			expectedGW: &gwNode1,
			precedence: mcsv1alpha1.PrecedencePublic,
		},
		{
			name:       "update a Gateway successfully by changing GatewayIP",
			nodes:      []*corev1.Node{&node1WithIPAnnotation},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Name: node1.Name}},
			existingGW: &gwNode1,
			expectedGW: &mcsv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "node-1",
					Namespace: "default",
				},
				GatewayIP:  "11.11.10.10",
				InternalIP: "172.11.10.1",
			},
			activeGateway: "node-1",
			precedence:    mcsv1alpha1.PrecedencePublic,
		},
		{
			name:          "remove a Gateway Node to delete a Gateway successfully",
			nodes:         []*corev1.Node{},
			req:           reconcile.Request{NamespacedName: types.NamespacedName{Name: node1.Name}},
			existingGW:    &gwNode1,
			activeGateway: "node-1",
			isDelete:      true,
			precedence:    mcsv1alpha1.PrecedencePublic,
		},
		{
			name:          "remove a Gateway Node's annotation to delete a Gateway successfully",
			nodes:         []*corev1.Node{&node1NoAnnotation},
			req:           reconcile.Request{NamespacedName: types.NamespacedName{Name: node1.Name}},
			existingGW:    &gwNode1,
			activeGateway: "node-1",
			isDelete:      true,
			precedence:    mcsv1alpha1.PrecedencePublic,
		},
		{
			name:       "remote a Gateway due to no IPs",
			nodes:      []*corev1.Node{newNode1},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Name: newNode1.Name}},
			existingGW: &gwNode1,
			isDelete:   true,
			precedence: mcsv1alpha1.PrecedencePrivate,
		},
		{
			name:          "remove a Gateway Node to create a new Gateway from candidates successfully",
			nodes:         []*corev1.Node{node2, node4},
			req:           reconcile.Request{NamespacedName: types.NamespacedName{Name: node1.Name}},
			existingGW:    &gwNode1,
			expectedGW:    updatedGateway2,
			activeGateway: "node-1",
			precedence:    mcsv1alpha1.PrecedencePublic,
		},
		{
			name:          "create a new Gateway successfully when active Gateway Node is not ready",
			nodes:         []*corev1.Node{node2, node3},
			req:           reconcile.Request{NamespacedName: types.NamespacedName{Name: node3.Name}},
			existingGW:    gateway3,
			expectedGW:    updatedGateway2,
			activeGateway: "node-3",
			precedence:    mcsv1alpha1.PrecedencePublic,
		},
		{
			name:          "create a new Gateway successfully when active Gateway Node has no valid IP",
			nodes:         []*corev1.Node{node2, node4},
			req:           reconcile.Request{NamespacedName: types.NamespacedName{Name: node4.Name}},
			existingGW:    gateway4,
			expectedGW:    updatedGateway2,
			activeGateway: "node-4",
			precedence:    mcsv1alpha1.PrecedencePublic,
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
			r := NewNodeReconciler(fakeClient, common.TestScheme, "default", tt.precedence)
			r.activeGateway = tt.activeGateway
			if _, err := r.Reconcile(common.TestCtx, tt.req); err != nil {
				t.Errorf("Node Reconciler should handle Node events successfully but got error = %v", err)
			} else {
				newGW := &mcsv1alpha1.Gateway{}
				gwNamespcedName := types.NamespacedName{Name: tt.req.Name, Namespace: "default"}
				if tt.expectedGW != nil {
					gwNamespcedName = types.NamespacedName{Name: tt.expectedGW.Name, Namespace: "default"}
				}
				err := fakeClient.Get(common.TestCtx, gwNamespcedName, newGW)
				if tt.isDelete {
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
		existingGW            *mcsv1alpha1.Gateway
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
			r := NewNodeReconciler(fakeClient, common.TestScheme, "default", mcsv1alpha1.PrecedencePublic)
			if err := r.initialize(); err != nil {
				t.Errorf("Expected initialize() successfully but got err: %v", err)
			} else {
				assert.Equal(t, tt.expectedActiveGateway, r.activeGateway)
				assert.Equal(t, tt.candidatesSize, len(r.gatewayCandidates))
				if tt.isDelete {
					deletedGW := &mcsv1alpha1.Gateway{}
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
