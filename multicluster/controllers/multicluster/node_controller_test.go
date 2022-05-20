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

package multicluster

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

func TestNodeReconciler(t *testing.T) {
	node1 := &corev1.Node{
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
		},
	}
	node1NoValidUpdate := *node1
	node1NoValidUpdate.Labels = map[string]string{"hostname.k8s.io": "node-1"}
	node1NoAnnotation := *node1
	node1NoAnnotation.Annotations = map[string]string{}
	node1WithIPAnnotation := *node1
	node1WithIPAnnotation.Annotations = map[string]string{
		common.GatewayAnnotation:   "true",
		common.GatewayIPAnnotation: "11.11.10.10",
	}

	tests := []struct {
		name        string
		nodes       []*corev1.Node
		req         reconcile.Request
		existingGW  *mcsv1alpha1.Gateway
		expectedGW  *mcsv1alpha1.Gateway
		isDelete    bool
		expectedErr string
	}{
		{
			name:       "create a Gateway successfully",
			nodes:      []*corev1.Node{node1},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "", Name: node1.Name}},
			expectedGW: &gwNode1,
		},
		{
			name:       "update a Gateway successfully by changing GatewayIP",
			nodes:      []*corev1.Node{&node1WithIPAnnotation},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "", Name: node1.Name}},
			existingGW: &gwNode1,
			expectedGW: &mcsv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "node-1",
					Namespace: "default",
				},
				GatewayIP:  "11.11.10.10",
				InternalIP: "172.11.10.1",
			},
		},
		{
			name:       "remove a Gateway Node to delete a Gateway successfully",
			nodes:      []*corev1.Node{},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "", Name: node1.Name}},
			existingGW: &gwNode1,
			isDelete:   true,
		},
		{
			name:       "remove a Gateway Node's annotation to delete a Gateway successfully",
			nodes:      []*corev1.Node{&node1NoAnnotation},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "", Name: node1.Name}},
			existingGW: &gwNode1,
			isDelete:   true,
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
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(obj...).Build()
			r := NewNodeReconciler(fakeClient, scheme, "default", mcsv1alpha1.PrecedencePublic)
			if _, err := r.Reconcile(ctx, tt.req); err != nil {
				if tt.expectedErr != "" {
					assert.Contains(t, err.Error(), tt.expectedErr)
				} else {
					t.Errorf("Node Reconciler should handle Node events successfully but got error = %v", err)
				}
			} else {
				newGW := &mcsv1alpha1.Gateway{}
				gwNamespcedName := types.NamespacedName{Name: "node-1", Namespace: "default"}
				err := fakeClient.Get(ctx, gwNamespcedName, newGW)
				if err != nil {
					if tt.isDelete {
						if !apierrors.IsNotFound(err) {
							t.Errorf("Expected to get not found error but got err: %v", err)
						}
					} else {
						t.Errorf("Expected to get Gateway but got err: %v", err)
					}
				} else if tt.expectedGW.GatewayIP != newGW.GatewayIP || tt.expectedGW.InternalIP != newGW.InternalIP {
					t.Errorf("Expected Gateway %v but got: %v", tt.expectedGW, newGW)
				}
			}
		})
	}
}
