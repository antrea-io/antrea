/*
Copyright 2021 Antrea Authors.

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

package leader

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	mcs "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"antrea.io/antrea/multicluster/apis/multicluster/constants"
	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
)

var (
	now        = metav1.Now()
	dropAction = v1beta1.RuleActionDrop
	svcLabels  = map[string]string{
		constants.SourceNamespace: "default",
		constants.SourceName:      "nginx",
		constants.SourceKind:      "Service",
	}
	epLabels = map[string]string{
		constants.SourceClusterID: "cluster-a",
		constants.SourceNamespace: "default",
		constants.SourceName:      "nginx",
		constants.SourceKind:      "Endpoints",
	}
	svcResReq = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: "default",
		Name:      "cluster-a-default-nginx-service",
	}}
	epResReq = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: "default",
		Name:      "cluster-a-default-nginx-endpoints",
	}}
	acnpResReq = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: "default",
		Name:      "test-acnp-export",
	}}
	isolationACNPSpec = &v1beta1.ClusterNetworkPolicySpec{
		Tier:     "securityops",
		Priority: 1.0,
		AppliedTo: []v1beta1.AppliedTo{
			{NamespaceSelector: &metav1.LabelSelector{}},
		},
		Ingress: []v1beta1.Rule{
			{
				Action: &dropAction,
				From: []v1beta1.NetworkPolicyPeer{
					{
						Namespaces: &v1beta1.PeerNamespaces{
							Match: v1beta1.NamespaceMatchSelf,
						},
					},
				},
			},
		},
	}
)

func TestResourceExportReconciler_handleServiceExportDeleteEvent(t *testing.T) {
	existingResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "cluster-a-default-nginx-service",
			Finalizers:        []string{constants.ResourceExportFinalizer},
			Labels:            svcLabels,
			DeletionTimestamp: &now,
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      constants.ServiceKind,
		},
	}
	existResImport := &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-nginx-service",
		},
	}
	namespacedName := types.NamespacedName{Namespace: "default", Name: "default-nginx-service"}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existingResExport, existResImport).Build()
	r := NewResourceExportReconciler(fakeClient, common.TestScheme)
	if _, err := r.Reconcile(common.TestCtx, svcResReq); err != nil {
		t.Errorf("ResourceExport Reconciler should handle ResourceExport delete event successfully but got error = %v", err)
	} else {
		resImport := &mcsv1alpha1.ResourceImport{}
		err := fakeClient.Get(common.TestCtx, namespacedName, resImport)
		if !apierrors.IsNotFound(err) {
			t.Errorf("ResourceExport Reconciler should delete ResourceImport successfully but got error = %v", err)
		}
	}
}

func TestResourceExportReconciler_handleEndpointsExportDeleteEvent(t *testing.T) {
	existingResExport1 := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "cluster-a-default-nginx-endpoints",
			Labels:            epLabels,
			DeletionTimestamp: &now,
			Finalizers:        []string{constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      constants.EndpointsKind,
			Endpoints: &mcsv1alpha1.EndpointsExport{
				Subsets: common.EPNginxSubset,
			},
		},
	}
	existingResExport2 := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "cluster-b-default-nginx-endpoints",
			Labels:     epLabels,
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      constants.EndpointsKind,
			Endpoints: &mcsv1alpha1.EndpointsExport{
				Subsets: common.EPNginxSubset2,
			},
		},
	}
	existResImport := &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-nginx-endpoints",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Name:      "nginx",
			Namespace: "default",
			Kind:      constants.EndpointsKind,
			Endpoints: &mcsv1alpha1.EndpointsImport{
				Subsets: append(common.EPNginxSubset, common.EPNginxSubset2...),
			},
		},
	}
	expectedSubsets := common.EPNginxSubset2
	namespacedName := types.NamespacedName{Namespace: "default", Name: "default-nginx-endpoints"}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existingResExport1, existingResExport2, existResImport).
		WithStatusSubresource(existingResExport1, existingResExport2, existResImport).Build()
	r := NewResourceExportReconciler(fakeClient, common.TestScheme)
	if _, err := r.Reconcile(common.TestCtx, epResReq); err != nil {
		t.Errorf("ResourceExport Reconciler should handle Endpoints ResourceExport delete event successfully but got error = %v", err)
	} else {
		resImport := &mcsv1alpha1.ResourceImport{}
		err := fakeClient.Get(common.TestCtx, namespacedName, resImport)
		if err != nil {
			t.Errorf("failed to get ResourceImport, got error = %v", err)
		} else if !reflect.DeepEqual(resImport.Spec.Endpoints.Subsets, expectedSubsets) {
			t.Errorf("expected ResourceImport Subsets are %v, but got %v", expectedSubsets, resImport.Spec.Endpoints.Subsets)
		}
	}
}

func TestResourceExportReconciler_handleServiceExportCreateEvent(t *testing.T) {
	existingResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "cluster-a-default-nginx-service",
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      constants.ServiceKind,
			Service: &mcsv1alpha1.ServiceExport{
				ServiceSpec: common.SvcNginxSpec,
			},
		},
	}
	expectedImportSpec := mcsv1alpha1.ResourceImportSpec{
		Name:      "nginx",
		Namespace: "default",
		Kind:      constants.ServiceImportKind,
		ServiceImport: &mcs.ServiceImport{
			Spec: mcs.ServiceImportSpec{
				Ports: SvcPortsConverter(existingResExport.Spec.Service.ServiceSpec.Ports),
				Type:  mcs.ClusterSetIP,
			},
		},
	}
	namespacedName := types.NamespacedName{Namespace: "default", Name: "default-nginx-service"}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existingResExport).Build()
	r := NewResourceExportReconciler(fakeClient, common.TestScheme)
	if _, err := r.Reconcile(common.TestCtx, svcResReq); err != nil {
		t.Errorf("ResourceExport Reconciler should handle Service ResourceExport create event successfully but got error = %v", err)
	} else {
		resImport := &mcsv1alpha1.ResourceImport{}
		err := fakeClient.Get(common.TestCtx, namespacedName, resImport)
		if err != nil {
			t.Errorf("failed to get ResourceImport, got error = %v", err)
		} else if !reflect.DeepEqual(resImport.Spec, expectedImportSpec) {
			t.Errorf("expected ResourceImport Spec %v, but got %v", expectedImportSpec, resImport.Spec)
		}
	}
}

func TestResourceExportReconciler_handleEndpointExportCreateEvent(t *testing.T) {
	existEPResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "cluster-a-default-nginx-endpoints",
			Finalizers: []string{constants.ResourceExportFinalizer},
			Labels: map[string]string{
				constants.SourceClusterID: "cluster-a",
				constants.SourceNamespace: "default",
				constants.SourceName:      "nginx",
			},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      constants.EndpointsKind,
			Endpoints: &mcsv1alpha1.EndpointsExport{
				Subsets: common.EPNginxSubset,
			},
		},
	}
	existSvcResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "cluster-a-default-nginx-service",
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      constants.ServiceImportKind,
		},
		Status: mcsv1alpha1.ResourceExportStatus{
			Conditions: []mcsv1alpha1.ResourceExportCondition{
				{Status: corev1.ConditionTrue},
			},
		},
	}
	expectedImportSpec := mcsv1alpha1.ResourceImportSpec{
		Name:      "nginx",
		Namespace: "default",
		Kind:      constants.EndpointsKind,
		Endpoints: &mcsv1alpha1.EndpointsImport{
			Subsets: existEPResExport.Spec.Endpoints.Subsets,
		},
	}
	namespacedName := types.NamespacedName{Namespace: "default", Name: "default-nginx-endpoints"}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existEPResExport, existSvcResExport).Build()
	r := NewResourceExportReconciler(fakeClient, common.TestScheme)
	if _, err := r.Reconcile(common.TestCtx, epResReq); err != nil {
		t.Errorf("ResourceExport Reconciler should handle Endpoints ResourceExport  create event successfully but got error = %v", err)
	} else {
		resImport := &mcsv1alpha1.ResourceImport{}
		err := fakeClient.Get(common.TestCtx, namespacedName, resImport)
		if err != nil {
			t.Errorf("failed to get ResourceImport, got error = %v", err)
		} else if !reflect.DeepEqual(resImport.Spec, expectedImportSpec) {
			t.Errorf("expected ResourceImport Spec %v, but got %v", expectedImportSpec, resImport.Spec)
		}
	}
}

func TestResourceExportReconciler_handleACNPExportCreateEvent(t *testing.T) {
	existingResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "test-acnp-export",
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Name:                 "test-acnp",
			Kind:                 constants.AntreaClusterNetworkPolicyKind,
			ClusterNetworkPolicy: isolationACNPSpec,
		},
	}
	expectedImportSpec := mcsv1alpha1.ResourceImportSpec{
		Name:                 "test-acnp",
		Kind:                 constants.AntreaClusterNetworkPolicyKind,
		ClusterNetworkPolicy: isolationACNPSpec,
	}
	namespacedName := GetResourceImportName(existingResExport)
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existingResExport).Build()
	r := NewResourceExportReconciler(fakeClient, common.TestScheme)
	if _, err := r.Reconcile(common.TestCtx, acnpResReq); err != nil {
		t.Errorf("ResourceExport Reconciler should handle ACNP ResourceExport create event successfully but got error = %v", err)
	} else {
		resImport := &mcsv1alpha1.ResourceImport{}
		err := fakeClient.Get(common.TestCtx, namespacedName, resImport)
		if err != nil {
			t.Errorf("failed to get ResourceImport, got error = %v", err)
		} else if !reflect.DeepEqual(resImport.Spec, expectedImportSpec) {
			t.Errorf("expected ResourceImport Spec %v, but got %v", expectedImportSpec, resImport.Spec)
		}
	}
}

var (
	newResExport = &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "cluster-a-default-nginx-service",
			Labels:     svcLabels,
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      constants.ServiceKind,
			Service: &mcsv1alpha1.ServiceExport{
				ServiceSpec: corev1.ServiceSpec{
					ClusterIP:  "192.168.2.3",
					ClusterIPs: []string{"192.168.2.3"},
					Ports:      []corev1.ServicePort{common.SvcPort8080},
					Type:       corev1.ServiceTypeClusterIP,
				},
			},
		},
	}

	existResImport = &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-nginx-service",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Name:      "nginx",
			Namespace: "default",
			Kind:      constants.ServiceImportKind,
			ServiceImport: &mcs.ServiceImport{
				Spec: mcs.ServiceImportSpec{
					Ports: SvcPortsConverter([]corev1.ServicePort{common.SvcPort80}),
					Type:  mcs.ClusterSetIP,
				},
			},
		},
	}
)

// When there is only one Service ResourceExport mapping to ResourceImport
// the single one ResourceExport update should trigger ResourceImport update
func TestResourceExportReconciler_handleSingleServiceUpdateEvent(t *testing.T) {
	expectedResImportSpec := mcsv1alpha1.ResourceImportSpec{
		Name:      "nginx",
		Namespace: "default",
		Kind:      constants.ServiceImportKind,
		ServiceImport: &mcs.ServiceImport{
			Spec: mcs.ServiceImportSpec{
				Ports: SvcPortsConverter([]corev1.ServicePort{{
					Name:     "http",
					Port:     8080,
					Protocol: corev1.ProtocolTCP,
				}}),
				Type: mcs.ClusterSetIP,
			},
		},
	}
	namespacedName := types.NamespacedName{Namespace: "default", Name: "default-nginx-service"}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).
		WithObjects(newResExport, existResImport).WithStatusSubresource(newResExport, existResImport).Build()
	r := NewResourceExportReconciler(fakeClient, common.TestScheme)
	if _, err := r.Reconcile(common.TestCtx, svcResReq); err != nil {
		t.Errorf("ResourceExport Reconciler should handle Service ResourceExport update event successfully but got error = %v", err)
	} else {
		resImport := &mcsv1alpha1.ResourceImport{}
		err := fakeClient.Get(common.TestCtx, namespacedName, resImport)
		if err != nil {
			t.Errorf("failed to get ResourceImport, got error = %v", err)
		} else if !reflect.DeepEqual(resImport.Spec, expectedResImportSpec) {
			t.Errorf("expected ResourceImport Spec %v, but got %v", expectedResImportSpec, resImport.Spec)
		}
	}
}

// When there are multiple Service ResourceExports mapping to ResourceImport
// one ResourceExport update with ports conflicts should return error
func TestResourceExportReconciler_handleServiceUpdateEvent(t *testing.T) {
	existingResExport2 := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "cluster-b-default-nginx-service",
			Labels:     svcLabels,
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      constants.ServiceKind,
			Service: &mcsv1alpha1.ServiceExport{
				ServiceSpec: common.SvcNginxSpec,
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).
		WithObjects(newResExport, existingResExport2, existResImport).WithStatusSubresource(newResExport, existingResExport2, existResImport).Build()
	r := NewResourceExportReconciler(fakeClient, common.TestScheme)
	if _, err := r.Reconcile(common.TestCtx, svcResReq); err != nil {
		if !assert.Contains(t, err.Error(), "don't match existing") {
			t.Errorf("ResourceExport Reconciler should handle Service ResourceExport update event successfully but got error = %v", err)
		}
		updatedSvcResExport := &mcsv1alpha1.ResourceExport{}
		err := fakeClient.Get(common.TestCtx, types.NamespacedName{Namespace: svcResReq.Namespace, Name: svcResReq.Name}, updatedSvcResExport)
		if err != nil {
			t.Errorf("should get ResourceExport successfully but got error = %v", err)
		}
		if updatedSvcResExport.Status.Conditions[0].Status != corev1.ConditionFalse {
			t.Errorf("expected ResourceExport status is 'False' but got %v", updatedSvcResExport.Status.Conditions[0].Status)
		}
	}
}

func TestResourceExportReconciler_handleClusterInfoKind(t *testing.T) {
	clusterAInfo := mcsv1alpha1.ClusterInfo{
		ClusterID:   "cluster-a",
		ServiceCIDR: "10.168.1.0/24",
		GatewayInfos: []mcsv1alpha1.GatewayInfo{
			{
				GatewayIP: "172.17.0.2",
			},
		},
	}
	clusterBInfo := mcsv1alpha1.ClusterInfo{
		ClusterID:   "cluster-b",
		ServiceCIDR: "110.16.1.0/24",
		GatewayInfos: []mcsv1alpha1.GatewayInfo{
			{
				GatewayIP: "12.17.0.2",
			},
		},
	}
	clusterBInfoNew := mcsv1alpha1.ClusterInfo{
		ClusterID:   "cluster-b",
		ServiceCIDR: "110.16.1.0/24",
		GatewayInfos: []mcsv1alpha1.GatewayInfo{
			{
				GatewayIP: "120.11.0.12",
			},
		},
	}
	clusterACIResExport := mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-default-clusterinfo",
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Kind:        constants.ClusterInfoKind,
			ClusterID:   "cluster-a",
			Name:        "cluster-a",
			Namespace:   "default",
			ClusterInfo: &clusterAInfo,
		},
	}
	clusterBCIResExport := mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-b-default-clusterinfo",
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Kind:        constants.ClusterInfoKind,
			ClusterID:   "cluster-b",
			Name:        "node-2",
			Namespace:   "default",
			ClusterInfo: &clusterBInfoNew,
		},
	}
	existResImport := mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-b-default-clusterinfo",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Kind:        constants.ClusterInfoKind,
			Name:        "node-2",
			Namespace:   "default",
			ClusterInfo: &clusterBInfo,
		},
	}
	deletedTime := metav1.Now()
	cluster3ResExportToDel := mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "cluster-c-default-clusterinfo",
			Finalizers:        []string{constants.ResourceExportFinalizer},
			DeletionTimestamp: &deletedTime,
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Kind:      constants.ClusterInfoKind,
			ClusterID: "cluster-c",
			Name:      "cluster-c",
			Namespace: "default",
		},
	}
	existResImportToDel := mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-c-default-clusterinfo",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Kind:        constants.ClusterInfoKind,
			Name:        "cluster-c",
			Namespace:   "default",
			ClusterInfo: &clusterBInfo,
		},
	}
	tests := []struct {
		name         string
		ciRes        mcsv1alpha1.ResourceExport
		expectedInfo mcsv1alpha1.ClusterInfo
		isDelete     bool
	}{
		{
			name:         "create a ClusterInfo kind of ResourceImport successfully",
			ciRes:        clusterACIResExport,
			expectedInfo: clusterAInfo,
		},
		{
			name:         "update a ClusterInfo kind of ResourceImport successfully",
			ciRes:        clusterBCIResExport,
			expectedInfo: clusterBInfoNew,
		},
		{
			name:     "delete a ClusterInfo kind of ResourceImport successfully",
			ciRes:    cluster3ResExportToDel,
			isDelete: true,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(&clusterACIResExport, &clusterBCIResExport,
		&existResImport, &existResImportToDel, &cluster3ResExportToDel).Build()
	r := NewResourceExportReconciler(fakeClient, common.TestScheme)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespacedName := types.NamespacedName{Namespace: tt.ciRes.Namespace, Name: tt.ciRes.Name}
			req := ctrl.Request{NamespacedName: namespacedName}
			if _, err := r.Reconcile(common.TestCtx, req); err != nil {
				t.Errorf("ResourceExport Reconciler should handle Resourcexports events successfully but got error = %v", err)
			} else {
				teImport := mcsv1alpha1.ResourceImport{}
				err := fakeClient.Get(common.TestCtx, namespacedName, &teImport)
				if err == nil {
					if tt.isDelete {
						t.Error("Expected not found err but got nil err")
					} else if !reflect.DeepEqual(*teImport.Spec.ClusterInfo, tt.expectedInfo) {
						t.Errorf("Expected ClusterInfo %v but got %v", tt.expectedInfo, teImport.Spec.ClusterInfo)
					}
				} else {
					teExport := mcsv1alpha1.ResourceExport{}
					err := fakeClient.Get(common.TestCtx, namespacedName, &teExport)
					if !apierrors.IsNotFound(err) {
						t.Errorf("ResourceExport should be deleted successfully but got = %v", err)
					}
				}
			}
		})
	}
}
