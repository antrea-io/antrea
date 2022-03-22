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

package multicluster

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

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

var (
	now        = metav1.Now()
	dropAction = v1alpha1.RuleActionDrop
	svcLabels  = map[string]string{
		common.SourceNamespace: "default",
		common.SourceName:      "nginx",
		common.SourceKind:      "Service",
	}
	epLabels = map[string]string{
		common.SourceClusterID: "cluster-a",
		common.SourceNamespace: "default",
		common.SourceName:      "nginx",
		common.SourceKind:      "Endpoints",
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
	isolationACNPSpec = &v1alpha1.ClusterNetworkPolicySpec{
		Tier:     "securityops",
		Priority: 1.0,
		AppliedTo: []v1alpha1.NetworkPolicyPeer{
			{NamespaceSelector: &metav1.LabelSelector{}},
		},
		Ingress: []v1alpha1.Rule{
			{
				Action: &dropAction,
				From: []v1alpha1.NetworkPolicyPeer{
					{
						Namespaces: &v1alpha1.PeerNamespaces{
							Match: v1alpha1.NamespaceMatchSelf,
						},
					},
				},
			},
		},
	}
)

func TestResourceExportReconciler_handleServiceExportDeleteEvent(t *testing.T) {
	existResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "cluster-a-default-nginx-service",
			Finalizers:        []string{common.ResourceExportFinalizer},
			Labels:            svcLabels,
			DeletionTimestamp: &now,
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      common.ServiceKind,
		},
	}
	existResImport := &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-nginx-service",
		},
	}
	namespacedName := types.NamespacedName{Namespace: "default", Name: "default-nginx-service"}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existResExport, existResImport).Build()
	r := NewResourceExportReconciler(fakeClient, scheme)
	if _, err := r.Reconcile(ctx, svcResReq); err != nil {
		t.Errorf("ResourceExport Reconciler should handle ResourceExport delete event successfully but got error = %v", err)
	} else {
		resImport := &mcsv1alpha1.ResourceImport{}
		err := fakeClient.Get(ctx, namespacedName, resImport)
		if !apierrors.IsNotFound(err) {
			t.Errorf("ResourceExport Reconciler should delete ResourceImport successfully but got error = %v", err)
		}
	}
}

func TestResourceExportReconciler_handleEndpointsExportDeleteEvent(t *testing.T) {
	existResExport1 := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "cluster-a-default-nginx-endpoints",
			Labels:            epLabels,
			DeletionTimestamp: &now,
			Finalizers:        []string{common.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      common.EndpointsKind,
			Endpoints: &mcsv1alpha1.EndpointsExport{
				Subsets: epNginxSubset,
			},
		},
	}
	existResExport2 := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "cluster-b-default-nginx-endpoints",
			Labels:     epLabels,
			Finalizers: []string{common.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      common.EndpointsKind,
			Endpoints: &mcsv1alpha1.EndpointsExport{
				Subsets: epNginxSubset2,
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
			Kind:      common.EndpointsKind,
			Endpoints: &mcsv1alpha1.EndpointsImport{
				Subsets: append(epNginxSubset, epNginxSubset2...),
			},
		},
	}
	expectedSubsets := epNginxSubset2
	namespacedName := types.NamespacedName{Namespace: "default", Name: "default-nginx-endpoints"}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existResExport1, existResExport2, existResImport).Build()
	r := NewResourceExportReconciler(fakeClient, scheme)
	if _, err := r.Reconcile(ctx, epResReq); err != nil {
		t.Errorf("ResourceExport Reconciler should handle Endpoints ResourceExport delete event successfully but got error = %v", err)
	} else {
		resImport := &mcsv1alpha1.ResourceImport{}
		err := fakeClient.Get(ctx, namespacedName, resImport)
		if err != nil {
			t.Errorf("failed to get ResourceImport, got error = %v", err)
		} else if !reflect.DeepEqual(resImport.Spec.Endpoints.Subsets, expectedSubsets) {
			t.Errorf("expected ResourceImport Subsets are %v, but got %v", expectedSubsets, resImport.Spec.Endpoints.Subsets)
		}
	}
}

func TestResourceExportReconciler_handleServiceExportCreateEvent(t *testing.T) {
	existResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "cluster-a-default-nginx-service",
			Finalizers: []string{common.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      common.ServiceKind,
			Service: &mcsv1alpha1.ServiceExport{
				ServiceSpec: svcNginxSpec,
			},
		},
	}
	expectedImportSpec := mcsv1alpha1.ResourceImportSpec{
		Name:      "nginx",
		Namespace: "default",
		Kind:      common.ServiceImportKind,
		ServiceImport: &mcs.ServiceImport{
			Spec: mcs.ServiceImportSpec{
				Ports: SvcPortsConverter(existResExport.Spec.Service.ServiceSpec.Ports),
				Type:  mcs.ClusterSetIP,
			},
		},
	}
	namespacedName := types.NamespacedName{Namespace: "default", Name: "default-nginx-service"}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existResExport).Build()
	r := NewResourceExportReconciler(fakeClient, scheme)
	if _, err := r.Reconcile(ctx, svcResReq); err != nil {
		t.Errorf("ResourceExport Reconciler should handle Service ResourceExport create event successfully but got error = %v", err)
	} else {
		resImport := &mcsv1alpha1.ResourceImport{}
		err := fakeClient.Get(ctx, namespacedName, resImport)
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
			Finalizers: []string{common.ResourceExportFinalizer},
			Labels: map[string]string{
				common.SourceClusterID: "cluster-a",
				common.SourceNamespace: "default",
				common.SourceName:      "nginx",
			},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      common.EndpointsKind,
			Endpoints: &mcsv1alpha1.EndpointsExport{
				Subsets: epNginxSubset,
			},
		},
	}
	existSvcResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "cluster-a-default-nginx-service",
			Finalizers: []string{common.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      common.ServiceImportKind,
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
		Kind:      common.EndpointsKind,
		Endpoints: &mcsv1alpha1.EndpointsImport{
			Subsets: existEPResExport.Spec.Endpoints.Subsets,
		},
	}
	namespacedName := types.NamespacedName{Namespace: "default", Name: "default-nginx-endpoints"}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existEPResExport, existSvcResExport).Build()
	r := NewResourceExportReconciler(fakeClient, scheme)
	if _, err := r.Reconcile(ctx, epResReq); err != nil {
		t.Errorf("ResourceExport Reconciler should handle Endpoints ResourceExport  create event successfully but got error = %v", err)
	} else {
		resImport := &mcsv1alpha1.ResourceImport{}
		err := fakeClient.Get(ctx, namespacedName, resImport)
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
			Finalizers: []string{common.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Name:                 "test-acnp",
			Kind:                 common.AntreaClusterNetworkPolicyKind,
			ClusterNetworkPolicy: isolationACNPSpec,
		},
	}
	expectedImportSpec := mcsv1alpha1.ResourceImportSpec{
		Name:                 "test-acnp",
		Kind:                 common.AntreaClusterNetworkPolicyKind,
		ClusterNetworkPolicy: isolationACNPSpec,
	}
	namespacedName := GetResourceImportName(existingResExport)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingResExport).Build()
	r := NewResourceExportReconciler(fakeClient, scheme)
	if _, err := r.Reconcile(ctx, acnpResReq); err != nil {
		t.Errorf("ResourceExport Reconciler should handle ACNP ResourceExport create event successfully but got error = %v", err)
	} else {
		resImport := &mcsv1alpha1.ResourceImport{}
		err := fakeClient.Get(ctx, namespacedName, resImport)
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
			Finalizers: []string{common.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      common.ServiceKind,
			Service: &mcsv1alpha1.ServiceExport{
				ServiceSpec: corev1.ServiceSpec{
					ClusterIP:  "192.168.2.3",
					ClusterIPs: []string{"192.168.2.3"},
					Ports:      []corev1.ServicePort{svcPort8080},
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
			Kind:      common.ServiceImportKind,
			ServiceImport: &mcs.ServiceImport{
				Spec: mcs.ServiceImportSpec{
					Ports: SvcPortsConverter([]corev1.ServicePort{svcPort80}),
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
		Kind:      common.ServiceImportKind,
		ServiceImport: &mcs.ServiceImport{
			Spec: mcs.ServiceImportSpec{
				Ports: SvcPortsConverter([]corev1.ServicePort{{
					Name:     "8080tcp",
					Port:     8080,
					Protocol: corev1.ProtocolTCP,
				}}),
				Type: mcs.ClusterSetIP,
			},
		},
	}
	namespacedName := types.NamespacedName{Namespace: "default", Name: "default-nginx-service"}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(newResExport, existResImport).Build()
	r := NewResourceExportReconciler(fakeClient, scheme)
	if _, err := r.Reconcile(ctx, svcResReq); err != nil {
		t.Errorf("ResourceExport Reconciler should handle Service ResourceExport update event successfully but got error = %v", err)
	} else {
		resImport := &mcsv1alpha1.ResourceImport{}
		err := fakeClient.Get(ctx, namespacedName, resImport)
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
	existResExport2 := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "cluster-b-default-nginx-service",
			Labels:     svcLabels,
			Finalizers: []string{common.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      common.ServiceKind,
			Service: &mcsv1alpha1.ServiceExport{
				ServiceSpec: svcNginxSpec,
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(newResExport, existResExport2, existResImport).Build()
	r := NewResourceExportReconciler(fakeClient, scheme)
	if _, err := r.Reconcile(ctx, svcResReq); err != nil {
		if !assert.Contains(t, err.Error(), "don't match existing") {
			t.Errorf("ResourceExport Reconciler should handle Service ResourceExport update event successfully but got error = %v", err)
		}
		updatedSvcResExport := &mcsv1alpha1.ResourceExport{}
		err := fakeClient.Get(ctx, types.NamespacedName{Namespace: svcResReq.Namespace, Name: svcResReq.Name}, updatedSvcResExport)
		if err != nil {
			t.Errorf("should get ResourceExport successfully but got error = %v", err)
		}
		if updatedSvcResExport.Status.Conditions[0].Status != corev1.ConditionFalse {
			t.Errorf("expected ResourceExport status is 'False' but got %v", updatedSvcResExport.Status.Conditions[0].Status)
		}
	}
}
