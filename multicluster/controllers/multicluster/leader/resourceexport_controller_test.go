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
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	mcs "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"antrea.io/antrea/v2/multicluster/apis/multicluster/constants"
	mcsv1alpha1 "antrea.io/antrea/v2/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/v2/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
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

	epReady    = true
	epProtocol = corev1.ProtocolTCP
	epPort80   = int32(80)

	// discEPsA is a set of discovery endpoints from cluster-a (pod1).
	discEPsA = []discoveryv1.Endpoint{
		{
			Addresses:  []string{"192.168.17.11"},
			Conditions: discoveryv1.EndpointConditions{Ready: &epReady},
		},
	}
	// discEPsB is a set of discovery endpoints from cluster-b (pod2).
	discEPsB = []discoveryv1.Endpoint{
		{
			Addresses:  []string{"192.168.17.12"},
			Conditions: discoveryv1.EndpointConditions{Ready: &epReady},
		},
	}
	discPorts80 = []discoveryv1.EndpointPort{
		{
			Name:     ptr.To("http"),
			Port:     ptr.To(epPort80),
			Protocol: ptr.To(epProtocol),
		},
	}
	svcResReq = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: "default",
		Name:      "cluster-a-default-nginx-service",
	}}
	svcResReq2 = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: "default",
		Name:      "cluster-b-default-nginx-service",
	}}
	epResReq = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: "default",
		Name:      "cluster-a-default-nginx-endpoints",
	}}
	epResReq2 = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: "default",
		Name:      "cluster-c-default-nginx-endpoints",
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
	existingResExportWithLegacyFinalizer := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "cluster-a-default-nginx-service",
			Finalizers:        []string{constants.LegacyResourceExportFinalizer},
			Labels:            svcLabels,
			DeletionTimestamp: &now,
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      constants.ServiceKind,
		},
	}
	existingResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "cluster-b-default-nginx-service",
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
		Spec: mcsv1alpha1.ResourceImportSpec{
			Name:      "nginx",
			Namespace: "default",
			Kind:      constants.ServiceImportKind,
		},
	}
	namespacedName := types.NamespacedName{Namespace: "default", Name: "default-nginx-service"}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existingResExportWithLegacyFinalizer, existingResExport, existResImport).Build()

	r := NewResourceExportReconciler(fakeClient, common.TestScheme)
	_, err := r.Reconcile(common.TestCtx, svcResReq)
	require.NoError(t, err, "ResourceExport Reconciler should handle ResourceExport delete event successfully")
	_, err = r.Reconcile(common.TestCtx, svcResReq2)
	require.NoError(t, err, "ResourceExport Reconciler should handle ResourceExport delete event successfully")

	resImport := &mcsv1alpha1.ResourceImport{}
	err = fakeClient.Get(common.TestCtx, namespacedName, resImport)
	assert.Truef(t, apierrors.IsNotFound(err), "ResourceExport Reconciler should delete ResourceImport successfully")

	resExportsLeft := &mcsv1alpha1.ResourceExportList{}
	err = fakeClient.List(common.TestCtx, resExportsLeft)
	require.NoError(t, err, "failed to get all ResourceExports")
	assert.Empty(t, resExportsLeft.Items, "unexpected number of ResourceExports left in the cluster after deletion")
}

func TestResourceExportReconciler_handleEndpointsExportDeleteEvent(t *testing.T) {
	// cluster-a export is being deleted (DeletionTimestamp set).
	existingResExport1 := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "cluster-a-default-nginx-endpoints",
			Labels:            epLabels,
			DeletionTimestamp: &now,
			Finalizers:        []string{constants.LegacyResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      constants.EndpointsKind,
			Endpoints: &mcsv1alpha1.EndpointsExport{
				Endpoints: discEPsA,
				Ports:     discPorts80,
			},
		},
	}
	// cluster-b export remains active after cluster-a is deleted.
	existingResExport2 := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "cluster-b-default-nginx-endpoints",
			Labels:     epLabels,
			Finalizers: []string{constants.LegacyResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      constants.EndpointsKind,
			Endpoints: &mcsv1alpha1.EndpointsExport{
				Endpoints: discEPsB,
				Ports:     discPorts80,
			},
		},
	}
	// A ResourceExport with both legacy and new domain qualified finalizers should remove
	// all the finalizers and be deleted successfully.
	existingResExport3 := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "cluster-c-default-nginx-endpoints",
			Labels:            epLabels,
			DeletionTimestamp: &now,
			Finalizers:        []string{constants.LegacyResourceExportFinalizer, constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      constants.EndpointsKind,
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
				Endpoints: append(discEPsA, discEPsB...),
				Ports:     discPorts80,
			},
		},
	}
	namespacedName := types.NamespacedName{Namespace: "default", Name: "default-nginx-endpoints"}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existingResExport1, existingResExport2, existingResExport3, existResImport).
		WithStatusSubresource(existingResExport1, existingResExport2, existingResExport3, existResImport).Build()

	r := NewResourceExportReconciler(fakeClient, common.TestScheme)
	_, err := r.Reconcile(common.TestCtx, epResReq)
	require.NoError(t, err, "ResourceExport Reconciler should handle Endpoints ResourceExport delete event successfully")
	_, err = r.Reconcile(common.TestCtx, epResReq2)
	require.NoError(t, err, "ResourceExport Reconciler should handle Endpoints ResourceExport delete event successfully")

	resImport := &mcsv1alpha1.ResourceImport{}
	err = fakeClient.Get(common.TestCtx, namespacedName, resImport)
	require.NoError(t, err, "failed to get ResourceImport")
	// After cluster-a is deleted, only cluster-b's endpoints should remain.
	assert.ElementsMatch(t, discEPsB, resImport.Spec.Endpoints.Endpoints, "unexpected ResourceImport Endpoints")
	assert.ElementsMatch(t, discPorts80, resImport.Spec.Endpoints.Ports, "unexpected ResourceImport Ports")

	resExportsLeft := &mcsv1alpha1.ResourceExportList{}
	err = fakeClient.List(common.TestCtx, resExportsLeft)
	require.NoError(t, err, "failed to get all ResourceExports")
	assert.Equalf(t, 1, len(resExportsLeft.Items), "unexpected number of ResourceExports left in the cluster after deletion")
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
				Endpoints: discEPsA,
				Ports:     discPorts80,
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
			Endpoints: discEPsA,
			Ports:     discPorts80,
			Subsets:   common.EndpointsToSubsets(discEPsA, discPorts80),
		},
	}
	namespacedName := types.NamespacedName{Namespace: "default", Name: "default-nginx-endpoints"}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existEPResExport, existSvcResExport).Build()
	r := NewResourceExportReconciler(fakeClient, common.TestScheme)
	if _, err := r.Reconcile(common.TestCtx, epResReq); err != nil {
		t.Errorf("ResourceExport Reconciler should handle Endpoints ResourceExport create event successfully but got error = %v", err)
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
	cluster3ResExportToDelLegacyFinalizer := mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "cluster-c-default-clusterinfo",
			Finalizers:        []string{constants.LegacyResourceExportFinalizer},
			DeletionTimestamp: &deletedTime,
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Kind:      constants.ClusterInfoKind,
			ClusterID: "cluster-c",
			Name:      "cluster-c",
			Namespace: "default",
		},
	}
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
		name            string
		ciRes           mcsv1alpha1.ResourceExport
		existingObjects []client.Object
		expectedInfo    mcsv1alpha1.ClusterInfo
		isDelete        bool
	}{
		{
			name:            "create a ClusterInfo kind of ResourceImport successfully",
			ciRes:           clusterACIResExport,
			existingObjects: []client.Object{&clusterACIResExport},
			expectedInfo:    clusterAInfo,
		},
		{
			name:            "update a ClusterInfo kind of ResourceImport successfully",
			ciRes:           clusterBCIResExport,
			existingObjects: []client.Object{&clusterBCIResExport, &existResImport},
			expectedInfo:    clusterBInfoNew,
		},
		{
			name:            "delete a ClusterInfo kind of ResourceImport and ResourceExport with legacy finalizer successfully",
			ciRes:           cluster3ResExportToDelLegacyFinalizer,
			existingObjects: []client.Object{&existResImportToDel, &cluster3ResExportToDelLegacyFinalizer},
			isDelete:        true,
		},
		{
			name:            "delete a ClusterInfo kind of ResourceImport and ResourceExport successfully",
			ciRes:           cluster3ResExportToDelLegacyFinalizer,
			existingObjects: []client.Object{&existResImportToDel, &cluster3ResExportToDel},
			isDelete:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(tt.existingObjects...).Build()
			r := NewResourceExportReconciler(fakeClient, common.TestScheme)
			namespacedName := types.NamespacedName{Namespace: tt.ciRes.Namespace, Name: tt.ciRes.Name}
			req := ctrl.Request{NamespacedName: namespacedName}
			_, err := r.Reconcile(common.TestCtx, req)
			require.NoError(t, err, "ResourceExport Reconciler should handle ResourceExports events successfully")

			teImport := mcsv1alpha1.ResourceImport{}
			err = fakeClient.Get(common.TestCtx, namespacedName, &teImport)
			if err == nil {
				assert.Falsef(t, tt.isDelete, "Expected error to be not found err but got nil")
				assert.Truef(t, reflect.DeepEqual(*teImport.Spec.ClusterInfo, tt.expectedInfo), "unexpected ClusterInfo")
			} else {
				teExport := mcsv1alpha1.ResourceExport{}
				err := fakeClient.Get(common.TestCtx, namespacedName, &teExport)
				assert.Truef(t, apierrors.IsNotFound(err), "ResourceExport should be deleted successfully")
			}
		})
	}
}

// A member can craft a Service/Endpoints export whose (Namespace, Name, Kind)
// tuple resolves to the same ResourceImport name as another member's export
// while being a different tuple (the import name is derived from the
// concatenated tuple alone). The reconciler must refuse to update the existing
// ResourceImport instead of overwriting it.
func TestResourceExportReconciler_refusesResourceImportTupleCollision(t *testing.T) {
	// cluster-b's export (Namespace "foo-bar", Name "baz") derives the same
	// ResourceImport name ("foo-bar-baz-service") as cluster-a's export
	// (Namespace "foo", Name "bar-baz"), but the tuples differ.
	resExportB := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "cluster-b-foo-bar-baz-service",
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "foo-bar",
			Name:      "baz",
			Kind:      constants.ServiceKind,
			Service: &mcsv1alpha1.ServiceExport{
				ServiceSpec: common.SvcNginxSpec,
			},
		},
	}
	// ResourceImport created from cluster-a's export.
	existResImport := &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "foo-bar-baz-service",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Name:      "bar-baz",
			Namespace: "foo",
			Kind:      constants.ServiceImportKind,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).
		WithObjects(resExportB, existResImport).WithStatusSubresource(resExportB, existResImport).Build()
	r := NewResourceExportReconciler(fakeClient, common.TestScheme)
	_, err := r.Reconcile(common.TestCtx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "cluster-b-foo-bar-baz-service"}})
	require.Error(t, err, "ResourceExport Reconciler should refuse to reconcile a ResourceExport whose tuple collides with the existing ResourceImport")

	updatedResExport := &mcsv1alpha1.ResourceExport{}
	err = fakeClient.Get(common.TestCtx, types.NamespacedName{Namespace: "default", Name: "cluster-b-foo-bar-baz-service"}, updatedResExport)
	require.NoError(t, err, "failed to get ResourceExport")
	require.Len(t, updatedResExport.Status.Conditions, 1, "ResourceExport status should record the reconcile failure")
	assert.Equal(t, mcsv1alpha1.ResourceExportFailure, updatedResExport.Status.Conditions[0].Type)
	assert.Equal(t, corev1.ConditionFalse, updatedResExport.Status.Conditions[0].Status)

	updatedResImport := &mcsv1alpha1.ResourceImport{}
	err = fakeClient.Get(common.TestCtx, types.NamespacedName{Namespace: "default", Name: "foo-bar-baz-service"}, updatedResImport)
	require.NoError(t, err, "failed to get ResourceImport")
	assert.Equal(t, "foo", updatedResImport.Spec.Namespace, "ResourceImport Namespace should not be overwritten by the colliding ResourceExport")
	assert.Equal(t, "bar-baz", updatedResImport.Spec.Name, "ResourceImport Name should not be overwritten by the colliding ResourceExport")
	assert.Equal(t, constants.ServiceImportKind, updatedResImport.Spec.Kind, "ResourceImport Kind should not be overwritten by the colliding ResourceExport")
}

// A transient non-NotFound error while reading the existing ResourceImport
// (e.g. a leader API server restart) stamps a ResourceExportFailure condition.
// The next clean reconcile must overwrite it: the success writes only fire when
// the import is created or changed, so without the overwrite the failure would
// linger and refreshEndpointsResourceImport would reject sibling Endpoints
// exports for the Service indefinitely.
func TestResourceExportReconciler_transientImportGetFailureSelfHeals(t *testing.T) {
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
	importName := "default-nginx-service"
	// Fail only the second Get on the ResourceImport, once the first reconcile
	// has created it, so the transient error lands mid-sequence.
	getCalls := 0
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existingResExport).
		WithStatusSubresource(existingResExport).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if key.Name == importName {
					getCalls++
					if getCalls == 2 {
						return fmt.Errorf("transient failure reading ResourceImport")
					}
				}
				// Delegate to the underlying client: returning nil here would
				// short-circuit the Get entirely, leaving the object untouched.
				return c.Get(ctx, key, obj, opts...)
			},
		}).Build()
	r := NewResourceExportReconciler(fakeClient, common.TestScheme)

	_, err := r.Reconcile(common.TestCtx, svcResReq)
	require.NoError(t, err, "first reconcile should create the ResourceImport")

	_, err = r.Reconcile(common.TestCtx, svcResReq)
	require.Error(t, err, "second reconcile should fail on the transient Get error")
	updatedResExport := &mcsv1alpha1.ResourceExport{}
	err = fakeClient.Get(common.TestCtx, types.NamespacedName{Namespace: "default", Name: "cluster-a-default-nginx-service"}, updatedResExport)
	require.NoError(t, err, "failed to get ResourceExport")
	require.Len(t, updatedResExport.Status.Conditions, 1, "ResourceExport status should record the reconcile failure")
	assert.Equal(t, mcsv1alpha1.ResourceExportFailure, updatedResExport.Status.Conditions[0].Type)
	assert.Equal(t, corev1.ConditionFalse, updatedResExport.Status.Conditions[0].Status)
	existingResImport := &mcsv1alpha1.ResourceImport{}
	err = fakeClient.Get(common.TestCtx, types.NamespacedName{Namespace: "default", Name: importName}, existingResImport)
	require.NoError(t, err, "the transient failure must not disturb the existing ResourceImport")

	_, err = r.Reconcile(common.TestCtx, svcResReq)
	require.NoError(t, err, "third reconcile is clean and should clear the failure")
	updatedResExport = &mcsv1alpha1.ResourceExport{}
	err = fakeClient.Get(common.TestCtx, types.NamespacedName{Namespace: "default", Name: "cluster-a-default-nginx-service"}, updatedResExport)
	require.NoError(t, err, "failed to get ResourceExport")
	require.Len(t, updatedResExport.Status.Conditions, 1, "ResourceExport status should be overwritten on the clean reconcile")
	assert.Equal(t, mcsv1alpha1.ResourceExportSucceeded, updatedResExport.Status.Conditions[0].Type)
	assert.Equal(t, corev1.ConditionTrue, updatedResExport.Status.Conditions[0].Status)
}

// When a member deletes an export whose tuple differs from the existing
// ResourceImport's (i.e. the import name collides with another member's
// export), the reconciler must not delete the ResourceImport, but must still
// let the export deletion (and its finalizer removal) complete.
func TestResourceExportReconciler_skipsResourceImportCleanupOnTupleCollision(t *testing.T) {
	resExportB := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-b-foo-bar-baz-endpoints",
			Labels: map[string]string{
				constants.SourceClusterID: "cluster-b",
				constants.SourceNamespace: "foo-bar",
				constants.SourceName:      "baz",
				constants.SourceKind:      "Endpoints",
			},
			Finalizers:        []string{constants.ResourceExportFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "foo-bar",
			Name:      "baz",
			Kind:      constants.EndpointsKind,
		},
	}
	// ResourceImport created from cluster-a's export (Namespace "foo", Name "bar-baz").
	existResImport := &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "foo-bar-baz-endpoints",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Name:      "bar-baz",
			Namespace: "foo",
			Kind:      constants.EndpointsKind,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).
		WithObjects(resExportB, existResImport).Build()
	r := NewResourceExportReconciler(fakeClient, common.TestScheme)
	_, err := r.Reconcile(common.TestCtx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "cluster-b-foo-bar-baz-endpoints"}})
	require.NoError(t, err, "ResourceExport Reconciler should let the colliding ResourceExport deletion complete")

	updatedResImport := &mcsv1alpha1.ResourceImport{}
	err = fakeClient.Get(common.TestCtx, types.NamespacedName{Namespace: "default", Name: "foo-bar-baz-endpoints"}, updatedResImport)
	require.NoError(t, err, "ResourceImport created from another member's export should not be deleted by the colliding export's deletion")

	resExportsLeft := &mcsv1alpha1.ResourceExportList{}
	err = fakeClient.List(common.TestCtx, resExportsLeft)
	require.NoError(t, err, "failed to list ResourceExports")
	assert.Empty(t, resExportsLeft.Items, "the colliding ResourceExport should still be deleted")
}

// The Endpoints merge dereferences Spec.Endpoints for every matching export and
// assumes at most one export per member per tuple, but the webhook does not
// cover every writer (objects predating it, non-ServiceAccount users, and SAs
// outside the leader Namespace all bypass admission). getNotDeletedResourceExports
// must therefore drop nil-payload exports and dedupe by ClusterID so the merge
// loop is safe independently of the webhook.
func TestResourceExportReconciler_getNotDeletedResourceExportsSkipsNilAndDuplicateExports(t *testing.T) {
	epResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-default-nginx-endpoints",
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      constants.EndpointsKind,
		},
	}
	newEndpointsExport := func(clusterID, name string, endpoints *mcsv1alpha1.EndpointsExport) *mcsv1alpha1.ResourceExport {
		return &mcsv1alpha1.ResourceExport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:  "default",
				Name:       name,
				Finalizers: []string{constants.ResourceExportFinalizer},
				Labels:     epLabels,
			},
			Spec: mcsv1alpha1.ResourceExportSpec{
				Namespace: "default",
				Name:      "nginx",
				Kind:      constants.EndpointsKind,
				ClusterID: clusterID,
				Endpoints: endpoints,
			},
		}
	}
	tests := []struct {
		name    string
		exports []client.Object
		wantIDs []string
	}{
		{
			name:    "skips an Endpoints export with a nil payload",
			exports: []client.Object{newEndpointsExport("cluster-a", "cluster-a-default-nginx-endpoints", &mcsv1alpha1.EndpointsExport{Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"192.168.17.11"}}}}), newEndpointsExport("cluster-b", "cluster-b-default-nginx-endpoints", nil)},
			wantIDs: []string{"cluster-a"},
		},
		{
			name:    "dedupes duplicate exports from the same member",
			exports: []client.Object{newEndpointsExport("cluster-a", "cluster-a-default-nginx-endpoints", &mcsv1alpha1.EndpointsExport{Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"192.168.17.11"}}}}), newEndpointsExport("cluster-a", "cluster-a-default-nginx-endpoints-dup", &mcsv1alpha1.EndpointsExport{Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"192.168.17.11"}}}}), newEndpointsExport("cluster-b", "cluster-b-default-nginx-endpoints", &mcsv1alpha1.EndpointsExport{Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"192.168.17.11"}}}})},
			wantIDs: []string{"cluster-a", "cluster-b"},
		},
		{
			name:    "drops a nil-payload duplicate",
			exports: []client.Object{newEndpointsExport("cluster-a", "cluster-a-default-nginx-endpoints", &mcsv1alpha1.EndpointsExport{Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"192.168.17.11"}}}}), newEndpointsExport("cluster-a", "cluster-a-default-nginx-endpoints-dup", &mcsv1alpha1.EndpointsExport{Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"192.168.17.11"}}}}), newEndpointsExport("cluster-b", "cluster-b-default-nginx-endpoints", nil)},
			wantIDs: []string{"cluster-a"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(tc.exports...).Build()
			r := NewResourceExportReconciler(fakeClient, common.TestScheme)
			items, err := r.getNotDeletedResourceExports(epResExport)
			require.NoError(t, err, "getNotDeletedResourceExports should succeed")
			gotIDs := make([]string, 0, len(items))
			for _, item := range items {
				gotIDs = append(gotIDs, item.Spec.ClusterID)
			}
			assert.ElementsMatch(t, tc.wantIDs, gotIDs, "surviving exports should be deduped by ClusterID and exclude nil payloads")
		})
	}
}

// A nil-payload Service export can reach the reconciler when the writer
// bypasses admission (objects predating the webhook, non-ServiceAccount users,
// and ServiceAccounts outside the leader Namespace). refreshServiceResourceImport
// dereferences Spec.Service, so Reconcile must fail with a visible
// ResourceExportFailure instead of panicking.
func TestResourceExportReconciler_nilServicePayloadFailsReconcile(t *testing.T) {
	resExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "cluster-a-default-nginx-service",
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      constants.ServiceKind,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(resExport).
		WithStatusSubresource(resExport).Build()
	r := NewResourceExportReconciler(fakeClient, common.TestScheme)

	_, err := r.Reconcile(common.TestCtx, svcResReq)
	require.Error(t, err, "Reconcile should fail for a Service ResourceExport with a nil payload")

	updatedResExport := &mcsv1alpha1.ResourceExport{}
	err = fakeClient.Get(common.TestCtx, types.NamespacedName{Namespace: "default", Name: "cluster-a-default-nginx-service"}, updatedResExport)
	require.NoError(t, err, "failed to get ResourceExport")
	require.Len(t, updatedResExport.Status.Conditions, 1, "ResourceExport status should record the reconcile failure")
	assert.Equal(t, mcsv1alpha1.ResourceExportFailure, updatedResExport.Status.Conditions[0].Type)
	assert.Equal(t, corev1.ConditionFalse, updatedResExport.Status.Conditions[0].Status)
}

// Same as TestResourceExportReconciler_nilServicePayloadFailsReconcile, for
// Endpoints. The converged Service export is present so that, without the
// guard, Reconcile would reach the Spec.Endpoints dereference and panic
// instead of failing with a recorded status.
func TestResourceExportReconciler_nilEndpointsPayloadFailsReconcile(t *testing.T) {
	convergedSvcResExport := &mcsv1alpha1.ResourceExport{
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
					Ports: []corev1.ServicePort{common.SvcPort8080},
				},
			},
		},
		Status: mcsv1alpha1.ResourceExportStatus{
			Conditions: []mcsv1alpha1.ResourceExportCondition{
				{
					Type:   mcsv1alpha1.ResourceExportSucceeded,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}
	resExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "cluster-a-default-nginx-endpoints",
			Labels:     epLabels,
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      constants.EndpointsKind,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(resExport, convergedSvcResExport).
		WithStatusSubresource(resExport, convergedSvcResExport).Build()
	r := NewResourceExportReconciler(fakeClient, common.TestScheme)

	_, err := r.Reconcile(common.TestCtx, epResReq)
	require.Error(t, err, "Reconcile should fail for an Endpoints ResourceExport with a nil payload")

	updatedResExport := &mcsv1alpha1.ResourceExport{}
	err = fakeClient.Get(common.TestCtx, types.NamespacedName{Namespace: "default", Name: "cluster-a-default-nginx-endpoints"}, updatedResExport)
	require.NoError(t, err, "failed to get ResourceExport")
	require.Len(t, updatedResExport.Status.Conditions, 1, "ResourceExport status should record the reconcile failure")
	assert.Equal(t, mcsv1alpha1.ResourceExportFailure, updatedResExport.Status.Conditions[0].Type)
	assert.Equal(t, corev1.ConditionFalse, updatedResExport.Status.Conditions[0].Status)
}

// Two ACNP exports for the same tuple are a conflict: neither may be applied
// to the ResourceImport. ACNP exports are created by cluster admins and carry
// no ClusterID, so the dedupe by ClusterID must not collapse them - two
// distinct exports with empty ClusterIDs are not a duplicate member. exportA
// is reconciled second, and its name sorts first in the List used by the
// merge, so with a collapsing dedupe it would be the surviving export and
// would overwrite the import with its own policy.
func TestResourceExportReconciler_acnpConflictNotDedupedByClusterID(t *testing.T) {
	acnpLabels := map[string]string{
		constants.SourceNamespace: "",
		constants.SourceName:      "test-acnp",
		constants.SourceKind:      constants.AntreaClusterNetworkPolicyKind,
	}
	policyB := isolationACNPSpec.DeepCopy()
	policyB.Priority = 2.0
	exportA := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "acnp-export-a",
			Labels:     acnpLabels,
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Name:                 "test-acnp",
			Kind:                 constants.AntreaClusterNetworkPolicyKind,
			ClusterNetworkPolicy: policyB,
		},
	}
	exportB := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "acnp-export-b",
			Labels:     acnpLabels,
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Name:                 "test-acnp",
			Kind:                 constants.AntreaClusterNetworkPolicyKind,
			ClusterNetworkPolicy: isolationACNPSpec,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).
		WithObjects(exportA, exportB).WithStatusSubresource(exportA, exportB).Build()
	r := NewResourceExportReconciler(fakeClient, common.TestScheme)

	_, err := r.Reconcile(common.TestCtx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "acnp-export-b"}})
	require.NoError(t, err, "first reconcile should create the ResourceImport from export B")

	_, err = r.Reconcile(common.TestCtx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "acnp-export-a"}})
	require.NoError(t, err, "second reconcile should not fail on the conflicting export")

	resImport := &mcsv1alpha1.ResourceImport{}
	err = fakeClient.Get(common.TestCtx, GetResourceImportName(exportA), resImport)
	require.NoError(t, err, "failed to get ResourceImport")
	assert.True(t, reflect.DeepEqual(resImport.Spec.ClusterNetworkPolicy, isolationACNPSpec),
		"the conflicting export must not overwrite the ResourceImport's policy")
}

func TestResourceExportReconciler_mergeEndpointsImportDualWrite(t *testing.T) {
	// Export 1 uses new Endpoints/Ports format
	newExport := mcsv1alpha1.ResourceExport{
		Spec: mcsv1alpha1.ResourceExportSpec{
			Endpoints: &mcsv1alpha1.EndpointsExport{
				Endpoints: []discoveryv1.Endpoint{
					{
						Addresses:  []string{"10.0.1.1"},
						Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
					},
				},
				Ports: []discoveryv1.EndpointPort{
					{
						Name:     ptr.To("http"),
						Port:     ptr.To(int32(80)),
						Protocol: ptr.To(corev1.ProtocolTCP),
					},
				},
			},
		},
	}
	// Export 2 uses legacy Subsets format
	legacyExport := mcsv1alpha1.ResourceExport{
		Spec: mcsv1alpha1.ResourceExportSpec{
			Endpoints: &mcsv1alpha1.EndpointsExport{
				Subsets: []corev1.EndpointSubset{
					{
						Addresses: []corev1.EndpointAddress{
							{IP: "10.0.2.1"},
						},
						Ports: []corev1.EndpointPort{
							{
								Name:     "http",
								Port:     80,
								Protocol: corev1.ProtocolTCP,
							},
						},
					},
				},
			},
		},
	}

	merged, hasData := mergeEndpointsImport([]mcsv1alpha1.ResourceExport{newExport, legacyExport})
	require.True(t, hasData)
	require.NotNil(t, merged)

	// Endpoints should contain both
	assert.Len(t, merged.Endpoints, 2)
	assert.Equal(t, []string{"10.0.1.1"}, merged.Endpoints[0].Addresses)
	assert.Equal(t, []string{"10.0.2.1"}, merged.Endpoints[1].Addresses)

	// Ports should be populated
	assert.Len(t, merged.Ports, 1)
	assert.Equal(t, int32(80), *merged.Ports[0].Port)

	// Subsets must be populated for legacy consumers
	require.Len(t, merged.Subsets, 1)
	assert.Len(t, merged.Subsets[0].Addresses, 2)
	assert.ElementsMatch(t, []string{"10.0.1.1", "10.0.2.1"}, []string{merged.Subsets[0].Addresses[0].IP, merged.Subsets[0].Addresses[1].IP})
}

func TestResourceExportReconciler_emptyEndpointsDoesNotOverwriteResourceImport(t *testing.T) {
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
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existSvcResExport).Build()
	r := NewResourceExportReconciler(fakeClient, common.TestScheme)

	existingEndpoints := &mcsv1alpha1.EndpointsImport{
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"192.168.1.1"}},
		},
		Ports: []discoveryv1.EndpointPort{
			{Port: ptr.To(int32(80))},
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{{IP: "192.168.1.1"}},
				Ports:     []corev1.EndpointPort{{Port: 80, Protocol: corev1.ProtocolTCP}},
			},
		},
	}
	existResImport := &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-nginx-endpoints",
			Namespace: "default",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Name:      "nginx",
			Namespace: "default",
			Kind:      constants.EndpointsKind,
			Endpoints: existingEndpoints,
		},
	}

	// resExport has empty EndpointsExport
	resExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-a-default-nginx-endpoints",
			Namespace: "default",
			Labels:    epLabels,
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Name:      "nginx",
			Namespace: "default",
			Kind:      constants.EndpointsKind,
			Endpoints: &mcsv1alpha1.EndpointsExport{},
		},
	}

	newResImport, changed, err := r.refreshEndpointsResourceImport(resExport, existResImport, false)
	require.NoError(t, err)
	assert.False(t, changed, "must not indicate change when all exports have empty endpoint data")
	assert.Equal(t, existingEndpoints, newResImport.Spec.Endpoints, "must not overwrite existing ResourceImport with empty endpoints")
}

func TestResourceExportReconciler_endpointsImportFromExportLegacyFallback(t *testing.T) {
	legacyExport := &mcsv1alpha1.EndpointsExport{
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{
					{IP: "10.0.3.1"},
				},
				Ports: []corev1.EndpointPort{
					{
						Name:     "web",
						Port:     8080,
						Protocol: corev1.ProtocolTCP,
					},
				},
			},
		},
	}

	epImport, hasData := endpointsImportFromExport(legacyExport)
	require.True(t, hasData)
	require.NotNil(t, epImport)
	assert.Len(t, epImport.Endpoints, 1)
	assert.Equal(t, []string{"10.0.3.1"}, epImport.Endpoints[0].Addresses)
	assert.Len(t, epImport.Ports, 1)
	assert.Equal(t, int32(8080), *epImport.Ports[0].Port)
	assert.Len(t, epImport.Subsets, 1)
	assert.Equal(t, "10.0.3.1", epImport.Subsets[0].Addresses[0].IP)
}
