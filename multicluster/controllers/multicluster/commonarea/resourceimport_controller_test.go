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

package commonarea

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	k8smcsapi "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

var (
	localClusterID    = "cluster-a"
	leaderNamespace   = "default"
	svcResImportName  = leaderNamespace + "-" + "nginx-service"
	epResImportName   = leaderNamespace + "-" + "nginx-endpoints"
	acnpImportName    = "acnp-for-isolation"
	acnpResImportName = leaderNamespace + "-" + acnpImportName

	svcImportReq = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: leaderNamespace,
		Name:      svcResImportName,
	}}
	epImportReq = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: leaderNamespace,
		Name:      epResImportName,
	}}
	acnpImpReq = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: leaderNamespace,
		Name:      acnpResImportName,
	}}
	acnpImpNoMatchingTierReq = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: leaderNamespace,
		Name:      "default-acnp-no-matching-tier",
	}}

	ctx    = context.Background()
	scheme = runtime.NewScheme()

	svcResImport = &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Name:      svcResImportName,
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      "ServiceImport",
			ServiceImport: &k8smcsapi.ServiceImport{
				Spec: k8smcsapi.ServiceImportSpec{
					Ports: []k8smcsapi.ServicePort{
						{
							Name:     "http",
							Protocol: corev1.ProtocolTCP,
							Port:     80,
						},
					},
				},
			},
		},
	}
	epSubset = []corev1.EndpointSubset{
		{
			Addresses: []corev1.EndpointAddress{
				{
					IP: "192.168.17.11",
				},
			},
			Ports: []corev1.EndpointPort{
				{
					Name:     "http",
					Port:     80,
					Protocol: corev1.ProtocolTCP,
				},
			},
		},
	}
	epResImport = &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Name:      epResImportName,
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      "Endpoints",
			Endpoints: &mcsv1alpha1.EndpointsImport{
				Subsets: epSubset,
			},
		},
	}
	allowAction     = v1alpha1.RuleActionAllow
	dropAction      = v1alpha1.RuleActionDrop
	securityOpsTier = &v1alpha1.Tier{
		ObjectMeta: metav1.ObjectMeta{
			Name: "securityops",
		},
		Spec: v1alpha1.TierSpec{
			Priority:    int32(100),
			Description: "[READ-ONLY]: System generated SecurityOps Tier",
		},
	}
	acnpResImport = &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Name:      acnpResImportName,
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Name: acnpImportName,
			Kind: common.AntreaClusterNetworkPolicyKind,
			ClusterNetworkPolicy: &v1alpha1.ClusterNetworkPolicySpec{
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
			},
		},
	}
	acnpResImportNoMatchingTier = &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Name:      "default-acnp-no-matching-tier",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Name: "acnp-no-matching-tier",
			Kind: common.AntreaClusterNetworkPolicyKind,
			ClusterNetworkPolicy: &v1alpha1.ClusterNetworkPolicySpec{
				Tier:     "somerandomtier",
				Priority: 1.0,
				AppliedTo: []v1alpha1.NetworkPolicyPeer{
					{NamespaceSelector: &metav1.LabelSelector{}},
				},
			},
		},
	}
)

func init() {
	utilruntime.Must(mcsv1alpha1.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	utilruntime.Must(k8smcsapi.AddToScheme(scheme))
	utilruntime.Must(k8sscheme.AddToScheme(scheme))
}

func TestResourceImportReconciler_handleCreateEvent(t *testing.T) {
	remoteMgr := NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(svcResImport, epResImport).Build()
	remoteCluster := NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")

	tests := []struct {
		name    string
		objType string
		req     ctrl.Request
	}{
		{
			name:    "import Service",
			objType: "Service",
			req:     svcImportReq,
		},
		{
			name:    "import Endpoints",
			objType: "Endpoints",
			req:     epImportReq,
		},
	}

	r := NewResourceImportReconciler(fakeClient, scheme, fakeClient, localClusterID, remoteCluster)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := r.Reconcile(ctx, tt.req); err != nil {
				if !assert.Contains(t, err.Error(), "ClusterSetIP is empty") {
					t.Errorf("ResourceImport Reconciler should handle create event successfully but got error = %v", err)
				}
			}
			switch tt.objType {
			case "Service":
				svc := &corev1.Service{}
				if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "antrea-mc-nginx"}, svc); err != nil {
					t.Errorf("ResourceImport Reconciler should import a Service successfully but got error = %v", err)
				}
				svcImp := &k8smcsapi.ServiceImport{}
				if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "nginx"}, svcImp); err != nil {
					t.Errorf("ResourceImport Reconciler should create a ServiceImport successfully but got error = %v", err)
				}
				checkAnnotation(t, svcImp)
			case "Endpoints":
				ep := &corev1.Endpoints{}
				if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "antrea-mc-nginx"}, ep); err != nil {
					t.Errorf("ResourceImport Reconciler should import an Endpoint successfully but got error = %v", err)
				}
			}

		})
	}
}

func TestResourceImportReconciler_handleCopySpanACNPCreateEvent(t *testing.T) {
	remoteMgr := NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()
	defer remoteMgr.Stop()

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(securityOpsTier).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(acnpResImport, acnpResImportNoMatchingTier).Build()
	remoteCluster := NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")

	tests := []struct {
		name            string
		acnpImportName  string
		req             ctrl.Request
		expectedSuccess bool
	}{
		{
			name:            "import ACNP of pre-defined tiers",
			acnpImportName:  acnpImportName,
			req:             acnpImpReq,
			expectedSuccess: true,
		},
		{
			name:            "import ACNP of non-existing tier",
			acnpImportName:  "acnp-no-matching-tier",
			req:             acnpImpNoMatchingTierReq,
			expectedSuccess: false,
		},
	}
	r := NewResourceImportReconciler(fakeClient, scheme, fakeClient, localClusterID, remoteCluster)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := r.Reconcile(ctx, tt.req); err != nil {
				if err != nil {
					t.Errorf("ResourceImport Reconciler should handle ACNP create event successfully but got error = %v", err)
				}
			} else {
				acnp := &v1alpha1.ClusterNetworkPolicy{}
				err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "", Name: common.AntreaMCSPrefix + tt.acnpImportName}, acnp)
				if tt.expectedSuccess && err != nil {
					t.Errorf("ResourceImport Reconciler should import an ACNP successfully but got error = %v", err)
				} else if !tt.expectedSuccess && (err == nil || !apierrors.IsNotFound(err)) {
					t.Errorf("ResourceImport Reconciler should not import an ACNP whose Tier does not exist in current cluster. Expected NotFound error. Actual err = %v", err)
				}
				acnpImport := &mcsv1alpha1.ACNPImport{}
				if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "", Name: tt.acnpImportName}, acnpImport); err != nil {
					t.Errorf("ResourceImport Reconciler should create ACNPImport for ACNP type resouc")
				}
				status := acnpImport.Status.Conditions
				if len(status) > 0 && status[0].Type == mcsv1alpha1.ACNPImportRealizable {
					if tt.expectedSuccess && status[0].Status != corev1.ConditionTrue {
						t.Errorf("ACNPImport %v realizable status should be True but is %v instead", acnpImportName, status[0].Status)
					} else if !tt.expectedSuccess && status[0].Status != corev1.ConditionFalse {
						t.Errorf("ACNPImport %v realizable status should be False but is %v instead", acnpImportName, status[0].Status)
					}
				} else {
					t.Errorf("No realizable status provided for ACNPImport %v", acnpImportName)
				}
			}
		})
	}
}

func TestResourceImportReconciler_handleDeleteEvent(t *testing.T) {
	remoteMgr := NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()

	existSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "antrea-mc-nginx",
		},
	}
	existSvcImp := &k8smcsapi.ServiceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx",
		},
	}
	existEp := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "antrea-mc-nginx",
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existSvc, existEp, existSvcImp).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	remoteCluster := NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")

	tests := []struct {
		name    string
		objType string
		req     ctrl.Request
	}{
		{
			name:    "delete Service",
			objType: "Service",
			req:     svcImportReq,
		},
		{
			name:    "delete Endpoints",
			objType: "Endpoints",
			req:     epImportReq,
		},
	}

	r := NewResourceImportReconciler(fakeClient, scheme, fakeClient, localClusterID, remoteCluster)
	r.installedResImports.Add(*svcResImport)
	r.installedResImports.Add(*epResImport)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := r.Reconcile(ctx, tt.req); err != nil {
				t.Errorf("ResourceImport Reconciler should handle delete event successfully but got error = %v", err)
			} else {
				switch tt.objType {
				case "Service":
					svc := &corev1.Service{}
					if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "antrea-mc-nginx"}, svc); !apierrors.IsNotFound(err) {
						t.Errorf("ResourceImport Reconciler should delete a Service successfully but got error = %v", err)
					}
					svcImp := &k8smcsapi.ServiceImport{}
					if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "nginx"}, svcImp); !apierrors.IsNotFound(err) {
						t.Errorf("ResourceImport Reconciler should delete a ServiceImport successfully but got error = %v", err)
					}
				case "Endpoints":
					ep := &corev1.Endpoints{}
					if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "antrea-mc-nginx"}, ep); !apierrors.IsNotFound(err) {
						t.Errorf("ResourceImport Reconciler should delete an Endpoint successfully but got error = %v", err)
					}
				}
			}
		})
	}
}

func TestResourceImportReconciler_handleCopySpanACNPDeleteEvent(t *testing.T) {
	remoteMgr := NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()
	defer remoteMgr.Stop()

	existingACNP := &v1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: common.AntreaMCSPrefix + acnpImportName,
		},
	}
	existingACNPImport := &mcsv1alpha1.ACNPImport{
		ObjectMeta: metav1.ObjectMeta{
			Name: acnpImportName,
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingACNP, existingACNPImport).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	remoteCluster := NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")

	r := NewResourceImportReconciler(fakeClient, scheme, fakeClient, localClusterID, remoteCluster)
	r.installedResImports.Add(*acnpResImport)

	if _, err := r.Reconcile(ctx, acnpImpReq); err != nil {
		t.Errorf("ResourceImport Reconciler should handle ACNP ResourceImport delete event successfully but got error = %v", err)
	}
	acnp := &v1alpha1.ClusterNetworkPolicy{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "", Name: common.AntreaMCSPrefix + acnpImportName}, acnp); !apierrors.IsNotFound(err) {
		t.Errorf("ResourceImport Reconciler should delete ACNP successfully but got error = %v", err)
	}
	acnpImport := &mcsv1alpha1.ACNPImport{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "", Name: acnpImportName}, acnpImport); !apierrors.IsNotFound(err) {
		t.Errorf("ResourceImport Reconciler should delete ACNPImport successfully but got error = %v", err)
	}
}

func TestResourceImportReconciler_handleUpdateEvent(t *testing.T) {
	remoteMgr := NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()

	nginxPorts := []corev1.ServicePort{
		{
			Protocol: corev1.ProtocolTCP,
			Port:     80,
		},
	}
	existMCSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "default",
			Name:        "antrea-mc-nginx",
			Annotations: map[string]string{common.AntreaMCServiceAnnotation: "true"},
		},
		Spec: corev1.ServiceSpec{
			Ports:     nginxPorts,
			ClusterIP: "192.168.1.1",
		},
	}
	existMCSvcConflicts := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      "antrea-mc-nginx",
		},
		Spec: corev1.ServiceSpec{
			Ports: nginxPorts,
		},
	}
	existSvcImp := &k8smcsapi.ServiceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "default",
			Name:        "nginx",
			Annotations: map[string]string{common.AntreaMCServiceAnnotation: "true"},
		},
		Spec: k8smcsapi.ServiceImportSpec{
			Ports: []k8smcsapi.ServicePort{
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     8080,
				},
			},
		},
	}
	existMCEp := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "default",
			Name:        "antrea-mc-nginx",
			Annotations: map[string]string{common.AntreaMCServiceAnnotation: "true"},
		},
		Subsets: epSubset,
	}
	existMCEpConflicts := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      "antrea-mc-nginx",
		},
		Subsets: epSubset,
	}

	subSetA := corev1.EndpointSubset{
		Addresses: []corev1.EndpointAddress{
			{
				IP: "192.168.17.12",
			},
		},
		Ports: []corev1.EndpointPort{
			{
				Name:     "http",
				Port:     8080,
				Protocol: corev1.ProtocolTCP,
			},
		},
	}
	subSetB := corev1.EndpointSubset{
		Addresses: []corev1.EndpointAddress{
			{
				IP: "10.10.11.13",
			},
		},
		Ports: []corev1.EndpointPort{
			{
				Name:     "http",
				Port:     8080,
				Protocol: corev1.ProtocolTCP,
			},
		},
	}
	newSubsets := []corev1.EndpointSubset{subSetA, subSetB}

	existEp := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx",
		},
		Subsets: []corev1.EndpointSubset{subSetB},
	}

	svcWithoutAutoAnnotation := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      "nginx",
		},
		Spec: corev1.ServiceSpec{
			Ports: nginxPorts,
		},
	}

	epWithoutAutoAnnotation := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      "nginx",
		},
		Subsets: epSubset,
	}
	newPorts := []k8smcsapi.ServicePort{
		{
			Name:     "http",
			Protocol: corev1.ProtocolTCP,
			Port:     8080,
		},
	}
	updatedSvcResImport := svcResImport.DeepCopy()
	updatedSvcResImport.Spec.ServiceImport = &k8smcsapi.ServiceImport{
		Spec: k8smcsapi.ServiceImportSpec{
			Ports: newPorts,
		},
	}
	updatedEpResImport := epResImport.DeepCopy()
	updatedEpResImport.Spec.Endpoints = &mcsv1alpha1.EndpointsImport{
		Subsets: newSubsets,
	}
	svcResImportWithConflicts := svcResImport.DeepCopy()
	svcResImportWithConflicts.Name = "kube-system-nginx-service"
	svcResImportWithConflicts.Spec.Namespace = "kube-system"
	epResImportWithConflicts := epResImport.DeepCopy()
	epResImportWithConflicts.Name = "kube-system-nginx-endpoints"
	epResImportWithConflicts.Spec.Namespace = "kube-system"

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existMCSvc, existMCEp, existSvcImp,
		existEp, existMCSvcConflicts, existMCEpConflicts, svcWithoutAutoAnnotation, epWithoutAutoAnnotation).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(updatedEpResImport, updatedSvcResImport,
		svcResImportWithConflicts, epResImportWithConflicts).Build()
	remoteCluster := NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")

	tests := []struct {
		name             string
		objType          string
		req              ctrl.Request
		resNamespaceName types.NamespacedName
		expectedSvcPorts []corev1.ServicePort
		expectedSubset   []corev1.EndpointSubset
		expectedErr      bool
	}{
		{
			name:             "update service",
			objType:          "Service",
			req:              svcImportReq,
			resNamespaceName: types.NamespacedName{Namespace: "default", Name: "antrea-mc-nginx"},
			expectedSvcPorts: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     8080,
				},
			},
		},
		{
			name:             "update endpoints",
			objType:          "Endpoints",
			req:              epImportReq,
			resNamespaceName: types.NamespacedName{Namespace: "default", Name: "antrea-mc-nginx"},
			expectedSubset:   []corev1.EndpointSubset{subSetA},
		},
		{
			name:    "skip update a service without mcs annotation",
			objType: "Service",
			req: ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: leaderNamespace,
				Name:      "kube-system-nginx-service",
			}},
			resNamespaceName: types.NamespacedName{Namespace: "kube-system", Name: "antrea-mc-nginx"},
			expectedErr:      true,
		},
		{
			name:    "skip update an endpoint without mcs annotation",
			objType: "Endpoints",
			req: ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: leaderNamespace,
				Name:      "kube-system-nginx-endpoints",
			}},
			resNamespaceName: types.NamespacedName{Namespace: "kube-system", Name: "antrea-mc-nginx"},
			expectedErr:      true,
		},
	}

	r := NewResourceImportReconciler(fakeClient, scheme, fakeClient, localClusterID, remoteCluster)
	r.installedResImports.Add(*svcResImport)
	r.installedResImports.Add(*epResImport)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := r.Reconcile(ctx, tt.req); err != nil {
				if tt.expectedErr {
					assert.Contains(t, err.Error(), "conflicts with existing one")
				} else {
					t.Errorf("ResourceImport Reconciler should handle update event successfully but got error = %v", err)
				}
			} else {
				switch tt.objType {
				case "Service":
					svc := &corev1.Service{}
					if err := fakeClient.Get(ctx, tt.resNamespaceName, svc); err != nil {
						t.Errorf("ResourceImport Reconciler should update a Service successfully but got error = %v", err)
					} else {
						if !reflect.DeepEqual(svc.Spec.Ports, tt.expectedSvcPorts) {
							t.Errorf("expected Service ports are %v but got %v", tt.expectedSvcPorts, svc.Spec.Ports)
						}
					}
					if strings.HasPrefix(tt.resNamespaceName.Name, common.AntreaMCSPrefix) {
						svcImp := &k8smcsapi.ServiceImport{}
						if err := fakeClient.Get(ctx, types.NamespacedName{
							Namespace: tt.resNamespaceName.Namespace,
							Name:      strings.TrimPrefix(tt.resNamespaceName.Name, common.AntreaMCSPrefix)}, svcImp); err != nil {
							t.Errorf("ResourceImport Reconciler should update a ServiceImport successfully but got error = %v", err)
							checkAnnotation(t, svcImp)
						} else {
							if !reflect.DeepEqual(svcImp.Spec.Ports, newPorts) {
								t.Errorf("expected ServiceImport ports are %v but got %v", newPorts, svc.Spec.Ports)
							}
							checkAnnotation(t, svcImp)
						}
					}
				case "Endpoints":
					ep := &corev1.Endpoints{}
					if err := fakeClient.Get(ctx, tt.resNamespaceName, ep); err != nil {
						t.Errorf("ResourceImport Reconciler should update an Endpoint successfully but got error = %v", err)
					} else {
						if !reflect.DeepEqual(ep.Subsets, tt.expectedSubset) {
							t.Errorf("expected Subsets are %v but got %v", tt.expectedSubset, ep.Subsets)
						}
					}
				}
			}
		})
	}
}

func TestResourceImportReconciler_handleCopySpanACNPUpdateEvent(t *testing.T) {
	remoteMgr := NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()
	defer remoteMgr.Stop()

	existingACNP1 := &v1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        common.AntreaMCSPrefix + acnpImportName,
			Annotations: map[string]string{common.AntreaMCACNPAnnotation: "true"},
		},
		Spec: v1alpha1.ClusterNetworkPolicySpec{
			Tier:     "securityops",
			Priority: 1.0,
			AppliedTo: []v1alpha1.NetworkPolicyPeer{
				{NamespaceSelector: &metav1.LabelSelector{}},
			},
			Ingress: []v1alpha1.Rule{
				{
					Action: &allowAction,
					From: []v1alpha1.NetworkPolicyPeer{
						{
							Namespaces: &v1alpha1.PeerNamespaces{
								Match: v1alpha1.NamespaceMatchSelf,
							},
						},
					},
				},
			},
		},
	}
	existingACNPImport1 := &mcsv1alpha1.ACNPImport{
		ObjectMeta: metav1.ObjectMeta{
			Name: acnpImportName,
		},
		Status: mcsv1alpha1.ACNPImportStatus{
			Conditions: []mcsv1alpha1.ACNPImportCondition{
				{
					Type:   mcsv1alpha1.ACNPImportRealizable,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}
	existingACNPImport2 := &mcsv1alpha1.ACNPImport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "acnp-no-matching-tier",
		},
		Status: mcsv1alpha1.ACNPImportStatus{
			Conditions: []mcsv1alpha1.ACNPImportCondition{
				{
					Type:   mcsv1alpha1.ACNPImportRealizable,
					Status: corev1.ConditionFalse,
				},
			},
		},
	}
	updatedResImport2 := &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Name:      "default-acnp-no-matching-tier",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Name: "acnp-no-matching-tier",
			Kind: common.AntreaClusterNetworkPolicyKind,
			ClusterNetworkPolicy: &v1alpha1.ClusterNetworkPolicySpec{
				Tier:     "securityops",
				Priority: 1.0,
				AppliedTo: []v1alpha1.NetworkPolicyPeer{
					{NamespaceSelector: &metav1.LabelSelector{}},
				},
			},
		},
	}
	existingACNP3 := &v1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        common.AntreaMCSPrefix + "valid-updated-to-no-valid",
			Annotations: map[string]string{common.AntreaMCACNPAnnotation: "true"},
		},
		Spec: v1alpha1.ClusterNetworkPolicySpec{
			Tier:     "securityops",
			Priority: 1.0,
			AppliedTo: []v1alpha1.NetworkPolicyPeer{
				{NamespaceSelector: &metav1.LabelSelector{}},
			},
		},
	}
	existingACNPImport3 := &mcsv1alpha1.ACNPImport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "valid-updated-to-no-valid",
		},
		Status: mcsv1alpha1.ACNPImportStatus{
			Conditions: []mcsv1alpha1.ACNPImportCondition{
				{
					Type:   mcsv1alpha1.ACNPImportRealizable,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}
	updatedResImport3 := &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Name:      "default-valid-updated-to-no-valid",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Name: acnpImportName,
			Kind: common.AntreaClusterNetworkPolicyKind,
			ClusterNetworkPolicy: &v1alpha1.ClusterNetworkPolicySpec{
				Tier:     "somerandomtier",
				Priority: 1.0,
				AppliedTo: []v1alpha1.NetworkPolicyPeer{
					{NamespaceSelector: &metav1.LabelSelector{}},
				},
			},
		},
	}
	acnpImp3Req := ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: leaderNamespace,
		Name:      "default-valid-updated-to-no-valid",
	}}
	acnpImp4Req := ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: leaderNamespace,
		Name:      "default-name-conflict",
	}}
	existingACNP4 := &v1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: common.AntreaMCSPrefix + "name-conflict",
		},
		Spec: v1alpha1.ClusterNetworkPolicySpec{
			Tier:     "securityops",
			Priority: 1.0,
			AppliedTo: []v1alpha1.NetworkPolicyPeer{
				{NamespaceSelector: &metav1.LabelSelector{}},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingACNP1, existingACNPImport1, existingACNPImport2,
		existingACNP3, existingACNPImport3, existingACNP4, securityOpsTier).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(acnpResImport, updatedResImport2, updatedResImport3).Build()
	remoteCluster := NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")

	r := NewResourceImportReconciler(fakeClient, scheme, fakeClient, localClusterID, remoteCluster)
	r.installedResImports.Add(*acnpResImport)
	r.installedResImports.Add(*acnpResImportNoMatchingTier)
	r.installedResImports.Add(*updatedResImport3)

	tests := []struct {
		name                    string
		acnpImportName          string
		req                     ctrl.Request
		expectErr               bool
		expectImportSuccess     bool
		expectedUpdatedACNPSpec *v1alpha1.ClusterNetworkPolicySpec
	}{
		{
			name:                    "update acnp spec",
			acnpImportName:          acnpImportName,
			req:                     acnpImpReq,
			expectErr:               false,
			expectImportSuccess:     true,
			expectedUpdatedACNPSpec: acnpResImport.Spec.ClusterNetworkPolicy,
		},
		{
			name:                    "imported acnp missing tier update to valid tier",
			acnpImportName:          "acnp-no-matching-tier",
			req:                     acnpImpNoMatchingTierReq,
			expectErr:               false,
			expectImportSuccess:     true,
			expectedUpdatedACNPSpec: updatedResImport2.Spec.ClusterNetworkPolicy,
		},
		{
			name:                    "valid imported acnp update to missing tier",
			req:                     acnpImp3Req,
			acnpImportName:          "valid-updated-to-no-valid",
			expectErr:               false,
			expectImportSuccess:     false,
			expectedUpdatedACNPSpec: nil,
		},
		{
			name:                    "name conflict with existing acnp",
			req:                     acnpImp4Req,
			acnpImportName:          "name-conflict",
			expectErr:               true,
			expectImportSuccess:     false,
			expectedUpdatedACNPSpec: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := r.Reconcile(ctx, tt.req); err != nil {
				if tt.expectErr {
					assert.Contains(t, err.Error(), "conflicts with existing one")
				} else {
					t.Errorf("ResourceImport Reconciler should handle update event successfully but got error = %v", err)
				}
			} else {
				if tt.expectedUpdatedACNPSpec != nil {
					acnp := &v1alpha1.ClusterNetworkPolicy{}
					err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "", Name: common.AntreaMCSPrefix + tt.acnpImportName}, acnp)
					if tt.expectImportSuccess && err != nil {
						t.Errorf("ResourceImport Reconciler should import an ACNP successfully but got error = %v", err)
					} else if !tt.expectImportSuccess && (err == nil || !apierrors.IsNotFound(err)) {
						t.Errorf("ResourceImport Reconciler should not import an ACNP whose Tier does not exist in current cluster. Expected NotFound error. Actual err = %v", err)
					} else if !reflect.DeepEqual(acnp.Spec, *tt.expectedUpdatedACNPSpec) {
						t.Errorf("ACNP spec was not updated successfully")
					}
				}
			}
		})
	}
}

func checkAnnotation(t *testing.T, svcImport *k8smcsapi.ServiceImport) {
	id, ok := svcImport.Annotations[common.AntreaMCClusterIDAnnotation]
	if id != localClusterID || !ok {
		t.Errorf("latest ServiceImport annotation should be %v but got %v", localClusterID, id)
	}
}
