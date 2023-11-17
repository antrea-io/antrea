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

package member

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	k8smcsapi "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

var (
	localClusterID   = "cluster-a"
	leaderNamespace  = "default"
	svcResImportName = leaderNamespace + "-" + "nginx-service"
	epResImportName  = leaderNamespace + "-" + "nginx-endpoints"

	svcImportReq = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: leaderNamespace,
		Name:      svcResImportName,
	}}
	epImportReq = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: leaderNamespace,
		Name:      epResImportName,
	}}

	ctx = context.Background()

	svcResImport = &mcv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Name:      svcResImportName,
		},
		Spec: mcv1alpha1.ResourceImportSpec{
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
	epResImport = &mcv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Name:      epResImportName,
		},
		Spec: mcv1alpha1.ResourceImportSpec{
			Namespace: "default",
			Name:      "nginx",
			Kind:      "Endpoints",
			Endpoints: &mcv1alpha1.EndpointsImport{
				Subsets: epSubset,
			},
		},
	}
)

func TestResourceImportReconciler_handleCreateEvent(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(svcResImport, epResImport).Build()
	remoteCluster := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, "default", nil)

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

	r := newResourceImportReconciler(fakeClient, localClusterID, "default", remoteCluster)
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
			case "Endpoints":
				ep := &corev1.Endpoints{}
				if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "antrea-mc-nginx"}, ep); err != nil {
					t.Errorf("ResourceImport Reconciler should import an Endpoint successfully but got error = %v", err)
				}
			}

		})
	}
}

func TestResourceImportReconciler_handleDeleteEvent(t *testing.T) {
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

	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existSvc, existEp, existSvcImp).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).Build()
	remoteCluster := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, "default", nil)

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

	r := newResourceImportReconciler(fakeClient, localClusterID, "default", remoteCluster)
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
					if _, exists, _ := r.installedResImports.Get(*svcResImport); exists {
						t.Errorf("Reconciler should delete ResImport from installedResImports after successful resource deletion")
					}
				case "Endpoints":
					ep := &corev1.Endpoints{}
					if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "antrea-mc-nginx"}, ep); !apierrors.IsNotFound(err) {
						t.Errorf("ResourceImport Reconciler should delete an Endpoint successfully but got error = %v", err)
					}
					if _, exists, _ := r.installedResImports.Get(*epResImport); exists {
						t.Errorf("Reconciler should delete ResImport from installedResImports after successful resource deletion")
					}
				}
			}
		})
	}
}

func TestResourceImportReconciler_handleUpdateEvent(t *testing.T) {
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

	existSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     8080,
				},
			},
			ClusterIP:  "10.10.11.13",
			ClusterIPs: []string{"10.10.11.13"},
		},
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
	updatedEpResImport.Spec.Endpoints = &mcv1alpha1.EndpointsImport{
		Subsets: newSubsets,
	}
	svcResImportWithConflicts := svcResImport.DeepCopy()
	svcResImportWithConflicts.Name = "kube-system-nginx-service"
	svcResImportWithConflicts.Spec.Namespace = "kube-system"
	epResImportWithConflicts := epResImport.DeepCopy()
	epResImportWithConflicts.Name = "kube-system-nginx-endpoints"
	epResImportWithConflicts.Spec.Namespace = "kube-system"

	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existMCSvc, existMCEp, existSvcImp,
		existSvc, existMCSvcConflicts, existMCEpConflicts, svcWithoutAutoAnnotation, epWithoutAutoAnnotation).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(updatedEpResImport, updatedSvcResImport,
		svcResImportWithConflicts, epResImportWithConflicts).Build()
	remoteCluster := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, "default", nil)

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
			name:             "update Service",
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
			name:             "update Endpoints",
			objType:          "Endpoints",
			req:              epImportReq,
			resNamespaceName: types.NamespacedName{Namespace: "default", Name: "antrea-mc-nginx"},
			expectedSubset:   newSubsets,
		},
		{
			name:    "skip update a Service without mcs annotation",
			objType: "Service",
			req: ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: leaderNamespace,
				Name:      "kube-system-nginx-service",
			}},
			resNamespaceName: types.NamespacedName{Namespace: "kube-system", Name: "antrea-mc-nginx"},
			expectedErr:      true,
		},
		{
			name:    "skip update an Endpoint without mcs annotation",
			objType: "Endpoints",
			req: ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: leaderNamespace,
				Name:      "kube-system-nginx-endpoints",
			}},
			resNamespaceName: types.NamespacedName{Namespace: "kube-system", Name: "antrea-mc-nginx"},
			expectedErr:      true,
		},
	}

	r := newResourceImportReconciler(fakeClient, localClusterID, "default", remoteCluster)
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
						} else {
							if !reflect.DeepEqual(svcImp.Spec.Ports, newPorts) {
								t.Errorf("expected ServiceImport ports are %v but got %v", newPorts, svc.Spec.Ports)
							}
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

// fakeManager is a fake K8s controller manager which simulates a burst of ResourceImport events
// from the leader's apiServer and triggers the LabelIdentityResourceImportReconciler's main
// Reconcile loop. Once the fakeManager is run, all ResourceImports in the queue will be added
// into the fakeRemoteClient's cache, and all these events will be reconciled.
type fakeManager struct {
	remoteClient client.Client
	reconciler   *LabelIdentityResourceImportReconciler
	queue        workqueue.RateLimitingInterface
}

func (fm *fakeManager) Run(stopCh <-chan struct{}) {
	defer fm.queue.ShutDown()
	for i := 0; i < common.DefaultWorkerCount; i++ {
		go wait.Until(fm.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (fm *fakeManager) worker() {
	for fm.syncNextItemInQueue() {
	}
}

func (fm *fakeManager) syncNextItemInQueue() bool {
	resImpObj, quit := fm.queue.Get()
	if quit {
		return false
	}
	defer fm.queue.Done(resImpObj)
	resImp := resImpObj.(*mcv1alpha1.ResourceImport)
	err := fm.remoteClient.Create(ctx, resImp)
	if err != nil {
		fm.queue.AddRateLimited(resImp)
		return true
	}
	// Simulate ResourceImport create event and have LabelIdentityResourceImportReconciler reconcile it.
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: resImp.Namespace, Name: resImp.Name}}
	if _, err = fm.reconciler.Reconcile(ctx, req); err != nil {
		fm.queue.AddRateLimited(resImp)
		return true
	}
	fm.queue.Forget(resImp)
	return true
}

func TestStaleControllerNoRaceWithResourceImportReconciler(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(&mcv1alpha2.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test-cluster",
		},
	}).WithLists().Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists().Build()
	ca := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, "antrea-mcs", nil)

	mcReconciler := NewMemberClusterSetReconciler(fakeClient, common.TestScheme, "default", true, false, make(chan struct{}))
	mcReconciler.SetRemoteCommonArea(ca)
	c := NewStaleResCleanupController(fakeClient, common.TestScheme, make(chan struct{}), "default", mcReconciler)
	go func() {
		c.commonAreaCreationCh <- struct{}{}
	}()
	r := newLabelIdentityResourceImportReconciler(fakeClient, localClusterID, "default", ca)

	stopCh := make(chan struct{})
	defer close(stopCh)
	q := workqueue.NewRateLimitingQueue(workqueue.DefaultItemBasedRateLimiter())
	numInitialResImp := 50
	for i := 1; i <= numInitialResImp; i++ {
		resImp := &mcv1alpha1.ResourceImport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "label-identity-" + strconv.Itoa(i),
				Namespace: "antrea-mcs",
			},
			Spec: mcv1alpha1.ResourceImportSpec{
				LabelIdentity: &mcv1alpha1.LabelIdentitySpec{
					Label: "ns:kubernetes.io/metadata.name=ns&pod:seq=" + strconv.Itoa(i),
					ID:    uint32(i),
				},
			},
		}
		q.Add(resImp)
	}
	mgr := fakeManager{
		reconciler:   r,
		remoteClient: fakeRemoteClient,
		queue:        q,
	}
	// Give the fakeManager a head start. LabelIdentityResourceImportReconciler should be busy
	// reconciling all new ResourceImport events.
	go mgr.Run(stopCh)
	// The staleController should not erroneously delete any LabelIdentities while the reconciliation
	// of newly added ResourceImports are in-flight.
	go c.Run(stopCh)
	time.Sleep(1 * time.Second)
	actLabelIdentities := &mcv1alpha1.LabelIdentityList{}
	err := fakeClient.List(ctx, actLabelIdentities)
	assert.NoError(t, err)
	// Verify that no LabelIdentities are deleted as part of the cleanup.
	assert.Equal(t, numInitialResImp, len(actLabelIdentities.Items))
}
