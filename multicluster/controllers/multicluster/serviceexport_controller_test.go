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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

var (
	leaderNamespace string
	localClusterID  string
)

func TestServiceExportReconciler_handleDeleteEvent(t *testing.T) {
	localClusterID = "cluster-a"
	leaderNamespace = "default"
	remoteMgr := commonarea.NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()

	existSvcResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Name:      getResourceExportName(localClusterID, req, "service"),
		},
	}
	existEpResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Name:      getResourceExportName(localClusterID, req, "endpoints"),
		},
	}
	exportedSvcNginx := svcNginx.DeepCopy()

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(exportedSvcNginx).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existSvcResExport, existEpResExport).Build()

	_ = commonarea.NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")
	r := NewServiceExportReconciler(fakeClient, scheme, &remoteMgr)
	r.installedSvcs.Add(&svcInfo{
		name:      svcNginx.Name,
		namespace: svcNginx.Namespace,
	})
	r.installedEps.Add(&epInfo{
		name:      epNginx.Name,
		namespace: epNginx.Namespace,
	})
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Errorf("ServiceExport Reconciler should handle delete event successfully but got error = %v", err)
	} else {
		epResource := &mcsv1alpha1.ResourceExport{}
		err := fakeRemoteClient.Get(ctx, types.NamespacedName{
			Namespace: "default",
			Name:      "cluster-a-default-nginx-endpoints",
		}, epResource)
		if !apierrors.IsNotFound(err) {
			t.Errorf("expect not found error but got error = %v", err)
		}
		svcResource := &mcsv1alpha1.ResourceExport{}
		err = fakeRemoteClient.Get(ctx, types.NamespacedName{
			Namespace: "default",
			Name:      "cluster-a-default-nginx-service",
		}, svcResource)
		if !apierrors.IsNotFound(err) {
			t.Errorf("expect not found error but got error = %v", err)
		}
	}
}

func TestServiceExportReconciler_ExportNotFoundService(t *testing.T) {
	localClusterID = "cluster-a"
	leaderNamespace = "default"
	remoteMgr := commonarea.NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()

	existSvcExport := &k8smcsv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx",
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existSvcExport).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	_ = commonarea.NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")
	r := NewServiceExportReconciler(fakeClient, scheme, &remoteMgr)
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Errorf("ServiceExport Reconciler should update ServiceExport status to 'not_found_service' but got error = %v", err)
	} else {
		newSvcExport := &k8smcsv1alpha1.ServiceExport{}
		err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "nginx"}, newSvcExport)
		if err != nil {
			t.Errorf("ServiceExport Reconciler should get new ServiceExport successfully but got error = %v", err)
		} else {
			reason := newSvcExport.Status.Conditions[0].Reason
			if *reason != "not_found_service" {
				t.Errorf("latest ServiceExport status should be 'not_found_service' but got %v", reason)
			}
			checkAnnotation(t, newSvcExport)
		}
	}
}

func checkAnnotation(t *testing.T, svcExport *k8smcsv1alpha1.ServiceExport) {
	id, ok := svcExport.Annotations[common.AntreaMCClusterIDAnnotation]
	if id != localClusterID || !ok {
		t.Errorf("latest ServiceExport annotation should be %v but got %v", localClusterID, id)
	}
}

func TestServiceExportReconciler_ExportMCSService(t *testing.T) {
	localClusterID = "cluster-a"
	leaderNamespace = "default"
	remoteMgr := commonarea.NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()

	mcsSvc := svcNginx.DeepCopy()
	mcsSvc.Annotations = map[string]string{common.AntreaMCServiceAnnotation: "true"}
	existSvcExport := &k8smcsv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx",
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mcsSvc, existSvcExport).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	_ = commonarea.NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")
	r := NewServiceExportReconciler(fakeClient, scheme, &remoteMgr)
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Errorf("ServiceExport Reconciler should update ServiceExport status to 'imported_service' but got error = %v", err)
	} else {
		newSvcExport := &k8smcsv1alpha1.ServiceExport{}
		err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "nginx"}, newSvcExport)
		if err != nil {
			t.Errorf("ServiceExport Reconciler should get new ServiceExport successfully but got error = %v", err)
		} else {
			reason := newSvcExport.Status.Conditions[0].Reason
			if *reason != "imported_service" {
				t.Errorf("latest ServiceExport status should be 'imported_service' but got %v", reason)
			}
			checkAnnotation(t, newSvcExport)
		}
	}
}

func TestServiceExportReconciler_handleServiceExportCreateEvent(t *testing.T) {
	localClusterID = "cluster-a"
	leaderNamespace = "default"
	remoteMgr := commonarea.NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()

	existSvcExport := &k8smcsv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx",
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(svcNginx, epNginx, existSvcExport).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	_ = commonarea.NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")
	r := NewServiceExportReconciler(fakeClient, scheme, &remoteMgr)
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Errorf("ServiceExport Reconciler should create ResourceExports but got error = %v", err)
	} else {
		svcResExport := &mcsv1alpha1.ResourceExport{}
		err := fakeRemoteClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "cluster-a-default-nginx-service"}, svcResExport)
		if err != nil {
			t.Errorf("ServiceExport Reconciler should get new Service kind of ResourceExport successfully but got error = %v", err)
		}
		epResExport := &mcsv1alpha1.ResourceExport{}
		err = fakeRemoteClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "cluster-a-default-nginx-endpoints"}, epResExport)
		if err != nil {
			t.Errorf("ServiceExport Reconciler should get new Endpoints kind of ResourceExport successfully but got error = %v", err)
		}
		newSvcExport := &k8smcsv1alpha1.ServiceExport{}
		fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "nginx"}, newSvcExport)
		checkAnnotation(t, newSvcExport)
	}
}

func TestServiceExportReconciler_handleServiceUpdateEvent(t *testing.T) {
	localClusterID = "cluster-a"
	leaderNamespace = "default"
	remoteMgr := commonarea.NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()

	existSvcExport := &k8smcsv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx",
		},
	}

	sinfo := &svcInfo{
		name:       svcNginx.Name,
		namespace:  svcNginx.Namespace,
		clusterIPs: svcNginx.Spec.ClusterIPs,
		ports:      svcNginx.Spec.Ports,
		svcType:    string(svcNginx.Spec.Type),
	}
	epInfo := &epInfo{
		name:       epNginx.Name,
		namespace:  epNginx.Namespace,
		addressIPs: getEndPointsAddress(epNginx),
		ports:      getEndPointsPorts(epNginx),
		labels:     epNginx.Labels,
	}

	newSvcNginx := svcNginx.DeepCopy()
	newSvcNginx.Spec.Ports = []corev1.ServicePort{svcPort8080}
	newEpNginx := epNginx.DeepCopy()
	newEpNginx.Subsets[0].Ports = epPorts8080

	re := mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Labels: map[string]string{
				common.SourceName:      req.Name,
				common.SourceNamespace: req.Namespace,
				common.SourceClusterID: localClusterID,
			},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			ClusterID: localClusterID,
			Name:      req.Name,
			Namespace: req.Namespace,
		},
	}
	existSvcRe := re.DeepCopy()
	existSvcRe.Name = "cluster-a-default-nginx-service"
	existSvcRe.Spec.Service = &mcsv1alpha1.ServiceExport{ServiceSpec: corev1.ServiceSpec{}}
	existSvcRe.Spec.Service.ServiceSpec.Ports = []corev1.ServicePort{svcPort80}

	existEpRe := re.DeepCopy()
	existEpRe.Name = "cluster-a-default-nginx-endpoints"
	existEpRe.Spec.Endpoints = &mcsv1alpha1.EndpointsExport{Subsets: epNginxSubset}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(newSvcNginx, newEpNginx, existSvcExport).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existSvcRe, existEpRe).Build()

	_ = commonarea.NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")
	r := NewServiceExportReconciler(fakeClient, scheme, &remoteMgr)
	r.installedSvcs.Add(sinfo)
	r.installedEps.Add(epInfo)
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Errorf("ServiceExport Reconciler should update ResourceExports but got error = %v", err)
	} else {
		svcResExport := &mcsv1alpha1.ResourceExport{}
		err := fakeRemoteClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "cluster-a-default-nginx-service"}, svcResExport)
		if err != nil {
			t.Errorf("ServiceExport Reconciler should get new Service kind of ResourceExport successfully but got error = %v", err)
		} else {
			ports := svcResExport.Spec.Service.ServiceSpec.Ports
			expectedPorts := []corev1.ServicePort{
				{
					Name:     "tcp8080",
					Protocol: corev1.ProtocolTCP,
					Port:     8080,
				},
			}
			if !reflect.DeepEqual(ports, expectedPorts) {
				t.Errorf("expected Service ports are %v but got %v", expectedPorts, ports)
			}
		}
		epResExport := &mcsv1alpha1.ResourceExport{}
		err = fakeRemoteClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "cluster-a-default-nginx-endpoints"}, epResExport)
		if err != nil {
			t.Errorf("ServiceExport Reconciler should get new Endpoints kind of ResourceExport successfully but got error = %v", err)
		} else {
			subsets := epResExport.Spec.Endpoints.Subsets
			expectedSubsets := []corev1.EndpointSubset{
				{
					Addresses: []corev1.EndpointAddress{
						{
							IP: "192.168.17.11",
						},
					},
					Ports: epPorts8080,
				},
			}
			if !reflect.DeepEqual(subsets, expectedSubsets) {
				t.Errorf("expected Endpoints subsets are %v but got %v", expectedSubsets, subsets)
			}
		}
		newSvcExport := &k8smcsv1alpha1.ServiceExport{}
		fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "nginx"}, newSvcExport)
		checkAnnotation(t, newSvcExport)
	}
}

func Test_objMapFunc(t *testing.T) {
	tests := []struct {
		name string
		obj  client.Object
		want []reconcile.Request
	}{
		{
			name: "map Service Object event",
			obj: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "default",
				},
			},
			want: []reconcile.Request{
				{
					NamespacedName: types.NamespacedName{
						Name:      "nginx",
						Namespace: "default",
					},
				},
			},
		},
		{
			name: "map Endpoints Object event",
			obj: &corev1.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "default",
				},
			},
			want: []reconcile.Request{
				{
					NamespacedName: types.NamespacedName{
						Name:      "nginx",
						Namespace: "default",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := objMapFunc(tt.obj); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Test_objMapFunc() = %v, want %v", got, tt.want)
			}
		})
	}
}
