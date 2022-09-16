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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

var (
	nginxReq = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: "default",
		Name:      "nginx",
	}}

	existSvcExport = &k8smcsv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx",
		},
	}
)

func TestServiceExportReconciler_handleDeleteEvent(t *testing.T) {
	existSvcResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Name:      getResourceExportName(localClusterID, nginxReq, "service"),
		},
	}
	existEpResExport := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Name:      getResourceExportName(localClusterID, nginxReq, "endpoints"),
		},
	}
	exportedSvcNginx := svcNginx.DeepCopy()

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(exportedSvcNginx).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existSvcResExport, existEpResExport).Build()

	commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, "default")
	mcReconciler := NewMemberClusterSetReconciler(fakeClient, scheme, "default")
	mcReconciler.SetRemoteCommonArea(commonArea)
	r := NewServiceExportReconciler(fakeClient, scheme, mcReconciler, "ClusterIP")
	r.installedSvcs.Add(&svcInfo{
		name:      svcNginx.Name,
		namespace: svcNginx.Namespace,
	})
	if _, err := r.Reconcile(ctx, nginxReq); err != nil {
		t.Errorf("ServiceExport Reconciler should handle delete event successfully but got error = %v", err)
	} else {
		epResource := &mcsv1alpha1.ResourceExport{}
		err := fakeRemoteClient.Get(ctx, types.NamespacedName{
			Namespace: "default",
			Name:      "cluster-a-default-nginx-endpoints",
		}, epResource)
		if !apierrors.IsNotFound(err) {
			t.Errorf("Expected not found error but got error = %v", err)
		}
		svcResource := &mcsv1alpha1.ResourceExport{}
		err = fakeRemoteClient.Get(ctx, types.NamespacedName{
			Namespace: "default",
			Name:      "cluster-a-default-nginx-service",
		}, svcResource)
		if !apierrors.IsNotFound(err) {
			t.Errorf("Expected not found error but got error = %v", err)
		}
	}
}

func TestServiceExportReconciler_CheckExportStatus(t *testing.T) {
	mcsSvc := svcNginx.DeepCopy()
	mcsSvc.Name = "antrea-mc-nginx"
	mcsSvc.Annotations = map[string]string{common.AntreaMCServiceAnnotation: "true"}
	mcsSvcExport := &k8smcsv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "antrea-mc-nginx",
		},
	}

	nginx0Svc := svcNginx.DeepCopy()
	nginx0Svc.Name = "nginx0"
	nginx0SvcExport := &k8smcsv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx0",
		},
	}

	nginx1Svc := svcNginx.DeepCopy()
	nginx1Svc.Name = "nginx1"
	now := metav1.Now()
	reason := "service_without_endpoints"
	message := "the Service has no Endpoints, failed to export"
	nginx1SvcExportWithStatus := &k8smcsv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx1",
		},
		Status: k8smcsv1alpha1.ServiceExportStatus{
			Conditions: []k8smcsv1alpha1.ServiceExportCondition{
				{
					Type:               k8smcsv1alpha1.ServiceExportValid,
					Status:             corev1.ConditionFalse,
					LastTransitionTime: &now,
					Reason:             &reason,
					Message:            &message,
				},
			},
		},
	}

	nginx1EP := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx1",
		},
		Subsets: epNginxSubset,
	}

	nginx2Svc := svcNginx.DeepCopy()
	nginx2Svc.Name = "nginx2"
	nginx2SvcExportWithStatus := nginx1SvcExportWithStatus.DeepCopy()
	nginx2SvcExportWithStatus.Name = "nginx2"
	existingMessage := "the Service has no related Endpoints"
	nginx2SvcExportWithStatus.Status.Conditions[0].Message = &existingMessage
	tests := []struct {
		name            string
		expectedReason  string
		expectedMessage string
		req             ctrl.Request
	}{
		{
			name:           "export non-existing Service",
			expectedReason: "service_not_found",
			req:            nginxReq,
		},
		{
			name:           "export multi-cluster Service",
			expectedReason: "imported_service",
			req: ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "antrea-mc-nginx",
			}},
		},
		{
			name:           "export Service without Endpoints",
			expectedReason: "service_without_endpoints",
			req: ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "nginx0",
			}},
		},
		{
			name:           "export Service and update status successfully",
			expectedReason: "export_succeeded",
			req: ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "nginx1",
			}},
		},
		{
			name:            "skip update status",
			expectedReason:  "service_without_endpoints",
			expectedMessage: "the Service has no related Endpoints",
			req: ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "nginx2",
			}},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mcsSvc, nginx0Svc, nginx1Svc, nginx1EP, nginx2Svc, existSvcExport,
		nginx0SvcExport, nginx1SvcExportWithStatus, nginx2SvcExportWithStatus, mcsSvcExport).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, "default")

	mcReconciler := NewMemberClusterSetReconciler(fakeClient, scheme, "default")
	mcReconciler.SetRemoteCommonArea(commonArea)
	r := NewServiceExportReconciler(fakeClient, scheme, mcReconciler, "ClusterIP")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := r.Reconcile(ctx, tt.req); err != nil {
				t.Errorf("ServiceExport Reconciler should update ServiceExport status successfully but got error = %v", err)
			} else {
				newSvcExport := &k8smcsv1alpha1.ServiceExport{}
				err := fakeClient.Get(ctx, types.NamespacedName{Namespace: tt.req.Namespace, Name: tt.req.Name}, newSvcExport)
				if err != nil {
					t.Errorf("ServiceExport Reconciler should get new ServiceExport successfully but got error = %v", err)
				} else {
					reason := newSvcExport.Status.Conditions[0].Reason
					if *reason != tt.expectedReason {
						t.Errorf("Expected ServiceExport status should be %s but got %v", tt.expectedReason, *reason)
					}
					if tt.expectedMessage != "" && tt.expectedMessage != *newSvcExport.Status.Conditions[0].Message {
						t.Errorf("Expected message %s but got %s", tt.expectedMessage, *newSvcExport.Status.Conditions[0].Message)
					}
				}
			}
		})
	}
}

func TestServiceExportReconciler_handleServiceExportCreateEvent(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(svcNginx, epNginx, existSvcExport).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, "default")
	mcReconciler := NewMemberClusterSetReconciler(fakeClient, scheme, "default")
	mcReconciler.SetRemoteCommonArea(commonArea)
	r := NewServiceExportReconciler(fakeClient, scheme, mcReconciler, "ClusterIP")
	if _, err := r.Reconcile(ctx, nginxReq); err != nil {
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
		if err = fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "nginx"}, newSvcExport); err != nil {
			t.Errorf("Should get ServiceExport successfully but got error = %v", err)
		} else {
			reason := newSvcExport.Status.Conditions[0].Reason
			if *reason != "export_succeeded" {
				t.Errorf("Expected ServiceExport status should be 'export_succeeded' but got %v", *reason)
			}
		}
	}
}

func TestServiceExportReconciler_handleUpdateEvent(t *testing.T) {
	sinfo := &svcInfo{
		name:       svcNginx.Name,
		namespace:  svcNginx.Namespace,
		clusterIPs: svcNginx.Spec.ClusterIPs,
		ports:      svcNginx.Spec.Ports,
		svcType:    string(svcNginx.Spec.Type),
	}

	epInfo := &epInfo{
		name:      epNginx.Name,
		namespace: epNginx.Namespace,
		subsets:   common.FilterEndpointSubsets(epNginx.Subsets),
	}

	newSvcNginx := svcNginx.DeepCopy()
	newSvcNginx.Spec.Ports = []corev1.ServicePort{svcPort8080}
	newEpNginx := epNginx.DeepCopy()
	newEpNginx.Subsets[0].Ports = epPorts8080

	svcNginxEPs := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "default",
		},
		Subsets: epNginxSubset,
	}
	re := mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Labels: map[string]string{
				common.SourceName:      nginxReq.Name,
				common.SourceNamespace: nginxReq.Namespace,
				common.SourceClusterID: localClusterID,
			},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			ClusterID: localClusterID,
			Name:      nginxReq.Name,
			Namespace: nginxReq.Namespace,
		},
	}
	existSvcRe := re.DeepCopy()
	existSvcRe.Name = "cluster-a-default-nginx-service"
	existSvcRe.Spec.Service = &mcsv1alpha1.ServiceExport{ServiceSpec: corev1.ServiceSpec{}}
	existSvcRe.Spec.Service.ServiceSpec.Ports = []corev1.ServicePort{svcPort80}

	existEpRe := re.DeepCopy()
	existEpRe.Name = "cluster-a-default-nginx-endpoints"
	existEpRe.Spec.Endpoints = &mcsv1alpha1.EndpointsExport{Subsets: common.FilterEndpointSubsets(epNginxSubset)}

	tests := []struct {
		name              string
		existingEndpoints *corev1.Endpoints
		existingService   *corev1.Service
		expectedPorts     []corev1.ServicePort
		expectedSubsets   []corev1.EndpointSubset
		endpointIPType    string
	}{
		{
			name:              "update ResourceExport successfully with ClusterIP",
			existingEndpoints: svcNginxEPs,
			existingService:   newSvcNginx,
			endpointIPType:    "ClusterIP",
			expectedPorts: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     8080,
				},
			},
			expectedSubsets: []corev1.EndpointSubset{
				{
					Addresses: []corev1.EndpointAddress{
						{
							IP: "192.168.2.3",
						},
					},
					Ports: epPorts8080,
				},
			},
		},
		{
			name:              "update ResourceExport successfully with Pod IP",
			existingEndpoints: newEpNginx,
			existingService:   newSvcNginx,
			endpointIPType:    "PodIP",
			expectedPorts: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     8080,
				},
			},
			expectedSubsets: []corev1.EndpointSubset{
				{
					Addresses: []corev1.EndpointAddress{
						{
							IP: "192.168.17.11",
						},
					},
					Ports: epPorts8080,
				},
			},
		},
		{
			name:              "update ResourceExport successfully without change",
			existingEndpoints: svcNginxEPs,
			existingService:   svcNginx,
			endpointIPType:    "PodIP",
			expectedPorts: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     80,
				},
			},
			expectedSubsets: []corev1.EndpointSubset{
				{
					Addresses: []corev1.EndpointAddress{
						{
							IP: "192.168.17.11",
						},
					},
					Ports: epPorts80,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.existingService, tt.existingEndpoints, existSvcExport).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existSvcRe, existEpRe).Build()

			commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, "default")
			mcReconciler := NewMemberClusterSetReconciler(fakeClient, scheme, "default")
			mcReconciler.SetRemoteCommonArea(commonArea)
			r := NewServiceExportReconciler(fakeClient, scheme, mcReconciler, tt.endpointIPType)
			r.installedSvcs.Add(sinfo)
			r.installedEps.Add(epInfo)
			if _, err := r.Reconcile(ctx, nginxReq); err != nil {
				t.Errorf("ServiceExport Reconciler should update ResourceExports but got error = %v", err)
			} else {
				svcResExport := &mcsv1alpha1.ResourceExport{}
				err := fakeRemoteClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "cluster-a-default-nginx-service"}, svcResExport)
				if err != nil {
					t.Errorf("ServiceExport Reconciler should get new Service kind of ResourceExport successfully but got error = %v", err)
				} else {
					ports := svcResExport.Spec.Service.ServiceSpec.Ports
					if !reflect.DeepEqual(ports, tt.expectedPorts) {
						t.Errorf("Expected Service ports are %v but got %v", tt.expectedPorts, ports)
					}
				}
				epResExport := &mcsv1alpha1.ResourceExport{}
				err = fakeRemoteClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "cluster-a-default-nginx-endpoints"}, epResExport)
				if err != nil {
					t.Errorf("ServiceExport Reconciler should get new Endpoints kind of ResourceExport successfully but got error = %v", err)
				} else {
					subsets := epResExport.Spec.Endpoints.Subsets
					if !reflect.DeepEqual(subsets, tt.expectedSubsets) {
						t.Errorf("Expected Endpoints subsets are %v but got %v", tt.expectedSubsets, subsets)
					}
				}
			}
		})
	}
}

func Test_serviceMapFunc(t *testing.T) {
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := objectMapFunc(tt.obj); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Test_objectMapFunc() = %v, want %v", got, tt.want)
			}
		})
	}
}
