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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	k8smcv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"antrea.io/antrea/v2/multicluster/apis/multicluster/constants"
	mcv1alpha1 "antrea.io/antrea/v2/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/v2/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/v2/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/v2/multicluster/controllers/multicluster/commonarea"
)

var (
	nginxReq = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: "default",
		Name:      "nginx",
	}}

	existSvcExport = &k8smcv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx",
		},
	}

	epReady    = true
	epProtocol = corev1.ProtocolTCP

	// epsNginx is a ready EndpointSlice for the nginx Service with a pod IP endpoint.
	epsNginx = &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-abe173ud",
			Namespace: "default",
			Labels:    map[string]string{discovery.LabelServiceName: "nginx"},
		},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{
			{
				Addresses:  []string{"192.168.17.11"},
				Conditions: discovery.EndpointConditions{Ready: &epReady},
			},
		},
		Ports: []discovery.EndpointPort{
			{
				Name:     ptr.To("http"),
				Port:     ptr.To(int32(80)),
				Protocol: ptr.To(epProtocol),
			},
		},
	}
)

func TestServiceExportReconciler_handleDeleteEvent(t *testing.T) {
	existSvcResExport := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: common.LeaderNamespace,
			Name:      getResourceExportName(common.LocalClusterID, nginxReq, "service"),
		},
	}
	existEpResExport := &mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: common.LeaderNamespace,
			Name:      getResourceExportName(common.LocalClusterID, nginxReq, "endpoints"),
		},
	}
	exportedSvcNginx := common.SvcNginx.DeepCopy()

	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(exportedSvcNginx).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existSvcResExport, existEpResExport).Build()

	commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, "default", nil)
	mcReconciler := NewMemberClusterSetReconciler(fakeClient, common.TestScheme, "default", false, false, make(chan struct{}))
	mcReconciler.SetRemoteCommonArea(commonArea)
	r := NewServiceExportReconciler(fakeClient, common.TestScheme, mcReconciler, "ClusterIP", "default")
	r.installedSvcs.Add(&svcInfo{
		name:      common.SvcNginx.Name,
		namespace: common.SvcNginx.Namespace,
	})
	if _, err := r.Reconcile(common.TestCtx, nginxReq); err != nil {
		t.Errorf("ServiceExport Reconciler should handle delete event successfully but got error = %v", err)
	} else {
		epResource := &mcv1alpha1.ResourceExport{}
		err := fakeRemoteClient.Get(common.TestCtx, types.NamespacedName{
			Namespace: "default",
			Name:      "cluster-a-default-nginx-endpoints",
		}, epResource)
		if !apierrors.IsNotFound(err) {
			t.Errorf("Expected not found error but got error = %v", err)
		}
		svcResource := &mcv1alpha1.ResourceExport{}
		err = fakeRemoteClient.Get(common.TestCtx, types.NamespacedName{
			Namespace: "default",
			Name:      "cluster-a-default-nginx-service",
		}, svcResource)
		if !apierrors.IsNotFound(err) {
			t.Errorf("Expected not found error but got error = %v", err)
		}
	}
}

func TestServiceExportReconciler_CheckExportStatus(t *testing.T) {
	mcsSvc := common.SvcNginx.DeepCopy()
	mcsSvc.Name = "antrea-mc-nginx"
	mcsSvc.Annotations = map[string]string{common.AntreaMCServiceAnnotation: "true"}
	mcsSvcExport := &k8smcv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "antrea-mc-nginx",
		},
	}

	nginx0Svc := common.SvcNginx.DeepCopy()
	nginx0Svc.Name = "nginx0"
	nginx0SvcExport := &k8smcv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx0",
		},
	}

	nginx1Svc := common.SvcNginx.DeepCopy()
	nginx1Svc.Name = "nginx1"
	nginx1SvcExportWithStatus := &k8smcv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx1",
		},
		Status: k8smcv1alpha1.ServiceExportStatus{
			Conditions: []metav1.Condition{
				{
					Type:               string(k8smcv1alpha1.ServiceExportConditionValid),
					Status:             metav1.ConditionFalse,
					LastTransitionTime: metav1.Now(),
					Reason:             "ServiceWithoutEndpoints",
					Message:            "the Service has no Endpoints, failed to export",
				},
			},
		},
	}

	nginx1EPS := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx1-abe173ud",
			Namespace: "default",
			Labels:    map[string]string{discovery.LabelServiceName: "nginx1"},
		},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{
			{
				Addresses:  []string{"192.168.17.11"},
				Conditions: discovery.EndpointConditions{Ready: &epReady},
			},
		},
		Ports: []discovery.EndpointPort{
			{
				Name:     ptr.To("http"),
				Port:     ptr.To(int32(80)),
				Protocol: ptr.To(epProtocol),
			},
		},
	}

	nginx2Svc := common.SvcNginx.DeepCopy()
	nginx2Svc.Name = "nginx2"
	nginx2SvcExportWithStatus := nginx1SvcExportWithStatus.DeepCopy()
	nginx2SvcExportWithStatus.Name = "nginx2"
	nginx2SvcExportWithStatus.Status.Conditions[0].Message = "the Service has no related Endpoints"

	nginx3Svc := common.SvcNginx.DeepCopy()
	nginx3Svc.Name = "nginx3"
	nginx3Svc.Spec.Type = corev1.ServiceTypeExternalName
	nginx3SvcExport := &k8smcv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx3",
		},
	}

	svcNoClusterIP := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-no-ip",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				common.SvcPort80,
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}

	// EndpointSlice for nginx-no-ip ensures hasReadyEndpoints=true so the
	// reconciler proceeds to the ClusterIP check and sets ServiceNoClusterIP.
	svcNoClusterIPEPS := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-no-ip-abe173ud",
			Namespace: "default",
			Labels:    map[string]string{discovery.LabelServiceName: "nginx-no-ip"},
		},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{
			{
				Addresses:  []string{"192.168.17.11"},
				Conditions: discovery.EndpointConditions{Ready: &epReady},
			},
		},
		Ports: []discovery.EndpointPort{
			{
				Name:     ptr.To("http"),
				Port:     ptr.To(int32(80)),
				Protocol: ptr.To(epProtocol),
			},
		},
	}

	svcExpNoClusterIP := &k8smcv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx-no-ip",
		},
	}

	tests := []struct {
		name            string
		expectedReason  string
		expectedMessage string
		req             ctrl.Request
	}{
		{
			name:            "export non-existing Service",
			expectedReason:  "ServiceNotFound",
			expectedMessage: "Service does not exist",
			req:             nginxReq,
		},
		{
			name:            "export ExternalName type of Service",
			expectedReason:  "ServiceTypeNotSupported",
			expectedMessage: "Service of ExternalName type is not supported",
			req: ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "nginx3",
			}},
		},
		{
			name:           "export Service without ClusterIP",
			expectedReason: "ServiceNoClusterIP",
			req: ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "nginx-no-ip",
			}},
		},
		{
			name:           "export multi-cluster Service",
			expectedReason: "ImportedService",
			req: ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "antrea-mc-nginx",
			}},
		},
		{
			name:           "export Service without Endpoints",
			expectedReason: "ServiceWithoutEndpoints",
			req: ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "nginx0",
			}},
		},
		{
			name:            "export Service and update status successfully",
			expectedReason:  "Succeed",
			expectedMessage: "The Service is exported successfully",
			req: ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "nginx1",
			}},
		},
		{
			name:            "skip update status",
			expectedReason:  "ServiceWithoutEndpoints",
			expectedMessage: "the Service has no related Endpoints",
			req: ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "nginx2",
			}},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(
		mcsSvc, nginx0Svc, nginx1Svc, nginx3Svc, svcNoClusterIP,
		nginx1EPS, svcNoClusterIPEPS,
		nginx2Svc, existSvcExport, nginx0SvcExport, nginx1SvcExportWithStatus, nginx2SvcExportWithStatus,
		nginx3SvcExport, mcsSvcExport, svcExpNoClusterIP).
		WithStatusSubresource(
			nginx0SvcExport, nginx1SvcExportWithStatus, nginx2SvcExportWithStatus,
			nginx3SvcExport, mcsSvcExport, svcExpNoClusterIP).
		Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).Build()
	commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, "default", nil)

	mcReconciler := NewMemberClusterSetReconciler(fakeClient, common.TestScheme, "default", false, false, make(chan struct{}))
	mcReconciler.SetRemoteCommonArea(commonArea)
	r := NewServiceExportReconciler(fakeClient, common.TestScheme, mcReconciler, "ClusterIP", "default")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := r.Reconcile(common.TestCtx, tt.req); err != nil {
				t.Errorf("ServiceExport Reconciler should update ServiceExport status successfully but got error = %v", err)
			} else {
				newSvcExport := &k8smcv1alpha1.ServiceExport{}
				err := fakeClient.Get(common.TestCtx, types.NamespacedName{Namespace: tt.req.Namespace, Name: tt.req.Name}, newSvcExport)
				if err != nil {
					t.Errorf("ServiceExport Reconciler should get new ServiceExport successfully but got error = %v", err)
				} else {
					if len(newSvcExport.Status.Conditions) == 0 {
						t.Errorf("Expected at least one condition but got none")
					} else {
						reason := newSvcExport.Status.Conditions[0].Reason
						if reason != tt.expectedReason {
							t.Errorf("Expected ServiceExport status reason should be %s but got %v", tt.expectedReason, reason)
						}
						if tt.expectedMessage != "" && tt.expectedMessage != newSvcExport.Status.Conditions[0].Message {
							t.Errorf("Expected message %s but got %s", tt.expectedMessage, newSvcExport.Status.Conditions[0].Message)
						}
					}
				}
			}
		})
	}
}

func TestServiceExportReconciler_handleServiceExportCreateEvent(t *testing.T) {
	tests := []struct {
		name           string
		endpointIPType string
		fakeClient     client.WithWatch
	}{
		{
			name: "with EndpointSlice and ClusterIP type",
			fakeClient: fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(common.SvcNginx, epsNginx, existSvcExport).
				WithStatusSubresource(existSvcExport).Build(),
			endpointIPType: "ClusterIP",
		},
		{
			name: "with EndpointSlice and PodIP type",
			fakeClient: fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(common.SvcNginx, epsNginx, existSvcExport).
				WithStatusSubresource(existSvcExport).Build(),
			endpointIPType: "PodIP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).Build()
			commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, "default", nil)
			mcReconciler := NewMemberClusterSetReconciler(tt.fakeClient, common.TestScheme, "default", false, false, make(chan struct{}))
			mcReconciler.SetRemoteCommonArea(commonArea)
			r := NewServiceExportReconciler(tt.fakeClient, common.TestScheme, mcReconciler, tt.endpointIPType, "default")
			if _, err := r.Reconcile(common.TestCtx, nginxReq); err != nil {
				t.Errorf("ServiceExport Reconciler should create ResourceExports but got error = %v", err)
			} else {
				svcResExport := &mcv1alpha1.ResourceExport{}
				err := fakeRemoteClient.Get(common.TestCtx, types.NamespacedName{Namespace: "default", Name: "cluster-a-default-nginx-service"}, svcResExport)
				if err != nil {
					t.Errorf("ServiceExport Reconciler should get new Service kind of ResourceExport successfully but got error = %v", err)
				}
				epResExport := &mcv1alpha1.ResourceExport{}
				err = fakeRemoteClient.Get(common.TestCtx, types.NamespacedName{Namespace: "default", Name: "cluster-a-default-nginx-endpoints"}, epResExport)
				if err != nil {
					t.Errorf("ServiceExport Reconciler should get new Endpoints kind of ResourceExport successfully but got error = %v", err)
				}
				newSvcExport := &k8smcv1alpha1.ServiceExport{}
				if err = tt.fakeClient.Get(common.TestCtx, types.NamespacedName{Namespace: "default", Name: "nginx"}, newSvcExport); err != nil {
					t.Errorf("Should get ServiceExport successfully but got error = %v", err)
				} else {
					status := newSvcExport.Status.Conditions[0].Status
					if status != metav1.ConditionTrue {
						t.Errorf("Expected ServiceExport status should be True but got %v", status)
					}
				}
			}
		})
	}
}

func TestServiceExportReconciler_handleUpdateEvent(t *testing.T) {
	sinfo := &svcInfo{
		name:       common.SvcNginx.Name,
		namespace:  common.SvcNginx.Namespace,
		clusterIPs: common.SvcNginx.Spec.ClusterIPs,
		ports:      common.SvcNginx.Spec.Ports,
		svcType:    string(common.SvcNginx.Spec.Type),
	}

	// cachedEpInfo holds the cached endpoint state matching epsNginx (port 80, pod IP 192.168.17.11).
	cachedEpInfo := &epInfo{
		name:      "nginx",
		namespace: "default",
		endpoints: []discovery.Endpoint{
			{
				Addresses:  []string{"192.168.17.11"},
				Conditions: discovery.EndpointConditions{Ready: &epReady},
			},
		},
		ports: []discovery.EndpointPort{
			{
				Name:     ptr.To("http"),
				Port:     ptr.To(int32(80)),
				Protocol: ptr.To(epProtocol),
			},
		},
	}

	newSvcNginx := common.SvcNginx.DeepCopy()
	newSvcNginx.Spec.Ports = []corev1.ServicePort{common.SvcPort8080}

	// epsNginx8080 is an EndpointSlice for nginx with port 8080.
	port8080 := int32(8080)
	epsNginx8080 := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-abe173ud",
			Namespace: "default",
			Labels:    map[string]string{discovery.LabelServiceName: "nginx"},
		},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{
			{
				Addresses:  []string{"192.168.17.11"},
				Conditions: discovery.EndpointConditions{Ready: &epReady},
			},
		},
		Ports: []discovery.EndpointPort{
			{
				Name:     ptr.To("http"),
				Port:     &port8080,
				Protocol: &epProtocol,
			},
		},
	}

	node1 := "node1"
	host1 := "host1"
	epsNginxWithClusterFields := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-unsanitized",
			Namespace: "default",
			Labels:    map[string]string{discovery.LabelServiceName: "nginx"},
		},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{
			{
				Addresses: []string{"192.168.17.11"},
				Conditions: discovery.EndpointConditions{
					Ready: &epReady,
				},
				NodeName:           &node1,
				Hostname:           &host1,
				TargetRef:          &corev1.ObjectReference{Kind: "Pod", Name: "pod1"},
				DeprecatedTopology: map[string]string{"kubernetes.io/hostname": "node1"},
			},
		},
		Ports: []discovery.EndpointPort{
			{
				Name:     ptr.To("http"),
				Port:     &port8080,
				Protocol: &epProtocol,
			},
		},
	}

	epsNginxUnnamedPort := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-unnamed",
			Namespace: "default",
			Labels:    map[string]string{discovery.LabelServiceName: "nginx"},
		},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{
			{
				Addresses:  []string{"192.168.17.11"},
				Conditions: discovery.EndpointConditions{Ready: &epReady},
			},
		},
		Ports: []discovery.EndpointPort{
			{
				Port:     &port8080,
				Protocol: &epProtocol,
			},
		},
	}

	re := mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: common.LeaderNamespace,
			Labels: map[string]string{
				constants.SourceName:      nginxReq.Name,
				constants.SourceNamespace: nginxReq.Namespace,
				constants.SourceClusterID: common.LocalClusterID,
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: common.LocalClusterID,
			Name:      nginxReq.Name,
			Namespace: nginxReq.Namespace,
		},
	}
	existSvcRe := re.DeepCopy()
	existSvcRe.Name = "cluster-a-default-nginx-service"
	existSvcRe.Spec.Kind = constants.ServiceKind
	existSvcRe.Spec.Service = &mcv1alpha1.ServiceExport{ServiceSpec: corev1.ServiceSpec{}}
	existSvcRe.Spec.Service.ServiceSpec.Ports = []corev1.ServicePort{common.SvcPort80}

	existEpRe := re.DeepCopy()
	existEpRe.Name = "cluster-a-default-nginx-endpoints"
	existEpRe.Spec.Kind = constants.EndpointsKind
	existEpRe.Spec.Endpoints = &mcv1alpha1.EndpointsExport{
		Endpoints: cachedEpInfo.endpoints,
		Ports:     cachedEpInfo.ports,
	}

	tests := []struct {
		name             string
		existingEPS      *discovery.EndpointSlice
		existingService  *corev1.Service
		expectedSvcPorts []corev1.ServicePort
		// expectedEndpoints are the discovery.Endpoint entries expected in the ResourceExport.
		expectedEndpoints []discovery.Endpoint
		// expectedEPPorts are the discovery.EndpointPort entries expected in the ResourceExport.
		expectedEPPorts []discovery.EndpointPort
		endpointIPType  string
	}{
		{
			name:            "update ResourceExport successfully with ClusterIP",
			existingEPS:     epsNginx8080,
			existingService: newSvcNginx,
			endpointIPType:  "ClusterIP",
			expectedSvcPorts: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     8080,
				},
			},
			// With ClusterIP type, endpoint address is the Service ClusterIP.
			expectedEndpoints: []discovery.Endpoint{
				{
					Addresses:  []string{"192.168.2.3"},
					Conditions: discovery.EndpointConditions{Ready: &epReady},
				},
			},
			expectedEPPorts: []discovery.EndpointPort{
				{
					Name:     ptr.To("http"),
					Port:     &port8080,
					Protocol: &epProtocol,
				},
			},
		},
		{
			name:            "update ResourceExport successfully with Pod IP",
			existingEPS:     epsNginx8080,
			existingService: newSvcNginx,
			endpointIPType:  "PodIP",
			expectedSvcPorts: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     8080,
				},
			},
			expectedEndpoints: []discovery.Endpoint{
				{
					Addresses:  []string{"192.168.17.11"},
					Conditions: discovery.EndpointConditions{Ready: &epReady},
				},
			},
			expectedEPPorts: []discovery.EndpointPort{
				{
					Name:     ptr.To("http"),
					Port:     &port8080,
					Protocol: &epProtocol,
				},
			},
		},
		{
			name:            "update ResourceExport successfully sanitizing endpoint cluster fields",
			existingEPS:     epsNginxWithClusterFields,
			existingService: newSvcNginx,
			endpointIPType:  "PodIP",
			expectedSvcPorts: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     8080,
				},
			},
			expectedEndpoints: []discovery.Endpoint{
				{
					Addresses:  []string{"192.168.17.11"},
					Conditions: discovery.EndpointConditions{Ready: &epReady},
				},
			},
			expectedEPPorts: []discovery.EndpointPort{
				{
					Name:     ptr.To("http"),
					Port:     &port8080,
					Protocol: &epProtocol,
				},
			},
		},
		{
			name:            "update ResourceExport successfully with unnamed port",
			existingEPS:     epsNginxUnnamedPort,
			existingService: newSvcNginx,
			endpointIPType:  "PodIP",
			expectedSvcPorts: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     8080,
				},
			},
			expectedEndpoints: []discovery.Endpoint{
				{
					Addresses:  []string{"192.168.17.11"},
					Conditions: discovery.EndpointConditions{Ready: &epReady},
				},
			},
			expectedEPPorts: []discovery.EndpointPort{
				{
					Name:     nil,
					Port:     &port8080,
					Protocol: &epProtocol,
				},
			},
		},
		{
			name:            "update ResourceExport successfully without change",
			existingEPS:     epsNginx,
			existingService: common.SvcNginx,
			endpointIPType:  "PodIP",
			expectedSvcPorts: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     80,
				},
			},
			expectedEndpoints: cachedEpInfo.endpoints,
			expectedEPPorts:   cachedEpInfo.ports,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(
				tt.existingService, tt.existingEPS, existSvcExport).
				WithStatusSubresource(existSvcExport).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existSvcRe, existEpRe).Build()

			commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, "default", nil)
			mcReconciler := NewMemberClusterSetReconciler(fakeClient, common.TestScheme, "default", false, false, make(chan struct{}))
			mcReconciler.SetRemoteCommonArea(commonArea)
			r := NewServiceExportReconciler(fakeClient, common.TestScheme, mcReconciler, tt.endpointIPType, "default")
			r.installedSvcs.Add(sinfo)
			r.installedEps.Add(cachedEpInfo)
			if _, err := r.Reconcile(common.TestCtx, nginxReq); err != nil {
				t.Errorf("ServiceExport Reconciler should update ResourceExports but got error = %v", err)
			} else {
				svcResExport := &mcv1alpha1.ResourceExport{}
				err := fakeRemoteClient.Get(common.TestCtx, types.NamespacedName{Namespace: "default", Name: "cluster-a-default-nginx-service"}, svcResExport)
				if err != nil {
					t.Errorf("ServiceExport Reconciler should get Service kind of ResourceExport successfully but got error = %v", err)
				} else {
					ports := svcResExport.Spec.Service.ServiceSpec.Ports
					if !reflect.DeepEqual(ports, tt.expectedSvcPorts) {
						t.Errorf("Expected Service ports are %v but got %v", tt.expectedSvcPorts, ports)
					}
				}
				epResExport := &mcv1alpha1.ResourceExport{}
				err = fakeRemoteClient.Get(common.TestCtx, types.NamespacedName{Namespace: "default", Name: "cluster-a-default-nginx-endpoints"}, epResExport)
				if err != nil {
					t.Errorf("ServiceExport Reconciler should get Endpoints kind of ResourceExport successfully but got error = %v", err)
				} else {
					eps := epResExport.Spec.Endpoints.Endpoints
					if !reflect.DeepEqual(eps, tt.expectedEndpoints) {
						t.Errorf("Expected Endpoints are %v but got %v", tt.expectedEndpoints, eps)
					}
					epPorts := epResExport.Spec.Endpoints.Ports
					if !reflect.DeepEqual(epPorts, tt.expectedEPPorts) {
						t.Errorf("Expected EndpointPorts are %v but got %v", tt.expectedEPPorts, epPorts)
					}
				}
			}
		})
	}
}

func Test_objectMapFunc(t *testing.T) {
	ctx := context.Background()
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
			if got := objectMapFunc(ctx, tt.obj); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Test_objectMapFunc() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_endpointSliceMapFunc(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		obj  client.Object
		want []reconcile.Request
	}{
		{
			name: "map EndpointSlice Object",
			obj: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx-as4asjh1",
					Namespace: "default",
					Labels:    map[string]string{discovery.LabelServiceName: "nginx"},
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
			name: "map EndpointSlice Object without Service Name label",
			obj: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx-as4asjh1",
					Namespace: "default",
				},
			},
			want: []reconcile.Request{{}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := endpointSliceMapFunc(ctx, tt.obj); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Test_endpointSliceMapFunc() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClusterSetMapFunc_ServiceExport(t *testing.T) {
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
	clusterSet2 := &mcv1alpha2.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "clusterset-test-deleted",
		},
	}
	svcExport1 := k8smcv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx",
		},
	}
	svcExport2 := k8smcv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      "web",
		},
	}
	serviceExports := &k8smcv1alpha1.ServiceExportList{
		Items: []k8smcv1alpha1.ServiceExport{
			svcExport1, svcExport2,
		},
	}
	expectedReqs := []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Name:      svcExport1.GetName(),
				Namespace: svcExport1.GetNamespace(),
			},
		},
		{
			NamespacedName: types.NamespacedName{
				Name:      svcExport2.GetName(),
				Namespace: svcExport2.GetNamespace(),
			},
		},
	}
	ctx := context.Background()
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(clusterSet).WithLists(serviceExports).Build()
	r := NewServiceExportReconciler(fakeClient, common.TestScheme, nil, "PodIP", clusterSet.Namespace)
	requests := r.clusterSetMapFunc(ctx, clusterSet)
	assert.Equal(t, expectedReqs, requests)

	r = NewServiceExportReconciler(fakeClient, common.TestScheme, nil, "PodIP", "mismatch_ns")
	requests = r.clusterSetMapFunc(ctx, clusterSet)
	assert.Equal(t, []reconcile.Request{}, requests)

	// non-existing ClusterSet
	r = NewServiceExportReconciler(fakeClient, common.TestScheme, nil, "PodIP", "default")
	r.installedSvcs.Add(&svcInfo{name: "nginx-stale", namespace: "default"})
	r.installedEps.Add(&epInfo{name: "nginx-stale", namespace: "default"})
	requests = r.clusterSetMapFunc(ctx, clusterSet2)
	assert.Equal(t, []reconcile.Request{}, requests)
	assert.Equal(t, 0, len(r.installedSvcs.List()))
	assert.Equal(t, 0, len(r.installedEps.List()))
}

func TestServiceExportReconciler_updateOrCreateResourceExport(t *testing.T) {
	const (
		leaderNamespace = "leader-cluster"
		clusterID       = "cluster-a"
	)
	// "prod/web-api" and "prod-web/api" both derive the export name
	// "cluster-a-prod-web-api-service".
	exportName := "cluster-a-prod-web-api-service"
	newResExport := func() *mcv1alpha1.ResourceExport {
		return &mcv1alpha1.ResourceExport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: leaderNamespace,
				Name:      exportName,
			},
			Spec: mcv1alpha1.ResourceExportSpec{
				ClusterID: clusterID,
				Namespace: "prod-web",
				Name:      "api",
				Kind:      constants.ServiceKind,
				Service: &mcv1alpha1.ServiceExport{
					ServiceSpec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{{Port: 80}},
					},
				},
			},
		}
	}
	tests := []struct {
		name        string
		existing    *mcv1alpha1.ResourceExport
		expectError string
	}{
		{
			name: "existing export owned by a different ServiceExport",
			existing: &mcv1alpha1.ResourceExport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: leaderNamespace,
					Name:      exportName,
				},
				Spec: mcv1alpha1.ResourceExportSpec{
					ClusterID: clusterID,
					Namespace: "prod",
					Name:      "web-api",
					Kind:      constants.ServiceKind,
				},
			},
			expectError: "another ServiceExport already exported prod/web-api (Service) under this name; rename one of the two Services",
		},
		{
			name: "existing export owned by the same ServiceExport",
			existing: &mcv1alpha1.ResourceExport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: leaderNamespace,
					Name:      exportName,
				},
				Spec: mcv1alpha1.ResourceExportSpec{
					ClusterID: clusterID,
					Namespace: "prod-web",
					Name:      "api",
					Kind:      constants.ServiceKind,
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			objs := []client.Object{tc.existing}
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(objs...).Build()
			rc := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", clusterID, leaderNamespace, nil)
			r := &ServiceExportReconciler{}
			err := r.updateOrCreateResourceExport(exportName, common.TestCtx, ctrl.Request{}, newResExport(), tc.existing, rc)
			if tc.expectError != "" {
				require.ErrorContains(t, err, tc.expectError)
				return
			}
			require.NoError(t, err)
			got := &mcv1alpha1.ResourceExport{}
			require.NoError(t, fakeRemoteClient.Get(common.TestCtx, types.NamespacedName{Namespace: leaderNamespace, Name: exportName}, got))
			require.Equal(t, "prod-web", got.Spec.Namespace)
		})
	}
}
