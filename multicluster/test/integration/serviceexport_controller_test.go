// Copyright 2021 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package integration

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"antrea.io/antrea/multicluster/apis/multicluster/constants"
	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
)

// This file contains test cases for below basic scenarios:
//   - Create ResourceExports when a ServiceExport is created.
//   - Update ResourceExport when exported Service is updated.
//   - Update ServiceExport status when the Service doesn't exist
//   - Update ResourceExport when the EndpointSlice has new Endpoints
//   - Delete ResourceExport when the ServiceExport is deleted

var _ = Describe("ServiceExport controller", func() {
	svcSpec := corev1.ServiceSpec{
		Ports: svcPorts,
	}

	ready := true
	epSlice := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-svc-abc",
			Namespace: testNamespace,
			Labels: map[string]string{
				discovery.LabelServiceName: "nginx-svc",
			},
		},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{
			{
				Addresses:  []string{"1.2.3.4"},
				Conditions: discovery.EndpointConditions{Ready: &ready},
			},
		},
		Ports: []discovery.EndpointPort{
			{
				Name:     ptr.To("http"),
				Port:     ptr.To(int32(80)),
				Protocol: ptr.To(corev1.ProtocolTCP),
			},
		},
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-svc",
			Namespace: testNamespace,
		},
		Spec: svcSpec,
	}
	svcNamespacedName := types.NamespacedName{
		Namespace: svc.Namespace,
		Name:      svc.Name,
	}

	svcExport := &k8smcsv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-svc",
			Namespace: testNamespace,
		},
	}
	svcExportNoService := &k8smcsv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-svc-dont-exist",
			Namespace: testNamespace,
		},
	}
	svcResExportName := LocalClusterID + "-" + svc.Namespace + "-" + svc.Name + "-service"
	epResExportName := LocalClusterID + "-" + svc.Namespace + "-" + svc.Name + "-endpoints"

	ctx := context.Background()
	It("Should create ResourceExports when new ServiceExport for ClusterIP Service is created", func() {
		By("By exposing a ClusterIP type of Service")
		Expect(k8sClient.Create(ctx, epSlice)).Should(Succeed())
		Expect(k8sClient.Create(ctx, svc)).Should(Succeed())
		Expect(k8sClient.Create(ctx, svcExport)).Should(Succeed())
		latestSvc := &corev1.Service{}
		err := k8sClient.Get(ctx, svcNamespacedName, latestSvc)
		Expect(err).ToNot(HaveOccurred())

		svcResExport := &mcsv1alpha1.ResourceExport{}
		epResExport := &mcsv1alpha1.ResourceExport{}
		Eventually(func() bool {
			err = k8sClient.Get(ctx, types.NamespacedName{Namespace: LeaderNamespace, Name: svcResExportName}, svcResExport)
			return err == nil
		}, timeout, interval).Should(BeTrue())
		Expect(svcResExport.ObjectMeta.Labels["sourceKind"]).Should(Equal("Service"))
		Expect(len(svcResExport.Spec.Service.ServiceSpec.Ports)).Should(Equal(len(svcPorts)))

		// Wait until the endpoints ResourceExport exists and has Endpoints populated.
		Eventually(func() bool {
			err = k8sClient.Get(ctx, types.NamespacedName{Namespace: LeaderNamespace, Name: epResExportName}, epResExport)
			if err != nil {
				return false
			}
			return epResExport.Spec.Endpoints != nil && len(epResExport.Spec.Endpoints.Endpoints) > 0
		}, timeout, interval).Should(BeTrue())
		Expect(epResExport.ObjectMeta.Labels["sourceKind"]).Should(Equal("Endpoints"))
		Expect(epResExport.Spec.Kind).Should(Equal(constants.EndpointsKind))
		Expect(epResExport.Spec.ClusterID).Should(Equal(LocalClusterID))
		Expect(epResExport.Spec.Name).Should(Equal(svc.Name))
		Expect(epResExport.Spec.Namespace).Should(Equal(svc.Namespace))
		// With ClusterIP endpoint type, the exported endpoints should use the Service ClusterIP.
		Expect(epResExport.Spec.Endpoints).ShouldNot(BeNil())
		Expect(len(epResExport.Spec.Endpoints.Endpoints)).Should(Equal(1))
		Expect(epResExport.Spec.Endpoints.Endpoints[0].Addresses).Should(ConsistOf(latestSvc.Spec.ClusterIP))
	})

	It("Should update existing ResourceExport when existing Service is updated", func() {
		By("By updating Service's ports")
		newPorts := []corev1.ServicePort{
			{
				Name:     "udp88",
				Protocol: "UDP",
				Port:     88,
			},
		}
		latestSvc := &corev1.Service{}
		err := k8sClient.Get(ctx, svcNamespacedName, latestSvc)
		Expect(err).ToNot(HaveOccurred())
		latestSvc.Spec.Ports = newPorts
		Expect(k8sClient.Update(ctx, latestSvc)).Should(Succeed())

		svcResExport := &mcsv1alpha1.ResourceExport{}
		time.Sleep(5 * time.Second)
		Eventually(func() bool {
			err = k8sClient.Get(ctx, types.NamespacedName{Namespace: LeaderNamespace, Name: svcResExportName}, svcResExport)
			return err == nil
		}, timeout, interval).Should(BeTrue())
		Expect(svcResExport.ObjectMeta.Labels["sourceKind"]).Should(Equal("Service"))
		Expect(len(svcResExport.Spec.Service.ServiceSpec.Ports)).Should(Equal(len(newPorts)))
	})

	It("Should update existing ServiceExport status when corresponding Service doesn't exist", func() {
		By("By creating a ServiceExport without a real Service")
		Expect(k8sClient.Create(ctx, svcExportNoService)).Should(Succeed())
		time.Sleep(2 * time.Second)
		latestSvcExportNoService := &k8smcsv1alpha1.ServiceExport{}
		err := k8sClient.Get(ctx, types.NamespacedName{
			Namespace: svcExportNoService.Namespace,
			Name:      svcExportNoService.Name,
		}, latestSvcExportNoService)
		Expect(err).ToNot(HaveOccurred())
		conditions := latestSvcExportNoService.Status.Conditions
		Expect(len(conditions)).Should(Equal(1))
		Expect(*conditions[0].Message).Should(Equal("Service does not exist"))
	})

	It("Should delete existing ResourceExport when existing ServiceExport is deleted", func() {
		By("By removing a ServiceExport resource")
		err := k8sClient.Delete(ctx, svcExport)
		Expect(err).ToNot(HaveOccurred())
		resExp := &mcsv1alpha1.ResourceExport{}
		Eventually(func() bool {
			err = k8sClient.Get(ctx, types.NamespacedName{Namespace: LeaderNamespace, Name: svcResExportName}, resExp)
			return apierrors.IsNotFound(err)
		}, timeout, interval).Should(BeTrue())
		Eventually(func() bool {
			err = k8sClient.Get(ctx, types.NamespacedName{Namespace: LeaderNamespace, Name: epResExportName}, resExp)
			return apierrors.IsNotFound(err)
		}, timeout, interval).Should(BeTrue())
	})

	It("Should update existing ServiceExport status when corresponding Service is removed", func() {
		By("By deleting a Service")
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-svc-deleted",
				Namespace: testNamespace,
			},
			Spec: svcSpec,
		}
		eps := &discovery.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-svc-deleted-xyz",
				Namespace: testNamespace,
				Labels: map[string]string{
					discovery.LabelServiceName: "nginx-svc-deleted",
				},
			},
			AddressType: discovery.AddressTypeIPv4,
			Endpoints: []discovery.Endpoint{
				{
					Addresses:  []string{"192.168.170.11"},
					Conditions: discovery.EndpointConditions{Ready: &ready},
				},
			},
			Ports: []discovery.EndpointPort{
				{
					Name:     ptr.To("http"),
					Port:     ptr.To(int32(80)),
					Protocol: ptr.To(corev1.ProtocolTCP),
				},
			},
		}
		svcResExportName := LocalClusterID + "-" + svc.Namespace + "-" + svc.Name + "-service"
		epResExportName := LocalClusterID + "-" + svc.Namespace + "-" + svc.Name + "-endpoints"

		svcExportDeletedService := &k8smcsv1alpha1.ServiceExport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-svc-deleted",
				Namespace: testNamespace,
			},
		}
		Expect(k8sClient.Create(ctx, svc)).Should(Succeed())
		Expect(k8sClient.Create(ctx, eps)).Should(Succeed())
		Expect(k8sClient.Create(ctx, svcExportDeletedService)).Should(Succeed())
		time.Sleep(2 * time.Second)

		err := k8sClient.Delete(ctx, svc)
		Expect(err).ToNot(HaveOccurred())
		time.Sleep(2 * time.Second)

		latestSvcExportDeletedService := &k8smcsv1alpha1.ServiceExport{}
		err = k8sClient.Get(ctx, types.NamespacedName{
			Namespace: svcExportDeletedService.Namespace,
			Name:      svcExportDeletedService.Name,
		}, latestSvcExportDeletedService)
		Expect(err).ToNot(HaveOccurred())
		conditions := latestSvcExportDeletedService.Status.Conditions
		Expect(len(conditions)).Should(Equal(1))
		Expect(*conditions[0].Message).Should(Equal("Service does not exist"))

		resExp := &mcsv1alpha1.ResourceExport{}
		Eventually(func() bool {
			err = k8sClient.Get(ctx, types.NamespacedName{Namespace: LeaderNamespace, Name: svcResExportName}, resExp)
			return apierrors.IsNotFound(err)
		}, timeout, interval).Should(BeTrue())
		Eventually(func() bool {
			err = k8sClient.Get(ctx, types.NamespacedName{Namespace: LeaderNamespace, Name: epResExportName}, resExp)
			return apierrors.IsNotFound(err)
		}, timeout, interval).Should(BeTrue())
	})
})
