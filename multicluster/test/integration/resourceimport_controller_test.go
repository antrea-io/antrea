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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8smcsapi "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
)

// This file contains test cases for below basic scenarios:
//   - Create MC Service, ServiceImport and EndpointSlice when a ResourceImport is created.
//   - Update MC Service and EndpointSlice when a ResourceImport is updated.
//   - Delete MC Service, ServiceImport and EndpointSlice when a ResourceImport is deleted.

var (
	nignxSvcResImport = &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "leader-ns",
			Name:      "cluster-a-exported-nginx-service",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Namespace: "default",
			Name:      "exported-nginx",
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
					Type: k8smcsapi.ClusterSetIP,
				},
			},
		},
	}

	riReady    = true
	riProtocol = corev1.ProtocolTCP
	riPort80   = int32(80)
	riPort8080 = int32(8080)

	riDiscEndpoints = []discovery.Endpoint{
		{
			Addresses:  []string{"192.168.17.11"},
			Conditions: discovery.EndpointConditions{Ready: &riReady},
		},
	}
	riDiscPorts = []discovery.EndpointPort{
		{
			Name:     ptr.To("http"),
			Port:     &riPort80,
			Protocol: &riProtocol,
		},
	}
	riNewDiscEndpoints = []discovery.Endpoint{
		{
			Addresses:  []string{"192.168.17.12"},
			Conditions: discovery.EndpointConditions{Ready: &riReady},
		},
	}
	riNewDiscPorts = []discovery.EndpointPort{
		{
			Name:     ptr.To("http"),
			Port:     &riPort8080,
			Protocol: &riProtocol,
		},
	}
)

var _ = Describe("ResourceImport controller", func() {
	ctx := context.Background()
	It("Should create MC Service, ServiceImport for existing ResourceImport", func() {
		By("By adding a Service ResourceImport")

		Expect(k8sClient.Create(ctx, nignxSvcResImport)).Should(Succeed())

		Eventually(func() bool {
			svc := &corev1.Service{}
			err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "antrea-mc-exported-nginx"}, svc)
			return err == nil
		}, timeout, interval).Should(BeTrue())

		Eventually(func() bool {
			svcImp := &k8smcsapi.ServiceImport{}
			err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "exported-nginx"}, svcImp)
			return err == nil
		}, timeout, interval).Should(BeTrue())
	})

	It("Should create MC EndpointSlice for an existing ResourceImport", func() {
		By("By adding an Endpoints ResourceImport")
		epResImport := &mcsv1alpha1.ResourceImport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "leader-ns",
				Name:      "cluster-a-exported-nginx-endpoints",
			},
			Spec: mcsv1alpha1.ResourceImportSpec{
				Namespace: "default",
				Name:      "exported-nginx",
				Kind:      "Endpoints",
				Endpoints: &mcsv1alpha1.EndpointsImport{
					Endpoints: riDiscEndpoints,
					Ports:     riDiscPorts,
				},
			},
		}

		Expect(k8sClient.Create(ctx, epResImport)).Should(Succeed())

		Eventually(func() bool {
			eps := &discovery.EndpointSlice{}
			err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "antrea-mc-exported-nginx"}, eps)
			return err == nil
		}, timeout, interval).Should(BeTrue())
	})

	It("Should update MC Service for an existing ResourceImport", func() {
		By("By updating a ResourceImport")
		svcResImp := &mcsv1alpha1.ResourceImport{}
		err := k8sClient.Get(ctx, types.NamespacedName{
			Namespace: "leader-ns",
			Name:      "cluster-a-exported-nginx-service"}, svcResImp)
		Expect(err).ToNot(HaveOccurred())
		svcResImp.Spec.ServiceImport.Spec.Ports = []k8smcsapi.ServicePort{
			{
				Name:     "http",
				Protocol: corev1.ProtocolTCP,
				Port:     8080,
			},
		}

		err = k8sClient.Update(ctx, svcResImp, &client.UpdateOptions{})
		Expect(err).ToNot(HaveOccurred())

		Eventually(func() bool {
			newSvc := &corev1.Service{}
			err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "antrea-mc-exported-nginx"}, newSvc)
			Expect(err).ToNot(HaveOccurred())
			return newSvc.Spec.Ports[0].Port == 8080
		}, timeout, interval).Should(BeTrue())

		Eventually(func() bool {
			newSvcImp := &k8smcsapi.ServiceImport{}
			err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "exported-nginx"}, newSvcImp)
			Expect(err).ToNot(HaveOccurred())
			return newSvcImp.Spec.Ports[0].Port == 8080
		}, timeout, interval).Should(BeTrue())
	})

	It("Should update MC EndpointSlice for an existing ResourceImport", func() {
		By("By updating a ResourceImport")
		epResImp := &mcsv1alpha1.ResourceImport{}
		err := k8sClient.Get(ctx, types.NamespacedName{
			Namespace: "leader-ns",
			Name:      "cluster-a-exported-nginx-endpoints"}, epResImp)
		Expect(err).ToNot(HaveOccurred())
		epResImp.Spec.Endpoints = &mcsv1alpha1.EndpointsImport{
			Endpoints: riNewDiscEndpoints,
			Ports:     riNewDiscPorts,
		}

		err = k8sClient.Update(ctx, epResImp, &client.UpdateOptions{})
		Expect(err).ToNot(HaveOccurred())

		Eventually(func() bool {
			newEPS := &discovery.EndpointSlice{}
			err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "antrea-mc-exported-nginx"}, newEPS)
			Expect(err).ToNot(HaveOccurred())
			if len(newEPS.Endpoints) == 0 || len(newEPS.Ports) == 0 {
				return false
			}
			return newEPS.Endpoints[0].Addresses[0] == riNewDiscEndpoints[0].Addresses[0] &&
				*newEPS.Ports[0].Port == *riNewDiscPorts[0].Port
		}, timeout, interval).Should(BeTrue())
	})

	It("Should delete MC Service, ServiceImport and EndpointSlice for a deleted ResourceImport", func() {
		By("By deleting an existing ResourceImport")

		err := k8sClient.Delete(ctx, nignxSvcResImport, &client.DeleteOptions{})
		Expect(err).ToNot(HaveOccurred())

		Eventually(func() bool {
			svc := &corev1.Service{}
			err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "antrea-mc-exported-nginx"}, svc)
			return apierrors.IsNotFound(err)
		}, timeout, interval).Should(BeTrue())

		Eventually(func() bool {
			eps := &discovery.EndpointSlice{}
			err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "antrea-mc-exported-nginx"}, eps)
			return apierrors.IsNotFound(err)
		}, timeout, interval).Should(BeTrue())

		Eventually(func() bool {
			svcImp := &k8smcsapi.ServiceImport{}
			err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "exported-nginx"}, svcImp)
			return apierrors.IsNotFound(err)
		}, timeout, interval).Should(BeTrue())
	})
})
