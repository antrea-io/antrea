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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"antrea.io/antrea/multicluster/apis/multicluster/constants"
	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

// This file contains test cases for below basic scenarios:
//  * Clean up MC Service and ServiceImport if no corresponding ResourceImport.
//  * Clean up ResourceExport if no corresponding exported Service.

var _ = Describe("Stale controller", func() {
	svcSpec := corev1.ServiceSpec{
		Ports: svcPorts,
	}
	ctx := context.Background()
	It("Should clean up MC Service and ServiceImport if no corresponding ResourceImport in leader cluster", func() {
		By("By claim a Service and ServiceImport without ResourceImport in leader cluster")
		svcImpNoDelete := &k8smcsv1alpha1.ServiceImport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: testNSForStale,
				Name:      "nginxnodelete",
			},
			Spec: k8smcsv1alpha1.ServiceImportSpec{
				Type: k8smcsv1alpha1.ClusterSetIP,
				Ports: []k8smcsv1alpha1.ServicePort{
					{
						Name:     "http",
						Protocol: corev1.ProtocolTCP,
						Port:     80,
					},
				},
			},
		}

		resImport := &mcsv1alpha1.ResourceImport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "resourceimportexist",
				Namespace: LeaderNamespace,
			},
			Spec: mcsv1alpha1.ResourceImportSpec{
				Name:          "nginxnodelete",
				Namespace:     testNSForStale,
				Kind:          constants.ServiceImportKind,
				ServiceImport: svcImpNoDelete,
			},
		}
		err := k8sClient.Create(ctx, resImport, &client.CreateOptions{})
		Expect(err == nil).Should(BeTrue())

		svcToDelete := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "antrea-mc-nginx",
				Namespace: testNSForStale,
				Annotations: map[string]string{
					common.AntreaMCServiceAnnotation: "true",
				},
			},
			Spec: svcSpec,
		}

		svcImpToDelete := &k8smcsv1alpha1.ServiceImport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: testNSForStale,
				Name:      "nginx",
			},
			Spec: k8smcsv1alpha1.ServiceImportSpec{
				Type: k8smcsv1alpha1.ClusterSetIP,
				Ports: []k8smcsv1alpha1.ServicePort{
					{
						Name:     "http",
						Protocol: corev1.ProtocolTCP,
						Port:     80,
					},
				},
			},
		}

		svcToDeleteNamespacedName := types.NamespacedName{
			Namespace: svcToDelete.Namespace,
			Name:      svcToDelete.Name,
		}

		svcNoDelete := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-no-delete",
				Namespace: testNSForStale,
			},
			Spec: svcSpec,
		}

		mcSvcNoDelete := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "antrea-mc-nginxnodelete",
				Namespace: testNSForStale,
				Annotations: map[string]string{
					common.AntreaMCServiceAnnotation: "true",
				},
			},
			Spec: svcSpec,
		}

		Expect(k8sClient.Create(ctx, svcToDelete)).Should(Succeed())
		Expect(k8sClient.Create(ctx, svcImpToDelete)).Should(Succeed())
		Expect(k8sClient.Create(ctx, svcNoDelete)).Should(Succeed())
		// ResourceImport controller will watch ResourceImport creation event,
		// it may create corresponding Service and ServiceImport already, so we
		// skip it if it's 409 AlreadyExists error.
		err = k8sClient.Create(ctx, mcSvcNoDelete)
		Expect(err == nil || apierrors.IsAlreadyExists(err)).Should(BeTrue())
		err = k8sClient.Create(ctx, svcImpNoDelete)
		Expect(err == nil || apierrors.IsAlreadyExists(err)).Should(BeTrue())

		Eventually(func() bool {
			latestSvc := &corev1.Service{}
			err := k8sClient.Get(ctx, svcToDeleteNamespacedName, latestSvc)
			return apierrors.IsNotFound(err)
		}, timeout, interval).Should(BeTrue())

		Eventually(func() bool {
			latestSvcImp := &k8smcsv1alpha1.ServiceImport{}
			err := k8sClient.Get(ctx, svcToDeleteNamespacedName, latestSvcImp)
			return apierrors.IsNotFound(err)
		}, timeout, interval).Should(BeTrue())

		Eventually(func() bool {
			svcList := &corev1.ServiceList{}
			err = k8sClient.List(ctx, svcList, &client.ListOptions{Namespace: testNSForStale})
			Expect(err).ToNot(HaveOccurred())
			return len(svcList.Items) == 2
		}, timeout, interval).Should(BeTrue())

		Eventually(func() bool {
			svcImpList := &k8smcsv1alpha1.ServiceImportList{}
			err = k8sClient.List(ctx, svcImpList, &client.ListOptions{Namespace: testNSForStale})
			Expect(err).ToNot(HaveOccurred())
			return len(svcImpList.Items) == 1
		}, timeout, interval).Should(BeTrue())
	})

	It("Should clean up ResourceExport if no corresponding ServiceExport in member cluster", func() {
		By("By create some ResourceExports without ServiceExport in local cluster")
		svcResExpFromA := &mcsv1alpha1.ResourceExport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cluster-a-testns-stale-nginx-service",
				Namespace: LeaderNamespace,
				Labels: map[string]string{
					constants.SourceClusterID: "cluster-a",
					constants.SourceNamespace: testNSForStale,
					constants.SourceName:      "nginx",
					constants.SourceKind:      "Service",
				},
			},
			Spec: mcsv1alpha1.ResourceExportSpec{
				Name:      "nginx",
				Namespace: testNSForStale,
				Kind:      constants.ServiceKind,
				Service: &mcsv1alpha1.ServiceExport{
					ServiceSpec: corev1.ServiceSpec{
						Ports: svcPorts,
					},
				},
			},
		}

		svcExp := &k8smcsv1alpha1.ServiceExport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx",
				Namespace: testNSForStale,
			},
		}

		svcResExpToBeDeletedFromA := &mcsv1alpha1.ResourceExport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cluster-a-testns-stale-busybus-service",
				Namespace: LeaderNamespace,
				Labels: map[string]string{
					constants.SourceClusterID: "cluster-a",
					constants.SourceNamespace: testNSForStale,
					constants.SourceName:      "busybus",
					constants.SourceKind:      "Service",
				},
			},
			Spec: mcsv1alpha1.ResourceExportSpec{
				Name:      "busybus",
				Namespace: testNSForStale,
				Kind:      constants.ServiceKind,
				Service: &mcsv1alpha1.ServiceExport{
					ServiceSpec: corev1.ServiceSpec{
						Ports: svcPorts,
					},
				},
			},
		}

		svcResExpFromB := &mcsv1alpha1.ResourceExport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cluster-b-testns-stale-nginx-service",
				Namespace: LeaderNamespace,
				Labels: map[string]string{
					constants.SourceClusterID: "cluster-b",
					constants.SourceNamespace: testNSForStale,
					constants.SourceName:      "nginx",
					constants.SourceKind:      "Service",
				},
			},
			Spec: mcsv1alpha1.ResourceExportSpec{
				Name:      "nginx",
				Namespace: testNSForStale,
				Kind:      constants.ServiceKind,
				Service: &mcsv1alpha1.ServiceExport{
					ServiceSpec: corev1.ServiceSpec{
						Ports: svcPorts,
					},
				},
			},
		}

		Expect(k8sClient.Create(ctx, svcExp)).Should(Succeed())
		Expect(k8sClient.Create(ctx, svcResExpFromA)).Should(Succeed())
		Expect(k8sClient.Create(ctx, svcResExpToBeDeletedFromA)).Should(Succeed())
		Expect(k8sClient.Create(ctx, svcResExpFromB)).Should(Succeed())

		Eventually(func() bool {
			resExpList := &mcsv1alpha1.ResourceExportList{}
			err := k8sClient.List(ctx, resExpList, &client.ListOptions{Namespace: LeaderNamespace})
			Expect(err).ToNot(HaveOccurred())
			return len(resExpList.Items) == 2
		}, timeout, interval).Should(BeTrue())
	})
})
