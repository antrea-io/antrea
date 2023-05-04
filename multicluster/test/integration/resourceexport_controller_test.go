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
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	mcs "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"antrea.io/antrea/multicluster/apis/multicluster/constants"
	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/leader"
)

// This file contains test cases for below basic scenarios:
//  * Create ResourceImports when two ResourceExports are created
//  * Update ResourceImports when one ResourceExports are removed
//  * Delete ResourceImport when all ResourceExports are removed

var (
	testLeaderNS = "leaderns-one"
)

var _ = Describe("ResourceExport controller", func() {
	const (
		timeout   = time.Second * 15
		interval  = time.Second * 1
		namespace = "kube-system"
	)
	svcName, epName := "busybox", "busybox"
	clusteraID := "clustera"
	clusterbID := "clusterb"
	svcResExportNameA := clusteraID + "-" + namespace + "-" + svcName + "-service"
	epResExportNameA := clusteraID + "-" + namespace + "-" + epName + "-endpoints"
	svcResExportNameB := clusterbID + "-" + namespace + "-" + svcName + "-service"
	epResExportNameB := clusterbID + "-" + namespace + "-" + epName + "-endpoints"

	leaderNamespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testLeaderNS,
		},
	}

	svcResExportA := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcResExportNameA,
			Namespace: testLeaderNS,
			Labels: map[string]string{
				constants.SourceNamespace: namespace,
				constants.SourceName:      svcName,
				constants.SourceKind:      constants.ServiceKind,
				constants.SourceClusterID: clusteraID,
			},
			Generation: 1,
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			ClusterID: clusteraID,
			Name:      svcName,
			Namespace: namespace,
			Kind:      constants.ServiceKind,
			Service: &mcsv1alpha1.ServiceExport{
				ServiceSpec: corev1.ServiceSpec{
					Ports: svcPorts,
				},
			},
		},
	}
	epResExportA := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      epResExportNameA,
			Namespace: testLeaderNS,
			Labels: map[string]string{
				constants.SourceNamespace: namespace,
				constants.SourceName:      epName,
				constants.SourceKind:      constants.EndpointsKind,
				constants.SourceClusterID: clusteraID,
			},
			Generation: 1,
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			ClusterID: clusteraID,
			Name:      epName,
			Namespace: namespace,
			Kind:      constants.EndpointsKind,
			Endpoints: &mcsv1alpha1.EndpointsExport{
				Subsets: []corev1.EndpointSubset{
					{
						Addresses: []corev1.EndpointAddress{
							addr1,
						},
						Ports: epPorts,
					},
				},
			},
		},
	}
	svcResExportB := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcResExportNameB,
			Namespace: testLeaderNS,
			Labels: map[string]string{
				constants.SourceNamespace: namespace,
				constants.SourceName:      svcName,
				constants.SourceKind:      constants.ServiceKind,
				constants.SourceClusterID: clusterbID,
			},
			Generation: 1,
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			ClusterID: clusterbID,
			Name:      epName,
			Namespace: namespace,
			Kind:      constants.ServiceKind,
			Service: &mcsv1alpha1.ServiceExport{
				ServiceSpec: corev1.ServiceSpec{
					Ports: svcPorts,
				},
			},
		},
	}
	epResExportB := &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      epResExportNameB,
			Namespace: testLeaderNS,
			Labels: map[string]string{
				constants.SourceNamespace: namespace,
				constants.SourceName:      epName,
				constants.SourceKind:      constants.EndpointsKind,
				constants.SourceClusterID: clusterbID,
			},
			Generation: 1,
			Finalizers: []string{constants.ResourceExportFinalizer},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			ClusterID: clusterbID,
			Name:      epName,
			Namespace: namespace,
			Kind:      constants.EndpointsKind,
			Endpoints: &mcsv1alpha1.EndpointsExport{
				Subsets: []corev1.EndpointSubset{
					{
						Addresses: []corev1.EndpointAddress{
							addr2,
							addr3,
						},
						Ports: epPorts,
					},
				},
			},
		},
	}
	svcResImportName := leader.GetResourceImportName(svcResExportA)
	epResImportName := leader.GetResourceImportName(epResExportA)
	expectedSvcImportSpec := mcs.ServiceImportSpec{
		Ports: leader.SvcPortsConverter(svcPorts),
		Type:  mcs.ClusterSetIP,
	}
	ctx := context.Background()
	It("Should create ResourceImports when two ResourceExports are created", func() {
		By("By exposing two Clusters' ResourceExports")
		Expect(k8sClient.Create(ctx, leaderNamespace)).Should(Succeed())
		err := k8sClient.Create(ctx, svcResExportA, &client.CreateOptions{})
		Expect(err == nil).Should(BeTrue())
		err = k8sClient.Create(ctx, epResExportA, &client.CreateOptions{})
		Expect(err == nil).Should(BeTrue())

		svcResImport := &mcsv1alpha1.ResourceImport{}
		Eventually(func() bool {
			err = k8sClient.Get(ctx, svcResImportName, svcResImport)
			return err == nil
		}, timeout, interval).Should(BeTrue())
		Expect(svcResImport.Spec.ServiceImport.Spec).Should(Equal(expectedSvcImportSpec))

		epResImport := &mcsv1alpha1.ResourceImport{}
		Eventually(func() bool {
			err = k8sClient.Get(ctx, epResImportName, epResImport)
			return err == nil
		}, timeout, interval).Should(BeTrue())
		Expect(epResImport.Spec.Endpoints.Subsets).Should(Equal(epResExportA.Spec.Endpoints.Subsets))

		expectedSubsets := append(epResExportA.Spec.Endpoints.Subsets, epResExportB.Spec.Endpoints.Subsets...)
		err = k8sClient.Create(ctx, svcResExportB, &client.CreateOptions{})
		Expect(err == nil).Should(BeTrue())
		err = k8sClient.Create(ctx, epResExportB, &client.CreateOptions{})
		Expect(err == nil).Should(BeTrue())

		// wait 2s for ResourceImport update
		time.Sleep(2 * time.Second)
		err = k8sClient.Get(ctx, epResImportName, epResImport)
		Expect(elementsMatch(epResImport.Spec.Endpoints.Subsets, expectedSubsets)).Should(BeTrue())
	})

	It("Should update ResourceImports when a member cluster's ResourceExports are removed", func() {
		By("By deleting one member cluster's ResourceExports")
		err := k8sClient.Delete(ctx, &mcsv1alpha1.ResourceExport{ObjectMeta: metav1.ObjectMeta{Namespace: testLeaderNS, Name: svcResExportNameA}}, &client.DeleteOptions{})
		Expect(err == nil).Should(BeTrue())
		err = k8sClient.Delete(ctx, &mcsv1alpha1.ResourceExport{ObjectMeta: metav1.ObjectMeta{Namespace: testLeaderNS, Name: epResExportNameA}}, &client.DeleteOptions{})
		Expect(err == nil).Should(BeTrue())

		// wait 5s for ResourceImport update
		time.Sleep(5 * time.Second)
		epResImport := &mcsv1alpha1.ResourceImport{}
		err = k8sClient.Get(ctx, epResImportName, epResImport)
		Expect(err == nil).Should(BeTrue())
		Expect(epResImport.Spec.Endpoints.Subsets).Should(Equal(epResExportB.Spec.Endpoints.Subsets))
		svcResImport := &mcsv1alpha1.ResourceImport{}
		err = k8sClient.Get(ctx, svcResImportName, svcResImport)
		Expect(err == nil).Should(BeTrue())
		Expect(svcResImport.Spec.ServiceImport.Spec).Should(Equal(expectedSvcImportSpec))
	})

	It("Should delete ResourceImport when all member cluster's ResourceExports are removed", func() {
		By("By deleting all member cluster's ResourceExports")
		err := k8sClient.Delete(ctx, &mcsv1alpha1.ResourceExport{ObjectMeta: metav1.ObjectMeta{Namespace: testLeaderNS, Name: svcResExportNameB}}, &client.DeleteOptions{})
		Expect(err == nil).Should(BeTrue())
		err = k8sClient.Delete(ctx, &mcsv1alpha1.ResourceExport{ObjectMeta: metav1.ObjectMeta{Namespace: testLeaderNS, Name: epResExportNameB}}, &client.DeleteOptions{})
		Expect(err == nil).Should(BeTrue())

		// wait 2s for ResourceImport deletion
		time.Sleep(2 * time.Second)
		resImp := &mcsv1alpha1.ResourceImport{}
		err = k8sClient.Get(ctx, epResImportName, resImp)
		Expect(apierrors.IsNotFound(err)).Should(BeTrue())
		err = k8sClient.Get(ctx, svcResImportName, resImp)
		Expect(apierrors.IsNotFound(err)).Should(BeTrue())
	})
})

type dummyT struct{}

func (t dummyT) Errorf(string, ...interface{}) {}

// compare array ignoring the order of elements.
func elementsMatch(listA, listB interface{}) bool {
	return assert.ElementsMatch(dummyT{}, listA, listB)
}
