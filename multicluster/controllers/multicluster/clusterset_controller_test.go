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
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
)

var _ = Describe("ClusterSet controller", func() {
	ctx := context.Background()
	It("Should create a MemberAnnounce when a new ClusterSet is created", func() {
		By("By claim a member cluster and a clusterset")
		clusterIDClaim := &mcsv1alpha1.ClusterClaim{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: LeaderNamespace,
				Name:      "local-cluster-id",
			},
			Name:  "id.k8s.io",
			Value: LocalClusterID,
		}
		clusterSetIDClaim := &mcsv1alpha1.ClusterClaim{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: LeaderNamespace,
				Name:      "clusterset-id",
			},
			Name:  "clusterSet.k8s.io",
			Value: clusterSetID,
		}
		clusterSet := &mcsv1alpha1.ClusterSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: LeaderNamespace,
				Name:      clusterSetID,
			},
			Spec: mcsv1alpha1.ClusterSetSpec{
				Leaders: []mcsv1alpha1.MemberCluster{
					{
						ClusterID: LocalClusterID,
						Secret:    "access-token",
						Server:    k8sServerURL,
					},
				},
				Members: []mcsv1alpha1.MemberCluster{
					{
						ClusterID: LocalClusterID,
					},
				},
				Namespace: LeaderNamespace,
			},
		}
		_, err := antreaMcsCrdClient.MulticlusterV1alpha1().ClusterClaims(LeaderNamespace).Create(ctx, clusterIDClaim, metav1.CreateOptions{})
		Expect(err == nil).Should(BeTrue())
		_, err = antreaMcsCrdClient.MulticlusterV1alpha1().ClusterClaims(LeaderNamespace).Create(ctx, clusterSetIDClaim, metav1.CreateOptions{})
		Expect(err == nil).Should(BeTrue())
		_, err = antreaMcsCrdClient.MulticlusterV1alpha1().ClusterSets(LeaderNamespace).Create(ctx, clusterSet, metav1.CreateOptions{})
		Expect(err == nil).Should(BeTrue())
		Eventually(func() bool {
			_, err = antreaMcsCrdClient.MulticlusterV1alpha1().MemberClusterAnnounces(LeaderNamespace).Get(ctx, "member-announce-from-cluster-a", metav1.GetOptions{})
			return err == nil
		}, timeout, interval).Should(BeTrue())
	})
})
