// Copyright 2021 Antrea Authors
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

// Package networkpolicy provides AntreaIPAMController implementation to manage
// and synchronize the GroupMembers and Namespaces affected by Network Policies and enforce
// their rules.
package ipam

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	fakecrd "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	listers "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	annotation "antrea.io/antrea/pkg/ipam"
	"antrea.io/antrea/pkg/ipam/poolallocator"
)

func initTestObjects(annotateNamespace bool, annotateStatefulSet bool, replicas int32) (*corev1.Namespace, *crdv1a2.IPPool, *appsv1.StatefulSet) {
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: uuid.New().String(),
		},
	}

	subnetRange := crdv1a2.SubnetIPRange{
		IPRange: crdv1a2.IPRange{
			Start: "10.2.2.100",
			End:   "10.2.2.110",
		},
		SubnetInfo: crdv1a2.SubnetInfo{
			Gateway:      "10.2.2.1",
			PrefixLength: 24,
		},
	}

	pool := &crdv1a2.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: uuid.New().String()},
		Spec: crdv1a2.IPPoolSpec{
			IPRanges: []crdv1a2.SubnetIPRange{subnetRange},
		},
	}

	if annotateNamespace {
		namespace.Annotations = map[string]string{annotation.AntreaIPAMAnnotationKey: pool.Name}
	}

	statefulSet := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      uuid.New().String(),
			Namespace: namespace.Name,
		},
		Spec: appsv1.StatefulSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        namespace.Name,
					Annotations: map[string]string{annotation.AntreaIPAMAnnotationKey: pool.Name},
				},
			},
			Replicas: &replicas,
		},
	}

	if annotateStatefulSet {
		statefulSet.Spec.Template.Annotations = map[string]string{annotation.AntreaIPAMAnnotationKey: pool.Name}
	}

	return namespace, pool, statefulSet
}

func verifyPoolAllocatedSize(t *testing.T, poolName string, poolLister listers.IPPoolLister, size int) {

	err := wait.PollImmediate(100*time.Millisecond, 1*time.Second, func() (bool, error) {
		pool, err := poolLister.Get(poolName)
		if err != nil {
			return false, nil
		}
		if len(pool.Status.IPAddresses) == size {
			return true, nil
		}

		return false, nil
	})

	require.NoError(t, err)
}

func testStatefulSetLifecycle(t *testing.T, dedicatedPool bool, replicas int32) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	namespace, pool, statefulSet := initTestObjects(!dedicatedPool, dedicatedPool, replicas)
	crdClient := fakecrd.NewSimpleClientset(pool)
	k8sClient := fake.NewSimpleClientset(namespace, statefulSet)

	informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)

	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	poolInformer := crdInformerFactory.Crd().V1alpha2().IPPools()
	poolLister := poolInformer.Lister()

	controller := NewAntreaIPAMController(crdClient, informerFactory, crdInformerFactory)
	require.NotNil(t, controller)
	informerFactory.Start(stopCh)
	crdInformerFactory.Start(stopCh)

	go controller.Run(stopCh)

	var allocator *poolallocator.IPPoolAllocator
	var err error
	// Wait until pool propagates to the informer
	pollErr := wait.PollImmediate(100*time.Millisecond, 1*time.Second, func() (bool, error) {
		allocator, err = poolallocator.NewIPPoolAllocator(pool.Name, crdClient, poolLister)
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	require.NoError(t, pollErr)
	defer allocator.ReleaseStatefulSet(statefulSet.Namespace, statefulSet.Name)

	if int(replicas) < allocator.Total() {
		// Verify create event was handled by the controller and preallocation was succesfull
		verifyPoolAllocatedSize(t, pool.Name, poolLister, int(replicas))
	} else {
		// Not enough IPs in the pool - preallocation should fail
		verifyPoolAllocatedSize(t, pool.Name, poolLister, 0)
	}

	// Delete StatefulSet
	k8sClient.AppsV1().StatefulSets(namespace.Name).Delete(context.TODO(), statefulSet.Name, metav1.DeleteOptions{})

	// Verify Delete event was processed
	verifyPoolAllocatedSize(t, pool.Name, poolLister, 0)
}

// This test verifies preallocation of IPs for dedicated IP pool annotation.
func TestStatefulSetLifecycle_DedicatedPool(t *testing.T) {
	testStatefulSetLifecycle(t, true, 5)
}

// This test verifies preallocation of IPs for IP pool annotation based on StatefulSet Namespace.
func TestStatefulSetLifecycle_NamespacePool(t *testing.T) {
	testStatefulSetLifecycle(t, false, 7)
}

// This test verifies use case when continuous IP range can not be preallocated.
// However we don't expect error since preallocation is best-effort feature.
func TestStatefulSetLifecycle_NoPreallocation(t *testing.T) {
	testStatefulSetLifecycle(t, false, 20)
}

// Test for cleanup on controller startup: stale addresses that belong no StatefulSet objects
// that no longer exist should be cleaned up.
func TestReleaseStaleAddresses(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	namespace, pool, statefulSet := initTestObjects(true, false, 7)

	activeSetOwner := crdv1a2.StatefulSetOwner{
		Name:      statefulSet.Name,
		Namespace: namespace.Name,
	}

	staleSetOwner := crdv1a2.StatefulSetOwner{
		Name:      uuid.New().String(),
		Namespace: namespace.Name,
	}

	addresses := []crdv1a2.IPAddressState{
		{IPAddress: "10.2.2.12",
			Phase: crdv1a2.IPAddressPhaseReserved,
			Owner: crdv1a2.IPAddressOwner{StatefulSet: &activeSetOwner}},
		{IPAddress: "20.1.1.100",
			Phase: crdv1a2.IPAddressPhaseReserved,
			Owner: crdv1a2.IPAddressOwner{StatefulSet: &staleSetOwner}},
		{IPAddress: "20.1.1.200",
			Phase: crdv1a2.IPAddressPhaseReserved,
			Owner: crdv1a2.IPAddressOwner{StatefulSet: &staleSetOwner}},
	}

	pool.Status = crdv1a2.IPPoolStatus{
		IPAddresses: addresses,
	}

	crdClient := fakecrd.NewSimpleClientset(pool)
	k8sClient := fake.NewSimpleClientset(namespace, statefulSet)

	informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)

	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	poolInformer := crdInformerFactory.Crd().V1alpha2().IPPools()
	poolLister := poolInformer.Lister()

	controller := NewAntreaIPAMController(crdClient, informerFactory, crdInformerFactory)
	require.NotNil(t, controller)
	informerFactory.Start(stopCh)
	crdInformerFactory.Start(stopCh)

	go controller.Run(stopCh)

	// after cleanup pool should have single entry
	verifyPoolAllocatedSize(t, pool.Name, poolLister, 1)
}
