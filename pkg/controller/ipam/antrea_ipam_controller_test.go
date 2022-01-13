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
	"testing"
	"time"

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
	"antrea.io/antrea/pkg/ipam/poolallocator"
)

var (
	testPool     = "test-pool"
	testWithPool = "test-pool"
	testNoPool   = "test-no-pool"
	testStale    = "test-stale"
)

// StatefulSet objects are not defined here, since IPAM annotations
// are configured on Pods which belong to the StatefulSet via "app" label.
func initTestClients(pool *crdv1a2.IPPool) (*fake.Clientset, *fakecrd.Clientset) {
	crdClient := fakecrd.NewSimpleClientset(pool)

	k8sClient := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        testWithPool,
				Annotations: map[string]string{AntreaIPAMAnnotationKey: testPool},
			},
		},
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNoPool,
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testNoPool,
				Namespace: testWithPool,
				Labels:    map[string]string{"app": testNoPool},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{AntreaIPAMAnnotationKey: testPool},
				Labels:      map[string]string{"app": testWithPool},
				Namespace:   testNoPool,
			},
		},
		&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testWithPool,
				Namespace: testNoPool,
			},
		},
	)

	return k8sClient, crdClient
}

func verifyPoolAllocatedSize(t *testing.T, poolLister listers.IPPoolLister, size int) {

	err := wait.PollImmediate(100*time.Millisecond, 1*time.Second, func() (bool, error) {
		pool, err := poolLister.Get(testPool)
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

// This test verifies release of reserved IPs for dedicated IP pool annotation,
// as well as namespace-based IP Pool annotation.
func TestReleaseStatefulSet(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	ipRange := crdv1a2.IPRange{
		Start: "10.2.2.100",
		End:   "10.2.2.200",
	}

	subnetInfo := crdv1a2.SubnetInfo{
		Gateway:      "10.2.2.1",
		PrefixLength: 24,
	}

	subnetRange := crdv1a2.SubnetIPRange{IPRange: ipRange,
		SubnetInfo: subnetInfo}

	pool := crdv1a2.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: testPool},
		Spec: crdv1a2.IPPoolSpec{
			IPRanges: []crdv1a2.SubnetIPRange{subnetRange},
		},
	}

	k8sClient, crdClient := initTestClients(&pool)

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
		allocator, err = poolallocator.NewIPPoolAllocator(testPool, crdClient, poolLister)
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	require.NoError(t, pollErr)

	verifyPoolAllocatedSize(t, poolLister, 0)

	// Allocate StatefulSet with dedicated IP Pool
	err = allocator.AllocateStatefulSet(testNoPool, testWithPool, 5)
	require.NoError(t, err, "Failed to reserve IPs for StatefulSet")
	verifyPoolAllocatedSize(t, poolLister, 5)

	// Allocate StatefulSet with namespace-based IP Pool annotation
	err = allocator.AllocateStatefulSet(testWithPool, testNoPool, 3)
	require.NoError(t, err, "Failed to reserve IPs for StatefulSet")
	verifyPoolAllocatedSize(t, poolLister, 8)

	// Delete StatefulSet with namespace-based IP Pool annotation
	controller.enqueueStatefulSetDeleteEvent(&appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testNoPool,
			Namespace: testWithPool,
		}})

	// Verify delete event was handled by the controller
	verifyPoolAllocatedSize(t, poolLister, 5)

	// Delete StatefulSet with dedicated IP Pool
	controller.enqueueStatefulSetDeleteEvent(&appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testWithPool,
			Namespace: testNoPool,
		}})

	// Verify delete event was handled by the controller
	verifyPoolAllocatedSize(t, poolLister, 0)
}

// Test for cleanup on controller startup: stale addresses that belong no StatefulSet objects
// that no longer exist should be cleaned up.
func TestReleaseStaleAddresses(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	ipRange := crdv1a2.IPRange{
		CIDR: "10.2.2.0/24",
	}

	subnetInfo := crdv1a2.SubnetInfo{
		Gateway:      "10.2.2.1",
		PrefixLength: 24,
	}

	subnetRange := crdv1a2.SubnetIPRange{IPRange: ipRange,
		SubnetInfo: subnetInfo}

	// pool includes two entries for non-existent StatefulSet at startup
	// as well as one legit entry
	activeSetOwner := crdv1a2.StatefulSetOwner{
		Name:      testWithPool,
		Namespace: testNoPool,
		Index:     0,
	}

	staleSetOwner := crdv1a2.StatefulSetOwner{
		Name:      testStale,
		Namespace: testNoPool,
		Index:     0,
	}

	addresses := []crdv1a2.IPAddressState{
		{IPAddress: "10.2.2.12",
			Phase: crdv1a2.IPAddressPhasePreallocated,
			Owner: crdv1a2.IPAddressOwner{StatefulSet: &activeSetOwner}},
		{IPAddress: "20.1.1.100",
			Phase: crdv1a2.IPAddressPhasePreallocated,
			Owner: crdv1a2.IPAddressOwner{StatefulSet: &staleSetOwner}},
		{IPAddress: "20.1.1.200",
			Phase: crdv1a2.IPAddressPhasePreallocated,
			Owner: crdv1a2.IPAddressOwner{StatefulSet: &staleSetOwner}},
	}
	pool := crdv1a2.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: testPool},
		Spec: crdv1a2.IPPoolSpec{
			IPRanges: []crdv1a2.SubnetIPRange{subnetRange},
		},
		Status: crdv1a2.IPPoolStatus{
			IPAddresses: addresses,
		},
	}

	k8sClient, crdClient := initTestClients(&pool)

	informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)

	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	poolInformer := crdInformerFactory.Crd().V1alpha2().IPPools()
	poolLister := poolInformer.Lister()

	controller := NewAntreaIPAMController(crdClient, informerFactory, crdInformerFactory)
	require.NotNil(t, controller)
	informerFactory.Start(stopCh)
	crdInformerFactory.Start(stopCh)

	go controller.Run(stopCh)

	// Wait until pool propagates to the informer
	pollErr := wait.PollImmediate(100*time.Millisecond, 1*time.Second, func() (bool, error) {
		_, err := poolallocator.NewIPPoolAllocator(testPool, crdClient, poolLister)
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	require.NoError(t, pollErr)

	// after cleanup pool should have single entry
	verifyPoolAllocatedSize(t, poolLister, 1)
}
