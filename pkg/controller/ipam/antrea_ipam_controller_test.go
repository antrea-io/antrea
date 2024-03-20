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

package ipam

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
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

type fakeAntreaIPAMController struct {
	*AntreaIPAMController
	fakeK8sClient      *fake.Clientset
	fakeCRDClient      *fakecrd.Clientset
	informerFactory    informers.SharedInformerFactory
	crdInformerFactory crdinformers.SharedInformerFactory
	poolLister         listers.IPPoolLister
}

func newFakeAntreaIPAMController(pool *crdv1a2.IPPool, namespace *corev1.Namespace, statefulSet *appsv1.StatefulSet) *fakeAntreaIPAMController {
	crdClient := fakecrd.NewSimpleClientset(pool)
	k8sClient := fake.NewSimpleClientset(namespace, statefulSet)

	informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)
	namespaceInformer := informerFactory.Core().V1().Namespaces()
	podInformer := informerFactory.Core().V1().Pods()
	statefulSetInformer := informerFactory.Apps().V1().StatefulSets()
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	poolInformer := crdInformerFactory.Crd().V1alpha2().IPPools()
	poolLister := poolInformer.Lister()

	controller := NewAntreaIPAMController(crdClient, poolInformer, namespaceInformer, podInformer, statefulSetInformer)
	return &fakeAntreaIPAMController{
		AntreaIPAMController: controller,
		fakeK8sClient:        k8sClient,
		fakeCRDClient:        crdClient,
		informerFactory:      informerFactory,
		crdInformerFactory:   crdInformerFactory,
		poolLister:           poolLister,
	}
}

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

	err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, 1*time.Second, true,
		func(ctx context.Context) (bool, error) {
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

func TestStatefulSetLifecycle(t *testing.T) {

	tests := []struct {
		name                string
		dedicatedPool       bool
		replicas            int32
		expectAllocatedSize int
	}{
		{
			name:                "Dedicated pool",
			dedicatedPool:       true,
			replicas:            5,
			expectAllocatedSize: 5,
		},
		{
			name:                "Full reservation of dedicated pool",
			dedicatedPool:       true,
			replicas:            11,
			expectAllocatedSize: 11,
		},
		{
			name:                "Namespace pool",
			dedicatedPool:       false,
			replicas:            7,
			expectAllocatedSize: 7,
		},
		{
			name:                "No enough IPs",
			dedicatedPool:       false,
			replicas:            20,
			expectAllocatedSize: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)

			namespace, pool, statefulSet := initTestObjects(!tt.dedicatedPool, tt.dedicatedPool, tt.replicas)
			controller := newFakeAntreaIPAMController(pool, namespace, statefulSet)
			controller.informerFactory.Start(stopCh)
			controller.crdInformerFactory.Start(stopCh)

			go controller.Run(stopCh)

			var allocator *poolallocator.IPPoolAllocator
			var err error
			// Wait until pool propagates to the informer
			pollErr := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, 3*time.Second, true,
				func(ctx context.Context) (bool, error) {
					allocator, err = poolallocator.NewIPPoolAllocator(pool.Name, controller.crdClient, controller.poolLister)
					if err != nil {
						return false, nil
					}
					return true, nil
				})
			require.NoError(t, pollErr)
			defer allocator.ReleaseStatefulSet(statefulSet.Namespace, statefulSet.Name)

			// Verify create event was handled by the controller
			verifyPoolAllocatedSize(t, pool.Name, controller.poolLister, tt.expectAllocatedSize)

			// Delete StatefulSet
			controller.fakeK8sClient.AppsV1().StatefulSets(namespace.Name).Delete(context.TODO(), statefulSet.Name, metav1.DeleteOptions{})

			// Verify Delete event was processed
			verifyPoolAllocatedSize(t, pool.Name, controller.poolLister, 0)
		})
	}
}

// Test for cleanup on controller startup: stale addresses that belong no StatefulSet objects
// that no longer exist should be cleaned up.
func TestReleaseStaleAddresses(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	namespace, pool, statefulSet := initTestObjects(true, false, 0)

	activeSetOwner := crdv1a2.StatefulSetOwner{
		Name:      statefulSet.Name,
		Namespace: namespace.Name,
	}

	staleSetOwner := crdv1a2.StatefulSetOwner{
		Name:      uuid.New().String(),
		Namespace: namespace.Name,
	}

	stalePodOwner := crdv1a2.PodOwner{
		Name:      uuid.New().String(),
		Namespace: namespace.Name,
	}

	addresses := []crdv1a2.IPAddressState{
		{IPAddress: "10.2.2.12",
			Phase: crdv1a2.IPAddressPhaseReserved,
			Owner: crdv1a2.IPAddressOwner{StatefulSet: &activeSetOwner}},
		{IPAddress: "20.2.2.13",
			Phase: crdv1a2.IPAddressPhaseReserved,
			Owner: crdv1a2.IPAddressOwner{StatefulSet: &staleSetOwner}},
		{IPAddress: "20.2.2.14",
			Phase: crdv1a2.IPAddressPhaseReserved,
			Owner: crdv1a2.IPAddressOwner{StatefulSet: &staleSetOwner}},
		{IPAddress: "20.2.2.15",
			Phase: crdv1a2.IPAddressPhaseAllocated,
			Owner: crdv1a2.IPAddressOwner{StatefulSet: &activeSetOwner,
				Pod: &stalePodOwner},
		},
	}

	pool.Status = crdv1a2.IPPoolStatus{
		IPAddresses: addresses,
	}

	controller := newFakeAntreaIPAMController(pool, namespace, statefulSet)
	controller.informerFactory.Start(stopCh)
	controller.crdInformerFactory.Start(stopCh)

	go controller.Run(stopCh)

	// verify two stale entries were deleted, one updated to Reserved status
	err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, 2*time.Second, true, func(ctx context.Context) (bool, error) {
		pool, err := controller.poolLister.Get(pool.Name)
		if err != nil {
			return false, nil
		}

		if len(pool.Status.IPAddresses) != 2 {
			t.Logf("IP Pool status: %v", pool.Status.IPAddresses)
			return false, nil
		}

		for _, addr := range pool.Status.IPAddresses {
			if addr.Phase != crdv1a2.IPAddressPhaseReserved {
				return true, fmt.Errorf("Incorrect phase %s after cleanup", addr.Phase)
			}
		}

		return true, nil
	})

	require.NoError(t, err)
}

func TestAntreaIPAMController_getIPPoolsForStatefulSet(t *testing.T) {
	tests := []struct {
		name        string
		prepareFunc func(*appsv1.StatefulSet)
		hasIPPool   bool
		expectedIPs []net.IP
	}{
		{
			name: "no annotation",
			prepareFunc: func(sts *appsv1.StatefulSet) {
				delete(sts.Spec.Template.Annotations, annotation.AntreaIPAMAnnotationKey)
			},
			hasIPPool:   false,
			expectedIPs: nil,
		},
		{
			name:        "ippool",
			prepareFunc: func(sts *appsv1.StatefulSet) {},
			hasIPPool:   true,
			expectedIPs: nil,
		},
		{
			name: "valid ip",
			prepareFunc: func(sts *appsv1.StatefulSet) {
				sts.Spec.Template.Annotations[annotation.AntreaIPAMPodIPAnnotationKey] = "10.2.2.109"
			},
			hasIPPool:   true,
			expectedIPs: []net.IP{net.ParseIP("10.2.2.109")},
		},
		{
			name: "invalid ip",
			prepareFunc: func(sts *appsv1.StatefulSet) {
				sts.Spec.Template.Annotations[annotation.AntreaIPAMPodIPAnnotationKey] = "10.2.2.109, a.b.c.d"
			},
			hasIPPool:   true,
			expectedIPs: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			namespace, pool, statefulSet := initTestObjects(false, true, 1)
			tt.prepareFunc(statefulSet)
			controller := newFakeAntreaIPAMController(pool, namespace, statefulSet)
			controller.informerFactory.Start(stopCh)
			controller.crdInformerFactory.Start(stopCh)

			got, got1 := controller.getIPPoolsForStatefulSet(statefulSet)
			var want []string
			if tt.hasIPPool {
				want = []string{pool.Name}
			}
			assert.Equalf(t, want, got, "Unexpected IPPool result")
			assert.Equalf(t, tt.expectedIPs, got1, "Unexpected IP result")
		})
	}
}
