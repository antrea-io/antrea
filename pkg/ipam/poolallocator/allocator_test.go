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

package poolallocator

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	crdv1b1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	informers "antrea.io/antrea/v2/pkg/client/informers/externalversions"
	crdlisters "antrea.io/antrea/v2/pkg/client/listers/crd/v1beta1"
	fakepoolclient "antrea.io/antrea/v2/pkg/ipam/poolallocator/testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
)

var testNamespace = "test"

var fakePodOwner = crdv1b1.IPAddressOwner{
	Pod: &crdv1b1.PodOwner{
		Name:        "fakePod",
		Namespace:   testNamespace,
		ContainerID: uuid.NewV4().String(),
	},
}

func newTestIPPoolAllocator(pool *crdv1b1.IPPool, stopCh <-chan struct{}) *IPPoolAllocator {

	crdClient := fakepoolclient.NewIPPoolClient()

	crdInformerFactory := informers.NewSharedInformerFactory(crdClient, 0)
	pools := crdInformerFactory.Crd().V1beta1().IPPools()
	poolInformer := pools.Informer()

	go crdInformerFactory.Start(stopCh)

	crdClient.CrdV1beta1().IPPools().Create(context.Background(), pool, metav1.CreateOptions{})
	cache.WaitForCacheSync(stopCh, poolInformer.HasSynced)

	var allocator *IPPoolAllocator
	var err error
	wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, 1*time.Second, true, func(ctx context.Context) (bool, error) {
		allocator, err = NewIPPoolAllocator(pool.Name, crdClient, pools.Lister())
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	return allocator
}

func validateAllocationSequence(t *testing.T, allocator *IPPoolAllocator, subnetInfo crdv1b1.SubnetInfo, ipList []string) {
	i := 1
	for _, expectedIP := range ipList {
		klog.Info("Validating allocation for ", expectedIP)
		owner := crdv1b1.IPAddressOwner{
			Pod: &crdv1b1.PodOwner{
				Name:        fmt.Sprintf("fakePod%d", i),
				Namespace:   testNamespace,
				ContainerID: uuid.NewV4().String(),
			},
		}
		ip, returnInfo, err := allocator.AllocateNext(crdv1b1.IPAddressPhaseAllocated, owner)
		require.NoError(t, err)
		assert.Equal(t, net.ParseIP(expectedIP), ip)
		assert.Equal(t, subnetInfo, *returnInfo)
		i += 1
	}
}

func TestAllocateIP(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	poolName := uuid.NewV4().String()
	ipRange := crdv1b1.IPRange{
		Start: "10.2.2.100",
		End:   "10.2.2.120",
	}
	subnetInfo := crdv1b1.SubnetInfo{
		Gateway:      "10.2.2.1",
		PrefixLength: 24,
		VLAN:         100,
	}

	pool := crdv1b1.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec:       crdv1b1.IPPoolSpec{IPRanges: []crdv1b1.IPRange{ipRange}, SubnetInfo: subnetInfo},
	}

	allocator := newTestIPPoolAllocator(&pool, stopCh)
	require.NotNil(t, allocator)
	assert.Equal(t, 21, allocator.Total())

	// Allocate specific IP from the range
	returnInfo, err := allocator.AllocateIP(net.ParseIP("10.2.2.101"), crdv1b1.IPAddressPhaseAllocated, fakePodOwner)
	assert.Equal(t, subnetInfo, *returnInfo)
	require.NoError(t, err)

	// Validate IP outside the range is not allocated
	_, err = allocator.AllocateIP(net.ParseIP("10.2.2.121"), crdv1b1.IPAddressPhaseAllocated, fakePodOwner)
	require.Error(t, err)

	// Make sure IP allocated above is not allocated again
	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.100", "10.2.2.102"})

	// Validate error is returned if IP is already allocated
	_, err = allocator.AllocateIP(net.ParseIP("10.2.2.102"), crdv1b1.IPAddressPhaseAllocated, fakePodOwner)
	require.Error(t, err)
}

func TestAllocateNext(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	poolName := "fakePool"
	ipRange := crdv1b1.IPRange{
		Start: "10.2.2.100",
		End:   "10.2.2.120",
	}
	subnetInfo := crdv1b1.SubnetInfo{
		Gateway:      "10.2.2.1",
		PrefixLength: 24,
	}

	pool := crdv1b1.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec:       crdv1b1.IPPoolSpec{IPRanges: []crdv1b1.IPRange{ipRange}, SubnetInfo: subnetInfo},
	}

	allocator := newTestIPPoolAllocator(&pool, stopCh)
	require.NotNil(t, allocator)
	assert.Equal(t, 21, allocator.Total())

	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.100", "10.2.2.101"})
}

func TestAllocateNextConflictWithStaleLister(t *testing.T) {
	for _, tc := range []struct {
		name               string
		additionalConflict bool
		getError           bool
		sameOwner          bool
		fullPool           bool
		differentInterface bool
	}{
		{name: "refetch after conflict"},
		{name: "refetch after every conflict", additionalConflict: true},
		{name: "propagate refetch error", getError: true},
		{name: "reuse allocation for same owner", sameOwner: true},
		{name: "reuse allocation for same owner in full pool", sameOwner: true, fullPool: true},
		{name: "allocate separately for different interface", differentInterface: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := context.Background()
				client := fakepoolclient.NewIPPoolClient()
				endIP := "10.2.2.20"
				if tc.fullPool {
					endIP = "10.2.2.10"
				}
				pool, err := client.CrdV1beta1().IPPools().Create(ctx, &crdv1b1.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: "stale-pool"},
					Spec: crdv1b1.IPPoolSpec{
						IPRanges:   []crdv1b1.IPRange{{Start: "10.2.2.10", End: endIP}},
						SubnetInfo: crdv1b1.SubnetInfo{Gateway: "10.2.2.1", PrefixLength: 24},
					},
				}, metav1.CreateOptions{})
				require.NoError(t, err)
				// Keep the lister at A without a running informer to update it.
				indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
				require.NoError(t, indexer.Add(pool.DeepCopy()))
				lister := crdlisters.NewIPPoolLister(indexer)
				allocator, err := NewIPPoolAllocator(pool.Name, client, lister)
				require.NoError(t, err)
				versionA := pool.ResourceVersion
				otherOwner := crdv1b1.IPAddressOwner{Pod: &crdv1b1.PodOwner{
					Name: "other-pod", Namespace: testNamespace, ContainerID: "other-container",
				}}
				if tc.sameOwner {
					otherOwner = fakePodOwner
				} else if tc.differentInterface {
					otherOwner = *fakePodOwner.DeepCopy()
					otherOwner.Pod.IFName = "net1"
				}
				pool.Status.IPAddresses = []crdv1b1.IPAddressState{{
					IPAddress: "10.2.2.10", Phase: crdv1b1.IPAddressPhaseAllocated, Owner: otherOwner,
				}}
				pool, err = client.CrdV1beta1().IPPools().UpdateStatus(ctx, pool, metav1.UpdateOptions{})
				require.NoError(t, err)
				versionB := pool.ResourceVersion
				intermediatePool := pool.DeepCopy()
				expectedVersions := []string{versionA, versionB}
				expectedIP := "10.2.2.11"
				expectedGetCalls := 1
				if tc.sameOwner {
					expectedVersions = []string{versionA}
					expectedIP = "10.2.2.10"
				}
				if tc.additionalConflict {
					pool.Status.IPAddresses = append(pool.Status.IPAddresses, crdv1b1.IPAddressState{
						IPAddress: "10.2.2.11", Phase: crdv1b1.IPAddressPhaseAllocated, Owner: otherOwner,
					})
					pool, err = client.CrdV1beta1().IPPools().UpdateStatus(ctx, pool, metav1.UpdateOptions{})
					require.NoError(t, err)
					expectedVersions = append(expectedVersions, pool.ResourceVersion)
					expectedIP = "10.2.2.12"
					expectedGetCalls++
				}
				existingAllocations := pool.DeepCopy().Status.IPAddresses
				var submittedVersions []string
				client.PrependReactor("update", "ippools", func(action k8stesting.Action) (bool, runtime.Object, error) {
					updated := action.(k8stesting.UpdateAction).GetObject().(*crdv1b1.IPPool)
					submittedVersions = append(submittedVersions, updated.ResourceVersion)
					// Let the fake client's actual ResourceVersion check reject stale writes.
					return false, nil, nil
				})
				getCalls := 0
				getErr := apierrors.NewServiceUnavailable("live GET failed")
				client.PrependReactor("get", "ippools", func(k8stesting.Action) (bool, runtime.Object, error) {
					getCalls++
					if tc.getError {
						return true, nil, getErr
					}
					if tc.additionalConflict && getCalls == 1 {
						// Model a GET of B followed by another writer advancing to C.
						return true, intermediatePool.DeepCopy(), nil
					}
					return false, nil, nil
				})

				ip, subnetInfo, err := allocator.AllocateNext(crdv1b1.IPAddressPhaseAllocated, fakePodOwner)
				if tc.getError {
					require.ErrorIs(t, err, getErr)
					assert.Equal(t, []string{versionA}, submittedVersions)
					assert.Equal(t, 1, getCalls)
				} else {
					require.NoError(t, err)
					assert.Equal(t, expectedIP, ip.String())
					assert.Equal(t, &pool.Spec.SubnetInfo, subnetInfo)
					assert.Equal(t, expectedVersions, submittedVersions)
					assert.Equal(t, expectedGetCalls, getCalls)
				}
				cached, err := lister.Get(pool.Name)
				require.NoError(t, err)
				assert.Equal(t, versionA, cached.ResourceVersion)
				assert.Empty(t, cached.Status.IPAddresses)
				stored, err := client.Tracker().Get(crdv1b1.SchemeGroupVersion.WithResource("ippools"), "", pool.Name)
				require.NoError(t, err)
				allocations := stored.(*crdv1b1.IPPool).Status.IPAddresses
				if tc.getError || tc.sameOwner {
					assert.Equal(t, existingAllocations, allocations)
				} else {
					require.Len(t, allocations, len(existingAllocations)+1)
					assert.Equal(t, existingAllocations, allocations[:len(existingAllocations)])
					assert.Equal(t, fakePodOwner, allocations[len(existingAllocations)].Owner)
				}
			})
		})
	}
}

func TestPoolUsageAfterConflictWithStaleLister(t *testing.T) {
	for _, operation := range []string{"allocate next", "allocate IP", "release container", "release IP"} {
		t.Run(operation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := context.Background()
				client := fakepoolclient.NewIPPoolClient()
				allocation := func(ip string, index int) crdv1b1.IPAddressState {
					return crdv1b1.IPAddressState{
						IPAddress: ip,
						Phase:     crdv1b1.IPAddressPhaseAllocated,
						Owner: crdv1b1.IPAddressOwner{Pod: &crdv1b1.PodOwner{
							Name:        fmt.Sprintf("pod-%d", index),
							Namespace:   testNamespace,
							ContainerID: fmt.Sprintf("container-%d", index),
							IFName:      "net1",
						}},
					}
				}
				pool, err := client.CrdV1beta1().IPPools().Create(ctx, &crdv1b1.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: "expanded-pool"},
					Spec: crdv1b1.IPPoolSpec{
						IPRanges:   []crdv1b1.IPRange{{Start: "10.2.2.10", End: "10.2.2.20"}},
						SubnetInfo: crdv1b1.SubnetInfo{Gateway: "10.2.2.1", PrefixLength: 24},
					},
					Status: crdv1b1.IPPoolStatus{
						IPAddresses: []crdv1b1.IPAddressState{allocation("10.2.2.10", 0)},
					},
				}, metav1.CreateOptions{})
				require.NoError(t, err)
				cachedPool := pool.DeepCopy()
				indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
				require.NoError(t, indexer.Add(cachedPool.DeepCopy()))
				lister := crdlisters.NewIPPoolLister(indexer)
				allocator, err := NewIPPoolAllocator(pool.Name, client, lister)
				require.NoError(t, err)

				// Expand and consume the live pool without updating the lister's 11-address snapshot.
				expectedIP := "10.2.2.31"
				if operation == "allocate IP" {
					// A requested IP must also be available in the cached range to reach the conflict retry.
					expectedIP = "10.2.2.11"
				}
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b1.IPRange{
					Start: "10.2.2.30", End: "10.2.2.40",
				})
				for i := 1; i <= 10; i++ {
					if operation == "allocate IP" && i == 1 {
						continue
					}
					pool.Status.IPAddresses = append(pool.Status.IPAddresses, allocation(fmt.Sprintf("10.2.2.%d", 10+i), i))
				}
				pool.Status.IPAddresses = append(pool.Status.IPAddresses, allocation("10.2.2.30", 11))
				if operation == "allocate IP" {
					pool.Status.IPAddresses = append(pool.Status.IPAddresses, allocation("10.2.2.32", 12))
				}
				pool, err = client.CrdV1beta1().IPPools().Update(ctx, pool, metav1.UpdateOptions{})
				require.NoError(t, err)
				expectedAllocations := pool.DeepCopy().Status.IPAddresses
				var submittedVersions []string
				client.PrependReactor("update", "ippools", func(action k8stesting.Action) (bool, runtime.Object, error) {
					updated := action.(k8stesting.UpdateAction).GetObject().(*crdv1b1.IPPool)
					submittedVersions = append(submittedVersions, updated.ResourceVersion)
					return false, nil, nil
				})
				getCalls := 0
				client.PrependReactor("get", "ippools", func(k8stesting.Action) (bool, runtime.Object, error) {
					getCalls++
					return false, nil, nil
				})

				if operation == "allocate next" || operation == "allocate IP" {
					var ip net.IP
					var subnetInfo *crdv1b1.SubnetInfo
					if operation == "allocate next" {
						ip, subnetInfo, err = allocator.AllocateNext(crdv1b1.IPAddressPhaseAllocated, fakePodOwner)
					} else {
						ip = net.ParseIP(expectedIP)
						subnetInfo, err = allocator.AllocateIP(ip, crdv1b1.IPAddressPhaseAllocated, fakePodOwner)
					}
					require.NoError(t, err)
					assert.Equal(t, expectedIP, ip.String())
					assert.Equal(t, &pool.Spec.SubnetInfo, subnetInfo)
					expectedAllocations = append(expectedAllocations, crdv1b1.IPAddressState{
						IPAddress: expectedIP, Phase: crdv1b1.IPAddressPhaseAllocated, Owner: fakePodOwner,
					})
				} else {
					if operation == "release container" {
						err = allocator.ReleaseContainer("container-0", "net1")
					} else {
						err = allocator.Release(net.ParseIP("10.2.2.10"))
					}
					require.NoError(t, err)
					expectedAllocations = expectedAllocations[1:]
				}

				assert.Equal(t, []string{cachedPool.ResourceVersion, pool.ResourceVersion}, submittedVersions)
				assert.Equal(t, 1, getCalls, "the conflict should trigger a live read")
				cached, err := lister.Get(pool.Name)
				require.NoError(t, err)
				assert.Equal(t, cachedPool, cached, "the lister must remain stale and unmodified")
				stored, err := client.Tracker().Get(crdv1b1.SchemeGroupVersion.WithResource("ippools"), "", pool.Name)
				require.NoError(t, err)
				updated := stored.(*crdv1b1.IPPool)
				assert.Equal(t, pool.Spec, updated.Spec)
				assert.Equal(t, expectedAllocations, updated.Status.IPAddresses)
				assert.Equal(t, 22, updated.Status.Usage.Total, "capacity must come from the expanded live pool")
				assert.Equal(t, len(expectedAllocations), updated.Status.Usage.Used)
			})
		})
	}
}

func TestAllocateNextConflictRetryLimit(t *testing.T) {
	steps := ipPoolStatusRetry.Steps
	for _, conflicts := range []int{steps - 1, steps} {
		t.Run(fmt.Sprintf("%d conflicts", conflicts), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				stopCh := make(chan struct{})
				defer close(stopCh)
				pool := &crdv1b1.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: "retry-pool"},
					Spec: crdv1b1.IPPoolSpec{
						IPRanges:   []crdv1b1.IPRange{{Start: "10.2.2.10", End: "10.2.2.20"}},
						SubnetInfo: crdv1b1.SubnetInfo{Gateway: "10.2.2.1", PrefixLength: 24},
					},
				}
				allocator := newTestIPPoolAllocator(pool, stopCh)
				require.NotNil(t, allocator)
				attempts := 0
				client := allocator.crdClient.(*fakepoolclient.IPPoolClientset)
				conflictErr := &apierrors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonConflict}}
				client.PrependReactor("update", "ippools", func(k8stesting.Action) (bool, runtime.Object, error) {
					attempts++
					if attempts <= conflicts {
						return true, nil, conflictErr
					}
					return false, nil, nil
				})
				ip, _, err := allocator.AllocateNext(crdv1b1.IPAddressPhaseAllocated, fakePodOwner)
				assert.Equal(t, steps, attempts, "all configured attempts should be available")
				if conflicts == steps-1 {
					require.NoError(t, err, "allocation should succeed on the final attempt")
					assert.Equal(t, net.ParseIP("10.2.2.10").String(), ip.String())
				} else {
					require.ErrorIs(t, err, conflictErr)
				}
				updated, err := client.CrdV1beta1().IPPools().Get(context.Background(), pool.Name, metav1.GetOptions{})
				require.NoError(t, err)
				if conflicts == steps-1 {
					assert.Len(t, updated.Status.IPAddresses, 1)
				} else {
					assert.Empty(t, updated.Status.IPAddresses)
				}
			})
		})
	}
}

// TestConcurrentAllocateNextSharedIPPool simulates many Nodes (or many Pods on
// different Nodes) calling AllocateNext on the same IPPool at once. The fake
// client returns 409-style conflicts when ResourceVersion is stale, matching
// concurrent UpdateStatus on a shared pool (e.g. several DaemonSets using the
// same Antrea IPPool for secondary networks). All goroutines must succeed with
// distinct IPs if ipPoolStatusRetry allows enough conflict retries.
//
// synctest.Test is used so that the time.Sleep calls inside retry.RetryOnConflict
// (driven by ipPoolStatusRetry backoff) use the fake clock instead of the real
// wall clock. When all worker goroutines are blocked on a backoff sleep, the
// synctest scheduler automatically advances fake time, so wg.Wait() returns as
// soon as all retries complete — no real delays, deterministic regardless of CI
// runner speed.
func TestConcurrentAllocateNextSharedIPPool(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stopCh := make(chan struct{})
		defer close(stopCh)

		// Six DaemonSets on a six-Node cluster all requesting the same pool is 36
		// concurrent status writers; keep headroom in the range.
		const concurrency = 36

		poolName := uuid.NewV4().String()
		ipRange := crdv1b1.IPRange{
			Start: "10.2.2.10",
			End:   "10.2.2.99", // 90 addresses
		}
		subnetInfo := crdv1b1.SubnetInfo{
			Gateway:      "10.2.2.1",
			PrefixLength: 24,
			VLAN:         101,
		}
		pool := crdv1b1.IPPool{
			ObjectMeta: metav1.ObjectMeta{Name: poolName},
			Spec:       crdv1b1.IPPoolSpec{IPRanges: []crdv1b1.IPRange{ipRange}, SubnetInfo: subnetInfo},
		}

		allocator := newTestIPPoolAllocator(&pool, stopCh)
		require.NotNil(t, allocator)
		require.GreaterOrEqual(t, allocator.Total(), concurrency)

		var wg sync.WaitGroup
		errs := make([]error, concurrency)
		ipStrs := make([]string, concurrency)

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				owner := crdv1b1.IPAddressOwner{
					Pod: &crdv1b1.PodOwner{
						Name:        fmt.Sprintf("concurrent-pod-%d", idx),
						Namespace:   testNamespace,
						ContainerID: uuid.NewV4().String(),
						IFName:      "net1",
					},
				}
				ip, _, err := allocator.AllocateNext(crdv1b1.IPAddressPhaseAllocated, owner)
				if err != nil {
					errs[idx] = err
					return
				}
				if ip == nil {
					errs[idx] = fmt.Errorf("worker %d: AllocateNext returned nil IP without error", idx)
					return
				}
				ipStrs[idx] = ip.String()
			}(i)
		}

		// wg.Wait() will block until all workers finish. When all workers are blocked on
		// time.Sleep (inside retry.RetryOnConflict backoff), the synctest runtime advances
		// the fake clock automatically, so conflicts are resolved without real delays.
		wg.Wait()

		for i, err := range errs {
			require.NoError(t, err, "AllocateNext for worker %d should succeed under contention", i)
			require.NotEmpty(t, ipStrs[i], "worker %d: no error but empty IP string returned", i)
		}
		seen := make(map[string]struct{}, concurrency)
		for _, s := range ipStrs {
			_, dup := seen[s]
			require.False(t, dup, "duplicate IP %s allocated", s)
			seen[s] = struct{}{}
		}
		require.Len(t, seen, concurrency, "expected a distinct IP per concurrent allocator")
	})
}

func TestAllocateNextMultiRange(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	poolName := uuid.NewV4().String()
	ipRange1 := crdv1b1.IPRange{
		Start: "10.2.2.100",
		End:   "10.2.2.101",
	}
	ipRange2 := crdv1b1.IPRange{CIDR: "10.2.2.0/28"}
	subnetInfo := crdv1b1.SubnetInfo{
		Gateway:      "10.2.2.1",
		PrefixLength: 24,
	}

	pool := crdv1b1.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec: crdv1b1.IPPoolSpec{
			IPRanges: []crdv1b1.IPRange{ipRange1, ipRange2}, SubnetInfo: subnetInfo},
	}

	allocator := newTestIPPoolAllocator(&pool, stopCh)
	require.NotNil(t, allocator)
	assert.Equal(t, 16, allocator.Total())

	// Allocate the 2 available IPs from first range then switch to second range
	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.100", "10.2.2.101", "10.2.2.2", "10.2.2.3"})
}

func TestAllocateNextMultiRangeExhausted(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	poolName := uuid.NewV4().String()
	ipRange1 := crdv1b1.IPRange{
		Start: "10.2.2.100",
		End:   "10.2.2.101",
	}
	ipRange2 := crdv1b1.IPRange{
		Start: "10.2.2.200",
		End:   "10.2.2.200",
	}
	subnetInfo := crdv1b1.SubnetInfo{
		Gateway:      "10.2.2.1",
		PrefixLength: 24,
	}
	pool := crdv1b1.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec: crdv1b1.IPPoolSpec{
			IPRanges:   []crdv1b1.IPRange{ipRange1, ipRange2},
			SubnetInfo: subnetInfo},
	}

	allocator := newTestIPPoolAllocator(&pool, stopCh)
	require.NotNil(t, allocator)
	assert.Equal(t, 3, allocator.Total())

	// Allocate all available IPs
	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.100", "10.2.2.101", "10.2.2.200"})

	// Allocate next IP and get error
	_, _, err := allocator.AllocateNext(crdv1b1.IPAddressPhaseAllocated, fakePodOwner)
	require.Error(t, err)
}

func TestAllocateReleaseSequence(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	poolName := uuid.NewV4().String()
	ipRange1 := crdv1b1.IPRange{
		Start: "2001::1000",
		End:   "2001::1000",
	}
	ipRange2 := crdv1b1.IPRange{CIDR: "2001::0/124"}
	subnetInfo := crdv1b1.SubnetInfo{
		Gateway:      "2001::1",
		PrefixLength: 64,
	}

	pool := crdv1b1.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec: crdv1b1.IPPoolSpec{
			IPRanges:   []crdv1b1.IPRange{ipRange1, ipRange2},
			SubnetInfo: subnetInfo},
	}

	allocator := newTestIPPoolAllocator(&pool, stopCh)
	require.NotNil(t, allocator)

	// Allocate the single available IPs from first range then 3 IPs from second range
	validateAllocationSequence(t, allocator, subnetInfo, []string{"2001::1000", "2001::2", "2001::3", "2001::4"})

	// Release first IP from first range and middle IP from second range
	for _, ipToRelease := range []string{"2001::1000", "2001::2"} {
		err := allocator.Release(net.ParseIP(ipToRelease))
		require.NoError(t, err)
	}

	validateAllocationSequence(t, allocator, subnetInfo, []string{"2001::1000", "2001::2", "2001::5"})
}

// releasePod releases the IP associated with the specified Pod, and updates the IPPool CR status.
// The func returns an error, if no IP is allocated to the Pod according to the IPPool CR status.
func (a *IPPoolAllocator) releasePod(namespace, podName string) error {
	// Retry on CRD update conflict which is caused by multiple agents updating a pool at same time.
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ipPool, err := a.getPool()
		if err != nil {
			return err
		}

		// Mark allocated IPs from pool status as unavailable
		for _, ip := range ipPool.Status.IPAddresses {
			if ip.Owner.Pod != nil && ip.Owner.Pod.Namespace == namespace && ip.Owner.Pod.Name == podName {
				allocators, err := a.initIPAllocators(ipPool)
				if err != nil {
					return err
				}
				return a.removeIPAddressState(ipPool, net.ParseIP(ip.IPAddress), allocators.Total())

			}
		}

		klog.V(4).InfoS("IP Pool state:", "name", a.ipPoolName, "allocation", ipPool.Status.IPAddresses)
		return fmt.Errorf("failed to find record of IP allocated to Pod:%s/%s in pool %s", namespace, podName, a.ipPoolName)
	})

	if err != nil {
		klog.ErrorS(err, "Failed to release IP address", "Namespace", namespace, "Pod", podName, "IPPool", a.ipPoolName)
	}
	return err
}

func TestReleaseResource(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	poolName := uuid.NewV4().String()
	ipRange1 := crdv1b1.IPRange{
		Start: "2001::1000",
		End:   "2001::1000",
	}
	ipRange2 := crdv1b1.IPRange{CIDR: "2001::0/124"}
	subnetInfo := crdv1b1.SubnetInfo{
		Gateway:      "2001::1",
		PrefixLength: 64,
	}

	pool := crdv1b1.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec: crdv1b1.IPPoolSpec{
			IPRanges:   []crdv1b1.IPRange{ipRange1, ipRange2},
			SubnetInfo: subnetInfo},
	}

	allocator := newTestIPPoolAllocator(&pool, stopCh)
	require.NotNil(t, allocator)
	assert.Equal(t, 15, allocator.Total())

	// Allocate the single available IPs from first range then 3 IPs from second range
	validateAllocationSequence(t, allocator, subnetInfo, []string{"2001::1000", "2001::2", "2001::3", "2001::4", "2001::5"})

	// Release first IP from first range and middle IP from second range
	for _, podName := range []string{"fakePod2", "fakePod4"} {
		err := allocator.releasePod(testNamespace, podName)
		require.NoError(t, err)
	}

	validateAllocationSequence(t, allocator, subnetInfo, []string{"2001::2", "2001::4", "2001::6"})
}

func TestHas(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	owner := crdv1b1.IPAddressOwner{
		Pod: &crdv1b1.PodOwner{
			Name:        "fakePod",
			Namespace:   testNamespace,
			ContainerID: "fakeContainer",
			IFName:      "eth1",
		},
	}
	poolName := uuid.NewV4().String()
	ipRange1 := crdv1b1.IPRange{
		Start: "2001::1000",
		End:   "2001::1000",
	}
	subnetInfo := crdv1b1.SubnetInfo{
		Gateway:      "2001::1",
		PrefixLength: 64,
	}
	pool := crdv1b1.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec: crdv1b1.IPPoolSpec{
			IPRanges:   []crdv1b1.IPRange{ipRange1},
			SubnetInfo: subnetInfo},
	}

	allocator := newTestIPPoolAllocator(&pool, stopCh)
	require.NotNil(t, allocator)

	_, _, err := allocator.AllocateNext(crdv1b1.IPAddressPhaseAllocated, owner)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		has, _ := allocator.hasPod(testNamespace, "fakePod")
		return has
	}, 1*time.Second, 100*time.Millisecond)

	has, err := allocator.hasPod(testNamespace, "realPod")
	require.NoError(t, err)
	assert.False(t, has)
	var ip net.IP
	ip, err = allocator.GetContainerIP("fakeContainer", "eth1")
	require.NoError(t, err)
	assert.NotNil(t, ip)
	ip, err = allocator.GetContainerIP("fakeContainer", "")
	require.NoError(t, err)
	assert.Nil(t, ip)
	ip, err = allocator.GetContainerIP("realContainer", "eth1")
	require.NoError(t, err)
	assert.Nil(t, ip)
}

func TestAllocateReleaseStatefulSet(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	poolName := uuid.NewV4().String()
	setName := "fakeSet"
	ipRange := crdv1b1.IPRange{
		Start: "10.2.2.100",
		End:   "10.2.2.120",
	}
	subnetInfo := crdv1b1.SubnetInfo{
		Gateway:      "10.2.2.1",
		PrefixLength: 24,
	}

	pool := crdv1b1.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec:       crdv1b1.IPPoolSpec{IPRanges: []crdv1b1.IPRange{ipRange}, SubnetInfo: subnetInfo},
	}

	allocator := newTestIPPoolAllocator(&pool, stopCh)
	err := allocator.AllocateStatefulSet(testNamespace, setName, 7, nil)
	require.NoError(t, err)

	// Make sure reserved IPs are respected for next allocate
	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.107", "10.2.2.108"})

	// Release the set
	err = allocator.ReleaseStatefulSet(testNamespace, setName)
	require.NoError(t, err)

	// Make sure reserved IPs are released
	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.100"})

	allocator = newTestIPPoolAllocator(&pool, stopCh)
	err = allocator.AllocateStatefulSet(testNamespace, setName, 1, net.ParseIP("10.2.2.101"))
	require.NoError(t, err)

	// Make sure specified IP is reserved
	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.100", "10.2.2.102"})

	// Release the set
	err = allocator.ReleaseStatefulSet(testNamespace, setName)
	require.NoError(t, err)

	// Make sure reserved IP is released
	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.101"})

	// Invalid IP will result in an error
	err = allocator.AllocateStatefulSet(testNamespace, setName, 1, net.ParseIP("10.2.3.103"))
	require.Error(t, err)
}
