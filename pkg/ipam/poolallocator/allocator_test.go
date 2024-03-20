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
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	informers "antrea.io/antrea/pkg/client/informers/externalversions"
	fakepoolclient "antrea.io/antrea/pkg/ipam/poolallocator/testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
)

var testNamespace = "test"

var fakePodOwner = crdv1a2.IPAddressOwner{
	Pod: &crdv1a2.PodOwner{
		Name:        "fakePod",
		Namespace:   testNamespace,
		ContainerID: uuid.New().String(),
	},
}

func newTestIPPoolAllocator(pool *crdv1a2.IPPool, stopCh <-chan struct{}) *IPPoolAllocator {

	crdClient := fakepoolclient.NewIPPoolClient()

	crdInformerFactory := informers.NewSharedInformerFactory(crdClient, 0)
	pools := crdInformerFactory.Crd().V1alpha2().IPPools()
	poolInformer := pools.Informer()

	go crdInformerFactory.Start(stopCh)

	crdClient.InitPool(pool)
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

func validateAllocationSequence(t *testing.T, allocator *IPPoolAllocator, subnetInfo crdv1a2.SubnetInfo, ipList []string) {
	i := 1
	for _, expectedIP := range ipList {
		klog.Info("Validating allocation for ", expectedIP)
		owner := crdv1a2.IPAddressOwner{
			Pod: &crdv1a2.PodOwner{
				Name:        fmt.Sprintf("fakePod%d", i),
				Namespace:   testNamespace,
				ContainerID: uuid.New().String(),
			},
		}
		ip, returnInfo, err := allocator.AllocateNext(crdv1a2.IPAddressPhaseAllocated, owner)
		require.NoError(t, err)
		assert.Equal(t, net.ParseIP(expectedIP), ip)
		assert.Equal(t, subnetInfo, *returnInfo)
		i += 1
	}
}

func TestAllocateIP(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	poolName := uuid.New().String()
	ipRange := crdv1a2.IPRange{
		Start: "10.2.2.100",
		End:   "10.2.2.120",
	}
	subnetInfo := crdv1a2.SubnetInfo{
		Gateway:      "10.2.2.1",
		PrefixLength: 24,
		VLAN:         100,
	}
	subnetRange := crdv1a2.SubnetIPRange{IPRange: ipRange,
		SubnetInfo: subnetInfo}

	pool := crdv1a2.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec:       crdv1a2.IPPoolSpec{IPRanges: []crdv1a2.SubnetIPRange{subnetRange}},
	}

	allocator := newTestIPPoolAllocator(&pool, stopCh)
	require.NotNil(t, allocator)
	assert.Equal(t, 21, allocator.Total())

	// Allocate specific IP from the range
	returnInfo, err := allocator.AllocateIP(net.ParseIP("10.2.2.101"), crdv1a2.IPAddressPhaseAllocated, fakePodOwner)
	assert.Equal(t, subnetInfo, *returnInfo)
	require.NoError(t, err)

	// Validate IP outside the range is not allocated
	_, err = allocator.AllocateIP(net.ParseIP("10.2.2.121"), crdv1a2.IPAddressPhaseAllocated, fakePodOwner)
	require.Error(t, err)

	// Make sure IP allocated above is not allocated again
	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.100", "10.2.2.102"})

	// Validate error is returned if IP is already allocated
	_, err = allocator.AllocateIP(net.ParseIP("10.2.2.102"), crdv1a2.IPAddressPhaseAllocated, fakePodOwner)
	require.Error(t, err)
}

func TestAllocateNext(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	poolName := "fakePool"
	ipRange := crdv1a2.IPRange{
		Start: "10.2.2.100",
		End:   "10.2.2.120",
	}
	subnetInfo := crdv1a2.SubnetInfo{
		Gateway:      "10.2.2.1",
		PrefixLength: 24,
	}
	subnetRange := crdv1a2.SubnetIPRange{IPRange: ipRange,
		SubnetInfo: subnetInfo}

	pool := crdv1a2.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec:       crdv1a2.IPPoolSpec{IPRanges: []crdv1a2.SubnetIPRange{subnetRange}},
	}

	allocator := newTestIPPoolAllocator(&pool, stopCh)
	require.NotNil(t, allocator)
	assert.Equal(t, 21, allocator.Total())

	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.100", "10.2.2.101"})
}

func TestAllocateNextMultiRange(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	poolName := uuid.New().String()
	ipRange1 := crdv1a2.IPRange{
		Start: "10.2.2.100",
		End:   "10.2.2.101",
	}
	ipRange2 := crdv1a2.IPRange{CIDR: "10.2.2.0/28"}
	subnetInfo := crdv1a2.SubnetInfo{
		Gateway:      "10.2.2.1",
		PrefixLength: 24,
	}
	subnetRange1 := crdv1a2.SubnetIPRange{IPRange: ipRange1,
		SubnetInfo: subnetInfo}
	subnetRange2 := crdv1a2.SubnetIPRange{IPRange: ipRange2,
		SubnetInfo: subnetInfo}

	pool := crdv1a2.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec: crdv1a2.IPPoolSpec{
			IPRanges: []crdv1a2.SubnetIPRange{subnetRange1, subnetRange2}},
	}

	allocator := newTestIPPoolAllocator(&pool, stopCh)
	require.NotNil(t, allocator)
	assert.Equal(t, 16, allocator.Total())

	// Allocate the 2 available IPs from first range then switch to second range
	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.100", "10.2.2.101", "10.2.2.2", "10.2.2.3"})
}

func TestAllocateNextMultiRangeExausted(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	poolName := uuid.New().String()
	ipRange1 := crdv1a2.IPRange{
		Start: "10.2.2.100",
		End:   "10.2.2.101",
	}
	ipRange2 := crdv1a2.IPRange{
		Start: "10.2.2.200",
		End:   "10.2.2.200",
	}
	subnetInfo := crdv1a2.SubnetInfo{
		Gateway:      "10.2.2.1",
		PrefixLength: 24,
	}
	subnetRange1 := crdv1a2.SubnetIPRange{IPRange: ipRange1,
		SubnetInfo: subnetInfo}
	subnetRange2 := crdv1a2.SubnetIPRange{IPRange: ipRange2,
		SubnetInfo: subnetInfo}

	pool := crdv1a2.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec: crdv1a2.IPPoolSpec{
			IPRanges: []crdv1a2.SubnetIPRange{subnetRange1, subnetRange2}},
	}

	allocator := newTestIPPoolAllocator(&pool, stopCh)
	require.NotNil(t, allocator)
	assert.Equal(t, 3, allocator.Total())

	// Allocate all available IPs
	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.100", "10.2.2.101", "10.2.2.200"})

	// Allocate next IP and get error
	_, _, err := allocator.AllocateNext(crdv1a2.IPAddressPhaseAllocated, fakePodOwner)
	require.Error(t, err)
}

func TestAllocateReleaseSequence(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	poolName := uuid.New().String()
	ipRange1 := crdv1a2.IPRange{
		Start: "2001::1000",
		End:   "2001::1000",
	}
	ipRange2 := crdv1a2.IPRange{CIDR: "2001::0/124"}
	subnetInfo := crdv1a2.SubnetInfo{
		Gateway:      "2001::1",
		PrefixLength: 64,
	}
	subnetRange1 := crdv1a2.SubnetIPRange{IPRange: ipRange1,
		SubnetInfo: subnetInfo}
	subnetRange2 := crdv1a2.SubnetIPRange{IPRange: ipRange2,
		SubnetInfo: subnetInfo}

	pool := crdv1a2.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec: crdv1a2.IPPoolSpec{
			IPRanges: []crdv1a2.SubnetIPRange{subnetRange1, subnetRange2}},
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
				return a.removeIPAddressState(ipPool, net.ParseIP(ip.IPAddress))

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

	poolName := uuid.New().String()
	ipRange1 := crdv1a2.IPRange{
		Start: "2001::1000",
		End:   "2001::1000",
	}
	ipRange2 := crdv1a2.IPRange{CIDR: "2001::0/124"}
	subnetInfo := crdv1a2.SubnetInfo{
		Gateway:      "2001::1",
		PrefixLength: 64,
	}
	subnetRange1 := crdv1a2.SubnetIPRange{IPRange: ipRange1,
		SubnetInfo: subnetInfo}
	subnetRange2 := crdv1a2.SubnetIPRange{IPRange: ipRange2,
		SubnetInfo: subnetInfo}

	pool := crdv1a2.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec: crdv1a2.IPPoolSpec{
			IPRanges: []crdv1a2.SubnetIPRange{subnetRange1, subnetRange2}},
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

	owner := crdv1a2.IPAddressOwner{
		Pod: &crdv1a2.PodOwner{
			Name:        "fakePod",
			Namespace:   testNamespace,
			ContainerID: "fakeContainer",
			IFName:      "eth1",
		},
	}
	poolName := uuid.New().String()
	ipRange1 := crdv1a2.IPRange{
		Start: "2001::1000",
		End:   "2001::1000",
	}
	subnetInfo := crdv1a2.SubnetInfo{
		Gateway:      "2001::1",
		PrefixLength: 64,
	}
	subnetRange1 := crdv1a2.SubnetIPRange{IPRange: ipRange1,
		SubnetInfo: subnetInfo}

	pool := crdv1a2.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec: crdv1a2.IPPoolSpec{
			IPRanges: []crdv1a2.SubnetIPRange{subnetRange1}},
	}

	allocator := newTestIPPoolAllocator(&pool, stopCh)
	require.NotNil(t, allocator)

	_, _, err := allocator.AllocateNext(crdv1a2.IPAddressPhaseAllocated, owner)
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

	poolName := uuid.New().String()
	setName := "fakeSet"
	ipRange := crdv1a2.IPRange{
		Start: "10.2.2.100",
		End:   "10.2.2.120",
	}
	subnetInfo := crdv1a2.SubnetInfo{
		Gateway:      "10.2.2.1",
		PrefixLength: 24,
	}
	subnetRange := crdv1a2.SubnetIPRange{IPRange: ipRange,
		SubnetInfo: subnetInfo}

	pool := crdv1a2.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: poolName},
		Spec:       crdv1a2.IPPoolSpec{IPRanges: []crdv1a2.SubnetIPRange{subnetRange}},
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
