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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/klog/v2"
)

var fakePodOwner = crdv1a2.IPAddressOwner{
	Pod: &crdv1a2.PodOwner{
		Name:        "",
		Namespace:   "",
		ContainerID: "fake-containerID",
	},
}

func newIPPoolAllocator(poolName string, initObjects []runtime.Object) *IPPoolAllocator {
	crdClient := fakeversioned.NewSimpleClientset(initObjects...)
	allocator, _ := NewIPPoolAllocator(poolName, crdClient)
	return allocator
}

func validateAllocationSequence(t *testing.T, allocator *IPPoolAllocator, subnetInfo crdv1a2.SubnetInfo, ipList []string) {
	// Allocate the 2 available IPs from first range then switch to second range
	for _, expectedIP := range ipList {
		klog.Info("Validating allocation for ", expectedIP)
		ip, returnInfo, err := allocator.AllocateNext(crdv1a2.IPAddressPhaseAllocated, fakePodOwner)
		require.NoError(t, err)
		assert.Equal(t, net.ParseIP(expectedIP), ip)
		assert.Equal(t, subnetInfo, returnInfo)
	}
}

func TestAllocateIP(t *testing.T) {
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

	allocator := newIPPoolAllocator(poolName, []runtime.Object{&pool})

	// Allocate specific IP from the range
	returnInfo, err := allocator.AllocateIP(net.ParseIP("10.2.2.101"), crdv1a2.IPAddressPhaseAllocated, fakePodOwner)
	assert.Equal(t, subnetInfo, returnInfo)
	require.NoError(t, err)

	// Validate IP outside the range is not allocated
	returnInfo, err = allocator.AllocateIP(net.ParseIP("10.2.2.121"), crdv1a2.IPAddressPhaseAllocated, fakePodOwner)
	require.Error(t, err)

	// Make sure IP allocated above is not allocated again
	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.100", "10.2.2.102"})

	// Validate error is returned if IP is already allocated
	_, err = allocator.AllocateIP(net.ParseIP("10.2.2.102"), crdv1a2.IPAddressPhaseAllocated, fakePodOwner)
	require.Error(t, err)

}

func TestAllocateNext(t *testing.T) {
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

	allocator := newIPPoolAllocator(poolName, []runtime.Object{&pool})

	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.100", "10.2.2.101"})
}

// This test verifies correct behavior in case of update conflict. Allocation should be retiried
// Taking into account the latest status
func TestAllocateConflict(t *testing.T) {
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

	crdClient := &fakeversioned.Clientset{}
	updateCount := 0
	// fail for the first two update attempts, and succeed on third
	crdClient.AddReactor("update", "ippools", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updateCount += 1
		if updateCount < 3 {
			return true, nil, &errors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonConflict, Message: "pool status update conflict"}}
		}
		return true, &pool, nil
	})

	// after update conflict, return pool status that simulates simultaneous allocation
	// by another agent
	crdClient.AddReactor("get", "ippools", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if updateCount > 0 && len(pool.Status.IPAddresses) == 0 {
			pool.Status.IPAddresses = append(pool.Status.IPAddresses, crdv1a2.IPAddressState{
				IPAddress: "10.2.2.100",
				Phase:     crdv1a2.IPAddressPhaseAllocated,
				Owner:     crdv1a2.IPAddressOwner{Pod: &crdv1a2.PodOwner{ContainerID: "another-containerID"}},
			})
		}
		return true, &pool, nil
	})

	allocator, _ := NewIPPoolAllocator(poolName, crdClient)

	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.101"})
	assert.Equal(t, updateCount, 3)
}

func TestAllocateNextMultiRange(t *testing.T) {
	poolName := "fakePool"
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

	allocator := newIPPoolAllocator(poolName, []runtime.Object{&pool})

	// Allocate the 2 available IPs from first range then switch to second range
	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.100", "10.2.2.101", "10.2.2.2", "10.2.2.3"})
}

func TestAllocateNextMultiRangeExausted(t *testing.T) {
	poolName := "fakePool"
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

	allocator := newIPPoolAllocator(poolName, []runtime.Object{&pool})

	// Allocate all available IPs
	validateAllocationSequence(t, allocator, subnetInfo, []string{"10.2.2.100", "10.2.2.101", "10.2.2.200"})

	// Allocate next IP and get error
	_, _, err := allocator.AllocateNext(crdv1a2.IPAddressPhaseAllocated, fakePodOwner)
	require.Error(t, err)
}

func TestAllocateReleaseSequence(t *testing.T) {
	poolName := "fakePool"
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

	allocator := newIPPoolAllocator(poolName, []runtime.Object{&pool})

	// Allocate the single available IPs from first range then 3 IPs from second range
	validateAllocationSequence(t, allocator, subnetInfo, []string{"2001::1000", "2001::2", "2001::3", "2001::4"})

	// Release first IP from first range and middle IP from second range
	for _, ipToRelease := range []string{"2001::1000", "2001::2"} {
		err := allocator.Release(net.ParseIP(ipToRelease))
		require.NoError(t, err)
	}

	validateAllocationSequence(t, allocator, subnetInfo, []string{"2001::1000", "2001::2", "2001::5"})
}
