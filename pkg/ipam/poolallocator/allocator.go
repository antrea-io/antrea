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

	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdclientset "antrea.io/antrea/pkg/client/clientset/versioned"
	"antrea.io/antrea/pkg/ipam/ipallocator"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
)

// IPPoolAllocator is responsible for allocating IPs from IP set defined in IPPool CRD.
// The will update CRD usage accordingly.
type IPPoolAllocator struct {
	// Name of IP Pool custom resource
	ipPoolName string

	// crd client to access the pool
	crdClient crdclientset.Interface
}

// NewIPPoolAllocator creates an IPPoolAllocator based on the provided IP pool.
func NewIPPoolAllocator(poolName string, client crdclientset.Interface) (*IPPoolAllocator, error) {

	allocator := &IPPoolAllocator{
		ipPoolName: poolName,
		crdClient:  client,
	}
	return allocator, nil
}

// initAllocatorList reads IP Pool status and initializes a list of allocators based on
// IP Pool spec and state of allocation recorded in the status
func (a *IPPoolAllocator) initIPAllocators(ipPool *v1alpha2.IPPool) (ipallocator.MultiIPAllocator, error) {

	var allocators ipallocator.MultiIPAllocator

	// Initialize a list of IP allocators based on pool spec
	for _, ipRange := range ipPool.Spec.IPRanges {
		if len(ipRange.CIDR) > 0 {
			allocator, err := ipallocator.NewCIDRAllocator(ipRange.CIDR)
			if err != nil {
				return nil, err
			}
			allocators = append(allocators, allocator)
		} else {
			allocator, err := ipallocator.NewIPRangeAllocator(ipRange.Start, ipRange.End)
			if err != nil {
				return allocators, err
			}
			allocators = append(allocators, allocator)
		}
	}

	// Mark allocated IPs from pool status as unavailable
	for _, ip := range ipPool.Status.IPAddresses {
		err := allocators.AllocateIP(net.ParseIP(ip.IPAddress))
		if err != nil {
			// TODO - fix state if possible
			return allocators, fmt.Errorf("Inconsistent state for IP Pool %s with IP %s", ipPool.Name, ip.IPAddress)
		}
	}

	return allocators, nil
}

func (a *IPPoolAllocator) readPoolAndInitIPAllocators() (*v1alpha2.IPPool, ipallocator.MultiIPAllocator, error) {
	ipPool, err := a.crdClient.CrdV1alpha2().IPPools().Get(context.TODO(), a.ipPoolName, metav1.GetOptions{})

	if err != nil {
		return nil, ipallocator.MultiIPAllocator{}, err
	}

	allocators, err := a.initIPAllocators(ipPool)
	if err != nil {
		return nil, ipallocator.MultiIPAllocator{}, err
	}
	return ipPool, allocators, nil
}

func (a *IPPoolAllocator) appendPoolUsage(ipPool *v1alpha2.IPPool, ip net.IP, state v1alpha2.IPAddressPhase, owner v1alpha2.IPAddressOwner) error {
	newPool := ipPool.DeepCopy()
	usageEntry := v1alpha2.IPAddressState{
		IPAddress: ip.String(),
		Phase:     state,
		Owner:     owner,
	}

	newPool.Status.IPAddresses = append(newPool.Status.IPAddresses, usageEntry)
	_, err := a.crdClient.CrdV1alpha2().IPPools().UpdateStatus(context.TODO(), newPool, metav1.UpdateOptions{})
	if err != nil {
		klog.Warningf("IP Pool %s update with status %+v failed: %+v", newPool.Name, newPool.Status, err)
		return err
	}
	klog.Infof("IP Pool update successful %s: %+v", newPool.Name, newPool.Status)
	return nil

}

func (a *IPPoolAllocator) removePoolUsage(ipPool *v1alpha2.IPPool, ip net.IP) error {

	ipString := ip.String()
	newPool := ipPool.DeepCopy()
	var newList []v1alpha2.IPAddressState
	for _, entry := range ipPool.Status.IPAddresses {
		if entry.IPAddress != ipString {
			newList = append(newList, entry)
		}
	}

	if len(newList) == len(ipPool.Status.IPAddresses) {
		return fmt.Errorf("IP address %s was not allocated from IP pool %s", ip, ipPool.Name)
	}

	newPool.Status.IPAddresses = newList

	_, err := a.crdClient.CrdV1alpha2().IPPools().UpdateStatus(context.TODO(), newPool, metav1.UpdateOptions{})
	if err != nil {
		klog.Warningf("IP Pool %s update failed: %+v", newPool.Name, err)
		return err
	}
	klog.Infof("IP Pool update successful %s: %+v", newPool.Name, newPool.Status)
	return nil

}

// AllocateIP allocates the specified IP. It returns error if the IP is not in the range or already
// allocated, or in case CRD failed to update its state.
// In case of success, IP pool CRD status is updated with allocated IP/state/resource.
// AllocateIP returns subnet details for the requested IP, as defined in IP pool spec.
func (a *IPPoolAllocator) AllocateIP(ip net.IP, state v1alpha2.IPAddressPhase, owner v1alpha2.IPAddressOwner) (v1alpha2.SubnetInfo, error) {
	var subnetSpec v1alpha2.SubnetInfo
	// Retry on CRD update conflict which is caused by multiple agents updating a pool at same time.
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ipPool, allocators, err := a.readPoolAndInitIPAllocators()
		if err != nil {
			return err
		}

		index := len(allocators)
		for i, allocator := range allocators {
			if allocator.Has(ip) {
				err := allocator.AllocateIP(ip)
				if err != nil {
					return err
				}
				index = i
				break
			}
		}

		if index == len(allocators) {
			// Failed to find matching range
			return fmt.Errorf("IP %v does not belong to IP pool %s", ip, a.ipPoolName)
		}

		subnetSpec = ipPool.Spec.IPRanges[index].SubnetInfo
		err = a.appendPoolUsage(ipPool, ip, state, owner)

		return err
	})

	if err != nil {
		klog.Errorf("Failed to allocate IP address %s from pool %s: %+v", ip, a.ipPoolName, err)
	}
	return subnetSpec, err
}

// AllocateNext allocates the next available IP. It returns error if pool is exausted,
// or in case CRD failed to update its state.
// In case of success, IP pool CRD status is updated with allocated IP/state/resource.
// AllocateIP returns subnet details for the requested IP, as defined in IP pool spec.
func (a *IPPoolAllocator) AllocateNext(state v1alpha2.IPAddressPhase, owner v1alpha2.IPAddressOwner) (net.IP, v1alpha2.SubnetInfo, error) {
	var subnetSpec v1alpha2.SubnetInfo
	var ip net.IP
	// Retry on CRD update conflict which is caused by multiple agents updating a pool at same time.
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ipPool, allocators, err := a.readPoolAndInitIPAllocators()
		if err != nil {
			return err
		}

		index := len(allocators)
		for i, allocator := range allocators {
			ip, err = allocator.AllocateNext()
			if err == nil {
				// successful allocation
				index = i
				break
			}
		}

		if index == len(allocators) {
			// Failed to find matching range
			return fmt.Errorf("Failed to allocate IP: Pool %s is exausted", a.ipPoolName)
		}

		subnetSpec = ipPool.Spec.IPRanges[index].SubnetInfo
		return a.appendPoolUsage(ipPool, ip, state, owner)
	})

	if err != nil {
		klog.Errorf("Failed to allocate from pool %s: %+v", a.ipPoolName, err)
	}
	return ip, subnetSpec, err
}

// Release releases the provided IP. It returns error if the IP is not in the range or not allocated,
// or in case CRD failed to update its state.
// In case of success, IP pool CRD status is updated with released IP/state/resource.
func (a *IPPoolAllocator) Release(ip net.IP) error {

	// Retry on CRD update conflict which is caused by multiple agents updating a pool at same time.
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ipPool, allocators, err := a.readPoolAndInitIPAllocators()
		if err != nil {
			return err
		}

		err = allocators.Release(ip)

		if err != nil {
			// Failed to find matching range
			return fmt.Errorf("IP %v does not belong to IP pool %s", ip, a.ipPoolName)
		}

		return a.removePoolUsage(ipPool, ip)
	})

	if err != nil {
		klog.Errorf("Failed to release IP address %s from pool %s: %+v", ip, a.ipPoolName, err)
	}
	return err
}
