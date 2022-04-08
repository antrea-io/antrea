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
	"reflect"

	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdclientset "antrea.io/antrea/pkg/client/clientset/versioned"
	informers "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	"antrea.io/antrea/pkg/ipam/ipallocator"
	iputil "antrea.io/antrea/pkg/util/ip"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
)

// IPPoolAllocator is responsible for allocating IPs from IP set defined in IPPool CRD.
// The will update CRD usage accordingly.
// Pool Allocator assumes that pool with allocated IPs can not be deleted. Pool ranges can
// only be extended.
type IPPoolAllocator struct {
	// IP version of the IPPool
	IPVersion v1alpha2.IPVersion

	// Name of IPPool custom resource
	ipPoolName string

	// crd client to update the pool
	crdClient crdclientset.Interface

	// pool lister for reading the pool
	ipPoolLister informers.IPPoolLister
}

// NewIPPoolAllocator creates an IPPoolAllocator based on the provided IP pool.
func NewIPPoolAllocator(poolName string, client crdclientset.Interface, poolLister informers.IPPoolLister) (*IPPoolAllocator, error) {

	// Validate the pool exists
	// This has an extra roundtrip cost, however this would allow fallback to
	// default IPAM driver if needed
	pool, err := poolLister.Get(poolName)
	if err != nil {
		return nil, err
	}

	allocator := &IPPoolAllocator{
		IPVersion:    pool.Spec.IPVersion,
		ipPoolName:   poolName,
		crdClient:    client,
		ipPoolLister: poolLister,
	}

	return allocator, nil
}

func (a *IPPoolAllocator) getPool() (*v1alpha2.IPPool, error) {
	pool, err := a.ipPoolLister.Get(a.ipPoolName)
	return pool, err
}

// initAllocatorList reads IP Pool status and initializes a list of allocators based on
// IP Pool spec and state of allocation recorded in the status
func (a *IPPoolAllocator) initIPAllocators(ipPool *v1alpha2.IPPool) (ipallocator.MultiIPAllocator, error) {

	var allocators ipallocator.MultiIPAllocator

	// Initialize a list of IP allocators based on pool spec
	for _, ipRange := range ipPool.Spec.IPRanges {
		if len(ipRange.CIDR) > 0 {
			// Reserve gateway address and broadcast address
			reservedIPs := []net.IP{net.ParseIP(ipRange.SubnetInfo.Gateway)}
			_, ipNet, err := net.ParseCIDR(ipRange.CIDR)
			if err != nil {
				return nil, err
			}

			size, bits := ipNet.Mask.Size()
			if int32(size) == ipRange.SubnetInfo.PrefixLength && bits == 32 {
				// Allocation CIDR covers entire subnet, thus we need
				// to reserve broadcast IP as well for IPv4
				reservedIPs = append(reservedIPs, iputil.GetLocalBroadcastIP(ipNet))
			}

			allocator, err := ipallocator.NewCIDRAllocator(ipNet, reservedIPs)
			if err != nil {
				return nil, err
			}
			allocators = append(allocators, allocator)
		} else {
			allocator, err := ipallocator.NewIPRangeAllocator(net.ParseIP(ipRange.Start), net.ParseIP(ipRange.End))
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
			return allocators, fmt.Errorf("inconsistent state for IP Pool %s with IP %s", ipPool.Name, ip.IPAddress)
		}
	}

	return allocators, nil
}

func (a *IPPoolAllocator) getPoolAndInitIPAllocators() (*v1alpha2.IPPool, ipallocator.MultiIPAllocator, error) {
	ipPool, err := a.getPool()

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
	klog.InfoS("IP Pool update succeeded", "pool", newPool.Name, "allocation", newPool.Status)
	return nil

}

// updateIPAddressState updates the status of the specified IP in the provided IPPool. It requires the IP is already in the IPAddresses list of the IPPool's status.
func (a *IPPoolAllocator) updateIPAddressState(ipPool *v1alpha2.IPPool, ip net.IP, state v1alpha2.IPAddressPhase, owner v1alpha2.IPAddressOwner) error {
	newPool := ipPool.DeepCopy()
	ipString := ip.String()
	found := false

	for i, ipAddress := range newPool.Status.IPAddresses {
		if ipAddress.IPAddress == ipString {
			newPool.Status.IPAddresses[i].Phase = state
			newPool.Status.IPAddresses[i].Owner = owner
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("ip %s usage not found in pool %s", ipString, newPool.Name)
	}

	_, err := a.crdClient.CrdV1alpha2().IPPools().UpdateStatus(context.TODO(), newPool, metav1.UpdateOptions{})
	if err != nil {
		klog.Warningf("IP Pool %s update with status %+v failed: %+v", newPool.Name, newPool.Status, err)
		return err
	}
	klog.InfoS("IP Pool update succeeded", "pool", newPool.Name, "allocation", newPool.Status)
	return nil

}

func (a *IPPoolAllocator) appendPoolUsageForStatefulSet(ipPool *v1alpha2.IPPool, ips []net.IP, namespace, name string) error {
	newPool := ipPool.DeepCopy()

	for i, ip := range ips {
		owner := v1alpha2.IPAddressOwner{
			StatefulSet: &v1alpha2.StatefulSetOwner{
				Namespace: namespace,
				Name:      name,
				Index:     i,
			},
		}
		usageEntry := v1alpha2.IPAddressState{
			IPAddress: ip.String(),
			Phase:     v1alpha2.IPAddressPhaseReserved,
			Owner:     owner,
		}

		newPool.Status.IPAddresses = append(newPool.Status.IPAddresses, usageEntry)
	}
	_, err := a.crdClient.CrdV1alpha2().IPPools().UpdateStatus(context.TODO(), newPool, metav1.UpdateOptions{})
	if err != nil {
		klog.Warningf("IP Pool %s update with status %+v failed: %+v", newPool.Name, newPool.Status, err)
		return err
	}
	klog.V(2).InfoS("IP Pool update succeeded", "pool", newPool.Name, "allocation", newPool.Status)
	return nil

}

// removeIPAddressState updates ipPool status to delete released IP allocation, and keeps preallocation information
func (a *IPPoolAllocator) removeIPAddressState(ipPool *v1alpha2.IPPool, ip net.IP) error {

	ipString := ip.String()
	newPool := ipPool.DeepCopy()
	var newList []v1alpha2.IPAddressState
	allocated := false
	for i := range ipPool.Status.IPAddresses {
		entry := ipPool.Status.IPAddresses[i]
		if entry.IPAddress != ipString {
			newList = append(newList, entry)
		} else {
			allocated = true
			if entry.Owner.StatefulSet != nil {
				entry = *entry.DeepCopy()
				entry.Owner.Pod = nil
				entry.Phase = v1alpha2.IPAddressPhaseReserved
				newList = append(newList, entry)
			}
		}
	}

	if !allocated {
		return fmt.Errorf("IP address %s was not allocated from IP pool %s", ip, ipPool.Name)
	}

	newPool.Status.IPAddresses = newList

	_, err := a.crdClient.CrdV1alpha2().IPPools().UpdateStatus(context.TODO(), newPool, metav1.UpdateOptions{})
	if err != nil {
		klog.Warningf("IP Pool %s update failed: %+v", newPool.Name, err)
		return err
	}
	klog.InfoS("IP Pool update succeeded", "pool", newPool.Name, "allocation", newPool.Status)
	return nil

}

// AllocateIP allocates the specified IP. It returns error if the IP is not in the range or already
// allocated, or in case CRD failed to update its state.
// In case of success, IP pool CRD status is updated with allocated IP/state/resource/container.
// AllocateIP returns subnet details for the requested IP, as defined in IP pool spec.
func (a *IPPoolAllocator) AllocateIP(ip net.IP, state v1alpha2.IPAddressPhase, owner v1alpha2.IPAddressOwner) (*v1alpha2.SubnetInfo, error) {
	var subnetSpec *v1alpha2.SubnetInfo
	// Retry on CRD update conflict which is caused by multiple agents updating a pool at same time.
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ipPool, allocators, err := a.getPoolAndInitIPAllocators()
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

		subnetSpec = &ipPool.Spec.IPRanges[index].SubnetInfo
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
// In case of success, IP pool CRD status is updated with allocated IP/state/resource/container.
// AllocateIP returns subnet details for the requested IP, as defined in IP pool spec.
func (a *IPPoolAllocator) AllocateNext(state v1alpha2.IPAddressPhase, owner v1alpha2.IPAddressOwner) (net.IP, *v1alpha2.SubnetInfo, error) {
	var subnetSpec *v1alpha2.SubnetInfo
	var ip net.IP
	// Same resource can not ask for allocation twice without release
	// This needs to be verified even at the expense of another API call
	exists, err := a.HasContainer(owner.Pod.ContainerID, owner.Pod.IFName)
	if err != nil {
		return nil, nil, err
	}

	if exists {
		return nil, nil, fmt.Errorf("container %s interface %s was already allocated an address from IP Pool %s",
			owner.Pod.ContainerID, owner.Pod.IFName, a.ipPoolName)
	}

	// Retry on CRD update conflict which is caused by multiple agents updating a pool at same time.
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ipPool, allocators, err := a.getPoolAndInitIPAllocators()
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
			return fmt.Errorf("failed to allocate IP: Pool %s is exausted", a.ipPoolName)
		}

		subnetSpec = &ipPool.Spec.IPRanges[index].SubnetInfo
		return a.appendPoolUsage(ipPool, ip, state, owner)
	})

	if err != nil {
		klog.ErrorS(err, "Failed to allocate from IPPool", "IPPool", a.ipPoolName)
	}
	return ip, subnetSpec, err
}

// AllocateReservedOrNext allocates the reserved IP if it exists, else allocates next available IP.
// It returns error if pool is exhausted, or in case it fails to update IPPool's state. In case of
// success, IP pool status is updated with allocated IP/state/resource/container.
// AllocateReservedOrNext returns subnet details for the requested IP, as defined in IP pool spec.
func (a *IPPoolAllocator) AllocateReservedOrNext(state v1alpha2.IPAddressPhase, owner v1alpha2.IPAddressOwner) (net.IP, *v1alpha2.SubnetInfo, error) {
	var subnetSpec *v1alpha2.SubnetInfo
	var ip net.IP

	ip, err := a.getReservedIP(owner)
	if err != nil {
		return nil, nil, err
	}
	if ip == nil {
		// ip is not reserved, allocate next available ip
		return a.AllocateNext(state, owner)
	}

	// Same resource can not ask for allocation twice without release
	// This needs to be verified even at the expense of another API call
	exists, err := a.HasContainer(owner.Pod.ContainerID, owner.Pod.IFName)
	if err != nil {
		return nil, nil, err
	}
	if exists {
		return nil, nil, fmt.Errorf("container %s was already allocated an address from IP Pool %s", owner.Pod.ContainerID, a.ipPoolName)
	}

	// Retry on CRD update conflict which is caused by multiple agents updating a pool at same time.
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ipPool, allocators, err := a.getPoolAndInitIPAllocators()
		if err != nil {
			return err
		}

		index := -1
		for i, allocator := range allocators {
			if allocator.Has(ip) {
				index = i
				break
			}
		}

		if index == -1 {
			// Failed to find matching range
			return fmt.Errorf("IP %v does not belong to IP pool %s", ip, a.ipPoolName)
		}

		subnetSpec = &ipPool.Spec.IPRanges[index].SubnetInfo
		return a.updateIPAddressState(ipPool, ip, state, owner)
	})

	if err != nil {
		klog.ErrorS(err, "Failed to allocate IP address", "ip", ip, "ipPool", a.ipPoolName)
	}
	return ip, subnetSpec, err
}

// AllocateStatefulSet pre-allocates continuous range of IPs for StatefulSet.
// This functionality is useful when StatefulSet does not have a dedicated IP Pool assigned.
// It returns error if such range is not available. In this case IPs for the StatefulSet will
// be allocated on the fly, and there is no guarantee for continuous IPs.
func (a *IPPoolAllocator) AllocateStatefulSet(namespace, name string, size int) error {
	// Retry on CRD update conflict which is caused by multiple agents updating a pool at same time.
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ipPool, allocators, err := a.getPoolAndInitIPAllocators()
		if err != nil {
			return err
		}

		// Make sure there is no double allocation for this StatefulSet
		for _, ip := range ipPool.Status.IPAddresses {
			if ip.Owner.StatefulSet != nil && ip.Owner.StatefulSet.Namespace == namespace && ip.Owner.StatefulSet.Name == name {
				return fmt.Errorf("StatefulSet %s/%s is already present in IPPool %s", namespace, name, ipPool.Name)
			}
		}

		ips, err := allocators.AllocateRange(size)
		if err != nil {
			return err
		}

		return a.appendPoolUsageForStatefulSet(ipPool, ips, namespace, name)
	})

	if err != nil {
		klog.ErrorS(err, "Failed to allocate from IPPool", "IPPool", a.ipPoolName)
	}
	return err
}

// Release releases the provided IP. It returns error if the IP is not in the range or not allocated,
// or in case CRD failed to update its state.
// In case of success, IP pool CRD status is updated with released IP/state/resource.
func (a *IPPoolAllocator) Release(ip net.IP) error {

	// Retry on CRD update conflict which is caused by multiple agents updating a pool at same time.
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ipPool, allocators, err := a.getPoolAndInitIPAllocators()
		if err != nil {
			return err
		}

		err = allocators.Release(ip)

		if err != nil {
			// Failed to find matching range
			return fmt.Errorf("IP %v does not belong to IP pool %s", ip, a.ipPoolName)
		}

		return a.removeIPAddressState(ipPool, ip)
	})

	if err != nil {
		klog.ErrorS(err, "Failed to release IP address", "IPAddress", ip, "IPPool", a.ipPoolName)
	}
	return err
}

// ReleaseStatefulSet releases all IPs associated with specified StatefulSet. It returns error
// in case CRD failed to update its state.
// In case of success, IP pool CRD status is updated with released entries.
func (a *IPPoolAllocator) ReleaseStatefulSet(namespace, name string) error {

	// Retry on CRD update conflict which is caused by multiple agents updating a pool at same time.
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ipPool, err := a.getPool()

		if err != nil {
			return err
		}

		var updatedAdresses []v1alpha2.IPAddressState
		for _, ip := range ipPool.Status.IPAddresses {
			if ip.Owner.StatefulSet == nil || ip.Owner.StatefulSet.Namespace != namespace || ip.Owner.StatefulSet.Name != name {
				updatedAdresses = append(updatedAdresses, ip)
			}
		}

		if len(ipPool.Status.IPAddresses) == len(updatedAdresses) {
			// no change
			klog.V(4).InfoS("No reserved IPs found", "pool", ipPool.Name, "Namespace", namespace, "StatefulSet", name)
			return nil
		}

		newPool := ipPool.DeepCopy()
		newPool.Status.IPAddresses = updatedAdresses

		_, err = a.crdClient.CrdV1alpha2().IPPools().UpdateStatus(context.TODO(), newPool, metav1.UpdateOptions{})
		if err != nil {
			klog.Warningf("IP Pool %s update failed: %+v", newPool.Name, err)
			return err
		}
		klog.V(2).InfoS("IP Pool update successful", "pool", newPool.Name, "allocation", newPool.Status)
		return nil

	})

	if err != nil {
		klog.ErrorS(err, "Failed to release IP addresses", "Namespace", namespace, "StatefulSet", name, "IPPool", a.ipPoolName)
	}
	return err
}

// ReleaseContainer releases the IP associated with the specified container ID and interface name,
// and updates the IPPool CR status.
// If no IP is allocated to the Pod according to the IPPool CR status, the func just returns with no
// change.
func (a *IPPoolAllocator) ReleaseContainer(containerID, ifName string) error {
	// Retry on CRD update conflict which is caused by multiple agents updating a pool at same time.
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ipPool, err := a.getPool()
		if err != nil {
			return err
		}

		// Mark allocated IPs from pool status as unavailable
		for _, ip := range ipPool.Status.IPAddresses {
			savedOwner := ip.Owner.Pod
			if savedOwner != nil && savedOwner.ContainerID == containerID && savedOwner.IFName == ifName {
				return a.removeIPAddressState(ipPool, net.ParseIP(ip.IPAddress))

			}
		}

		klog.V(4).InfoS("Did not find the allocation record in IPPool",
			"container", containerID, "interface", ifName, "pool", a.ipPoolName, "allocation", ipPool.Status.IPAddresses)
		return nil
	})

	if err != nil {
		klog.ErrorS(err, "Failed to release IP address", "Container", containerID, "interface", ifName, "IPPool", a.ipPoolName)
	}
	return err
}

// HasResource checks whether an IP was associated with specified pod. It returns error if the resource is crd fails to be retrieved.
func (a *IPPoolAllocator) HasPod(namespace, podName string) (bool, error) {

	ipPool, err := a.getPool()

	if err != nil {
		return false, err
	}

	for _, ip := range ipPool.Status.IPAddresses {
		if ip.Owner.Pod != nil && ip.Owner.Pod.Namespace == namespace && ip.Owner.Pod.Name == podName {
			return true, nil
		}
	}
	return false, nil
}

// HasContainer checks whether an IP was associated with specified container. It returns error if the resource crd fails to be retrieved.
func (a *IPPoolAllocator) HasContainer(containerID, ifName string) (bool, error) {

	ipPool, err := a.getPool()

	if err != nil {
		return false, err
	}

	for _, ip := range ipPool.Status.IPAddresses {
		if ip.Owner.Pod != nil && ip.Owner.Pod.ContainerID == containerID && ip.Owner.Pod.IFName == ifName {
			return true, nil
		}
	}
	return false, nil
}

// getReservedIP checks whether an IP was reserved with specified owner. It returns error if the resource crd fails to be retrieved.
func (a *IPPoolAllocator) getReservedIP(reservedOwner v1alpha2.IPAddressOwner) (net.IP, error) {
	ipPool, err := a.getPool()
	if err != nil {
		return nil, err
	}

	if reservedOwner.StatefulSet != nil {
		for _, ip := range ipPool.Status.IPAddresses {
			if reflect.DeepEqual(ip.Owner.StatefulSet, reservedOwner.StatefulSet) {
				return net.ParseIP(ip.IPAddress), nil
			}
		}
	}
	return nil, nil
}

func (a IPPoolAllocator) Total() int {
	_, allocators, err := a.getPoolAndInitIPAllocators()
	if err != nil {
		return 0
	}
	return allocators.Total()
}
