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

package externalippool

import (
	"context"
	"errors"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	antreacrds "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/v2/pkg/client/clientset/versioned"
	fakeversioned "antrea.io/antrea/v2/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions"
	"antrea.io/antrea/v2/pkg/features"
)

func newExternalIPPool(name, cidr, start, end string) *antreacrds.ExternalIPPool {
	pool := &antreacrds.ExternalIPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	if len(cidr) > 0 {
		pool.Spec.IPRanges = append(pool.Spec.IPRanges, antreacrds.IPRange{CIDR: cidr})
	}
	if len(start) > 0 && len(end) > 0 {
		pool.Spec.IPRanges = append(pool.Spec.IPRanges, antreacrds.IPRange{Start: start, End: end})
	}
	return pool
}

type controller struct {
	*ExternalIPPoolController
	crdClient          versioned.Interface
	crdInformerFactory crdinformers.SharedInformerFactory
}

// objects is an initial set of K8s objects that is exposed through the client.
func newController(crdObjects []runtime.Object) *controller {
	crdClient := fakeversioned.NewSimpleClientset(crdObjects...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, resyncPeriod)
	externalIPPoolController := NewExternalIPPoolController(crdClient, crdInformerFactory.Crd().V1beta1().ExternalIPPools())
	return &controller{
		externalIPPoolController,
		crdClient,
		crdInformerFactory,
	}
}

func TestAllocateIPFromPool(t *testing.T) {
	tests := []struct {
		name        string
		ipPools     []*antreacrds.ExternalIPPool
		allocatedIP []struct {
			ip   string
			pool string
		}
		allocateFrom         string
		expectedIP           string
		expectError          bool
		expectedIPPoolStatus []antreacrds.IPPoolUsage
	}{
		{
			name: "allocate from proper IP pool",
			ipPools: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "10.10.10.2", "10.10.10.3"),
			},
			allocatedIP:  nil,
			allocateFrom: "eip1",
			expectedIP:   "10.10.10.2",
			expectError:  false,
			expectedIPPoolStatus: []antreacrds.IPPoolUsage{
				{Total: 2, Used: 1},
			},
		},
		{
			name: "allocate from exhausted IP pool",
			ipPools: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "10.10.10.2", "10.10.10.3"),
			},
			allocatedIP: []struct {
				ip   string
				pool string
			}{
				{"10.10.10.2", "eip1"},
				{"10.10.10.3", "eip1"},
			},
			allocateFrom: "eip1",
			expectedIP:   "",
			expectError:  true,
			expectedIPPoolStatus: []antreacrds.IPPoolUsage{
				{Total: 2, Used: 2},
			},
		},
		{
			name: "allocate from non existing IP pool",
			ipPools: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "10.10.10.2", "10.10.10.3"),
			},
			allocatedIP:  nil,
			allocateFrom: "eip2",
			expectedIP:   "",
			expectError:  true,
			expectedIPPoolStatus: []antreacrds.IPPoolUsage{
				{Total: 2, Used: 0},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			var fakeCRDObjects []runtime.Object
			for _, p := range tt.ipPools {
				fakeCRDObjects = append(fakeCRDObjects, p)
			}
			controller := newController(fakeCRDObjects)
			controller.crdInformerFactory.Start(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)
			go controller.Run(stopCh)
			require.True(t, cache.WaitForCacheSync(stopCh, controller.HasSynced))
			for _, alloc := range tt.allocatedIP {
				require.NoError(t, controller.UpdateIPAllocation(alloc.pool, net.ParseIP(alloc.ip)))
			}
			ipGot, err := controller.AllocateIPFromPool(tt.allocateFrom)
			assert.Equal(t, tt.expectError, err != nil)
			assert.Equal(t, net.ParseIP(tt.expectedIP), ipGot)
			for idx, pool := range tt.ipPools {
				checkExternalIPPoolStatus(t, controller, pool.Name, tt.expectedIPPoolStatus[idx])
			}
		})
	}
}

func TestReleaseIP(t *testing.T) {
	tests := []struct {
		name        string
		ipPools     []*antreacrds.ExternalIPPool
		allocatedIP []struct {
			ip   string
			pool string
		}
		ipPoolToRelease      string
		ipToRelease          string
		expectError          bool
		expectedIPPoolStatus []antreacrds.IPPoolUsage
	}{
		{
			name: "release IP to pool",
			ipPools: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "10.10.10.2", "10.10.10.3"),
			},
			allocatedIP: []struct {
				ip   string
				pool string
			}{
				{"10.10.10.2", "eip1"},
				{"10.10.10.3", "eip1"},
			},
			ipPoolToRelease: "eip1",
			ipToRelease:     "10.10.10.2",
			expectError:     false,
			expectedIPPoolStatus: []antreacrds.IPPoolUsage{
				{Total: 2, Used: 1},
			},
		},
		{
			name: "release unknown IP to pool",
			ipPools: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "10.10.10.2", "10.10.10.3"),
			},
			allocatedIP: []struct {
				ip   string
				pool string
			}{
				{"10.10.10.2", "eip1"},
				{"10.10.10.3", "eip1"},
			},
			ipPoolToRelease: "eip1",
			ipToRelease:     "10.10.11.2",
			expectError:     true,
			expectedIPPoolStatus: []antreacrds.IPPoolUsage{
				{Total: 2, Used: 2},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			var fakeCRDObjects []runtime.Object
			for _, p := range tt.ipPools {
				fakeCRDObjects = append(fakeCRDObjects, p)
			}
			controller := newController(fakeCRDObjects)
			controller.crdInformerFactory.Start(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)
			go controller.Run(stopCh)
			require.True(t, cache.WaitForCacheSync(stopCh, controller.HasSynced))
			for _, alloc := range tt.allocatedIP {
				require.NoError(t, controller.UpdateIPAllocation(alloc.pool, net.ParseIP(alloc.ip)))
			}
			err := controller.ReleaseIP(tt.ipPoolToRelease, net.ParseIP(tt.ipToRelease))
			assert.Equal(t, tt.expectError, err != nil)
			for idx, pool := range tt.ipPools {
				checkExternalIPPoolStatus(t, controller, pool.Name, tt.expectedIPPoolStatus[idx])
			}
		})
	}
}

func TestCreateOrUpdateIPAllocator(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)
	controller := newController(nil)
	controller.crdInformerFactory.Start(stopCh)
	controller.crdInformerFactory.WaitForCacheSync(stopCh)

	ipPool := newExternalIPPool("ipPoolA", "1.1.1.0/30", "", "")
	changed := controller.createOrUpdateIPAllocator(ipPool)
	assert.True(t, changed)
	allocator, exists := controller.getIPAllocator(ipPool.Name)
	require.True(t, exists)
	assert.Equal(t, 1, len(allocator))
	assert.Equal(t, 2, allocator.Total())

	// Append a non-strict CIDR, it should handle it correctly.
	ipPool.Spec.IPRanges = append(ipPool.Spec.IPRanges, antreacrds.IPRange{CIDR: "1.1.2.1/30"})
	changed = controller.createOrUpdateIPAllocator(ipPool)
	assert.True(t, changed)
	allocator, exists = controller.getIPAllocator(ipPool.Name)
	require.True(t, exists)
	assert.Equal(t, 2, len(allocator))
	assert.Equal(t, 4, allocator.Total())

	ipPool.Spec.IPRanges = append(ipPool.Spec.IPRanges, antreacrds.IPRange{Start: "1.1.3.1", End: "1.1.3.10"})
	changed = controller.createOrUpdateIPAllocator(ipPool)
	assert.True(t, changed)
	allocator, exists = controller.getIPAllocator(ipPool.Name)
	require.True(t, exists)
	assert.Equal(t, 3, len(allocator))
	assert.Equal(t, 14, allocator.Total())

	// IPv6 CIDR shouldn't exclude broadcast address, so total should be increased by 15.
	ipPool.Spec.IPRanges = append(ipPool.Spec.IPRanges, antreacrds.IPRange{CIDR: "2021:3::aaa1/124"})
	changed = controller.createOrUpdateIPAllocator(ipPool)
	assert.True(t, changed)
	allocator, exists = controller.getIPAllocator(ipPool.Name)
	require.True(t, exists)
	assert.Equal(t, 4, len(allocator))
	assert.Equal(t, 29, allocator.Total())

	// When there is no change, the method should do nothing and the return value should be false.
	changed = controller.createOrUpdateIPAllocator(ipPool)
	assert.False(t, changed)
	allocator, exists = controller.getIPAllocator(ipPool.Name)
	require.True(t, exists)
	assert.Equal(t, 4, len(allocator))
	assert.Equal(t, 29, allocator.Total())
}

func TestCreateOrUpdateIPAllocatorGateway(t *testing.T) {
	tests := []struct {
		name      string
		ipRange   antreacrds.IPRange
		gateway   string
		wantTotal int
		wantFirst string
	}{
		{
			name:      "IPv4 gateway in CIDR",
			ipRange:   antreacrds.IPRange{CIDR: "192.168.1.144/28"},
			gateway:   "192.168.1.145",
			wantTotal: 13,
			wantFirst: "192.168.1.146",
		},
		{
			name:      "IPv4 gateway outside CIDR",
			ipRange:   antreacrds.IPRange{CIDR: "192.168.1.144/28"},
			gateway:   "192.168.1.1",
			wantTotal: 14,
			wantFirst: "192.168.1.145",
		},
		{
			name:      "gateway equals CIDR network address",
			ipRange:   antreacrds.IPRange{CIDR: "192.168.1.144/28"},
			gateway:   "192.168.1.144",
			wantTotal: 14,
			wantFirst: "192.168.1.145",
		},
		{
			name:      "gateway equals reserved broadcast address",
			ipRange:   antreacrds.IPRange{CIDR: "192.168.1.144/28"},
			gateway:   "192.168.1.159",
			wantTotal: 14,
			wantFirst: "192.168.1.145",
		},
		{
			name:      "IPv6 gateway in CIDR",
			ipRange:   antreacrds.IPRange{CIDR: "2001:db8::/124"},
			gateway:   "2001:db8::1",
			wantTotal: 14,
			wantFirst: "2001:db8::2",
		},
		{
			name:      "IPv4 gateway in start-end range",
			ipRange:   antreacrds.IPRange{Start: "192.168.1.145", End: "192.168.1.158"},
			gateway:   "192.168.1.145",
			wantTotal: 13,
			wantFirst: "192.168.1.146",
		},
		{
			name:      "gateway outside start-end range",
			ipRange:   antreacrds.IPRange{Start: "192.168.1.146", End: "192.168.1.158"},
			gateway:   "192.168.1.145",
			wantTotal: 13,
			wantFirst: "192.168.1.146",
		},
		{
			name:      "IPv6 gateway in start-end range",
			ipRange:   antreacrds.IPRange{Start: "2001:db8::1", End: "2001:db8::f"},
			gateway:   "2001:db8::1",
			wantTotal: 14,
			wantFirst: "2001:db8::2",
		},
		{
			name:    "range contains only gateway",
			ipRange: antreacrds.IPRange{Start: "192.168.1.145", End: "192.168.1.145"},
			gateway: "192.168.1.145",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newController(nil)
			pool := newExternalIPPool("pool", "", "", "")
			pool.Spec.IPRanges = []antreacrds.IPRange{tt.ipRange}
			pool.Spec.SubnetInfo = &antreacrds.SubnetInfo{Gateway: tt.gateway, PrefixLength: 24}
			if net.ParseIP(tt.gateway).To4() == nil {
				pool.Spec.SubnetInfo.PrefixLength = 64
			}
			require.True(t, c.createOrUpdateIPAllocator(pool))
			allocator, exists := c.getIPAllocator(pool.Name)
			require.True(t, exists)
			assert.Equal(t, tt.wantTotal, allocator.Total())
			assert.Zero(t, allocator.Used())
			require.Error(t, c.UpdateIPAllocation(pool.Name, net.ParseIP(tt.gateway)))
			assert.Zero(t, allocator.Used())
			if tt.wantTotal == 0 {
				_, err := c.AllocateIPFromPool(pool.Name)
				require.Error(t, err)
				return
			}
			ip, err := c.AllocateIPFromPool(pool.Name)
			require.NoError(t, err)
			assert.Equal(t, tt.wantFirst, ip.String())
			// Reusing an existing range must preserve allocations and reservations.
			assert.False(t, c.createOrUpdateIPAllocator(pool))
			assert.Equal(t, 1, allocator.Used())
			for i := 1; i < tt.wantTotal; i++ {
				ip, err := c.AllocateIPFromPool(pool.Name)
				require.NoError(t, err)
				assert.NotEqual(t, tt.gateway, ip.String())
			}
			_, err = c.AllocateIPFromPool(pool.Name)
			require.Error(t, err)
			assert.Equal(t, tt.wantTotal, allocator.Used())
			require.Error(t, c.ReleaseIP(pool.Name, net.ParseIP(tt.gateway)))
		})
	}
}

func TestCreateOrUpdateIPAllocatorGatewayNewRange(t *testing.T) {
	c := newController(nil)
	pool := newExternalIPPool("pool", "192.168.1.128/28", "", "")
	pool.Spec.SubnetInfo = &antreacrds.SubnetInfo{Gateway: "192.168.1.145", PrefixLength: 24}
	require.True(t, c.createOrUpdateIPAllocator(pool))
	ip, err := c.AllocateIPFromPool(pool.Name)
	require.NoError(t, err)
	pool.Spec.IPRanges = append(pool.Spec.IPRanges, antreacrds.IPRange{CIDR: "192.168.1.144/28"})
	require.True(t, c.createOrUpdateIPAllocator(pool))
	allocator, exists := c.getIPAllocator(pool.Name)
	require.True(t, exists)
	assert.Equal(t, 27, allocator.Total())
	assert.Equal(t, 1, allocator.Used())
	assert.Error(t, c.UpdateIPAllocation(pool.Name, ip))
	assert.Error(t, c.UpdateIPAllocation(pool.Name, net.ParseIP(pool.Spec.SubnetInfo.Gateway)))
}

func TestRestoreIPAllocationsGateway(t *testing.T) {
	c := newController(nil)
	pool := newExternalIPPool("pool", "192.168.1.144/28", "", "")
	pool.Spec.SubnetInfo = &antreacrds.SubnetInfo{Gateway: "192.168.1.145", PrefixLength: 28}
	c.createOrUpdateIPAllocator(pool)
	c.AddEventHandler(func(string) {})
	allocations := []IPAllocation{
		{IPPoolName: pool.Name, IP: net.ParseIP("192.168.1.145")},
		{IPPoolName: pool.Name, IP: net.ParseIP("192.168.1.146")},
	}
	assert.Equal(t, allocations[1:], c.RestoreIPAllocations(allocations))
	ip, err := c.AllocateIPFromPool(pool.Name)
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.147", ip.String())
}

func TestIPPoolHasIPGateway(t *testing.T) {
	tests := []struct {
		name    string
		ipRange antreacrds.IPRange
		gateway string
		ip      string
	}{
		{
			name: "IPv4 CIDR", ipRange: antreacrds.IPRange{CIDR: "192.168.1.144/28"},
			gateway: "192.168.1.145", ip: "192.168.1.146",
		},
		{
			name: "IPv4 range", ipRange: antreacrds.IPRange{Start: "192.168.1.145", End: "192.168.1.158"},
			gateway: "192.168.1.145", ip: "192.168.1.146",
		},
		{
			name: "IPv6 CIDR", ipRange: antreacrds.IPRange{CIDR: "2001:db8::/124"},
			gateway: "2001:db8::1", ip: "2001:db8::2",
		},
		{
			name: "IPv6 range", ipRange: antreacrds.IPRange{Start: "2001:db8::1", End: "2001:db8::f"},
			gateway: "2001:db8::1", ip: "2001:db8::2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newController(nil)
			pool := newExternalIPPool("pool", "", "", "")
			pool.Spec.IPRanges = []antreacrds.IPRange{tt.ipRange}
			pool.Spec.SubnetInfo = &antreacrds.SubnetInfo{Gateway: tt.gateway, PrefixLength: 28}
			require.NoError(t, c.crdInformerFactory.Crd().V1beta1().ExternalIPPools().Informer().GetStore().Add(pool))
			c.createOrUpdateIPAllocator(pool)
			assert.False(t, c.IPPoolHasIP(pool.Name, net.ParseIP(tt.gateway)))
			ip := net.ParseIP(tt.ip)
			assert.True(t, c.IPPoolHasIP(pool.Name, ip))
			require.NoError(t, c.UpdateIPAllocation(pool.Name, ip))
			assert.True(t, c.IPPoolHasIP(pool.Name, ip), "allocated IPs must remain valid members of the pool")
		})
	}
}

func TestUpdateExternalIPPoolRecreated(t *testing.T) {
	c := newController(nil)
	pool := newExternalIPPool("pool", "192.168.1.144/28", "", "")
	pool.UID = "old"
	pool.Spec.SubnetInfo = &antreacrds.SubnetInfo{Gateway: "192.168.1.145", PrefixLength: 28}
	store := c.crdInformerFactory.Crd().V1beta1().ExternalIPPools().Informer().GetStore()
	require.NoError(t, store.Add(pool))
	var notifications int
	c.AddEventHandler(func(string) { notifications++ })
	c.RestoreIPAllocations(nil)
	c.addExternalIPPool(pool)
	ip, err := c.AllocateIPFromPool(pool.Name)
	require.NoError(t, err)
	require.Equal(t, "192.168.1.146", ip.String())
	validIP := net.ParseIP("192.168.1.147")
	require.NoError(t, c.UpdateIPAllocation(pool.Name, validIP))

	// A relist can merge a DELETE and CREATE into an UPDATE with a different UID.
	recreated := pool.DeepCopy()
	recreated.UID = "new"
	recreated.Spec.SubnetInfo.Gateway = ip.String()
	require.NoError(t, store.Update(recreated))
	c.updateExternalIPPool(pool, recreated)
	assert.Equal(t, 2, notifications)
	assert.False(t, c.IPPoolHasIP(pool.Name, ip))
	require.Error(t, c.UpdateIPAllocation(pool.Name, ip))
	assert.Error(t, c.UpdateIPAllocation(pool.Name, validIP), "valid leases must survive a UID replacement")
	ip, err = c.AllocateIPFromPool(pool.Name)
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.145", ip.String())

	// Updates to the same object must preserve allocations and avoid unnecessary notifications.
	updated := recreated.DeepCopy()
	updated.Spec.SubnetInfo.VLAN = 201
	require.NoError(t, store.Update(updated))
	c.updateExternalIPPool(recreated, updated)
	assert.Equal(t, 2, notifications)
	assert.Error(t, c.UpdateIPAllocation(pool.Name, ip))
}

func TestDeleteAndRecreateExternalIPPool(t *testing.T) {
	c := newController(nil)
	pool := newExternalIPPool("pool", "192.0.2.0/29", "", "")
	pool.UID = "old"
	pool.Spec.SubnetInfo = &antreacrds.SubnetInfo{Gateway: "192.0.2.6", PrefixLength: 29}
	c.addExternalIPPool(pool)
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		require.NoError(t, c.UpdateIPAllocation(pool.Name, net.ParseIP(ip)))
	}

	c.deleteExternalIPPool(pool)
	require.False(t, c.IPPoolExists(pool.Name))
	_, err := c.AllocateIPFromPool(pool.Name)
	require.ErrorIs(t, err, ErrExternalIPPoolNotFound)
	// Consumers can release their leases before the replacement pool is observed.
	require.ErrorIs(t, c.ReleaseIP(pool.Name, net.ParseIP("192.0.2.3")), ErrExternalIPPoolNotFound)

	recreated := pool.DeepCopy()
	recreated.UID = "new"
	recreated.Spec.SubnetInfo.Gateway = "192.0.2.1"
	c.addExternalIPPool(recreated)
	require.True(t, c.IPPoolExists(pool.Name))
	assert.Empty(t, c.deletedIPAllocatorMap, "recreation must consume the retained leases")
	require.Error(t, c.UpdateIPAllocation(pool.Name, net.ParseIP("192.0.2.1")), "the new gateway must be reserved")
	require.Error(t, c.UpdateIPAllocation(pool.Name, net.ParseIP("192.0.2.2")), "valid leases must survive DELETE and ADD")
	ip, err := c.AllocateIPFromPool(pool.Name)
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.3", ip.String(), "leases released while the pool was absent must remain available")
}

func TestReleaseIPFromDeletedPool(t *testing.T) {
	c := newController(nil)
	pool := newExternalIPPool("pool", "192.0.2.0/29", "", "")
	c.addExternalIPPool(pool)
	ip, err := c.AllocateIPFromPool(pool.Name)
	require.NoError(t, err)
	c.deleteExternalIPPool(pool)
	require.Len(t, c.deletedIPAllocatorMap, 1)

	require.ErrorIs(t, c.ReleaseIP(pool.Name, net.ParseIP("192.0.2.2")), ErrExternalIPPoolNotFound)
	assert.Len(t, c.deletedIPAllocatorMap, 1, "an unrelated release must preserve outstanding leases")
	require.ErrorIs(t, c.ReleaseIP(pool.Name, ip), ErrExternalIPPoolNotFound)
	assert.Empty(t, c.deletedIPAllocatorMap, "releasing the last lease must clean up the deleted allocator")

	c.addExternalIPPool(pool)
	c.deleteExternalIPPool(pool)
	assert.Empty(t, c.deletedIPAllocatorMap, "an unused deleted pool must not retain an allocator")
}

func TestIPPoolEvents(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)
	context, cancel := context.WithCancel(context.Background())
	defer cancel()
	controller := newController(nil)
	consumerCh := make(chan string)
	controller.AddEventHandler(
		func(ippool string) {
			consumerCh <- ippool
		})
	controller.crdInformerFactory.Start(stopCh)
	controller.crdInformerFactory.WaitForCacheSync(stopCh)
	go controller.Run(stopCh)
	require.True(t, cache.WaitForCacheSync(stopCh, controller.HasSynced))
	// ADD event
	eip, err := controller.crdClient.CrdV1beta1().ExternalIPPools().Create(context,
		newExternalIPPool("eip1", "", "10.10.10.2", "10.10.10.3"),
		metav1.CreateOptions{},
	)
	require.NoError(t, err)
	assert.Equal(t, "eip1", <-consumerCh)
	// UPDATE event
	eip.Spec.IPRanges[0].End = "10.10.10.4"
	eip, err = controller.crdClient.CrdV1beta1().ExternalIPPools().Update(context,
		eip,
		metav1.UpdateOptions{},
	)
	require.NoError(t, err)
	assert.Equal(t, "eip1", <-consumerCh)
	// DELETE event
	err = controller.crdClient.CrdV1beta1().ExternalIPPools().Delete(context,
		eip.Name,
		metav1.DeleteOptions{},
	)
	require.NoError(t, err)
	assert.Equal(t, "eip1", <-consumerCh)
}

func TestConsumersRestoreIPAllocation(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)
	eip := newExternalIPPool("eip1", "", "10.10.10.2", "10.10.10.10")
	controller := newController([]runtime.Object{eip})
	controller.AddEventHandler(func(ippool string) {})
	controller.AddEventHandler(func(ippool string) {})
	controller.crdInformerFactory.Start(stopCh)
	controller.crdInformerFactory.WaitForCacheSync(stopCh)
	go controller.Run(stopCh)
	require.True(t, cache.WaitForCacheSync(stopCh, controller.HasSynced))
	allocatedIPCh := make(chan string)
	go func() {
		allocatedIPs := []IPAllocation{
			{
				IPPoolName: "eip1",
				IP:         net.ParseIP("10.10.10.2"),
			},
		}
		restored := controller.RestoreIPAllocations(allocatedIPs)
		assert.Equal(t, allocatedIPs, restored)
		ip, err := controller.AllocateIPFromPool("eip1")
		assert.NoError(t, err)
		allocatedIPCh <- ip.String()
	}()
	go func() {
		allocatedIPs := []IPAllocation{
			{
				IPPoolName: "eip1",
				IP:         net.ParseIP("10.10.10.3"),
			},
		}
		restored := controller.RestoreIPAllocations(allocatedIPs)
		assert.Equal(t, allocatedIPs, restored)
		ip, err := controller.AllocateIPFromPool("eip1")
		assert.NoError(t, err)
		allocatedIPCh <- ip.String()
	}()
	var allocated [2]string
	for idx := 0; idx < len(allocated); idx++ {
		allocated[idx] = <-allocatedIPCh
	}
	sort.Strings(allocated[:])
	assert.Equal(t, "10.10.10.4", allocated[0])
	assert.Equal(t, "10.10.10.5", allocated[1])
}

func TestIPPoolExists(t *testing.T) {
	tests := []struct {
		name           string
		ipPools        []*antreacrds.ExternalIPPool
		ipPoolToCheck  string
		expectedExists bool
	}{
		{
			name: "check for existing IPPool",
			ipPools: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "10.10.10.2", "10.10.10.3"),
			},
			ipPoolToCheck:  "eip1",
			expectedExists: true,
		},
		{
			name: "check for non-existing IPPool",
			ipPools: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "10.10.10.2", "10.10.10.3"),
			},
			ipPoolToCheck:  "eip2",
			expectedExists: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			var fakeCRDObjects []runtime.Object
			for _, p := range tt.ipPools {
				fakeCRDObjects = append(fakeCRDObjects, p)
			}
			controller := newController(fakeCRDObjects)
			controller.crdInformerFactory.Start(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)
			go controller.Run(stopCh)
			require.True(t, cache.WaitForCacheSync(stopCh, controller.HasSynced))
			exists := controller.IPPoolExists(tt.ipPoolToCheck)
			assert.Equal(t, tt.expectedExists, exists)
		})
	}
}

func TestIPPoolHasIP(t *testing.T) {
	tests := []struct {
		name           string
		ipPools        []*antreacrds.ExternalIPPool
		ipPoolToCheck  string
		ipToCheck      net.IP
		expectedExists bool
	}{
		{
			name: "check for existing IP in IPPool",
			ipPools: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "10.10.10.2", "10.10.10.3"),
			},
			ipPoolToCheck:  "eip1",
			ipToCheck:      net.ParseIP("10.10.10.2"),
			expectedExists: true,
		},
		{
			name: "check for non-existing IP in IPPool",
			ipPools: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "10.10.10.2", "10.10.10.3"),
			},
			ipPoolToCheck:  "eip1",
			ipToCheck:      net.ParseIP("10.10.10.1"),
			expectedExists: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			var fakeCRDObjects []runtime.Object
			for _, p := range tt.ipPools {
				fakeCRDObjects = append(fakeCRDObjects, p)
			}
			controller := newController(fakeCRDObjects)
			controller.crdInformerFactory.Start(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)
			go controller.Run(stopCh)
			require.True(t, cache.WaitForCacheSync(stopCh, controller.HasSynced))
			exists := controller.IPPoolHasIP(tt.ipPoolToCheck, tt.ipToCheck)
			assert.Equal(t, tt.expectedExists, exists)
		})
	}
}

func checkExternalIPPoolStatus(t *testing.T, controller *controller, poolName string, expectedStatus antreacrds.IPPoolUsage) {
	exists := controller.IPPoolExists(poolName)
	require.True(t, exists)
	err := wait.PollUntilContextTimeout(context.Background(), 50*time.Millisecond, 2*time.Second, true, func(ctx context.Context) (found bool, err error) {
		eip, err := controller.crdClient.CrdV1beta1().ExternalIPPools().Get(context.TODO(), poolName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return eip.Status.Usage == expectedStatus, nil
	})
	assert.NoError(t, err)
}

func TestExternalIPPoolController_RestoreIPAllocations(t *testing.T) {
	tests := []struct {
		name                 string
		ipPools              []*antreacrds.ExternalIPPool
		allocations          []IPAllocation
		allocationsToRestore []IPAllocation
		expectedSucceeded    []IPAllocation
		expectedIPPoolStatus []antreacrds.IPPoolUsage
	}{
		{
			name: "restore all IP successfully",
			ipPools: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "10.10.10.2", "10.10.10.3"),
				newExternalIPPool("eip2", "", "10.10.11.2", "10.10.11.3"),
			},
			allocations: nil,
			allocationsToRestore: []IPAllocation{
				{
					v1.ObjectReference{
						Name: "egress-1",
					},
					"eip1",
					net.ParseIP("10.10.10.2"),
				},
				{
					v1.ObjectReference{
						Name: "egress-2",
					},
					"eip2",
					net.ParseIP("10.10.11.2"),
				},
			},
			expectedSucceeded: []IPAllocation{
				{
					v1.ObjectReference{
						Name: "egress-1",
					},
					"eip1",
					net.ParseIP("10.10.10.2"),
				},
				{
					v1.ObjectReference{
						Name: "egress-2",
					},
					"eip2",
					net.ParseIP("10.10.11.2"),
				},
			},
			expectedIPPoolStatus: []antreacrds.IPPoolUsage{
				{Total: 2, Used: 1},
				{Total: 2, Used: 1},
			},
		},
		{
			name: "restore IP conflict",
			ipPools: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "10.10.10.2", "10.10.10.3"),
				newExternalIPPool("eip2", "", "10.10.11.2", "10.10.11.3"),
			},
			allocations: []IPAllocation{
				{
					v1.ObjectReference{
						Name: "other-service-1",
					},
					"eip1",
					net.ParseIP("10.10.10.2"),
				},
			},
			allocationsToRestore: []IPAllocation{
				{
					v1.ObjectReference{
						Name: "egress-1",
					},
					"eip1",
					net.ParseIP("10.10.10.2"),
				},
				{
					v1.ObjectReference{
						Name: "egress-2",
					},
					"eip2",
					net.ParseIP("10.10.11.2"),
				},
			},
			expectedSucceeded: []IPAllocation{
				{
					v1.ObjectReference{
						Name: "egress-2",
					},
					"eip2",
					net.ParseIP("10.10.11.2"),
				},
			},
			expectedIPPoolStatus: []antreacrds.IPPoolUsage{
				{Total: 2, Used: 1},
				{Total: 2, Used: 1},
			},
		},
		{
			name: "restore IP from unknown IP pool",
			ipPools: []*antreacrds.ExternalIPPool{
				newExternalIPPool("eip1", "", "10.10.10.2", "10.10.10.3"),
				newExternalIPPool("eip2", "", "10.10.11.2", "10.10.11.3"),
			},
			allocations: nil,
			allocationsToRestore: []IPAllocation{
				{
					v1.ObjectReference{
						Name: "egress-1",
					},
					"eip2",
					net.ParseIP("10.10.11.2"),
				},
				{
					v1.ObjectReference{
						Name: "egress-2",
					},
					"eip3",
					net.ParseIP("10.10.12.2"),
				},
			},
			expectedSucceeded: []IPAllocation{
				{
					v1.ObjectReference{
						Name: "egress-1",
					},
					"eip2",
					net.ParseIP("10.10.11.2"),
				},
			},
			expectedIPPoolStatus: []antreacrds.IPPoolUsage{
				{Total: 2, Used: 0},
				{Total: 2, Used: 1},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			var fakeCRDObjects []runtime.Object
			for _, p := range tt.ipPools {
				fakeCRDObjects = append(fakeCRDObjects, p)
			}
			controller := newController(fakeCRDObjects)
			controller.AddEventHandler(
				func(ippool string) {
				})
			controller.crdInformerFactory.Start(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)
			go controller.Run(stopCh)
			require.True(t, cache.WaitForCacheSync(stopCh, controller.HasSynced))
			for _, alloc := range tt.allocations {
				err := controller.UpdateIPAllocation(alloc.IPPoolName, alloc.IP)
				require.NoError(t, err)
			}
			succeeded := controller.RestoreIPAllocations(tt.allocationsToRestore)
			assert.Equal(t, tt.expectedSucceeded, succeeded)
			for idx, pool := range tt.ipPools {
				checkExternalIPPoolStatus(t, controller, pool.Name, tt.expectedIPPoolStatus[idx])
			}
		})
	}
}

func TestDeleteExternalIPPool_Tombstone(t *testing.T) {
	pool := newExternalIPPool("pool1", "10.10.10.0/24", "", "")
	c := newController([]runtime.Object{pool})

	// Simulate the controller having created an allocator for the pool.
	c.createOrUpdateIPAllocator(pool)
	require.True(t, c.IPPoolExists(pool.Name))

	// Deliver the delete as a tombstone, as the informer does after a watch reconnect.
	c.deleteExternalIPPool(cache.DeletedFinalStateUnknown{
		Key: pool.Name,
		Obj: pool,
	})
	assert.False(t, c.IPPoolExists(pool.Name))
}

func TestAllocateIPFromPoolPendingEgress(t *testing.T) {
	for _, tt := range []struct {
		name         string
		start        string
		end          string
		declaredIP   string
		declaredPool string
		wantIP       string
		excluded     bool
	}{
		{
			name: "IPv4 declaration", start: "192.0.2.1", end: "192.0.2.3",
			declaredIP: "192.0.2.1", declaredPool: "pool", wantIP: "192.0.2.2", excluded: true,
		},
		{
			name: "equivalent IPv6 declaration", start: "2001:db8::1", end: "2001:db8::3",
			declaredIP: "2001:0db8:0000:0000:0000:0000:0000:0001", declaredPool: "pool",
			wantIP: "2001:db8::2", excluded: true,
		},
		{
			name: "other pool declaration", start: "192.0.2.1", end: "192.0.2.3",
			declaredIP: "192.0.2.1", declaredPool: "other", wantIP: "192.0.2.1",
		},
		{
			name: "malformed declaration", start: "192.0.2.1", end: "192.0.2.3",
			declaredIP: "invalid-ip", declaredPool: "pool", wantIP: "192.0.2.1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pending := &antreacrds.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "pending"},
				Spec: antreacrds.EgressSpec{
					EgressIP: tt.declaredIP, ExternalIPPool: tt.declaredPool,
				},
			}
			// Leave the informer unstarted so the declaration is available only through the API.
			c := newController([]runtime.Object{pending})
			pool := newExternalIPPool("pool", "", tt.start, tt.end)
			c.createOrUpdateIPAllocator(pool)
			allocator, exists := c.getIPAllocator(pool.Name)
			require.True(t, exists)
			ip, err := c.AllocateIPFromPool(pool.Name)
			require.NoError(t, err)
			assert.Equal(t, tt.wantIP, ip.String())
			assert.Equal(t, 1, allocator.Used(), "excluded declarations must not consume allocator capacity")
			if tt.excluded {
				declaredIP := net.ParseIP(tt.declaredIP)
				require.NoError(t, c.UpdateIPAllocation(pool.Name, declaredIP),
					"the pending Egress must still be able to claim its declared IP")
				assert.Equal(t, 2, allocator.Used())
				require.NoError(t, c.ReleaseIP(pool.Name, declaredIP))
			}
			require.NoError(t, c.ReleaseIP(pool.Name, ip))
			assert.Zero(t, allocator.Used())

			require.NoError(t, c.crdClient.CrdV1beta1().Egresses().Delete(context.TODO(), pending.Name, metav1.DeleteOptions{}))
			ip, err = c.AllocateIPFromPool(pool.Name)
			require.NoError(t, err)
			assert.Equal(t, tt.start, ip.String(), "deleting a declaration must make the IP available again")
			assert.Equal(t, 1, allocator.Used())
		})
	}
}

func TestAllocateIPFromPoolEgressListFailure(t *testing.T) {
	c := newController(nil)
	pool := newExternalIPPool("pool", "", "192.0.2.1", "192.0.2.3")
	c.createOrUpdateIPAllocator(pool)
	allocator, exists := c.getIPAllocator(pool.Name)
	require.True(t, exists)
	listErr := errors.New("egress list unavailable")
	failList := true
	var listCalls int
	c.crdClient.(*fakeversioned.Clientset).PrependReactor("list", "egresses",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			listCalls++
			if failList {
				return true, nil, listErr
			}
			return false, nil, nil
		})

	ip, err := c.AllocateIPFromPool("missing")
	require.ErrorIs(t, err, ErrExternalIPPoolNotFound)
	assert.Nil(t, ip)
	assert.Zero(t, listCalls, "missing pools must not require an Egress API lookup")

	ip, err = c.AllocateIPFromPool(pool.Name)
	require.ErrorContains(t, err, listErr.Error())
	assert.Nil(t, ip)
	assert.Equal(t, 1, listCalls)
	assert.Zero(t, allocator.Used(), "a failed declaration lookup must not allocate an IP")

	failList = false
	ip, err = c.AllocateIPFromPool(pool.Name)
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.1", ip.String())
	assert.Equal(t, 2, listCalls)
	assert.Equal(t, 1, allocator.Used())
}

func TestAllocateIPFromPoolEgressFeatureGate(t *testing.T) {
	for _, tt := range []struct {
		name          string
		egressEnabled bool
	}{
		{name: "disabled"},
		{name: "enabled", egressEnabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.Egress, tt.egressEnabled)
			featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.ServiceExternalIP, true)
			pending := &antreacrds.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "pending"},
				Spec: antreacrds.EgressSpec{
					EgressIP: "192.0.2.2", ExternalIPPool: "pool",
				},
			}
			c := newController([]runtime.Object{pending})
			pool := newExternalIPPool("pool", "192.0.2.0/30", "", "")
			pool.Spec.SubnetInfo = &antreacrds.SubnetInfo{Gateway: "192.0.2.1", PrefixLength: 30}
			c.createOrUpdateIPAllocator(pool)
			allocator, exists := c.getIPAllocator(pool.Name)
			require.True(t, exists)
			require.Equal(t, 1, allocator.Total())
			var listCalls int
			c.crdClient.(*fakeversioned.Clientset).PrependReactor("list", "egresses",
				func(k8stesting.Action) (bool, runtime.Object, error) {
					listCalls++
					if !tt.egressEnabled {
						return true, nil, errors.New("egress list unavailable")
					}
					return false, nil, nil
				})

			ip, err := c.AllocateIPFromPool(pool.Name)
			if tt.egressEnabled {
				require.Error(t, err, "the only usable IP must be protected for the pending Egress")
				assert.Nil(t, ip)
				assert.Equal(t, 1, listCalls)
				assert.Zero(t, allocator.Used(), "declaration exclusions must not allocate an IP")
			} else {
				require.NoError(t, err, "Service allocation must ignore inactive Egress declarations and API failures")
				assert.Equal(t, "192.0.2.2", ip.String())
				assert.Zero(t, listCalls, "disabled Egress must not require an Egress API lookup")
				assert.Equal(t, 1, allocator.Used())
			}
		})
	}
}
