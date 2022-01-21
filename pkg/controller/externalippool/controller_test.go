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
	"k8s.io/client-go/tools/cache"

	antreacrds "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
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
	externalIPPoolController := NewExternalIPPoolController(crdClient, crdInformerFactory.Crd().V1alpha2().ExternalIPPools())
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
		expectedIPPoolStatus []antreacrds.ExternalIPPoolUsage
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
			expectedIPPoolStatus: []antreacrds.ExternalIPPoolUsage{
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
			expectedIPPoolStatus: []antreacrds.ExternalIPPoolUsage{
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
			expectedIPPoolStatus: []antreacrds.ExternalIPPoolUsage{
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
		expectedIPPoolStatus []antreacrds.ExternalIPPoolUsage
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
			expectedIPPoolStatus: []antreacrds.ExternalIPPoolUsage{
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
			expectedIPPoolStatus: []antreacrds.ExternalIPPoolUsage{
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
	eip, err := controller.crdClient.CrdV1alpha2().ExternalIPPools().Create(context,
		newExternalIPPool("eip1", "", "10.10.10.2", "10.10.10.3"),
		metav1.CreateOptions{},
	)
	require.NoError(t, err)
	assert.Equal(t, "eip1", <-consumerCh)
	// UPDATE event
	eip.Spec.IPRanges[0].End = "10.10.10.4"
	eip, err = controller.crdClient.CrdV1alpha2().ExternalIPPools().Update(context,
		eip,
		metav1.UpdateOptions{},
	)
	require.NoError(t, err)
	assert.Equal(t, "eip1", <-consumerCh)
	// DELETE event
	err = controller.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context,
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

func checkExternalIPPoolStatus(t *testing.T, controller *controller, poolName string, expectedStatus antreacrds.ExternalIPPoolUsage) {
	exists := controller.IPPoolExists(poolName)
	require.True(t, exists)
	err := wait.PollImmediate(50*time.Millisecond, 2*time.Second, func() (found bool, err error) {
		eip, err := controller.crdClient.CrdV1alpha2().ExternalIPPools().Get(context.TODO(), poolName, metav1.GetOptions{})
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
		expectedIPPoolStatus []antreacrds.ExternalIPPoolUsage
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
			expectedIPPoolStatus: []antreacrds.ExternalIPPoolUsage{
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
			expectedIPPoolStatus: []antreacrds.ExternalIPPoolUsage{
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
			expectedIPPoolStatus: []antreacrds.ExternalIPPoolUsage{
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
