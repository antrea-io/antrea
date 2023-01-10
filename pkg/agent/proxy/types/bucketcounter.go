package types

import (
	"sync"

	"antrea.io/antrea/pkg/agent/openflow"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

type BucketCounter interface {
	// AllocateIfNotExist generates a unique bucketID for an Endpoint of a Service if the bucketID has not been generated,
	// then return the bucketID (newly allocated or already allocated).
	AllocateIfNotExist(svcPortName k8sproxy.ServicePortName, endpoint k8sproxy.Endpoint) binding.BucketIDType
	// Get gets the bucket ID for the Endpoint of the Service.
	Get(svcPortName k8sproxy.ServicePortName, endpoint k8sproxy.Endpoint) (binding.BucketIDType, bool)
	// Recycle recycles a single bucket ID allocated for an Endpoint of a Service when endpoint is not nil, or removes
	// all bucket IDs allocated for a Service and its bucket ID allocator when endpoint is nil.
	Recycle(svcPortName k8sproxy.ServicePortName, endpoint k8sproxy.Endpoint) bool
}

type bucketCounter struct {
	mu               sync.Mutex
	bucketAllocators map[string]openflow.BucketAllocator
	bucketMap        map[string]map[string]binding.BucketIDType
}

func NewBucketCounter() *bucketCounter {
	return &bucketCounter{
		bucketAllocators: make(map[string]openflow.BucketAllocator),
		bucketMap:        make(map[string]map[string]binding.BucketIDType),
	}
}

func (c *bucketCounter) AllocateIfNotExist(svcPortName k8sproxy.ServicePortName, endpoint k8sproxy.Endpoint) binding.BucketIDType {
	c.mu.Lock()
	defer c.mu.Unlock()

	serviceString := svcPortName.String()
	if _, ok := c.bucketAllocators[serviceString]; !ok {
		c.bucketAllocators[serviceString] = openflow.NewBucketAllocator()
		c.bucketMap[serviceString] = make(map[string]binding.BucketIDType)
	}
	endpointString := endpoint.String()
	if id, ok := c.bucketMap[serviceString][endpointString]; ok {
		return id
	}
	id := c.bucketAllocators[serviceString].Allocate()
	c.bucketMap[serviceString][endpointString] = id
	return id
}

func (c *bucketCounter) Get(svcPortName k8sproxy.ServicePortName, endpoint k8sproxy.Endpoint) (binding.BucketIDType, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	serviceString := svcPortName.String()
	bucketIDs, exist := c.bucketMap[serviceString]
	if !exist {
		return 0, exist
	}
	endpointString := endpoint.String()
	id, exist := bucketIDs[endpointString]
	return id, exist
}

func (c *bucketCounter) Recycle(svcPortName k8sproxy.ServicePortName, endpoint k8sproxy.Endpoint) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	serviceString := svcPortName.String()
	bucketIDs, exist := c.bucketMap[serviceString]
	if !exist {
		return false
	}
	if endpoint != nil {
		endpointString := endpoint.String()
		if id, ok := bucketIDs[endpointString]; ok {
			delete(bucketIDs, endpointString)
			c.bucketAllocators[serviceString].Release(id)
			return true
		}
	} else {
		delete(c.bucketAllocators, serviceString)
		delete(c.bucketMap, serviceString)
	}

	return false
}
