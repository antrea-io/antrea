package egress

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewIPAllocator(t *testing.T) {
	allocator := newIPAllocator(22)
	assert.Equalf(t, 22, allocator.unallocatedPool.Len(), "the IPAllocator's size should match unallocatedPool's size after initialization")
}

func TestAllocateAndReleaseIP(t *testing.T) {
	allocator := newIPAllocator(2)

	allocator.allocateForIP("10.10.10.10")
	assert.Equalf(t, 1, len(allocator.allocatedIPMap), "Got allocatedIPMap size %v, expected %v", allocator.unallocatedPool.Len(), 1)
	assert.Equalf(t, 1, allocator.unallocatedPool.Len(), "Got availunallocatedPool size %v, expected %v", allocator.unallocatedPool.Len(), 1)
	assert.Equalf(t, uint32(1), allocator.allocatedIPMap["10.10.10.10"], "Got allocated id %v, expected %v", allocator.allocatedIPMap["10.10.10.10"], uint32(1))

	allocator.allocateForIP("10.10.10.11")
	assert.Equalf(t, 2, len(allocator.allocatedIPMap), "Got allocatedIPMap size %v, expected %v", allocator.unallocatedPool.Len(), 2)
	assert.Equalf(t, 0, allocator.unallocatedPool.Len(), "Got availunallocatedPool size %v, expected %v", allocator.unallocatedPool.Len(), 0)
	assert.Equalf(t, uint32(2), allocator.allocatedIPMap["10.10.10.11"], "Got allocated id %v, expected %v", allocator.allocatedIPMap["10.10.10.11"], uint32(2))

	_, err3 := allocator.allocateForIP("10.10.10.11")
	assert.NotNil(t, err3)
	assert.Equalf(t, "ip 10.10.10.11 already allocated", err3.Error(), "Got error message %v, expected %v", err3.Error(), "ip 10.10.10.11 already allocated")

	_, err4 := allocator.allocateForIP("10.10.10.12")
	assert.NotNil(t, err4)
	assert.Equalf(t, "no ID available", err4.Error(), "Got error message %v, expected %v", err3.Error(), "no ID available")

	allocator.release("10.10.10.10")
	assert.Equalf(t, 1, len(allocator.allocatedIPMap), "Got allocatedIPMap size %v, expected %v", allocator.unallocatedPool.Len(), 1)
	assert.Equalf(t, 1, allocator.unallocatedPool.Len(), "Got availunallocatedPool size %v, expected %v", allocator.unallocatedPool.Len(), 1)

	_, err5 := allocator.release("10.10.10.10")
	assert.NotNil(t, err5)
	assert.Equalf(t, "ip 10.10.10.10 is not allocated", err5.Error(), "Got error message %v, expected %v", err5.Error(), "ip 10.10.10.10 is not allocated")
}
