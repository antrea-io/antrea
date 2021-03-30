package egress

import (
	"container/list"
	"fmt"
	"sync"
)

type IPAllocator struct {
	sync.Mutex
	size            uint32
	unallocatedPool *list.List
	allocatedIPMap  map[string]uint32
}

func (a *IPAllocator) allocateForIP(ip string) (uint32, error) {
	a.Lock()
	defer a.Unlock()

	if _, exist := a.allocatedIPMap[ip]; exist {
		return 0, fmt.Errorf("ip %s already allocated", ip)
	}

	if a.unallocatedPool.Len() == 0 {
		return 0, fmt.Errorf("no ID available")
	}

	firstUnallocated := a.unallocatedPool.Front()
	value := a.unallocatedPool.Remove(firstUnallocated)

	v := value.(uint32)
	a.allocatedIPMap[ip] = v
	return v, nil
}

func (a *IPAllocator) release(ip string) (uint32, error) {
	a.Lock()
	defer a.Unlock()

	if _, exist := a.allocatedIPMap[ip]; !exist {
		return 0, fmt.Errorf("ip %s is not allocated", ip)
	}

	value := a.allocatedIPMap[ip]
	delete(a.allocatedIPMap, ip)
	a.unallocatedPool.PushFront(value)
	return value, nil
}

func newIPAllocator(size uint32) *IPAllocator {
	unallocatedPool := list.New()
	for i := uint32(1); uint32(i) <= size; i++ {
		unallocatedPool.PushBack(i)
	}
	return &IPAllocator{
		size:            size,
		unallocatedPool: unallocatedPool,
		allocatedIPMap:  make(map[string]uint32),
	}
}
