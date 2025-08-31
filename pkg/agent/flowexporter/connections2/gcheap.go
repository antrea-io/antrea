package connections2

import "antrea.io/antrea/pkg/agent/flowexporter/connection"

type gcItem struct {
	key      connection.ConnKey
	expiryMs int64
	index    int
}
type gcHeap []*gcItem

func (h gcHeap) Len() int           { return len(h) }
func (h gcHeap) Less(i, j int) bool { return h[i].expiryMs < h[j].expiryMs }
func (h gcHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *gcHeap) Push(x interface{}) { *h = append(*h, x.(*gcItem)) }
func (h *gcHeap) Pop() interface{} {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}
