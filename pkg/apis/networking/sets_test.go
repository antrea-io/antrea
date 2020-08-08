package networking

import (
	"net"
	"testing"
)

func BenchmarkNormalizeGroupMemberPod(b *testing.B) {
	pod := &GroupMemberPod{Pod: &PodReference{Namespace: "foo", Name: "bar"}, IP: IPAddress(net.ParseIP("1.1.1.1"))}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeGroupMemberPod(pod)
	}
}

func BenchmarkInsert(b *testing.B) {
	pod := &GroupMemberPod{Pod: &PodReference{Namespace: "foo", Name: "bar"}, IP: IPAddress(net.ParseIP("1.1.1.1"))}
	pods := NewGroupMemberPodSet()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pods.Insert(pod)
	}
}
