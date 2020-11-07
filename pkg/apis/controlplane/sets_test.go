package controlplane

import (
	"net"
	"testing"
)

func BenchmarkNormalizeGroupMemberPod(b *testing.B) {
	pod := &GroupMember{Pod: &PodReference{
		Namespace: "foo", Name: "bar"},
		IPs: []IPAddress{IPAddress(net.ParseIP("1.1.1.1"))},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeGroupMember(pod)
	}
}

func BenchmarkInsert(b *testing.B) {
	pod := &GroupMember{Pod: &PodReference{
		Namespace: "foo", Name: "bar"},
		IPs: []IPAddress{IPAddress(net.ParseIP("1.1.1.1"))},
	}
	pods := NewGroupMemberSet()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pods.Insert(pod)
	}
}
