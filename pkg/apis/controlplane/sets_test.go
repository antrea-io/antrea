package controlplane

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

func BenchmarkUInt32Insert(b *testing.B) {
	priorities := UInt32{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		priorities.Insert(uint32(i))
	}
}

func TestUInt32Set(t *testing.T) {
	i := UInt32{}
	u10 := uint32(10)
	u20 := uint32(20)
	u30 := uint32(30)
	u40 := uint32(40)
	if len(i) != 0 {
		t.Errorf("Expected len=0: %d", len(i))
	}
	i.Insert(u10, u20)
	if len(i) != 2 {
		t.Errorf("Expected len=2: %d", len(i))
	}
	i.Insert(u30)
	if i.Has(u40) {
		t.Errorf("Unexpected contents: %#v", i)
	}
	if !i.Has(u10) {
		t.Errorf("Missing contents: %#v", i)
	}
	i.Delete(u10)
	if i.Has(u10) {
		t.Errorf("Unexpected contents: %#v", i)
	}
}

func TestUInt32SetDeleteMultiples(t *testing.T) {
	i := UInt32{}
	u10 := uint32(10)
	u20 := uint32(20)
	u30 := uint32(30)
	u40 := uint32(40)
	i.Insert(u10, u20, u30, u40)
	if len(i) != 4 {
		t.Errorf("Expected len=4: %d", len(i))
	}

	i.Delete(u30, u10)
	if len(i) != 2 {
		t.Errorf("Expected len=2: %d", len(i))
	}
	if i.Has(u10) {
		t.Errorf("Unexpected contents: %#v", i)
	}
	if i.Has(u30) {
		t.Errorf("Unexpected contents: %#v", i)
	}
	if !i.Has(u40) {
		t.Errorf("Missing contents: %#v", i)
	}

}
