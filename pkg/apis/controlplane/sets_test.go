// Copyright 2022 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
