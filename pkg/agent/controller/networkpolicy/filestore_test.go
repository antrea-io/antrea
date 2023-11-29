// Copyright 2023 Antrea Authors
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

package networkpolicy

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

const (
	testDataPath = "/var/run/antrea-test/file-store"
)

// Set it to NewMemMapFs as the file system may be not writable.
// Change it to NewOsFs to evaluate performance when writing to disk.
var newFS = afero.NewMemMapFs

func newFakeFileStore(tb testing.TB, dir string) *fileStore {
	serializer := protobuf.NewSerializer(scheme, scheme)
	codec := codecs.CodecForVersions(serializer, serializer, v1beta2.SchemeGroupVersion, v1beta2.SchemeGroupVersion)
	// Create a new FS for every fileStore in case of interaction between tests.
	fs := afero.NewBasePathFs(newFS(), testDataPath)
	s, err := newFileStore(fs, dir, codec)
	assert.NoError(tb, err)
	return s
}

func TestFileStore(t *testing.T) {
	policy1 := newNetworkPolicy("policy1", "uid1", []string{"addressGroup1"}, nil, []string{"appliedToGroup1"}, nil)
	policy2 := newNetworkPolicy("policy2", "uid2", []string{"addressGroup2"}, nil, []string{"appliedToGroup2"}, nil)
	policy3 := newNetworkPolicy("policy3", "uid3", []string{"addressGroup3"}, nil, []string{"appliedToGroup3"}, nil)
	updatedPolicy2 := policy2.DeepCopy()
	updatedPolicy2.AppliedToGroups = []string{"foo"}

	tests := []struct {
		name            string
		ops             func(*fileStore)
		expectedObjects []runtime.Object
	}{
		{
			name: "add",
			ops: func(store *fileStore) {
				store.save(policy1)
				store.save(policy2)
				store.save(policy3)
			},
			expectedObjects: []runtime.Object{policy1, policy2, policy3},
		},
		{
			name: "update",
			ops: func(store *fileStore) {
				store.save(policy1)
				store.save(policy2)
				store.save(updatedPolicy2)
			},
			expectedObjects: []runtime.Object{policy1, updatedPolicy2},
		},
		{
			name: "delete",
			ops: func(store *fileStore) {
				store.save(policy1)
				store.save(policy2)
				store.delete(policy2)
			},
			expectedObjects: []runtime.Object{policy1},
		},
		{
			name: "replace",
			ops: func(store *fileStore) {
				store.save(policy1)
				store.save(policy2)
				store.replaceAll([]runtime.Object{updatedPolicy2, policy3})
			},
			expectedObjects: []runtime.Object{updatedPolicy2, policy3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newFakeFileStore(t, networkPoliciesDir)
			tt.ops(s)
			gotObjects, err := s.loadAll()
			require.NoError(t, err)
			assert.Equal(t, tt.expectedObjects, gotObjects)
		})
	}
}

func BenchmarkFileStoreAddNetworkPolicy(b *testing.B) {
	policy := newNetworkPolicy("policy1", types.UID(uuid.New().String()), []string{uuid.New().String()}, nil, []string{uuid.New().String()}, nil)
	s := newFakeFileStore(b, networkPoliciesDir)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.save(policy)
	}
}

func BenchmarkFileStoreAddAppliedToGroup(b *testing.B) {
	members := make([]v1beta2.GroupMember, 0, 100)
	for i := 0; i < 100; i++ {
		members = append(members, *newAppliedToGroupMemberPod(fmt.Sprintf("pod-%d", i), "namespace"))
	}
	atg := newAppliedToGroup(uuid.New().String(), members)
	s := newFakeFileStore(b, appliedToGroupsDir)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.save(atg)
	}
}

func BenchmarkFileStoreAddAddressGroup(b *testing.B) {
	members := make([]v1beta2.GroupMember, 0, 1000)
	for i := 0; i < 1000; i++ {
		members = append(members, *newAddressGroupPodMember(fmt.Sprintf("pod-%d", i), "namespace", "192.168.0.1"))
	}
	ag := newAddressGroup(uuid.New().String(), members)
	s := newFakeFileStore(b, addressGroupsDir)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.save(ag)
	}
}

func BenchmarkFileStoreReplaceAll(b *testing.B) {
	nps := make([]runtime.Object, 0, 1000)
	atgs := make([]runtime.Object, 0, 1000)
	ags := make([]runtime.Object, 0, 1000)
	for i := 0; i < 1000; i++ {
		policyName := uuid.New().String()
		addressGroupName := uuid.New().String()
		appliedToGroupName := uuid.New().String()
		nps = append(nps, newNetworkPolicy(policyName, types.UID(policyName), []string{addressGroupName}, nil, []string{appliedToGroupName}, nil))

		var atgMembers []v1beta2.GroupMember
		for j := 0; j < 100; j++ {
			atgMembers = append(atgMembers, *newAppliedToGroupMemberPod(fmt.Sprintf("pod-%d", j), "namespace"))
		}
		atg := newAppliedToGroup(appliedToGroupName, atgMembers)
		atgs = append(atgs, atg)

		var agMembers []v1beta2.GroupMember
		podNum := 100
		if i < 10 {
			podNum = 10000
		} else if i < 110 {
			podNum = 1000
		}
		for j := 0; j < podNum; j++ {
			agMembers = append(agMembers, *newAddressGroupPodMember(fmt.Sprintf("pod-%d", j), "namespace", "192.168.0.1"))
		}
		ag := newAddressGroup(addressGroupName, agMembers)
		ags = append(ags, ag)
	}

	networkPolicyStore := newFakeFileStore(b, networkPoliciesDir)
	appliedToGroupStore := newFakeFileStore(b, appliedToGroupsDir)
	addressGroupStore := newFakeFileStore(b, addressGroupsDir)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		networkPolicyStore.replaceAll(nps)
		appliedToGroupStore.replaceAll(atgs)
		addressGroupStore.replaceAll(ags)
	}
}
