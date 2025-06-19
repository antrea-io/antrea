// Copyright 2025 Antrea Authors
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

package filestore

import (
	"encoding/gob"
	"testing"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"github.com/google/uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testDataPath   = "/var/run/antrea-test/file-store"
	testObjectsDir = "test"
)

// Set it to NewMemMapFs as the file system may be not writable.
// Change it to NewOsFs to evaluate performance when writing to disk.
var newFS = afero.NewMemMapFs

func init() {
	gob.Register(&interfacestore.InterfaceConfig{})
}

func newAnyObjectWithID(uid string, podName, podNamespace string, netNS string) AnyObjectWithID {
	return AnyObjectWithID{
		UID: uid,
		Object: &interfacestore.InterfaceConfig{
			InterfaceName: "eth0",
			ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
				PodName:      podName,
				PodNamespace: podNamespace,
				NetNS:        netNS,
			},
		},
	}
}

func newFakeFileStore(tb testing.TB, dir string) *FileStore {
	serializer := &GobSerializer{}
	// Create a new FS for every fileStore in case of interaction between tests.
	fs := afero.NewBasePathFs(newFS(), testDataPath)
	s, err := NewFileStore(fs, dir, serializer)
	assert.NoError(tb, err)
	return s
}

func TestFileStore(t *testing.T) {
	object1 := newAnyObjectWithID("uid1", "pod1", "ns1", "netns1")
	object2 := newAnyObjectWithID("uid2", "pod2", "ns2", "netns2")
	object3 := newAnyObjectWithID("uid3", "pod3", "ns3", "netns3")
	updatedObject2 := object2
	updatedObject2.Object = &interfacestore.InterfaceConfig{
		InterfaceName: "eth1",
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
			PodName:      "podName",
			PodNamespace: "podNamespace",
			NetNS:        "netNS",
		},
	}

	tests := []struct {
		name            string
		ops             func(*FileStore)
		expectedObjects []AnyObjectWithID
	}{
		{
			name: "add",
			ops: func(store *FileStore) {
				store.Save(object1)
				store.Save(object2)
				store.Save(object3)
			},
			expectedObjects: []AnyObjectWithID{object1, object2, object3},
		},
		{
			name: "update",
			ops: func(store *FileStore) {
				store.Save(object1)
				store.Save(object2)
				store.Save(updatedObject2)
			},
			expectedObjects: []AnyObjectWithID{object1, updatedObject2},
		},
		{
			name: "delete",
			ops: func(store *FileStore) {
				store.Save(object1)
				store.Save(object2)
				store.Delete(object2)
			},
			expectedObjects: []AnyObjectWithID{object1},
		},
		{
			name: "replace",
			ops: func(store *FileStore) {
				store.Save(object1)
				store.Save(object2)
				store.ReplaceAll([]AnyObjectWithID{updatedObject2, object3})
			},
			expectedObjects: []AnyObjectWithID{updatedObject2, object3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newFakeFileStore(t, testObjectsDir)
			tt.ops(s)
			gotObjects, err := s.LoadAll()
			require.NoError(t, err)
			assert.Equal(t, tt.expectedObjects, gotObjects)
		})
	}
}

func BenchmarkFileStoreAddTestObject(b *testing.B) {
	object := newAnyObjectWithID(uuid.New().String(), "pod1", "podNS", "netns1")
	s := newFakeFileStore(b, testObjectsDir)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.Save(object)
	}
}

func BenchmarkFileStoreReplaceAll(b *testing.B) {
	objs := make([]AnyObjectWithID, 0, 1000)
	for i := 0; i < 1000; i++ {
		objectID := uuid.New().String()
		objectName := uuid.New().String()
		objs = append(objs, newAnyObjectWithID(objectID, objectName, "ns1", "netns"))
	}

	testObjectStore := newFakeFileStore(b, testObjectsDir)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		testObjectStore.ReplaceAll(objs)
	}
}
