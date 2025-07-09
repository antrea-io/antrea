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

package objectstore

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
)

// testObject implements the Object interface for testing
type testObject struct {
	uid          types.UID
	name         string
	namespace    string
	indexedValue string
	creationTime time.Time
}

func (o *testObject) GetUID() types.UID {
	return o.uid
}

func (o *testObject) GetName() string {
	return o.name
}

func (o *testObject) GetNamespace() string {
	return o.namespace
}

func (o *testObject) GetCreationTimestamp() metav1.Time {
	return metav1.NewTime(o.creationTime)
}

// testObject implements the Object interface
var _ Object = &testObject{}

// Test variables
var (
	refTime  = time.Now()
	refTime2 = refTime.Add(-5 * time.Minute)
	testObj1 = &testObject{
		uid:          "obj1",
		name:         "obj1",
		namespace:    "obj1_ns",
		indexedValue: "1.2.3.4",
		creationTime: refTime,
	}
	testObj2 = &testObject{
		uid:          "obj2",
		name:         "obj2",
		namespace:    "obj2_ns",
		indexedValue: "5.6.7.8",
		creationTime: refTime2,
	}
	testObj3 = &testObject{
		uid:          "obj3",
		name:         "obj1",
		namespace:    "obj1_ns",
		indexedValue: "1.2.3.4",
		creationTime: refTime2,
	}
	testTimestampMap = map[types.UID]*objectTimestamps{
		"obj1": {CreationTimestamp: refTime},
		"obj2": {CreationTimestamp: refTime2, DeletionTimestamp: &refTime},
		"obj3": {CreationTimestamp: refTime2, DeletionTimestamp: &refTime},
	}
)

func testIndexFunc(obj interface{}) ([]string, error) {
	testObj, ok := obj.(*testObject)
	if !ok {
		return nil, fmt.Errorf("object is not a testObject")
	}
	if testObj.indexedValue == "" {
		return nil, nil
	}
	return []string{testObj.indexedValue}, nil
}

func getObjectCreationTimestamp(obj *testObject, now time.Time) time.Time {
	return obj.creationTime
}

func newTestObjectStore(clock clock.WithTicker, delayTime time.Duration) *ObjectStore[*testObject] {
	return &ObjectStore[*testObject]{
		objects: cache.NewIndexer(objectKeyFunc, cache.Indexers{"testIndex": testIndexFunc}),
		objectsToDelete: workqueue.NewTypedDelayingQueueWithConfig(workqueue.TypedDelayingQueueConfig[types.UID]{
			Name:  "testDeleteQueue",
			Clock: clock,
		}),
		delayTime:                  delayTime,
		clock:                      clock,
		timestampMap:               map[types.UID]*objectTimestamps{},
		getObjectCreationTimestamp: getObjectCreationTimestamp,
	}
}

func Test_onObjectUpdate(t *testing.T) {
	fakeClock := clocktesting.NewFakeClock(time.Now())
	oldObj := &testObject{
		uid:       "obj1",
		name:      "obj1",
		namespace: "obj1_ns",
	}
	newObj1 := &testObject{
		uid:          "obj1",
		name:         "obj1",
		namespace:    "obj1_ns",
		indexedValue: "4.5.6.7",
	}
	newObj2 := &testObject{
		uid:       "obj1_new",
		name:      "obj1",
		namespace: "obj1_ns",
	}
	tests := []struct {
		name          string
		newObj        interface{}
		expectedObjs  []*testObject
		oldObjDeleted bool
	}{
		{
			name:         "newObj is not testObject",
			newObj:       &struct{}{},
			expectedObjs: []*testObject{oldObj},
		},
		{
			name:         "indexed value update",
			newObj:       newObj1,
			expectedObjs: []*testObject{newObj1},
		},
		{
			name:          "same name, new UID",
			newObj:        newObj2,
			expectedObjs:  []*testObject{oldObj, newObj2},
			oldObjDeleted: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestObjectStore(fakeClock, 0)
			require.NoError(t, store.addObject(oldObj))
			store.onObjectUpdate(oldObj, tt.newObj)
			objs := make([]*testObject, 0)
			for _, obj := range store.objects.List() {
				objs = append(objs, obj.(*testObject))
			}
			assert.ElementsMatch(t, tt.expectedObjs, objs)
			if tt.oldObjDeleted {
				require.Equal(t, 1, store.objectsToDelete.Len())
				uid, _ := store.objectsToDelete.Get()
				assert.Equal(t, oldObj.GetUID(), uid)
			} else {
				assert.Equal(t, 0, store.objectsToDelete.Len())
			}
		})
	}
}

func Test_onObjectCreate(t *testing.T) {
	tests := []struct {
		name        string
		obj         interface{}
		expectedMap map[types.UID]*objectTimestamps
	}{
		{
			name:        "object is not testObject",
			obj:         &struct{}{},
			expectedMap: map[types.UID]*objectTimestamps{},
		},
		{
			name:        "valid object",
			obj:         testObj1,
			expectedMap: map[types.UID]*objectTimestamps{"obj1": {CreationTimestamp: refTime}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestObjectStore(clocktesting.NewFakeClock(time.Now()), 0)
			store.onObjectCreate(tt.obj)
			assert.Equal(t, tt.expectedMap, store.timestampMap)
		})
	}
}

func Test_GetObjectByIndexAndTime(t *testing.T) {
	tests := []struct {
		name           string
		indexedValue   string
		startTime      time.Time
		expectedResult *testObject
	}{
		{
			name:           "no object in the object store",
			indexedValue:   "1.3.5.7",
			startTime:      refTime,
			expectedResult: nil,
		},
		{
			name:           "find only one object in the object store - correct startTime",
			indexedValue:   "5.6.7.8",
			startTime:      refTime.Add(-time.Minute),
			expectedResult: testObj2,
		},
		{
			name:           "find only one object in the object store - incorrect startTime",
			indexedValue:   "5.6.7.8",
			startTime:      refTime.Add(time.Minute),
			expectedResult: testObj2,
		},
		{
			name:           "find current object in the object store",
			indexedValue:   "1.2.3.4",
			startTime:      refTime.Add(time.Minute),
			expectedResult: testObj1,
		},
		{
			name:           "find previous object in the object store",
			indexedValue:   "1.2.3.4",
			startTime:      refTime.Add(-time.Minute),
			expectedResult: testObj3,
		},
		{
			name:           "cannot find the object in the object store - SearchTime < CreationTime",
			indexedValue:   "1.2.3.4",
			startTime:      refTime.Add(-time.Minute * 10),
			expectedResult: nil,
		},
		{
			name:           "cannot find the object in the object store - SearchTime > DeletionTime",
			indexedValue:   "1.2.3.4",
			startTime:      refTime,
			expectedResult: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestObjectStore(clocktesting.NewFakeClock(time.Now()), 0)
			require.NoError(t, store.objects.Add(testObj1))
			require.NoError(t, store.objects.Add(testObj2))
			require.NoError(t, store.objects.Add(testObj3))
			store.timestampMap = testTimestampMap

			obj, ok := store.GetObjectByIndexAndTime("testIndex", tt.indexedValue, tt.startTime)
			if tt.expectedResult == nil {
				assert.False(t, ok)
			} else {
				assert.True(t, ok)
				assert.Equal(t, tt.expectedResult, obj)
			}
		})
	}
}

func Test_onObjectDelete(t *testing.T) {
	deletionTime := time.Now()

	t.Run("invalid object", func(t *testing.T) {
		fakeClock := clocktesting.NewFakeClock(deletionTime)
		store := newTestObjectStore(fakeClock, delayTime)
		store.timestampMap = map[types.UID]*objectTimestamps{"obj1": {CreationTimestamp: refTime}}
		store.onObjectDelete(&struct{}{})
		expectedMap := map[types.UID]*objectTimestamps{"obj1": {CreationTimestamp: refTime}}
		assert.Equal(t, expectedMap, store.timestampMap)
	})

	t.Run("known object", func(t *testing.T) {
		fakeClock := clocktesting.NewFakeClock(deletionTime)
		store := newTestObjectStore(fakeClock, delayTime)
		store.timestampMap = map[types.UID]*objectTimestamps{"obj1": {CreationTimestamp: refTime}}
		store.onObjectDelete(testObj1)
		expectedMap := map[types.UID]*objectTimestamps{"obj1": {CreationTimestamp: refTime, DeletionTimestamp: &deletionTime}}
		assert.Equal(t, expectedMap, store.timestampMap)
		assert.Equal(t, 0, store.objectsToDelete.Len())
		expectedMapDeletionTime := deletionTime.Add(delayTime)
		fakeClock.SetTime(expectedMapDeletionTime.Add(-10 * time.Millisecond))
		assert.Equal(t, 0, store.objectsToDelete.Len())
		fakeClock.SetTime(expectedMapDeletionTime)
		assert.Eventuallyf(t, func() bool {
			return store.objectsToDelete.Len() == 1
		}, 1*time.Second, 10*time.Millisecond, "Object is not added to objectsToDelete")
	})
}

func Test_checkDeletedObject(t *testing.T) {
	tests := []struct {
		name           string
		obj            interface{}
		expectedResult *testObject
		expectedErr    string
	}{
		{
			name:        "not a DeletedFinalStateUnknown",
			obj:         &struct{}{},
			expectedErr: "received unexpected object: ",
		},
		{
			name:        "DeletedFinalStateUnknown with wrong type",
			obj:         cache.DeletedFinalStateUnknown{Obj: &struct{}{}},
			expectedErr: "DeletedFinalStateUnknown object is not of expected type",
		},
		{
			name:           "valid DeletedFinalStateUnknown",
			obj:            cache.DeletedFinalStateUnknown{Obj: testObj1},
			expectedResult: testObj1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestObjectStore(clocktesting.NewFakeClock(time.Now()), 0)
			obj, err := store.checkDeletedObject(tt.obj)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResult, obj)
			}
		})
	}
}

func Test_processDeleteQueueItem(t *testing.T) {
	store := newTestObjectStore(clocktesting.NewFakeClock(time.Now()), 0)
	store.timestampMap = map[types.UID]*objectTimestamps{"obj1": {}}
	require.NoError(t, store.objects.Add(testObj1))
	store.objectsToDelete.Add(testObj1.uid)
	result := store.processDeleteQueueItem(&objectKey{
		uid: testObj1.uid,
	})
	require.True(t, result)
	assert.Equal(t, 0, store.objectsToDelete.Len())
	assert.Len(t, store.objects.List(), 0)
	assert.Len(t, store.timestampMap, 0)
}

func Test_Run(t *testing.T) {
	store := newTestObjectStore(clocktesting.NewFakeClock(time.Now()), 0)
	store.timestampMap = map[types.UID]*objectTimestamps{"obj1": {}}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go store.Run(stopCh)
	require.NoError(t, store.objects.Add(testObj1))
	store.objectsToDelete.Add(testObj1.uid)
	assert.Eventuallyf(t, func() bool {
		store.mutex.RLock()
		defer store.mutex.RUnlock()
		return len(store.timestampMap) == 0
	}, 1*time.Second, 10*time.Millisecond, "Object is not deleted from timestampMap")
}
