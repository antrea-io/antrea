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

package podstore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	clock "k8s.io/utils/clock/testing"
)

var (
	refTime  = time.Now()
	refTime2 = refTime.Add(-5 * time.Minute)
	pod1     = &v1.Pod{
		Status: v1.PodStatus{
			PodIPs: []v1.PodIP{
				{
					IP: "1.2.3.4",
				},
			},
			Phase: v1.PodPending,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pod1",
			Namespace:         "pod1_ns",
			UID:               "pod1",
			CreationTimestamp: metav1.Time{Time: refTime2},
		},
	}
	pod2 = &v1.Pod{
		Status: v1.PodStatus{
			PodIPs: []v1.PodIP{
				{
					IP: "5.6.7.8",
				},
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pod2",
			Namespace:         "pod2_ns",
			UID:               "pod2",
			CreationTimestamp: metav1.Time{Time: refTime2},
			DeletionTimestamp: &metav1.Time{Time: refTime},
		},
	}
	pod3 = &v1.Pod{
		Status: v1.PodStatus{
			PodIPs: []v1.PodIP{
				{
					IP: "4.3.2.1",
				},
			},
			Phase: v1.PodRunning,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pod3",
			Namespace:         "pod3_ns",
			UID:               "pod3",
			CreationTimestamp: metav1.Time{Time: refTime2},
		},
	}
	pod4 = &v1.Pod{
		Status: v1.PodStatus{
			PodIPs: []v1.PodIP{
				{
					IP: "1.2.3.4",
				},
			},
			Phase: v1.PodSucceeded,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pod1",
			Namespace:         "pod1_ns",
			UID:               "pod4",
			CreationTimestamp: metav1.Time{Time: refTime2},
			DeletionTimestamp: &metav1.Time{Time: refTime},
		},
	}
	timestampMap = map[types.UID]*podTimestamps{
		"pod1": {CreationTimestamp: refTime},
		"pod2": {CreationTimestamp: refTime2, DeletionTimestamp: &refTime},
		"pod4": {CreationTimestamp: refTime2, DeletionTimestamp: &refTime},
	}
	node = &v1.Node{}
)

func Test_onPodUpdate(t *testing.T) {
	newPod1 := &v1.Pod{
		Status: v1.PodStatus{
			PodIPs: []v1.PodIP{
				{
					IP: "4.5.6.7",
				},
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod1",
			Namespace: "pod1_ns",
			UID:       "pod1",
		},
	}
	tests := []struct {
		name        string
		oldObj      interface{}
		newObj      interface{}
		expectedPod *v1.Pod
	}{
		{
			name:        "newObj is not Pod",
			newObj:      node,
			expectedPod: pod1,
		},
		{
			name:        "valid case",
			newObj:      newPod1,
			expectedPod: newPod1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			podStore := &PodStore{
				pods: cache.NewIndexer(podKeyFunc, cache.Indexers{podIPIndex: podIPIndexFunc}),
			}
			require.NoError(t, podStore.pods.Add(pod1))
			podStore.onPodUpdate(tt.oldObj, tt.newObj)
			require.Len(t, podStore.pods.List(), 1)
			assert.Equal(t, tt.expectedPod, podStore.pods.List()[0].(*v1.Pod))
		})
	}
}

func Test_onPodCreate(t *testing.T) {
	tests := []struct {
		name        string
		obj         interface{}
		expectedMap map[types.UID]*podTimestamps
	}{
		{
			name:        "object is not Pod",
			obj:         node,
			expectedMap: map[types.UID]*podTimestamps{},
		},
		{
			name:        "valid case for Pending Pod",
			obj:         pod1,
			expectedMap: map[types.UID]*podTimestamps{"pod1": {CreationTimestamp: refTime}},
		},
		{
			name:        "valid case for Running Pod",
			obj:         pod3,
			expectedMap: map[types.UID]*podTimestamps{"pod3": {CreationTimestamp: refTime2}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			podStore := &PodStore{
				timestampMap: map[types.UID]*podTimestamps{},
				clock:        clock.NewFakeClock(refTime),
				pods:         cache.NewIndexer(podKeyFunc, cache.Indexers{podIPIndex: podIPIndexFunc}),
			}
			podStore.onPodCreate(tt.obj)
			assert.Equal(t, tt.expectedMap, podStore.timestampMap)
		})
	}
}

func Test_onPodDelete(t *testing.T) {
	t.Run("object is neither Pod nor DeletedFinalStateUnknown", func(t *testing.T) {
		k8sClient := fake.NewSimpleClientset()
		podInformer := coreinformers.NewPodInformer(k8sClient, metav1.NamespaceAll, 0, cache.Indexers{})
		podStore := NewPodStore(podInformer)
		require.NoError(t, podStore.pods.Add(pod1))
		podStore.timestampMap = map[types.UID]*podTimestamps{"pod1": {CreationTimestamp: refTime}}
		podStore.onPodDelete(node)
		assert.Equal(t, &podTimestamps{CreationTimestamp: refTime}, podStore.timestampMap["pod1"])
	})
	t.Run("Pod is in prevPod and podsToDelete", func(t *testing.T) {
		k8sClient := fake.NewSimpleClientset()
		podInformer := coreinformers.NewPodInformer(k8sClient, metav1.NamespaceAll, 0, cache.Indexers{})
		fakeClock := clock.NewFakeClock(refTime)
		podStore := NewPodStoreWithClock(podInformer, fakeClock)
		require.NoError(t, podStore.pods.Add(pod1))
		podStore.timestampMap = map[types.UID]*podTimestamps{"pod1": {CreationTimestamp: refTime}}
		expectedDeleteTime := refTime.Add(delayTime)
		podStore.onPodDelete(pod1)
		assert.Equal(t, &podTimestamps{CreationTimestamp: refTime, DeletionTimestamp: &refTime}, podStore.timestampMap["pod1"])
		fakeClock.SetTime(expectedDeleteTime.Add(-10 * time.Millisecond))
		assert.Equal(t, podStore.podsToDelete.Len(), 0)
		fakeClock.SetTime(expectedDeleteTime.Add(10 * time.Millisecond))
		assert.Eventuallyf(t, func() bool {
			return podStore.podsToDelete.Len() == 1
		}, 1*time.Second, 10*time.Millisecond, "Pod is not added to PodsToDelete")
	})
}

func Test_checkDeletedPod(t *testing.T) {
	tests := []struct {
		name           string
		obj            interface{}
		expectedResult *v1.Pod
		expectedErr    string
	}{
		{
			name:        "object is not DeletedFinalStateUnknown",
			obj:         node,
			expectedErr: "received unexpected object: ",
		},
		{
			name:        "object in DeletedFinalStateUnknown is not Pod",
			obj:         cache.DeletedFinalStateUnknown{Obj: node},
			expectedErr: "DeletedFinalStateUnknown object is not of type Pod",
		},
		{
			name:           "valid case",
			obj:            cache.DeletedFinalStateUnknown{Obj: pod1},
			expectedResult: pod1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod, err := (&PodStore{}).checkDeletedPod(tt.obj)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResult, pod)
			}
		})
	}
}

func Test_GetPodByIPAndTime(t *testing.T) {
	tests := []struct {
		name           string
		ip             string
		startTime      time.Time
		expectedResult *v1.Pod
	}{
		{
			name:           "no Pod in the Pod store",
			ip:             "1.3.5.7",
			startTime:      refTime,
			expectedResult: nil,
		},
		{
			name:           "find only one Pod in the Pod store - correct startTime",
			ip:             "5.6.7.8",
			startTime:      refTime.Add(-time.Minute),
			expectedResult: pod2,
		},
		{
			name:           "find only one Pod in the Pod store - incorrect startTime",
			ip:             "5.6.7.8",
			startTime:      refTime.Add(time.Minute),
			expectedResult: pod2,
		},
		{
			name:           "find current Pod in the Pod store",
			ip:             "1.2.3.4",
			startTime:      refTime.Add(time.Minute),
			expectedResult: pod1,
		},
		{
			name:           "find previous Pod in the Pod store",
			ip:             "1.2.3.4",
			startTime:      refTime.Add(-time.Minute),
			expectedResult: pod4,
		},
		{
			name:           "cannot find the Pod in the Pod store - SearchTime < CreationTime",
			ip:             "1.2.3.4",
			startTime:      refTime.Add(-time.Minute * 10),
			expectedResult: nil,
		},
		{
			name:           "cannot find the Pod in the Pod store - SearchTime > DeletionTime",
			ip:             "1.2.3.4",
			startTime:      refTime,
			expectedResult: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sClient := fake.NewSimpleClientset()
			podInformer := coreinformers.NewPodInformer(k8sClient, metav1.NamespaceAll, 0, cache.Indexers{})
			podStore := NewPodStore(podInformer)
			require.NoError(t, podStore.pods.Add(pod1))
			require.NoError(t, podStore.pods.Add(pod2))
			require.NoError(t, podStore.pods.Add(pod4))
			podStore.timestampMap = timestampMap
			pod, ok := podStore.GetPodByIPAndTime(tt.ip, tt.startTime)
			if tt.expectedResult == nil {
				assert.False(t, ok)
			} else {
				assert.True(t, ok)
				assert.Equal(t, tt.expectedResult, pod)
			}
		})
	}
}

func Test_processDeleteQueueItem(t *testing.T) {
	fakeClock := clock.NewFakeClock(time.Now())
	podStore := &PodStore{
		pods:         cache.NewIndexer(podKeyFunc, cache.Indexers{podIPIndex: podIPIndexFunc}),
		podsToDelete: workqueue.NewDelayingQueueWithCustomClock(fakeClock, deleteQueueName),
		timestampMap: map[types.UID]*podTimestamps{"pod1": {}},
	}
	require.NoError(t, podStore.pods.Add(pod1))
	podStore.podsToDelete.Add(pod1)
	result := podStore.processDeleteQueueItem()
	require.Equal(t, true, result)
	assert.Equal(t, 0, podStore.podsToDelete.Len())
	assert.Len(t, podStore.pods.List(), 0)
	assert.Len(t, podStore.timestampMap, 0)
}

func Test_podKeyFunc(t *testing.T) {
	tests := []struct {
		name           string
		obj            interface{}
		expectedResult string
		expectedErr    string
	}{
		{
			name:        "object is not Pod",
			obj:         node,
			expectedErr: "obj is not Pod: ",
		},
		{
			name:           "valid case",
			obj:            pod1,
			expectedResult: "pod1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := podKeyFunc(tt.obj)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResult, got)
			}
		})
	}
}

func Test_podIPIndexFunc(t *testing.T) {
	tests := []struct {
		name           string
		obj            interface{}
		expectedResult []string
		expectedErr    string
	}{
		{
			name:        "object is not Pod",
			obj:         node,
			expectedErr: "obj is not Pod:",
		},
		{
			name:           "valid case",
			obj:            pod1,
			expectedResult: []string{"1.2.3.4"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := podIPIndexFunc(tt.obj)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.ElementsMatch(t, tt.expectedResult, got)
			}
		})
	}
}

/*
Sample output:
goos: darwin
goarch: amd64
pkg: antrea.io/antrea/pkg/util/podstore
cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
BenchmarkGetPodByIPAndTime
BenchmarkGetPodByIPAndTime/input_size_100
BenchmarkGetPodByIPAndTime/input_size_100-12         	 2232166	       538.6 ns/op
    podstore_test.go:465:
        Summary:
        Number of initial Pods: 100
        Total times of calling GetPodByIPAndTime: 3242267
        Total times of successfully finding Pod in podStore: 3242267
BenchmarkGetPodByIPAndTime/input_size_1000
BenchmarkGetPodByIPAndTime/input_size_1000-12        	 2238074	       551.0 ns/op
    podstore_test.go:465:
        Summary:
        Number of initial Pods: 1000
        Total times of calling GetPodByIPAndTime: 3248175
        Total times of successfully finding Pod in podStore: 3248175
BenchmarkGetPodByIPAndTime/input_size_10000
BenchmarkGetPodByIPAndTime/input_size_10000-12       	 1000000	      1043 ns/op
    podstore_test.go:465:
        Summary:
        Number of initial Pods: 10000
        Total times of calling GetPodByIPAndTime: 1010101
        Total times of successfully finding Pod in podStore: 1010101
PASS
*/

func BenchmarkGetPodByIPAndTime(b *testing.B) {
	var PodNumber = []struct {
		input int
	}{
		{input: 100},
		{input: 1000},
		{input: 10000},
	}
	for _, v := range PodNumber {
		success := 0
		total := 0
		k8sClient := fake.NewSimpleClientset()
		podInformer := coreinformers.NewPodInformer(k8sClient, metav1.NamespaceAll, 0, cache.Indexers{})
		podStore := NewPodStore(podInformer)
		stopCh := make(chan struct{})
		go podInformer.Run(stopCh)
		cache.WaitForCacheSync(stopCh, podInformer.HasSynced)
		podArray, err := addPods(v.input, k8sClient)
		if err != nil {
			b.Fatalf("error when adding Pods: %v", err)
		}
		assert.Eventuallyf(b, func() bool {
			return len(podInformer.GetIndexer().List()) == v.input
		}, 1*time.Second, 10*time.Millisecond, "Pods should be added to podInformer")
		errChan := make(chan error)
		go func() {
			err = deletePodsK8s(podArray, k8sClient)
			if err != nil {
				errChan <- err
				return
			}
			close(errChan)
		}()
		b.Run(fmt.Sprintf("input_size_%d", v.input), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				randomPod := podArray[rand.Intn(v.input)]
				creationTime := podStore.timestampMap[randomPod.UID].CreationTimestamp
				_, ok := podStore.GetPodByIPAndTime(randomPod.Status.PodIPs[0].IP, creationTime.Add(time.Millisecond))
				total++
				if ok {
					success++
				}
			}
		})
		close(stopCh)
		err = <-errChan
		if err != nil {
			b.Fatalf("error when deleting Pods: %v", err)
		}
		b.Logf("\nSummary:\nNumber of initial Pods: %d\nTotal times of calling GetPodByIPAndTime: %d\nTotal times of successfully finding Pod in podStore: %d\n", v.input, total, success)
	}
}

func deletePodsK8s(pods []*v1.Pod, k8sClient kubernetes.Interface) error {
	for _, pod := range pods {
		err := k8sClient.CoreV1().Pods(pod.Namespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("error when deleting Pods through k8s api: %v", err)
		}
		// the channel will be full if no sleep time.
		time.Sleep(time.Millisecond)
	}
	return nil
}

func addPods(number int, k8sClient kubernetes.Interface) ([]*v1.Pod, error) {
	var podArray []*v1.Pod
	for i := 0; i < number; i++ {
		pod := generatePod()
		_, err := k8sClient.CoreV1().Pods(pod.Namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
		if err != nil {
			return nil, fmt.Errorf("error when adding Pods through k8s api: %v", err)
		}
		// the channel will be full if no sleep time.
		time.Sleep(time.Millisecond)
		podArray = append(podArray, pod)
	}
	return podArray, nil
}

func generatePod() *v1.Pod {
	ip := getRandomIP()
	uid := uuid.New().String()
	startTime := rand.Intn(360000000)
	creationTime := refTime.Add(time.Duration(startTime))
	deletionTime := creationTime.Add(time.Hour)
	pod := &v1.Pod{
		Status: v1.PodStatus{
			PodIPs: []v1.PodIP{
				{
					IP: ip,
				},
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			CreationTimestamp: metav1.Time{Time: creationTime},
			DeletionTimestamp: &metav1.Time{Time: deletionTime},
			Name:              "pod-" + uid,
			Namespace:         "pod_ns",
			UID:               types.UID(uid),
		},
	}
	return pod
}

func getRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
}
