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

package objectstore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/v2/pkg/util/k8s"
)

var (
	testPod1 = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pod1",
			Namespace:         "pod1_ns",
			UID:               "pod1",
			CreationTimestamp: metav1.Time{Time: refTime2},
		},
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{
				{
					IP: "1.2.3.4",
				},
			},
			Phase: corev1.PodPending,
		},
	}
	testPod2 = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pod2",
			Namespace:         "pod2_ns",
			UID:               "pod2",
			CreationTimestamp: metav1.Time{Time: refTime2},
			DeletionTimestamp: &metav1.Time{Time: refTime},
		},
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{
				{
					IP: "5.6.7.8",
				},
			},
		},
	}
	// dual-stack Pod
	testPod3 = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pod3",
			Namespace:         "pod3_ns",
			UID:               "pod3",
			CreationTimestamp: metav1.Time{Time: refTime2},
		},
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{
				{
					IP: "9.10.11.12",
				},
				{
					IP: "2025:1::aaa1",
				},
			},
		},
	}
	hostNetworkPod = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "hnpod",
			UID:               "hnpod",
			CreationTimestamp: metav1.Time{Time: refTime2},
		},
		Spec: corev1.PodSpec{
			HostNetwork: true,
		},
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{
				{
					IP: "172.18.0.1",
				},
			},
			Phase: corev1.PodSucceeded,
		},
	}
)

func getPodInformer(k8sClient kubernetes.Interface) cache.SharedIndexInformer {
	podInformer := coreinformers.NewPodInformer(
		k8sClient,
		metav1.NamespaceAll,
		0, // no resync
		cache.Indexers{},
	)
	// Trim Pod objects to match antrea-agent / flow-aggregator.
	podInformer.SetTransform(k8s.NewTrimmer(k8s.TrimPod))
	return podInformer
}

func Test_GetPodByIPAndTime(t *testing.T) {
	testCases := []struct {
		name string
		pod  *corev1.Pod
		ips  []string
	}{
		{
			name: "ipv4-only",
			pod:  testPod2,
			ips:  []string{"5.6.7.8"},
		},
		{
			name: "dual-stack",
			pod:  testPod3,
			ips:  []string{"9.10.11.12", "2025:1::aaa1"},
		},
	}

	for _, tc := range testCases {
		stopCh := make(chan struct{})
		defer close(stopCh)
		k8sClient := fake.NewSimpleClientset()
		podInformer := getPodInformer(k8sClient)
		podStore := NewPodStore(podInformer)
		go podInformer.Run(stopCh)
		cache.WaitForCacheSync(stopCh, podInformer.HasSynced)
		_, err := k8sClient.CoreV1().Pods(tc.pod.Namespace).Create(context.TODO(), tc.pod, metav1.CreateOptions{})
		require.NoError(t, err)
		assert.EventuallyWithT(t, func(t *assert.CollectT) {
			for _, ip := range tc.ips {
				pod, ok := podStore.GetPodByIPAndTime(ip, refTime.Add(-time.Minute))
				if assert.True(t, ok) {
					assert.Equal(t, tc.pod, pod)
				}
			}
		}, 1*time.Second, 10*time.Millisecond)
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
			obj:         &struct{}{},
			expectedErr: "obj is not Pod:",
		},
		{
			name:           "valid case",
			obj:            testPod1,
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

func Test_noHostNetworkPod(t *testing.T) {
	k8sClient := fake.NewSimpleClientset(hostNetworkPod, testPod1)
	podInformer := getPodInformer(k8sClient)
	podStore := NewPodStore(podInformer)
	stopCh := make(chan struct{})
	go podInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, podInformer.HasSynced)
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		podStore.mutex.RLock()
		defer podStore.mutex.RUnlock()
		assert.Contains(t, podStore.timestampMap, testPod1.UID)
	}, 1*time.Second, 10*time.Millisecond)
	// hostNetworkPod should never be added to the store.
	assert.Never(t, func() bool {
		podStore.mutex.RLock()
		defer podStore.mutex.RUnlock()
		// pod1 should stay the only Pod in the store.
		return len(podStore.timestampMap) != 1
	}, 100*time.Millisecond, 10*time.Millisecond, "host-network Pods should be filtered out by informer")
}

// Test_podTerminationExcludesFromStore validates that when a running Pod transitions to a
// terminal phase (Succeeded/Failed), the update event causes it to be treated as a deletion
// by the FilteringResourceEventHandler, setting a DeletionTimestamp in the store and making
// GetPodByIPAndTime no longer return it.
func Test_podTerminationExcludesFromStore(t *testing.T) {
	const testPodIP = "10.1.2.3"
	runningPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "job-pod",
			Namespace:         "default",
			UID:               "job-pod-uid",
			CreationTimestamp: metav1.Time{Time: refTime2},
		},
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{{IP: testPodIP}},
			Phase:  corev1.PodRunning,
		},
	}

	k8sClient := fake.NewSimpleClientset()
	podInformer := getPodInformer(k8sClient)
	podStore := NewPodStore(podInformer)
	stopCh := make(chan struct{})
	defer close(stopCh)

	go podInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, podInformer.HasSynced)

	// Step 1: create the running Pod and verify it is indexed.
	// The Pod's CreationTimestamp is refTime2; we query slightly after that so the
	// timestamp filter passes while the Pod is still running.
	_, err := k8sClient.CoreV1().Pods(runningPod.Namespace).Create(context.TODO(), runningPod, metav1.CreateOptions{})
	require.NoError(t, err)
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		pod, ok := podStore.GetPodByIPAndTime(testPodIP, refTime2.Add(time.Second))
		if assert.True(t, ok, "running Pod should be found by IP lookup") {
			assert.Equal(t, runningPod.UID, pod.UID)
		}
	}, 1*time.Second, 10*time.Millisecond)

	// Step 2: update the same Pod to Succeeded.
	succeededPod := runningPod.DeepCopy()
	succeededPod.Status.Phase = corev1.PodSucceeded
	_, err = k8sClient.CoreV1().Pods(succeededPod.Namespace).UpdateStatus(context.TODO(), succeededPod, metav1.UpdateOptions{})
	require.NoError(t, err)

	// Step 3: verify the Pod is no longer returned even while it is still the only entry
	// in the indexer (during the 5-minute grace period before complete removal from store).
	// The FilteringResourceEventHandler translates the filter transition
	// (older passed FilterFunc, newer does not) into onObjectDelete(), which
	// records DeletionTimestamp = time.Now(). The single-object fast-path in
	// GetObjectByIndexAndTime now honors DeletionTimestamp, so querying at a time after
	// the deletion must return nothing.
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		_, ok := podStore.GetPodByIPAndTime(testPodIP, time.Now())
		assert.False(t, ok, "terminated pod should not be returned by GetPodByIPAndTime after phase transition")
	}, 1*time.Second, 10*time.Millisecond)
}

/*
Sample output:
goos: darwin
goarch: amd64
pkg: antrea.io/antrea/v2/pkg/util/objectstore
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
		podInformer := getPodInformer(k8sClient)
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

func deletePodsK8s(pods []*corev1.Pod, k8sClient kubernetes.Interface) error {
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

func addPods(number int, k8sClient kubernetes.Interface) ([]*corev1.Pod, error) {
	var podArray []*corev1.Pod
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

func generatePod() *corev1.Pod {
	ip := getRandomIP()
	uid := uuid.New().String()
	startTime := rand.Intn(360000000)
	creationTime := refTime.Add(time.Duration(startTime))
	deletionTime := creationTime.Add(time.Hour)
	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{
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

// Test_GetPodByIPAndTime_IPReuse_CompletedJobPod validates that when a Job Pod completes and
// its IP is reused by a new running Pod, GetPodByIPAndTime correctly returns only the new Pod.
func Test_GetPodByIPAndTime_IPReuse_CompletedJobPod(t *testing.T) {
	const reusedPodIP = "10.0.0.100"

	jobPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "job-pod",
			Namespace:         "ns-a",
			UID:               "job-pod-uid",
			CreationTimestamp: metav1.Time{Time: refTime2},
		},
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{{IP: reusedPodIP}},
			Phase:  corev1.PodRunning,
		},
	}
	newPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "new-running-pod",
			Namespace:         "ns-b",
			UID:               "new-running-uid",
			CreationTimestamp: metav1.Time{Time: refTime},
		},
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{{IP: reusedPodIP}},
			Phase:  corev1.PodRunning,
		},
	}

	stopCh := make(chan struct{})
	defer close(stopCh)
	k8sClient := fake.NewSimpleClientset()
	podInformer := getPodInformer(k8sClient)
	podStore := NewPodStore(podInformer)
	go podInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, podInformer.HasSynced)

	// Step 1: create the job Pod while it is still running.
	_, err := k8sClient.CoreV1().Pods(jobPod.Namespace).Create(context.TODO(), jobPod, metav1.CreateOptions{})
	require.NoError(t, err)
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		podStore.mutex.RLock()
		defer podStore.mutex.RUnlock()
		assert.Contains(t, podStore.timestampMap, jobPod.UID)
	}, 1*time.Second, 10*time.Millisecond)

	// Step 2: job Pod transitions to Succeeded; the store treats this as a deletion.
	succeededJobPod := jobPod.DeepCopy()
	succeededJobPod.Status.Phase = corev1.PodSucceeded
	_, err = k8sClient.CoreV1().Pods(succeededJobPod.Namespace).UpdateStatus(context.TODO(), succeededJobPod, metav1.UpdateOptions{})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		podStore.mutex.RLock()
		defer podStore.mutex.RUnlock()
		ts, exists := podStore.timestampMap[jobPod.UID]
		assert.True(t, exists)
		assert.NotNil(t, ts.DeletionTimestamp, "job pod should have a DeletionTimestamp after transitioning to Succeeded")
	}, 1*time.Second, 10*time.Millisecond)
	// Read the actual DeletionTimestamp recorded by the store (set to time.Now() by the
	// store's own clock when the phase transition was processed). queryTime must be after
	// this value to guarantee the completed job pod is excluded by the timestamp filter.
	podStore.mutex.RLock()
	jobPodDeletionTimestamp := *podStore.timestampMap[jobPod.UID].DeletionTimestamp
	podStore.mutex.RUnlock()

	// Step 3: a new Pod is assigned the same IP. Create the Pod in the informer's indexer.
	_, err = k8sClient.CoreV1().Pods(newPod.Namespace).Create(context.TODO(), newPod, metav1.CreateOptions{})
	require.NoError(t, err)
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		podStore.mutex.RLock()
		defer podStore.mutex.RUnlock()
		assert.Contains(t, podStore.timestampMap, newPod.UID)
	}, 1*time.Second, 10*time.Millisecond)

	// Step 4: GetPodByIPAndTime must return the new running Pod and the new Pod only.
	queryTime := jobPodDeletionTimestamp.Add(time.Second)
	pod, found := podStore.GetPodByIPAndTime(reusedPodIP, queryTime)
	require.True(t, found, "should find a pod for the reused IP")
	assert.Equal(t, newPod.UID, pod.UID, "should return the new running pod, not the completed job pod")
}
