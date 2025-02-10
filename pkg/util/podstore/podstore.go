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
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

const (
	deleteQueueName = "podStorePodsToDelete"
	podIPIndex      = "PodIP"
	delayTime       = time.Minute * 5
)

type PodStore struct {
	pods         cache.Indexer
	podsToDelete workqueue.TypedDelayingInterface[types.UID]
	delayTime    time.Duration
	// Mapping pod.uuid to podTimestamps
	timestampMap map[types.UID]*podTimestamps
	clock        clock.Clock
	mutex        sync.RWMutex
}

type podTimestamps struct {
	CreationTimestamp time.Time
	// DeletionTimestamp is nil if a Pod is not deleted.
	DeletionTimestamp *time.Time
}

// Interface is a podStore interface to create local podStore for Flow Exporter and Flow Aggregator.
type Interface interface {
	GetPodByIPAndTime(ip string, startTime time.Time) (*corev1.Pod, bool)
	Run(stopCh <-chan struct{})
}

// NewPodStoreWithClock creates a Pod Store with a custom clock,
// which is useful when writing robust unit tests.
func NewPodStoreWithClock(podInformer cache.SharedIndexInformer, clock clock.WithTicker) *PodStore {
	s := &PodStore{
		pods: cache.NewIndexer(podKeyFunc, cache.Indexers{podIPIndex: podIPIndexFunc}),
		podsToDelete: workqueue.NewTypedDelayingQueueWithConfig(workqueue.TypedDelayingQueueConfig[types.UID]{
			Name:  deleteQueueName,
			Clock: clock,
		}),
		delayTime:    delayTime,
		clock:        clock,
		timestampMap: map[types.UID]*podTimestamps{},
		mutex:        sync.RWMutex{},
	}
	podInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    s.onPodCreate,
			UpdateFunc: s.onPodUpdate,
			DeleteFunc: s.onPodDelete,
		})
	return s
}

func NewPodStore(podInformer cache.SharedIndexInformer) *PodStore {
	return NewPodStoreWithClock(podInformer, clock.RealClock{})
}

func (s *PodStore) onPodUpdate(oldObj interface{}, newObj interface{}) {
	oldPod, ok := oldObj.(*corev1.Pod)
	if !ok {
		klog.ErrorS(nil, "Received unexpected object", "oldObj", oldObj)
		return
	}
	newPod, ok := newObj.(*corev1.Pod)
	if !ok {
		klog.ErrorS(nil, "Received unexpected object", "newObj", newObj)
		return
	}

	// From https://pkg.go.dev/k8s.io/client-go/tools/cache#SharedInformer:
	// Because `ObjectMeta.UID` has no role in identifying objects, it is possible that when (1)
	// object O1 with ID (e.g. namespace and name) X and `ObjectMeta.UID` U1 in the
	// SharedInformer's local cache is deleted and later (2) another object O2 with ID X and
	// ObjectMeta.UID U2 is created the informer's clients are not notified of (1) and (2) but
	// rather are notified only of an update from O1 to O2. Clients that need to detect such
	// cases might do so by comparing the `ObjectMeta.UID` field of the old and the new object
	// in the code that handles update notifications (i.e. `OnUpdate` method of
	// ResourceEventHandler).
	if oldPod.UID != newPod.UID {
		if err := s.deletePod(oldPod); err != nil {
			klog.ErrorS(err, "Error when deleting Pod from store", "Pod", klog.KObj(oldPod), "UID", oldPod.UID)
		}
		if err := s.addPod(newPod); err != nil {
			klog.ErrorS(err, "Error when adding Pod to store", "Pod", klog.KObj(newPod), "UID", newPod.UID)
		}
	} else {
		if err := s.updatePod(newPod); err != nil {
			klog.ErrorS(err, "Error when updating Pod in store", "Pod", klog.KObj(newPod), "UID", newPod.UID)
		}
	}
	klog.V(4).InfoS("Processed Pod Update Event", "Pod", klog.KObj(newPod))
}

func (s *PodStore) onPodCreate(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		klog.ErrorS(nil, "Received unexpected object", "obj", obj)
		return
	}
	if err := s.addPod(pod); err != nil {
		klog.ErrorS(err, "Error when adding Pod to store", "Pod", klog.KObj(pod), "UID", pod.UID)
	}
	klog.V(4).InfoS("Processed Pod Create Event", "Pod", klog.KObj(pod))
}

func (s *PodStore) onPodDelete(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		var err error
		pod, err = s.checkDeletedPod(obj)
		if err != nil {
			klog.ErrorS(err, "Got error while processing Delete Event")
			return
		}
	}
	if err := s.deletePod(pod); err != nil {
		klog.ErrorS(err, "Error when deleting Pod from store", "Pod", klog.KObj(pod), "UID", pod.UID)
	}
	klog.V(4).InfoS("Processed Pod Delete Event", "Pod", klog.KObj(pod))
}

func (s *PodStore) addPod(pod *corev1.Pod) error {
	timeNow := s.clock.Now()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	err := s.pods.Add(pod)
	if err != nil {
		return fmt.Errorf("error when adding Pod to index: %w", err)
	}
	switch pod.Status.Phase {
	case corev1.PodPending:
		s.timestampMap[pod.UID] = &podTimestamps{CreationTimestamp: timeNow}
	default:
		s.timestampMap[pod.UID] = &podTimestamps{CreationTimestamp: pod.CreationTimestamp.Time}
	}
	return nil
}

func (s *PodStore) updatePod(pod *corev1.Pod) error {
	if err := s.pods.Update(pod); err != nil {
		return fmt.Errorf("error when updating Pod in index: %w", err)
	}
	return nil
}

func (s *PodStore) deletePod(pod *corev1.Pod) error {
	timeNow := s.clock.Now()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	timestamp, ok := s.timestampMap[pod.UID]
	if !ok {
		return fmt.Errorf("cannot find podTimestamps in timestampMap")
	}
	timestamp.DeletionTimestamp = &timeNow
	s.podsToDelete.AddAfter(pod.UID, s.delayTime)
	return nil
}

func (s *PodStore) checkDeletedPod(obj interface{}) (*corev1.Pod, error) {
	deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		return nil, fmt.Errorf("received unexpected object: %v", obj)
	}
	pod, ok := deletedState.Obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("DeletedFinalStateUnknown object is not of type Pod: %v", deletedState.Obj)
	}
	return pod, nil
}

func (s *PodStore) GetPodByIPAndTime(ip string, time time.Time) (*corev1.Pod, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	pods, _ := s.pods.ByIndex(podIPIndex, ip)
	if len(pods) == 0 {
		return nil, false
	} else if len(pods) == 1 {
		pod := pods[0].(*corev1.Pod)
		// In case the clocks may be skewed between different Nodes in the cluster, we directly return the Pod if there is only
		// one Pod in the indexer. Otherwise, we check the timestamp for Pods in the indexer.
		klog.V(4).InfoS("Matched Pod IP to Pod from indexer", "ip", ip, "Pod", klog.KObj(pod))
		return pod, true
	}
	for _, pod := range pods {
		pod := pod.(*corev1.Pod)
		timestamp, ok := s.timestampMap[pod.UID]
		if !ok {
			continue
		}
		if timestamp.CreationTimestamp.Before(time) && (timestamp.DeletionTimestamp == nil || time.Before(*timestamp.DeletionTimestamp)) {
			klog.V(4).InfoS("Matched Pod IP and time to Pod from indexer", "ip", ip, "time", time, "Pod", klog.KObj(pod))
			return pod, true
		}
	}
	return nil, false
}

func (s *PodStore) Run(stopCh <-chan struct{}) {
	defer s.podsToDelete.ShutDown()
	go wait.Until(s.worker, time.Second, stopCh)
	<-stopCh
}

// worker runs a worker thread that just dequeues item from deleteQueue and
// remove the item from prevPod.
func (s *PodStore) worker() {
	// Use the same object in each worker to delete from the indexer by key
	// (UID), as there is no reason to allocate a new object for each call
	// to processDeleteQueueItem.
	podDeletionKey := &corev1.Pod{}
	for s.processDeleteQueueItem(podDeletionKey) {
	}
}

func (s *PodStore) processDeleteQueueItem(podDeletionKey *corev1.Pod) bool {
	podUID, quit := s.podsToDelete.Get()
	if quit {
		return false
	}
	defer s.podsToDelete.Done(podUID)
	pod := podDeletionKey
	pod.UID = podUID
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if err := s.pods.Delete(pod); err != nil {
		klog.ErrorS(err, "Error when deleting Pod from store", "key", podUID)
		return true
	}
	delete(s.timestampMap, podUID)
	klog.V(4).InfoS("Removed Pod from Pod Store", "UID", podUID)
	return true
}

func podKeyFunc(obj interface{}) (string, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return "", fmt.Errorf("obj is not Pod: %+v", obj)
	}
	return string(pod.UID), nil
}

func podIPIndexFunc(obj interface{}) ([]string, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("obj is not Pod: %+v", obj)
	}
	if len(pod.Status.PodIPs) > 0 {
		indexes := make([]string, len(pod.Status.PodIPs))
		for i := range pod.Status.PodIPs {
			indexes[i] = pod.Status.PodIPs[i].IP
		}
		return indexes, nil
	}
	return nil, nil
}
