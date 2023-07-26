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
	podsToDelete workqueue.DelayingInterface
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
		pods:         cache.NewIndexer(podKeyFunc, cache.Indexers{podIPIndex: podIPIndexFunc}),
		podsToDelete: workqueue.NewDelayingQueueWithCustomClock(clock, deleteQueueName),
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
	newPod, ok := newObj.(*corev1.Pod)
	if !ok {
		klog.ErrorS(nil, "Received unexpected object", "newObj", newObj)
		return
	}
	err := s.pods.Update(newPod)
	if err != nil {
		klog.ErrorS(err, "Error when updating Pod in index")
		return
	}
	klog.V(4).InfoS("Processed Pod Update Event", "Pod", klog.KObj(newPod))
}

func (s *PodStore) onPodCreate(obj interface{}) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	timeNow := s.clock.Now()
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		klog.ErrorS(nil, "Received unexpected object", "obj", obj)
		return
	}
	err := s.pods.Add(pod)
	if err != nil {
		klog.ErrorS(err, "Error when adding Pod to index")
		return
	}
	switch pod.Status.Phase {
	case corev1.PodPending:
		s.timestampMap[pod.UID] = &podTimestamps{CreationTimestamp: timeNow}
	default:
		s.timestampMap[pod.UID] = &podTimestamps{CreationTimestamp: pod.CreationTimestamp.Time}
	}
	klog.V(4).InfoS("Processed Pod Create Event", "Pod", klog.KObj(pod))
}

func (s *PodStore) onPodDelete(obj interface{}) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	timeNow := s.clock.Now()
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		var err error
		pod, err = s.checkDeletedPod(obj)
		if err != nil {
			klog.ErrorS(err, "Got error while processing Delete Event")
			return
		}
	}
	timestamp, ok := s.timestampMap[pod.UID]
	if !ok {
		klog.ErrorS(nil, "Cannot find podTimestamps in timestampMap", "UID", pod.UID)
		return
	}
	timestamp.DeletionTimestamp = &timeNow
	s.podsToDelete.AddAfter(pod, delayTime)
	klog.V(4).InfoS("Processed Pod Delete Event", "Pod", klog.KObj(pod))
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
	for s.processDeleteQueueItem() {
	}
}

func (s *PodStore) processDeleteQueueItem() bool {
	pod, quit := s.podsToDelete.Get()
	if quit {
		return false
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	err := s.pods.Delete(pod)
	if err != nil {
		klog.ErrorS(err, "Error when deleting Pod from deletion workqueue", "Pod", klog.KObj(pod.(*corev1.Pod)))
		return false
	}
	delete(s.timestampMap, pod.(*corev1.Pod).UID)
	s.podsToDelete.Done(pod)
	klog.V(4).InfoS("Removed Pod from Pod Store", "Pod", klog.KObj(pod.(*corev1.Pod)))
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
