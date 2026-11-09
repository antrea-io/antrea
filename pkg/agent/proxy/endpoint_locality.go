// Copyright 2026 Antrea Authors
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

package proxy

import (
	"net"
	"sync"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	crdinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions/crd/v1beta1"
)

// endpointLocalityTracker tracks primary-network IP allocations for Pods on this Node. IPPool
// allocations identify their owning Pod, while the local Pod informer identifies which owners
// belong to this Node.
type endpointLocalityTracker struct {
	mu sync.Mutex

	podLister corelisters.PodLister
	onUpdate  func(sets.Set[string])

	localPodIPsByPod  map[string]sets.Set[string]
	poolAllocations   map[string]map[string]string
	allocatedIPOwners map[string]map[string]string
	localIPs          sets.Set[string]
}

func newEndpointLocalityTracker(podInformer cache.SharedIndexInformer, ipPoolInformer crdinformers.IPPoolInformer, onUpdate func(sets.Set[string])) *endpointLocalityTracker {
	t := &endpointLocalityTracker{
		podLister:         corelisters.NewPodLister(podInformer.GetIndexer()),
		onUpdate:          onUpdate,
		localPodIPsByPod:  map[string]sets.Set[string]{},
		poolAllocations:   map[string]map[string]string{},
		allocatedIPOwners: map[string]map[string]string{},
		localIPs:          sets.New[string](),
	}

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(interface{}) { t.refreshLocalPods() },
		UpdateFunc: func(interface{}, interface{}) { t.refreshLocalPods() },
		DeleteFunc: func(interface{}) { t.refreshLocalPods() },
	})
	ipPoolInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) { t.updatePool(obj, false) },
		UpdateFunc: func(_, newObj interface{}) {
			t.updatePool(newObj, false)
		},
		DeleteFunc: func(obj interface{}) { t.updatePool(obj, true) },
	})
	return t
}

func (t *endpointLocalityTracker) refreshLocalPods() {
	pods, err := t.podLister.List(labels.Everything())
	if err != nil {
		return
	}
	localPodIPsByPod := map[string]sets.Set[string]{}
	for _, pod := range pods {
		podIPs := sets.New[string]()
		if ip := net.ParseIP(pod.Status.PodIP); ip != nil {
			podIPs.Insert(ip.String())
		}
		for _, podIP := range pod.Status.PodIPs {
			if ip := net.ParseIP(podIP.IP); ip != nil {
				podIPs.Insert(ip.String())
			}
		}
		localPodIPsByPod[podKey(pod.Namespace, pod.Name)] = podIPs
	}

	t.mu.Lock()
	t.localPodIPsByPod = localPodIPsByPod
	localIPs := t.localIPsForPodsLocked()
	changed := !localIPs.Equal(t.localIPs)
	if changed {
		t.localIPs = localIPs
	}
	t.mu.Unlock()
	if changed {
		t.onUpdate(localIPs)
	}
}

func (t *endpointLocalityTracker) updatePool(obj interface{}, remove bool) {
	ipPool := getIPPoolFromEvent(obj)
	if ipPool == nil {
		return
	}
	poolAllocations := map[string]string{}
	if !remove {
		for _, address := range ipPool.Status.IPAddresses {
			if address.Phase != crdv1beta1.IPAddressPhaseAllocated || address.Owner.Pod == nil {
				continue
			}
			ip := net.ParseIP(address.IPAddress)
			if ip != nil {
				poolAllocations[ip.String()] = podKey(address.Owner.Pod.Namespace, address.Owner.Pod.Name)
			}
		}
	}

	t.mu.Lock()
	for ip := range t.poolAllocations[ipPool.Name] {
		delete(t.allocatedIPOwners[ip], ipPool.Name)
		if len(t.allocatedIPOwners[ip]) == 0 {
			delete(t.allocatedIPOwners, ip)
		}
	}
	if remove {
		delete(t.poolAllocations, ipPool.Name)
	} else {
		t.poolAllocations[ipPool.Name] = poolAllocations
		for ip, pod := range poolAllocations {
			if t.allocatedIPOwners[ip] == nil {
				t.allocatedIPOwners[ip] = map[string]string{}
			}
			t.allocatedIPOwners[ip][ipPool.Name] = pod
		}
	}
	localIPs := t.localIPsForPodsLocked()
	changed := !localIPs.Equal(t.localIPs)
	if changed {
		t.localIPs = localIPs
	}
	t.mu.Unlock()
	if changed {
		t.onUpdate(localIPs)
	}
}

func (t *endpointLocalityTracker) localIPsForPodsLocked() sets.Set[string] {
	localIPs := sets.New[string]()
	for pod, podIPs := range t.localPodIPsByPod {
		for podIP := range podIPs {
			for _, owner := range t.allocatedIPOwners[podIP] {
				if owner == pod {
					localIPs.Insert(podIP)
					break
				}
			}
		}
	}
	return localIPs
}

func getIPPoolFromEvent(obj interface{}) *crdv1beta1.IPPool {
	switch event := obj.(type) {
	case *crdv1beta1.IPPool:
		return event
	case cache.DeletedFinalStateUnknown:
		pool, _ := event.Obj.(*crdv1beta1.IPPool)
		return pool
	case *cache.DeletedFinalStateUnknown:
		pool, _ := event.Obj.(*crdv1beta1.IPPool)
		return pool
	default:
		return nil
	}
}

func podKey(namespace, name string) string {
	return namespace + "/" + name
}
