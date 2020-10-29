// +build !windows

// Copyright 2020 Antrea Authors
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
package k8s

import (
	"sync"

	corev1 "k8s.io/api/core/v1"
)

type ObjectStore struct {
	podPortsMap map[string][]int32
	sync.RWMutex
}

var objOnce sync.Once
var objStore ObjectStore

func NewObjectStore() *ObjectStore {
	objOnce.Do(func() {
		objStore = ObjectStore{}
	})
	return &objStore
}

func (o *ObjectStore) AddUpdatePodToSync(pod *corev1.Pod) {
	o.Lock()
	defer o.Unlock()
	ports := []int32{}
	if !o.IsPodInStore(pod.Name) {
		o.podPortsMap[pod.Name] = ports
	}

	for _, container := range pod.Spec.Containers {
		for _, cport := range container.Ports {
			if !o.IsPortInPodMapping(pod.Name, cport.ContainerPort) {
				ports = append(ports, cport.ContainerPort)
			}
		}
	}
	o.podPortsMap[pod.Name] = ports
}

func (o *ObjectStore) IsPodInStore(podname string) bool {
	o.Lock()
	defer o.Unlock()
	_, found := o.podPortsMap[podname]
	return found
}

func (o *ObjectStore) IsPortInPodMapping(podname string, port int32) bool {
	o.Lock()
	defer o.Unlock()
	for _, p := range o.podPortsMap[podname] {
		if p == port {
			return true
		}
	}
	return false
}
