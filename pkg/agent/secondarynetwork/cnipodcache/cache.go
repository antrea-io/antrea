// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http:// www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cnipodcache

import (
	"sync"

	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	podIndex = "pod"
)

type CNIPodInfoCache struct {
	sync.RWMutex
	cache cache.Indexer
}

// Add CNIPodInfo to local cache store.
func (c *CNIPodInfoCache) AddCNIConfigInfo(CNIConfig *CNIConfigInfo) {
	c.Lock()
	defer c.Unlock()
	c.cache.Add(CNIConfig)
}

// Delete CNIPodInfo from local cache store.
func (c *CNIPodInfoCache) DeleteCNIConfigInfo(CNIConfig *CNIConfigInfo) {
	c.Lock()
	defer c.Unlock()
	c.cache.Delete(CNIConfig)
}

func (c *CNIPodInfoCache) SetPodCNIDeleted(CNIConfig *CNIConfigInfo) {
	c.Lock()
	defer c.Unlock()
	CNIConfig.PodCNIDeleted = true
}

// Retrieve a valid CNI cache (PodCNIDeleted is not true) entry for the given Pod name and namespace.
func (c *CNIPodInfoCache) GetValidCNIConfigInfoPerPod(podName, podNamespace string) *CNIConfigInfo {
	c.RLock()
	defer c.RUnlock()
	podObjs, _ := c.cache.ByIndex(podIndex, k8s.NamespacedName(podNamespace, podName))
	for i := range podObjs {
		var cniPodConfig *CNIConfigInfo
		cniPodConfig = podObjs[i].(*CNIConfigInfo)
		if cniPodConfig.PodCNIDeleted != true {
			return cniPodConfig
		}
	}
	return nil
}

// Retrieve all CNIConfigInfo from cacheStore for the given podName and its Namespace
// NOTE: In an ideal scenario, there should be one cache entry per Pod name and namespace.
func (c *CNIPodInfoCache) GetAllCNIConfigInfoPerPod(podName, podNamespace string) []*CNIConfigInfo {
	c.RLock()
	defer c.RUnlock()
	podObjs, _ := c.cache.ByIndex(podIndex, k8s.NamespacedName(podNamespace, podName))
	CNIPodConfigs := make([]*CNIConfigInfo, len(podObjs))
	for i := range podObjs {
		CNIPodConfigs[i] = podObjs[i].(*CNIConfigInfo)
	}
	return CNIPodConfigs
}

func (c *CNIPodInfoCache) GetCNIConfigInfoByContainerID(podName, podNamespace, containerID string) *CNIConfigInfo {
	c.RLock()
	defer c.RUnlock()
	podObjs, _ := c.cache.ByIndex(podIndex, k8s.NamespacedName(podNamespace, podName))
	for i := range podObjs {
		var cniPodConfig *CNIConfigInfo
		cniPodConfig = podObjs[i].(*CNIConfigInfo)
		if cniPodConfig.ContainerID == containerID {
			return cniPodConfig
		}
	}
	return nil
}

func podIndexFunc(obj interface{}) ([]string, error) {
	podConfig := obj.(*CNIConfigInfo)
	return []string{k8s.NamespacedName(podConfig.PodNameSpace, podConfig.PodName)}, nil
}

func getCNIPodInfoKey(obj interface{}) (string, error) {
	podConfig := obj.(*CNIConfigInfo)
	var key string
	key = util.GenerateContainerInterfaceKey(podConfig.ContainerID)
	return key, nil
}

func NewCNIPodInfoStore() CNIPodInfoStore {
	return &CNIPodInfoCache{
		cache: cache.NewIndexer(getCNIPodInfoKey, cache.Indexers{
			podIndex: podIndexFunc,
		}),
	}
}
