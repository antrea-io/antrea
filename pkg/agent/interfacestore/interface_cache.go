// Copyright 2019 Antrea Authors
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

package interfacestore

import (
	"fmt"

	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	// interfaceNameIndex is the index built with InterfaceConfig.InterfaceName.
	interfaceNameIndex = "interfaceName"
	// interfaceTypeIndex is the index built with InterfaceConfig.Type.
	interfaceTypeIndex = "interfaceType"
	// containerIDIndex is the index built with InterfaceConfig.ContainerID.
	// Only container interfaces will be indexed.
	// One containerID should get at most one interface in theory.
	containerIDIndex = "containerID"
	// podIndex is the index built with InterfaceConfig.PodNamespace + Podname.
	// Only container interfaces will be indexed.
	// One Pod may get more than one interface.
	podIndex = "pod"
	// interfaceIPIndex is the index built with InterfaceConfig.IP
	// Only the interfaces with IP get indexed.
	interfaceIPIndex = "ip"
	// ofPortIndex is the index built with InterfaceConfig.OFPort
	ofPortIndex = "ofPort"
	// externalEntityIndex is the index built with InterfaceConfig.EntityNamespace + EntityName.
	// Only the interfaces of an ExternalEntity get indexed.
	externalEntityIndex = "externalEntity"
)

// Local cache for interfaces created on node, including container, host gateway, and tunnel
// ports, `Type` field is used to differentiate interface category.
//  1) For container interface, the fields should include: containerID, podName, Namespace,
//     IP, MAC, and OVS Port configurations.
//  2) For host gateway port, the fields should include: name, IP, MAC, and OVS port
//     configurations.
//  3) For tunnel port, the fields include: name and tunnel type; and for an IPsec tunnel,
//     additionally: remoteIP, PSK and remote Node name.
// OVS Port configurations include PortUUID and OFPort.
// Container interface is added into cache after invocation of cniserver.CmdAdd, and removed
// from cache after invocation of cniserver.CmdDel. For cniserver.CmdCheck, the server would
// check previousResult with local cache.
// Host gateway and the default tunnel interfaces are added into cache in node initialization
// phase or retrieved from existing OVS ports.
// An IPsec tunnel interface is added into the cache when IPsec encryption is enabled, and
// NodeRouteController watches a new remote Node from K8s API, and is removed when the remote
// Node is deleted.
// Todo: add periodic task to sync local cache with container veth pair

type interfaceCache struct {
	cache cache.Indexer
}

func (c *interfaceCache) Initialize(interfaces []*InterfaceConfig) {
	for _, intf := range interfaces {
		c.cache.Add(intf)
		if intf.Type == ContainerInterface {
			metrics.PodCount.Inc()
		}
	}
}

// getInterfaceKey returns the key to access interfaceConfig from the cache.
// It implements cache.KeyFunc.
func getInterfaceKey(obj interface{}) (string, error) {
	interfaceConfig := obj.(*InterfaceConfig)
	var key string
	if interfaceConfig.Type == ContainerInterface {
		key = util.GenerateContainerInterfaceKey(interfaceConfig.ContainerID, interfaceConfig.IFDev)
	} else if interfaceConfig.Type == IPSecTunnelInterface {
		// IPsec tunnel interface for a Node.
		key = util.GenerateNodeTunnelInterfaceKey(interfaceConfig.NodeName)
	} else {
		// Use the interface name as the key by default.
		key = interfaceConfig.InterfaceName
	}
	return key, nil
}

// AddInterface adds interfaceConfig into local cache.
func (c *interfaceCache) AddInterface(interfaceConfig *InterfaceConfig) {
	c.cache.Add(interfaceConfig)

	if interfaceConfig.Type == ContainerInterface {
		metrics.PodCount.Inc()
	}
}

// DeleteInterface deletes interface from local cache.
func (c *interfaceCache) DeleteInterface(interfaceConfig *InterfaceConfig) {
	c.cache.Delete(interfaceConfig)

	if interfaceConfig.Type == ContainerInterface {
		metrics.PodCount.Dec()
	}
}

// GetInterface retrieves interface from local cache given the interface key.
func (c *interfaceCache) GetInterface(interfaceKey string) (*InterfaceConfig, bool) {
	iface, found, _ := c.cache.GetByKey(interfaceKey)
	if !found {
		return nil, false
	}
	return iface.(*InterfaceConfig), found
}

// ListInterfacesByType lists all interfaces from local cache.
func (c *interfaceCache) ListInterfaces() []*InterfaceConfig {
	interfaceConfigs := make([]*InterfaceConfig, 0)
	for _, iface := range c.cache.List() {
		interfaceConfigs = append(interfaceConfigs, iface.(*InterfaceConfig))
	}
	return interfaceConfigs
}

// GetInterfaceByName retrieves interface from local cache given the interface
// name.
func (c *interfaceCache) GetInterfaceByName(interfaceName string) (*InterfaceConfig, bool) {
	interfaceConfigs, _ := c.cache.ByIndex(interfaceNameIndex, interfaceName)
	if len(interfaceConfigs) == 0 {
		return nil, false
	}
	return interfaceConfigs[0].(*InterfaceConfig), true
}

// GetInterfaceByIP retrieves interface from local cache given the interface IP.
func (c *interfaceCache) GetInterfaceByIP(interfaceIP string) (*InterfaceConfig, bool) {
	interfaceConfigs, _ := c.cache.ByIndex(interfaceIPIndex, interfaceIP)
	if len(interfaceConfigs) == 0 {
		return nil, false
	}
	return interfaceConfigs[0].(*InterfaceConfig), true
}

func (c *interfaceCache) GetContainerInterfaceNum() int {
	keys, _ := c.cache.IndexKeys(interfaceTypeIndex, ContainerInterface.String())
	return len(keys)
}

func (c *interfaceCache) GetInterfacesByType(interfaceType InterfaceType) []*InterfaceConfig {
	objs, _ := c.cache.ByIndex(interfaceTypeIndex, interfaceType.String())
	interfaces := make([]*InterfaceConfig, len(objs))
	for i := range objs {
		interfaces[i] = objs[i].(*InterfaceConfig)
	}
	return interfaces
}

func (c *interfaceCache) Len() int {
	return len(c.cache.ListKeys())
}

func (c *interfaceCache) GetInterfaceKeysByType(interfaceType InterfaceType) []string {
	keys, _ := c.cache.IndexKeys(interfaceTypeIndex, interfaceType.String())
	return keys
}

// GetContainerInterface retrieves InterfaceConfig by the given container ID.
func (c *interfaceCache) GetContainerInterface(containerID string) (*InterfaceConfig, bool) {
	objs, _ := c.cache.ByIndex(containerIDIndex, containerID)
	if len(objs) == 0 {
		return nil, false
	}
	return objs[0].(*InterfaceConfig), true
}

func (c *interfaceCache) GetInterfacesByEntity(name, namespace string) []*InterfaceConfig {
	objs, _ := c.cache.ByIndex(externalEntityIndex, k8s.NamespacedName(namespace, name))
	interfaces := make([]*InterfaceConfig, len(objs))
	for i := range objs {
		interfaces[i] = objs[i].(*InterfaceConfig)
	}
	return interfaces
}

// GetContainerInterfacesByPod retrieves InterfaceConfigs for the Pod.
// It's possible that more than one container interface (with different containerIDs) has the same Pod namespace and
// name temporarily when the previous Pod is being deleted and the new Pod is being created almost simultaneously.
// https://github.com/antrea-io/antrea/issues/785#issuecomment-642051884
func (c *interfaceCache) GetContainerInterfacesByPod(podName string, podNamespace string) []*InterfaceConfig {
	objs, _ := c.cache.ByIndex(podIndex, k8s.NamespacedName(podNamespace, podName))
	interfaces := make([]*InterfaceConfig, len(objs))
	for i := range objs {
		interfaces[i] = objs[i].(*InterfaceConfig)
	}
	return interfaces
}

// GetNodeTunnelInterface retrieves InterfaceConfig for the tunnel to the Node.
func (c *interfaceCache) GetNodeTunnelInterface(nodeName string) (*InterfaceConfig, bool) {
	key := util.GenerateNodeTunnelInterfaceKey(nodeName)
	obj, ok, _ := c.cache.GetByKey(key)
	if !ok {
		return nil, false
	}
	return obj.(*InterfaceConfig), true
}

// GetInterfaceByOFPort retrieves InterfaceConfig by the given ofPort number.
func (c *interfaceCache) GetInterfaceByOFPort(ofPort uint32) (*InterfaceConfig, bool) {
	ofportStr := fmt.Sprintf("%d", ofPort)
	interfaceConfigs, _ := c.cache.ByIndex(ofPortIndex, ofportStr)
	if len(interfaceConfigs) == 0 {
		return nil, false
	}
	return interfaceConfigs[0].(*InterfaceConfig), true
}

func interfaceNameIndexFunc(obj interface{}) ([]string, error) {
	interfaceConfig := obj.(*InterfaceConfig)
	return []string{interfaceConfig.InterfaceName}, nil
}

func interfaceTypeIndexFunc(obj interface{}) ([]string, error) {
	interfaceConfig := obj.(*InterfaceConfig)
	return []string{interfaceConfig.Type.String()}, nil
}

func containerIDIndexFunc(obj interface{}) ([]string, error) {
	interfaceConfig := obj.(*InterfaceConfig)
	if interfaceConfig.Type != ContainerInterface {
		return []string{}, nil
	}
	return []string{interfaceConfig.ContainerID}, nil
}

func podIndexFunc(obj interface{}) ([]string, error) {
	interfaceConfig := obj.(*InterfaceConfig)
	if interfaceConfig.Type != ContainerInterface {
		return []string{}, nil
	}
	return []string{k8s.NamespacedName(interfaceConfig.PodNamespace, interfaceConfig.PodName)}, nil
}

func interfaceIPIndexFunc(obj interface{}) ([]string, error) {
	interfaceConfig := obj.(*InterfaceConfig)
	if interfaceConfig.IPs == nil {
		// If interfaceConfig IP is not set, we return empty key.
		return []string{}, nil
	}
	var intfIPs []string
	for _, ip := range interfaceConfig.IPs {
		intfIPs = append(intfIPs, ip.String())
	}
	return intfIPs, nil
}

func interfaceOFPortIndexFunc(obj interface{}) ([]string, error) {
	interfaceConfig := obj.(*InterfaceConfig)
	// OVSPortConfig can be nil for a secondary SR-IOV interface.
	if interfaceConfig.OVSPortConfig == nil || interfaceConfig.OFPort < 0 {
		// If interfaceConfig OFport is not valid, we return empty key.
		return []string{}, nil
	}
	return []string{fmt.Sprintf("%d", interfaceConfig.OFPort)}, nil
}

func externalEntityIndexFunc(obj interface{}) ([]string, error) {
	interfaceConfig := obj.(*InterfaceConfig)
	if interfaceConfig.Type != ExternalEntityInterface {
		return []string{}, nil
	}
	return []string{k8s.NamespacedName(interfaceConfig.EntityNamespace, interfaceConfig.EntityName)}, nil
}

func NewInterfaceStore() InterfaceStore {
	return &interfaceCache{
		cache: cache.NewIndexer(getInterfaceKey, cache.Indexers{
			interfaceNameIndex:  interfaceNameIndexFunc,
			interfaceTypeIndex:  interfaceTypeIndexFunc,
			containerIDIndex:    containerIDIndexFunc,
			podIndex:            podIndexFunc,
			interfaceIPIndex:    interfaceIPIndexFunc,
			ofPortIndex:         interfaceOFPortIndexFunc,
			externalEntityIndex: externalEntityIndexFunc,
		}),
	}
}
