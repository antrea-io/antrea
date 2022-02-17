// Copyright 2022 Antrea Authors
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

package externalnode

import (
	"antrea.io/antrea/pkg/util/channel"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	eeinformer "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	eelister "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/env"
)

const (
	controllerName = "ExternalEntityController"
	// How long to wait before retrying the processing of an ExternalEntity change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing ExternalEntity changes.
	defaultWorkers = 1
	// Disable resyncing.
	resyncPeriod time.Duration = 0
)

var (
	keyFunc      = cache.DeletionHandlingMetaNamespaceKeyFunc
	splitKeyFunc = cache.SplitMetaNamespaceKey
)

type ExternalEntityController struct {
	ovsBridgeClient            ovsconfig.OVSBridgeClient
	ofClient                   openflow.Client
	externalEntityInformer     cache.SharedIndexInformer
	externalEntityLister       eelister.ExternalEntityNamespaceLister
	externalEntityListerSynced cache.InformerSynced
	queue                      workqueue.RateLimitingInterface
	ifaceStore                 interfacestore.InterfaceStore
	nodeName                   string
	syncedExternalEntities     cache.Store
	// entityUpdateNotifier is used for notifying updates of local ExternalEntities to NetworkPolicyController.
	entityUpdateNotifier channel.Notifier
	eeStoreReadyCh       chan<- struct{}
	namespace            string
}

func NewExternalEntityController(ovsBridgeClient ovsconfig.OVSBridgeClient, ofClient openflow.Client, externalEntityInformer eeinformer.ExternalEntityInformer,
	ifaceStore interfacestore.InterfaceStore, entityUpdateNotifier channel.Notifier, eeStoreReadyCh chan<- struct{}, namespace string) (*ExternalEntityController, error) {
	c := &ExternalEntityController{
		ovsBridgeClient:            ovsBridgeClient,
		ofClient:                   ofClient,
		externalEntityInformer:     externalEntityInformer.Informer(),
		externalEntityLister:       externalEntityInformer.Lister().ExternalEntities(namespace),
		externalEntityListerSynced: externalEntityInformer.Informer().HasSynced,
		queue:                      workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "externalEntity"),
		ifaceStore:                 ifaceStore,
		syncedExternalEntities:     cache.NewStore(keyFunc),
		entityUpdateNotifier:       entityUpdateNotifier,
		eeStoreReadyCh:             eeStoreReadyCh,
	}
	nodeName, err := env.GetNodeName()
	if err != nil {
		return nil, err
	}
	c.nodeName = nodeName
	c.externalEntityInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.enqueueEntityAdd,
			UpdateFunc: c.enqueueEntityUpdate,
			DeleteFunc: c.enqueueEntityDelete,
		},
		resyncPeriod)

	return c, nil
}

func (c *ExternalEntityController) enqueueEntityAdd(obj interface{}) {
	entity := obj.(*v1alpha2.ExternalEntity)
	if entity.Spec.ExternalNode != c.nodeName {
		return
	}
	key, _ := keyFunc(entity)
	c.queue.Add(key)
	klog.InfoS("Enqueued ExternalEntity ADD event", "ExternalEntity", klog.KObj(entity))
}

func (c *ExternalEntityController) enqueueEntityUpdate(oldObj interface{}, newObj interface{}) {
	oldEntity := oldObj.(*v1alpha2.ExternalEntity)
	newEntity := newObj.(*v1alpha2.ExternalEntity)
	if newEntity.Spec.ExternalNode != c.nodeName {
		return
	}
	if (oldEntity.Spec.ExternalNode == newEntity.Spec.ExternalNode) && (!endpointChanged(oldEntity.Spec.Endpoints, newEntity.Spec.Endpoints)) {
		klog.InfoS("Skip enqueuing ExternalEntity UPDATE event as no changes for endpoints", "ExternalEntity", klog.KObj(newEntity))
		return
	}
	key, _ := keyFunc(newEntity)
	c.queue.Add(key)
	klog.InfoS("Enqueued ExternalEntity UPDATE event", "ExternalEntity", klog.KObj(newEntity))
}

func (c *ExternalEntityController) enqueueEntityDelete(obj interface{}) {
	entity := obj.(*v1alpha2.ExternalEntity)
	if entity.Spec.ExternalNode != c.nodeName {
		return
	}
	key, _ := keyFunc(entity)
	c.queue.Add(key)
	klog.InfoS("Enqueued ExternalEntity DELETE event", "ExternalEntity", klog.KObj(entity))
}

func endpointChanged(oldEndpoints []v1alpha2.Endpoint, newEndpoints []v1alpha2.Endpoint) bool {
	if len(oldEndpoints) != len(newEndpoints) {
		return true
	}
	oldEndpointNameIP := sets.NewString()
	newEndpointNameIP := sets.NewString()
	for _, oldEndpoint := range oldEndpoints {
		oldEndpointNameIP.Insert(oldEndpoint.Name + "$" + oldEndpoint.IP)
	}
	for _, newEndpoint := range newEndpoints {
		newEndpointNameIP.Insert(newEndpoint.Name + "$" + newEndpoint.IP)
	}
	return !newEndpointNameIP.Equal(oldEndpointNameIP)
}

// Run will create defaultWorkers workers (goroutines) which will process the ExternalEntity events from the work queue.
func (c *ExternalEntityController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.externalEntityListerSynced) {
		klog.Error("Failed to wait for syncing cache for ExternalEntities")
		return
	}

	if err := c.reconcile(); err != nil {
		klog.Errorf("Failed to reconcile %v", err)
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *ExternalEntityController) reconcile() error {
	if err := c.reconcileHostUplinkFlows(); err != nil {
		return fmt.Errorf("failed to reconcile host uplink flows %v", err)
	}
	if err := c.reconcileExternalEntityInterfaces(); err != nil {
		return fmt.Errorf("failed to reconcile ExternalEntity interfaces %v", err)
	}
	// Notify NetworkPolicyController interface store has contains ExternalEntityInterfaceConfig with endpoint IPs.
	close(c.eeStoreReadyCh)
	return nil
}

func (c *ExternalEntityController) reconcileHostUplinkFlows() error {
	hostIfaces := c.ifaceStore.GetInterfacesByType(interfacestore.ExternalEntityInterface)
	for _, hostIface := range hostIfaces {
		// TODO: Install host uplink flows
		klog.InfoS("Reconcile host uplink flow for ExternalEntityInterface", "ifName", hostIface.InterfaceName)
	}
	return nil
}

func (c *ExternalEntityController) reconcileExternalEntityInterfaces() error {
	entityList, err := c.externalEntityLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("reconcile failed to list ExternalEntities %v", err)
	}
	ifNameKeysMap := make(map[string]sets.String)
	for _, entity := range entityList {
		if entity.Spec.ExternalNode == c.nodeName {
			key, _ := keyFunc(entity)
			if err = c.addExternalEntity(key, entity); err != nil {
				return err
			}
			ifNameIPsMap, err := c.getInterfaceIPsMap(entity.Spec.Endpoints)
			if err != nil {
				return err
			}
			for ifName := range ifNameIPsMap {
				if _, exist := ifNameKeysMap[ifName]; exist {
					ifNameKeysMap[ifName].Insert(key)
				} else {
					ifNameKeysMap[ifName] = sets.NewString(key)
				}
			}
		}
	}
	hostIfaces := c.ifaceStore.GetInterfacesByType(interfacestore.ExternalEntityInterface)
	for _, hostIface := range hostIfaces {
		if expectedKeys, exists := ifNameKeysMap[hostIface.InterfaceName]; exists {
			for key := range hostIface.ExternalEntityKeyIPsMap {
				if !expectedKeys.Has(key) {
					err := c.deleteEntityEndpoint(key, hostIface.InterfaceName)
					if err != nil {
						return err
					}
				}
			}
		} else {
			for key := range hostIface.ExternalEntityKeyIPsMap {
				err := c.deleteEntityEndpoint(key, hostIface.InterfaceName)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// worker is a long-running function that will continually call the processNextWorkItem function in
// order to read and process a message on the work queue.
func (c *ExternalEntityController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *ExternalEntityController) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)

	if key, ok := obj.(string); !ok {
		c.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else if err := c.syncExternalEntity(key); err == nil {
		// If no error occurs we Forget this item so it does not get queued again until
		// another change happens.
		c.queue.Forget(key)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.Errorf("Error syncing ExternalEntity %s, requeuing. Error: %v", key, err)
	}
	return true
}

func (c *ExternalEntityController) syncExternalEntity(key string) error {
	_, name, err := splitKeyFunc(key)
	if err != nil {
		// This err should not occur.
		return err
	}
	entity, err := c.externalEntityLister.Get(name)
	if errors.IsNotFound(err) {
		return c.deleteExternalEntity(key)
	}
	preEntity, exists, _ := c.syncedExternalEntities.GetByKey(key)
	if !exists {
		return c.addExternalEntity(key, entity)
	} else {
		return c.updateExternalEntity(key, preEntity, entity)
	}
}

func (c *ExternalEntityController) getInterfaceIPsMap(endpoints []v1alpha2.Endpoint) (map[string]sets.String, error) {
	ifNameIPsMap := make(map[string]sets.String)
	for _, ep := range endpoints {
		ifName, err := c.getHostInterfaceNameByEndpoint(ep)
		if err != nil {
			return nil, err
		}
		if _, exist := ifNameIPsMap[ifName]; exist {
			ifNameIPsMap[ifName].Insert(ep.IP)
		} else {
			ifNameIPsMap[ifName] = sets.NewString(ep.IP)
		}
	}
	return ifNameIPsMap, nil
}

func (c *ExternalEntityController) addExternalEntity(key string, entity *v1alpha2.ExternalEntity) error {
	klog.InfoS("Adding ExternalEntity", "key", key)
	ifNameIPsMap, err := c.getInterfaceIPsMap(entity.Spec.Endpoints)
	if err != nil {
		return fmt.Errorf("failed to get endpointIPsMap %v", err)
	}
	for ifName, ips := range ifNameIPsMap {
		if err := c.addEntityEndpoint(key, ifName, ips); err != nil {
			return err
		}
	}
	c.syncedExternalEntities.Add(entity)
	// Notify the ExternalEntity create event to NetworkPolicyController.
	c.entityUpdateNotifier.Notify(key)
	return nil
}

func (c *ExternalEntityController) getHostInterfaceNameByEndpoint(ep v1alpha2.Endpoint) (string, error) {
	// TODO
	return "", nil
}

func (c *ExternalEntityController) addEntityEndpoint(eeKey string, ifName string, ips sets.String) error {
	hostIface, portExists := c.ifaceStore.GetInterfaceByName(ifName)
	if !portExists {
		klog.InfoS("Creating OVS ports and flows for EntityEndpoint", "ifName", ifName, "ExternalEntityKey", eeKey)
		uplinkName := genUplinkInterfaceName(ifName)
		hostIface, err := c.createOVSPortsAndFlows(uplinkName, ifName, eeKey)
		if err != nil {
			return err
		}
		keyIPsMap := make(map[string]sets.String)
		keyIPsMap[eeKey] = ips
		hostIface.ExternalEntityKeyIPsMap = keyIPsMap
		c.ifaceStore.AddInterface(hostIface)
		return nil
	}

	klog.InfoS("Updating OVS port data", "ExternalEntityKey", eeKey, "ifName", ifName, "ip", ips)
	updatedKeyIPsMap := make(map[string]sets.String)
	for entityKey, epIPs := range hostIface.ExternalEntityKeyIPsMap {
		updatedKeyIPsMap[entityKey] = epIPs
	}
	ifIPs, keyExists := hostIface.ExternalEntityKeyIPsMap[eeKey]
	if keyExists {
		if ifIPs.HasAll(ips.List()...) {
			klog.InfoS("Skipping updating ExternalEntityKeyIPsMap for key ip already exists", "ExternalEntityKey", eeKey, "ifName", ifName, "ips", ips)
			return nil
		} else {
			ifIPs.Union(ips)
		}
		updatedKeyIPsMap[eeKey] = ifIPs
	} else {
		updatedKeyIPsMap[eeKey] = ips
	}
	err := c.updateOVSPortData(hostIface, updatedKeyIPsMap)
	if err != nil {
		return err
	}

	c.updateInterfaceKeyIPsMap(hostIface, updatedKeyIPsMap)
	return nil
}

func (c *ExternalEntityController) updateInterfaceKeyIPsMap(hostIface *interfacestore.InterfaceConfig, keyIPsMap map[string]sets.String) {
	iface := &interfacestore.InterfaceConfig{
		InterfaceName: hostIface.InterfaceName,
		Type:          interfacestore.ExternalEntityInterface,
		OVSPortConfig: &interfacestore.OVSPortConfig{
			PortUUID: hostIface.PortUUID,
			OFPort:   hostIface.OFPort,
		},
		EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
			UplinkPort: &interfacestore.OVSPortConfig{
				PortUUID: hostIface.UplinkPort.PortUUID,
				OFPort:   hostIface.UplinkPort.OFPort,
			},
			HostIfaceIndex:          hostIface.EntityInterfaceConfig.HostIfaceIndex,
			ExternalEntityKeyIPsMap: keyIPsMap,
		},
	}
	c.ifaceStore.AddInterface(iface)
}

func (c *ExternalEntityController) updateExternalEntity(key string, obj interface{}, curEntity *v1alpha2.ExternalEntity) error {
	klog.InfoS("Updating ExternalEntity", "key", key)
	preEntity := obj.(*v1alpha2.ExternalEntity)
	preIfNameIPsMap, err := c.getInterfaceIPsMap(preEntity.Spec.Endpoints)
	if err != nil {
		return err
	}
	curIfNameIPsMap, err := c.getInterfaceIPsMap(curEntity.Spec.Endpoints)
	if err != nil {
		return err
	}
	// Handle case for deleted endpoints
	for pName := range preIfNameIPsMap {
		if _, exists := curIfNameIPsMap[pName]; !exists {
			err = c.deleteEntityEndpoint(key, pName)
			if err != nil {
				return err
			}
		}
	}
	// Handle cases for created and ip updated endpoints
	for cName, cIPs := range curIfNameIPsMap {
		if pIPs, exists := preIfNameIPsMap[cName]; !exists {
			err = c.addEntityEndpoint(key, cName, cIPs)
			if err != nil {
				return err
			}
		} else {
			if !cIPs.Equal(pIPs) {
				err := c.updateEntityEndpointIPs(cName, key, cIPs)
				if err != nil {
					return err
				}
			}
		}
	}
	c.syncedExternalEntities.Add(curEntity)
	// Notify the ExternalEntity create event to NetworkPolicyController.
	c.entityUpdateNotifier.Notify(key)
	return nil
}

// updateEntityEndpointIPs updates interface ExternalEntityKeyIPsMap in the interface store.
// It doesn't change OVSDB since we only store ExternalEntityKey in OVSDB.
func (c *ExternalEntityController) updateEntityEndpointIPs(ifName string, key string, cIPs sets.String) error {
	hostIface, portExists := c.ifaceStore.GetInterfaceByName(ifName)
	if !portExists {
		return fmt.Errorf("failed to find interface %s for updating ExternalEntity key %s EntityEndpointIPs", ifName, key)
	}
	updatedKeyIPsMap := hostIface.ExternalEntityKeyIPsMap
	updatedKeyIPsMap[key] = cIPs
	c.updateInterfaceKeyIPsMap(hostIface, updatedKeyIPsMap)
	return nil
}

func (c *ExternalEntityController) deleteExternalEntity(key string) error {
	klog.InfoS("Deleting ExternalEntity", "key", key)
	obj, exists, _ := c.syncedExternalEntities.GetByKey(key)
	if !exists {
		klog.InfoS("Skipping ExternalEntity deletion as it hasn't been synced", "ExternalEntityKey", key)
		return nil
	}
	entity := obj.(*v1alpha2.ExternalEntity)
	ifNameIPsMap, err := c.getInterfaceIPsMap(entity.Spec.Endpoints)
	if err != nil {
		return err
	}
	for ifName := range ifNameIPsMap {
		if err := c.deleteEntityEndpoint(key, ifName); err != nil {
			return err
		}
	}
	c.syncedExternalEntities.Delete(entity)
	return nil
}

func (c *ExternalEntityController) deleteEntityEndpoint(key string, ifName string) error {
	hostIface, portExists := c.ifaceStore.GetInterface(ifName)
	if !portExists {
		klog.InfoS("Skipping deleting host interface since it doesn't exist ", "ifName", ifName)
		return nil
	}
	if _, exist := hostIface.ExternalEntityKeyIPsMap[key]; exist {
		updatedKeyIPsMap := make(map[string]sets.String)
		for eeKey, ips := range hostIface.ExternalEntityKeyIPsMap {
			updatedKeyIPsMap[eeKey] = ips
		}
		delete(updatedKeyIPsMap, key)
		if len(updatedKeyIPsMap) == 0 {
			if err := c.removeOVSPortsAndFlows(hostIface); err != nil {
				return err
			}
			c.ifaceStore.DeleteInterface(hostIface)
		} else {
			if err := c.updateOVSPortData(hostIface, updatedKeyIPsMap); err != nil {
				return err
			}
			c.updateInterfaceKeyIPsMap(hostIface, updatedKeyIPsMap)
		}
	} else {
		klog.Warningf("Skipping deleting key %s for host interface %s since it doesn't exist ", key, ifName)
	}
	return nil
}

func (c *ExternalEntityController) createOVSPortsAndFlows(uplinkName, hostIfName, key string) (*interfacestore.InterfaceConfig, error) {
	return &interfacestore.InterfaceConfig{}, nil
}

func (c *ExternalEntityController) updateOVSPortData(interfaceConfig *interfacestore.InterfaceConfig, eeKeyIPsMap map[string]sets.String) error {
	return nil
}

func (a *ExternalEntityController) removeOVSPortsAndFlows(interfaceConfig *interfacestore.InterfaceConfig) error {
	return nil
}

func ParseHostInterfaceConfig(ovsBridgeClient ovsconfig.OVSBridgeClient, portData *ovsconfig.OVSPortData, portConfig *interfacestore.OVSPortConfig) (*interfacestore.InterfaceConfig, error) {
	return nil, nil
}

func genUplinkInterfaceName(hostIfName string) string {
	return fmt.Sprintf("phy-%s", hostIfName)
}
