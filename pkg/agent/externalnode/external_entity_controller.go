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
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	cpv1b2 "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/env"
)

const (
	controllerName = "ExternalEntityController"
	// How long to wait before retrying the processing of an ExternalEntity change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing ExternalEntity changes.
	defaultWorkers = 4
	// Disable resyncing.
	resyncPeriod time.Duration = 0
)

var (
	keyFunc      = cache.DeletionHandlingMetaNamespaceKeyFunc
	splitKeyFunc = cache.SplitMetaNamespaceKey
	emptyWatch   = watch.NewEmptyWatch()
)

type ExternalEntityController struct {
	// antreaClientProvider provides interfaces to get antreaClient, which can be
	// used to watch Antrea ExternalEntity.
	antreaClientProvider   agent.AntreaClientProvider
	ovsBridgeClient        ovsconfig.OVSBridgeClient
	ofClient               openflow.Client
	queue                  workqueue.RateLimitingInterface
	ifaceStore             interfacestore.InterfaceStore
	nodeName               string
	syncedExternalEntities cache.Store
	// entityUpdateNotifier is used for notifying updates of local ExternalEntities to NetworkPolicyController.
	entityUpdateNotifier channel.Notifier
	eeStoreReadyCh       chan<- struct{}
	namespace            string
	fullSyncGroup        sync.WaitGroup
}

func NewExternalEntityController(antreaClientGetter agent.AntreaClientProvider, ovsBridgeClient ovsconfig.OVSBridgeClient, ofClient openflow.Client,
	ifaceStore interfacestore.InterfaceStore, entityUpdateNotifier channel.Notifier, eeStoreReadyCh chan<- struct{}, namespace string) (*ExternalEntityController, error) {
	c := &ExternalEntityController{
		antreaClientProvider:   antreaClientGetter,
		ovsBridgeClient:        ovsBridgeClient,
		ofClient:               ofClient,
		queue:                  workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "externalEntity"),
		ifaceStore:             ifaceStore,
		syncedExternalEntities: cache.NewStore(keyFunc),
		entityUpdateNotifier:   entityUpdateNotifier,
		eeStoreReadyCh:         eeStoreReadyCh,
		namespace:              namespace,
	}
	nodeName, err := env.GetNodeName()
	if err != nil {
		return nil, err
	}
	c.nodeName = nodeName
	c.fullSyncGroup.Add(1)
	return c, nil
}

func (c *ExternalEntityController) watchExternalEntity() {
	klog.Info("Starting watch for ExternalEntity")
	antreaClient, err := c.antreaClientProvider.GetAntreaClient()
	if err != nil {
		klog.Warningf("Failed to get antrea client: %v", err)
		return
	}
	klog.InfoS("watch external entity", "nodeName", c.nodeName)
	options := metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("nodeName", c.nodeName).String(),
	}
	watcher, err := antreaClient.ControlplaneV1beta2().ExternalEntities(c.namespace).Watch(context.TODO(), options)
	if err != nil {
		klog.Warningf("Failed to start watch for ExternalEntity: %v", err)
		return
	}
	// Watch method doesn't return error but "emptyWatch" in case of some partial data errors,
	// e.g. timeout error. Make sure that watcher is not empty and log warning otherwise.
	if reflect.TypeOf(watcher) == reflect.TypeOf(emptyWatch) {
		klog.Warning("Failed to start watch for ExternalEntity, please ensure antrea service is reachable for the agent")
		return
	}

	klog.Info("Started watch for ExternalEntity")
	eventCount := 0
	defer func() {
		klog.Infof("Stopped watch for ExternalEntity, total items received: %d", eventCount)
		watcher.Stop()
	}()

	// First receive init events from the result channel and buffer them until
	// a Bookmark event is received, indicating that all init events have been
	// received.
	var initObjects []*cpv1b2.ExternalEntity
loop:
	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				klog.Warningf("Result channel for ExternalEntity was closed")
				return
			}
			switch event.Type {
			case watch.Added:
				klog.V(2).Infof("Added ExternalEntity (%#v)", event.Object)
				initObjects = append(initObjects, event.Object.(*cpv1b2.ExternalEntity))
			case watch.Bookmark:
				break loop
			}
		}
	}
	klog.Infof("Received %d init events for ExternalEntity", len(initObjects))

	eventCount += len(initObjects)
	err = c.reconcileExternalEntityInterfaces(initObjects)
	if err != nil {
		klog.Errorf("Watcher failed to reconcile ExternalEntity interfaces: %v", err)
		return
	}
	c.fullSyncGroup.Done()

	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return
			}
			switch event.Type {
			case watch.Added:
				c.enqueueExternalEntity(event.Object.(*cpv1b2.ExternalEntity))
				klog.InfoS("Enqueued Add ExternalEntity", "entity", klog.KObj(event.Object.(*cpv1b2.ExternalEntity)))
			case watch.Modified:
				c.enqueueExternalEntity(event.Object.(*cpv1b2.ExternalEntity))
				klog.InfoS("Enqueued Update ExternalEntity", "entity", klog.KObj(event.Object.(*cpv1b2.ExternalEntity)))
			case watch.Deleted:
				c.enqueueExternalEntity(event.Object.(*cpv1b2.ExternalEntity))
				klog.InfoS("Enqueued Delete ExternalEntity", "entity", klog.KObj(event.Object.(*cpv1b2.ExternalEntity)))
			default:
				klog.Errorf("Unknown event: %v", event)
				return
			}
			eventCount++
		}
	}
}

func (c *ExternalEntityController) enqueueExternalEntity(ee *cpv1b2.ExternalEntity) {
	key, _ := keyFunc(ee)
	c.queue.Add(key)
}

// Run will create defaultWorkers workers (goroutines) which will process the ExternalEntity events from the work queue.
func (c *ExternalEntityController) Run(stopCh <-chan struct{}) {
	attempts := 0
	if err := wait.PollImmediateUntil(200*time.Millisecond, func() (bool, error) {
		if attempts%10 == 0 {
			klog.Info("Waiting for Antrea client to be ready")
		}
		if _, err := c.antreaClientProvider.GetAntreaClient(); err != nil {
			attempts++
			return false, nil
		}
		return true, nil
	}, stopCh); err != nil {
		klog.Info("Stopped waiting for Antrea client")
		return
	}
	klog.Info("Antrea client is ready")

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)
	defer c.queue.ShutDown()
	// Use NonSlidingUntil so that normal reconnection (disconnected after
	// running a while) can reconnect immediately while abnormal reconnection
	// won't be too aggressive.
	go wait.NonSlidingUntil(c.watchExternalEntity, 5*time.Second, stopCh)

	c.fullSyncGroup.Wait()
	// Notify NetworkPolicyController interface store has contains ExternalEntityInterfaceConfig with endpoint IPs.
	close(c.eeStoreReadyCh)

	if err := c.reconcileFlows(); err != nil {
		klog.Errorf("Failed to reconcile flows %v", err)
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *ExternalEntityController) reconcileFlows() error {
	if err := c.reconcileHostUplinkFlows(); err != nil {
		return fmt.Errorf("failed to reconcile host uplink flows %v", err)
	}
	return nil
}

func (c *ExternalEntityController) reconcileHostUplinkFlows() error {
	klog.Info("Start reconciling host uplink flows")
	hostIfaces := c.ifaceStore.GetInterfacesByType(interfacestore.ExternalEntityInterface)
	for _, hostIface := range hostIfaces {
		// TODO: Install host uplink flows
		klog.InfoS("Reconcile host uplink flow for ExternalEntityInterface", "ifName", hostIface.InterfaceName)
	}
	return nil
}

func (c *ExternalEntityController) reconcileExternalEntityInterfaces(entityList []*cpv1b2.ExternalEntity) error {
	klog.Info("Start reconciling ExternalEntity interfaces")
	ifNameKeysMap := make(map[string]sets.String)
	for _, entity := range entityList {
		key, _ := keyFunc(entity)
		if err := c.addExternalEntity(key, entity); err != nil {
			return err
		}
		ifNameIPsMap, err := c.getInterfaceIPsMap(entity.Endpoints)
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
	namespace, name, err := splitKeyFunc(key)
	if err != nil {
		// This err should not occur.
		return err
	}
	antreaClient, err := c.antreaClientProvider.GetAntreaClient()
	if err != nil {
		return err
	}
	entity, err := antreaClient.ControlplaneV1beta2().ExternalEntities(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return c.deleteExternalEntity(key)
	}
	preEntity, exists, _ := c.syncedExternalEntities.GetByKey(key)
	if !exists {
		return c.addExternalEntity(key, entity)
	} else {
		return c.updateExternalEntity(key, preEntity, entity)
	}
	return nil
}

func (c *ExternalEntityController) addExternalEntity(key string, entity *cpv1b2.ExternalEntity) error {
	klog.InfoS("Adding ExternalEntity", "key", key)
	ifNameIPsMap, err := c.getInterfaceIPsMap(entity.Endpoints)
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
	klog.InfoS("Added ExternalEntity", "key", key)
	return nil
}

func (c *ExternalEntityController) getInterfaceIPsMap(endpoints []cpv1b2.Endpoint) (map[string]sets.String, error) {
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

func (c *ExternalEntityController) getHostInterfaceNameByEndpoint(ep cpv1b2.Endpoint) (string, error) {
	// TODO
	return "", nil
}

func (c *ExternalEntityController) addEntityEndpoint(eeKey string, ifName string, ips sets.String) error {
	klog.InfoS("Adding entity endpoint", "eeKey", eeKey, "ifName", ifName)
	hostIface, portExists := c.ifaceStore.GetInterfaceByName(ifName)
	if !portExists {
		klog.InfoS("Creating OVS ports and flows for EntityEndpoint", "ifName", ifName, "ExternalEntityKey", eeKey, "ips", ips)
		uplinkName := genUplinkInterfaceName(ifName)
		hostIface, err := c.createOVSPortsAndFlows(uplinkName, ifName, eeKey)
		if err != nil {
			return err
		}
		keyIPsMap := make(map[string]sets.String)
		keyIPsMap[eeKey] = ips
		c.updateInterfaceKeyIPsMap(hostIface, keyIPsMap)
		return nil
	}

	klog.InfoS("Updating OVS port data", "ExternalEntityKey", eeKey, "ifName", ifName, "ips", ips)
	updatedKeyIPsMap := make(map[string]sets.String)
	eeKeys := make([]string, 0)
	for entityKey, epIPs := range hostIface.ExternalEntityKeyIPsMap {
		updatedKeyIPsMap[entityKey] = epIPs
		eeKeys = append(eeKeys, entityKey)
	}
	ifIPs, keyExists := hostIface.ExternalEntityKeyIPsMap[eeKey]
	if keyExists {
		if ifIPs.HasAll(ips.List()...) {
			klog.InfoS("Skipping updating ExternalEntityKeyIPsMap for key ip already exists", "ExternalEntityKey", eeKey, "ifName", ifName, "ips", ips)
			return nil
		} else {
			ifIPs = ifIPs.Union(ips)
		}
		updatedKeyIPsMap[eeKey] = ifIPs
	} else {
		eeKeys = append(eeKeys, eeKey)
		updatedKeyIPsMap[eeKey] = ips
		err := c.updateOVSPortData(hostIface, eeKeys)
		if err != nil {
			return err
		}
	}
	c.updateInterfaceKeyIPsMap(hostIface, updatedKeyIPsMap)
	klog.InfoS("Added entity endpoint", "eeKey", eeKey, "ifName", ifName)
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

func endpointChanged(oldEndpoints []cpv1b2.Endpoint, newEndpoints []cpv1b2.Endpoint) bool {
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

func (c *ExternalEntityController) updateExternalEntity(key string, obj interface{}, curEntity *cpv1b2.ExternalEntity) error {
	klog.InfoS("Updating ExternalEntity", "key", key)
	preEntity := obj.(*cpv1b2.ExternalEntity)
	if !endpointChanged(preEntity.Endpoints, curEntity.Endpoints) {
		klog.InfoS("Skipping update ExternalEntity as no endpoints changed", "key", key)
		return nil
	}
	preIfNameIPsMap, err := c.getInterfaceIPsMap(preEntity.Endpoints)
	if err != nil {
		return err
	}
	curIfNameIPsMap, err := c.getInterfaceIPsMap(curEntity.Endpoints)
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
				hostIface, portExists := c.ifaceStore.GetInterfaceByName(cName)
				if !portExists {
					return fmt.Errorf("failed to find interface %s for updating ExternalEntity key %s EntityEndpointIPs", cName, key)
				}
				updatedKeyIPsMap := hostIface.ExternalEntityKeyIPsMap
				updatedKeyIPsMap[key] = cIPs
				c.updateInterfaceKeyIPsMap(hostIface, updatedKeyIPsMap)
			}
		}
	}
	c.syncedExternalEntities.Add(curEntity)
	// Notify the ExternalEntity create event to NetworkPolicyController.
	c.entityUpdateNotifier.Notify(key)
	klog.InfoS("Updated ExternalEntity", "key", key)
	return nil
}

func (c *ExternalEntityController) deleteExternalEntity(key string) error {
	klog.InfoS("Deleting ExternalEntity", "key", key)
	obj, exists, _ := c.syncedExternalEntities.GetByKey(key)
	if !exists {
		klog.InfoS("Skipping ExternalEntity deletion as it hasn't been synced", "ExternalEntityKey", key)
		return nil
	}
	entity := obj.(*cpv1b2.ExternalEntity)
	ifNameIPsMap, err := c.getInterfaceIPsMap(entity.Endpoints)
	if err != nil {
		return err
	}
	for ifName := range ifNameIPsMap {
		if err := c.deleteEntityEndpoint(key, ifName); err != nil {
			return err
		}
	}
	c.syncedExternalEntities.Delete(entity)
	klog.InfoS("Deleted ExternalEntity", "key", key)
	return nil
}

func (c *ExternalEntityController) deleteEntityEndpoint(key string, ifName string) error {
	klog.InfoS("Deleting entity endpoint", "key", key, "ifName", ifName)
	hostIface, portExists := c.ifaceStore.GetInterface(ifName)
	if !portExists {
		klog.InfoS("Skipping deleting host interface since it doesn't exist ", "ifName", ifName)
		return nil
	}
	if _, exist := hostIface.ExternalEntityKeyIPsMap[key]; exist {
		updatedKeyIPsMap := make(map[string]sets.String)
		updatedKeys := make([]string, 0)
		for eeKey, ips := range hostIface.ExternalEntityKeyIPsMap {
			updatedKeyIPsMap[eeKey] = ips
			if eeKey != key {
				updatedKeys = append(updatedKeys, eeKey)
			}
		}
		delete(updatedKeyIPsMap, key)
		if len(updatedKeyIPsMap) == 0 {
			if err := c.removeOVSPortsAndFlows(hostIface); err != nil {
				return err
			}
			c.ifaceStore.DeleteInterface(hostIface)
		} else {
			if err := c.updateOVSPortData(hostIface, updatedKeys); err != nil {
				return err
			}
			c.updateInterfaceKeyIPsMap(hostIface, updatedKeyIPsMap)
		}
	} else {
		klog.Warningf("Skipping deleting key %s for host interface %s since it doesn't exist ", key, ifName)
	}
	klog.InfoS("Deleted entity endpoint", "key", key, "ifName", ifName)
	return nil
}

// TODO: Implement ExternalEntityInterface create and flows installation.
func (c *ExternalEntityController) createOVSPortsAndFlows(uplinkName, hostIfName, key string) (*interfacestore.InterfaceConfig, error) {
	return &interfacestore.InterfaceConfig{}, nil
}

// TODO: Implement ExternalEntityInterface update and flows installation.
func (c *ExternalEntityController) updateOVSPortData(interfaceConfig *interfacestore.InterfaceConfig, eeKeys []string) error {
	return nil
}

// TODO: Implement ExternalEntityInterface delete and flows installation.
func (a *ExternalEntityController) removeOVSPortsAndFlows(interfaceConfig *interfacestore.InterfaceConfig) error {
	return nil
}

func genUplinkInterfaceName(hostIfName string) string {
	return fmt.Sprintf("phy-%s", hostIfName)
}
