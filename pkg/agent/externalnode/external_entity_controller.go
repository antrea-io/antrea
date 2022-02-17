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
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	eeinformer "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	eelister "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/k8s"
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

	ovsExternalIDUplinkName      = "uplink-name"
	ovsExternalIDHostIFName      = "hostInterface-name"
	ovsExternalIDHostIFIndex     = "hostInterface-index"
	ovsExternalIDUplinkPort      = "uplink-port"
	ovsExternalIDEntityName      = "entity-name"
	ovsExternalIDEntityNamespace = "entity-namespace"
	ovsExternalIDIP              = "ip"
	eeSplitter                   = ","
	reserveRuleSplitter          = ":"
)

var (
	keyFunc      = cache.DeletionHandlingMetaNamespaceKeyFunc
	splitKeyFunc = cache.SplitMetaNamespaceKey
)

type ExternalEntityController struct {
	ovsBridgeClient            ovsconfig.OVSBridgeClient
	ovsctlClient               ovsctl.OVSCtlClient
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
	endpointNameIPMap    map[string]string
	reservedHostPorts    []reserveHostPort
	reservedRules        []string
}

type reserveHostPort struct {
	// The protocol (TCP, UDP, or SCTP) which traffic must match.
	protocol binding.Protocol
	// The dst port on the given protocol.
	port uint16
	// The remote IP to which is reserved.
	ip net.IP
	// The remote CIDR to which is reserved.
	ipnet   *net.IPNet
	ingress bool
}

type EndpointInterfaceNotFound struct {
	error
}

func newEndpointInterfaceNotFound(ep v1alpha2.Endpoint) EndpointInterfaceNotFound {
	return EndpointInterfaceNotFound{
		fmt.Errorf("not found endpoint interface on the host with name %s ip %s", ep.Name, ep.IP),
	}
}

func NewExternalEntityController(ovsBridgeClient ovsconfig.OVSBridgeClient, ofClient openflow.Client, externalEntityInformer eeinformer.ExternalEntityInformer,
	ifaceStore interfacestore.InterfaceStore, entityUpdateNotifier channel.Notifier, eeStoreReadyCh chan<- struct{}, namespace string, reservedRules []string) (*ExternalEntityController, error) {
	c := &ExternalEntityController{
		ovsBridgeClient:            ovsBridgeClient,
		ovsctlClient:               ovsctl.NewClient(ovsBridgeClient.GetBridgeName()),
		ofClient:                   ofClient,
		externalEntityInformer:     externalEntityInformer.Informer(),
		externalEntityLister:       externalEntityInformer.Lister().ExternalEntities(namespace),
		externalEntityListerSynced: externalEntityInformer.Informer().HasSynced,
		queue:                      workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "externalEntity"),
		ifaceStore:                 ifaceStore,
		syncedExternalEntities:     cache.NewStore(keyFunc),
		entityUpdateNotifier:       entityUpdateNotifier,
		eeStoreReadyCh:             eeStoreReadyCh,
		endpointNameIPMap:          make(map[string]string),
		reservedRules:              reservedRules,
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
	if err := c.reconcilePolicyBypassFlows(); err != nil {
		return fmt.Errorf("failed to reconcile reserved flows %v", err)
	}
	// Notify NetworkPolicyController interface store has contains ExternalEntityInterfaceConfig with endpoint IPs.
	close(c.eeStoreReadyCh)
	return nil
}

func (c *ExternalEntityController) reconcileHostUplinkFlows() error {
	hostIfaces := c.ifaceStore.GetInterfacesByType(interfacestore.ExternalEntityInterface)
	for _, hostIface := range hostIfaces {
		if err := c.ofClient.InstallVMUplinkFlows(hostIface.InterfaceName, hostIface.OVSPortConfig.OFPort, hostIface.UplinkPort.OFPort); err != nil {
			klog.ErrorS(err, "Failed to install openflow entries to forward packet between uplink and host interface", "hostInterface", hostIface.InterfaceName)
			return err
		}
		klog.InfoS("Reconcile host uplink flow for ExternalEntityInterface", "ifName", hostIface.InterfaceName)
	}
	return nil
}

func (c *ExternalEntityController) reconcileExternalEntityInterfaces() error {
	entityList, err := c.externalEntityLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("reconcile failed to list ExternalEntities %v", err)
	}
	desiredInterfaces := sets.NewString()
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
				desiredInterfaces = desiredInterfaces.Insert(ifName)
			}
		}
	}
	hostIfaces := c.ifaceStore.GetInterfacesByType(interfacestore.ExternalEntityInterface)
	for _, hostIface := range hostIfaces {
		if exists := desiredInterfaces.Has(hostIface.InterfaceName); !exists {
			key := k8s.NamespacedName(hostIface.EntityNamespace, hostIface.EntityName)
			err := c.deleteEntityEndpoint(key, hostIface.InterfaceName)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *ExternalEntityController) reconcilePolicyBypassFlows() error {
	if err := c.getReservedHostPorts(); err != nil {
		return err
	}
	for _, rhp := range c.reservedHostPorts {
		klog.V(2).InfoS("Installing reserved flows", "protocol", rhp.protocol, "IP", rhp.ip, "IPNet", rhp.ipnet, "port", rhp.port, "ingress", rhp.ingress)
		if err := c.ofClient.InstallPolicyBypassFlows(rhp.protocol, rhp.ipnet, rhp.ip, rhp.port, rhp.ingress); err != nil {
			klog.ErrorS(err, "Failed to install reserved flows", "protocol", rhp.protocol, "IP", rhp.ip, "IPNet", rhp.ipnet, "port", rhp.port, "direction", rhp.ingress)
			return err
		}
	}
	klog.InfoS("Installed reserved flows")
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
			if _, ok := err.(EndpointInterfaceNotFound); !ok {
				return nil, err
			}
			klog.ErrorS(err, "Skip endpoint", "name", ep.Name, "ip", ep.IP)
			continue
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
		if err := c.addEntityEndpoint(entity.Namespace, entity.Name, ifName, ips); err != nil {
			return err
		}
	}
	c.syncedExternalEntities.Add(entity)
	// Notify the ExternalEntity create event to NetworkPolicyController.
	c.entityUpdateNotifier.Notify(key)
	return nil
}

func (c *ExternalEntityController) getHostInterfaceNameByEndpoint(ep v1alpha2.Endpoint) (string, error) {
	if ep.Name != "" {
		hostIfName, found := c.endpointNameIPMap[ep.Name]
		if found {
			return hostIfName, nil
		}
		link, err := net.InterfaceByName(ep.Name)
		if err == nil {
			c.endpointNameIPMap[ep.Name] = link.Name
			return link.Name, nil
		}
		if !strings.Contains(err.Error(), "no such network interface") {
			return "", err
		}
	}
	if ep.IP != "" {
		hostIfName, found := c.endpointNameIPMap[ep.IP]
		if found {
			return hostIfName, nil
		}
		var ipFilter *ip.DualStackIPs
		epIP := net.ParseIP(ep.IP)
		if epIP.To4() != nil {
			ipFilter = &ip.DualStackIPs{IPv4: epIP}
		} else {
			ipFilter = &ip.DualStackIPs{IPv6: epIP}
		}
		_, _, link, err := util.GetIPNetDeviceFromIP(ipFilter, sets.NewString())
		if err == nil {
			c.endpointNameIPMap[ep.IP] = link.Name
			return link.Name, nil
		}
		if !strings.Contains(err.Error(), "unable to find local IPs and device") {
			return "", err
		}
	}
	return "", newEndpointInterfaceNotFound(ep)
}

func (c *ExternalEntityController) addEntityEndpoint(entityNamespace, entityName string, ifName string, ips sets.String) error {
	eeKey := k8s.NamespacedName(entityNamespace, entityName)
	hostIface, portExists := c.ifaceStore.GetInterfaceByName(ifName)
	if !portExists {
		klog.InfoS("Creating OVS ports and flows for EntityEndpoint", "ifName", ifName, "ExternalEntityKey", eeKey)
		uplinkName := genUplinkInterfaceName(ifName)
		klog.V(2).InfoS("Creating OVS ports for host interface and ExternalEntity", "externalEntity", eeKey, "interface", ifName)
		newInterface, err := c.createOVSPortsAndFlows(uplinkName, ifName, entityName, entityNamespace)
		if err != nil {
			return err
		}
		var ifIPs []net.IP
		for _, entityIP := range ips.List() {
			ifIPs = append(ifIPs, net.ParseIP(entityIP))
		}
		if err := c.updateOVSPortIPsData(newInterface, ips); err != nil {
			return err
		}
		newInterface.IPs = ifIPs
		c.ifaceStore.AddInterface(newInterface)
		return nil
	}

	klog.InfoS("Updating OVS port data", "ExternalEntityKey", eeKey, "ifName", ifName, "ip", ips)
	updateOVSPortData := false
	if hostIface.EntityName == "" {
		hostIface.EntityName = entityName
		hostIface.EntityNamespace = entityNamespace
		updateOVSPortData = true
	}
	oldIPs := sets.NewString()
	for _, oip := range hostIface.IPs {
		oldIPs.Insert(oip.String())
	}
	if !oldIPs.Equal(ips) {
		var newIPs []net.IP
		for _, ipStr := range ips.List() {
			newIPs = append(newIPs, net.ParseIP(ipStr))
		}
		c.updateInterfaceIPs(hostIface, newIPs)
		updateOVSPortData = true
	}
	if updateOVSPortData {
		err := c.updateOVSPortIPsData(hostIface, ips)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *ExternalEntityController) updateInterfaceIPs(hostIface *interfacestore.InterfaceConfig, updatedIPs []net.IP) {
	iface := &interfacestore.InterfaceConfig{
		InterfaceName: hostIface.InterfaceName,
		Type:          interfacestore.ExternalEntityInterface,
		OVSPortConfig: &interfacestore.OVSPortConfig{
			PortUUID: hostIface.PortUUID,
			OFPort:   hostIface.OFPort,
		},
		EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
			EntityName:      hostIface.EntityName,
			EntityNamespace: hostIface.EntityNamespace,
			UplinkPort: &interfacestore.OVSPortConfig{
				PortUUID: hostIface.UplinkPort.PortUUID,
				OFPort:   hostIface.UplinkPort.OFPort,
			},
			HostIfaceIndex: hostIface.EntityInterfaceConfig.HostIfaceIndex,
		},
		IPs: updatedIPs,
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
			err = c.addEntityEndpoint(curEntity.Namespace, curEntity.Name, cName, cIPs)
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
	updatedIPs := make([]net.IP, cIPs.Len())
	for i, ipStr := range cIPs.List() {
		updatedIPs[i] = net.ParseIP(ipStr)
	}
	c.updateInterfaceIPs(hostIface, updatedIPs)
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
	if err := c.removeOVSPortsAndFlows(hostIface); err != nil {
		return err
	}
	c.ifaceStore.DeleteInterface(hostIface)
	for key, ifaceName := range c.endpointNameIPMap {
		if ifaceName == ifName {
			delete(c.endpointNameIPMap, key)
		}
	}
	return nil
}

func (c *ExternalEntityController) createOVSPortsAndFlows(uplinkName, hostIfName, entityName, entityNamespace string) (*interfacestore.InterfaceConfig, error) {
	adapterConfig, err := getUplinkConfig(hostIfName)
	if err != nil {
		klog.ErrorS(err, "Failed to get the configuration on the host interface", "hostInterface", hostIfName)
		return nil, err
	}
	if err := renameInterface(hostIfName, uplinkName); err != nil {
		klog.ErrorS(err, "Failed to rename host interface name as the uplink name", "hostInterface", hostIfName, "uplink", uplinkName)
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			renameInterface(uplinkName, hostIfName)
		}
	}()
	// Create uplink port on OVS.
	uplinkExternalIDs := map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUplink,
	}
	uplinkUUID, err := c.ovsBridgeClient.CreatePort(uplinkName, uplinkName, uplinkExternalIDs)
	if err != nil {
		klog.ErrorS(err, "Failed to create uplink port on OVS", "uplink", uplinkName)
		return nil, err
	}
	defer func() {
		if !success {
			c.ovsBridgeClient.DeletePort(uplinkUUID)
		}
	}()
	uplinkOFPort, err := c.ovsBridgeClient.GetOFPort(uplinkName, false)
	if err != nil {
		klog.ErrorS(err, "Failed to get uplink ofport", "uplink", uplinkName)
		return nil, err
	}
	klog.V(2).InfoS("Added uplink port on OVS", "port", uplinkName)

	// Create host port on OVS.
	hostIfUUID, err := c.ovsBridgeClient.CreateInternalPort(hostIfName, 0, nil)
	if err != nil {
		klog.ErrorS(err, "Failed to create host port on OVS", "hostInterface", hostIfName)
		return nil, err
	}
	defer func() {
		if !success {
			c.ovsBridgeClient.DeletePort(hostIfUUID)
		}
	}()
	hostOFPort, err := c.ovsBridgeClient.GetOFPort(hostIfName, false)
	if err != nil {
		klog.ErrorS(err, "Failed to get host interface ofport", "hostInterface", uplinkName)
		return nil, err
	}
	klog.V(2).InfoS("Added host port on OVS", "port", hostIfName)

	hostIF, err := net.InterfaceByName(hostIfName)
	if err != nil {
		return nil, err
	}
	attachInfo := GetOVSAttachInfo(uplinkName, uplinkUUID, fmt.Sprintf("%d", hostIF.Index), hostIF.Name, entityName, entityNamespace)
	// Update OVS port external_ids with the host interface id and name.
	if err := c.ovsBridgeClient.SetPortExternalIDs(hostIfName, attachInfo); err != nil {
		return nil, err
	}
	if err := util.MoveIFConfigurations(adapterConfig.IPs, adapterConfig.Routes, adapterConfig.MAC, adapterConfig.MTU, uplinkName, hostIfName); err != nil {
		klog.ErrorS(err, "Failed to move configuration from the host interface to uplink", "hostInterface", hostIfName, "uplink", uplinkName)
		return nil, err
	}
	klog.V(2).InfoS("Moved configuration from the uplink to host port", "uplink", uplinkName, "hostInterface", hostIfName)
	if err := c.ofClient.InstallVMUplinkFlows(hostIfName, hostOFPort, uplinkOFPort); err != nil {
		return nil, err
	}
	klog.InfoS("Added uplink and host port on OVS and installed openflow entries", "uplink", uplinkName, "hostInterface", hostIfName)
	success = true
	hostIFConfig := &interfacestore.InterfaceConfig{
		InterfaceName: hostIfName,
		Type:          interfacestore.ExternalEntityInterface,
		OVSPortConfig: &interfacestore.OVSPortConfig{
			PortUUID: hostIfUUID,
			OFPort:   hostOFPort,
		},
		EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
			EntityName:      entityName,
			EntityNamespace: entityNamespace,
			UplinkPort: &interfacestore.OVSPortConfig{
				PortUUID: uplinkUUID,
				OFPort:   uplinkOFPort,
			},
			HostIfaceIndex: hostIF.Index,
		},
	}
	return hostIFConfig, nil
}

func (c *ExternalEntityController) updateOVSPortIPsData(interfaceConfig *interfacestore.InterfaceConfig, ips sets.String) error {
	portUUID := interfaceConfig.PortUUID
	portName := interfaceConfig.InterfaceName
	port, err := c.ovsBridgeClient.GetPortData(portUUID, portName)
	if err != nil {
		return err
	}

	attachInfo := map[string]interface{}{
		ovsExternalIDUplinkName:               port.ExternalIDs[ovsExternalIDUplinkName],
		ovsExternalIDHostIFIndex:              port.ExternalIDs[ovsExternalIDHostIFIndex],
		ovsExternalIDHostIFName:               port.ExternalIDs[ovsExternalIDHostIFName],
		ovsExternalIDUplinkPort:               port.ExternalIDs[ovsExternalIDUplinkPort],
		ovsExternalIDEntityName:               port.ExternalIDs[ovsExternalIDEntityName],
		ovsExternalIDEntityNamespace:          port.ExternalIDs[ovsExternalIDEntityNamespace],
		ovsExternalIDIP:                       strings.Join(ips.List(), eeSplitter),
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
	}

	// Reset with the external entity's name and namespace. This happens on Windows if the host network interface is
	// used to create VMSwitch in the agent initialzation phase.
	if attachInfo[ovsExternalIDEntityName] == "" {
		attachInfo[ovsExternalIDEntityName] = interfaceConfig.EntityName
	}
	if attachInfo[ovsExternalIDEntityNamespace] == "" {
		attachInfo[ovsExternalIDEntityNamespace] = interfaceConfig.EntityNamespace
	}

	return c.ovsBridgeClient.SetPortExternalIDs(portName, attachInfo)
}

func (c *ExternalEntityController) removeOVSPortsAndFlows(interfaceConfig *interfacestore.InterfaceConfig) error {
	portUUID := interfaceConfig.PortUUID
	portName := interfaceConfig.InterfaceName
	if err := c.ofClient.UninstallVMUplinkFlows(portName); err != nil {
		return err
	}
	port, err := c.ovsBridgeClient.GetPortData(portUUID, portName)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			klog.ErrorS(err, "OVS port is not found", "port", portName)
			return nil
		}
		return err
	}
	hostIfName := port.ExternalIDs[ovsExternalIDHostIFName]
	uplinkIfName := port.ExternalIDs[ovsExternalIDUplinkName]
	uplinkPortID := port.ExternalIDs[ovsExternalIDUplinkPort]
	adapterConfig, er := getUplinkConfig(hostIfName)
	if er != nil {
		klog.ErrorS(err, "Failed to get the configuration on the host interface", "hostInterface", hostIfName)
		return err
	}
	if err := c.ovsBridgeClient.DeletePort(port.UUID); err != nil {
		klog.ErrorS(err, "Failed to delete port on OVS", "port", hostIfName)
		return err
	}
	if err := c.ovsBridgeClient.DeletePort(uplinkPortID); err != nil {
		return err
	}
	defer func() {
		// Delete host interface from OVS datapath if it is existing.
		// This is to resolve an issue that OVS fails to remove the interface from datapath. It might happen because the interface
		// is busy when OVS tries to remove it with the OVSDB interface deletion event.
		if err := c.ovsctlClient.DeleteDPInterface(hostIfName); err != nil {
			klog.ErrorS(err, "Failed delete host interface from OVS datapath", "interface", hostIfName)
		}
	}()

	// Wait until the host interface created by OVS is removed.
	pollErr := wait.PollImmediate(50*time.Millisecond, 2*time.Second, func() (bool, error) {
		return !util.HostInterfaceExists(hostIfName), nil
	})
	if pollErr != nil {
		klog.ErrorS(pollErr, "Failed to wait for host interface deletion in 2s", "interface", hostIfName)
	}
	// Recover the uplink interface's name.
	if err := renameInterface(uplinkIfName, hostIfName); err != nil {
		klog.ErrorS(err, "Failed to recover uplink name to the host interface name", "uplink", uplinkIfName, "hostInterface", hostIfName)
		return err
	}
	// Move the IP configurations back to the host interface.
	if err := util.MoveIFConfigurations(adapterConfig.IPs, adapterConfig.Routes, adapterConfig.MAC, adapterConfig.MTU, uplinkIfName, hostIfName); err != nil {
		klog.ErrorS(err, "Failed to move back configuration to the host interface", "hostInterface", hostIfName)
		return err
	}
	return nil
}

func (c *ExternalEntityController) getReservedHostPorts() error {
	for _, s := range c.reservedRules {
		rule := strings.Split(s, reserveRuleSplitter)

		// parse direction.
		direction := false
		if rule[0] == "in" {
			direction = true
		}

		// parse protocol.
		var proto binding.Protocol
		switch rule[1] {
		case "tcp":
			proto = binding.ProtocolTCP
		case "udp":
			proto = binding.ProtocolUDP
		case "icmp":
			proto = binding.ProtocolICMP
		default:
			proto = binding.ProtocolIP
		}

		// parse remote IP or CIDR.
		var remoteCIDR *net.IPNet
		var remoteIP net.IP
		var err error
		if rule[2] != "" {
			if strings.Contains(rule[2], "/") {
				_, remoteCIDR, err = net.ParseCIDR(rule[2])
				if err != nil {
					return err
				}
			} else {
				remoteIP = net.ParseIP(rule[2])
			}
		}

		// parse port number.
		var port int
		if rule[3] != "" {
			port, _ = strconv.Atoi(rule[3])
		}
		c.reservedHostPorts = append(c.reservedHostPorts, reserveHostPort{
			ipnet:    remoteCIDR,
			ip:       remoteIP,
			port:     uint16(port),
			protocol: proto,
			ingress:  direction,
		})
	}
	return nil
}

func ParseHostInterfaceConfig(ovsBridgeClient ovsconfig.OVSBridgeClient, portData *ovsconfig.OVSPortData, portConfig *interfacestore.OVSPortConfig) (*interfacestore.InterfaceConfig, error) {
	var interfaceConfig *interfacestore.InterfaceConfig
	interfaceConfig = &interfacestore.InterfaceConfig{
		InterfaceName: portData.Name,
		Type:          interfacestore.ExternalEntityInterface,
		OVSPortConfig: portConfig,
	}
	var hostUplinkConfig *interfacestore.EntityInterfaceConfig
	if portData.ExternalIDs != nil {
		entityIPStrs := strings.Split(portData.ExternalIDs[ovsExternalIDIP], eeSplitter)
		var entityIPs []net.IP
		for _, ipStr := range entityIPStrs {
			entityIPs = append(entityIPs, net.ParseIP(ipStr))
		}
		interfaceConfig.IPs = entityIPs
		uplinkName, ok := portData.ExternalIDs[ovsExternalIDUplinkName]
		uplinkPortUUID, ok := portData.ExternalIDs[ovsExternalIDUplinkPort]
		if !ok {
			klog.InfoS("Host port %d doesn't match the uplink interface", portData.Name)
			return interfaceConfig, nil
		}
		uplinkPortData, ovsErr := ovsBridgeClient.GetPortData(uplinkPortUUID, uplinkName)
		if ovsErr != nil {
			return nil, ovsErr
		}
		hostLinkStr := portData.ExternalIDs[ovsExternalIDHostIFIndex]
		hostLink, err := strconv.Atoi(hostLinkStr)
		if err != nil {
			return nil, err
		}
		entityName, _ := portData.ExternalIDs[ovsExternalIDEntityName]
		entityNamespace, _ := portData.ExternalIDs[ovsExternalIDEntityNamespace]
		hostUplinkConfig = &interfacestore.EntityInterfaceConfig{
			EntityName:      entityName,
			EntityNamespace: entityNamespace,
			UplinkPort: &interfacestore.OVSPortConfig{
				PortUUID: uplinkPortUUID,
				OFPort:   uplinkPortData.OFPort,
			},
			HostIfaceIndex: hostLink,
		}
	}
	interfaceConfig.EntityInterfaceConfig = hostUplinkConfig
	return interfaceConfig, nil
}

func genUplinkInterfaceName(hostIfName string) string {
	return fmt.Sprintf("phy-%s", hostIfName)
}

func getUplinkConfig(uplinkIfName string) (*config.AdapterNetConfig, error) {
	iface, err := net.InterfaceByName(uplinkIfName)
	if err != nil {
		return nil, err
	}
	addrs, err := util.GetGlobalIPNetsByName(iface)
	if err != nil {
		return nil, err
	}
	gw, routes, err := util.GetNetRoutesOnAdapter(iface.Index)
	if err != nil {
		return nil, err
	}
	return &config.AdapterNetConfig{
		Name:    uplinkIfName,
		Index:   iface.Index,
		MAC:     iface.HardwareAddr,
		IPs:     addrs,
		Routes:  routes,
		Gateway: gw,
		MTU:     iface.MTU,
	}, nil
}

func renameInterface(from, to string) error {
	var renameErr error
	pollErr := wait.Poll(time.Millisecond*100, time.Second, func() (done bool, err error) {
		renameErr = util.RenameHostInterface(from, to)
		if renameErr != nil {
			klog.InfoS("Unable to rename host interface name with error, retrying", "oldName", from, "newName", to, "err", renameErr)
			return false, nil
		}
		return true, nil
	})
	if pollErr != nil {
		return fmt.Errorf("failed to rename host interface name %s to %s", from, to)
	}
	return nil
}

func GetOVSAttachInfo(uplinkName, uplinkUUID, hostIFIdx, hostPortName, entityName, entityNamespace string) map[string]interface{} {
	attachInfo := map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
	}
	if uplinkName != "" {
		attachInfo[ovsExternalIDUplinkName] = uplinkName
	}
	if uplinkUUID != "" {
		attachInfo[ovsExternalIDUplinkPort] = uplinkUUID
	}
	if hostIFIdx != "" {
		attachInfo[ovsExternalIDHostIFIndex] = hostIFIdx
	}
	if hostPortName != "" {
		attachInfo[ovsExternalIDHostIFName] = hostPortName
	}
	if entityName != "" {
		attachInfo[ovsExternalIDEntityName] = entityName
	}
	if entityNamespace != "" {
		attachInfo[ovsExternalIDEntityNamespace] = entityNamespace
	}
	return attachInfo
}
