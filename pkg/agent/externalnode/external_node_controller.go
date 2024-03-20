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
	"net"
	"reflect"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	enlister "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	agentConfig "antrea.io/antrea/pkg/config/agent"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/externalnode"
	"antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	controllerName = "ExternalNodeController"
	// How long to wait before retrying the processing of an ExternalNode change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Disable resyncing.
	resyncPeriod time.Duration = 0

	ovsExternalIDUplinkName      = "uplink-name"
	ovsExternalIDUplinkPort      = "uplink-port"
	ovsExternalIDEntityName      = "entity-name"
	ovsExternalIDEntityNamespace = "entity-namespace"
	ovsExternalIDIPs             = "ip-address"
	ipsSplitter                  = ","
)

var (
	keyFunc              = cache.MetaNamespaceKeyFunc
	splitKeyFunc         = cache.SplitMetaNamespaceKey
	renameInterface      = util.RenameInterface
	getInterfaceConfig   = util.GetInterfaceConfig
	getIPNetDeviceFromIP = util.GetIPNetDeviceFromIP
	hostInterfaceExists  = util.HostInterfaceExists
)

type ExternalNodeController struct {
	ovsBridgeClient          ovsconfig.OVSBridgeClient
	ovsctlClient             ovsctl.OVSCtlClient
	ofClient                 openflow.Client
	externalNodeInformer     cache.SharedIndexInformer
	externalNodeLister       enlister.ExternalNodeLister
	externalNodeListerSynced cache.InformerSynced
	queue                    workqueue.RateLimitingInterface
	ifaceStore               interfacestore.InterfaceStore
	syncedExternalNode       *v1alpha1.ExternalNode
	// externalEntityUpdateNotifier is used for notifying ExternalEntity updates to NetworkPolicyController.
	externalEntityUpdateNotifier channel.Notifier
	nodeName                     string
	externalNodeNamespace        string
	policyBypassRules            []agentConfig.PolicyBypassRule
}

func NewExternalNodeController(ovsBridgeClient ovsconfig.OVSBridgeClient, ofClient openflow.Client, externalNodeInformer cache.SharedIndexInformer,
	ifaceStore interfacestore.InterfaceStore, externalEntityUpdateNotifier channel.Notifier, externalNodeNamespace string, policyBypassRules []agentConfig.PolicyBypassRule) (*ExternalNodeController, error) {
	c := &ExternalNodeController{
		ovsBridgeClient:              ovsBridgeClient,
		ovsctlClient:                 ovsctl.NewClient(ovsBridgeClient.GetBridgeName()),
		ofClient:                     ofClient,
		externalNodeInformer:         externalNodeInformer,
		externalNodeLister:           enlister.NewExternalNodeLister(externalNodeInformer.GetIndexer()),
		externalNodeListerSynced:     externalNodeInformer.HasSynced,
		queue:                        workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "externalNode"),
		ifaceStore:                   ifaceStore,
		externalEntityUpdateNotifier: externalEntityUpdateNotifier,
		policyBypassRules:            policyBypassRules,
	}
	nodeName, err := env.GetNodeName()
	if err != nil {
		return nil, err
	}
	c.nodeName = nodeName
	c.externalNodeNamespace = externalNodeNamespace
	c.externalNodeInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.enqueueExternalNodeAdd,
			UpdateFunc: c.enqueueExternalNodeUpdate,
			DeleteFunc: c.enqueueExternalNodeDelete,
		},
		resyncPeriod)

	return c, nil
}

// Run will create a worker (goroutine) which will process the ExternalNode events from the work queue.
func (c *ExternalNodeController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting controller", "name", controllerName)
	defer klog.InfoS("Shutting down controller", "name", controllerName)

	if err := wait.PollUntilContextCancel(wait.ContextForChannel(stopCh), 5*time.Second, true, func(ctx context.Context) (done bool, err error) {
		if err = c.reconcile(); err != nil {
			klog.ErrorS(err, "ExternalNodeController failed during reconciliation")
			return false, nil
		}
		return true, nil
	}); err != nil {
		klog.Info("Stopped ExternalNodeController reconciliation")
		return
	}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.externalNodeListerSynced) {
		klog.Error("Failed to wait for syncing ExternalNodes cache")
		return
	}

	c.queue.Add(k8s.NamespacedName(c.externalNodeNamespace, c.nodeName))
	go wait.Until(c.worker, time.Second, stopCh)

	<-stopCh
}

func (c *ExternalNodeController) enqueueExternalNodeAdd(obj interface{}) {
	en := obj.(*v1alpha1.ExternalNode)
	key, _ := keyFunc(en)
	c.queue.Add(key)
	klog.InfoS("Enqueued ExternalNode ADD event", "ExternalNode", klog.KObj(en))
}

func (c *ExternalNodeController) enqueueExternalNodeUpdate(oldObj interface{}, newObj interface{}) {
	oldEN := oldObj.(*v1alpha1.ExternalNode)
	newEN := newObj.(*v1alpha1.ExternalNode)
	if reflect.DeepEqual(oldEN.Spec.Interfaces, newEN.Spec.Interfaces) {
		klog.InfoS("Skip enqueuing ExternalNode UPDATE event as no changes for interfaces", "ExternalNode", klog.KObj(newEN))
		return
	}
	key, _ := keyFunc(newEN)
	c.queue.Add(key)
	klog.InfoS("Enqueued ExternalNode UPDATE event", "ExternalNode", klog.KObj(newEN))
}

func (c *ExternalNodeController) enqueueExternalNodeDelete(obj interface{}) {
	en := obj.(*v1alpha1.ExternalNode)
	key, _ := keyFunc(en)
	c.queue.Add(key)
	klog.InfoS("Enqueued ExternalNode DELETE event", "ExternalNode", klog.KObj(en))
}

func (c *ExternalNodeController) reconcile() error {
	klog.InfoS("Reconciling for controller", "name", controllerName)
	if err := c.reconcileHostUplinkFlows(); err != nil {
		return fmt.Errorf("failed to reconcile host uplink flows %v", err)
	}
	if err := c.reconcilePolicyBypassFlows(); err != nil {
		return fmt.Errorf("failed to reconcile reserved flows %v", err)
	}
	klog.InfoS("Reconciled for controller", "name", controllerName)
	return nil
}

func (c *ExternalNodeController) reconcileHostUplinkFlows() error {
	hostIfaces := c.ifaceStore.GetInterfacesByType(interfacestore.ExternalEntityInterface)
	for _, hostIface := range hostIfaces {
		if err := c.ofClient.InstallVMUplinkFlows(hostIface.InterfaceName, hostIface.OVSPortConfig.OFPort, hostIface.UplinkPort.OFPort); err != nil {
			return err
		}
		klog.InfoS("Reconciled host uplink flow for ExternalEntityInterface", "ifName", hostIface.InterfaceName)
	}
	return nil
}

func (c *ExternalNodeController) reconcilePolicyBypassFlows() error {
	for _, rule := range c.policyBypassRules {
		klog.V(2).InfoS("Installing policy bypass flows", "protocol", rule.Protocol, "CIDR", rule.CIDR, "port", rule.Port, "direction", rule.Direction)
		protocol := parseProtocol(rule.Protocol)
		_, ipNet, _ := net.ParseCIDR(rule.CIDR)
		if err := c.ofClient.InstallPolicyBypassFlows(protocol, ipNet, uint16(rule.Port), rule.Direction == "ingress"); err != nil {
			return err
		}
	}
	klog.InfoS("Installed policy bypass flows", "RuleCount", len(c.policyBypassRules))
	return nil
}

// worker is a long-running function that will continuously call the processNextWorkItem function in
// order to read and process a message on the work queue.
func (c *ExternalNodeController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *ExternalNodeController) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)

	if key, ok := obj.(string); !ok {
		c.queue.Forget(obj)
		klog.Errorf("Expected string type in work queue but got %#v", obj)
		return true
	} else if err := c.syncExternalNode(key); err == nil {
		// If no error occurs, then forget this item so it does not get queued again until
		// another change happens.
		c.queue.Forget(key)
	} else {
		// Put the item back on the work queue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Error syncing ExternalNode", "ExternalNode", key)
	}
	return true
}

func (c *ExternalNodeController) syncExternalNode(key string) error {
	_, name, err := splitKeyFunc(key)
	if err != nil {
		// This err should not occur.
		return err
	}
	en, err := c.externalNodeLister.ExternalNodes(c.externalNodeNamespace).Get(name)
	if errors.IsNotFound(err) {
		return c.deleteExternalNode()
	}

	if c.syncedExternalNode == nil {
		return c.addExternalNode(en)
	} else {
		return c.updateExternalNode(c.syncedExternalNode, en)
	}
}

func (c *ExternalNodeController) addExternalNode(en *v1alpha1.ExternalNode) error {
	klog.InfoS("Adding ExternalNode", "ExternalNode", klog.KObj(en))
	eeName, err := externalnode.GenExternalEntityName(en)
	if err != nil {
		return err
	}
	ifName, ips, err := getHostInterfaceName(en.Spec.Interfaces[0])
	if err != nil {
		return err
	}
	if err := c.addInterface(ifName, en.Namespace, eeName, ips); err != nil {
		return err
	}
	c.syncedExternalNode = en
	// Notify the ExternalEntity event to NetworkPolicyController.
	c.externalEntityUpdateNotifier.Notify(v1beta2.ExternalEntityReference{
		Name:      eeName,
		Namespace: en.Namespace,
	})
	return nil
}

func (c *ExternalNodeController) addInterface(ifName string, eeNamespace string, eeName string, ips []string) error {
	hostIface, ifaceExists := c.ifaceStore.GetInterfaceByName(ifName)
	if !ifaceExists {
		klog.InfoS("Creating OVS ports and flows for ExternalEntityInterface", "ifName", ifName, "externalEntity", eeName, "ips", ips)
		uplinkName := util.GenerateUplinkInterfaceName(ifName)
		iface, err := c.createOVSPortsAndFlows(uplinkName, ifName, eeNamespace, eeName, ips)
		if err != nil {
			return err
		}
		c.ifaceStore.AddInterface(iface)
		return nil
	}
	klog.InfoS("Updating OVS port data", "ifName", ifName, "externalEntity", eeName, "ips", ips)
	portUUID := hostIface.PortUUID
	portName := hostIface.InterfaceName
	portData, ovsErr := c.ovsBridgeClient.GetPortData(portUUID, portName)
	if ovsErr != nil {
		return ovsErr
	}
	preEEName := portData.ExternalIDs[ovsExternalIDEntityName]
	preIPs := sets.New[string](strings.Split(portData.ExternalIDs[ovsExternalIDIPs], ipsSplitter)...)
	if preEEName == eeName && sets.New[string](ips...).Equal(preIPs) {
		klog.InfoS("Skipping updating OVS port data as both entity name and ip are not changed", "ifName", ifName)
		return nil
	}

	iface, err := c.updateOVSPortsData(hostIface, portData, eeName, ips)
	if err != nil {
		return err
	}
	c.ifaceStore.AddInterface(iface)
	return nil
}

func (c *ExternalNodeController) updateExternalNode(preEN *v1alpha1.ExternalNode, curEN *v1alpha1.ExternalNode) error {
	klog.InfoS("Updating ExternalNode", "ExternalNode", klog.KObj(curEN))
	if reflect.DeepEqual(preEN.Spec.Interfaces[0], curEN.Spec.Interfaces[0]) {
		klog.InfoS("Skip processing ExternalNode update as no changes for Interface[0]", "ExternalNode", klog.KObj(curEN))
		return nil
	}
	preEEName, err := externalnode.GenExternalEntityName(preEN)
	if err != nil {
		return err
	}
	preIfName, preIPs, err := getHostInterfaceName(preEN.Spec.Interfaces[0])
	if err != nil {
		return err
	}
	curEEName, err := externalnode.GenExternalEntityName(curEN)
	if err != nil {
		return err
	}
	curIfName, curIPs, err := getHostInterfaceName(curEN.Spec.Interfaces[0])
	if err != nil {
		return err
	}
	if preIfName != curIfName {
		klog.InfoS("Found interface name is changed", "preName", preIfName, "curName", curIfName)
		if err = c.addInterface(curIfName, curEN.Namespace, curEEName, curIPs); err != nil {
			return err
		}
		ifaceConfig, ifaceExists := c.ifaceStore.GetInterfaceByName(preIfName)
		if ifaceExists {
			if err = c.deleteInterface(ifaceConfig); err != nil {
				return err
			}
		}
	} else if !reflect.DeepEqual(preIPs, curIPs) || preEEName != curEEName {
		klog.InfoS("Found interface configuration is changed", "preIPs", preIPs, "preExternalEntity", preEEName,
			"curIPs", curIPs, "curExternalEntity", curEEName)
		if err = c.addInterface(curIfName, curEN.Namespace, curEEName, curIPs); err != nil {
			return err
		}
	}
	c.syncedExternalNode = curEN
	// Notify the ExternalEntity event to NetworkPolicyController.
	c.externalEntityUpdateNotifier.Notify(v1beta2.ExternalEntityReference{
		Name:      curEEName,
		Namespace: curEN.Namespace,
	})
	return nil
}

func (c *ExternalNodeController) deleteExternalNode() error {
	if err := c.deleteInterfaces(); err != nil {
		return err
	}
	c.syncedExternalNode = nil
	// Remove any stale configuration that is related to the deleted ExternalNode
	// and terminate the process if required.
	return c.removeExternalNodeConfig()
}

func (c *ExternalNodeController) deleteInterfaces() error {
	hostIfaces := c.ifaceStore.GetInterfacesByType(interfacestore.ExternalEntityInterface)
	for _, hostIface := range hostIfaces {
		if err := c.deleteInterface(hostIface); err != nil {
			return err
		}
	}
	return nil
}

func (c *ExternalNodeController) deleteInterface(interfaceConfig *interfacestore.InterfaceConfig) error {
	klog.InfoS("Deleting interface", "ifName", interfaceConfig.InterfaceName)
	if err := c.removeOVSPortsAndFlows(interfaceConfig); err != nil {
		return err
	}
	c.ifaceStore.DeleteInterface(interfaceConfig)
	return nil
}

func (c *ExternalNodeController) createOVSPortsAndFlows(uplinkName, hostIFName, eeNamespace, eeName string, ips []string) (*interfacestore.InterfaceConfig, error) {
	iface, addrs, routes, err := getInterfaceConfig(hostIFName)
	if err != nil {
		return nil, err
	}
	adapterConfig := &config.AdapterNetConfig{
		Name:   hostIFName,
		Index:  iface.Index,
		MAC:    iface.HardwareAddr,
		IPs:    addrs,
		Routes: routes,
		MTU:    iface.MTU,
	}
	if err = renameInterface(hostIFName, uplinkName); err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			if err = renameInterface(uplinkName, hostIFName); err != nil {
				klog.ErrorS(err, "Failed to restore uplink name back to host interface name. Manual cleanup is required", "uplinkName", uplinkName, "hostIFName", hostIFName)
			}
		}
	}()

	// Create uplink port in OVS.
	uplinkExternalIDs := map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUplink,
	}
	uplinkUUID, ovsErr := c.ovsBridgeClient.CreatePort(uplinkName, uplinkName, uplinkExternalIDs)
	if ovsErr != nil {
		return nil, fmt.Errorf("failed to create uplink port %s in OVS, err %v", uplinkName, ovsErr)
	}
	defer func() {
		if !success {
			if ovsErr = c.ovsBridgeClient.DeletePort(uplinkUUID); ovsErr != nil {
				klog.ErrorS(err, "Failed to delete uplink port. Manual cleanup is required", "portUUID", uplinkUUID, "uplinkName", uplinkName)
			}
		}
	}()
	uplinkOFPort, ovsErr := c.ovsBridgeClient.GetOFPort(uplinkName, false)
	if ovsErr != nil {
		return nil, ovsErr
	}
	klog.InfoS("Added uplink port in OVS", "port", uplinkOFPort, "uplinkName", uplinkName)

	// Create host port in OVS.
	attachInfo := GetOVSAttachInfo(uplinkName, uplinkUUID, eeName, eeNamespace, ips)
	hostIfUUID, ovsErr := c.ovsBridgeClient.CreateInternalPort(hostIFName, 0, adapterConfig.MAC.String(), attachInfo)
	if ovsErr != nil {
		return nil, fmt.Errorf("failed to create OVS internal port for host interface %s, err %v", hostIFName, ovsErr)
	}
	defer func() {
		if !success {
			if ovsErr = c.ovsBridgeClient.DeletePort(hostIfUUID); ovsErr != nil {
				klog.ErrorS(err, "Failed to delete host interface port. Manual cleanup is required", "portUUID", hostIfUUID, "hostIFName", hostIFName)
			}
		}
	}()
	hostOFPort, ovsErr := c.ovsBridgeClient.GetOFPort(hostIFName, false)
	if ovsErr != nil {
		return nil, ovsErr
	}
	klog.InfoS("Created an OVS internal port for host interface", "ofPort", hostOFPort, "interfaceName", hostIFName)
	// Move configurations from the uplink to host port
	if err = c.moveIFConfigurations(adapterConfig, uplinkName, hostIFName); err != nil {
		return nil, err
	}
	klog.InfoS("Moved configurations to the host interface", "hostInterface", hostIFName)
	if err = c.ofClient.InstallVMUplinkFlows(hostIFName, hostOFPort, uplinkOFPort); err != nil {
		return nil, err
	}
	klog.InfoS("Added uplink and host port in OVS and installed openflow entries", "uplink", uplinkName, "hostInterface", hostIFName)
	success = true
	ifIPs := make([]net.IP, 0)
	for _, ip := range ips {
		ifIPs = append(ifIPs, net.ParseIP(ip))
	}
	hostIFConfig := &interfacestore.InterfaceConfig{
		Type:          interfacestore.ExternalEntityInterface,
		InterfaceName: hostIFName,
		IPs:           ifIPs,
		OVSPortConfig: &interfacestore.OVSPortConfig{
			PortUUID: hostIfUUID,
			OFPort:   hostOFPort,
		},
		EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
			EntityName:      eeName,
			EntityNamespace: eeNamespace,
			UplinkPort: &interfacestore.OVSPortConfig{
				PortUUID: uplinkUUID,
				OFPort:   uplinkOFPort,
			},
		},
	}
	return hostIFConfig, nil
}

func GetOVSAttachInfo(uplinkName, uplinkUUID, entityName, entityNamespace string, ips []string) map[string]interface{} {
	attachInfo := map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
	}
	if uplinkName != "" {
		attachInfo[ovsExternalIDUplinkName] = uplinkName
	}
	if uplinkUUID != "" {
		attachInfo[ovsExternalIDUplinkPort] = uplinkUUID
	}
	if entityName != "" {
		attachInfo[ovsExternalIDEntityName] = entityName
	}
	if entityNamespace != "" {
		attachInfo[ovsExternalIDEntityNamespace] = entityNamespace
	}
	if len(ips) != 0 {
		attachInfo[ovsExternalIDIPs] = strings.Join(ips, ipsSplitter)
	}

	return attachInfo
}

func (c *ExternalNodeController) updateOVSPortsData(interfaceConfig *interfacestore.InterfaceConfig, portData *ovsconfig.OVSPortData, eeName string, ips []string) (*interfacestore.InterfaceConfig, error) {
	attachInfo := map[string]interface{}{
		ovsExternalIDUplinkName:               portData.ExternalIDs[ovsExternalIDUplinkName],
		ovsExternalIDUplinkPort:               portData.ExternalIDs[ovsExternalIDUplinkPort],
		ovsExternalIDEntityName:               eeName,
		ovsExternalIDEntityNamespace:          portData.ExternalIDs[ovsExternalIDEntityNamespace],
		ovsExternalIDIPs:                      strings.Join(ips, ipsSplitter),
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
	}
	err := c.ovsBridgeClient.SetPortExternalIDs(interfaceConfig.InterfaceName, attachInfo)
	if err != nil {
		return nil, err
	}
	ifIPs := make([]net.IP, 0)
	for _, ip := range ips {
		ifIPs = append(ifIPs, net.ParseIP(ip))
	}
	iface := &interfacestore.InterfaceConfig{
		InterfaceName: interfaceConfig.InterfaceName,
		Type:          interfacestore.ExternalEntityInterface,
		OVSPortConfig: &interfacestore.OVSPortConfig{
			PortUUID: interfaceConfig.PortUUID,
			OFPort:   interfaceConfig.OFPort,
		},
		EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
			EntityName:      eeName,
			EntityNamespace: interfaceConfig.EntityNamespace,
			UplinkPort: &interfacestore.OVSPortConfig{
				PortUUID: interfaceConfig.UplinkPort.PortUUID,
				OFPort:   interfaceConfig.UplinkPort.OFPort,
			},
		},
		IPs: ifIPs,
	}
	return iface, nil
}

func (c *ExternalNodeController) removeOVSPortsAndFlows(interfaceConfig *interfacestore.InterfaceConfig) error {
	portUUID := interfaceConfig.PortUUID
	portName := interfaceConfig.InterfaceName
	hostIFName := interfaceConfig.InterfaceName
	uplinkIfName := util.GenerateUplinkInterfaceName(portName)

	// This is for issue #5111 (https://github.com/antrea-io/antrea/issues/5111), which may happen if an error occurs
	// when moving the configuration back from host internal interface to uplink. This logic is run in the second
	// try after the error is returned, at this time the host internal interface is already deleted, and the uplink's
	// name is recovered. So the ips and routes in "adapterConfig" are actually read from the uplink and no need to
	// move the configurations back. The issue was seen on VM with RHEL 8.4 on azure cloud.
	if !hostInterfaceExists(uplinkIfName) {
		klog.InfoS("The interface with uplink name did not exist on the host, skipping its recovery", "uplinkIfName", uplinkIfName)
		return nil
	}

	if err := c.ofClient.UninstallVMUplinkFlows(portName); err != nil {
		return fmt.Errorf("failed to uninstall uplink and host port openflow entries, portName %s, err %v", portName, err)
	}
	klog.InfoS("Removed the flows installed to forward packet between uplinkPort and hostPort", "hostInterface", portName)
	uplinkPortID := interfaceConfig.UplinkPort.PortUUID
	iface, addrs, routes, err := getInterfaceConfig(hostIFName)
	if err != nil {
		return err
	}
	adapterConfig := &config.AdapterNetConfig{
		Name:   hostIFName,
		Index:  iface.Index,
		MAC:    iface.HardwareAddr,
		IPs:    addrs,
		Routes: routes,
		MTU:    iface.MTU,
	}
	if ovsErr := c.ovsBridgeClient.DeletePort(portUUID); ovsErr != nil {
		return fmt.Errorf("failed to delete host port %s, err %v", hostIFName, ovsErr)
	}
	klog.InfoS("Deleted host port in OVS", "hostInterface", hostIFName)
	if ovsErr := c.ovsBridgeClient.DeletePort(uplinkPortID); ovsErr != nil {
		return fmt.Errorf("failed to delete uplink port %s, err %v", uplinkIfName, ovsErr)
	}
	klog.InfoS("Deleted uplink port in OVS", "uplinkIfName", uplinkIfName)
	defer func() {
		// Delete host interface from OVS datapath if it exists.
		// This is to resolve an issue that OVS fails to remove the interface from datapath. It might happen because the interface
		// is busy when OVS tries to remove it with the OVSDB interface deletion event.
		if err := c.ovsctlClient.DeleteDPInterface(hostIFName); err != nil {
			klog.ErrorS(err, "Failed to delete host interface from OVS datapath", "interface", hostIFName)
		}
	}()

	// Wait until the host interface created by OVS is removed.
	if err = wait.PollUntilContextTimeout(context.TODO(), 50*time.Millisecond, 2*time.Second, true, func(ctx context.Context) (bool, error) {
		return !hostInterfaceExists(hostIFName), nil
	}); err != nil {
		return fmt.Errorf("failed to wait for host interface %s deletion in 2s, err %v", hostIFName, err)
	}
	// Recover the uplink interface's name.
	if err = renameInterface(uplinkIfName, hostIFName); err != nil {
		return err
	}
	klog.InfoS("Recovered uplink name to the host interface name", "uplinkIfName", uplinkIfName, "hostInterface", hostIFName)
	// Move the IP configurations back to the host interface.
	if err = c.moveIFConfigurations(adapterConfig, "", hostIFName); err != nil {
		return err
	}
	klog.InfoS("Moved back configuration to the host interface", "hostInterface", hostIFName)
	return nil
}

func getHostInterfaceName(iface v1alpha1.NetworkInterface) (string, []string, error) {
	ifName := ""
	ips := sets.New[string]()
	for _, ipStr := range iface.IPs {
		var ipFilter *ip.DualStackIPs
		ifIP := net.ParseIP(ipStr)
		if ifIP.To4() != nil {
			ipFilter = &ip.DualStackIPs{IPv4: ifIP}
		} else {
			ipFilter = &ip.DualStackIPs{IPv6: ifIP}
		}
		_, _, link, err := getIPNetDeviceFromIP(ipFilter, sets.New[string]())
		if err == nil {
			klog.InfoS("Using the interface", "linkName", link.Name, "IP", ipStr)
			ips.Insert(ipStr)
			if ifName == "" {
				ifName = link.Name
			} else if ifName != link.Name {
				return "", sets.List(ips), fmt.Errorf("find different interfaces by IPs, ifName %s, linkName %s", ifName, link.Name)
			}
		} else {
			klog.ErrorS(err, "Failed to get device from IP", "ip", ifIP)
		}
	}
	if ifName == "" {
		return "", sets.List(ips), fmt.Errorf("cannot find interface via IPs %v", iface.IPs)
	}
	return ifName, sets.List(ips), nil
}

func ParseHostInterfaceConfig(ovsBridgeClient ovsconfig.OVSBridgeClient, portData *ovsconfig.OVSPortData, portConfig *interfacestore.OVSPortConfig) (*interfacestore.InterfaceConfig, error) {
	interfaceConfig := &interfacestore.InterfaceConfig{
		InterfaceName: portData.Name,
		Type:          interfacestore.ExternalEntityInterface,
		OVSPortConfig: portConfig,
	}
	var hostUplinkConfig *interfacestore.EntityInterfaceConfig
	entityIPArr := strings.Split(portData.ExternalIDs[ovsExternalIDIPs], ipsSplitter)
	var entityIPs []net.IP
	for _, ipStr := range entityIPArr {
		entityIPs = append(entityIPs, net.ParseIP(ipStr))
	}
	interfaceConfig.IPs = entityIPs
	uplinkName, _ := portData.ExternalIDs[ovsExternalIDUplinkName]
	uplinkPortUUID, _ := portData.ExternalIDs[ovsExternalIDUplinkPort]
	uplinkPortData, ovsErr := ovsBridgeClient.GetPortData(uplinkPortUUID, uplinkName)
	if ovsErr != nil {
		return nil, ovsErr
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
	}
	interfaceConfig.EntityInterfaceConfig = hostUplinkConfig
	return interfaceConfig, nil
}

func parseProtocol(protocol string) binding.Protocol {
	var proto binding.Protocol
	switch protocol {
	case "tcp":
		proto = binding.ProtocolTCP
	case "udp":
		proto = binding.ProtocolUDP
	case "icmp":
		proto = binding.ProtocolICMP
	case "ip":
		proto = binding.ProtocolIP
	}
	return proto
}
