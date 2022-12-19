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

package multicluster

import (
	"fmt"
	"net"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcclientset "antrea.io/antrea/multicluster/pkg/client/clientset/versioned"
	mcinformers "antrea.io/antrea/multicluster/pkg/client/informers/externalversions/multicluster/v1alpha1"
	mclisters "antrea.io/antrea/multicluster/pkg/client/listers/multicluster/v1alpha1"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

const (
	controllerName = "AntreaAgentMCRouteController"

	// Set resyncPeriod to 0 to disable resyncing
	resyncPeriod = 0 * time.Second
	// How long to wait before retrying the processing of a resource change
	minRetryDelay = 2 * time.Second
	maxRetryDelay = 120 * time.Second

	// Default number of workers processing a resource change
	defaultWorkers = 1
	workerItemKey  = "key"
)

// MCRouteController watches Gateway and ClusterInfoImport events.
// It is responsible for setting up necessary Openflow entries for multi-cluster
// traffic on a Gateway or a regular Node.
type MCRouteController struct {
	mcClient             mcclientset.Interface
	ovsBridgeClient      ovsconfig.OVSBridgeClient
	ofClient             openflow.Client
	interfaceStore       interfacestore.InterfaceStore
	nodeConfig           *config.NodeConfig
	gwInformer           mcinformers.GatewayInformer
	gwLister             mclisters.GatewayLister
	gwListerSynced       cache.InformerSynced
	ciImportInformer     mcinformers.ClusterInfoImportInformer
	ciImportLister       mclisters.ClusterInfoImportLister
	ciImportListerSynced cache.InformerSynced
	queue                workqueue.RateLimitingInterface
	// installedCIImports is for saving ClusterInfos which have been processed
	// in MCRouteController. Need to use mutex to protect 'installedCIImports' if
	// we change the number of 'defaultWorkers'.
	installedCIImports map[string]*mcv1alpha1.ClusterInfoImport
	// Need to use mutex to protect 'installedActiveGW' if we change
	// the number of 'defaultWorkers' to run multiple go routines to handle
	// events.
	installedActiveGW *mcv1alpha1.Gateway
	// The Namespace where Antrea Multi-cluster Controller is running.
	namespace                    string
	enableStretchedNetworkPolicy bool
}

func NewMCRouteController(
	mcClient mcclientset.Interface,
	gwInformer mcinformers.GatewayInformer,
	ciImportInformer mcinformers.ClusterInfoImportInformer,
	client openflow.Client,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	interfaceStore interfacestore.InterfaceStore,
	nodeConfig *config.NodeConfig,
	namespace string,
	enableStretchedNetworkPolicy bool,
) *MCRouteController {
	controller := &MCRouteController{
		mcClient:                     mcClient,
		ovsBridgeClient:              ovsBridgeClient,
		ofClient:                     client,
		interfaceStore:               interfaceStore,
		nodeConfig:                   nodeConfig,
		gwInformer:                   gwInformer,
		gwLister:                     gwInformer.Lister(),
		gwListerSynced:               gwInformer.Informer().HasSynced,
		ciImportInformer:             ciImportInformer,
		ciImportLister:               ciImportInformer.Lister(),
		ciImportListerSynced:         ciImportInformer.Informer().HasSynced,
		queue:                        workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "gatewayroute"),
		installedCIImports:           make(map[string]*mcv1alpha1.ClusterInfoImport),
		namespace:                    namespace,
		enableStretchedNetworkPolicy: enableStretchedNetworkPolicy,
	}
	controller.gwInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(cur interface{}) {
				controller.enqueueGateway(cur, false)
			},
			UpdateFunc: func(old, cur interface{}) {
				controller.enqueueGateway(cur, false)
			},
			DeleteFunc: func(old interface{}) {
				controller.enqueueGateway(old, true)
			},
		},
		resyncPeriod,
	)
	controller.ciImportInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(cur interface{}) {
				controller.enqueueClusterInfoImport(cur, false)
			},
			UpdateFunc: func(old, cur interface{}) {
				controller.enqueueClusterInfoImport(cur, false)
			},
			DeleteFunc: func(old interface{}) {
				controller.enqueueClusterInfoImport(old, true)
			},
		},
		resyncPeriod,
	)
	return controller
}

func (c *MCRouteController) enqueueGateway(obj interface{}, isDelete bool) {
	gw, isGW := obj.(*mcv1alpha1.Gateway)
	if !isGW {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(nil, "Received unexpected object", "object", obj)
			return
		}
		gw, ok = deletedState.Obj.(*mcv1alpha1.Gateway)
		if !ok {
			klog.ErrorS(nil, "DeletedFinalStateUnknown contains non-Gateway object", "object", deletedState.Obj)
			return
		}
	}

	if gw.Namespace != c.namespace {
		return
	}

	if !isDelete {
		if net.ParseIP(gw.InternalIP) == nil || net.ParseIP(gw.GatewayIP) == nil {
			klog.ErrorS(nil, "No valid Internal IP or Gateway IP is found in Gateway", "gateway", gw.Namespace+"/"+gw.Name)
			return
		}
	}
	c.queue.Add(workerItemKey)
}

func (c *MCRouteController) enqueueClusterInfoImport(obj interface{}, isDelete bool) {
	ciImp, isciImp := obj.(*mcv1alpha1.ClusterInfoImport)
	if !isciImp {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(nil, "Received unexpected object", "object", obj)
			return
		}
		ciImp, ok = deletedState.Obj.(*mcv1alpha1.ClusterInfoImport)
		if !ok {
			klog.ErrorS(nil, "DeletedFinalStateUnknown contains non-ClusterInfoImport object", "object", deletedState.Obj)
			return
		}
	}

	if ciImp.Namespace != c.namespace {
		return
	}

	if !isDelete {
		if len(ciImp.Spec.GatewayInfos) == 0 {
			klog.ErrorS(nil, "Received invalid ClusterInfoImport", "object", obj)
			return
		}
		if net.ParseIP(ciImp.Spec.GatewayInfos[0].GatewayIP) == nil {
			klog.ErrorS(nil, "Received ClusterInfoImport with invalid Gateway IP", "object", obj)
			return
		}
	}

	c.queue.Add(workerItemKey)
}

// Run will create defaultWorkers workers (go routines) which will process
// the Gateway events from the workqueue.
func (c *MCRouteController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()
	cacheSyncs := []cache.InformerSynced{c.gwListerSynced, c.ciImportListerSynced}
	klog.InfoS("Starting controller", "controller", controllerName)
	defer klog.InfoS("Shutting down controller", "controller", controllerName)
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSyncs...) {
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

// worker is a long-running function that will continually call the processNextWorkItem
// function in order to read and process a message on the workqueue.
func (c *MCRouteController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *MCRouteController) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)

	if k, ok := obj.(string); !ok {
		c.queue.Forget(obj)
		klog.InfoS("Expected string in work queue but got", "object", obj)
		return true
	} else if err := c.syncMCFlows(); err == nil {
		c.queue.Forget(k)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		c.queue.AddRateLimited(k)
		klog.ErrorS(err, "Error syncing key, requeuing", "key", k)
	}
	return true
}

func (c *MCRouteController) syncMCFlows() error {
	startTime := time.Now()
	defer func() {
		klog.V(4).InfoS("Finished syncing flows for Multi-cluster", "time", time.Since(startTime))
	}()
	activeGW, err := c.getActiveGateway()
	if err != nil {
		return err
	}
	if activeGW == nil && c.installedActiveGW == nil {
		klog.V(2).InfoS("No active Gateway is found")
		return nil
	}

	klog.V(2).InfoS("Installed Gateway", "gateway", klog.KObj(c.installedActiveGW))
	if activeGW != nil && c.installedActiveGW != nil && activeGW.Name == c.installedActiveGW.Name {
		// Active Gateway name doesn't change but still do a full flow sync
		// for any Gateway Spec or ClusterInfoImport changes.
		if err := c.syncMCFlowsForAllCIImps(activeGW); err != nil {
			return err
		}
		c.installedActiveGW = activeGW
		return nil
	}

	if c.installedActiveGW != nil {
		if err := c.deleteMCFlowsForAllCIImps(); err != nil {
			return err
		}
		klog.V(2).InfoS("Deleted flows for installed Gateway", "gateway", klog.KObj(c.installedActiveGW))
		c.installedActiveGW = nil
	}

	if activeGW != nil {
		if err := c.ofClient.InstallMulticlusterClassifierFlows(config.DefaultTunOFPort, activeGW.Name == c.nodeConfig.Name); err != nil {
			return err
		}
		c.installedActiveGW = activeGW
		return c.addMCFlowsForAllCIImps(activeGW)
	}
	return nil
}

func (c *MCRouteController) syncMCFlowsForAllCIImps(activeGW *mcv1alpha1.Gateway) error {
	desiredCIImports, err := c.ciImportLister.ClusterInfoImports(c.namespace).List(labels.Everything())
	if err != nil {
		return err
	}

	activeGWChanged := c.checkGateWayIPChange(activeGW)
	installedCIImportNames := sets.StringKeySet(c.installedCIImports)
	for _, ciImp := range desiredCIImports {
		if err = c.addMCFlowsForSingleCIImp(activeGW, ciImp, c.installedCIImports[ciImp.Name], activeGWChanged); err != nil {
			return err
		}
		installedCIImportNames.Delete(ciImp.Name)
	}

	for name := range installedCIImportNames {
		if err := c.deleteMCFlowsForSingleCIImp(name); err != nil {
			return err
		}
	}
	return nil
}

func (c *MCRouteController) checkGateWayIPChange(activeGW *mcv1alpha1.Gateway) bool {
	var activeGWChanged bool
	if activeGW.Name == c.nodeConfig.Name {
		// On a Gateway Node, the GatewayIP of the active Gateway will impact the Openflow rules.
		activeGWChanged = activeGW.GatewayIP != c.installedActiveGW.GatewayIP
	} else {
		// On a regular Node, the InternalIP of the active Gateway will impact the Openflow rules.
		activeGWChanged = activeGW.InternalIP != c.installedActiveGW.InternalIP
	}
	return activeGWChanged
}

func (c *MCRouteController) addMCFlowsForAllCIImps(activeGW *mcv1alpha1.Gateway) error {
	allCIImports, err := c.ciImportLister.ClusterInfoImports(c.namespace).List(labels.Everything())
	if err != nil {
		return err
	}
	if len(allCIImports) == 0 {
		klog.V(2).InfoS("No remote ClusterInfo imported, do nothing")
		return nil
	}
	for _, ciImport := range allCIImports {
		if err := c.addMCFlowsForSingleCIImp(activeGW, ciImport, nil, true); err != nil {
			return err
		}
	}

	return nil
}

func (c *MCRouteController) addMCFlowsForSingleCIImp(activeGW *mcv1alpha1.Gateway, ciImport *mcv1alpha1.ClusterInfoImport,
	installedCIImp *mcv1alpha1.ClusterInfoImport, activeGWChanged bool) error {
	tunnelPeerIPToRemoteGW := getPeerGatewayIP(ciImport.Spec)
	if tunnelPeerIPToRemoteGW == nil {
		klog.ErrorS(nil, "The ClusterInfoImport has no valid Gateway IP, skip it", "clusterinfoimport", klog.KObj(ciImport))
		return nil
	}

	var ciImportNoChange bool
	if installedCIImp != nil {
		oldTunnelPeerIPToRemoteGW := getPeerGatewayIP(installedCIImp.Spec)
		ciImportNoChange = oldTunnelPeerIPToRemoteGW.Equal(tunnelPeerIPToRemoteGW) && installedCIImp.Spec.ServiceCIDR == ciImport.Spec.ServiceCIDR &&
			sets.NewString(installedCIImp.Spec.PodCIDRs...).Equal(sets.NewString(ciImport.Spec.PodCIDRs...))
	}

	if ciImportNoChange && !activeGWChanged {
		klog.V(2).InfoS("ClusterInfoImport and the active Gateway have no change, skip updating", "clusterinfoimport", klog.KObj(ciImport), "gateway", klog.KObj(activeGW))
		return nil
	}

	klog.InfoS("Adding/updating remote Gateway Node flows for Multi-cluster", "gateway", klog.KObj(activeGW),
		"node", c.nodeConfig.Name, "peer", tunnelPeerIPToRemoteGW)
	allCIDRs := append([]string{ciImport.Spec.ServiceCIDR}, ciImport.Spec.PodCIDRs...)
	peerConfigs, err := generatePeerConfigs(allCIDRs, tunnelPeerIPToRemoteGW)
	if err != nil {
		klog.ErrorS(err, "Parse error for serviceCIDR from remote cluster", "clusterinfoimport", ciImport.Name, "gateway", activeGW.Name)
		return err
	}
	if activeGW.Name == c.nodeConfig.Name {
		klog.V(2).InfoS("Adding/updating flows to remote Gateway Node for Multi-cluster traffic", "clusterinfoimport", ciImport.Name, "cidrs", allCIDRs)
		localGatewayIP := net.ParseIP(activeGW.GatewayIP)
		if err := c.ofClient.InstallMulticlusterGatewayFlows(
			ciImport.Name,
			peerConfigs,
			tunnelPeerIPToRemoteGW,
			localGatewayIP,
			c.enableStretchedNetworkPolicy); err != nil {
			return fmt.Errorf("failed to install flows to remote Gateway in ClusterInfoImport %s: %v", ciImport.Name, err)
		}
	} else {
		klog.V(2).InfoS("Adding/updating flows to the local active Gateway for Multi-cluster traffic", "clusterinfoimport", ciImport.Name, "cidrs", allCIDRs)
		tunnelPeerIPToLocalGW := net.ParseIP(activeGW.InternalIP)
		if err := c.ofClient.InstallMulticlusterNodeFlows(
			ciImport.Name,
			peerConfigs,
			tunnelPeerIPToLocalGW,
			c.enableStretchedNetworkPolicy); err != nil {
			return fmt.Errorf("failed to install flows to Gateway %s: %v", activeGW.Name, err)
		}
	}

	c.installedCIImports[ciImport.Name] = ciImport
	return nil
}

func (c *MCRouteController) deleteMCFlowsForSingleCIImp(ciImpName string) error {
	if err := c.ofClient.UninstallMulticlusterFlows(ciImpName); err != nil {
		return fmt.Errorf("failed to uninstall multi-cluster flows to remote Gateway Node %s: %v", ciImpName, err)
	}
	delete(c.installedCIImports, ciImpName)
	return nil
}

func (c *MCRouteController) deleteMCFlowsForAllCIImps() error {
	for _, ciImp := range c.installedCIImports {
		c.deleteMCFlowsForSingleCIImp(ciImp.Name)
	}
	return nil
}

// getActiveGateway compares Gateway's CreationTimestamp to get the active Gateway,
// The last created Gateway will be the active Gateway.
func (c *MCRouteController) getActiveGateway() (*mcv1alpha1.Gateway, error) {
	gws, err := c.gwLister.Gateways(c.namespace).List(labels.Everything())
	if err != nil {
		return nil, err
	}
	if len(gws) == 0 {
		return nil, nil
	}
	// Comparing Gateway's CreationTimestamp to get the last created Gateway.
	lastCreatedGW := gws[0]
	for _, gw := range gws {
		if lastCreatedGW.CreationTimestamp.Before(&gw.CreationTimestamp) {
			lastCreatedGW = gw
		}
	}
	if net.ParseIP(lastCreatedGW.GatewayIP) == nil || net.ParseIP(lastCreatedGW.InternalIP) == nil {
		return nil, fmt.Errorf("the last created Gateway %s has no valid GatewayIP or InternalIP", lastCreatedGW.Name)
	}
	return lastCreatedGW, nil
}

func generatePeerConfigs(subnets []string, gatewayIP net.IP) (map[*net.IPNet]net.IP, error) {
	peerConfigs := make(map[*net.IPNet]net.IP, len(subnets))
	for _, subnet := range subnets {
		_, peerCIDR, err := net.ParseCIDR(subnet)
		if err != nil {
			return nil, err
		}
		peerConfigs[peerCIDR] = gatewayIP
	}
	return peerConfigs, nil
}

// getPeerGatewayIP will always return the first Gateway IP.
func getPeerGatewayIP(spec mcv1alpha1.ClusterInfo) net.IP {
	if len(spec.GatewayInfos) == 0 {
		return nil
	}
	return net.ParseIP(spec.GatewayInfos[0].GatewayIP)
}
