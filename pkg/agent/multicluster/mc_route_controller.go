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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	apitypes "k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcclientset "antrea.io/antrea/multicluster/pkg/client/clientset/versioned"
	mcinformersv1alpha1 "antrea.io/antrea/multicluster/pkg/client/informers/externalversions/multicluster/v1alpha1"
	mclisters "antrea.io/antrea/multicluster/pkg/client/listers/multicluster/v1alpha1"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow"
	antrearoute "antrea.io/antrea/pkg/agent/route"
	"antrea.io/antrea/pkg/agent/wireguard"
	"antrea.io/antrea/pkg/config/agent"
)

const (
	controllerName = "MCDefaultRouteController"

	// Set resyncPeriod to 0 to disable resyncing
	resyncPeriod = 0 * time.Second
	// How long to wait before retrying the processing of a resource change
	minRetryDelay = 2 * time.Second
	maxRetryDelay = 120 * time.Second

	workerItemKey = "key"

	multiclusterWireGuardInterface = "antrea-mc-wg0"
	multiclusterWireGuardPublicKey = "publicKey"
)

var (
	wireGuardNewFunc = wireguard.New
)

// MCDefaultRouteController watches Gateway and ClusterInfoImport events.
// It is responsible for setting up necessary Openflow entries for multi-cluster
// traffic on a Gateway or a regular Node.
type MCDefaultRouteController struct {
	mcClient             mcclientset.Interface
	ofClient             openflow.Client
	routeClient          antrearoute.Interface
	wireGuardClient      wireguard.Interface
	nodeConfig           *config.NodeConfig
	networkConfig        *config.NetworkConfig
	wireGuardConfig      *config.WireGuardConfig
	gwInformer           mcinformersv1alpha1.GatewayInformer
	gwLister             mclisters.GatewayLister
	gwListerSynced       cache.InformerSynced
	ciImportInformer     mcinformersv1alpha1.ClusterInfoImportInformer
	ciImportLister       mclisters.ClusterInfoImportLister
	ciImportListerSynced cache.InformerSynced
	queue                workqueue.RateLimitingInterface
	// installedCIImports is for saving ClusterInfos which have been processed
	// in MCDefaultRouteController. Need to use mutex to protect 'installedCIImports' if
	// we change the number of 'defaultWorkers'.
	installedCIImports      map[string]*mcv1alpha1.ClusterInfoImport
	installedWireGuardPeers map[string]*mcv1alpha1.ClusterInfoImport
	// Need to use mutex to protect 'installedActiveGW' if we change to
	// use multiple go routines to handle events
	installedActiveGW *mcv1alpha1.Gateway
	// The Namespace where Antrea Multi-cluster Controller is running.
	namespace                    string
	enableStretchedNetworkPolicy bool
	enablePodToPodConnectivity   bool
	wireGuardInitialized         bool
}

func NewMCDefaultRouteController(
	mcClient mcclientset.Interface,
	gwInformer mcinformersv1alpha1.GatewayInformer,
	ciImportInformer mcinformersv1alpha1.ClusterInfoImportInformer,
	client openflow.Client,
	nodeConfig *config.NodeConfig,
	networkConfig *config.NetworkConfig,
	routeClient antrearoute.Interface,
	multiclusterConfig agent.MulticlusterConfig,
) *MCDefaultRouteController {
	controller := &MCDefaultRouteController{
		mcClient:                     mcClient,
		ofClient:                     client,
		routeClient:                  routeClient,
		nodeConfig:                   nodeConfig,
		networkConfig:                networkConfig,
		gwInformer:                   gwInformer,
		gwLister:                     gwInformer.Lister(),
		gwListerSynced:               gwInformer.Informer().HasSynced,
		ciImportInformer:             ciImportInformer,
		ciImportLister:               ciImportInformer.Lister(),
		ciImportListerSynced:         ciImportInformer.Informer().HasSynced,
		queue:                        workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "gatewayroute"),
		installedCIImports:           make(map[string]*mcv1alpha1.ClusterInfoImport),
		installedWireGuardPeers:      make(map[string]*mcv1alpha1.ClusterInfoImport),
		namespace:                    multiclusterConfig.Namespace,
		enableStretchedNetworkPolicy: multiclusterConfig.EnableStretchedNetworkPolicy,
		enablePodToPodConnectivity:   multiclusterConfig.EnablePodToPodConnectivity,
	}
	_, trafficEncryptionMode := config.GetTrafficEncryptionModeFromStr(multiclusterConfig.TrafficEncryptionMode)
	if trafficEncryptionMode == config.TrafficEncryptionModeWireGuard {
		controller.wireGuardConfig = &config.WireGuardConfig{
			Port: multiclusterConfig.WireGuard.Port,
			Name: multiclusterWireGuardInterface,
			// Regardless of the tunnel type, the WireGuard device must only reduce MTU for encryption because the
			// packets it transmits have been encapsulated.
			MTU: nodeConfig.NodeTransportInterfaceMTU - networkConfig.WireGuardMTUDeduction,
		}
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

func (c *MCDefaultRouteController) enqueueGateway(obj interface{}, isDelete bool) {
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

	if !isDelete {
		if net.ParseIP(gw.InternalIP) == nil || net.ParseIP(gw.GatewayIP) == nil {
			klog.ErrorS(nil, "No valid Internal IP or Gateway IP is found in Gateway", "gateway", gw.Namespace+"/"+gw.Name)
			return
		}
	}
	c.queue.Add(workerItemKey)
}

func (c *MCDefaultRouteController) enqueueClusterInfoImport(obj interface{}, isDelete bool) {
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

// Run will create a worker (go routines) which will process
// the Gateway events from the workqueue.
func (c *MCDefaultRouteController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()
	cacheSyncs := []cache.InformerSynced{c.gwListerSynced, c.ciImportListerSynced}
	klog.InfoS("Starting controller", "controller", controllerName)
	defer klog.InfoS("Shutting down controller", "controller", controllerName)
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSyncs...) {
		return
	}

	go wait.Until(c.worker, time.Second, stopCh)
	<-stopCh
}

// worker is a long-running function that will continually call the processNextWorkItem
// function in order to read and process a message on the workqueue.
func (c *MCDefaultRouteController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *MCDefaultRouteController) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)

	key, ok := obj.(string)
	if !ok {
		c.queue.Forget(obj)
		klog.InfoS("Expected string in work queue but got", "object", obj)
		return true
	}

	syncFn := func() error {
		if c.wireGuardConfig != nil {
			if err := c.syncWireGuard(); err != nil {
				return err
			}
		}
		return c.syncMCFlows()
	}
	if err := syncFn(); err == nil {
		c.queue.Forget(key)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Error syncing key, requeuing", "key", key)
	}
	return true
}

// syncWireGuard reconciles WireGuard configurations in following way:
//  1. If the current Node is the Multi-cluster Gateway Node, controller will try to initialize corresponding WireGuard
//     configuration and route on the host, then add all existing Gateway Nodes in other member clusters as WireGuard peers.
//  2. If the current Node is not Multi-cluster Gateway Node, controller will try to clean up WireGuard configurations.
//
// Note: MCDefaultRouteController runs only one worker to process Gateway and ClusterInfoImport. So we do not need
// any synchronization mechanism.
func (c *MCDefaultRouteController) syncWireGuard() error {
	gateway, err := c.getActiveGateway()
	if err != nil {
		return err
	}

	amIGateway := gateway != nil && gateway.Name == c.nodeConfig.Name
	if c.wireGuardClient != nil && (!amIGateway || !c.wireGuardInitialized) {
		if err := c.cleanUpWireGuard(); err != nil {
			return err
		}
		c.wireGuardInitialized = false
	}
	if !amIGateway {
		return nil
	}
	if !c.wireGuardInitialized {
		if initErr := c.initializeWireGuard(gateway); initErr != nil {
			if err := c.cleanUpWireGuard(); err != nil {
				klog.ErrorS(err, "Failed to clean up WireGuard")
			}
			return initErr
		}
		c.wireGuardInitialized = true
	}
	ciImports, err := c.ciImportLister.List(labels.Everything())
	if err != nil {
		return err
	}

	desiredCIImports := sets.New[string]()
	var updateErr []error
	for _, ciImport := range ciImports {
		desiredCIImports.Insert(ciImport.Name)
		if ciImportCache, ok := c.installedWireGuardPeers[ciImport.Name]; ok && !isWireGuardInfoChanged(ciImportCache, ciImport) {
			klog.V(2).InfoS("The ClusterInfoImport did not change, skip updating WireGuard peer", "ClusterInfoImport", klog.KObj(ciImport))
		}
		if err = c.addWireGuardRouteAndPeer(ciImport); err != nil {
			klog.ErrorS(err, "Failed to update WireGuard peer", "ClusterInfoImport", klog.KObj(ciImport))
			updateErr = append(updateErr, err)
		}
		c.installedWireGuardPeers[ciImport.Name] = ciImport
	}
	if len(updateErr) > 0 {
		return utilerrors.NewAggregate(updateErr)
	}

	// Check cache and existing ClusterInfoImports, clean up routes and WireGuard peers of the
	// removed ClusterInfoImports.
	for ciName, ciImport := range c.installedWireGuardPeers {
		if desiredCIImports.Has(ciName) {
			continue
		}
		if err := c.removeWireGuardRouteAndPeer(ciImport); err != nil {
			return err
		}
		delete(c.installedWireGuardPeers, ciName)
	}

	return nil
}

func (c *MCDefaultRouteController) removeWireGuardRouteAndPeer(ciImport *mcv1alpha1.ClusterInfoImport) error {
	remoteGatewayIP, _, _ := net.ParseCIDR(ciImport.Spec.ServiceCIDR)
	dstCIDR := net.IPNet{IP: remoteGatewayIP, Mask: net.CIDRMask(32, 32)}
	if err := c.routeClient.DeleteRouteForLink(&dstCIDR, c.wireGuardConfig.LinkIndex); err != nil {
		return err
	}
	return c.wireGuardClient.DeletePeer(ciImport.Name)
}

// addWireGuardRouteAndPeer tries to update a WireGuard peer with ClusterInfoImport. If updating successfully,
// it will also create host route to WireGuard peer.
func (c *MCDefaultRouteController) addWireGuardRouteAndPeer(ciImport *mcv1alpha1.ClusterInfoImport) error {
	if ciImport.Spec.WireGuard == nil || ciImport.Spec.WireGuard.PublicKey == "" {
		klog.V(2).InfoS("ClusterInfoImport's WireGuard field has not been initialized, skip it", "ClusterInfoImport", klog.KObj(ciImport))
		return nil
	}

	klog.V(2).InfoS("Updating WireGuard peer with ClusterInfoImport", "ClusterInfoImport", klog.KObj(ciImport))
	// The cross-cluster traffic will be both encapsulated and encrypted. To avoid routing loop, we use a tunnel endpoint
	// IP different from the WireGuard endpoint IP. Since the ServiceCIDR is guaranteed to be unique across member clusters,
	// we choose the ServiceCIDR's network address as the tunnel endpoint IP. For instance, if a cluster's ServiceCIDR is
	// 10.96.0.0/16, 10.96.0.0 will be used as the tunnel endpoint IP of the cluster's Gateway Node.
	remoteWireGuardIP, _, err := net.ParseCIDR(ciImport.Spec.ServiceCIDR)
	if err != nil {
		return err
	}
	remoteWireGuardNet := &net.IPNet{IP: remoteWireGuardIP, Mask: net.CIDRMask(32, 32)}

	gatewayIP := net.ParseIP(ciImport.Spec.GatewayInfos[0].GatewayIP)
	allowedIPs := []*net.IPNet{remoteWireGuardNet}
	if err := c.wireGuardClient.UpdatePeer(ciImport.Name, ciImport.Spec.WireGuard.PublicKey, gatewayIP, allowedIPs); err != nil {
		return err
	}

	klog.V(2).InfoS("Adding route on the host", "CIDR", remoteWireGuardNet, "device", c.wireGuardConfig.Name)
	return c.routeClient.AddRouteForLink(remoteWireGuardNet, c.wireGuardConfig.LinkIndex)
}

// initializeWireGuard initializes the WireGuard interface and client.
// It will also update Gateway's WireGuard field.
func (c *MCDefaultRouteController) initializeWireGuard(gateway *mcv1alpha1.Gateway) error {
	wgClient, err := wireGuardNewFunc(c.nodeConfig, c.wireGuardConfig)
	if err != nil {
		return err
	}
	c.wireGuardClient = wgClient

	wireGuardInterfaceIP, _, err := net.ParseCIDR(gateway.ServiceCIDR)
	if err != nil {
		return err
	}
	publicKey, err := c.wireGuardClient.Init(wireGuardInterfaceIP, nil)
	if err != nil {
		return err
	}

	patch, _ := json.Marshal(map[string]interface{}{
		"wireGuard": map[string]interface{}{
			multiclusterWireGuardPublicKey: publicKey,
		},
	})
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		_, err := c.mcClient.MulticlusterV1alpha1().Gateways(c.namespace).Patch(context.TODO(), c.nodeConfig.Name, apitypes.MergePatchType, patch,
			metav1.PatchOptions{})
		return err
	}); err != nil {
		return fmt.Errorf("error when patching the Gateway with WireGuard information, error: %s", err)
	}

	return nil
}

// cleanUpWireGuard deletes the WireGuard interface on the host.
// The WireGuard route will also be deleted automatically when the interface is deleted.
func (c *MCDefaultRouteController) cleanUpWireGuard() error {
	if err := c.wireGuardClient.CleanUp(); err != nil {
		return err
	}
	c.wireGuardClient = nil
	return nil
}

func (c *MCDefaultRouteController) syncMCFlows() error {
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

func (c *MCDefaultRouteController) syncMCFlowsForAllCIImps(activeGW *mcv1alpha1.Gateway) error {
	desiredCIImports, err := c.ciImportLister.List(labels.Everything())
	if err != nil {
		return err
	}

	activeGWChanged := c.checkGatewayIPChange(activeGW)
	installedCIImportNames := sets.KeySet(c.installedCIImports)
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

func (c *MCDefaultRouteController) checkGatewayIPChange(activeGW *mcv1alpha1.Gateway) bool {
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

func (c *MCDefaultRouteController) addMCFlowsForAllCIImps(activeGW *mcv1alpha1.Gateway) error {
	allCIImports, err := c.ciImportLister.List(labels.Everything())
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

func (c *MCDefaultRouteController) addMCFlowsForSingleCIImp(activeGW *mcv1alpha1.Gateway, ciImport *mcv1alpha1.ClusterInfoImport,
	installedCIImp *mcv1alpha1.ClusterInfoImport, activeGWChanged bool) error {
	tunnelPeerIPToRemoteGW := getPeerGatewayTunnelIP(ciImport.Spec, c.wireGuardConfig != nil)
	if tunnelPeerIPToRemoteGW == nil {
		klog.ErrorS(nil, "The ClusterInfoImport has no valid Gateway IP, skip it", "clusterinfoimport", klog.KObj(ciImport))
		return nil
	}

	var ciImportNoChange bool
	if installedCIImp != nil {
		oldTunnelPeerIPToRemoteGW := getPeerGatewayTunnelIP(installedCIImp.Spec, c.wireGuardConfig != nil)
		ciImportNoChange = oldTunnelPeerIPToRemoteGW.Equal(tunnelPeerIPToRemoteGW) && installedCIImp.Spec.ServiceCIDR == ciImport.Spec.ServiceCIDR
		if c.enablePodToPodConnectivity {
			ciImportNoChange = ciImportNoChange && sets.New[string](installedCIImp.Spec.PodCIDRs...).Equal(sets.New[string](ciImport.Spec.PodCIDRs...))
		}
	}

	if ciImportNoChange && !activeGWChanged {
		klog.V(2).InfoS("ClusterInfoImport and the active Gateway have no change, skip updating", "clusterinfoimport", klog.KObj(ciImport), "gateway", klog.KObj(activeGW))
		return nil
	}

	klog.InfoS("Adding/updating remote Gateway Node flows for Multi-cluster", "gateway", klog.KObj(activeGW),
		"node", c.nodeConfig.Name, "peer", tunnelPeerIPToRemoteGW)
	allCIDRs := []string{ciImport.Spec.ServiceCIDR}
	if c.enablePodToPodConnectivity {
		allCIDRs = append(allCIDRs, ciImport.Spec.PodCIDRs...)
	}
	peerConfigs, err := generatePeerConfigs(allCIDRs, tunnelPeerIPToRemoteGW)
	if err != nil {
		klog.ErrorS(err, "Parse error for serviceCIDR from remote cluster", "clusterinfoimport", ciImport.Name, "gateway", activeGW.Name)
		return err
	}
	if activeGW.Name == c.nodeConfig.Name {
		klog.V(2).InfoS("Adding/updating flows to remote Gateway Node for Multi-cluster traffic", "clusterinfoimport", ciImport.Name, "cidrs", allCIDRs)
		localGatewayIP := getLocalGatewayIP(activeGW, c.wireGuardConfig != nil)
		if localGatewayIP == nil {
			klog.V(2).InfoS("Local Gateway IP has not been allocated, skip", "gateway", klog.KObj(activeGW))
			return nil
		}
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

func (c *MCDefaultRouteController) deleteMCFlowsForSingleCIImp(ciImpName string) error {
	if err := c.ofClient.UninstallMulticlusterFlows(ciImpName); err != nil {
		return fmt.Errorf("failed to uninstall multi-cluster flows to remote Gateway Node %s: %v", ciImpName, err)
	}
	delete(c.installedCIImports, ciImpName)
	return nil
}

func (c *MCDefaultRouteController) deleteMCFlowsForAllCIImps() error {
	for _, ciImp := range c.installedCIImports {
		c.deleteMCFlowsForSingleCIImp(ciImp.Name)
	}
	return nil
}

func (c *MCDefaultRouteController) getActiveGateway() (*mcv1alpha1.Gateway, error) {
	activeGW, err := getActiveGateway(c.gwLister)
	if err != nil {
		return nil, err
	}
	if activeGW == nil {
		return nil, nil
	}
	if net.ParseIP(activeGW.GatewayIP) == nil || net.ParseIP(activeGW.InternalIP) == nil {
		return nil, fmt.Errorf("the active Gateway %s has no valid GatewayIP or InternalIP", activeGW.Name)
	}
	return activeGW, nil
}

func getActiveGateway(gwLister mclisters.GatewayLister) (*mcv1alpha1.Gateway, error) {
	gws, err := gwLister.List(labels.Everything())
	if err != nil {
		return nil, err
	}
	if len(gws) == 0 {
		return nil, nil
	}
	// The Gateway webhook guarantees there will be at most one Gateway in a cluster.
	return gws[0], nil
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

// If WireGuard is disabled, getPeerGatewayTunnelIP will return Gateway's GatewayIP.
// If WireGuard is enabled, the WireGuard interfaces use the first IP address of ServiceCIDR
// as its IP address. So getPeerGatewayTunnelIP will return the first IP of the ServiceCIDR
// as the remote Gateway tunnel IP.
func getPeerGatewayTunnelIP(spec mcv1alpha1.ClusterInfo, enableWireGuard bool) net.IP {
	if enableWireGuard {
		if spec.ServiceCIDR == "" {
			klog.InfoS("The ServiceCIDR of the peer cluster has not been updated, skip it", "clusterID", spec.ClusterID)
			return nil
		}
		_, serviceCIDR, _ := net.ParseCIDR(spec.ServiceCIDR)
		return serviceCIDR.IP
	}
	if len(spec.GatewayInfos) == 0 {
		return nil
	}
	return net.ParseIP(spec.GatewayInfos[0].GatewayIP)
}

func getLocalGatewayIP(gateway *mcv1alpha1.Gateway, enableWireGuard bool) net.IP {
	if enableWireGuard {
		if gateway.ServiceCIDR == "" {
			klog.InfoS("The ServiceCIDR of the Gateway has not been updated, skip it", "Gateway", klog.KObj(gateway))
			return nil
		}
		localGatewayIP, _, _ := net.ParseCIDR(gateway.ServiceCIDR)
		return localGatewayIP
	}
	return net.ParseIP(gateway.GatewayIP)
}

// isWireGuardInfoChanged checks the information in ClusterInfoImport needed by WireGuard change or not.
func isWireGuardInfoChanged(cache, cur *mcv1alpha1.ClusterInfoImport) bool {
	if cache.Spec.ServiceCIDR != cur.Spec.ServiceCIDR {
		return true
	}
	if cache.Spec.WireGuard == nil && cur.Spec.WireGuard == nil {
		return false
	}
	if cache.Spec.WireGuard == nil || cur.Spec.WireGuard == nil {
		return true
	}
	return cache.Spec.WireGuard.PublicKey != cur.Spec.WireGuard.PublicKey
}
