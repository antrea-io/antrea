// Copyright 2024 Antrea Authors
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

package bgp

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	discoveryinformers "k8s.io/client-go/informers/discovery/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"k8s.io/utils/net"
	"k8s.io/utils/strings/slices"

	"antrea.io/antrea/pkg/agent/bgp"
	"antrea.io/antrea/pkg/agent/bgp/gobgp"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	crdinformersv1a1 "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdinformersv1b1 "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1beta1"
	crdlistersv1a1 "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	crdlistersv1b1 "antrea.io/antrea/pkg/client/listers/crd/v1beta1"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/util/env"
	utilipset "antrea.io/antrea/pkg/util/sets"
)

const (
	controllerName = "BGPPolicyController"
	// How long to wait before retrying the processing of a BGPPolicy change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing a BGPPolicy change.
	defaultWorkers = 4
	// Disable resyncing.
	resyncPeriod time.Duration = 0
)

const (
	bgpRouteIDAnnotation = "antrea.io/bgp-route-id"

	defaultBGPListenPort int32 = 179
)

const (
	ipv4Suffix = "/32"
	ipv6Suffix = "/128"
)

var (
	protocolIPv4 = net.IPv4
	protocolIPv6 = net.IPv6

	newBGPServerFn = func(globalConfig *bgp.GlobalConfig) bgp.Interface {
		return gobgp.NewGoBGPServer(globalConfig)
	}
)

type nodeToBGPPolicyBinding struct {
	effectiveBP    string
	alternativeBPs sets.Set[string]
}

type bgpPolicyState struct {
	// The local BGP server created for the BGPPolicy.
	bgpServer bgp.Interface
	// The port on which local the BGP server listens.
	listenPort int32
	// The AS number used by the local BGP server.
	localASN int32
	// The router ID used by the local BGP server.
	routerID string
	// Routes to be advertised to BGP peers.
	routes sets.Set[bgp.Route]
	// peers maps IP families to concatenated strings of BGP peer IP addresses and ASNs.
	// Example: "192.168.77.100-65000", "2001::1-65000".
	peerKeys sets.Set[string]
	// peerConfigs maps concatenated string of BGP peer IP addresses and ASN to the configuration of the peer.
	peerConfigs map[string]bgp.PeerConfig
}

type Controller struct {
	ctx context.Context

	nodeInformer     cache.SharedIndexInformer
	nodeLister       corelisters.NodeLister
	nodeListerSynced cache.InformerSynced

	serviceInformer     cache.SharedIndexInformer
	serviceLister       corelisters.ServiceLister
	serviceListerSynced cache.InformerSynced

	egressInformer     cache.SharedIndexInformer
	egressLister       crdlistersv1b1.EgressLister
	egressListerSynced cache.InformerSynced

	bgpPolicyInformer     cache.SharedIndexInformer
	bgpPolicyLister       crdlistersv1a1.BGPPolicyLister
	bgpPolicyListerSynced cache.InformerSynced

	endpointSliceLister       discoverylisters.EndpointSliceLister
	endpointSliceListerSynced cache.InformerSynced

	bgpPolicyBinding      *nodeToBGPPolicyBinding
	bgpPolicyBindingMutex sync.RWMutex

	bgpPolicyStates      map[string]*bgpPolicyState
	bgpPolicyStatesMutex sync.RWMutex

	k8sClient              kubernetes.Interface
	bgpPeerPasswordsSecret string
	bgpPeerPasswords       map[string]string
	bgpPeerPasswordsMutex  sync.RWMutex

	nodeName     string
	enabledIPv4  bool
	enabledIPv6  bool
	podIPv4CIDR  string
	podIPv6CIDR  string
	nodeIPv4Addr string
	ipProtocols  []net.IPFamily

	egressEnabled bool

	queue workqueue.RateLimitingInterface
}

func NewBGPPolicyController(ctx context.Context,
	nodeInformer coreinformers.NodeInformer,
	serviceInformer coreinformers.ServiceInformer,
	egressInformer crdinformersv1b1.EgressInformer,
	bgpPolicyInformer crdinformersv1a1.BGPPolicyInformer,
	endpointSliceInformer discoveryinformers.EndpointSliceInformer,
	k8sClient kubernetes.Interface,
	bgpPeerPasswordsSecret string,
	nodeConfig *config.NodeConfig,
	networkConfig *config.NetworkConfig) (*Controller, error) {
	c := &Controller{
		ctx:                       ctx,
		nodeInformer:              nodeInformer.Informer(),
		nodeLister:                nodeInformer.Lister(),
		nodeListerSynced:          nodeInformer.Informer().HasSynced,
		serviceInformer:           serviceInformer.Informer(),
		serviceLister:             serviceInformer.Lister(),
		serviceListerSynced:       serviceInformer.Informer().HasSynced,
		egressInformer:            egressInformer.Informer(),
		egressLister:              egressInformer.Lister(),
		egressListerSynced:        egressInformer.Informer().HasSynced,
		bgpPolicyInformer:         bgpPolicyInformer.Informer(),
		bgpPolicyLister:           bgpPolicyInformer.Lister(),
		bgpPolicyListerSynced:     bgpPolicyInformer.Informer().HasSynced,
		endpointSliceLister:       endpointSliceInformer.Lister(),
		endpointSliceListerSynced: endpointSliceInformer.Informer().HasSynced,
		bgpPolicyBinding:          &nodeToBGPPolicyBinding{alternativeBPs: sets.Set[string]{}},
		bgpPolicyStates:           make(map[string]*bgpPolicyState),
		k8sClient:                 k8sClient,
		bgpPeerPasswordsSecret:    bgpPeerPasswordsSecret,
		bgpPeerPasswords:          make(map[string]string),
		nodeName:                  nodeConfig.Name,
		enabledIPv4:               networkConfig.IPv4Enabled,
		enabledIPv6:               networkConfig.IPv6Enabled,
		podIPv4CIDR:               nodeConfig.PodIPv4CIDR.String(),
		podIPv6CIDR:               nodeConfig.PodIPv6CIDR.String(),
		nodeIPv4Addr:              nodeConfig.NodeIPv4Addr.IP.String(),
		egressEnabled:             features.DefaultFeatureGate.Enabled(features.Egress),
		queue:                     workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "bgpPolicyGroup"),
	}
	c.bgpPolicyInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addBGPPolicy,
			UpdateFunc: c.updateBGPPolicy,
			DeleteFunc: c.deleteBGPPolicy,
		},
		resyncPeriod,
	)
	c.serviceInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addService,
			UpdateFunc: c.updateService,
			DeleteFunc: c.deleteService,
		},
		resyncPeriod,
	)
	if c.egressEnabled {
		c.egressInformer.AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    c.addEgress,
				UpdateFunc: c.updateEgress,
				DeleteFunc: c.deleteEgress,
			},
			resyncPeriod,
		)
	}
	c.nodeInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    nil,
			UpdateFunc: c.updateNode,
			DeleteFunc: nil,
		},
		resyncPeriod,
	)
	if c.enabledIPv4 {
		c.ipProtocols = append(c.ipProtocols, protocolIPv4)
	}
	if c.enabledIPv6 {
		c.ipProtocols = append(c.ipProtocols, protocolIPv6)
	}
	return c, nil
}

// watchSecretChanges uses watch API directly to watch for the changes of the specific Secret.
func (c *Controller) watchSecretChanges(endCh <-chan struct{}) error {
	ns := env.GetAntreaNamespace()
	watcher, err := c.k8sClient.CoreV1().Secrets(ns).Watch(context.TODO(), metav1.SingleObject(metav1.ObjectMeta{
		Namespace: ns,
		Name:      c.bgpPeerPasswordsSecret,
	}))
	if err != nil {
		return fmt.Errorf("failed to create Secret watcher: %v", err)
	}

	ch := watcher.ResultChan()
	defer watcher.Stop()
	klog.InfoS("Starting watching Secret changes", "Secret", fmt.Sprintf("%s/%s", ns, c.bgpPeerPasswordsSecret))
	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return nil
			}
			// Update BGP peer passwords.
			klog.InfoS("Processing Secret event", "Secret", fmt.Sprintf("%s/%s", ns, c.bgpPeerPasswordsSecret))
			func() {
				c.bgpPeerPasswordsMutex.Lock()
				defer c.bgpPeerPasswordsMutex.Unlock()

				secretObj := event.Object.(*corev1.Secret)
				c.bgpPeerPasswords = make(map[string]string)
				for key, data := range secretObj.Data {
					c.bgpPeerPasswords[key] = string(data)
				}
			}()
			func() {
				c.bgpPolicyBindingMutex.RLock()
				defer c.bgpPolicyBindingMutex.RUnlock()
				if c.bgpPolicyBinding.effectiveBP != "" {
					c.queue.Add(c.bgpPolicyBinding.effectiveBP)
				}
			}()
		case <-endCh:
			return nil
		}
	}
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting", "controllerName", controllerName)
	defer klog.InfoS("Shutting down", "controllerName", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName,
		stopCh,
		c.nodeListerSynced,
		c.serviceListerSynced,
		c.egressListerSynced,
		c.bgpPolicyListerSynced,
		c.endpointSliceListerSynced) {
		return
	}

	go wait.NonSlidingUntil(func() {
		if err := c.watchSecretChanges(stopCh); err != nil {
			klog.ErrorS(err, "Watch Secret error", "secret", c.bgpPeerPasswordsSecret)
		}
	}, time.Second*10, stopCh)

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)

	if key, ok := obj.(string); !ok {
		// As the item in the work queue is actually invalid, we call Forget here else we'd go into a loop of attempting
		// to process a work item that is invalid. This should not happen.
		c.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else if err := c.syncBGPPolicy(key); err == nil {
		// If no error occurs we Forget this item, so it does not get queued again until another change happens.
		c.queue.Forget(key)
	} else {
		// Put the item back on the work queue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Syncing BGPPolicy failed, requeue", "BGPPolicy", key)
	}
	return true
}

func (c *Controller) syncBGPPolicy(bpName string) error {
	startTime := time.Now()
	defer func() {
		klog.V(2).InfoS("Finished syncing BGPPolicy", "BGPPolicy", bpName, "durationTime", time.Since(startTime))
	}()

	bp, err := c.bgpPolicyLister.Get(bpName)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	// If the BGPPolicy is deleted or not applied to the current Node anymore, do some cleanup.
	if bp == nil || !c.matchedCurrentNode(bp) {
		bpState, exists := c.getBGPPolicyState(bpName)
		// If this is the effective BGPPolicy for the current Node, the BGPPolicy state should exist, and do some cleanup.
		if exists {
			// Stop the BGP server process on the current Node.
			if err := bpState.bgpServer.Stop(c.ctx); err != nil {
				return err
			}
			// Delete the BGPPolicy state.
			c.deleteBGPPolicyState(bpName)
		}

		// Unbind the BGPPolicy from the current Node.
		// If the BGPPolicy is the effective one for the current Node, try to pop a new effective BGPPolicy from the
		// alternatives list to the queue. If the BGPPolicy is an alternative, remove it from the alternatives list.
		if newEffectiveBP := c.unbindNodeFromBGPPolicy(bpName); newEffectiveBP != "" {
			c.queue.Add(newEffectiveBP)
		}
		return nil
	}

	// Bind the BGPPolicy to the current Node. If the BGPPolicy is not as the effective one, just return.
	if asEffective := c.bindNodeToBGPPolicy(bpName); !asEffective {
		klog.InfoS("The Node has already got an effective BGPPolicy. This is as an alternative", "BGPPolicy", bpName)
		return nil
	}

	// Retrieve the listen port, local AS number, and router ID from the current BGPPolicy to start the BGP server.
	routerID, err := c.getRouterID()
	if err != nil {
		return err
	}
	listenPort := defaultBGPListenPort
	if bp.Spec.ListenPort != nil {
		listenPort = *bp.Spec.ListenPort
	}
	localASN := bp.Spec.LocalASN

	var needUpdateBGPServer bool
	// Get the BGPPolicy state.
	bpState, exists := c.getBGPPolicyState(bpName)
	if !exists {
		// If the BGPPolicy state doesn't exist, meaning the BGPPolicy has not been enforced on the current Node, create
		// state for the BGPPolicy, and then start the BGP server.
		bpState = c.newBGPPolicyState(bp)
		needUpdateBGPServer = true
	} else {
		// Check the listen port, local AS number and routerID. If any of them have changed, then start a new BGP server
		// and stop the stale one.
		needUpdateBGPServer = bpState.listenPort != listenPort ||
			bpState.localASN != localASN ||
			bpState.routerID != routerID
	}

	if needUpdateBGPServer {
		// Start the new BGP server.
		globalConfig := &bgp.GlobalConfig{
			ASN:        uint32(localASN),
			RouterID:   routerID,
			ListenPort: listenPort,
		}
		// Stop the stale BGP server if it exists.
		if bpState.bgpServer != nil {
			if err := bpState.bgpServer.Stop(c.ctx); err != nil {
				klog.ErrorS(err, "Failed to stop stale BGP Server", "BGPPolicy", bpName)
			}
		}
		// Start the new BGP server.
		bgpServer := newBGPServerFn(globalConfig)
		if err := bgpServer.Start(c.ctx); err != nil {
			return fmt.Errorf("failed to start BGP server: %w", err)
		}

		// Update the BGPPolicy state.
		bpState.bgpServer = bgpServer
		bpState.listenPort = listenPort
		bpState.localASN = localASN
		bpState.routerID = routerID
	}

	// Reconcile BGP peers.
	peerKeys, peerConfigs, err := c.getPeers(bp.Spec.BGPPeers)
	if err != nil {
		return err
	}
	if err := c.reconcileBGPPeers(peerKeys, peerConfigs, bpState, needUpdateBGPServer); err != nil {
		return err
	}

	// Reconcile advertisements.
	routes, err := c.getRoutes(bp.Spec.Advertisements)
	if err != nil {
		return err
	}
	if err := c.reconcileRoutes(routes, bpState, needUpdateBGPServer); err != nil {
		return err
	}

	// Update the BGPPolicy state.
	bpState.routes = routes
	bpState.peerKeys = peerKeys
	bpState.peerConfigs = peerConfigs

	return nil
}

func getPeerConfigs(peerKeys sets.Set[string], allPeerConfigs map[string]bgp.PeerConfig) []bgp.PeerConfig {
	peerConfigs := make([]bgp.PeerConfig, 0, len(peerKeys))
	for peer := range peerKeys {
		peerConfigs = append(peerConfigs, allPeerConfigs[peer])
	}
	return peerConfigs
}

func (c *Controller) reconcileBGPPeers(curPeerKeys sets.Set[string],
	curPeerConfigs map[string]bgp.PeerConfig,
	bpState *bgpPolicyState,
	bgpServerUpdated bool) error {

	prePeerKeys := bpState.peerKeys
	prePeerConfigs := bpState.peerConfigs

	var peerToAddKeys sets.Set[string]
	if !bgpServerUpdated {
		peerToAddKeys = curPeerKeys.Difference(prePeerKeys)
	} else {
		peerToAddKeys = curPeerKeys
	}
	peerConfigsToAdd := getPeerConfigs(peerToAddKeys, curPeerConfigs)
	for _, peer := range peerConfigsToAdd {
		if err := bpState.bgpServer.AddPeer(c.ctx, peer); err != nil {
			return err
		}
	}

	if !bgpServerUpdated {
		peerToUpdateKeys := sets.New[string]()
		remainPeerKeys := prePeerKeys.Intersection(curPeerKeys)
		for peerKey := range remainPeerKeys {
			prevPeerConfig := bpState.peerConfigs[peerKey]
			curPeerConfig := curPeerConfigs[peerKey]
			if !reflect.DeepEqual(prevPeerConfig, curPeerConfig) {
				peerToUpdateKeys.Insert(peerKey)
			}
		}
		peerToUpdateConfigs := getPeerConfigs(peerToUpdateKeys, curPeerConfigs)
		for _, peer := range peerToUpdateConfigs {
			if err := bpState.bgpServer.UpdatePeer(c.ctx, peer); err != nil {
				return err
			}
		}

		peerToDeleteKeys := prePeerKeys.Difference(curPeerKeys)
		peerToDeleteConfigs := getPeerConfigs(peerToDeleteKeys, prePeerConfigs)
		for _, peer := range peerToDeleteConfigs {
			if err := bpState.bgpServer.RemovePeer(c.ctx, peer); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Controller) reconcileRoutes(curRoutes sets.Set[bgp.Route], bpState *bgpPolicyState, bgpServerUpdated bool) error {
	prevRoutes := bpState.routes

	var routesToAdvertise sets.Set[bgp.Route]
	if !bgpServerUpdated {
		routesToAdvertise = curRoutes.Difference(prevRoutes)
	} else {
		routesToAdvertise = curRoutes
	}
	if routesToAdvertise.Len() != 0 {
		if err := bpState.bgpServer.AdvertiseRoutes(c.ctx, routesToAdvertise.UnsortedList()); err != nil {
			return err
		}
	}

	if !bgpServerUpdated {
		routesToWithdraw := prevRoutes.Difference(curRoutes)
		if routesToWithdraw.Len() != 0 {
			if err := bpState.bgpServer.WithdrawRoutes(c.ctx, routesToWithdraw.UnsortedList()); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *Controller) getBGPPolicyState(bpName string) (*bgpPolicyState, bool) {
	c.bgpPolicyStatesMutex.RLock()
	defer c.bgpPolicyStatesMutex.RUnlock()
	state, exists := c.bgpPolicyStates[bpName]
	return state, exists
}

func (c *Controller) deleteBGPPolicyState(bpName string) {
	c.bgpPolicyStatesMutex.Lock()
	defer c.bgpPolicyStatesMutex.Unlock()
	delete(c.bgpPolicyStates, bpName)
}

func (c *Controller) getRouterID() (string, error) {
	var routerID string
	// For IPv6 only environment, the BGP routerID should be specified by K8s Node annotation `antrea.io/bgp-route-id`.
	if !c.enabledIPv4 && c.enabledIPv6 {
		nodeObj, _ := c.nodeLister.Get(c.nodeName)
		var exists bool
		if routerID, exists = nodeObj.GetAnnotations()[bgpRouteIDAnnotation]; !exists {
			return "", fmt.Errorf("BGP routerID should be assigned by annotation manually when IPv6 is only enabled")
		}
		if !net.IsIPv4String(routerID) {
			return "", fmt.Errorf("BGP routerID should be an IPv4 address")
		}
	} else {
		routerID = c.nodeIPv4Addr
	}
	return routerID, nil
}

func (c *Controller) newBGPPolicyState(bp *v1alpha1.BGPPolicy) *bgpPolicyState {
	c.bgpPolicyStatesMutex.Lock()
	defer c.bgpPolicyStatesMutex.Unlock()

	routes := make(sets.Set[bgp.Route])
	peers := make(sets.Set[string])
	peerConfigs := make(map[string]bgp.PeerConfig)

	state := &bgpPolicyState{
		routes:      routes,
		peerKeys:    peers,
		peerConfigs: peerConfigs,
	}
	c.bgpPolicyStates[bp.Name] = state
	return state
}

func (c *Controller) getRoutes(advertisements v1alpha1.Advertisements) (sets.Set[bgp.Route], error) {
	allRoutes := sets.New[bgp.Route]()

	if advertisements.Service != nil {
		if err := c.addServiceRoutes(advertisements.Service, allRoutes); err != nil {
			return nil, err
		}
	}
	if c.egressEnabled && advertisements.Egress != nil {
		if err := c.addEgressRoutes(allRoutes); err != nil {
			return nil, err
		}
	}
	if advertisements.Pod != nil {
		c.addPodRoutes(allRoutes)
	}

	return allRoutes, nil
}

func serviceIPTypesToAdvertise(serviceIPTypes []v1alpha1.ServiceIPType) sets.Set[v1alpha1.ServiceIPType] {
	ipTypeMap := sets.New[v1alpha1.ServiceIPType]()
	for _, ipType := range serviceIPTypes {
		ipTypeMap.Insert(ipType)
	}
	return ipTypeMap
}

func (c *Controller) addServiceRoutes(advertisement *v1alpha1.ServiceAdvertisement, allRoutes sets.Set[bgp.Route]) error {
	ipTypeMap := serviceIPTypesToAdvertise(advertisement.IPTypes)

	services, err := c.serviceLister.List(labels.Everything())
	if err != nil {
		return err
	}

	var serviceIPs []string
	for _, svc := range services {
		internalLocal := svc.Spec.InternalTrafficPolicy != nil && *svc.Spec.InternalTrafficPolicy == corev1.ServiceInternalTrafficPolicyLocal
		externalLocal := svc.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyLocal
		var hasLocalEndpoints bool
		if internalLocal || externalLocal {
			var err error
			hasLocalEndpoints, err = c.hasLocalEndpoints(svc)
			if err != nil {
				return err
			}
		}
		if ipTypeMap.Has(v1alpha1.ServiceIPTypeClusterIP) {
			if internalLocal && hasLocalEndpoints || !internalLocal {
				for _, clusterIP := range svc.Spec.ClusterIPs {
					serviceIPs = append(serviceIPs, clusterIP)
				}
			}
		}
		if ipTypeMap.Has(v1alpha1.ServiceIPTypeExternalIP) {
			if externalLocal && hasLocalEndpoints || !externalLocal {
				for _, externalIP := range svc.Spec.ExternalIPs {
					serviceIPs = append(serviceIPs, externalIP)
				}
			}
		}
		if ipTypeMap.Has(v1alpha1.ServiceIPTypeLoadBalancerIP) && svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
			if externalLocal && hasLocalEndpoints || !externalLocal {
				for _, ingressIP := range svc.Status.LoadBalancer.Ingress {
					if ingressIP.IP != "" {
						serviceIPs = append(serviceIPs, ingressIP.IP)
					}
				}
			}
		}
	}

	for _, ip := range serviceIPs {
		if c.enabledIPv4 && net.IsIPv4String(ip) {
			allRoutes.Insert(bgp.Route{Prefix: ip + ipv4Suffix})
		}
		if c.enabledIPv6 && net.IsIPv6String(ip) {
			allRoutes.Insert(bgp.Route{Prefix: ip + ipv6Suffix})
		}
	}

	return nil
}

func (c *Controller) addEgressRoutes(allRoutes sets.Set[bgp.Route]) error {
	egresses, err := c.egressLister.List(labels.Everything())
	if err != nil {
		return err
	}

	for _, eg := range egresses {
		if eg.Status.EgressNode != c.nodeName {
			continue
		}
		ip := eg.Status.EgressIP
		if c.enabledIPv4 && net.IsIPv4String(ip) {
			allRoutes.Insert(bgp.Route{Prefix: ip + ipv4Suffix})
		}
		if c.enabledIPv6 && net.IsIPv6String(ip) {
			allRoutes.Insert(bgp.Route{Prefix: ip + ipv6Suffix})
		}
	}

	return nil
}

func (c *Controller) addPodRoutes(allRoutes sets.Set[bgp.Route]) {
	if c.enabledIPv4 {
		allRoutes.Insert(bgp.Route{Prefix: c.podIPv4CIDR})
	}
	if c.enabledIPv6 {
		allRoutes.Insert(bgp.Route{Prefix: c.podIPv6CIDR})
	}
}

func (c *Controller) hasLocalEndpoints(svc *corev1.Service) (bool, error) {
	eps, err := c.endpointSliceLister.EndpointSlices(svc.GetNamespace()).Get(svc.GetName())
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	for _, ep := range eps.Endpoints {
		if ep.NodeName != nil && *ep.NodeName == c.nodeName {
			return true, nil
		}
	}

	return false, nil
}

func (c *Controller) generateBGPPeerConfig(peer *v1alpha1.BGPPeer) bgp.PeerConfig {
	bgpPeerConfig := bgp.PeerConfig{
		BGPPeer: peer,
	}
	bgpPeerKey := generateBGPPeerKey(peer.Address, peer.ASN)
	c.bgpPeerPasswordsMutex.RLock()
	defer c.bgpPeerPasswordsMutex.RUnlock()
	if password, exists := c.bgpPeerPasswords[bgpPeerKey]; exists {
		bgpPeerConfig.Password = password
	}
	return bgpPeerConfig
}

func (c *Controller) getPeers(allPeers []v1alpha1.BGPPeer) (sets.Set[string], map[string]bgp.PeerConfig, error) {
	peerKeys := sets.New[string]()
	peerConfigs := make(map[string]bgp.PeerConfig)

	for i := range allPeers {
		peerKey := generateBGPPeerKey(allPeers[i].Address, allPeers[i].ASN)
		if c.enabledIPv4 && net.IsIPv4String(allPeers[i].Address) {
			peerKeys.Insert(peerKey)
		}
		if c.enabledIPv6 && net.IsIPv6String(allPeers[i].Address) {
			peerKeys.Insert(peerKey)
		}
		peerConfigs[peerKey] = c.generateBGPPeerConfig(&allPeers[i])
	}
	return peerKeys, peerConfigs, nil
}

func generateBGPPeerKey(address string, asn int32) string {
	return fmt.Sprintf("%s-%d", address, asn)
}

func (c *Controller) addBGPPolicy(obj interface{}) {
	bp := obj.(*v1alpha1.BGPPolicy)
	if !c.matchedCurrentNode(bp) {
		return
	}
	klog.V(2).InfoS("Processing BGPPolicy ADD event", "BGPPolicy", klog.KObj(bp))
	c.queue.Add(bp.Name)
}

func (c *Controller) updateBGPPolicy(oldObj, obj interface{}) {
	oldBP := oldObj.(*v1alpha1.BGPPolicy)
	bp := obj.(*v1alpha1.BGPPolicy)
	if !c.matchedCurrentNode(bp) && !c.matchedCurrentNode(oldBP) {
		return
	}
	if bp.GetGeneration() != oldBP.GetGeneration() {
		klog.V(2).InfoS("Processing BGPPolicy UPDATE event", "BGPPolicy", klog.KObj(bp))
		c.queue.Add(bp.Name)
	}
}

func (c *Controller) deleteBGPPolicy(obj interface{}) {
	bp := obj.(*v1alpha1.BGPPolicy)
	if !c.matchedCurrentNode(bp) {
		return
	}
	klog.V(2).InfoS("Processing BGPPolicy DELETE event", "BGPPolicy", klog.KObj(bp))
	c.queue.Add(bp.Name)
}

func getIngressIPs(svc *corev1.Service) []string {
	var ips []string
	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		if ingress.IP != "" {
			ips = append(ips, ingress.IP)
		}
	}
	return ips
}

func (c *Controller) matchedCurrentNode(bp *v1alpha1.BGPPolicy) bool {
	nodeSelector, _ := metav1.LabelSelectorAsSelector(&bp.Spec.NodeSelector)
	node, _ := c.nodeLister.Get(c.nodeName)
	return nodeSelector.Matches(labels.Set(node.GetLabels()))
}

func (c *Controller) matchedNode(node *corev1.Node, bp *v1alpha1.BGPPolicy) bool {
	nodeSel, _ := metav1.LabelSelectorAsSelector(&bp.Spec.NodeSelector)
	if !nodeSel.Matches(labels.Set(node.Labels)) {
		return false
	}
	return true
}

func (c *Controller) filterAffectedBPsByNode(node *corev1.Node) sets.Set[string] {
	affectedBPs := sets.New[string]()
	allBPs, _ := c.bgpPolicyLister.List(labels.Everything())
	for _, bp := range allBPs {
		if c.matchedNode(node, bp) {
			affectedBPs.Insert(bp.GetName())
		}
	}
	return affectedBPs
}

func (c *Controller) filterAffectedBPsByService(svc *corev1.Service) sets.Set[string] {
	affectedBPs := sets.New[string]()
	allBPs, _ := c.bgpPolicyLister.List(labels.Everything())
	for _, bp := range allBPs {
		if bp.Spec.Advertisements.Service == nil {
			continue
		}
		ipTypeMap := serviceIPTypesToAdvertise(bp.Spec.Advertisements.Service.IPTypes)

		if ipTypeMap.Has(v1alpha1.ServiceIPTypeClusterIP) && len(svc.Spec.ClusterIPs) != 0 ||
			ipTypeMap.Has(v1alpha1.ServiceIPTypeExternalIP) && len(svc.Spec.ExternalIPs) != 0 ||
			ipTypeMap.Has(v1alpha1.ServiceIPTypeLoadBalancerIP) && len(getIngressIPs(svc)) != 0 {
			if c.matchedCurrentNode(bp) {
				affectedBPs.Insert(bp.GetName())
			}
		}
	}
	return affectedBPs
}

func (c *Controller) filterAffectedBPsByEgress() sets.Set[string] {
	affectedBPs := sets.New[string]()
	allBPs, _ := c.bgpPolicyLister.List(labels.Everything())
	for _, bp := range allBPs {
		if bp.Spec.Advertisements.Egress != nil && c.matchedCurrentNode(bp) {
			affectedBPs.Insert(bp.GetName())
		}
	}
	return affectedBPs
}

func (c *Controller) addService(obj interface{}) {
	svc := obj.(*corev1.Service)
	affectedBPs := c.filterAffectedBPsByService(svc)
	if len(affectedBPs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Service ADD event", "Service", klog.KObj(svc))
	for affectedBP := range affectedBPs {
		c.queue.Add(affectedBP)
	}
}

func (c *Controller) updateService(oldObj, obj interface{}) {
	oldSvc := oldObj.(*corev1.Service)
	svc := obj.(*corev1.Service)

	if slices.Equal(oldSvc.Spec.ClusterIPs, svc.Spec.ClusterIPs) &&
		slices.Equal(oldSvc.Spec.ExternalIPs, svc.Spec.ExternalIPs) &&
		slices.Equal(getIngressIPs(oldSvc), getIngressIPs(svc)) {
		return
	}
	oldAffectedBPs := c.filterAffectedBPsByService(oldSvc)
	newAffectedBPs := c.filterAffectedBPsByService(svc)
	affectedBPs := utilipset.MergeString(oldAffectedBPs, newAffectedBPs)
	if len(affectedBPs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Service UPDATE event", "Service", klog.KObj(svc))
	for affectedBP := range affectedBPs {
		c.queue.Add(affectedBP)
	}
}

func (c *Controller) deleteService(obj interface{}) {
	svc := obj.(*corev1.Service)
	affectedBPs := c.filterAffectedBPsByService(svc)
	if len(affectedBPs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Service DELETE event", "Service", klog.KObj(svc))
	for affectedBP := range affectedBPs {
		c.queue.Add(affectedBP)
	}
}

func (c *Controller) addEgress(obj interface{}) {
	if !c.egressEnabled {
		return
	}
	eg := obj.(*v1beta1.Egress)
	if eg.Status.EgressNode != c.nodeName {
		return
	}
	affectedBPs := c.filterAffectedBPsByEgress()
	if len(affectedBPs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Egress ADD event", "Egress", klog.KObj(eg))
	for affectedBP := range affectedBPs {
		c.queue.Add(affectedBP)
	}
}

// TODO: if the update of status can be captured
func (c *Controller) updateEgress(oldObj, obj interface{}) {
	if !c.egressEnabled {
		return
	}
	oldEg := oldObj.(*v1beta1.Egress)
	eg := obj.(*v1beta1.Egress)
	if oldEg.Status.EgressNode != c.nodeName && eg.Status.EgressNode != c.nodeName {
		return
	}
	if oldEg.Status.EgressIP == eg.Status.EgressIP {
		return
	}
	affectedBPs := c.filterAffectedBPsByEgress()
	if len(affectedBPs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Egress UPDATE event", "Egress", klog.KObj(eg))
	for affectedBP := range affectedBPs {
		c.queue.Add(affectedBP)
	}
}

func (c *Controller) deleteEgress(obj interface{}) {
	if !c.egressEnabled {
		return
	}
	eg := obj.(*v1beta1.Egress)
	if eg.Status.EgressNode != c.nodeName {
		return
	}
	affectedBPs := c.filterAffectedBPsByEgress()
	if len(affectedBPs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Egress DELETE event", "Service", klog.KObj(eg))
	for affectedBP := range affectedBPs {
		c.queue.Add(affectedBP)
	}
}

func (c *Controller) updateNode(oldObj, obj interface{}) {
	oldNode := oldObj.(*corev1.Node)
	node := obj.(*corev1.Node)
	if node.GetName() != c.nodeName {
		return
	}
	if reflect.DeepEqual(node.GetLabels(), oldNode.GetLabels()) &&
		reflect.DeepEqual(node.GetAnnotations(), oldNode.GetAnnotations()) {
		return
	}
	oldAffectedBPs := c.filterAffectedBPsByNode(oldNode)
	newAffectedBPs := c.filterAffectedBPsByNode(node)
	affectedBPs := utilipset.SymmetricDifferenceString(oldAffectedBPs, newAffectedBPs)
	if len(affectedBPs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Node UPDATE event", "Node", klog.KObj(node))
	for affectedBP := range affectedBPs {
		c.queue.Add(affectedBP)
	}
}

func (c *Controller) bindNodeToBGPPolicy(bpName string) bool {
	c.bgpPolicyBindingMutex.Lock()
	defer c.bgpPolicyBindingMutex.Unlock()

	binding := c.bgpPolicyBinding
	if binding.effectiveBP == "" {
		binding.effectiveBP = bpName
		return true
	}
	if binding.effectiveBP == bpName {
		return true
	}

	if !binding.alternativeBPs.Has(bpName) {
		binding.alternativeBPs.Insert(bpName)
	}
	return false
}

func (c *Controller) unbindNodeFromBGPPolicy(bpName string) string {
	c.bgpPolicyBindingMutex.Lock()
	defer c.bgpPolicyBindingMutex.Unlock()

	binding := c.bgpPolicyBinding
	if binding.effectiveBP == bpName {
		var popped bool
		// Select a new effective BGPPolicy.
		binding.effectiveBP, popped = binding.alternativeBPs.PopAny()
		if !popped {
			// Remove the binding information for the Node if there is no alternative BGPPolicies.
			binding.effectiveBP = ""
			return ""
		}
		return binding.effectiveBP
	}
	binding.alternativeBPs.Delete(bpName)
	return ""
}
