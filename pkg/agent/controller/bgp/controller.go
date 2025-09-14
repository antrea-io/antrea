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
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"reflect"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	apitypes "k8s.io/apimachinery/pkg/types"
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
	utilnet "k8s.io/utils/net"
	"k8s.io/utils/ptr"
	"k8s.io/utils/strings/slices"

	"antrea.io/antrea/pkg/agent/bgp"
	"antrea.io/antrea/pkg/agent/bgp/gobgp"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	crdinformersv1a1 "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdinformersv1b1 "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1beta1"
	crdlistersv1a1 "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	crdlistersv1b1 "antrea.io/antrea/pkg/client/listers/crd/v1beta1"
	"antrea.io/antrea/pkg/util/env"
)

const (
	controllerName = "BGPPolicyController"
	// How long to wait before retrying the processing of a BGPPolicy change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Disable resyncing.
	resyncPeriod time.Duration = 0
)

const (
	ipv4Suffix = "/32"
	ipv6Suffix = "/128"
)

const dummyKey = "dummyKey"

var (
	ErrBGPPolicyNotFound = errors.New("BGPPolicy not found")
)

type AdvertisedRouteType string

const (
	EgressIP              AdvertisedRouteType = "EgressIP"
	ServiceLoadBalancerIP AdvertisedRouteType = "ServiceLoadBalancerIP"
	ServiceExternalIP     AdvertisedRouteType = "ServiceExternalIP"
	ServiceClusterIP      AdvertisedRouteType = "ServiceClusterIP"
	NodeIPAMPodCIDR       AdvertisedRouteType = "NodeIPAMPodCIDR"
)

type RouteMetadata struct {
	Type      AdvertisedRouteType
	K8sObjRef string
}

type confederationConfig struct {
	identifier int32
	memberASNs sets.Set[uint32]
}

type bgpPolicyState struct {
	// The local BGP server.
	bgpServer bgp.Interface
	// name of the BGP policy.
	bgpPolicyName string
	// The port on which the local BGP server listens.
	listenPort int32
	// The AS number used by the local BGP server.
	localASN int32
	// The router ID used by the local BGP server.
	routerID string
	// The confederation config used by the local BGP server.
	confederationConfig *confederationConfig
	// routes stores all BGP routes advertised to BGP peers.
	routes map[bgp.Route]RouteMetadata
	// peerConfigs is a map that stores configurations of BGP peers. The map keys are the concatenated strings of BGP
	// peer IP address and ASN (e.g., "192.168.77.100-65000", "2001::1-65000").
	peerConfigs map[string]bgp.PeerConfig
}

type Controller struct {
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

	endpointSliceInformer     cache.SharedIndexInformer
	endpointSliceLister       discoverylisters.EndpointSliceLister
	endpointSliceListerSynced cache.InformerSynced

	secretInformer cache.SharedIndexInformer

	bgpPolicyState      *bgpPolicyState
	bgpPolicyStateMutex sync.RWMutex

	k8sClient             kubernetes.Interface
	bgpPeerPasswords      map[string]string
	bgpPeerPasswordsMutex sync.RWMutex

	nodeName     string
	enabledIPv4  bool
	enabledIPv6  bool
	podIPv4CIDR  string
	podIPv6CIDR  string
	nodeIPv4Addr string

	egressEnabled bool

	newBGPServerFn func(globalConfig *bgp.GlobalConfig) bgp.Interface

	queue workqueue.TypedRateLimitingInterface[string]
}

func NewBGPPolicyController(nodeInformer coreinformers.NodeInformer,
	serviceInformer coreinformers.ServiceInformer,
	egressInformer crdinformersv1b1.EgressInformer,
	bgpPolicyInformer crdinformersv1a1.BGPPolicyInformer,
	endpointSliceInformer discoveryinformers.EndpointSliceInformer,
	egressEnabled bool,
	k8sClient kubernetes.Interface,
	nodeConfig *config.NodeConfig,
	networkConfig *config.NetworkConfig) (*Controller, error) {
	c := &Controller{
		nodeInformer:              nodeInformer.Informer(),
		nodeLister:                nodeInformer.Lister(),
		nodeListerSynced:          nodeInformer.Informer().HasSynced,
		serviceInformer:           serviceInformer.Informer(),
		serviceLister:             serviceInformer.Lister(),
		serviceListerSynced:       serviceInformer.Informer().HasSynced,
		bgpPolicyInformer:         bgpPolicyInformer.Informer(),
		bgpPolicyLister:           bgpPolicyInformer.Lister(),
		bgpPolicyListerSynced:     bgpPolicyInformer.Informer().HasSynced,
		endpointSliceInformer:     endpointSliceInformer.Informer(),
		endpointSliceLister:       endpointSliceInformer.Lister(),
		endpointSliceListerSynced: endpointSliceInformer.Informer().HasSynced,
		k8sClient:                 k8sClient,
		bgpPeerPasswords:          make(map[string]string),
		nodeName:                  nodeConfig.Name,
		enabledIPv4:               networkConfig.IPv4Enabled,
		enabledIPv6:               networkConfig.IPv6Enabled,
		podIPv4CIDR:               nodeConfig.PodIPv4CIDR.String(),
		podIPv6CIDR:               nodeConfig.PodIPv6CIDR.String(),
		nodeIPv4Addr:              nodeConfig.NodeIPv4Addr.IP.String(),
		egressEnabled:             egressEnabled,
		newBGPServerFn: func(globalConfig *bgp.GlobalConfig) bgp.Interface {
			return gobgp.NewGoBGPServer(globalConfig)
		},
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: "bgpPolicy",
			},
		),
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
	c.endpointSliceInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addEndpointSlice,
			UpdateFunc: c.updateEndpointSlice,
			DeleteFunc: c.deleteEndpointSlice,
		},
		resyncPeriod,
	)
	if c.egressEnabled {
		c.egressInformer = egressInformer.Informer()
		c.egressLister = egressInformer.Lister()
		c.egressListerSynced = egressInformer.Informer().HasSynced
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
			AddFunc:    c.addNode,
			UpdateFunc: c.updateNode,
			DeleteFunc: nil,
		},
		resyncPeriod,
	)

	c.secretInformer = coreinformers.NewFilteredSecretInformer(k8sClient,
		env.GetAntreaNamespace(),
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("metadata.name", types.BGPPolicySecretName).String()
		})
	c.secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addSecret,
		UpdateFunc: c.updateSecret,
		DeleteFunc: c.deleteSecret,
	})

	return c, nil
}

func (c *Controller) Run(ctx context.Context) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting", "controllerName", controllerName)
	defer klog.InfoS("Shutting down", "controllerName", controllerName)

	go c.secretInformer.Run(ctx.Done())

	cacheSyncs := []cache.InformerSynced{
		c.nodeListerSynced,
		c.serviceListerSynced,
		c.bgpPolicyListerSynced,
		c.endpointSliceListerSynced,
		c.serviceListerSynced,
		c.secretInformer.HasSynced,
	}
	if c.egressEnabled {
		cacheSyncs = append(cacheSyncs, c.egressListerSynced)
	}
	if !cache.WaitForNamedCacheSync(controllerName, ctx.Done(), cacheSyncs...) {
		return
	}

	go wait.UntilWithContext(ctx, c.worker, time.Second)

	<-ctx.Done()
}

func (c *Controller) worker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

func (c *Controller) processNextWorkItem(ctx context.Context) bool {
	_, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(dummyKey)

	if err := c.syncBGPPolicy(ctx); err == nil {
		// If no error occurs we Forget this item, so it does not get queued again until another change happens.
		c.queue.Forget(dummyKey)
	} else {
		// Put the item back on the work queue to handle any transient errors.
		c.queue.AddRateLimited(dummyKey)
		klog.ErrorS(err, "Syncing BGPPolicy failed, requeue")
	}
	return true
}

func (c *Controller) getEffectiveBGPPolicy() *v1alpha1.BGPPolicy {
	allPolicies, _ := c.bgpPolicyLister.List(labels.Everything())
	var oldestPolicy *v1alpha1.BGPPolicy
	for _, policy := range allPolicies {
		if c.matchesCurrentNode(policy) {
			if oldestPolicy == nil || policy.CreationTimestamp.Before(&oldestPolicy.CreationTimestamp) {
				oldestPolicy = policy
			}
		}
	}
	return oldestPolicy
}

func getConfederationConfig(conf *v1alpha1.Confederation) *confederationConfig {
	if conf == nil {
		return nil
	}
	peers := sets.New[uint32]()
	for _, v := range conf.MemberASNs {
		peers.Insert(uint32(v))
	}
	return &confederationConfig{
		identifier: conf.Identifier,
		memberASNs: peers,
	}
}

func confederationConfigEqual(a, b *confederationConfig) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && a.identifier == b.identifier && a.memberASNs.Equal(b.memberASNs))
}

func (c *Controller) syncBGPPolicy(ctx context.Context) error {
	ctx, cancel := context.WithTimeoutCause(ctx, 60*time.Second, fmt.Errorf("BGPPolicy took too long to sync"))
	defer cancel()

	startTime := time.Now()
	defer func() {
		klog.InfoS("Finished syncing BGPPolicy", "durationTime", time.Since(startTime))
	}()

	// Get the oldest BGPPolicy applied to the current Node as the effective BGPPolicy.
	effectivePolicy := c.getEffectiveBGPPolicy()

	c.bgpPolicyStateMutex.Lock()
	defer c.bgpPolicyStateMutex.Unlock()

	// When the effective BGPPolicy is nil, it means that there is no available BGPPolicy.
	if effectivePolicy == nil {
		// If the BGPPolicy state is nil, just return.
		if c.bgpPolicyState == nil {
			return nil
		}

		// If the BGPPolicy state is not nil, stop the BGP server and reset the state to nil, then return.
		if err := c.bgpPolicyState.bgpServer.Stop(ctx); err != nil {
			return err
		}
		c.bgpPolicyState = nil
		return nil
	}

	klog.V(2).InfoS("Syncing BGPPolicy", "BGPPolicy", klog.KObj(effectivePolicy))
	// Retrieve the BGP policy name, listen port, local AS number and router ID from the effective BGPPolicy, and update them to the
	// current state.
	routerID, err := c.getRouterID()
	if err != nil {
		return err
	}
	bgpPolicyName := effectivePolicy.Name
	listenPort := *effectivePolicy.Spec.ListenPort
	localASN := effectivePolicy.Spec.LocalASN
	confederationConfig := getConfederationConfig(effectivePolicy.Spec.Confederation)

	// If the BGPPolicy state is nil, a new BGP server should be started, initialize the BGPPolicy state to store the
	// new BGP server, BGP policy name, listen port, local ASN, and router ID.
	// If the BGPPolicy is not nil, any of the listen port, local AS number, router ID or confederation configuration
	// has changed, stop the current BGP server first and reset the BGPPolicy state to nil; then start a new BGP server
	// and initialize the BGPPolicy state to store the new BGP server, listen port, local ASN, and router ID.
	needUpdateBGPServer := c.bgpPolicyState == nil ||
		c.bgpPolicyState.listenPort != listenPort ||
		c.bgpPolicyState.localASN != localASN ||
		c.bgpPolicyState.routerID != routerID ||
		!confederationConfigEqual(c.bgpPolicyState.confederationConfig, confederationConfig)

	if needUpdateBGPServer {
		if c.bgpPolicyState != nil {
			// Stop the current BGP server.
			if err := c.bgpPolicyState.bgpServer.Stop(ctx); err != nil {
				return fmt.Errorf("failed to stop current BGP server: %w", err)
			}
			// Reset the BGPPolicy state to nil.
			c.bgpPolicyState = nil
		}

		// Create a new BGP server.
		bgpConfig := &bgp.GlobalConfig{
			ASN:        uint32(localASN),
			RouterID:   routerID,
			ListenPort: listenPort,
		}
		if confederationConfig != nil {
			bgpConfig.Confederation = &bgp.Confederation{
				Identifier: uint32(confederationConfig.identifier),
				MemberASNs: confederationConfig.memberASNs.UnsortedList(),
			}
		}
		bgpServer := c.newBGPServerFn(bgpConfig)

		// Start the new BGP server.
		if err := bgpServer.Start(ctx); err != nil {
			return fmt.Errorf("failed to start BGP server: %w", err)
		}

		// Initialize the BGPPolicy state to store the new BGP server, BGP policy name, listen port, local ASN, and router ID.
		c.bgpPolicyState = &bgpPolicyState{
			bgpServer:           bgpServer,
			bgpPolicyName:       bgpPolicyName,
			routerID:            routerID,
			listenPort:          listenPort,
			localASN:            localASN,
			confederationConfig: confederationConfig,
			routes:              make(map[bgp.Route]RouteMetadata),
			peerConfigs:         make(map[string]bgp.PeerConfig),
		}
	} else if c.bgpPolicyState.bgpPolicyName != bgpPolicyName {
		// It may happen that only BGP policy name has changed in effective BGP policy.
		c.bgpPolicyState.bgpPolicyName = bgpPolicyName
	}

	// Reconcile BGP peers.
	if err := c.reconcileBGPPeers(ctx, effectivePolicy.Spec.BGPPeers); err != nil {
		return err
	}

	// Reconcile BGP advertisements.
	if err := c.reconcileBGPAdvertisements(ctx, effectivePolicy.Spec.Advertisements); err != nil {
		return err
	}

	return nil
}

func (c *Controller) reconcileBGPPeers(ctx context.Context, bgpPeers []v1alpha1.BGPPeer) error {
	curPeerConfigs := c.getPeerConfigs(bgpPeers)
	prePeerConfigs := c.bgpPolicyState.peerConfigs
	prePeerKeys := sets.KeySet(prePeerConfigs)
	curPeerKeys := sets.KeySet(curPeerConfigs)

	peerToAddKeys := curPeerKeys.Difference(prePeerKeys)
	peerToUpdateKeys := sets.New[string]()
	for peerKey := range prePeerKeys.Intersection(curPeerKeys) {
		prevPeerConfig := prePeerConfigs[peerKey]
		curPeerConfig := curPeerConfigs[peerKey]
		if !reflect.DeepEqual(prevPeerConfig, curPeerConfig) {
			peerToUpdateKeys.Insert(peerKey)
		}
	}
	peerToDeleteKeys := prePeerKeys.Difference(curPeerKeys)

	bgpServer := c.bgpPolicyState.bgpServer
	for key := range peerToAddKeys {
		peerConfig := curPeerConfigs[key]
		if err := bgpServer.AddPeer(ctx, peerConfig); err != nil {
			return err
		}
		c.bgpPolicyState.peerConfigs[key] = peerConfig
	}
	for key := range peerToUpdateKeys {
		peerConfig := curPeerConfigs[key]
		if err := bgpServer.UpdatePeer(ctx, peerConfig); err != nil {
			return err
		}
		c.bgpPolicyState.peerConfigs[key] = peerConfig
	}
	for key := range peerToDeleteKeys {
		peerConfig := prePeerConfigs[key]
		if err := bgpServer.RemovePeer(ctx, peerConfig); err != nil {
			return err
		}
		delete(c.bgpPolicyState.peerConfigs, key)
	}

	return nil
}

func (c *Controller) reconcileBGPAdvertisements(ctx context.Context, bgpAdvertisements v1alpha1.Advertisements) error {
	curRoutes := c.getRoutes(bgpAdvertisements)
	preRoutes := c.bgpPolicyState.routes
	currRoutesKeys := sets.KeySet(curRoutes)
	preRoutesKeys := sets.KeySet(preRoutes)

	routesToAdvertise := currRoutesKeys.Difference(preRoutesKeys)
	routesToWithdraw := preRoutesKeys.Difference(currRoutesKeys)

	bgpServer := c.bgpPolicyState.bgpServer
	for route := range routesToAdvertise {
		if err := bgpServer.AdvertiseRoutes(ctx, []bgp.Route{route}); err != nil {
			return err
		}
		c.bgpPolicyState.routes[route] = RouteMetadata{
			Type:      curRoutes[route].Type,
			K8sObjRef: curRoutes[route].K8sObjRef,
		}
	}
	for route := range routesToWithdraw {
		if err := bgpServer.WithdrawRoutes(ctx, []bgp.Route{route}); err != nil {
			return err
		}
		delete(c.bgpPolicyState.routes, route)
	}

	return nil
}

func hashNodeNameToIP(s string) string {
	h := fnv.New32a() // Create a new FNV hash
	h.Write([]byte(s))
	hashValue := h.Sum32() // Get the 32-bit hash

	// Convert the hash to a 4-byte slice
	ip := make(net.IP, 4)
	ip[0] = byte(hashValue >> 24)
	ip[1] = byte(hashValue >> 16)
	ip[2] = byte(hashValue >> 8)
	ip[3] = byte(hashValue)

	return ip.String()
}

func (c *Controller) getRouterID() (string, error) {
	// According to RFC 4271:
	// BGP Identifier:
	//   This 4-octet unsigned integer indicates the BGP Identifier of
	//   the sender.  A given BGP speaker sets the value of its BGP
	//   Identifier to an IP address that is assigned to that BGP
	//   speaker.  The value of the BGP Identifier is determined upon
	//   startup and is the same for every local interface and BGP peer.
	//
	// In goBGP, only an IPv4 address can be used as the BGP Identifier (BGP router ID).
	// The router ID could be specified in the Node annotation `node.antrea.io/bgp-router-id`.
	// For IPv4-only or dual-stack Kubernetes clusters, if the annotation is not present,
	// the Node's IPv4 address is used as the BGP router ID, ensuring uniqueness, and updated
	// to the Node annotation `node.antrea.io/bgp-router-id`.
	// For IPv6-only Kubernetes clusters without a Node IPv4 address, if the annotation is
	// not present, an IPv4 address will be generated by hashing the Node name and updated
	// to the Node annotation `node.antrea.io/bgp-router-id`.

	nodeObj, err := c.nodeLister.Get(c.nodeName)
	if err != nil {
		return "", fmt.Errorf("failed to get Node object: %w", err)
	}

	var exists bool
	var routerID string
	routerID, exists = nodeObj.GetAnnotations()[types.NodeBGPRouterIDAnnotationKey]
	if !exists {
		if c.enabledIPv4 {
			routerID = c.nodeIPv4Addr
		} else {
			routerID = hashNodeNameToIP(c.nodeName)
		}
		patch, _ := json.Marshal(map[string]interface{}{
			"metadata": map[string]interface{}{
				"annotations": map[string]string{
					types.NodeBGPRouterIDAnnotationKey: routerID,
				},
			},
		})
		if _, err := c.k8sClient.CoreV1().Nodes().Patch(context.TODO(), c.nodeName, apitypes.MergePatchType, patch, metav1.PatchOptions{}, "status"); err != nil {
			return "", fmt.Errorf("failed to patch BGP router ID to Node annotation %s: %w", types.NodeBGPRouterIDAnnotationKey, err)
		}
	} else if !utilnet.IsIPv4String(routerID) {
		return "", fmt.Errorf("BGP router ID should be an IPv4 address string")
	}
	return routerID, nil
}

func (c *Controller) getRoutes(advertisements v1alpha1.Advertisements) map[bgp.Route]RouteMetadata {
	allRoutes := make(map[bgp.Route]RouteMetadata)

	if advertisements.Service != nil {
		c.addServiceRoutes(advertisements.Service, allRoutes)
	}
	if c.egressEnabled && advertisements.Egress != nil {
		c.addEgressRoutes(allRoutes)
	}
	if advertisements.Pod != nil {
		c.addPodRoutes(allRoutes)
	}

	return allRoutes
}

func (c *Controller) addServiceRoutes(advertisement *v1alpha1.ServiceAdvertisement, allRoutes map[bgp.Route]RouteMetadata) {
	ipTypes := sets.New(advertisement.IPTypes...)
	services, _ := c.serviceLister.List(labels.Everything())

	for _, svc := range services {
		svcRef := svc.Namespace + "/" + svc.Name
		internalLocal := svc.Spec.InternalTrafficPolicy != nil && *svc.Spec.InternalTrafficPolicy == corev1.ServiceInternalTrafficPolicyLocal
		externalLocal := svc.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyLocal
		var hasLocalEndpoints bool
		if internalLocal || externalLocal {
			hasLocalEndpoints = c.hasLocalEndpoints(svc)
		}
		if ipTypes.Has(v1alpha1.ServiceIPTypeClusterIP) {
			if internalLocal && hasLocalEndpoints || !internalLocal {
				for _, clusterIP := range svc.Spec.ClusterIPs {
					if c.enabledIPv4 && utilnet.IsIPv4String(clusterIP) {
						addRoutes(allRoutes, clusterIP+ipv4Suffix, svcRef, ServiceClusterIP)
					} else if c.enabledIPv6 && utilnet.IsIPv6String(clusterIP) {
						addRoutes(allRoutes, clusterIP+ipv6Suffix, svcRef, ServiceClusterIP)
					}
				}
			}
		}
		if ipTypes.Has(v1alpha1.ServiceIPTypeExternalIP) {
			if externalLocal && hasLocalEndpoints || !externalLocal {
				for _, externalIP := range svc.Spec.ExternalIPs {
					if c.enabledIPv4 && utilnet.IsIPv4String(externalIP) {
						addRoutes(allRoutes, externalIP+ipv4Suffix, svcRef, ServiceExternalIP)
					} else if c.enabledIPv6 && utilnet.IsIPv6String(externalIP) {
						addRoutes(allRoutes, externalIP+ipv6Suffix, svcRef, ServiceExternalIP)
					}
				}
			}
		}
		if ipTypes.Has(v1alpha1.ServiceIPTypeLoadBalancerIP) && svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
			if externalLocal && hasLocalEndpoints || !externalLocal {
				loadBalancerIPs := getIngressIPs(svc)
				for _, loadBalancerIP := range loadBalancerIPs {
					if c.enabledIPv4 && utilnet.IsIPv4String(loadBalancerIP) {
						addRoutes(allRoutes, loadBalancerIP+ipv4Suffix, svcRef, ServiceLoadBalancerIP)
					} else if c.enabledIPv6 && utilnet.IsIPv6String(loadBalancerIP) {
						addRoutes(allRoutes, loadBalancerIP+ipv6Suffix, svcRef, ServiceLoadBalancerIP)
					}
				}
			}
		}
	}
}

func (c *Controller) addEgressRoutes(allRoutes map[bgp.Route]RouteMetadata) {
	egresses, _ := c.egressLister.List(labels.Everything())
	for _, eg := range egresses {
		if eg.Status.EgressNode != c.nodeName {
			continue
		}
		ip := eg.Status.EgressIP
		if c.enabledIPv4 && utilnet.IsIPv4String(ip) {
			addRoutes(allRoutes, ip+ipv4Suffix, eg.Name, EgressIP)
		} else if c.enabledIPv6 && utilnet.IsIPv6String(ip) {
			addRoutes(allRoutes, ip+ipv6Suffix, eg.Name, EgressIP)
		}
	}
}

func (c *Controller) addPodRoutes(allRoutes map[bgp.Route]RouteMetadata) {
	if c.enabledIPv4 {
		addRoutes(allRoutes, c.podIPv4CIDR, "", NodeIPAMPodCIDR)
	}
	if c.enabledIPv6 {
		addRoutes(allRoutes, c.podIPv6CIDR, "", NodeIPAMPodCIDR)
	}
}

func addRoutes(allRoutes map[bgp.Route]RouteMetadata, prefix, k8sObjRef string, routeType AdvertisedRouteType) {
	allRoutes[bgp.Route{Prefix: prefix}] = RouteMetadata{
		Type:      routeType,
		K8sObjRef: k8sObjRef,
	}
}

func (c *Controller) hasLocalEndpoints(svc *corev1.Service) bool {
	labelSelector := labels.Set{discovery.LabelServiceName: svc.GetName()}.AsSelector()
	items, _ := c.endpointSliceLister.EndpointSlices(svc.GetNamespace()).List(labelSelector)
	for _, eps := range items {
		for _, ep := range eps.Endpoints {
			if ep.NodeName != nil && *ep.NodeName == c.nodeName {
				return true
			}
		}
	}
	return false
}

func (c *Controller) getPeerConfigs(peers []v1alpha1.BGPPeer) map[string]bgp.PeerConfig {
	c.bgpPeerPasswordsMutex.RLock()
	defer c.bgpPeerPasswordsMutex.RUnlock()

	peerConfigs := make(map[string]bgp.PeerConfig)
	for i := range peers {
		if c.enabledIPv4 && utilnet.IsIPv4String(peers[i].Address) ||
			c.enabledIPv6 && utilnet.IsIPv6String(peers[i].Address) {
			peerKey := generateBGPPeerKey(peers[i].Address, peers[i].ASN)

			var password string
			if p, exists := c.bgpPeerPasswords[peerKey]; exists {
				password = p
			}

			peerConfigs[peerKey] = bgp.PeerConfig{
				BGPPeer:  &peers[i],
				Password: password,
			}
		}
	}
	return peerConfigs
}

func generateBGPPeerKey(address string, asn int32) string {
	return fmt.Sprintf("%s-%d", address, asn)
}

func (c *Controller) addBGPPolicy(obj interface{}) {
	bgpPolicy := obj.(*v1alpha1.BGPPolicy)
	if !c.matchesCurrentNode(bgpPolicy) {
		return
	}
	klog.V(2).InfoS("Processing BGPPolicy ADD event", "BGPPolicy", klog.KObj(bgpPolicy))
	c.queue.Add(dummyKey)
}

func (c *Controller) updateBGPPolicy(oldObj, obj interface{}) {
	oldBGPPolicy := oldObj.(*v1alpha1.BGPPolicy)
	policy := obj.(*v1alpha1.BGPPolicy)
	if !c.matchesCurrentNode(policy) && !c.matchesCurrentNode(oldBGPPolicy) {
		return
	}
	if policy.GetGeneration() != oldBGPPolicy.GetGeneration() {
		klog.V(2).InfoS("Processing BGPPolicy UPDATE event", "BGPPolicy", klog.KObj(policy))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) deleteBGPPolicy(obj interface{}) {
	bgpPolicy := obj.(*v1alpha1.BGPPolicy)
	if !c.matchesCurrentNode(bgpPolicy) {
		return
	}
	klog.V(2).InfoS("Processing BGPPolicy DELETE event", "BGPPolicy", klog.KObj(bgpPolicy))
	c.queue.Add(dummyKey)
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

func (c *Controller) matchesCurrentNode(bgpPolicy *v1alpha1.BGPPolicy) bool {
	node, _ := c.nodeLister.Get(c.nodeName)
	if node == nil {
		return false
	}
	return matchesNode(node, bgpPolicy)
}

func matchesNode(node *corev1.Node, bgpPolicy *v1alpha1.BGPPolicy) bool {
	nodeSelector, _ := metav1.LabelSelectorAsSelector(&bgpPolicy.Spec.NodeSelector)
	return nodeSelector.Matches(labels.Set(node.Labels))
}

func matchesService(svc *corev1.Service, bgpPolicy *v1alpha1.BGPPolicy) bool {
	ipTypeMap := sets.New(bgpPolicy.Spec.Advertisements.Service.IPTypes...)
	if ipTypeMap.Has(v1alpha1.ServiceIPTypeClusterIP) && len(svc.Spec.ClusterIPs) != 0 ||
		ipTypeMap.Has(v1alpha1.ServiceIPTypeExternalIP) && len(svc.Spec.ExternalIPs) != 0 ||
		ipTypeMap.Has(v1alpha1.ServiceIPTypeLoadBalancerIP) && len(getIngressIPs(svc)) != 0 {
		return true
	}
	return false
}

func (c *Controller) hasAffectedPolicyByService(svc *corev1.Service) bool {
	allPolicies, _ := c.bgpPolicyLister.List(labels.Everything())
	for _, policy := range allPolicies {
		if policy.Spec.Advertisements.Service == nil || !c.matchesCurrentNode(policy) {
			continue
		}
		if matchesService(svc, policy) {
			return true
		}
	}
	return false
}

func (c *Controller) addService(obj interface{}) {
	svc := obj.(*corev1.Service)
	if c.hasAffectedPolicyByService(svc) {
		klog.V(2).InfoS("Processing Service ADD event", "Service", klog.KObj(svc))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) updateService(oldObj, obj interface{}) {
	oldSvc := oldObj.(*corev1.Service)
	svc := obj.(*corev1.Service)

	if slices.Equal(oldSvc.Spec.ClusterIPs, svc.Spec.ClusterIPs) &&
		slices.Equal(oldSvc.Spec.ExternalIPs, svc.Spec.ExternalIPs) &&
		slices.Equal(getIngressIPs(oldSvc), getIngressIPs(svc)) &&
		oldSvc.Spec.ExternalTrafficPolicy == svc.Spec.ExternalTrafficPolicy &&
		ptr.Equal(oldSvc.Spec.InternalTrafficPolicy, svc.Spec.InternalTrafficPolicy) {
		return
	}
	if c.hasAffectedPolicyByService(oldSvc) || c.hasAffectedPolicyByService(svc) {
		klog.V(2).InfoS("Processing Service UPDATE event", "Service", klog.KObj(svc))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) deleteService(obj interface{}) {
	svc := obj.(*corev1.Service)
	if c.hasAffectedPolicyByService(svc) {
		klog.V(2).InfoS("Processing Service DELETE event", "Service", klog.KObj(svc))
		c.queue.Add(dummyKey)
	}
}

func noLocalTrafficPolicy(svc *corev1.Service) bool {
	internalTrafficCluster := svc.Spec.InternalTrafficPolicy == nil || *svc.Spec.InternalTrafficPolicy == corev1.ServiceInternalTrafficPolicyCluster
	if svc.Spec.Type == corev1.ServiceTypeClusterIP {
		return internalTrafficCluster
	}
	externalTrafficCluster := svc.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyTypeCluster
	return internalTrafficCluster && externalTrafficCluster
}

func (c *Controller) addEndpointSlice(obj interface{}) {
	eps := obj.(*discovery.EndpointSlice)
	svc, _ := c.serviceLister.Services(eps.GetNamespace()).Get(eps.GetLabels()[discovery.LabelServiceName])
	if svc == nil {
		return
	}
	// Events of EndpointSlices for Services without a `Local` traffic policy are ignored, as the Service IPs will
	// always be advertised.
	if noLocalTrafficPolicy(svc) {
		return
	}
	if c.hasAffectedPolicyByService(svc) {
		klog.V(2).InfoS("Processing EndpointSlice ADD event", "EndpointSlice", klog.KObj(eps))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) updateEndpointSlice(_, obj interface{}) {
	eps := obj.(*discovery.EndpointSlice)
	svc, _ := c.serviceLister.Services(eps.GetNamespace()).Get(eps.GetLabels()[discovery.LabelServiceName])
	if svc == nil {
		return
	}
	// Events of EndpointSlices for Services without a `Local` traffic policy are ignored, as the Service IPs will
	// always be advertised.
	if noLocalTrafficPolicy(svc) {
		return
	}
	if c.hasAffectedPolicyByService(svc) {
		klog.V(2).InfoS("Processing EndpointSlice UPDATE event", "EndpointSlice", klog.KObj(eps))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) deleteEndpointSlice(obj interface{}) {
	eps := obj.(*discovery.EndpointSlice)
	svc, _ := c.serviceLister.Services(eps.GetNamespace()).Get(eps.GetLabels()[discovery.LabelServiceName])
	if svc == nil {
		return
	}
	// Events of EndpointSlices for Services without a `Local` traffic policy are ignored, as the Service IPs will
	// always be advertised.
	if noLocalTrafficPolicy(svc) {
		return
	}
	if c.hasAffectedPolicyByService(svc) {
		klog.V(2).InfoS("Processing EndpointSlice DELETE event", "EndpointSlice", klog.KObj(eps))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) hasAffectedPolicyByEgress() bool {
	allPolicies, _ := c.bgpPolicyLister.List(labels.Everything())
	for _, policy := range allPolicies {
		if !c.matchesCurrentNode(policy) {
			continue
		}
		if policy.Spec.Advertisements.Egress != nil {
			return true
		}
	}
	return false
}

func (c *Controller) addEgress(obj interface{}) {
	eg := obj.(*v1beta1.Egress)
	if eg.Status.EgressNode != c.nodeName {
		return
	}
	if c.hasAffectedPolicyByEgress() {
		klog.V(2).InfoS("Processing Egress ADD event", "Egress", klog.KObj(eg))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) updateEgress(oldObj, obj interface{}) {
	oldEg := oldObj.(*v1beta1.Egress)
	eg := obj.(*v1beta1.Egress)
	if oldEg.Status.EgressNode != c.nodeName && eg.Status.EgressNode != c.nodeName {
		return
	}
	if oldEg.Status.EgressIP == eg.Status.EgressIP && oldEg.Status.EgressNode == eg.Status.EgressNode {
		return
	}
	if c.hasAffectedPolicyByEgress() {
		klog.V(2).InfoS("Processing Egress UPDATE event", "Egress", klog.KObj(eg))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) deleteEgress(obj interface{}) {
	eg := obj.(*v1beta1.Egress)
	if eg.Status.EgressNode != c.nodeName {
		return
	}
	if c.hasAffectedPolicyByEgress() {
		klog.V(2).InfoS("Processing Egress DELETE event", "Egress", klog.KObj(eg))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) hasAffectedPolicyByNode(node *corev1.Node) bool {
	allPolicies, _ := c.bgpPolicyLister.List(labels.Everything())
	for _, policy := range allPolicies {
		if matchesNode(node, policy) {
			return true
		}
	}
	return false
}

func (c *Controller) addNode(obj interface{}) {
	node := obj.(*corev1.Node)
	if node.GetName() != c.nodeName {
		return
	}
	if c.hasAffectedPolicyByNode(node) {
		klog.V(2).InfoS("Processing Node UPDATE event", "Node", klog.KObj(node))
		c.queue.Add(dummyKey)
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
	if c.hasAffectedPolicyByNode(oldNode) || c.hasAffectedPolicyByNode(node) {
		klog.V(2).InfoS("Processing Node UPDATE event", "Node", klog.KObj(node))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) addSecret(obj interface{}) {
	secret := obj.(*corev1.Secret)
	klog.V(2).InfoS("Processing Secret ADD event", "Secret", klog.KObj(secret))
	c.updateBGPPeerPasswords(secret)
	c.queue.Add(dummyKey)
}

func (c *Controller) updateSecret(_, obj interface{}) {
	secret := obj.(*corev1.Secret)
	klog.V(2).InfoS("Processing Secret UPDATE event", "Secret", klog.KObj(secret))
	c.updateBGPPeerPasswords(secret)
	c.queue.Add(dummyKey)
}

func (c *Controller) deleteSecret(obj interface{}) {
	klog.V(2).InfoS("Processing Secret DELETE event", "Secret", klog.KObj(obj.(*corev1.Secret)))
	c.updateBGPPeerPasswords(nil)
	c.queue.Add(dummyKey)
}

func (c *Controller) updateBGPPeerPasswords(secret *corev1.Secret) {
	c.bgpPeerPasswordsMutex.Lock()
	defer c.bgpPeerPasswordsMutex.Unlock()

	c.bgpPeerPasswords = make(map[string]string)
	if secret != nil && secret.Data != nil {
		for k, v := range secret.Data {
			c.bgpPeerPasswords[k] = string(v)
		}
	}
}

// GetBGPPolicyInfo returns Name, RouterID, LocalASN, ListenPort and ConfederationIdentifier of effective BGP Policy applied on the Node.
func (c *Controller) GetBGPPolicyInfo() (string, string, int32, int32, int32) {
	var name, routerID string
	var localASN, listenPort, confederationIdentifier int32

	c.bgpPolicyStateMutex.RLock()
	defer c.bgpPolicyStateMutex.RUnlock()

	if c.bgpPolicyState != nil {
		name = c.bgpPolicyState.bgpPolicyName
		routerID = c.bgpPolicyState.routerID
		localASN = c.bgpPolicyState.localASN
		listenPort = c.bgpPolicyState.listenPort
		if c.bgpPolicyState.confederationConfig != nil {
			confederationIdentifier = c.bgpPolicyState.confederationConfig.identifier
		}
	}
	return name, routerID, localASN, listenPort, confederationIdentifier
}

// GetBGPPeerStatus returns current status of BGP Peers of effective BGP Policy applied on the Node.
func (c *Controller) GetBGPPeerStatus(ctx context.Context) ([]bgp.PeerStatus, error) {
	getBgpServer := func() bgp.Interface {
		c.bgpPolicyStateMutex.RLock()
		defer c.bgpPolicyStateMutex.RUnlock()
		if c.bgpPolicyState == nil {
			return nil
		}
		return c.bgpPolicyState.bgpServer
	}

	bgpServer := getBgpServer()
	if bgpServer == nil {
		return nil, ErrBGPPolicyNotFound
	}
	allPeers, err := bgpServer.GetPeers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get bgp peers: %w", err)
	}
	return allPeers, nil
}

// GetBGPRoutes returns the advertised BGP routes.
func (c *Controller) GetBGPRoutes(ctx context.Context) (map[bgp.Route]RouteMetadata, error) {
	c.bgpPolicyStateMutex.RLock()
	defer c.bgpPolicyStateMutex.RUnlock()

	if c.bgpPolicyState == nil {
		return nil, ErrBGPPolicyNotFound
	}

	bgpRoutes := make(map[bgp.Route]RouteMetadata)
	for route, routeMetadata := range c.bgpPolicyState.routes {
		bgpRoutes[route] = routeMetadata
	}
	return bgpRoutes, nil
}
