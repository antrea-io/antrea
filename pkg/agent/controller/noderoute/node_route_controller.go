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

package noderoute

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/cache/synctrack"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/controller/ipseccertificate"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/route"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/wireguard"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	utilip "antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/k8s"
	utilwait "antrea.io/antrea/pkg/util/wait"
)

const (
	controllerName = "AntreaAgentNodeRouteController"
	// Interval of reprocessing every node.
	nodeResyncPeriod = 60 * time.Second
	// How long to wait before retrying the processing of a node change
	minRetryDelay = 2 * time.Second
	maxRetryDelay = 120 * time.Second
	// Default number of workers processing a node change
	defaultWorkers = 4

	ovsExternalIDNodeName = "node-name"

	nodeRouteInfoPodCIDRIndexName = "podCIDR"
)

// Controller is responsible for setting up necessary IP routes and Openflow entries for inter-node traffic.
type Controller struct {
	ovsBridgeClient  ovsconfig.OVSBridgeClient
	ofClient         openflow.Client
	ovsCtlClient     ovsctl.OVSCtlClient
	routeClient      route.Interface
	interfaceStore   interfacestore.InterfaceStore
	networkConfig    *config.NetworkConfig
	nodeConfig       *config.NodeConfig
	nodeInformer     coreinformers.NodeInformer
	nodeLister       corelisters.NodeLister
	nodeListerSynced cache.InformerSynced
	queue            workqueue.TypedRateLimitingInterface[string]
	// installedNodes records routes and flows installation states of Nodes.
	// The key is the host name of the Node, the value is the nodeRouteInfo of the Node.
	// A node will be in the map after its flows and routes are installed successfully.
	installedNodes cache.Indexer
	// podSubnetsMutex protects access to the podSubnets set.
	podSubnetsMutex sync.RWMutex
	// podSubnets is a set which stores all known PodCIDRs in the cluster as masked netip.Prefix objects.
	podSubnets      sets.Set[netip.Prefix]
	maskSizeV4      int
	maskSizeV6      int
	wireGuardClient wireguard.Interface
	// ipsecCertificateManager is useful for determining whether the ipsec certificate has been configured
	// or not when IPsec is enabled with "cert" mode. The NodeRouteController must wait for the certificate
	// to be configured before installing routes/flows to peer Nodes to prevent unencrypted traffic across Nodes.
	ipsecCertificateManager ipseccertificate.Manager
	// flowRestoreCompleteWait is to be decremented after installing flows for initial Nodes.
	flowRestoreCompleteWait *utilwait.Group
	// hasProcessedInitialList keeps track of whether the initial informer list has been
	// processed by workers.
	// See https://github.com/kubernetes/apiserver/blob/v0.30.1/pkg/admission/plugin/policy/internal/generic/controller.go
	hasProcessedInitialList synctrack.AsyncTracker[string]
}

// NewNodeRouteController instantiates a new Controller object which will process Node events
// and ensure connectivity between different Nodes.
func NewNodeRouteController(
	nodeInformer coreinformers.NodeInformer,
	client openflow.Client,
	ovsCtlClient ovsctl.OVSCtlClient,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	routeClient route.Interface,
	interfaceStore interfacestore.InterfaceStore,
	networkConfig *config.NetworkConfig,
	nodeConfig *config.NodeConfig,
	wireguardClient wireguard.Interface,
	ipsecCertificateManager ipseccertificate.Manager,
	flowRestoreCompleteWait *utilwait.Group,
) *Controller {
	controller := &Controller{
		ovsBridgeClient:  ovsBridgeClient,
		ofClient:         client,
		ovsCtlClient:     ovsCtlClient,
		routeClient:      routeClient,
		interfaceStore:   interfaceStore,
		networkConfig:    networkConfig,
		nodeConfig:       nodeConfig,
		nodeInformer:     nodeInformer,
		nodeLister:       nodeInformer.Lister(),
		nodeListerSynced: nodeInformer.Informer().HasSynced,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: "noderoute",
			},
		),
		installedNodes:          cache.NewIndexer(nodeRouteInfoKeyFunc, cache.Indexers{nodeRouteInfoPodCIDRIndexName: nodeRouteInfoPodCIDRIndexFunc}),
		podSubnets:              sets.New[netip.Prefix](),
		wireGuardClient:         wireguardClient,
		ipsecCertificateManager: ipsecCertificateManager,
		flowRestoreCompleteWait: flowRestoreCompleteWait.Increment(),
	}
	if nodeConfig.PodIPv4CIDR != nil {
		prefix, _ := cidrToPrefix(nodeConfig.PodIPv4CIDR)
		controller.podSubnets.Insert(prefix)
		controller.maskSizeV4 = prefix.Bits()
	}
	if nodeConfig.PodIPv6CIDR != nil {
		prefix, _ := cidrToPrefix(nodeConfig.PodIPv6CIDR)
		controller.podSubnets.Insert(prefix)
		controller.maskSizeV6 = prefix.Bits()
	}
	registration, _ := nodeInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerDetailedFuncs{
			AddFunc: func(cur interface{}, isInInitialList bool) {
				controller.enqueueNode(cur, isInInitialList)
			},
			UpdateFunc: func(old, cur interface{}) {
				controller.enqueueNode(cur, false)
			},
			DeleteFunc: func(old interface{}) {
				controller.enqueueNode(old, false)
			},
		},
		nodeResyncPeriod,
	)
	// UpstreamHasSynced is used by hasProcessedInitialList to determine whether even handlers
	// have been called for the initial list.
	controller.hasProcessedInitialList.UpstreamHasSynced = registration.HasSynced
	return controller
}

func nodeRouteInfoKeyFunc(obj interface{}) (string, error) {
	return obj.(*nodeRouteInfo).nodeName, nil
}

func nodeRouteInfoPodCIDRIndexFunc(obj interface{}) ([]string, error) {
	var podCIDRs []string
	for _, podCIDR := range obj.(*nodeRouteInfo).podCIDRs {
		podCIDRs = append(podCIDRs, podCIDR.String())
	}
	return podCIDRs, nil
}

// nodeRouteInfo is the route related information extracted from corev1.Node.
type nodeRouteInfo struct {
	nodeName           string
	podCIDRs           []*net.IPNet
	nodeIPs            *utilip.DualStackIPs
	gatewayIPs         *utilip.DualStackIPs
	nodeMAC            net.HardwareAddr
	wireGuardPublicKey string
}

// enqueueNode adds an object to the controller work queue
// obj could be a *corev1.Node, or a DeletionFinalStateUnknown item.
func (c *Controller) enqueueNode(obj interface{}, isInInitialList bool) {
	node, isNode := obj.(*corev1.Node)
	if !isNode {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Received unexpected object: %v", obj)
			return
		}
		node, ok = deletedState.Obj.(*corev1.Node)
		if !ok {
			klog.Errorf("DeletedFinalStateUnknown contains non-Node object: %v", deletedState.Obj)
			return
		}
	}

	// Ignore notifications for this Node, no need to establish connectivity to itself.
	if node.Name != c.nodeConfig.Name {
		if isInInitialList {
			c.hasProcessedInitialList.Start(node.Name)
		}
		c.queue.Add(node.Name)
	}
}

// removeStaleGatewayRoutes removes all the gateway routes which no longer correspond to a Node in
// the cluster. If the antrea agent restarts and Nodes have left the cluster, this function will
// take care of removing routes which are no longer valid.
func (c *Controller) removeStaleGatewayRoutes() error {
	nodes, err := c.nodeLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("error when listing Nodes: %v", err)
	}

	// We iterate over all current Nodes, including the Node on which this agent is
	// running, so the route to local Pods will be desired as well.
	var desiredPodCIDRs []string
	for _, node := range nodes {
		podCIDRs := getPodCIDRsOnNode(node)
		if len(podCIDRs) == 0 {
			continue
		}
		desiredPodCIDRs = append(desiredPodCIDRs, podCIDRs...)
	}

	// routeClient will remove orphaned routes whose destinations are not in desiredPodCIDRs.
	if err := c.routeClient.Reconcile(desiredPodCIDRs); err != nil {
		return err
	}
	return nil
}

// removeStaleTunnelPorts removes all the tunnel ports which no longer correspond to a Node in the
// cluster. If the antrea agent restarts and Nodes have left the cluster, this function will take
// care of removing tunnel ports which are no longer valid. If the tunnel port configuration has
// changed, the tunnel port will also be deleted (the controller loop will later take care of
// re-creating the port with the correct configuration).
func (c *Controller) removeStaleTunnelPorts() error {
	nodes, err := c.nodeLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("error when listing Nodes: %v", err)
	}
	// desiredInterfaces is the set of interfaces we wish to have, based on the current list of
	// Nodes. If a tunnel port corresponds to a valid Node but its configuration is wrong, we
	// will not include it in the set.
	desiredInterfaces := make(map[string]bool)
	// knownInterfaces is the list of interfaces currently in the local cache.
	knownInterfaces := c.interfaceStore.GetInterfaceKeysByType(interfacestore.IPSecTunnelInterface)

	if c.networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeIPSec {
		for _, node := range nodes {
			interfaceConfig, found := c.interfaceStore.GetNodeTunnelInterface(node.Name)
			if !found {
				// Tunnel port not created for this Node, nothing to do.
				continue
			}

			peerNodeIPs, err := k8s.GetNodeAddrs(node)
			if err != nil {
				klog.Errorf("Failed to retrieve IP address of Node %s: %v", node.Name, err)
				continue
			}
			var remoteName, psk string
			// remote_name and psk are mutually exclusive.
			switch c.networkConfig.IPsecConfig.AuthenticationMode {
			case config.IPsecAuthenticationModeCert:
				remoteName = node.Name
			case config.IPsecAuthenticationModePSK:
				psk = c.networkConfig.IPsecConfig.PSK
			}
			ifaceID := util.GenerateNodeTunnelInterfaceKey(node.Name)
			ifaceName := util.GenerateNodeTunnelInterfaceName(node.Name)
			if c.compareInterfaceConfig(interfaceConfig, peerNodeIPs.IPv4, psk, remoteName, ifaceName) || c.compareInterfaceConfig(interfaceConfig, peerNodeIPs.IPv6, psk, remoteName, ifaceName) {
				desiredInterfaces[ifaceID] = true
			}
		}
	}

	// remove all ports which are no longer needed or for which the configuration is no longer
	// valid.
	for _, ifaceID := range knownInterfaces {
		if _, found := desiredInterfaces[ifaceID]; found {
			// this interface matches an existing Node, nothing to do.
			continue
		}
		interfaceConfig, found := c.interfaceStore.GetInterface(ifaceID)
		if !found {
			// should not happen, nothing should have concurrent access to the interface
			// store for tunnel interfaces.
			klog.Errorf("Interface %s can no longer be found in the interface store", ifaceID)
			continue
		}
		if interfaceConfig.InterfaceName == c.nodeConfig.DefaultTunName {
			continue
		}
		if err := c.ovsBridgeClient.DeletePort(interfaceConfig.PortUUID); err != nil {
			klog.Errorf("Failed to delete OVS tunnel port %s: %v", interfaceConfig.InterfaceName, err)
		} else {
			c.interfaceStore.DeleteInterface(interfaceConfig)
		}
	}

	return nil
}

func (c *Controller) compareInterfaceConfig(interfaceConfig *interfacestore.InterfaceConfig,
	peerNodeIP net.IP, psk, remoteName, interfaceName string) bool {
	return interfaceConfig.InterfaceName == interfaceName &&
		interfaceConfig.PSK == psk &&
		interfaceConfig.RemoteName == remoteName &&
		interfaceConfig.RemoteIP.Equal(peerNodeIP) &&
		interfaceConfig.TunnelInterfaceConfig.Type == c.networkConfig.TunnelType
}

func (c *Controller) reconcile() error {
	klog.Infof("Reconciliation for %s", controllerName)
	// reconciliation consists of removing stale routes and stale / invalid tunnel ports:
	// missing routes and tunnel ports will be added normally by processNextWorkItem, which will
	// also take care of updating incorrect routes.
	if err := c.removeStaleGatewayRoutes(); err != nil {
		return fmt.Errorf("error when removing stale routes: %v", err)
	}
	if err := c.removeStaleTunnelPorts(); err != nil {
		return fmt.Errorf("error when removing stale tunnel ports: %v", err)
	}
	if err := c.removeStaleWireGuardPeers(); err != nil {
		return fmt.Errorf("error when removing stale WireGuard peers: %v", err)
	}
	return nil
}

// removeStaleWireGuardPeers deletes stale WireGuard peers if necessary.
func (c *Controller) removeStaleWireGuardPeers() error {
	if c.networkConfig.TrafficEncryptionMode != config.TrafficEncryptionModeWireGuard {
		return nil
	}
	nodes, err := c.nodeLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("error when listing Nodes: %v", err)
	}
	currentPeerPublicKeys := make(map[string]string)
	for _, n := range nodes {
		if pubkey, ok := n.Annotations[types.NodeWireGuardPublicAnnotationKey]; ok {
			currentPeerPublicKeys[n.Name] = pubkey
		}
	}
	return c.wireGuardClient.RemoveStalePeers(currentPeerPublicKeys)
}

// Run will create defaultWorkers workers (go routines) which will process the Node events from the
// workqueue.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	// If agent is running policy-only mode, it delegates routing to
	// underlying network. Therefore it needs not know the routes to
	// peer Pod CIDRs.
	if c.networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		c.flowRestoreCompleteWait.Done()
		<-stopCh
		return
	}

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	cacheSynced := []cache.InformerSynced{
		c.nodeListerSynced,
	}
	if c.networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeIPSec &&
		c.networkConfig.IPsecConfig.AuthenticationMode == config.IPsecAuthenticationModeCert {
		cacheSynced = append(cacheSynced, c.ipsecCertificateManager.HasSynced)
	}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSynced...) {
		return
	}

	if err := c.reconcile(); err != nil {
		klog.ErrorS(err, "Error during reconciliation", "controller", controllerName)
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

	go func() {
		// When the initial list of Nodes has been processed, we decrement flowRestoreCompleteWait.
		err := wait.PollUntilContextCancel(wait.ContextForChannel(stopCh), 100*time.Millisecond, true, func(ctx context.Context) (done bool, err error) {
			return c.HasSynced(), nil
		})
		// An error here means the context has been cancelled, which means that the stopCh
		// has been closed. While it is still possible for c.hasProcessedInitialList.HasSynced
		// to become true, as workers may not have returned yet, we should not decrement
		// flowRestoreCompleteWait or log the message below.
		if err != nil {
			return
		}
		c.flowRestoreCompleteWait.Done()
		klog.V(2).InfoS("Initial list of Nodes has been processed")
	}()

	<-stopCh
}

// HasSynced returns true when the initial list of Nodes has been processed by the controller.
func (c *Controller) HasSynced() bool {
	return c.hasProcessedInitialList.HasSynced()
}

// worker is a long-running function that will continually call the processNextWorkItem function in
// order to read and process a message on the workqueue.
func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem processes an item in the "node" work queue, by calling syncNodeRoute after
// casting the item to a string (Node name). If syncNodeRoute returns an error, this function
// handles it by requeueing the item so that it can be processed again later. If syncNodeRoute is
// successful, the Node is removed from the queue until we get notified of a new change. This
// function returns false if and only if the work queue was shutdown (no more items will be
// processed).
func (c *Controller) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	// We call Done here so the workqueue knows we have finished processing this item. We also
	// must remember to call Forget if we do not want this work item being re-queued. For
	// example, we do not call Forget if a transient error occurs, instead the item is put back
	// on the workqueue and attempted again after a back-off period.
	defer c.queue.Done(key)

	// We call Finished unconditionally even if this only matters for the initial list of
	// Nodes. There is no harm in calling Finished without a corresponding call to Start.
	defer c.hasProcessedInitialList.Finished(key)

	if err := c.syncNodeRoute(key); err == nil {
		// If no error occurs we Forget this item so it does not get queued again until
		// another change happens.
		c.queue.Forget(key)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.Errorf("Error syncing Node %s, requeuing. Error: %v", key, err)
	}
	return true
}

// syncNode manages connectivity to "peer" Node with name nodeName
// If we have not established connectivity to the Node yet:
//   - we install the appropriate Linux route:
//
// Destination     Gateway         Use Iface
// peerPodCIDR     peerGatewayIP   localGatewayIface (e.g antrea-gw0)
//   - we install the appropriate OpenFlow flows to ensure that all the traffic destined to
//     peerPodCIDR goes through the correct L3 tunnel.
//
// If the Node no longer exists (cannot be retrieved by name from nodeLister) we delete the route
// and OpenFlow flows associated with it.
func (c *Controller) syncNodeRoute(nodeName string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing Node Route for %s. (%v)", nodeName, time.Since(startTime))
	}()

	// The work queue guarantees that concurrent goroutines cannot call syncNodeRoute on the
	// same Node, which is required by the InstallNodeFlows / UninstallNodeFlows OF Client
	// methods.

	node, err := c.nodeLister.Get(nodeName)
	if err != nil {
		return c.deleteNodeRoute(nodeName)
	}
	return c.addNodeRoute(nodeName, node)
}

func (c *Controller) deleteNodeRoute(nodeName string) error {
	klog.Infof("Deleting routes and flows to Node %s", nodeName)

	obj, installed, _ := c.installedNodes.GetByKey(nodeName)
	if !installed {
		// Route is not added for this Node.
		return nil
	}
	nodeRouteInfo := obj.(*nodeRouteInfo)

	for _, podCIDR := range nodeRouteInfo.podCIDRs {
		if err := c.routeClient.DeleteRoutes(podCIDR); err != nil {
			return fmt.Errorf("failed to delete the route to Node %s: %v", nodeName, err)
		}
	}
	if err := c.ofClient.UninstallNodeFlows(nodeName); err != nil {
		return fmt.Errorf("failed to uninstall flows to Node %s: %v", nodeName, err)
	}
	c.installedNodes.Delete(obj)
	func() {
		subnets, _ := cidrsToPrefixes(nodeRouteInfo.podCIDRs)
		c.podSubnetsMutex.Lock()
		defer c.podSubnetsMutex.Unlock()
		c.podSubnets.Delete(subnets...)
	}()

	if c.networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeIPSec {
		interfaceConfig, ok := c.interfaceStore.GetNodeTunnelInterface(nodeName)
		if !ok {
			// Tunnel port not created for this Node.
			return nil
		}
		if err := c.ovsBridgeClient.DeletePort(interfaceConfig.PortUUID); err != nil {
			klog.Errorf("Failed to delete OVS tunnel port %s for Node %s: %v",
				interfaceConfig.InterfaceName, nodeName, err)
			return fmt.Errorf("failed to delete OVS tunnel port for Node %s", nodeName)
		}
		c.interfaceStore.DeleteInterface(interfaceConfig)
	}

	if c.networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeWireGuard {
		if err := c.wireGuardClient.DeletePeer(nodeName); err != nil {
			return fmt.Errorf("delete WireGuard peer %s failed: %v", nodeName, err)
		}
	}
	return nil
}

func (c *Controller) addNodeRoute(nodeName string, node *corev1.Node) error {
	// It is only for Windows Noencap mode to get Node MAC.
	peerNodeMAC, err := getNodeMAC(node)
	if err != nil {
		return fmt.Errorf("error when retrieving MAC of Node %s: %v", nodeName, err)
	}
	peerNodeIPs, err := k8s.GetNodeTransportAddrs(node)
	if err != nil {
		klog.ErrorS(err, "Failed to retrieve Node IP addresses", "node", node.Name)
		return err
	}
	peerWireGuardPublicKey := node.Annotations[types.NodeWireGuardPublicAnnotationKey]

	nrInfo, installed, _ := c.installedNodes.GetByKey(nodeName)
	// Route is already added for this Node and Node MAC, transport IP
	// and WireGuard public key are not changed.
	if installed && nrInfo.(*nodeRouteInfo).nodeMAC.String() == peerNodeMAC.String() &&
		peerNodeIPs.Equal(*nrInfo.(*nodeRouteInfo).nodeIPs) &&
		nrInfo.(*nodeRouteInfo).wireGuardPublicKey == peerWireGuardPublicKey {
		return nil
	}

	podCIDRStrs := getPodCIDRsOnNode(node)
	if len(podCIDRStrs) == 0 {
		// If no valid PodCIDR is configured in Node.Spec, return immediately.
		return nil
	}
	klog.InfoS("Adding routes and flows to Node", "Node", nodeName, "podCIDRs", podCIDRStrs,
		"addresses", node.Status.Addresses)

	var peerPodCIDRs []*net.IPNet
	peerConfigs := make(map[*net.IPNet]net.IP, len(podCIDRStrs))
	for _, podCIDR := range podCIDRStrs {
		if podCIDR == "" {
			klog.Errorf("PodCIDR is empty for Node %s", nodeName)
			// Does not help to return an error and trigger controller retries.
			return nil
		}

		nodesHaveSamePodCIDR, _ := c.installedNodes.IndexKeys(nodeRouteInfoPodCIDRIndexName, podCIDR)
		// PodCIDRs can be released from deleted Nodes and allocated to new Nodes. For server side, it won't happen that a
		// PodCIDR is allocated to more than one Node at any point. However, for client side, if a resync happens to occur
		// when there are Node creation and deletion events, the informer will generate the events in a way that all
		// creation events come before deletion ones even they actually happen in the opposite order on the server side.
		// See https://github.com/kubernetes/kubernetes/blob/v1.18.2/staging/src/k8s.io/client-go/tools/cache/delta_fifo.go#L503-L512
		// Therefore, a PodCIDR may appear in a new Node before the Node that previously owns it is removed. To ensure the
		// stale routes, flows, and relevant cache of this podCIDR are removed appropriately, we wait for the Node deletion
		// event to be processed before proceeding, or the route installation and uninstallation operations may override or
		// conflict with each other.
		// For Windows Noencap case, it is possible that nodesHaveSamePodCIDR is the Node itself because the Node
		// MAC annotation was not set yet when the Node was initially installed. Then it is processed for the second
		// time when its MAC annotation is updated.
		if len(nodesHaveSamePodCIDR) > 0 && (len(nodesHaveSamePodCIDR) != 1 || nodesHaveSamePodCIDR[0] != nodeName) {
			// Return an error so that the Node will be put back to the workqueue and will be retried later.
			return fmt.Errorf("skipping addNodeRoute for Node %s because podCIDR %s is duplicate with Node %s, will retry later", nodeName, podCIDR, nodesHaveSamePodCIDR[0])
		}

		peerPodCIDRAddr, peerPodCIDR, err := net.ParseCIDR(podCIDR)
		if err != nil {
			klog.Errorf("Failed to parse PodCIDR %s for Node %s", podCIDR, nodeName)
			return nil
		}
		peerGatewayIP := ip.NextIP(peerPodCIDRAddr)
		peerConfigs[peerPodCIDR] = peerGatewayIP
		peerPodCIDRs = append(peerPodCIDRs, peerPodCIDR)
		peerNodeIP := peerNodeIPs.IPv4
		if peerGatewayIP.To4() == nil {
			peerNodeIP = peerNodeIPs.IPv6
		}

		func() {
			subnet, _ := cidrToPrefix(peerPodCIDR)
			c.podSubnetsMutex.Lock()
			defer c.podSubnetsMutex.Unlock()
			c.podSubnets.Insert(subnet)
		}()

		klog.InfoS("Adding route and flow to Node", "Node", nodeName, "podCIDR", podCIDR,
			"peerNodeIP", peerNodeIP)
	}

	var ipsecTunOFPort uint32
	if c.networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeIPSec {
		// Create a separate tunnel port for the Node, as OVS IPsec monitor needs to
		// read PSK and remote IP from the Node's tunnel interface to create IPsec
		// security policies.
		peerNodeIP := peerNodeIPs.IPv4
		if peerNodeIP == nil {
			peerNodeIP = peerNodeIPs.IPv6
		}
		port, err := c.createIPSecTunnelPort(nodeName, peerNodeIP)
		if err != nil {
			return err
		}
		ipsecTunOFPort = uint32(port)
	}

	if c.networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeWireGuard && peerWireGuardPublicKey != "" {
		peerNodeIP := peerNodeIPs.IPv4
		if peerNodeIP == nil {
			peerNodeIP = peerNodeIPs.IPv6
		}
		if err := c.wireGuardClient.UpdatePeer(nodeName, peerWireGuardPublicKey, peerNodeIP, peerPodCIDRs); err != nil {
			return err
		}
	}

	if err = c.ofClient.InstallNodeFlows(
		nodeName,
		peerConfigs,
		peerNodeIPs,
		ipsecTunOFPort,
		peerNodeMAC); err != nil {
		return fmt.Errorf("failed to install flows to Node %s: %v", nodeName, err)
	}

	peerGatewayIPs := new(utilip.DualStackIPs)
	for peerPodCIDR, peerGatewayIP := range peerConfigs {
		if peerGatewayIP.To4() == nil {
			if err := c.routeClient.AddRoutes(peerPodCIDR, nodeName, peerNodeIPs.IPv6, peerGatewayIP); err != nil {
				return err
			}
			peerGatewayIPs.IPv6 = peerGatewayIP
		} else {
			if err := c.routeClient.AddRoutes(peerPodCIDR, nodeName, peerNodeIPs.IPv4, peerGatewayIP); err != nil {
				return err
			}
			peerGatewayIPs.IPv4 = peerGatewayIP
		}
	}

	c.installedNodes.Add(&nodeRouteInfo{
		nodeName:           nodeName,
		podCIDRs:           peerPodCIDRs,
		nodeIPs:            peerNodeIPs,
		gatewayIPs:         peerGatewayIPs,
		nodeMAC:            peerNodeMAC,
		wireGuardPublicKey: peerWireGuardPublicKey,
	})

	return err
}

func getPodCIDRsOnNode(node *corev1.Node) []string {
	if node.Spec.PodCIDRs != nil {
		return node.Spec.PodCIDRs
	}

	if node.Spec.PodCIDR == "" {
		klog.Errorf("PodCIDR is empty for Node %s", node.Name)
		// Does not help to return an error and trigger controller retries.
		return nil
	}
	return []string{node.Spec.PodCIDR}
}

// createIPSecTunnelPort creates an IPsec tunnel port for the remote Node if the
// tunnel does not exist, and returns the ofport number.
func (c *Controller) createIPSecTunnelPort(nodeName string, nodeIP net.IP) (int32, error) {
	portName := util.GenerateNodeTunnelInterfaceName(nodeName)
	interfaceConfig, exists := c.interfaceStore.GetNodeTunnelInterface(nodeName)

	var remoteName, psk string
	// remote_name and psk are mutually exclusive.
	switch c.networkConfig.IPsecConfig.AuthenticationMode {
	case config.IPsecAuthenticationModeCert:
		remoteName = nodeName
	case config.IPsecAuthenticationModePSK:
		psk = c.networkConfig.IPsecConfig.PSK
	}
	// check if Node IP, PSK, remote name, or tunnel type changes. This can
	// happen if removeStaleTunnelPorts fails to remove a "stale"
	// tunnel port for which the configuration has changed, return error to requeue the Node.
	if exists {
		if !c.compareInterfaceConfig(interfaceConfig, nodeIP, psk, remoteName, portName) {
			klog.InfoS("IPsec tunnel interface config doesn't match the cached one, deleting the stale IPsec tunnel port", "node", nodeName, "interface", interfaceConfig.InterfaceName)
			if err := c.ovsBridgeClient.DeletePort(interfaceConfig.PortUUID); err != nil {
				return 0, fmt.Errorf("fail to delete the stale IPsec tunnel port %s: %v", interfaceConfig.InterfaceName, err)
			}
			c.interfaceStore.DeleteInterface(interfaceConfig)
			exists = false
		}
	}

	if !exists {
		ovsExternalIDs := map[string]interface{}{
			ovsExternalIDNodeName:                 nodeName,
			interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaIPsecTunnel,
		}
		portUUID, err := c.ovsBridgeClient.CreateTunnelPortExt(
			portName,
			c.networkConfig.TunnelType,
			0, // ofPortRequest - let OVS allocate OFPort number.
			false,
			"",
			nodeIP.String(),
			remoteName,
			psk,
			nil,
			ovsExternalIDs)
		if err != nil {
			return 0, fmt.Errorf("failed to create IPsec tunnel port for Node %s", nodeName)
		}
		klog.Infof("Created IPsec tunnel port %s for Node %s", portName, nodeName)

		ovsPortConfig := &interfacestore.OVSPortConfig{PortUUID: portUUID}
		interfaceConfig = interfacestore.NewIPSecTunnelInterface(
			portName,
			c.networkConfig.TunnelType,
			nodeName,
			nodeIP,
			psk,
			remoteName,
			ovsPortConfig,
		)
		c.interfaceStore.AddInterface(interfaceConfig)
	}
	// GetOFPort will wait for up to 1 second for OVSDB to report the OFPort number.
	ofPort, err := c.ovsBridgeClient.GetOFPort(interfaceConfig.InterfaceName, false)
	if err != nil {
		// Could be a temporary OVSDB connection failure or timeout.
		// Let NodeRouteController retry at errors.
		return 0, fmt.Errorf("failed to get of_port of IPsec tunnel port for Node %s", nodeName)
	}

	// Set the port with no-flood to reject ARP flood packets.
	if err := c.ovsCtlClient.SetPortNoFlood(int(ofPort)); err != nil {
		return 0, fmt.Errorf("failed to set port %s with no-flood config: %w", portName, err)
	}

	interfaceConfig.OFPort = ofPort
	return ofPort, nil
}

// ParseTunnelInterfaceConfig initializes and returns an InterfaceConfig struct
// for a tunnel interface. It reads tunnel type, remote IP, IPsec PSK from the
// OVS interface options, and NodeName from the OVS port external_ids.
// nil is returned, if the OVS port and interface configurations are not valid
// for a tunnel interface.
func ParseTunnelInterfaceConfig(
	portData *ovsconfig.OVSPortData,
	portConfig *interfacestore.OVSPortConfig) *interfacestore.InterfaceConfig {
	if portData.Options == nil {
		klog.V(2).Infof("OVS port %s has no options", portData.Name)
		return nil
	}
	remoteIP, localIP, tunnelPort, psk, remoteName, csum := ovsconfig.ParseTunnelInterfaceOptions(portData)

	var interfaceConfig *interfacestore.InterfaceConfig
	var nodeName string
	if portData.ExternalIDs != nil {
		nodeName = portData.ExternalIDs[ovsExternalIDNodeName]
	}
	if psk != "" || remoteName != "" {
		interfaceConfig = interfacestore.NewIPSecTunnelInterface(
			portData.Name,
			ovsconfig.TunnelType(portData.IFType),
			nodeName,
			remoteIP,
			psk,
			remoteName,
			portConfig,
		)
	} else {
		interfaceConfig = interfacestore.NewTunnelInterface(
			portData.Name,
			ovsconfig.TunnelType(portData.IFType),
			tunnelPort,
			localIP,
			csum,
			portConfig)
	}
	return interfaceConfig
}

func (c *Controller) findPodSubnetForIP(ip netip.Addr) (netip.Prefix, bool) {
	var maskSize int
	if ip.Is4() {
		maskSize = c.maskSizeV4
	} else {
		maskSize = c.maskSizeV6
	}
	if maskSize == 0 {
		return netip.Prefix{}, false
	}
	prefix, _ := ip.Prefix(maskSize)
	c.podSubnetsMutex.RLock()
	defer c.podSubnetsMutex.RUnlock()
	return prefix, c.podSubnets.Has(prefix)
}

// LookupIPInPodSubnets returns two boolean values. The first one indicates whether the IP can be
// found in a PodCIDR for one of the cluster Nodes. The second one indicates whether the IP is used
// as a gwateway IP. The second boolean value can only be true if the first one is true.
func (c *Controller) LookupIPInPodSubnets(ip netip.Addr) (bool, bool) {
	prefix, ok := c.findPodSubnetForIP(ip)
	if !ok {
		return false, false
	}
	return ok, ip == util.GetGatewayIPForPodPrefix(prefix)
}

// getNodeMAC gets Node's br-int MAC from its annotation. It is only for Windows Noencap mode.
func getNodeMAC(node *corev1.Node) (net.HardwareAddr, error) {
	macStr := node.Annotations[types.NodeMACAddressAnnotationKey]
	if macStr == "" {
		return nil, nil
	}
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MAC `%s`: %v", macStr, err)
	}
	return mac, nil
}

func cidrToPrefix(cidr *net.IPNet) (netip.Prefix, error) {
	addr, ok := netip.AddrFromSlice(cidr.IP)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("invalid IP in cidr: %v", cidr)
	}
	size, _ := cidr.Mask.Size()
	return addr.Prefix(size)
}

func cidrsToPrefixes(cidrs []*net.IPNet) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, len(cidrs))
	for idx := range cidrs {
		prefix, err := cidrToPrefix(cidrs[idx])
		if err != nil {
			return nil, err
		}
		prefixes[idx] = prefix
	}
	return prefixes, nil
}
