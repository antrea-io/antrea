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
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/route"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
)

const (
	controllerName = "AntreaAgentNodeRouteController"
	// Interval of reprocessing every node.
	nodeResyncPeriod = 60 * time.Second
	// How long to wait before retrying the processing of a node change
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing a node change
	defaultWorkers = 4

	ovsExternalIDNodeName = "node-name"
)

// Controller is responsible for setting up necessary IP routes and Openflow entries for inter-node traffic.
type Controller struct {
	kubeClient       clientset.Interface
	ovsBridgeClient  ovsconfig.OVSBridgeClient
	ofClient         openflow.Client
	routeClient      route.Interface
	interfaceStore   interfacestore.InterfaceStore
	networkConfig    *config.NetworkConfig
	nodeConfig       *config.NodeConfig
	nodeInformer     coreinformers.NodeInformer
	nodeLister       corelisters.NodeLister
	nodeListerSynced cache.InformerSynced
	queue            workqueue.RateLimitingInterface
	// installedNodes records routes and flows installation states of Nodes.
	// The key is the host name of the Node, the value is the podCIDR of the Node.
	// A node will be in the map after its flows and routes are installed successfully.
	installedNodes *sync.Map
}

// NewNodeRouteController instantiates a new Controller object which will process Node events
// and ensure connectivity between different Nodes.
func NewNodeRouteController(
	kubeClient clientset.Interface,
	informerFactory informers.SharedInformerFactory,
	client openflow.Client,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	routeClient route.Interface,
	interfaceStore interfacestore.InterfaceStore,
	networkConfig *config.NetworkConfig,
	nodeConfig *config.NodeConfig) *Controller {
	nodeInformer := informerFactory.Core().V1().Nodes()
	controller := &Controller{
		kubeClient:       kubeClient,
		ovsBridgeClient:  ovsBridgeClient,
		ofClient:         client,
		routeClient:      routeClient,
		interfaceStore:   interfaceStore,
		networkConfig:    networkConfig,
		nodeConfig:       nodeConfig,
		nodeInformer:     nodeInformer,
		nodeLister:       nodeInformer.Lister(),
		nodeListerSynced: nodeInformer.Informer().HasSynced,
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "noderoute"),
		installedNodes:   &sync.Map{}}
	nodeInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(cur interface{}) {
				controller.enqueueNode(cur)
			},
			UpdateFunc: func(old, cur interface{}) {
				controller.enqueueNode(cur)
			},
			DeleteFunc: func(old interface{}) {
				controller.enqueueNode(old)
			},
		},
		nodeResyncPeriod,
	)
	return controller
}

// enqueueNode adds an object to the controller work queue
// obj could be an *v1.Node, or a DeletionFinalStateUnknown item.
func (c *Controller) enqueueNode(obj interface{}) {
	node, isNode := obj.(*v1.Node)
	if !isNode {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Received unexpected object: %v", obj)
			return
		}
		node, ok = deletedState.Obj.(*v1.Node)
		if !ok {
			klog.Errorf("DeletedFinalStateUnknown contains non-Node object: %v", deletedState.Obj)
			return
		}
	}

	// Ignore notifications for this Node, no need to establish connectivity to itself.
	if node.Name != c.nodeConfig.Name {
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
		// PodCIDR is allocated by K8s NodeIpamController asynchronously so it's possible we see a Node
		// with no PodCIDR set when it just joins the cluster.
		if node.Spec.PodCIDR == "" {
			continue
		}
		desiredPodCIDRs = append(desiredPodCIDRs, node.Spec.PodCIDR)
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
	knownInterfaces := c.interfaceStore.GetInterfaceKeysByType(interfacestore.TunnelInterface)

	if c.networkConfig.EnableIPSecTunnel {
		for _, node := range nodes {
			interfaceConfig, found := c.interfaceStore.GetNodeTunnelInterface(node.Name)
			if !found {
				// Tunnel port not created for this Node, nothing to do.
				continue
			}

			peerNodeIP, err := GetNodeAddr(node)
			if err != nil {
				klog.Errorf("Failed to retrieve IP address of Node %s: %v", node.Name, err)
				continue
			}

			ifaceID := util.GenerateNodeTunnelInterfaceKey(node.Name)
			validConfiguration := interfaceConfig.PSK == c.networkConfig.IPSecPSK &&
				interfaceConfig.RemoteIP.Equal(peerNodeIP) &&
				interfaceConfig.TunnelInterfaceConfig.Type == c.networkConfig.TunnelType
			if validConfiguration {
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
		if interfaceConfig.InterfaceName == config.DefaultTunPortName {
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
	return nil
}

// Run will create defaultWorkers workers (go routines) which will process the Node events from the
// workqueue.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	// If agent is running policy-only mode, it delegates routing to
	// underlying network. Therefore it needs not know the routes to
	// peer Pod CIDRs.
	if c.networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		<-stopCh
		return
	}

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	klog.Infof("Waiting for caches to sync for %s", controllerName)
	if !cache.WaitForCacheSync(stopCh, c.nodeListerSynced) {
		klog.Errorf("Unable to sync caches for %s", controllerName)
		return
	}
	klog.Infof("Caches are synced for %s", controllerName)

	if err := c.reconcile(); err != nil {
		klog.Errorf("Error during %s reconciliation", controllerName)
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
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
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	// We call Done here so the workqueue knows we have finished processing this item. We also
	// must remember to call Forget if we do not want this work item being re-queued. For
	// example, we do not call Forget if a transient error occurs, instead the item is put back
	// on the workqueue and attempted again after a back-off period.
	defer c.queue.Done(obj)

	// We expect strings (Node name) to come off the workqueue.
	if key, ok := obj.(string); !ok {
		// As the item in the workqueue is actually invalid, we call Forget here else we'd
		// go into a loop of attempting to process a work item that is invalid.
		// This should not happen: enqueueNode only enqueues strings.
		c.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else if err := c.syncNodeRoute(key); err == nil {
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
//   * we install the appropriate Linux route:
// Destination     Gateway         Use Iface
// peerPodCIDR     peerGatewayIP   localGatewayIface (e.g gw0)
//   * we install the appropriate OpenFlow flows to ensure that all the traffic destined to
//   peerPodCIDR goes through the correct L3 tunnel.
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

	podCIDR, installed := c.installedNodes.Load(nodeName)
	if !installed {
		// Route is not added for this Node.
		return nil
	}

	if err := c.routeClient.DeleteRoutes(podCIDR.(*net.IPNet)); err != nil {
		return fmt.Errorf("failed to delete the route to Node %s: %v", nodeName, err)
	}

	if err := c.ofClient.UninstallNodeFlows(nodeName); err != nil {
		return fmt.Errorf("failed to uninstall flows to Node %s: %v", nodeName, err)
	}
	c.installedNodes.Delete(nodeName)

	if c.networkConfig.EnableIPSecTunnel {
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
	return nil
}

func (c *Controller) addNodeRoute(nodeName string, node *v1.Node) error {
	if _, installed := c.installedNodes.Load(nodeName); installed {
		// Route is already added for this Node.
		return nil
	}

	klog.Infof("Adding routes and flows to Node %s, podCIDR: %s, addresses: %v",
		nodeName, node.Spec.PodCIDR, node.Status.Addresses)

	if node.Spec.PodCIDR == "" {
		klog.Errorf("PodCIDR is empty for Node %s", nodeName)
		// Does not help to return an error and trigger controller retries.
		return nil
	}
	peerPodCIDRAddr, peerPodCIDR, err := net.ParseCIDR(node.Spec.PodCIDR)
	if err != nil {
		klog.Errorf("Failed to parse PodCIDR %s for Node %s", node.Spec.PodCIDR, nodeName)
		return nil
	}
	peerNodeIP, err := GetNodeAddr(node)
	if err != nil {
		klog.Errorf("Failed to retrieve IP address of Node %s: %v", nodeName, err)
		return nil
	}
	peerGatewayIP := ip.NextIP(peerPodCIDRAddr)

	ipsecTunOFPort := int32(0)
	if c.networkConfig.EnableIPSecTunnel {
		// Create a separate tunnel port for the Node, as OVS IPSec monitor needs to
		// read PSK and remote IP from the Node's tunnel interface to create IPSec
		// security policies.
		if ipsecTunOFPort, err = c.createIPSecTunnelPort(nodeName, peerNodeIP); err != nil {
			return err
		}
	}

	err = c.ofClient.InstallNodeFlows(
		nodeName,
		c.nodeConfig.GatewayConfig.MAC,
		*peerPodCIDR,
		peerGatewayIP,
		peerNodeIP,
		config.DefaultTunOFPort,
		uint32(ipsecTunOFPort))
	if err != nil {
		return fmt.Errorf("failed to install flows to Node %s: %v", nodeName, err)
	}

	if err := c.routeClient.AddRoutes(peerPodCIDR, peerNodeIP, peerGatewayIP); err != nil {
		return err
	}
	c.installedNodes.Store(nodeName, peerPodCIDR)
	return err
}

// createIPSecTunnelPort creates an IPSec tunnel port for the remote Node if the
// tunnel does not exist, and returns the ofport number.
func (c *Controller) createIPSecTunnelPort(nodeName string, nodeIP net.IP) (int32, error) {
	interfaceConfig, ok := c.interfaceStore.GetNodeTunnelInterface(nodeName)
	if ok {
		// TODO: check if Node IP, PSK, or tunnel type changes. This can
		// happen if removeStaleTunnelPorts fails to remove a "stale"
		// tunnel port for which the configuration has changed.
		if interfaceConfig.OFPort != 0 {
			return interfaceConfig.OFPort, nil
		}
	} else {
		portName := util.GenerateNodeTunnelInterfaceName(nodeName)
		ovsExternalIDs := map[string]interface{}{ovsExternalIDNodeName: nodeName}
		portUUID, err := c.ovsBridgeClient.CreateTunnelPortExt(
			portName,
			c.networkConfig.TunnelType,
			0, // ofPortRequest - let OVS allocate OFPort number.
			"",
			nodeIP.String(),
			c.networkConfig.IPSecPSK,
			ovsExternalIDs)
		if err != nil {
			return 0, fmt.Errorf("failed to create IPSec tunnel port for Node %s", nodeName)
		}
		klog.Infof("Created IPSec tunnel port %s for Node %s", portName, nodeName)

		ovsPortConfig := &interfacestore.OVSPortConfig{PortUUID: portUUID}
		interfaceConfig = interfacestore.NewIPSecTunnelInterface(
			portName,
			c.networkConfig.TunnelType,
			nodeName,
			nodeIP,
			c.networkConfig.IPSecPSK)
		interfaceConfig.OVSPortConfig = ovsPortConfig
		c.interfaceStore.AddInterface(interfaceConfig)
	}

	// GetOFPort will wait for up to 1 second for OVSDB to report the OFPort number.
	ofPort, err := c.ovsBridgeClient.GetOFPort(interfaceConfig.InterfaceName)
	if err != nil {
		// Could be a temporary OVSDB connection failure or timeout.
		// Let NodeRouteController retry at errors.
		return 0, fmt.Errorf("failed to get of_port of IPSec tunnel port for Node %s", nodeName)
	}
	interfaceConfig.OFPort = ofPort
	return ofPort, nil
}

// ParseTunnelInterfaceConfig initializes and returns an InterfaceConfig struct
// for a tunnel interface. It reads tunnel type, remote IP, IPSec PSK from the
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
	remoteIP, localIP, psk := ovsconfig.ParseTunnelInterfaceOptions(portData)

	var interfaceConfig *interfacestore.InterfaceConfig
	var nodeName string
	if portData.ExternalIDs != nil {
		nodeName = portData.ExternalIDs[ovsExternalIDNodeName]
	}
	if psk != "" {
		interfaceConfig = interfacestore.NewIPSecTunnelInterface(
			portData.Name,
			ovsconfig.TunnelType(portData.IFType),
			nodeName,
			remoteIP,
			psk)
	} else {
		interfaceConfig = interfacestore.NewTunnelInterface(portData.Name, ovsconfig.TunnelType(portData.IFType), localIP)
	}
	interfaceConfig.OVSPortConfig = portConfig
	return interfaceConfig
}

// GetNodeAddr gets the available IP address of a Node. GetNodeAddr will first try to get the
// NodeInternalIP, then try to get the NodeExternalIP.
func GetNodeAddr(node *v1.Node) (net.IP, error) {
	addresses := make(map[v1.NodeAddressType]string)
	for _, addr := range node.Status.Addresses {
		addresses[addr.Type] = addr.Address
	}
	var ipAddrStr string
	if internalIP, ok := addresses[v1.NodeInternalIP]; ok {
		ipAddrStr = internalIP
	} else if externalIP, ok := addresses[v1.NodeExternalIP]; ok {
		ipAddrStr = externalIP
	} else {
		return nil, fmt.Errorf("node %s has neither external ip nor internal ip", node.Name)
	}
	ipAddr := net.ParseIP(ipAddrStr)
	if ipAddr == nil {
		return nil, fmt.Errorf("<%v> is not a valid ip address", ipAddrStr)
	}
	return ipAddr, nil
}
