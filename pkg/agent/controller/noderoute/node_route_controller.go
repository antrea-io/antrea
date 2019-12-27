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
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
)

const (
	// Interval of synchronizing node status from apiserver
	nodeSyncPeriod = 60 * time.Second
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
	nodeInformer     coreinformers.NodeInformer
	nodeLister       corelisters.NodeLister
	nodeListerSynced cache.InformerSynced
	queue            workqueue.RateLimitingInterface
	ofClient         openflow.Client
	ovsBridgeClient  ovsconfig.OVSBridgeClient
	interfaceStore   interfacestore.InterfaceStore
	nodeConfig       *types.NodeConfig
	tunnelType       ovsconfig.TunnelType
	// Pre-shared key for IPSec IKE authentication. If not empty IPSec tunnels will
	// be enabled.
	ipsecPSK    string
	gatewayLink netlink.Link
	// installedNodes records routes and flows installation states of Nodes.
	// The key is the host name of the Node, the value is the route to the Node.
	// If the flows of the Node are installed, the installedNodes must contains a key which is the host name.
	// If the route of the Node are installed, the flows of the Node must be installed first and the value of host name
	// key must not be nil.
	// TODO: handle agent restart cases.
	installedNodes *sync.Map
}

func NewNodeRouteController(
	kubeClient clientset.Interface,
	informerFactory informers.SharedInformerFactory,
	client openflow.Client,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	interfaceStore interfacestore.InterfaceStore,
	config *types.NodeConfig,
	tunnelType ovsconfig.TunnelType,
	ipsecPSK string,
) *Controller {
	nodeInformer := informerFactory.Core().V1().Nodes()
	link, _ := netlink.LinkByName(config.GatewayConfig.Name)

	controller := &Controller{
		kubeClient:       kubeClient,
		nodeInformer:     nodeInformer,
		nodeLister:       nodeInformer.Lister(),
		nodeListerSynced: nodeInformer.Informer().HasSynced,
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "noderoute"),
		ofClient:         client,
		ovsBridgeClient:  ovsBridgeClient,
		interfaceStore:   interfaceStore,
		nodeConfig:       config,
		gatewayLink:      link,
		installedNodes:   &sync.Map{},
		tunnelType:       tunnelType,
		ipsecPSK:         ipsecPSK}
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
		nodeSyncPeriod,
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

func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.Info("Starting Node Route controller")
	defer klog.Info("Shutting down Node Route controller")

	klog.Info("Waiting for caches to sync for Node Route controller")
	if !cache.WaitForCacheSync(stopCh, c.nodeListerSynced) {
		klog.Error("Unable to sync caches for Node Route controller")
		return
	}
	klog.Info("Caches are synced for Node Route controller")

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

// Processes an item in the "node" work queue, by calling syncNodeRoute after casting the item to a
// string (Node name). If syncNodeRoute returns an error, this function handles it by requeueing the item
// so that it can be processed again later. If syncNodeRoute is successful, the Node is removed from the
// queue until we get notify of a new change. This function return false if and only if the work
// queue was shutdown (no more items will be processed).
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

// Manages connectivity to "peer" Node with name nodeName
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

	if node, err := c.nodeLister.Get(nodeName); err != nil {
		return c.deleteNodeRoute(nodeName)
	} else {
		return c.addNodeRoute(nodeName, node)
	}
}

func (c *Controller) deleteNodeRoute(nodeName string) error {
	klog.Infof("Deleting routes and flows to Node %s", nodeName)

	route, flowsAreInstalled := c.installedNodes.Load(nodeName)
	if route != nil {
		if err := netlink.RouteDel(route.(*netlink.Route)); err != nil {
			return fmt.Errorf("failed to delete the route to Node %s: %v", nodeName, err)
		}
		c.installedNodes.Store(nodeName, nil)
	}

	if flowsAreInstalled {
		if err := c.ofClient.UninstallNodeFlows(nodeName); err != nil {
			return fmt.Errorf("failed to uninstall flows to Node %s: %v", nodeName, err)
		}
		c.installedNodes.Delete(nodeName)
	}

	if c.ipsecPSK != "" {
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
	}
	return nil
}

func (c *Controller) addNodeRoute(nodeName string, node *v1.Node) error {
	entry, flowsAreInstalled := c.installedNodes.Load(nodeName)
	if entry != nil {
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
	peerNodeIP, err := getNodeAddr(node)
	if err != nil {
		klog.Errorf("Failed to retrieve IP address of Node %s: %v", nodeName, err)
		return nil
	}
	peerGatewayIP := ip.NextIP(peerPodCIDRAddr)

	var tunOFPort int32
	var remoteIP net.IP
	if c.ipsecPSK != "" {
		// Create a separate tunnel port for the Node, as OVS does not support flow
		// based tunnel for IPSec.
		if tunOFPort, err = c.createIPSecTunnelPort(nodeName, peerNodeIP); err != nil {
			return err
		}
		remoteIP = nil
	} else {
		// Use the default tunnel port.
		tunOFPort = types.DefaultTunOFPort
		// Flow based tunnel. Set remote IP in the OVS flow.
		remoteIP = peerNodeIP
	}

	if !flowsAreInstalled { // then install flows
		err = c.ofClient.InstallNodeFlows(
			nodeName,
			c.nodeConfig.GatewayConfig.MAC,
			peerGatewayIP,
			*peerPodCIDR,
			remoteIP,
			uint32(tunOFPort))
		if err != nil {
			return fmt.Errorf("failed to install flows to Node %s: %v", nodeName, err)
		}
		c.installedNodes.Store(nodeName, nil)
	}

	// install route
	route := &netlink.Route{
		Dst:       peerPodCIDR,
		Flags:     int(netlink.FLAG_ONLINK),
		LinkIndex: c.gatewayLink.Attrs().Index,
		Gw:        peerGatewayIP,
	}

	err = netlink.RouteAdd(route)
	// This is likely to be caused by an agent restart and so should not happen once we
	// handle state reconciliation on restart properly. However, it is probably better
	// to handle this case gracefully for the time being.
	if err == unix.EEXIST {
		klog.Warningf("Route to Node %s already exists, replacing it", nodeName)
		err = netlink.RouteReplace(route)
	}
	if err != nil {
		return fmt.Errorf("failed to install route to Node %s with netlink: %v", nodeName, err)
	}
	c.installedNodes.Store(nodeName, route)
	return nil
}

// createIPSecTunnelPort creates an IPSec tunnel port for the remote Node if the
// tunnel does not exist, and returns the ofport number.
func (c *Controller) createIPSecTunnelPort(nodeName string, nodeIP net.IP) (int32, error) {
	interfaceConfig, ok := c.interfaceStore.GetNodeTunnelInterface(nodeName)
	if ok {
		// TODO: check if Node IP, PSK, or tunnel type changes or handle it in
		// reconciliation.
		if interfaceConfig.OFPort != 0 {
			return interfaceConfig.OFPort, nil
		}
	} else {
		portName := util.GenerateTunnelInterfaceName(nodeName)
		ovsExternalIDs := map[string]interface{}{ovsExternalIDNodeName: nodeName}
		portUUID, err := c.ovsBridgeClient.CreateTunnelPortExt(
			portName,
			c.tunnelType,
			0, // ofPortRequest - let OVS allocate OFPort number.
			nodeIP.String(),
			c.ipsecPSK,
			ovsExternalIDs)
		if err != nil {
			klog.Errorf("Failed to create OVS IPSec tunnel port for Node %s: %v", nodeName, err)
			return 0, fmt.Errorf("failed to create IPSec tunnel port for Node %s", nodeName)
		}
		ovsPortConfig := &interfacestore.OVSPortConfig{PortUUID: portUUID}
		interfaceConfig = interfacestore.NewIPSecTunnelInterface(
			nodeName,
			c.tunnelType,
			nodeName,
			nodeIP,
			c.ipsecPSK)
		interfaceConfig.OVSPortConfig = ovsPortConfig
		c.interfaceStore.AddInterface(interfaceConfig)
	}

	// GetOFPort will wait for up to 1 second for OVSDB to report the OFPort number.
	ofPort, err := c.ovsBridgeClient.GetOFPort(interfaceConfig.InterfaceName)
	if err != nil {
		// Could be a temporary OVSDB connection failure or timeout.
		// Let NodeRouteController retry at errors.
		klog.Errorf("Failed to get of_port of the tunnel port for Node %s: %v", nodeName, err)
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
	remoteIP, psk := ovsconfig.ParseTunnelInterfaceOptions(portData)

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
		interfaceConfig = interfacestore.NewTunnelInterface(portData.Name, ovsconfig.TunnelType(portData.IFType))
	}
	interfaceConfig.OVSPortConfig = portConfig
	return interfaceConfig
}

// getNodeAddr gets the available IP address of a Node. getNodeAddr will first try to get the
// NodeInternalIP, then try to get the NodeExternalIP.
func getNodeAddr(node *v1.Node) (net.IP, error) {
	addresses := make(map[v1.NodeAddressType]string)
	for _, addr := range node.Status.Addresses {
		addresses[addr.Type] = addr.Address
	}
	var ipAddrStr string
	if internalIp, ok := addresses[v1.NodeInternalIP]; ok {
		ipAddrStr = internalIp
	} else if externalIp, ok := addresses[v1.NodeExternalIP]; ok {
		ipAddrStr = externalIp
	} else {
		return nil, fmt.Errorf("Node %s has neither external ip nor internal ip", node.Name)
	}
	ipAddr := net.ParseIP(ipAddrStr)
	if ipAddr == nil {
		return nil, fmt.Errorf("<%v> is not a valid ip address", ipAddrStr)
	}
	return ipAddr, nil
}
