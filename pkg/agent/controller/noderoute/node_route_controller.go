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

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
)

const (
	// Interval of synchronizing node status from apiserver
	nodeSyncPeriod = 60 * time.Second
	// How long to wait before retrying the processing of a node change
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing a node change
	defaultWorkers = 4
)

// Controller is responsible for setting up necessary IP routes and Openflow entries for inter-node traffic.
type Controller struct {
	kubeClient       clientset.Interface
	nodeInformer     coreinformers.NodeInformer
	nodeLister       corelisters.NodeLister
	nodeListerSynced cache.InformerSynced
	queue            workqueue.RateLimitingInterface
	ofClient         openflow.Client
	nodeConfig       *types.NodeConfig
	gatewayLink      netlink.Link
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
	config *types.NodeConfig,
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
		nodeConfig:       config,
		gatewayLink:      link,
		installedNodes:   &sync.Map{},
	}
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
		klog.Infof("Deleting routes and flow entries to Node %s", nodeName)
		route, flowsAreInstalled := c.installedNodes.Load(nodeName)
		if route != nil {
			if err = netlink.RouteDel(route.(*netlink.Route)); err != nil {
				return fmt.Errorf("failed to delete the route to Node %s: %v", nodeName, err)
			}
			c.installedNodes.Store(nodeName, nil)
		}
		if flowsAreInstalled {
			if err = c.ofClient.UninstallNodeFlows(nodeName); err != nil {
				return fmt.Errorf("failed to uninstall flows to Node %s: %v", nodeName, err)
			}
		}
		c.installedNodes.Delete(nodeName)
	} else if route, flowsAreInstalled := c.installedNodes.Load(nodeName); route == nil {
		klog.Infof("Adding routes and flows to Node %s, podCIDR: %s, addresses: %v",
			nodeName, node.Spec.PodCIDR, node.Status.Addresses)
		if node.Spec.PodCIDR == "" {
			klog.V(1).Infof("PodCIDR is empty for peer node %s", nodeName)
			return nil
		}

		peerPodCIDRAddr, peerPodCIDR, err := net.ParseCIDR(node.Spec.PodCIDR)
		if err != nil {
			return fmt.Errorf("failed to parse PodCIDR %s", node.Spec.PodCIDR)
		}
		peerNodeIP, err := getNodeAddr(node)
		if err != nil {
			return fmt.Errorf("failed to retrieve IP address of Node %s: %v", nodeName, err)
		}
		peerGatewayIP := ip.NextIP(peerPodCIDRAddr)

		if !flowsAreInstalled { // then install flows
			err = c.ofClient.InstallNodeFlows(nodeName, c.nodeConfig.GatewayConfig.MAC, peerGatewayIP, *peerPodCIDR, peerNodeIP)
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
	}
	return nil
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
