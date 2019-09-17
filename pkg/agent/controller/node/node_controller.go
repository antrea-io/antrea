package node

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/vishvananda/netlink"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"okn/pkg/agent"
	"okn/pkg/agent/openflow"
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

type NodeController struct {
	kubeClient       clientset.Interface
	nodeInformer     coreinformers.NodeInformer
	nodeLister       corelisters.NodeLister
	nodeListerSynced cache.InformerSynced
	queue            workqueue.RateLimitingInterface
	ofClient         openflow.Client
	nodeConfig       *agent.NodeConfig
	gatewayLink      netlink.Link
	// connectedNodes records routes and flows installation states of nodes.
	// The key is the host name of the node, the value is the route to the node.
	// If the flows of the node are installed, the connectedNodes must contains a key which is the host name.
	// If the route of the node are installed, the flows of the node must be installed first and the value of host name
	// key must not be nil.
	// TODO: handle agent restart cases.
	connectedNodes *sync.Map
}

func NewNodeController(
	kubeClient clientset.Interface,
	informerFactory informers.SharedInformerFactory,
	client openflow.Client,
	config *agent.NodeConfig,
) *NodeController {
	nodeInformer := informerFactory.Core().V1().Nodes()
	link, _ := netlink.LinkByName(config.Gateway.Name)

	controller := &NodeController{
		kubeClient:       kubeClient,
		nodeInformer:     nodeInformer,
		nodeLister:       nodeInformer.Lister(),
		nodeListerSynced: nodeInformer.Informer().HasSynced,
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "node"),
		ofClient:         client,
		nodeConfig:       config,
		gatewayLink:      link,
		connectedNodes:   &sync.Map{},
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
func (c *NodeController) enqueueNode(obj interface{}) {
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

	if node.Name != c.nodeConfig.Name { // no need to connect itself
		c.queue.Add(node.Name)
	}

}

func (c *NodeController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.Info("Starting node controller")
	defer klog.Info("Shutting down node controller")

	klog.Info("Waiting for caches to sync for node controller")
	if !cache.WaitForCacheSync(stopCh, c.nodeListerSynced) {
		klog.Error("Unable to sync caches for node controller")
		return
	}
	klog.Info("Caches are synced for node controller")

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *NodeController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *NodeController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncNode(key.(string))
	c.handleErr(err, key)
	return true
}

func (c *NodeController) syncNode(nodeName string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing node %q. (%v)", nodeName, time.Since(startTime))
	}()

	if node, err := c.nodeLister.Get(nodeName); err != nil {
		klog.Infof("Deleting routes and flow entries to node %v", nodeName)
		route, flowsAreInstalled := c.connectedNodes.Load(nodeName)
		if route != nil {
			if err = netlink.RouteDel(route.(*netlink.Route)); err != nil {
				klog.Errorf("Failed to delete the route to the node %v: %v", nodeName, err)
				return err
			}
			c.connectedNodes.Store(nodeName, nil)
		}
		if flowsAreInstalled {
			if err = c.ofClient.UninstallNodeFlows(nodeName); err != nil {
				klog.Errorf("Failed to uninstall flows to the node %v: %v", nodeName, err)
				return err
			}
		}
		c.connectedNodes.Delete(nodeName)
	} else if route, flowsAreInstalled := c.connectedNodes.Load(nodeName); route == nil {
		klog.Infof("Adding routes and flows to node %v, podCIDR: %v, addresses: %v",
			nodeName, node.Spec.PodCIDR, node.Status.Addresses)

		peerPodCIDRAddr, peerPodCIDR, _ := net.ParseCIDR(node.Spec.PodCIDR)
		peerNodeIP, err := getNodeAddr(node)
		if err != nil {
			klog.Errorf("Failed to retrieve IP address of node: %v: %v", nodeName, err)
			return err
		}
		peerGatewayIP := ip.NextIP(peerPodCIDRAddr)

		if !flowsAreInstalled { // then install flows
			err = c.ofClient.InstallNodeFlows(nodeName, c.nodeConfig.Gateway.MAC, peerNodeIP, peerGatewayIP, *peerPodCIDR, peerNodeIP.String())
			if err != nil {
				return err
			}
			c.connectedNodes.Store(nodeName, nil)
		}
		// install route
		route := &netlink.Route{
			Dst:       peerPodCIDR,
			Flags:     int(netlink.FLAG_ONLINK),
			LinkIndex: c.gatewayLink.Attrs().Index,
			Gw:        peerGatewayIP,
		}
		err = netlink.RouteAdd(route)
		if err != nil {
			return err
		}
		c.connectedNodes.Store(nodeName, route)
	}
	return nil
}

func (c *NodeController) handleErr(err error, key interface{}) {
	if err == nil {
		c.queue.Forget(key)
		return
	}

	klog.V(2).Infof("Error syncing node %q, retrying. Error: %v", key, err)
	c.queue.AddRateLimited(key)
}

// getNodeAddr gets the available IP address of a node. getNodeAddr will first try to get the NodeInternalIP,
// then try to get the NodeExternalIP.
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
		return nil, fmt.Errorf("node %v has neither external ip nor internal ip", node.Name)
	}
	ipAddr := net.ParseIP(ipAddrStr)
	if ipAddr == nil {
		return nil, fmt.Errorf("<%v> is not a valid ip address", ipAddrStr)
	}
	return ipAddr, nil
}
