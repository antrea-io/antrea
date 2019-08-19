package node

import (
	"time"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
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
}

func NewNodeController(kubeClient clientset.Interface, informerFactory informers.SharedInformerFactory) *NodeController {
	nodeInformer := informerFactory.Core().V1().Nodes()
	n := &NodeController{
		kubeClient:       kubeClient,
		nodeInformer:     nodeInformer,
		nodeLister:       nodeInformer.Lister(),
		nodeListerSynced: nodeInformer.Informer().HasSynced,
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "node"),
	}
	nodeInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(cur interface{}) {
				n.enqueueNode(cur)
			},
			UpdateFunc: func(old, cur interface{}) {
				n.enqueueNode(cur)
			},
			DeleteFunc: func(old interface{}) {
				n.enqueueNode(old)
			},
		},
		nodeSyncPeriod,
	)
	return n
}

// enqueueNode adds an object to the controller work queue
// obj could be an *v1.Node, or a DeletionFinalStateUnknown item.
func (n *NodeController) enqueueNode(obj interface{}) {
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
	n.queue.Add(node.Name)
}

func (n *NodeController) Run(stopCh <-chan struct{}) {
	defer n.queue.ShutDown()

	klog.Info("Starting node controller")
	defer klog.Info("Shutting down node controller")

	klog.Info("Waiting for caches to sync for node controller")
	if !cache.WaitForCacheSync(stopCh, n.nodeListerSynced) {
		klog.Error("Unable to sync caches for node controller")
		return
	}
	klog.Info("Caches are synced for node controller")

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(n.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (n *NodeController) worker() {
	for n.processNextWorkItem() {
	}
}

func (n *NodeController) processNextWorkItem() bool {
	key, quit := n.queue.Get()
	if quit {
		return false
	}
	defer n.queue.Done(key)

	err := n.syncNode(key.(string))
	n.handleErr(err, key)
	return true
}

func (n *NodeController) syncNode(nodeName string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing node %q. (%v)", nodeName, time.Since(startTime))
	}()

	node, err := n.nodeLister.Get(nodeName)
	if err != nil {
		klog.Errorf("Failed to get node %v: %v", nodeName, err)
	}
	// TODO: Get podCIDR and status.addresses to setup routes and tunnels
	klog.Infof("Syncing node %v, podCIDR: %v, addresses: %v", nodeName, node.Spec.PodCIDR, node.Status.Addresses)
	return nil
}

func (n *NodeController) handleErr(err error, key interface{}) {
	if err == nil {
		n.queue.Forget(key)
		return
	}

	klog.V(2).Infof("Error syncing node %q, retrying. Error: %v", key, err)
	n.queue.AddRateLimited(key)
}
