package networkpolicy

import (
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	networkinginformers "k8s.io/client-go/informers/networking/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

const (
	// Interval of synchronizing status from apiserver
	syncPeriod = 60 * time.Second
	// How long to wait before retrying the processing of a networkpolicy change
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing a networkpolicy change
	defaultWorkers = 4
)

var (
	keyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc
)

type NetworkPolicyController struct {
	kubeClient                clientset.Interface
	podInformer               coreinformers.PodInformer
	podLister                 corelisters.PodLister
	podListerSynced           cache.InformerSynced
	namespaceInformer         coreinformers.NamespaceInformer
	namespaceLister           corelisters.NamespaceLister
	namespaceListerSynced     cache.InformerSynced
	networkPolicyInformer     networkinginformers.NetworkPolicyInformer
	networkPolicyLister       networkinglisters.NetworkPolicyLister
	networkPolicyListerSynced cache.InformerSynced
	queue                     workqueue.RateLimitingInterface
}

func New(kubeClient clientset.Interface, podInformer coreinformers.PodInformer, namespaceInformer coreinformers.NamespaceInformer, networkPolicyInformer networkinginformers.NetworkPolicyInformer) (*NetworkPolicyController, error) {
	n := &NetworkPolicyController{
		kubeClient:                kubeClient,
		podInformer:               podInformer,
		podLister:                 podInformer.Lister(),
		podListerSynced:           podInformer.Informer().HasSynced,
		namespaceInformer:         namespaceInformer,
		namespaceLister:           namespaceInformer.Lister(),
		namespaceListerSynced:     namespaceInformer.Informer().HasSynced,
		networkPolicyInformer:     networkPolicyInformer,
		networkPolicyLister:       networkPolicyInformer.Lister(),
		networkPolicyListerSynced: networkPolicyInformer.Informer().HasSynced,
		queue:                     workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "networkpolicy"),
	}
	podInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(cur interface{}) {
			},
			UpdateFunc: func(old, cur interface{}) {
			},
			DeleteFunc: func(old interface{}) {
			},
		},
		syncPeriod,
	)
	namespaceInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(cur interface{}) {
			},
			UpdateFunc: func(old, cur interface{}) {
			},
			DeleteFunc: func(old interface{}) {
			},
		},
		syncPeriod,
	)
	networkPolicyInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(cur interface{}) {
				n.enqueueNetworkPolicy(cur)
			},
			UpdateFunc: func(old, cur interface{}) {
				n.enqueueNetworkPolicy(cur)
			},
			DeleteFunc: func(old interface{}) {
				n.enqueueNetworkPolicy(old)
			},
		},
		syncPeriod,
	)
	return n, nil
}

// enqueueNetworkPolicy adds an object to the controller work queue
// obj could be an *v1.NetworkPolicy, or a DeletionFinalStateUnknown item.
func (n *NetworkPolicyController) enqueueNetworkPolicy(obj interface{}) {
	key, err := keyFunc(obj)
	if err != nil {
		klog.Errorf("Couldn't get key for object %+v: %v", obj, err)
		return
	}

	n.queue.Add(key)
}

func (n *NetworkPolicyController) Run(stopCh <-chan struct{}) {
	defer n.queue.ShutDown()

	klog.Info("Starting networkpolicy controller")
	defer klog.Info("Shutting down networkpolicy controller")

	klog.Info("Waiting for caches to sync for networkpolicy controller")
	if !cache.WaitForCacheSync(stopCh, n.podListerSynced, n.namespaceListerSynced, n.networkPolicyListerSynced) {
		klog.Error("Unable to sync caches for networkpolicy controller")
		return
	}
	klog.Info("Caches are synced for networkpolicy controller")

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(n.worker, time.Second, stopCh)
	}
	<-stopCh
}

// worker runs a worker thread that just dequeues items, processes them, and marks them done.
// It enforces that the syncNetworkPolicy is never invoked concurrently with the same key.
func (n *NetworkPolicyController) worker() {
	for n.processNextWorkItem() {
	}
}

func (n *NetworkPolicyController) processNextWorkItem() bool {
	key, quit := n.queue.Get()
	if quit {
		return false
	}
	defer n.queue.Done(key)

	err := n.syncNetworkPolicy(key.(string))
	n.handleErr(err, key)
	return true
}

func (n *NetworkPolicyController) syncNetworkPolicy(key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing networkpolicy %q. (%v)", key, time.Since(startTime))
	}()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	networkPolicy, err := n.networkPolicyLister.NetworkPolicies(namespace).Get(name)
	if err != nil {
		klog.Errorf("Failed to get networkpolicy %v: %v", key, err)
		return err
	}
	klog.Infof("Syncing networkpolicy %v: %v", key, networkPolicy.Spec.PodSelector)
	return nil
}

func (n *NetworkPolicyController) handleErr(err error, key interface{}) {
	if err == nil {
		n.queue.Forget(key)
		return
	}

	klog.V(2).Infof("Error syncing networkpolicy %q, retrying. Error: %v", key, err)
	n.queue.AddRateLimited(key)
}
