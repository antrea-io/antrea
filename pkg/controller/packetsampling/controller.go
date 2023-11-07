package packetsampling

import (
	"sync"
	"time"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog"

	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	"k8s.io/client-go/tools/cache"

	"k8s.io/client-go/util/workqueue"
)

const (
	controllerName = "PacketSamplingController"

	// set resyncPeriod to 0 to disable resyncing
	resyncPeriod time.Duration = 0

	// Default number of workers processing packetsampling request.
	defaultWorkers = 4

	// reason for timeout
	samplingTimeout = "PacketSampling timeout"

	defaultTimeoutDuration = time.Second * time.Duration(crdv1alpha1.DefaultPacketSamplingTimeout)
)

var (
	timeoutCheckInterval = 10 * time.Second
)

type Controller struct {
	client                     versiond.Interface
	podInformer                coreinformers.PodInformer
	podLister                  corelisters.PodLister
	packetSamplingInformer     crdinformers.PacketSamplingInformer
	packetSamplingLister       crdlisters.PacketSamplingLister
	packetSamplingListerSynced cache.InformerSynced

	queue workqueue.RateLimitingInterface

	runningPacketSamplingMutex sync.Mutex
	runningPacketSamplings     map[string]string
}

func NewPacketSamplingController(client versiond.Interface, podInformer coreinformers.PodInformer, packetSamplingInformer crdinformers.PacketSamplingInformer) *Controller {

	c := &Controller{
		client:                     client,
		podInformer:                podInformer,
		packetSamplingInformer:     packetSamplingInformer,
		packetSamplingLister:       packetSamplingInformer.Lister(),
		packetSamplingListerSynced: packetSamplingInformer.Informer().HasSynced,
		queue:                      workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "packetsampling"),
	}

	// add handlers
	packetSamplingInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addPacketSampling,
			UpdateFunc: c.updatePacketSampling,
			DeleteFunc: c.deletePacketSampling,
		},
	)
}

func (c *Controller) enqueuePacketSampling(ps *crdv1alpha1.PacketSampling) {
	c.queue.Add(ps.Name)
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()
	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.packetSamplingListerSynced) {
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

}

func (c *Controller) worker() {
	for c.processPacketSamplingItem() {

	}
}

func (c *Controller) repostPacketSampling() {
	c.runningPacketSamplingMutex.Lock()

	pss := make([]string, 0, len(c.runningPacketSamplings))
	for _, psName := range c.runningPacketSamplings {
		pss = append(pss, psName)
	}
	c.runningPacketSamplingMutex.Unlock()

	for _, psName := range pss {
		c.queue.Add(psName)
	}

}

func (c *Controller) processPacketSamplingItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(obj)

	key, ok := obj.(string)
	if !ok {
		c.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	}
}
