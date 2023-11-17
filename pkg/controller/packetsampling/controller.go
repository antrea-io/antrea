package packetsampling

import (
	"context"
	"sync"
	"time"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/client/clientset/versioned"
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

	// How long to wait before retrying the processing of a traceflow.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second

	defaultTimeoutDuration = time.Second * time.Duration(crdv1alpha1.DefaultPacketSamplingTimeout)
)

var (
	timeoutCheckInterval = 10 * time.Second
)

type Controller struct {
	client                     versioned.Interface
	podInformer                coreinformers.PodInformer
	podLister                  corelisters.PodLister
	packetSamplingInformer     crdinformers.PacketSamplingInformer
	packetSamplingLister       crdlisters.PacketSamplingLister
	packetSamplingListerSynced cache.InformerSynced

	queue workqueue.RateLimitingInterface

	runningPacketSamplingMutex sync.Mutex
	runningPacketSamplings     map[string]string
}

func NewPacketSamplingController(client versioned.Interface, podInformer coreinformers.PodInformer, packetSamplingInformer crdinformers.PacketSamplingInformer) *Controller {

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
		}, resyncPeriod,
	)
	return c
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

func (c *Controller) startTraceflow() error {
	return nil
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
	return true
}

type packetSamplingUpdater struct {
	ps          *crdv1alpha1.PacketSampling
	controller  *Controller
	phase       *crdv1alpha1.PacketSamplingPhase
	reason      *string
	uid         *string
	tag         *int8
	packetsPath *string
}

func newPacketSamplingUpdater(base *crdv1alpha1.PacketSampling, c *Controller) *packetSamplingUpdater {
	return &packetSamplingUpdater{
		tf:         base,
		controller: c,
	}
}

func (u *packetSamplingUpdater) Phase(phase crdv1alpha1.PacketSamplingPhase) *packetSamplingUpdater {
	u.phase = &phase
	return u
}

func (u *packetSamplingUpdater) Reason(reason string) *packetSamplingUpdater {
	u.reason = &reason
	return u
}

func (u *packetSamplingUpdater) UID(uid string) *packetSamplingUpdater {
	u.uid = &uid
	return u
}

func (u *packetSamplingUpdater) PacketsPath(path string) *packetSamplingUpdater {
	u.packetsPath = &path
	return u
}

func (u *packetSamplingUpdater) Update() error {
	newPS := u.ps.DeepCopy()
	if u.phase != nil {
		newPS.Status.Phase = *u.phase
	}
	if u.ps.Status.Phase == crdv1alpha1.PacketSamplingRunning && u.ps.Status.StartTime == nil {
		time := metav1.Now()
		t.tf.Status.StartTime = &time
	}
	if t.tag != nil {
		newTF.Status.DataplaneTag = *t.tag
	}
	if t.reason != nil {
		newTF.Status.Reason = *t.reason
	}
	if t.packetsPath != nil {
		newTF.Status.Sampling.PacketsPath = *t.packetsPath
	}
	_, err := t.controller.client.CrdV1beta1().Traceflows().UpdateStatus(context.TODO(), newTF, metav1.UpdateOptions{})
	return err
}
