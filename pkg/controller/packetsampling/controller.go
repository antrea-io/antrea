package packetsampling

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

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

	tagStep   uint8 = 0b100
	minTagNum uint8 = 0b1*tagStep + 0b11
	maxTagNum uint8 = 0b1110*tagStep + 0b11

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

	runningPacketSamplingsMutex sync.Mutex
	runningPacketSamplings      map[uint8]string
}

func NewPacketSamplingController(client versioned.Interface, podInformer coreinformers.PodInformer, packetSamplingInformer crdinformers.PacketSamplingInformer) *Controller {

	c := &Controller{
		client:                     client,
		podInformer:                podInformer,
		packetSamplingInformer:     packetSamplingInformer,
		packetSamplingLister:       packetSamplingInformer.Lister(),
		packetSamplingListerSynced: packetSamplingInformer.Informer().HasSynced,
		queue:                      workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "packetsampling"),
		runningPacketSamplings:     make(map[uint8]string),
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

func (c *Controller) addPacketSampling(obj interface{}) {
	ps := obj.(*crdv1alpha1.PacketSampling)
	klog.V(2).Infof("Adding PacketSampling %s", ps.Name)
	c.enqueuePacketSampling(ps)
}

func (c *Controller) updatePacketSampling(_, cur interface{}) {
	ps := cur.(*crdv1alpha1.PacketSampling)
	klog.V(2).Infof("Updating PacketSampling %s", ps.Name)
	c.enqueuePacketSampling(ps)
}

func (c *Controller) deletePacketSampling(obj interface{}) {
	ps := obj.(*crdv1alpha1.PacketSampling)
	klog.V(2).Infof("Deleting PacketSampling %s", ps.Name)
	c.deallocateTagForPS(ps)
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

	pss, err := c.packetSamplingLister.List(labels.Everything())
	if err != nil {
		klog.Errorf("Failed to list all PacketSamplings: %v", err)
	}

	for _, ps := range pss {
		if ps.Status.Phase == crdv1alpha1.PacketSamplingRunning {
			if err := c.occupyTag(ps); err != nil {
				klog.Errorf("load packetsampling data plane tag failed: %+v+, %v", ps, err)
			}
		}
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh

}

func (c *Controller) worker() {
	for c.processPacketSamplingItem() {

	}
}

func (c *Controller) repostPacketSampling() {
	c.runningPacketSamplingsMutex.Lock()

	pss := make([]string, 0, len(c.runningPacketSamplings))
	for _, psName := range c.runningPacketSamplings {
		pss = append(pss, psName)
	}
	c.runningPacketSamplingsMutex.Unlock()

	for _, psName := range pss {
		c.queue.Add(psName)
	}

}

func (c *Controller) startPacketSampling(ps *crdv1alpha1.PacketSampling) error {
	tag, err := c.allocateTag(ps.Name)
	if err != nil {
		return err
	}
	if tag == 0 {
		return nil
	}
	err = c.updatePacketSamplingStatus(ps, crdv1alpha1.PacketSamplingRunning, "", tag)
	if err != nil {
		c.deallocateTag(ps.Name, tag)
	}
	return err
}

func (c *Controller) updatePacketSamplingStatus(ps *crdv1alpha1.PacketSampling, phase crdv1alpha1.PacketSamplingPhase, reason string, dataPlaneTag uint8) error {
	update := ps.DeepCopy()
	update.Status.Phase = phase
	if phase == crdv1alpha1.PacketSamplingRunning && update.Status.StartTime == nil {
		t := metav1.Now()
		update.Status.StartTime = &t
	}
	update.Status.DataplaneTag = dataPlaneTag
	if reason != "" {
		update.Status.Reason = reason
	}
	_, err := c.client.CrdV1alpha1().PacketSamplings().UpdateStatus(context.TODO(), update, metav1.UpdateOptions{})
	return err
}

// Allocates a tag. If the PacketSampling request has been allocated with a tag
// already, 0 is returned. If number of existing PacketSampling requests reaches
// the upper limit, an error is returned.
func (c *Controller) allocateTag(name string) (uint8, error) {
	c.runningPacketSamplingsMutex.Lock()
	defer c.runningPacketSamplingsMutex.Unlock()

	for _, n := range c.runningPacketSamplings {
		if n == name {
			// The packetsampling request has been processed already.
			return 0, nil
		}
	}
	for i := minTagNum; i <= maxTagNum; i += tagStep {
		if _, ok := c.runningPacketSamplings[i]; !ok {
			c.runningPacketSamplings[i] = name
			return i, nil
		}
	}
	return 0, fmt.Errorf("number of on-going packetsampling operations already reached the upper limit: %d", maxTagNum)
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

	err := c.syncPacketSampling(key)

	if err != nil {
		klog.Errorf("error sync packetSampling %s, existing,error: %v", key, err)
		c.queue.AddRateLimited(key)
	} else {
		c.queue.Forget(key)
	}

	return true
}

func (c *Controller) deallocateTagForPS(ps *crdv1alpha1.PacketSampling) {
	if ps.Status.DataplaneTag != 0 {
		c.deallocateTag(ps.Name, uint8(ps.Status.DataplaneTag))
	}
}

func (c *Controller) deallocateTag(name string, tag uint8) {
	c.runningPacketSamplingsMutex.Lock()
	defer c.runningPacketSamplingsMutex.Unlock()

	if existing, ok := c.runningPacketSamplings[tag]; ok {
		if name == existing {
			delete(c.runningPacketSamplings, tag)
		}
	}
}

func (c *Controller) occupyTag(ps *crdv1alpha1.PacketSampling) error {
	tag := uint8(ps.Status.DataplaneTag)

	if tag < minTagNum || tag > maxTagNum {
		return errors.New("this packetsamping crd's data plane tag is out of range")
	}
	c.runningPacketSamplingsMutex.Lock()
	defer c.runningPacketSamplingsMutex.Unlock()

	if exist, ok := c.runningPacketSamplings[tag]; ok {
		if ps.Name == exist {
			return nil
		}
		return errors.New("this packetsamping crd's data plane tag is already occupied")
	}
	c.runningPacketSamplings[tag] = ps.Name
	return nil

}

func (c *Controller) syncPacketSampling(name string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finsished sync for packetsampling for %s.(%v)", name, time.Since(startTime))
	}()

	ps, err := c.packetSamplingLister.Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	switch ps.Status.Phase {
	case "":
		err = c.startPacketSampling(ps)
	case crdv1alpha1.PacketSamplingRunning:
		err = c.checkPacketSamplingStatus(ps)
	case crdv1alpha1.PacketSamplingFailed:
		c.deallocateTagForPS(ps)
	}
	return err
}

type packetSamplingUpdater struct {
	ps          *crdv1alpha1.PacketSampling
	controller  *Controller
	phase       *crdv1alpha1.PacketSamplingPhase
	reason      *string
	uid         *string
	tag         *uint8
	packetsPath *string
}

func newPacketSamplingUpdater(base *crdv1alpha1.PacketSampling, c *Controller) *packetSamplingUpdater {
	return &packetSamplingUpdater{
		ps:         base,
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

func (u *packetSamplingUpdater) Tag(tag uint8) *packetSamplingUpdater {
	u.tag = &tag
	return u
}

func (u *packetSamplingUpdater) Update() error {
	newPS := u.ps.DeepCopy()
	if u.phase != nil {
		newPS.Status.Phase = *u.phase
	}
	if u.ps.Status.Phase == crdv1alpha1.PacketSamplingRunning && u.ps.Status.StartTime == nil {
		time := metav1.Now()
		u.ps.Status.StartTime = &time
	}
	if u.tag != nil {
		newPS.Status.DataplaneTag = *u.tag
	}
	if u.reason != nil {
		newPS.Status.Reason = *u.reason
	}
	if u.packetsPath != nil {
		newPS.Status.PacketsPath = *u.packetsPath
	}
	_, err := u.controller.client.CrdV1alpha1().PacketSamplings().UpdateStatus(context.TODO(), newPS, metav1.UpdateOptions{})
	return err
}

// checkTraceflowStatus is only called for Traceflows in the Running phase
func (c *Controller) checkPacketSamplingStatus(ps *crdv1alpha1.PacketSampling) error {
	if checkPacketSamplingSucceeded(ps) {
		c.deallocateTagForPS(ps)
		return newPacketSamplingUpdater(ps, c).
			Phase(crdv1alpha1.PacketSamplingSucceeded).
			Tag(0).
			Update()
	}

	if checkPacketSamplingTimeout(ps) {
		c.deallocateTagForPS(ps)
		return newPacketSamplingUpdater(ps, c).
			Phase(crdv1alpha1.PacketSamplingFailed).
			//TODO: var
			Reason("Timeout").
			Tag(0).
			Update()
	}

	return nil
}

func checkPacketSamplingSucceeded(ps *crdv1alpha1.PacketSampling) bool {
	succeeded := false
	if ps.Spec.Type == crdv1alpha1.FirstNSampling && ps.Status.NumCapturedPackets == ps.Spec.FirstNSamplingConfig.Number {
		succeeded = true
	}
	return succeeded
}

func checkPacketSamplingTimeout(ps *crdv1alpha1.PacketSampling) bool {
	var timeout time.Duration
	if ps.Spec.Timeout != 0 {
		timeout = time.Duration(ps.Spec.Timeout) * time.Second
	} else {
		timeout = defaultTimeoutDuration
	}
	var startTime time.Time
	if ps.Status.StartTime != nil {
		startTime = ps.Status.StartTime.Time
	} else {
		// a fallback that should not be needed in general since we are in the Running phase
		// when upgrading Antrea from a previous version, the field would be empty
		klog.V(2).InfoS("StartTime field in PacketSampling Status should not be empty", "Traceflow", klog.KObj(ps))
		startTime = ps.CreationTimestamp.Time
	}
	return startTime.Add(timeout).Before(time.Now())
}
