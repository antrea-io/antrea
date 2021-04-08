// Copyright 2020 Antrea Authors
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

package traceflow

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	crdv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/crd/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	crdinformers "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "github.com/vmware-tanzu/antrea/pkg/client/listers/crd/v1alpha1"
)

const (
	controllerName = "TraceflowController"

	// Set resyncPeriod to 0 to disable resyncing.
	resyncPeriod time.Duration = 0

	// How long to wait before retrying the processing of a traceflow.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second

	// Default number of workers processing traceflow request.
	defaultWorkers = 4

	// Min and max data plane tag for traceflow. minTagNum is 7 (0b000111), maxTagNum is 59 (0b111011).
	// As per RFC2474, 16 different DSCP values are we reserved for Experimental or Local Use, which we use as the 16 possible data plane tag values.
	// tagStep is 4 (0b100) to keep last 2 bits at 0b11.
	tagStep   uint8 = 0b100
	minTagNum uint8 = 0b1*tagStep + 0b11
	maxTagNum uint8 = 0b1110*tagStep + 0b11

	// PodIP index name for Pod cache.
	podIPsIndex = "podIPs"

	// String set to TraceflowStatus.Reason.
	traceflowTimeout = "Traceflow timeout"

	// Traceflow timeout period.
	defaultTimeoutDuration = time.Second * time.Duration(crdv1alpha1.DefaultTraceflowTimeout)
)

var (
	timeoutCheckInterval = 10 * time.Second
)

// Controller is for traceflow.
type Controller struct {
	client                 versioned.Interface
	podInformer            coreinformers.PodInformer
	traceflowInformer      crdinformers.TraceflowInformer
	traceflowLister        crdlisters.TraceflowLister
	traceflowListerSynced  cache.InformerSynced
	queue                  workqueue.RateLimitingInterface
	runningTraceflowsMutex sync.Mutex
	runningTraceflows      map[uint8]string // tag->traceflowName if tf.Status.Phase is Running.
}

// NewTraceflowController creates a new traceflow controller and adds podIP indexer to podInformer.
func NewTraceflowController(client versioned.Interface, podInformer coreinformers.PodInformer, traceflowInformer crdinformers.TraceflowInformer) *Controller {
	c := &Controller{
		client:                client,
		podInformer:           podInformer,
		traceflowInformer:     traceflowInformer,
		traceflowLister:       traceflowInformer.Lister(),
		traceflowListerSynced: traceflowInformer.Informer().HasSynced,
		queue:                 workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "traceflow"),
		runningTraceflows:     make(map[uint8]string)}
	// Add handlers for ClusterNetworkPolicy events.
	traceflowInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addTraceflow,
			UpdateFunc: c.updateTraceflow,
			DeleteFunc: c.deleteTraceflow,
		},
		resyncPeriod,
	)
	// Add IP-Pod index. Each Pod has no more than 2 IPs, the extra overhead is constant and acceptable.
	// @tnqn evaluated the performance without/with IP index is 3us vs 4us per pod, i.e. 300ms vs 400ms for 100k Pods.
	podInformer.Informer().AddIndexers(cache.Indexers{podIPsIndex: podIPsIndexFunc})
	return c
}

func podIPsIndexFunc(obj interface{}) ([]string, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("obj is not pod: %+v", obj)
	}
	if pod.Status.PodIPs != nil && len(pod.Status.PodIPs) > 0 && pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed {
		indexes := make([]string, len(pod.Status.PodIPs))
		for i := range pod.Status.PodIPs {
			indexes[i] = pod.Status.PodIPs[i].IP
		}
		return indexes, nil
	}
	return nil, nil
}

// enqueueTraceflow adds an object to the controller work queue.
func (c *Controller) enqueueTraceflow(tf *crdv1alpha1.Traceflow) {
	c.queue.Add(tf.Name)
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.traceflowListerSynced) {
		return
	}

	// Load all data plane tags from CRD into controller's cache.
	tfs, err := c.traceflowLister.List(labels.Everything())
	if err != nil {
		klog.Errorf("Failed to list all Antrea Traceflows")
	}
	for _, tf := range tfs {
		if tf.Status.Phase == crdv1alpha1.Running {
			if err := c.occupyTag(tf); err != nil {
				klog.Errorf("Load Traceflow data plane tag failed %v+: %v", tf, err)
			}
		}
	}

	go func() {
		wait.Until(c.checkTraceflowTimeout, timeoutCheckInterval, stopCh)
	}()

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *Controller) addTraceflow(obj interface{}) {
	tf := obj.(*crdv1alpha1.Traceflow)
	klog.Infof("Processing Traceflow %s ADD event", tf.Name)
	c.enqueueTraceflow(tf)
}

func (c *Controller) updateTraceflow(_, curObj interface{}) {
	tf := curObj.(*crdv1alpha1.Traceflow)
	klog.Infof("Processing Traceflow %s UPDATE event", tf.Name)
	c.enqueueTraceflow(tf)
}

func (c *Controller) deleteTraceflow(old interface{}) {
	tf := old.(*crdv1alpha1.Traceflow)
	klog.Infof("Processing Traceflow %s DELETE event", tf.Name)
	c.deallocateTagForTF(tf)
}

// worker is a long-running function that will continually call the processTraceflowItem function
// in order to read and process a message on the workqueue.
func (c *Controller) worker() {
	for c.processTraceflowItem() {
	}
}

func (c *Controller) checkTraceflowTimeout() {
	c.runningTraceflowsMutex.Lock()
	tfs := make([]string, 0, len(c.runningTraceflows))
	for _, tfName := range c.runningTraceflows {
		tfs = append(tfs, tfName)
	}
	c.runningTraceflowsMutex.Unlock()

	for _, tfName := range tfs {
		// Re-post all running Traceflow requests to the work queue to
		// be processed and checked for timeout.
		c.queue.Add(tfName)
	}
}

// processTraceflowItem processes an item in the "traceflow" work queue, by calling syncTraceflow
// after casting the item to a string (Traceflow name). If syncTraceflow returns an error, this
// function logs the error and adds the Traceflow request back to the queue with a rate limit. If
// no error occurs, the Traceflow request is removed from the queue until we get notified of a new
// change. This function returns false if and only if the work queue was shutdown (no more items
// will be processed).
func (c *Controller) processTraceflowItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	// We call Done here so the workqueue knows we have finished processing this item. We also
	// must remember to call Forget if we do not want this work item being re-queued. For
	// example, we do not call Forget if a transient error occurs, instead the item is put back
	// on the workqueue and attempted again after a back-off period.
	defer c.queue.Done(obj)

	// We expect strings (Traceflow name) to come off the workqueue.
	if key, ok := obj.(string); !ok {
		// As the item in the workqueue is actually invalid, we call Forget here else we'd
		// go into a loop of attempting to process a work item that is invalid.
		// This should not happen: enqueueTraceflow only enqueues strings.
		c.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else {
		err := c.syncTraceflow(key)
		if err != nil {
			klog.Errorf("Error syncing Traceflow %s, exiting. Error: %v", key, err)
			c.queue.AddRateLimited(key)
		} else {
			c.queue.Forget(key)
		}
	}
	return true
}

func (c *Controller) syncTraceflow(traceflowName string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing Traceflow for %s. (%v)", traceflowName, time.Since(startTime))
	}()

	tf, err := c.traceflowLister.Get(traceflowName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Traceflow CRD has been deleted.
			return nil
		}
		return err
	}
	switch tf.Status.Phase {
	case "", crdv1alpha1.Pending:
		err = c.startTraceflow(tf)
	case crdv1alpha1.Running:
		err = c.checkTraceflowStatus(tf)
	case crdv1alpha1.Failed:
		// Deallocate tag when agent set Traceflow status to Failed.
		c.deallocateTagForTF(tf)
	}
	return err
}

func (c *Controller) startTraceflow(tf *crdv1alpha1.Traceflow) error {
	// Allocate data plane tag.
	tag, err := c.allocateTag(tf.Name)
	if err != nil {
		return err
	}
	if tag == 0 {
		return nil
	}

	err = c.updateTraceflowStatus(tf, crdv1alpha1.Running, "", tag)
	if err != nil {
		c.deallocateTag(tf.Name, tag)
	}
	return err
}

func (c *Controller) checkTraceflowStatus(tf *crdv1alpha1.Traceflow) error {
	succeeded := false
	if tf.Spec.LiveTraffic && tf.Spec.DroppedOnly {
		// There should be only one reported NodeResult for droppedOnly
		// Traceflow.
		if len(tf.Status.Results) > 0 {
			succeeded = true
		}
	} else {
		sender := false
		receiver := false
		for i, nodeResult := range tf.Status.Results {
			for j, ob := range nodeResult.Observations {
				if ob.Component == crdv1alpha1.ComponentSpoofGuard {
					sender = true
				}
				if ob.Action == crdv1alpha1.ActionDelivered ||
					ob.Action == crdv1alpha1.ActionDropped ||
					ob.Action == crdv1alpha1.ActionForwardedOutOfOverlay {
					receiver = true
				}
				if ob.TranslatedDstIP != "" {
					// Add Pod ns/name to observation if TranslatedDstIP (a.k.a. Service Endpoint address) is Pod IP.
					pods, err := c.podInformer.Informer().GetIndexer().ByIndex(podIPsIndex, ob.TranslatedDstIP)
					if err != nil {
						klog.Infof("Unable to find Pod from IP, error: %+v", err)
					} else if len(pods) > 0 {
						pod, ok := pods[0].(*corev1.Pod)
						if !ok {
							klog.Warningf("Invalid Pod obj in cache")
						} else {
							tf.Status.Results[i].Observations[j].Pod = fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
						}
					}
				}
			}
		}
		succeeded = sender && receiver
	}
	if succeeded {
		c.deallocateTagForTF(tf)
		return c.updateTraceflowStatus(tf, crdv1alpha1.Succeeded, "", 0)
	}

	timeoutSeconds := int64(tf.Spec.Timeout)
	if timeoutSeconds == 0 {
		timeoutSeconds = int64(defaultTimeoutDuration.Seconds())
	}
	// CreationTimestamp is of second accuracy.
	if time.Now().Unix() > tf.CreationTimestamp.Unix()+timeoutSeconds {
		c.deallocateTagForTF(tf)
		return c.updateTraceflowStatus(tf, crdv1alpha1.Failed, traceflowTimeout, 0)
	}
	return nil
}

func (c *Controller) updateTraceflowStatus(tf *crdv1alpha1.Traceflow, phase crdv1alpha1.TraceflowPhase, reason string, dataPlaneTag uint8) error {
	update := tf.DeepCopy()
	update.Status.Phase = phase
	update.Status.DataplaneTag = dataPlaneTag
	if reason != "" {
		update.Status.Reason = reason
	}
	_, err := c.client.CrdV1alpha1().Traceflows().UpdateStatus(context.TODO(), update, metav1.UpdateOptions{})
	return err
}

func (c *Controller) occupyTag(tf *crdv1alpha1.Traceflow) error {
	tag := tf.Status.DataplaneTag
	if tag < minTagNum || tag > maxTagNum {
		return errors.New("this Traceflow CRD's data plane tag is out of range")
	}

	c.runningTraceflowsMutex.Lock()
	defer c.runningTraceflowsMutex.Unlock()
	if existingTraceflowName, ok := c.runningTraceflows[tag]; ok {
		if tf.Name == existingTraceflowName {
			return nil
		} else {
			return errors.New("this Traceflow's CRD data plane tag is already taken")
		}
	}

	c.runningTraceflows[tag] = tf.Name
	return nil
}

// Allocates a tag. If the Traceflow request has been allocated with a tag
// already, 0 is returned. If number of existing Traceflow requests reaches
// the upper limit, an error is returned.
func (c *Controller) allocateTag(name string) (uint8, error) {
	c.runningTraceflowsMutex.Lock()
	defer c.runningTraceflowsMutex.Unlock()

	for _, n := range c.runningTraceflows {
		if n == name {
			// The Traceflow request has been processed already.
			return 0, nil
		}
	}
	for i := minTagNum; i <= maxTagNum; i += tagStep {
		if _, ok := c.runningTraceflows[i]; !ok {
			c.runningTraceflows[i] = name
			return i, nil
		}
	}
	return 0, fmt.Errorf("number of on-going Traceflow operations already reached the upper limit: %d", maxTagNum)
}

// Deallocates tag from cache. Ignore DataplaneTag == 0 which is an invalid case.
func (c *Controller) deallocateTagForTF(tf *crdv1alpha1.Traceflow) {
	if tf.Status.DataplaneTag != 0 {
		c.deallocateTag(tf.Name, tf.Status.DataplaneTag)
	}
}

func (c *Controller) deallocateTag(name string, tag uint8) {
	c.runningTraceflowsMutex.Lock()
	defer c.runningTraceflowsMutex.Unlock()
	if existingTraceflowName, ok := c.runningTraceflows[tag]; ok {
		if name == existingTraceflowName {
			delete(c.runningTraceflows, tag)
		}
	}
}
