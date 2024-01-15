// Copyright 2023 Antrea Authors
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

package l7flowexporter

import (
	"fmt"
	"strings"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/controller/networkpolicy/l7engine"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	controllerName               = "L7FlowExporterController"
	resyncPeriod   time.Duration = 0 * time.Second
	minRetryDelay                = 5 * time.Second
	maxRetryDelay                = 300 * time.Second
	defaultWorkers               = 4
)

var (
	errInvalidAnnotation    = fmt.Errorf("annotation key %s can only have values (Ingress/Egress/Both)", types.L7FlowExporterAnnotationKey)
	errPodInterfaceNotFound = fmt.Errorf("interface of Pod not found")
)

type L7FlowExporterController struct {
	ofClient       openflow.Client
	interfaceStore interfacestore.InterfaceStore

	podInformer     cache.SharedIndexInformer
	podLister       corelisters.PodLister
	podListerSynced cache.InformerSynced

	namespaceInformer     cache.SharedIndexInformer
	namespaceLister       corelisters.NamespaceLister
	namespaceListerSynced cache.InformerSynced

	l7Reconciler           *l7engine.Reconciler
	podToDirectionMap      map[string]v1alpha2.Direction
	podToDirectionMapMutex sync.RWMutex

	targetPort uint32

	queue workqueue.RateLimitingInterface
}

func NewL7FlowExporterController(
	ofClient openflow.Client,
	interfaceStore interfacestore.InterfaceStore,
	podInformer cache.SharedIndexInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	l7Reconciler *l7engine.Reconciler) *L7FlowExporterController {
	l7c := &L7FlowExporterController{
		ofClient:              ofClient,
		interfaceStore:        interfaceStore,
		podInformer:           podInformer,
		podLister:             corelisters.NewPodLister(podInformer.GetIndexer()),
		podListerSynced:       podInformer.HasSynced,
		namespaceInformer:     namespaceInformer.Informer(),
		namespaceLister:       namespaceInformer.Lister(),
		namespaceListerSynced: namespaceInformer.Informer().HasSynced,
		l7Reconciler:          l7Reconciler,
		podToDirectionMap:     make(map[string]v1alpha2.Direction),
		queue:                 workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "L7FlowExporterController"),
	}
	l7c.podInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    l7c.addPod,
			UpdateFunc: l7c.updatePod,
			DeleteFunc: l7c.deletePod,
		},
		resyncPeriod,
	)
	l7c.namespaceInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    l7c.addNamespace,
			UpdateFunc: l7c.updateNamespace,
		},
		resyncPeriod,
	)
	return l7c
}

func (l7c *L7FlowExporterController) Run(stopCh <-chan struct{}) {
	defer l7c.queue.ShutDown()
	klog.InfoS("Starting", "Controller", controllerName)
	defer klog.InfoS("Shutting down", "Controller", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, l7c.podListerSynced, l7c.namespaceListerSynced) {
		return
	}
	// Interface is expected to be present as it is created during Antrea agent initialization.
	if intf, ok := l7c.interfaceStore.GetInterfaceByName(config.L7RedirectTargetPortName); ok {
		l7c.targetPort = uint32(intf.OFPort)
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(l7c.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (l7c *L7FlowExporterController) worker() {
	for l7c.processNextWorkItem() {
	}
}

func (l7c *L7FlowExporterController) processNextWorkItem() bool {
	obj, quit := l7c.queue.Get()
	if quit {
		return false
	}
	defer l7c.queue.Done(obj)

	if key, ok := obj.(string); !ok {
		// As the item in the work queue is actually invalid, we call Forget here else we'd
		// go into a loop of attempting to process a work item that is invalid.
		// This should not happen.
		l7c.queue.Forget(key)
		klog.ErrorS(nil, "Expected string in work queue but got", "key", obj)
		return true
	} else if err := l7c.syncPod(key); err == nil {
		// If no error occurs we Forget this item, so it does not get queued again until
		// another change happens.
		l7c.queue.Forget(key)
	} else if err == errInvalidAnnotation {
		// Handle errors
		// Do not add key again to the queue if annotation is incorrect
		klog.ErrorS(err, "Syncing Pod object for L7FlowExporter failed", "Pod", key)
		l7c.queue.Forget(key)
	} else {
		// Put the item back on the work queue to handle any transient errors.
		l7c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Syncing Pod object for L7FlowExporter failed, requeue", "Pod", key)
	}
	return true
}

func (l7c *L7FlowExporterController) addPod(obj interface{}) {
	pod := obj.(*v1.Pod)
	if !isValidPod(pod) {
		return
	}
	podNS, err := l7c.namespaceLister.Get(pod.Namespace)
	if err != nil {
		return
	}
	// Both Pod and Namespace are not annotated, return
	_, podOK := pod.Annotations[types.L7FlowExporterAnnotationKey]
	_, nsOK := podNS.Annotations[types.L7FlowExporterAnnotationKey]
	if !podOK && !nsOK {
		return
	}

	klog.V(2).InfoS("Processing Pod ADD event", "Pod", klog.KObj(pod))
	podNN := k8s.NamespacedName(pod.Namespace, pod.Name)
	l7c.queue.Add(podNN)
}

func (l7c *L7FlowExporterController) updatePod(oldObj interface{}, obj interface{}) {
	oldPod := oldObj.(*v1.Pod)
	updatedPod := obj.(*v1.Pod)
	if !isValidPod(updatedPod) {
		return
	}
	oldAnnotation := oldPod.Annotations[types.L7FlowExporterAnnotationKey]
	updatedAnnotation, updatedAnnotationOk := updatedPod.Annotations[types.L7FlowExporterAnnotationKey]
	if oldAnnotation == updatedAnnotation {
		if !updatedAnnotationOk {
			return
		}
		if oldPod.Status.PodIP == updatedPod.Status.PodIP {
			return
		}
	}

	klog.V(2).InfoS("Processing Pod UPDATE event", "Pod", klog.KObj(updatedPod))
	podNN := k8s.NamespacedName(updatedPod.Namespace, updatedPod.Name)
	l7c.queue.Add(podNN)
}

func (l7c *L7FlowExporterController) deletePod(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(nil, "Received unexpected object", "object", obj)
			return
		}
		pod, ok = deletedState.Obj.(*v1.Pod)
		if !ok {
			klog.ErrorS(nil, "DeletedFinalStateUnknown contains non-Pod object", "object", deletedState.Obj)
			return
		}
	}
	if _, ok := pod.Annotations[types.L7FlowExporterAnnotationKey]; !ok {
		if !l7c.namespaceAnnotationExists(pod) {
			return
		}
	}

	klog.V(2).InfoS("Processing Pod DELETE event", "Pod", klog.KObj(pod))
	podNN := k8s.NamespacedName(pod.Namespace, pod.Name)
	l7c.queue.Add(podNN)
}

func (l7c *L7FlowExporterController) namespaceAnnotationExists(pod *v1.Pod) bool {
	podNamespace, err := l7c.namespaceLister.Get(pod.Namespace)
	if err != nil {
		return false
	}
	_, ok := podNamespace.Annotations[types.L7FlowExporterAnnotationKey]
	return ok
}

func isValidPod(pod *v1.Pod) bool {
	return pod.Status.PodIP != "" && !pod.Spec.HostNetwork
}

func (l7c *L7FlowExporterController) addNamespace(obj interface{}) {
	ns := obj.(*v1.Namespace)
	if _, ok := ns.Annotations[types.L7FlowExporterAnnotationKey]; !ok {
		return
	}
	klog.V(2).InfoS("Processing Namespace ADD event", "Namespace", klog.KObj(ns))
	affectedPods := l7c.getNonAnnotatedPodsFromNamespace(ns)
	for _, pod := range affectedPods {
		podNN := k8s.NamespacedName(pod.Namespace, pod.Name)
		l7c.queue.Add(podNN)
	}
}

func (l7c *L7FlowExporterController) updateNamespace(oldObj, obj interface{}) {
	oldNS := oldObj.(*v1.Namespace)
	updatedNS := obj.(*v1.Namespace)
	oldAnnotation := oldNS.GetAnnotations()[types.L7FlowExporterAnnotationKey]
	updatedAnnotation := updatedNS.GetAnnotations()[types.L7FlowExporterAnnotationKey]
	if oldAnnotation == updatedAnnotation {
		return
	}

	klog.V(2).InfoS("Processing Namespace UPDATE event", "Namespace", klog.KObj(updatedNS))

	affectedPods := l7c.getNonAnnotatedPodsFromNamespace(updatedNS)
	for _, pod := range affectedPods {
		podNN := k8s.NamespacedName(pod.Namespace, pod.Name)
		l7c.queue.Add(podNN)
	}
}

func (l7c *L7FlowExporterController) getNonAnnotatedPodsFromNamespace(ns *v1.Namespace) []*v1.Pod {
	var nonAnnotatedPods []*v1.Pod
	pods, _ := l7c.podLister.Pods(ns.Name).List(labels.Everything())

	// Only select the non annotated Pods, as annotated Pods are handled separately
	for _, pod := range pods {
		_, ok := pod.Annotations[types.L7FlowExporterAnnotationKey]
		if !ok {
			nonAnnotatedPods = append(nonAnnotatedPods, pod)
		}
	}
	return nonAnnotatedPods
}

func (l7c *L7FlowExporterController) syncPod(podNN string) error {
	podNamespace, podName := k8s.SplitNamespacedName(podNN)
	pod, err := l7c.podLister.Pods(podNamespace).Get(podName)
	if err != nil {
		// Remove the TC flows if the Pod has been deleted
		return l7c.removeTCFlow(podNN)
	}
	if !isValidPod(pod) {
		return nil
	}
	annotationValue, ok := pod.Annotations[types.L7FlowExporterAnnotationKey]
	if !ok {
		podNS, err := l7c.namespaceLister.Get(pod.Namespace)
		if err != nil {
			// Remove TC flows if Namespace has been deleted
			return l7c.removeTCFlow(podNN)
		}
		// Both Pod and Namespace are not annotated, remove the TC Mark flow
		annotationValue, ok = podNS.Annotations[types.L7FlowExporterAnnotationKey]
		if !ok {
			return l7c.removeTCFlow(podNN)
		}
	}

	// Check if the annotation value is one of the specified values
	direction, err := checkIfAnnotationCorrect(annotationValue)
	if err != nil {
		return err
	}
	podInterfaces := l7c.interfaceStore.GetContainerInterfacesByPod(pod.Name, pod.Namespace)
	if len(podInterfaces) == 0 {
		return errPodInterfaceNotFound
	}
	sourceOfPort := []uint32{uint32(podInterfaces[0].OFPort)}

	// Start Suricata before starting traffic control mark flows
	l7c.l7Reconciler.StartSuricataOnce()

	oldDirection, exists := l7c.getMirroredDirection(podNN)
	if exists {
		if oldDirection == direction {
			return nil
		}
		if err := l7c.removeTCFlow(podNN); err != nil {
			return err
		}
	}
	tcName := l7c.generateTCName(podNN)
	if err := l7c.ofClient.InstallTrafficControlMarkFlows(tcName, sourceOfPort, l7c.targetPort, direction, v1alpha2.ActionMirror, types.TrafficControlFlowPriorityLow); err != nil {
		return err
	}
	l7c.updateMirroredDirection(podNN, direction)
	return nil
}

func (l7c *L7FlowExporterController) updateMirroredDirection(podNN string, direction v1alpha2.Direction) {
	l7c.podToDirectionMapMutex.Lock()
	defer l7c.podToDirectionMapMutex.Unlock()
	l7c.podToDirectionMap[podNN] = direction
}

func (l7c *L7FlowExporterController) deleteMirroredDirection(podNN string) {
	l7c.podToDirectionMapMutex.Lock()
	defer l7c.podToDirectionMapMutex.Unlock()
	delete(l7c.podToDirectionMap, podNN)
}

func (l7c *L7FlowExporterController) getMirroredDirection(podNN string) (v1alpha2.Direction, bool) {
	l7c.podToDirectionMapMutex.RLock()
	defer l7c.podToDirectionMapMutex.RUnlock()
	direction, ok := l7c.podToDirectionMap[podNN]
	return direction, ok
}

func (l7c *L7FlowExporterController) IsL7FlowExporterRequested(podNN string, ingress bool) bool {
	l7c.podToDirectionMapMutex.RLock()
	defer l7c.podToDirectionMapMutex.RUnlock()
	if direction, ok := l7c.podToDirectionMap[podNN]; ok {
		switch direction {
		case v1alpha2.DirectionIngress:
			return ingress
		case v1alpha2.DirectionEgress:
			return !ingress
		case v1alpha2.DirectionBoth:
			return true
		}
	}
	return false
}

func (l7c *L7FlowExporterController) removeTCFlow(podNN string) error {
	if _, exists := l7c.getMirroredDirection(podNN); !exists {
		return nil
	}
	if err := l7c.ofClient.UninstallTrafficControlMarkFlows(l7c.generateTCName(podNN)); err != nil {
		return err
	}
	l7c.deleteMirroredDirection(podNN)
	return nil
}

func (l7c *L7FlowExporterController) generateTCName(podNN string) string {
	return fmt.Sprintf("tcl7:%s", podNN)
}

func checkIfAnnotationCorrect(annotationValue string) (v1alpha2.Direction, error) {
	var direction v1alpha2.Direction
	annotationValue = strings.ToLower(annotationValue)
	switch annotationValue {
	case "ingress":
		direction = v1alpha2.DirectionIngress
	case "egress":
		direction = v1alpha2.DirectionEgress
	case "both":
		direction = v1alpha2.DirectionBoth
	default:
		return direction, errInvalidAnnotation
	}
	return direction, nil
}
