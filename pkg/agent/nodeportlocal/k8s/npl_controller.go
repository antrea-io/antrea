//go:build !windows
// +build !windows

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

package k8s

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"time"

	"antrea.io/antrea/pkg/agent/nodeportlocal/portcache"
	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"
	"antrea.io/antrea/pkg/agent/nodeportlocal/util"
	utilsets "antrea.io/antrea/pkg/util/sets"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	controllerName = "NPLController"
	minRetryDelay  = 2 * time.Second
	maxRetryDelay  = 120 * time.Second
	numWorkers     = 4

	// Set resyncPeriod to 0 to disable resyncing.
	// UpdateFunc event handler will be called only when the object is actually updated.
	resyncPeriod = 0 * time.Minute
)

type NPLController struct {
	portTable   *portcache.PortTable
	kubeClient  clientset.Interface
	queue       workqueue.RateLimitingInterface
	podInformer cache.SharedIndexInformer
	podLister   corelisters.PodLister
	svcInformer cache.SharedIndexInformer
	podToIP     map[string]string
	nodeName    string
	podIPLock   sync.RWMutex
}

func NewNPLController(kubeClient clientset.Interface,
	podInformer cache.SharedIndexInformer,
	svcInformer cache.SharedIndexInformer,
	pt *portcache.PortTable,
	nodeName string) *NPLController {
	c := NPLController{
		kubeClient:  kubeClient,
		portTable:   pt,
		podInformer: podInformer,
		podLister:   corelisters.NewPodLister(podInformer.GetIndexer()),
		svcInformer: svcInformer,
		podToIP:     make(map[string]string),
		nodeName:    nodeName,
	}

	podInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.enqueuePod,
			DeleteFunc: c.enqueuePod,
			UpdateFunc: func(old, cur interface{}) { c.enqueuePod(cur) },
		},
		resyncPeriod,
	)

	svcInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.enqueueSvc,
			DeleteFunc: c.enqueueSvc,
			UpdateFunc: c.enqueueSvcUpdate,
		},
		resyncPeriod,
	)
	svcInformer.AddIndexers(
		cache.Indexers{
			NPLEnabledAnnotationIndex: func(obj interface{}) ([]string, error) {
				svc, ok := obj.(*corev1.Service)
				if !ok {
					return []string{}, nil
				}
				if val, ok := svc.GetAnnotations()[NPLEnabledAnnotationKey]; ok {
					return []string{val}, nil
				}
				return []string{}, nil
			},
		},
	)

	c.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "nodeportlocal")
	return &c
}

func podKeyFunc(pod *corev1.Pod) string {
	return pod.Namespace + "/" + pod.Name
}

// Run starts to watch and process Pod updates for the Node where Antrea Agent is running.
// It starts a queue and a fixed number of workers to process the objects from the queue.
func (c *NPLController) Run(stopCh <-chan struct{}) {
	defer func() {
		klog.Infof("Shutting down %s", controllerName)
		c.queue.ShutDown()
	}()

	klog.Infof("Starting %s", controllerName)
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.podInformer.HasSynced, c.svcInformer.HasSynced) {
		return
	}

	c.waitForRulesInitialization()

	for i := 0; i < numWorkers; i++ {
		go wait.Until(c.Worker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *NPLController) syncPod(key string) error {
	obj, exists, err := c.podInformer.GetIndexer().GetByKey(key)
	if err != nil {
		return err
	} else if exists {
		return c.handleAddUpdatePod(key, obj)
	} else {
		return c.handleRemovePod(key)
	}
}

func (c *NPLController) checkDeletedPod(obj interface{}) (*corev1.Pod, error) {
	deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		return nil, fmt.Errorf("received unexpected object: %v", obj)

	}
	pod, ok := deletedState.Obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("DeletedFinalStateUnknown object is not of type Pod: %v", deletedState.Obj)
	}
	return pod, nil
}

func (c *NPLController) enqueuePod(obj interface{}) {
	pod, isPod := obj.(*corev1.Pod)
	if !isPod {
		var err error
		pod, err = c.checkDeletedPod(obj)
		if err != nil {
			klog.Errorf("Got error while processing event update: %v", err)
			return
		}
	}
	podKey := podKeyFunc(pod)
	c.queue.Add(podKey)
}

func (c *NPLController) checkDeletedSvc(obj interface{}) (*corev1.Service, error) {
	deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		return nil, fmt.Errorf("received unexpected object: %v", obj)
	}
	svc, ok := deletedState.Obj.(*corev1.Service)
	if !ok {
		return nil, fmt.Errorf("DeletedFinalStateUnknown object is not of type Service: %v", deletedState.Obj)
	}
	return svc, nil
}

func validateNPLService(svc *corev1.Service) {
	if svc.Spec.Type == corev1.ServiceTypeNodePort {
		klog.InfoS("Service is of type NodePort and cannot be used for NodePortLocal, the NodePortLocal annotation will have no effect", "service", klog.KObj(svc))
		return
	}
	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		klog.InfoS("Service is of type ExternalName and cannot be used for NodePortLocal, the NodePortLocal annotation will have no effect", "service", klog.KObj(svc))
		return
	}
	if len(svc.Spec.Selector) == 0 {
		klog.InfoS("Service does not have a selector, the NodePortLocal annotation will have no effect", "service", klog.KObj(svc))
		return
	}
	for _, port := range svc.Spec.Ports {
		if port.Protocol == corev1.ProtocolSCTP {
			klog.InfoS("Service has NodePortLocal enabled but it includes a SCTP Service port, which will be ignored", "service", klog.KObj(svc))
		}
	}
}

func (c *NPLController) enqueueSvcUpdate(oldObj, newObj interface{}) {
	// In case where the app selector in Service gets updated from one valid selector to another
	// both sets of Pods (corresponding to old and new selector) need to be considered.
	newSvc := newObj.(*corev1.Service)
	oldSvc := oldObj.(*corev1.Service)

	oldSvcAnnotation := oldSvc.Annotations[NPLEnabledAnnotationKey]
	newSvcAnnotation := newSvc.Annotations[NPLEnabledAnnotationKey]
	// Return if both Services do not have the NPL annotation.
	if oldSvcAnnotation != "true" && newSvcAnnotation != "true" {
		return
	}

	if newSvcAnnotation == "true" {
		validateNPLService(newSvc)
	}

	podKeys := sets.String{}
	oldNPLEnabled := oldSvcAnnotation == "true" && oldSvc.Spec.Type != corev1.ServiceTypeNodePort && oldSvc.Spec.Type != corev1.ServiceTypeExternalName
	newNPLEnabled := newSvcAnnotation == "true" && newSvc.Spec.Type != corev1.ServiceTypeNodePort && newSvc.Spec.Type != corev1.ServiceTypeExternalName

	if oldNPLEnabled != newNPLEnabled {
		// Process Pods corresponding to Service with valid NPL annotation and Service type.
		if oldNPLEnabled {
			podKeys = sets.NewString(c.getPodsFromService(oldSvc)...)
		} else if newNPLEnabled {
			podKeys = sets.NewString(c.getPodsFromService(newSvc)...)
		}
	} else if oldNPLEnabled && newNPLEnabled {
		newPodSet := sets.NewString(c.getPodsFromService(newSvc)...)
		if !reflect.DeepEqual(oldSvc.Spec.Selector, newSvc.Spec.Selector) {
			// Disjunctive union of Pods from both Service sets.
			oldPodSet := sets.NewString(c.getPodsFromService(oldSvc)...)
			podKeys = utilsets.SymmetricDifferenceString(oldPodSet, newPodSet)
		}
		if !reflect.DeepEqual(oldSvc.Spec.Ports, newSvc.Spec.Ports) {
			// If ports in a Service are changed, all the Pods selected by the Service have to be processed.
			podKeys = podKeys.Union(newPodSet)
		}
	}

	for podKey := range podKeys {
		c.queue.Add(podKey)
	}
}

func (c *NPLController) enqueueSvc(obj interface{}) {
	svc, isSvc := obj.(*corev1.Service)
	if !isSvc {
		var err error
		svc, err = c.checkDeletedSvc(obj)
		if err != nil {
			klog.Errorf("Got error while processing event update: %v", err)
			return
		}
	}

	// Process Pods corresponding to Service with valid NPL annotation.
	if svc.Annotations[NPLEnabledAnnotationKey] == "true" {
		validateNPLService(svc)
		for _, podKey := range c.getPodsFromService(svc) {
			c.queue.Add(podKey)
		}
	}
}

func (c *NPLController) getPodsFromService(svc *corev1.Service) []string {
	var pods []string

	// Handling Service without selectors.
	if len(svc.Spec.Selector) == 0 {
		return pods
	}

	podList, err := c.podLister.Pods(svc.Namespace).List(labels.SelectorFromSet(labels.Set(svc.Spec.Selector)))
	if err != nil {
		klog.Errorf("Got error while listing Pods: %v", err)
		return pods
	}
	for _, pod := range podList {
		pods = append(pods, podKeyFunc(pod))
	}
	return pods
}

func (c *NPLController) getTargetPortsForServicesOfPod(obj interface{}) (sets.String, sets.String) {
	targetPortsInt := sets.NewString()
	targetPortsStr := sets.NewString()
	pod := obj.(*corev1.Pod)
	services, err := c.svcInformer.GetIndexer().ByIndex(NPLEnabledAnnotationIndex, "true")
	if err != nil {
		klog.Errorf("Got error while listing Services with annotation %s: %v", NPLEnabledAnnotationKey, err)
		return targetPortsInt, targetPortsStr
	}

	for _, service := range services {
		svc, isSvc := service.(*corev1.Service)
		// Selecting Services NOT of type NodePort, with Service selector matching Pod labels.
		if !isSvc || svc.Spec.Type == corev1.ServiceTypeNodePort || svc.Spec.Type == corev1.ServiceTypeExternalName {
			continue
		}
		if pod.Namespace == svc.Namespace && matchSvcSelectorPodLabels(svc.Spec.Selector, pod.GetLabels()) {
			for _, port := range svc.Spec.Ports {
				if port.Protocol == corev1.ProtocolSCTP {
					// Not supported yet. A message is logged when the
					// Service is processed.
					continue
				}
				switch port.TargetPort.Type {
				case intstr.Int:
					// An entry of format <target-port>:<protocol> (e.g. 8080:TCP) is added for a target port in the set targetPortsInt.
					// This is done to ensure that we can match with both port and protocol fields in container port of a Pod.
					portProto := util.BuildPortProto(fmt.Sprint(port.TargetPort.IntVal), string(port.Protocol))
					klog.V(4).Infof("Added target port in targetPortsInt set: %v", portProto)
					targetPortsInt.Insert(portProto)
				case intstr.String:
					portProto := util.BuildPortProto(port.TargetPort.StrVal, string(port.Protocol))
					klog.V(4).Infof("Added target port in targetPortsStr set: %v", portProto)
					targetPortsStr.Insert(portProto)
				}
			}
		}
	}
	return targetPortsInt, targetPortsStr
}

// matchSvcSelectorPodLabels verifies that all key/value pairs present in Service's selector
// are also present in Pod's labels.
func matchSvcSelectorPodLabels(svcSelector, podLabel map[string]string) bool {
	// Handling Service without selectors.
	if len(svcSelector) == 0 {
		return false
	}

	for selectorKey, selectorVal := range svcSelector {
		if labelVal, ok := podLabel[selectorKey]; !ok || selectorVal != labelVal {
			return false
		}
	}
	return true
}

func (c *NPLController) Worker() {
	for c.processNextWorkItem() {
	}
}

func (c *NPLController) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)

	if key, ok := obj.(string); !ok {
		c.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else if err := c.syncPod(key); err == nil {
		klog.V(2).Infof("Successfully processed key: %s, in queue", key)
		c.queue.Forget(key)
	} else {
		c.queue.AddRateLimited(key)
		klog.Errorf("Error syncing Pod %s, requeuing. Error: %v", key, err)
	}
	return true
}

func (c *NPLController) getPodIPFromCache(key string) (string, bool) {
	c.podIPLock.RLock()
	defer c.podIPLock.RUnlock()
	podIP, found := c.podToIP[key]
	return podIP, found
}

func (c *NPLController) addPodIPToCache(key, podIP string) {
	c.podIPLock.Lock()
	defer c.podIPLock.Unlock()
	c.podToIP[key] = podIP
}

func (c *NPLController) deletePodIPFromCache(key string) {
	c.podIPLock.Lock()
	defer c.podIPLock.Unlock()
	delete(c.podToIP, key)
}

func (c *NPLController) deleteAllPortRulesIfAny(podIP string) error {
	return c.portTable.DeleteRulesForPod(podIP)
}

// handleRemovePod removes rules from port table and
// rules programmed in the system based on implementation type (e.g. IPTABLES).
// This also removes Pod annotation from Pods that are not selected by Service annotation.
func (c *NPLController) handleRemovePod(key string) error {
	klog.V(2).Infof("Got delete event for Pod: %s", key)
	podIP, found := c.getPodIPFromCache(key)
	if !found {
		klog.Infof("IP address not found for Pod: %s", key)
		return nil
	}

	if err := c.deleteAllPortRulesIfAny(podIP); err != nil {
		return err
	}

	c.deletePodIPFromCache(key)

	return nil
}

// handleAddUpdatePod handles Pod Add, Update events and updates annotation if required.
func (c *NPLController) handleAddUpdatePod(key string, obj interface{}) error {
	pod := obj.(*corev1.Pod)
	klog.V(2).Infof("Got add/update event for Pod: %s", key)

	podIP := pod.Status.PodIP
	if podIP == "" {
		klog.Infof("IP address not set for Pod: %s", key)
		return nil
	}
	c.addPodIPToCache(key, podIP)

	targetPortsInt, targetPortsStr := c.getTargetPortsForServicesOfPod(obj)
	klog.V(2).Infof("Pod %s is selected by a Service for which NodePortLocal is enabled", key)

	var nodePort int
	podPorts := make(map[string]struct{})
	podContainers := pod.Spec.Containers
	nplAnnotations := []NPLAnnotation{}

	podAnnotation, nplExists := pod.GetAnnotations()[NPLAnnotationKey]
	if nplExists {
		if err := json.Unmarshal([]byte(podAnnotation), &nplAnnotations); err != nil {
			klog.Warningf("Unable to unmarshal NodePortLocal annotation for Pod %s", key)
			return nil
		}
	}

	nplAnnotationsRequiredMap := map[int]NPLAnnotation{}
	nplAnnotationsRequired := []NPLAnnotation{}

	hostPorts := make(map[string]int)
	for _, container := range podContainers {
		for _, cport := range container.Ports {
			portProtoInt := util.BuildPortProto(fmt.Sprint(cport.ContainerPort), string(cport.Protocol))
			if int(cport.HostPort) > 0 {
				klog.V(4).Infof("Host Port is defined for Container %s in Pod %s, thus extra NPL port is not allocated", container.Name, key)
				hostPorts[portProtoInt] = int(cport.HostPort)
			}
			if cport.Name == "" {
				continue
			}
			portProtoStr := util.BuildPortProto(cport.Name, string(cport.Protocol))
			if targetPortsStr.Has(portProtoStr) {
				targetPortsInt.Insert(portProtoInt)
			}
		}
	}

	// targetPortsInt contains list of all ports that needs to be exposed for the Pod, including container ports
	// for named ports present in targetPortsStr. If it is empty, then all existing rules and annotations for the
	// Pod have to be cleaned up. If a Service uses a named target port that doesn't match any named container port
	// for the current Pod, no corresponding entry will be added to the targetPortsInt set by the code above.
	if len(targetPortsInt) == 0 {
		if err := c.deleteAllPortRulesIfAny(podIP); err != nil {
			return err
		}
		if _, exists := pod.Annotations[NPLAnnotationKey]; exists {
			return c.cleanupNPLAnnotationForPod(pod)
		}
		return nil
	}

	// first, check which rules are needed based on the target ports of the Services selecting the Pod
	// (ignoring NPL annotations) and make sure they are present. As we do so, we build the expected list of
	// NPL annotations for the Pod.
	for _, targetPortProto := range targetPortsInt.List() {
		port, protocol, err := util.ParsePortProto(targetPortProto)
		if err != nil {
			return fmt.Errorf("failed to parse port number and protocol from %s for Pod %s: %v", targetPortProto, key, err)
		}
		podPorts[targetPortProto] = struct{}{}
		portData := c.portTable.GetEntry(podIP, port)
		if portData != nil && !portData.ProtocolInUse(protocol) {
			// If the PortTable has an entry for the Pod but does not have an
			// entry with protocol, we enforce AddRule for the missing Protocol.
			portData = nil
		}
		if portData == nil {
			if hport, ok := hostPorts[targetPortProto]; ok {
				nodePort = hport
			} else {
				nodePort, err = c.portTable.AddRule(podIP, port, protocol)
				if err != nil {
					return fmt.Errorf("failed to add rule for Pod %s: %v", key, err)
				}
			}
		} else {
			nodePort = portData.NodePort
		}

		if val, ok := nplAnnotationsRequiredMap[nodePort]; ok {
			val.Protocols = append(val.Protocols, protocol)
			nplAnnotationsRequiredMap[nodePort] = val
		} else {
			nplAnnotationsRequiredMap[nodePort] = NPLAnnotation{
				PodPort:   port,
				NodeIP:    pod.Status.HostIP,
				NodePort:  nodePort,
				Protocols: []string{protocol},
			}
		}
	}
	for _, annotation := range nplAnnotationsRequiredMap {
		nplAnnotationsRequired = append(nplAnnotationsRequired, annotation)
	}

	// second, delete any existing rule that is not needed based on the current Pod
	// specification.
	entries := c.portTable.GetDataForPodIP(podIP)
	if nplExists {
		for _, data := range entries {
			for _, proto := range data.Protocols {
				if _, exists := podPorts[util.BuildPortProto(fmt.Sprint(data.PodPort), proto.Protocol)]; !exists {
					if err := c.portTable.DeleteRule(podIP, int(data.PodPort), proto.Protocol); err != nil {
						return fmt.Errorf("failed to delete rule for Pod IP %s, Pod Port %d, Protocol %s: %v", podIP, data.PodPort, proto.Protocol, err)
					}
				}
			}
		}
	}

	// finally, we can check if the current annotation matches the expected one (which we built
	// in the first step). If not, the Pod needed to be patched.
	updatePodAnnotation := !compareNPLAnnotationLists(nplAnnotations, nplAnnotationsRequired)
	if updatePodAnnotation {
		return c.updatePodNPLAnnotation(pod, nplAnnotationsRequired)
	}
	return nil
}

// waitForRulesInitialization fetches all the Pods on this Node and looks for valid NodePortLocal
// annotations. If they exist, with a valid Node port, it adds the Node port to the port table and
// rules. If the NodePortLocal annotation is invalid (cannot be unmarshalled), the annotation is
// cleared. If the Node port is invalid (maybe the port range was changed and the Agent was
// restarted), the annotation is ignored and will be removed by the Pod event handlers. The Pod
// event handlers will also take care of allocating a new Node port if required.
// The function is meant to be called during Controller initialization, after the caches have
// synced. It will block until iptables rules have been synced successfully based on the listed
// Pods. After it returns, the Controller should start handling events. In case of an unexpected
// error, the function can return early or may not complete initialization. The Controller's event
// handlers are able to recover from these errors.
func (c *NPLController) waitForRulesInitialization() {
	klog.InfoS("Will fetch Pods and generate NodePortLocal rules for these Pods")

	podList, err := c.podLister.List(labels.Everything())
	if err != nil {
		klog.ErrorS(err, "Error when listing Pods for Node")
	}

	// in case of an error when listing Pods above, allNPLPorts will be
	// empty and all NPL iptables rules will be deleted.
	allNPLPorts := []rules.PodNodePort{}
	for i := range podList {
		// For each Pod:
		// check if a valid NodePortLocal annotation exists for this Pod:
		//   if yes, verifiy validity of the Node port, update the port table and add a rule to the
		//   rules buffer.
		pod := podList[i]
		annotations := pod.GetAnnotations()
		nplAnnotation, ok := annotations[NPLAnnotationKey]
		if !ok {
			continue
		}
		nplData := []NPLAnnotation{}
		if err := json.Unmarshal([]byte(nplAnnotation), &nplData); err != nil {
			klog.InfoS("Found invalid NodePortLocal annotation for Pod that cannot be parsed, cleaning it up", "pod", klog.KObj(pod))
			// if there's an error in this NodePortLocal annotation, clean it up
			if err := c.cleanupNPLAnnotationForPod(pod); err != nil {
				klog.ErrorS(err, "Error when cleaning up NodePortLocal annotation for Pod", "pod", klog.KObj(pod))
			}
			continue
		}

		for _, npl := range nplData {
			if npl.NodePort > c.portTable.EndPort || npl.NodePort < c.portTable.StartPort {
				// ignoring annotation for now, it will be removed by the first call
				// to handleAddUpdatePod
				klog.V(2).InfoS("Found NodePortLocal annotation for which the allocated port doesn't fall into the configured range", "pod", klog.KObj(pod))
				continue
			}
			allNPLPorts = append(allNPLPorts, rules.PodNodePort{
				NodePort:  npl.NodePort,
				PodPort:   npl.PodPort,
				PodIP:     pod.Status.PodIP,
				Protocols: npl.Protocols,
			})
		}
	}

	rulesInitialized := make(chan struct{})
	if err := c.addRulesForNPLPorts(allNPLPorts, rulesInitialized); err != nil {
		klog.ErrorS(err, "Cannot install NodePortLocal rules")
		return
	}

	klog.InfoS("Waiting for initialization of NodePortLocal rules to complete")
	<-rulesInitialized
	klog.InfoS("Initialization of NodePortLocal rules successful")
}

func (c *NPLController) addRulesForNPLPorts(allNPLPorts []rules.PodNodePort, synced chan<- struct{}) error {
	return c.portTable.RestoreRules(allNPLPorts, synced)
}

// cleanupNPLAnnotationForPod removes the NodePortLocal annotation from the Pod's annotations map entirely.
func (c *NPLController) cleanupNPLAnnotationForPod(pod *corev1.Pod) error {
	_, ok := pod.Annotations[NPLAnnotationKey]
	if !ok {
		return nil
	}
	return patchPod(nil, pod, c.kubeClient)
}
