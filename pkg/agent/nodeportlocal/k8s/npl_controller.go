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
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"time"

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

	"antrea.io/antrea/pkg/agent/nodeportlocal/portcache"
	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"
	"antrea.io/antrea/pkg/agent/nodeportlocal/types"
	"antrea.io/antrea/pkg/agent/nodeportlocal/util"
	"antrea.io/antrea/pkg/util/k8s"
	utilsets "antrea.io/antrea/pkg/util/sets"
	waitutil "antrea.io/antrea/pkg/util/wait"
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
	portTableIPv4 *portcache.PortTable
	portTableIPv6 *portcache.PortTable
	kubeClient    clientset.Interface
	queue         workqueue.TypedRateLimitingInterface[string]
	podInformer   cache.SharedIndexInformer
	podLister     corelisters.PodLister
	svcInformer   cache.SharedIndexInformer
	nodeInformer  cache.SharedIndexInformer
	nodeName      string
	// nodeIPv4 and nodeIPv6 store the current Node IPs for NPL annotations.
	// They are populated from the Node object and prioritize external IPs over internal IPs.
	nodeIPv4    string
	nodeIPv6    string
	nodeIPMutex sync.RWMutex
}

func NewNPLController(kubeClient clientset.Interface,
	podInformer cache.SharedIndexInformer,
	svcInformer cache.SharedIndexInformer,
	nodeInformer cache.SharedIndexInformer,
	ptIPv4 *portcache.PortTable,
	ptIPv6 *portcache.PortTable,
	nodeName string) *NPLController {
	c := NPLController{
		kubeClient:    kubeClient,
		portTableIPv4: ptIPv4,
		portTableIPv6: ptIPv6,
		podInformer:   podInformer,
		podLister:     corelisters.NewPodLister(podInformer.GetIndexer()),
		svcInformer:   svcInformer,
		nodeInformer:  nodeInformer,
		nodeName:      nodeName,
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
				if val, ok := svc.GetAnnotations()[types.NPLEnabledAnnotationKey]; ok {
					return []string{val}, nil
				}
				return []string{}, nil
			},
		},
	)

	nodeInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleNodeAdd,
			UpdateFunc: c.handleNodeUpdate,
		},
		resyncPeriod,
	)

	c.queue = workqueue.NewTypedRateLimitingQueueWithConfig(
		workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
		workqueue.TypedRateLimitingQueueConfig[string]{
			Name: "nodeportlocal",
		},
	)
	return &c
}

func podKeyFunc(pod *corev1.Pod) string {
	return pod.Namespace + "/" + pod.Name
}

// updateNodeIPs updates the cached Node IPs from the Node object.
// It returns true if the IPs have changed, false otherwise.
func (c *NPLController) updateNodeIPs(node *corev1.Node) bool {
	// Use GetNodeAddrsWithType to prioritize external IPs over internal IPs
	nodeAddrs, err := k8s.GetNodeAddrsWithType(node, []corev1.NodeAddressType{corev1.NodeExternalIP, corev1.NodeInternalIP})
	if err != nil {
		klog.ErrorS(err, "Failed to get Node addresses", "node", klog.KObj(node))
		return false
	}

	c.nodeIPMutex.Lock()
	defer c.nodeIPMutex.Unlock()

	oldIPv4 := c.nodeIPv4
	oldIPv6 := c.nodeIPv6

	if nodeAddrs.IPv4 != nil {
		c.nodeIPv4 = nodeAddrs.IPv4.String()
	} else {
		c.nodeIPv4 = ""
	}

	if nodeAddrs.IPv6 != nil {
		c.nodeIPv6 = nodeAddrs.IPv6.String()
	} else {
		c.nodeIPv6 = ""
	}

	return oldIPv4 != c.nodeIPv4 || oldIPv6 != c.nodeIPv6
}

// getNodeIPForFamily returns the cached Node IP for the given IP family.
func (c *NPLController) getNodeIPForFamily(ipFamily corev1.IPFamily) string {
	c.nodeIPMutex.RLock()
	defer c.nodeIPMutex.RUnlock()

	if ipFamily == corev1.IPv6Protocol {
		return c.nodeIPv6
	}
	return c.nodeIPv4
}

func (c *NPLController) getPortTableForFamily(ipFamily corev1.IPFamily) *portcache.PortTable {
	if ipFamily == corev1.IPv6Protocol {
		return c.portTableIPv6
	}
	return c.portTableIPv4
}

// nodeIPsReady returns true if the Node IPs have been determined.
func (c *NPLController) nodeIPsReady() bool {
	c.nodeIPMutex.RLock()
	defer c.nodeIPMutex.RUnlock()
	// At least one IP family must be available
	return c.nodeIPv4 != "" || c.nodeIPv6 != ""
}

// handleNodeAdd handles Node add events.
func (c *NPLController) handleNodeAdd(obj interface{}) {
	node := obj.(*corev1.Node)
	if node.Name != c.nodeName {
		return
	}

	if c.updateNodeIPs(node) {
		klog.InfoS("Node IPs initialized", "node", klog.KObj(node), "IPv4", c.nodeIPv4, "IPv6", c.nodeIPv6)
	}
}

// handleNodeUpdate handles Node update events.
func (c *NPLController) handleNodeUpdate(oldObj, newObj interface{}) {
	oldNode := oldObj.(*corev1.Node)
	newNode := newObj.(*corev1.Node)
	if newNode.Name != c.nodeName {
		return
	}

	// Check if Node addresses have changed
	if reflect.DeepEqual(oldNode.Status.Addresses, newNode.Status.Addresses) {
		return
	}

	if c.updateNodeIPs(newNode) {
		klog.InfoS("Node IPs changed, reconciling all Pods", "node", klog.KObj(newNode), "IPv4", c.nodeIPv4, "IPv6", c.nodeIPv6)
		// Reconcile all local Pods when Node IPs change
		c.reconcileAllPods()
	}
}

// reconcileAllPods reconciles all Pods on the local Node.
func (c *NPLController) reconcileAllPods() {
	pods, err := c.podLister.List(labels.Everything())
	if err != nil {
		klog.ErrorS(err, "Failed to list Pods for reconciliation")
		return
	}

	for _, pod := range pods {
		c.enqueuePod(pod)
	}
}

// Run starts to watch and process Pod updates for the Node where Antrea Agent is running.
// It starts a queue and a fixed number of workers to process the objects from the queue.
func (c *NPLController) Run(stopCh <-chan struct{}) {
	defer func() {
		klog.Infof("Shutting down %s", controllerName)
		c.queue.ShutDown()
	}()

	klog.Infof("Starting %s", controllerName)
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.podInformer.HasSynced, c.svcInformer.HasSynced, c.nodeInformer.HasSynced) {
		return
	}

	// Wait for Node IPs to be determined before processing Pods
	if err := wait.PollUntilContextCancel(wait.ContextForChannel(stopCh), time.Second, true, func(ctx context.Context) (bool, error) {
		return c.nodeIPsReady(), nil
	}); err != nil {
		klog.ErrorS(err, "Failed to determine Node IPs")
		return
	}
	klog.InfoS("Node IPs are ready", "IPv4", c.nodeIPv4, "IPv6", c.nodeIPv6)

	if err := c.waitForRulesInitialization(wait.ContextForChannel(stopCh)); err != nil {
		klog.ErrorS(err, "Failed to initialize NodePortLocal rules")
		return
	}

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

	oldSvcAnnotation := oldSvc.Annotations[types.NPLEnabledAnnotationKey]
	newSvcAnnotation := newSvc.Annotations[types.NPLEnabledAnnotationKey]
	// Return if both Services do not have the NPL annotation.
	if oldSvcAnnotation != "true" && newSvcAnnotation != "true" {
		return
	}

	if newSvcAnnotation == "true" {
		validateNPLService(newSvc)
	}

	podKeys := sets.Set[string]{}
	oldNPLEnabled := oldSvcAnnotation == "true" && oldSvc.Spec.Type != corev1.ServiceTypeNodePort && oldSvc.Spec.Type != corev1.ServiceTypeExternalName
	newNPLEnabled := newSvcAnnotation == "true" && newSvc.Spec.Type != corev1.ServiceTypeNodePort && newSvc.Spec.Type != corev1.ServiceTypeExternalName

	if oldNPLEnabled != newNPLEnabled {
		// Process Pods corresponding to Service with valid NPL annotation and Service type.
		if oldNPLEnabled {
			podKeys = sets.New[string](c.getPodsFromService(oldSvc)...)
		} else if newNPLEnabled {
			podKeys = sets.New[string](c.getPodsFromService(newSvc)...)
		}
	} else if oldNPLEnabled && newNPLEnabled {
		newPodSet := sets.New[string](c.getPodsFromService(newSvc)...)
		if !reflect.DeepEqual(oldSvc.Spec.Selector, newSvc.Spec.Selector) {
			// Disjunctive union of Pods from both Service sets.
			oldPodSet := sets.New[string](c.getPodsFromService(oldSvc)...)
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
	if svc.Annotations[types.NPLEnabledAnnotationKey] == "true" {
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

// getTargetPortsForServicesOfPod returns target ports and IP families needed for NPL mappings.
// It returns two maps: one for numeric target ports and one for named target ports.
// Both map portProto -> set of IP families that require this port.
func (c *NPLController) getTargetPortsForServicesOfPod(pod *corev1.Pod) (map[string]ipFamilies, map[string]ipFamilies) {
	targetPortsInt := make(map[string]ipFamilies)
	targetPortsStr := make(map[string]ipFamilies)
	// If the Pod is already terminated, its NodePortLocal ports should be released.
	if k8s.IsPodTerminated(pod) {
		return targetPortsInt, targetPortsStr
	}
	services, err := c.svcInformer.GetIndexer().ByIndex(NPLEnabledAnnotationIndex, "true")
	if err != nil {
		klog.Errorf("Got error while listing Services with annotation %s: %v", types.NPLEnabledAnnotationKey, err)
		return targetPortsInt, targetPortsStr
	}

	for _, service := range services {
		svc, isSvc := service.(*corev1.Service)
		// Selecting Services NOT of type NodePort, with Service selector matching Pod labels.
		if !isSvc || svc.Spec.Type == corev1.ServiceTypeNodePort || svc.Spec.Type == corev1.ServiceTypeExternalName {
			continue
		}
		if pod.Namespace == svc.Namespace && matchSvcSelectorPodLabels(svc.Spec.Selector, pod.GetLabels()) {
			svcIPFamilies := getServiceIPFamilies(svc)
			for _, port := range svc.Spec.Ports {
				if port.Protocol == corev1.ProtocolSCTP {
					// Not supported yet. A message is logged when the
					// Service is processed.
					continue
				}
				switch port.TargetPort.Type {
				case intstr.Int:
					// An entry of format <target-port>:<protocol> (e.g. 8080:TCP) is added for a target port in the map.
					// We track which IP families need this port.
					portProto := util.BuildPortProto(fmt.Sprint(port.TargetPort.IntVal), string(port.Protocol))
					klog.V(4).InfoS("Added target port in targetPortsInt map", "portProto", portProto, "ipFamilies", svcIPFamilies)
					for _, ipFamily := range svcIPFamilies {
						targetPortsInt[portProto] = targetPortsInt[portProto].add(ipFamily)
					}
				case intstr.String:
					portProto := util.BuildPortProto(port.TargetPort.StrVal, string(port.Protocol))
					klog.V(4).InfoS("Added target port in targetPortsStr map", "portProto", portProto, "ipFamilies", svcIPFamilies)
					for _, ipFamily := range svcIPFamilies {
						targetPortsStr[portProto] = targetPortsStr[portProto].add(ipFamily)
					}
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
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	if err := c.syncPod(key); err == nil {
		klog.V(2).Infof("Successfully processed key: %s, in queue", key)
		c.queue.Forget(key)
	} else {
		c.queue.AddRateLimited(key)
		klog.Errorf("Error syncing Pod %s, requeuing. Error: %v", key, err)
	}
	return true
}

// handleRemovePod removes rules from port table and
// rules programmed in the system based on implementation type (e.g. IPTABLES).
// This also removes Pod annotation from Pods that are not selected by Service annotation.
func (c *NPLController) handleRemovePod(key string) error {
	klog.V(2).Infof("Got delete event for Pod: %s", key)

	if err := c.cleanupPodRules(key, nil); err != nil {
		return err
	}

	return nil
}

// handleAddUpdatePod handles Pod Add, Update events and updates annotation if required.
func (c *NPLController) handleAddUpdatePod(key string, obj interface{}) error {
	pod := obj.(*corev1.Pod)
	klog.V(2).InfoS("Got add/update event for Pod", "pod", klog.KObj(pod))

	nplAnnotations := []types.NPLAnnotation{}
	podAnnotation, nplExists := pod.GetAnnotations()[types.NPLAnnotationKey]
	if nplExists {
		// TODO: should the annotation be removed by us in this case?
		if err := json.Unmarshal([]byte(podAnnotation), &nplAnnotations); err != nil {
			klog.ErrorS(err, "Unable to unmarshal NodePortLocal annotation for Pod, skipping", "pod", klog.KObj(pod))
			return nil
		}
	}

	// Check if Pod has any IPs
	if len(pod.Status.PodIPs) == 0 {
		klog.V(2).InfoS("IP address not set for Pod", "pod", klog.KObj(pod))
		// We want to delete NPL rules and remove the annotation in this case, as a Pod can
		// theoretically lose its IP address if there is an issue with the Sandbox.
		if err := c.cleanupPodRules(key, nil); err != nil { // it is valid to pass a nil Set to cleanupPodRules
			return err
		}
		if nplExists {
			if err := c.cleanupNPLAnnotationForPod(context.TODO(), pod); err != nil {
				return err
			}
		}
		return nil
	}

	targetPortsInt, targetPortsStr := c.getTargetPortsForServicesOfPod(pod)
	nplEnabled := len(targetPortsInt) > 0 || len(targetPortsStr) > 0
	if nplEnabled {
		klog.V(2).InfoS("Pod is selected by a Service for which NodePortLocal is enabled", "pod", klog.KObj(pod))
	}

	var nodePort int
	podPorts := sets.New[string]()
	podContainers := pod.Spec.Containers

	nplAnnotationsRequiredMap := map[string]types.NPLAnnotation{}
	nplAnnotationsRequired := []types.NPLAnnotation{}

	hostPorts := make(map[string]int)
	if nplEnabled { // no need for this calculation if NPL is not enabled for the Pod
		for _, container := range podContainers {
			for _, cport := range container.Ports {
				portProtoInt := util.BuildPortProto(fmt.Sprint(cport.ContainerPort), string(cport.Protocol))
				if int(cport.HostPort) > 0 {
					klog.V(4).InfoS("Host Port is defined for container, thus extra NPL port is not allocated", "pod", klog.KObj(pod), "container", container.Name)
					hostPorts[portProtoInt] = int(cport.HostPort)
				}
				if cport.Name == "" {
					continue
				}
				portProtoStr := util.BuildPortProto(cport.Name, string(cport.Protocol))
				if ipFamilies, exists := targetPortsStr[portProtoStr]; exists {
					// When resolving named ports, add them to targetPortsInt with the IP families from the named port
					targetPortsInt[portProtoInt] = targetPortsInt[portProtoInt].union(ipFamilies)
				}
			}
		}
	}

	// first, check which rules are needed based on the target ports of the Services selecting the Pod
	// (ignoring NPL annotations) and make sure they are present. As we do so, we build the expected list of
	// NPL annotations for the Pod.
	// We need to create separate NPL mappings for each IP family.
	for targetPortProto, ipFamilies := range targetPortsInt {
		port, protocol, err := util.ParsePortProto(targetPortProto)
		if err != nil {
			return fmt.Errorf("failed to parse port number and protocol from %s for Pod %s: %v", targetPortProto, key, err)
		}
		podPorts.Insert(targetPortProto)

		// Process each IP family separately
		for ipFamily := range ipFamilies.values() {
			podIP := getPodIPForFamily(pod, ipFamily)
			if podIP == "" {
				klog.ErrorS(nil, "Pod does not have IP for family", "pod", klog.KObj(pod), "ipFamily", ipFamily)
				continue
			}
			nodeIP := c.getNodeIPForFamily(ipFamily)
			if nodeIP == "" {
				klog.ErrorS(nil, "Node does not have IP for family", "ipFamily", ipFamily)
				continue
			}

			portTable := c.getPortTableForFamily(ipFamily)
			portData := portTable.GetEntry(key, port, protocol)
			// Special handling for a rule that was previously marked for deletion but could not
			// be deleted properly: we have to retry now.
			if portData != nil && portData.Defunct() {
				klog.InfoS("Deleting defunct NodePortLocal rule for Pod to prevent re-use", "pod", klog.KObj(pod), "podIP", podIP, "port", port, "protocol", protocol)
				if err := portTable.DeleteRule(key, port, protocol); err != nil {
					return fmt.Errorf("failed to delete defunct rule for Pod %s, Pod Port %d, Protocol %s: %w", key, port, protocol, err)
				}
				portData = nil
			}
			// There are a few edge cases which can cause us to observe a different IP for the
			// same Pod name:
			//  * a new Sandbox can be created for the same Pod (e.g., after a Node restart)
			//  * because we use a workqueue, when a Pod is recreated with the same name but a
			//    different IP, both events (DELETE and CREATE) can be "merged" in the workqueue
			//    and treated as a single UPDATE event.
			// If we detect a Pod IP change, delete existing rules and recreate them with the new IP.
			if portData != nil && portData.PodIP != podIP {
				klog.InfoS("Deleting NodePortLocal rule for Pod because of IP change", "pod", klog.KObj(pod), "podIP", podIP, "prevPodIP", portData.PodIP)
				if err := portTable.DeleteRule(key, port, protocol); err != nil {
					return fmt.Errorf("failed to delete rule for Pod %s, Pod Port %d, Protocol %s: %w", key, port, protocol, err)
				}
				portData = nil
			}
			if portData == nil {
				if hport, ok := hostPorts[targetPortProto]; ok {
					nodePort = hport
				} else {
					klog.InfoS("Adding NodePortLocal rule", "pod", klog.KObj(pod), "podIP", podIP, "port", port, "protocol", protocol, "ipFamily", ipFamily)
					nodePort, err = portTable.AddRule(key, port, protocol, podIP)
					if err != nil {
						return fmt.Errorf("failed to add rule for Pod %s: %w", key, err)
					}
				}
			} else {
				nodePort = portData.NodePort
			}
			// Create unique key for annotation: nodePort:protocol:ipFamily
			annotationKey := fmt.Sprintf("%d:%s:%s", nodePort, protocol, ipFamilyForAnnotation(ipFamily))
			if _, ok := nplAnnotationsRequiredMap[annotationKey]; !ok {
				nplAnnotationsRequiredMap[annotationKey] = types.NPLAnnotation{
					PodPort:  port,
					NodeIP:   nodeIP,
					NodePort: nodePort,
					Protocol: protocol,
					IPFamily: ipFamilyForAnnotation(ipFamily),
				}
			}
		}
	}
	for _, annotation := range nplAnnotationsRequiredMap {
		nplAnnotationsRequired = append(nplAnnotationsRequired, annotation)
	}

	// second, delete any existing rule that is not needed based on the current Pod
	// specification.
	if err := c.cleanupPodRules(key, podPorts); err != nil {
		return err
	}

	// finally, we can check if the current annotation matches the expected one (which we built
	// in the first step). If not, the Pod needed to be patched.
	updatePodAnnotation := !compareNPLAnnotationLists(nplAnnotations, nplAnnotationsRequired)
	if updatePodAnnotation {
		return c.updatePodNPLAnnotation(context.TODO(), pod, nplAnnotationsRequired)
	}
	return nil
}

func (c *NPLController) cleanupPodRules(key string, podPortsToKeep sets.Set[string]) error {
	// Clean up rules from both IPv4 and IPv6 port tables
	for _, portTable := range []*portcache.PortTable{c.portTableIPv4, c.portTableIPv6} {
		if portTable == nil {
			continue
		}
		entries := portTable.GetDataForPod(key)
		for _, data := range entries {
			proto := data.Protocol
			if exists := podPortsToKeep.Has(util.BuildPortProto(fmt.Sprint(data.PodPort), proto.Protocol)); !exists {
				klog.InfoS("Deleting NodePortLocal rule", "pod", key, "podIP", data.PodIP, "port", data.PodPort, "protocol", proto.Protocol)
				if err := portTable.DeleteRule(key, data.PodPort, proto.Protocol); err != nil {
					return fmt.Errorf("failed to delete rule for Pod %s, Pod Port %d, Protocol %s: %w", key, data.PodPort, proto.Protocol, err)
				}
			}
		}
	}
	return nil
}

// waitForRulesInitialization fetches all the Pods on this Node and looks for valid NodePortLocal
// annotations. If they exist, with a valid Node port, it adds the Node port to the port table and
// rules. If the NodePortLocal annotation is invalid (cannot be unmarshalled), the annotation is
// cleared. If the Pod's IP address is not available (yet), the annotation is also cleared. If the
// Node port is invalid (maybe the port range was changed and the Agent was restarted), the
// annotation is ignored and will be removed by the Pod event handlers. The Pod event handlers will
// also take care of allocating a new Node port if required. The function is meant to be called
// during Controller initialization, after the caches have synced. It will block until iptables
// rules have been synced successfully based on the listed Pods, or until the context is
// canceled. It only returns an error if the context is cancelled before rules have been
// synced. After it returns, the Controller should start handling events. The Controller's event
// handlers are able to recover from any error occurring during initialization.  Unlike the event
// handler (handleAddUpdatePod), this function tries to reuse existing NPL mappings (from Pod
// annotations), and that's its main value add. It also avoids datapath disruption by syncing all
// rules (including removing stale ones) with a single "operation".
func (c *NPLController) waitForRulesInitialization(ctx context.Context) error {
	klog.InfoS("Will fetch Pods and generate NodePortLocal rules for these Pods")

	podList, err := c.podLister.List(labels.Everything())
	if err != nil {
		klog.ErrorS(err, "Error when listing Pods for Node, removing all NodePortLocal rules")
	}

	var allNPLPortsV4, allNPLPortsV6 []rules.PodNodePort
	for i := range podList {
		pod := podList[i]
		podKey := podKeyFunc(pod)
		annotations := pod.GetAnnotations()
		nplAnnotation, ok := annotations[types.NPLAnnotationKey]
		if !ok {
			continue
		}
		nplData := []types.NPLAnnotation{}
		if err := json.Unmarshal([]byte(nplAnnotation), &nplData); err != nil {
			klog.InfoS("Found invalid NodePortLocal annotation for Pod that cannot be parsed, cleaning it up", "pod", klog.KObj(pod))
			// if there's an error in this NodePortLocal annotation, clean it up
			if err := c.cleanupNPLAnnotationForPod(ctx, pod); err != nil {
				klog.ErrorS(err, "Error when cleaning up NodePortLocal annotation for Pod", "pod", klog.KObj(pod))
			}
			continue
		}

		if len(pod.Status.PodIPs) == 0 {
			klog.InfoS("Found Pod with NodePortLocal annotation but no IP address, removing annotation", "pod", klog.KObj(pod))
			// While we could just skip the Pod without removing the annotation, and let
			// the controller update the annotation later, the advantage of removing the
			// annotation is that we let consumers of the feature know right away that
			// something is wrong (missing precondition).
			if err := c.cleanupNPLAnnotationForPod(ctx, pod); err != nil {
				klog.ErrorS(err, "Error when cleaning up NodePortLocal annotation for Pod", "pod", klog.KObj(pod))
			}
			continue
		}

		for _, npl := range nplData {
			if npl.NodePort == 0 || npl.PodPort == 0 || npl.Protocol == "" {
				klog.InfoS("Found NodePortLocal annotation with an incomplete rule, ignoring it", "pod", klog.KObj(pod), "rule", npl)
				continue
			}
			var portTable *portcache.PortTable
			var podIP string
			if npl.IPFamily == types.IPFamilyIPv6 {
				portTable = c.portTableIPv6
				podIP = getPodIPForFamily(pod, corev1.IPv6Protocol)
			} else {
				// Default to IPv4 for backward compatibility (empty IPFamily field)
				portTable = c.portTableIPv4
				podIP = getPodIPForFamily(pod, corev1.IPv4Protocol)
			}
			if portTable == nil || podIP == "" {
				klog.InfoS("Found NodePortLocal annotation for an unsupported IP family", "pod", klog.KObj(pod), "ipFamily", npl.IPFamily, "podIP", podIP)
				continue
			}
			if npl.NodePort > portTable.EndPort || npl.NodePort < portTable.StartPort {
				// Ignoring annotation for now, it will be removed by the first call
				// to handleAddUpdatePod. Note that we could also remove the annotation
				// here, but it is not as useful as in the missing PodIP case.
				klog.V(2).InfoS("Found NodePortLocal annotation for which the allocated port doesn't fall into the configured range", "pod", klog.KObj(pod))
				continue
			}

			nplPort := rules.PodNodePort{
				PodKey:   podKey,
				NodePort: npl.NodePort,
				PodPort:  npl.PodPort,
				PodIP:    podIP,
				Protocol: npl.Protocol,
			}
			if npl.IPFamily == types.IPFamilyIPv6 {
				allNPLPortsV6 = append(allNPLPortsV6, nplPort)
			} else {
				allNPLPortsV4 = append(allNPLPortsV4, nplPort)
			}
		}
	}

	klog.InfoS("Starting initialization of NodePortLocal rules and waiting for it to complete")
	if err := c.addRulesForNPLPorts(ctx, allNPLPortsV4, allNPLPortsV6); err != nil {
		return err
	}
	klog.InfoS("Initialization of NodePortLocal rules successful")
	return nil
}

func (c *NPLController) addRulesForNPLPorts(ctx context.Context, allNPLPortsV4, allNPLPortsV6 []rules.PodNodePort) error {
	wg := waitutil.NewGroup()
	addRules := func(portTable *portcache.PortTable, nplPorts []rules.PodNodePort) {
		wg.Go(func() {
			portTable.RestoreRules(ctx, nplPorts)
		})
	}
	if c.portTableIPv4 != nil {
		addRules(c.portTableIPv4, allNPLPortsV4)
	}
	if c.portTableIPv6 != nil {
		addRules(c.portTableIPv6, allNPLPortsV6)
	}
	return wg.WaitUntilWithContext(ctx)
}

// cleanupNPLAnnotationForPod removes the NodePortLocal annotation from the Pod's annotations map entirely.
func (c *NPLController) cleanupNPLAnnotationForPod(ctx context.Context, pod *corev1.Pod) error {
	_, ok := pod.Annotations[types.NPLAnnotationKey]
	if !ok {
		return nil
	}
	return patchPod(ctx, nil, pod, c.kubeClient)
}
