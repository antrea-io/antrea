// Copyright 2022 Antrea Authors
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

package multicluster

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/member"
	mcinformers "antrea.io/antrea/multicluster/pkg/client/informers/externalversions/multicluster/v1alpha1"
	mclisters "antrea.io/antrea/multicluster/pkg/client/listers/multicluster/v1alpha1"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	antreatypes "antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/util/channel"
)

const (
	stretchedNetworkPolicyWorker         = 4
	stretchedNetworkPolicyControllerName = "AntreaAgentStretchedNetworkPolicyController"

	labelIndex = "Label"
)

type podSet map[types.NamespacedName]struct{}

// StretchedNetworkPolicyController is used to update classifier flows of Pods.
// It will make sure the latest LabelIdentity of the Pod, if available, will be
// loaded into tun_id in the classifier flow of the Pod.
// If the LabelIdentity of the Pod is not available when updating, the
// UnknownLabelIdentity will be loaded. When the actual LabelIdentity is created,
// the classifier flow will be updated accordingly.
type StretchedNetworkPolicyController struct {
	ofClient                  openflow.Client
	interfaceStore            interfacestore.InterfaceStore
	podInformer               cache.SharedIndexInformer
	podLister                 corelisters.PodLister
	podListerSynced           cache.InformerSynced
	namespaceInformer         coreinformers.NamespaceInformer
	namespaceLister           corelisters.NamespaceLister
	namespaceListerSynced     cache.InformerSynced
	labelIdentityInformer     mcinformers.LabelIdentityInformer
	labelIdentityLister       mclisters.LabelIdentityLister
	LabelIdentityListerSynced cache.InformerSynced
	queue                     workqueue.RateLimitingInterface
	lock                      sync.RWMutex

	labelToPods map[string]podSet
	podToLabel  map[types.NamespacedName]string
}

func NewMCAgentStretchedNetworkPolicyController(
	client openflow.Client,
	interfaceStore interfacestore.InterfaceStore,
	podInformer cache.SharedIndexInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	labelIdentityInformer mcinformers.LabelIdentityInformer,
	podUpdateSubscriber channel.Subscriber,
) *StretchedNetworkPolicyController {
	controller := &StretchedNetworkPolicyController{
		ofClient:                  client,
		interfaceStore:            interfaceStore,
		podInformer:               podInformer,
		podLister:                 corelisters.NewPodLister(podInformer.GetIndexer()),
		podListerSynced:           podInformer.HasSynced,
		namespaceInformer:         namespaceInformer,
		namespaceLister:           namespaceInformer.Lister(),
		namespaceListerSynced:     namespaceInformer.Informer().HasSynced,
		labelIdentityInformer:     labelIdentityInformer,
		labelIdentityLister:       labelIdentityInformer.Lister(),
		LabelIdentityListerSynced: labelIdentityInformer.Informer().HasSynced,
		queue:                     workqueue.NewNamedRateLimitingQueue(workqueue.DefaultItemBasedRateLimiter(), "stretchedNetworkPolicy"),
		labelToPods:               map[string]podSet{},
		podToLabel:                map[types.NamespacedName]string{},
	}

	controller.podInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			// Pod add event will be handled by processPodCNIAddEvent.
			// We choose to use events from podUpdateSubscriber instead of the informer because
			// the controller can only update the Pod classifier flow when the Pod container
			// config is available. Events from the Informer may be received way before the Pod
			// container config is available, which will cause the work item be continually
			// re-queued with an exponential increased delay time. When the Pod container
			// config is ready, the work item could wait for a long time to be processed.
			UpdateFunc: controller.processPodUpdate,
			DeleteFunc: controller.processPodDelete,
		},
		resyncPeriod,
	)
	controller.namespaceInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: controller.processNamespaceUpdate,
		},
		resyncPeriod,
	)
	controller.labelIdentityInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: controller.processLabelIdentityEvent,
			UpdateFunc: func(old, cur interface{}) {
				controller.processLabelIdentityEvent(cur)
			},
			DeleteFunc: controller.processLabelIdentityEvent,
		},
		resyncPeriod,
	)
	podUpdateSubscriber.Subscribe(controller.processPodCNIAddEvent)

	controller.labelIdentityInformer.Informer().AddIndexers(cache.Indexers{
		labelIndex: func(obj interface{}) ([]string, error) {
			labelID, ok := obj.(*v1alpha1.LabelIdentity)
			if !ok {
				return []string{}, nil
			}
			return []string{labelID.Spec.Label}, nil
		}})
	return controller
}

func (s *StretchedNetworkPolicyController) Run(stopCh <-chan struct{}) {
	defer s.queue.ShutDown()

	klog.InfoS("Starting controller", "controller", stretchedNetworkPolicyControllerName)
	defer klog.InfoS("Shutting down controller", "controller", stretchedNetworkPolicyControllerName)
	cacheSyncs := []cache.InformerSynced{s.podListerSynced, s.namespaceListerSynced, s.LabelIdentityListerSynced}
	if !cache.WaitForNamedCacheSync(stretchedNetworkPolicyControllerName, stopCh, cacheSyncs...) {
		return
	}
	s.enqueueAllPods()
	for i := 0; i < stretchedNetworkPolicyWorker; i++ {
		go wait.Until(s.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (s *StretchedNetworkPolicyController) enqueueAllPods() {
	pods, _ := s.podLister.List(labels.Everything())
	for _, pod := range pods {
		if pod.Spec.HostNetwork {
			continue
		}
		s.queue.Add(getPodReference(pod))
	}
}

// worker is a long-running function that will continually call the processNextWorkItem
// function in order to read and process a message on the workqueue.
func (s *StretchedNetworkPolicyController) worker() {
	for s.processNextWorkItem() {
	}
}

func (s *StretchedNetworkPolicyController) processNextWorkItem() bool {
	obj, quit := s.queue.Get()
	if quit {
		return false
	}
	defer s.queue.Done(obj)

	if podRef, ok := obj.(types.NamespacedName); !ok {
		s.queue.Forget(obj)
		klog.ErrorS(nil, "Expected type 'NamespacedName' in work queue but got object", "object", obj)
	} else if err := s.syncPodClassifierFlow(podRef); err == nil {
		s.queue.Forget(podRef)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		s.queue.AddRateLimited(podRef)
		klog.ErrorS(err, "Error syncing Pod classifier flow, requeuing", "name", podRef.Name, "namespace", podRef.Namespace)
	}
	return true
}

// syncPodClassifierFlow gets containerConfigs and labelIdentity according to a
// Pod reference and updates this Pod's classifierFlow.
func (s *StretchedNetworkPolicyController) syncPodClassifierFlow(podRef types.NamespacedName) error {
	pod, err := s.podLister.Pods(podRef.Namespace).Get(podRef.Name)
	if err != nil || pod.Spec.HostNetwork {
		return nil
	}
	containerConfigs := s.interfaceStore.GetContainerInterfacesByPod(podRef.Name, podRef.Namespace)
	if len(containerConfigs) == 0 {
		klog.InfoS("Pod container config not found, will retry after it's ready", "name", podRef.Name, "namespace", podRef.Namespace)
		return nil
	}
	podNS, err := s.namespaceLister.Get(podRef.Namespace)
	if err != nil {
		return fmt.Errorf("can't get Namespace %s: %v", podRef.Namespace, err)
	}
	normalizedLabel := member.GetNormalizedLabel(podNS.Labels, pod.Labels, podNS.Name)
	labelID := s.getLabelIdentity(podRef, normalizedLabel)
	return s.ofClient.InstallPodFlows(
		containerConfigs[0].InterfaceName,
		containerConfigs[0].IPs,
		containerConfigs[0].MAC,
		uint32(containerConfigs[0].OFPort),
		containerConfigs[0].VLANID,
		&labelID,
	)
}

// getLabelIdentity updates labelToPods and podToLabel and returns the
// LabelIdentity based on the normalizedLabel.
func (s *StretchedNetworkPolicyController) getLabelIdentity(podRef types.NamespacedName, normalizedLabel string) uint32 {
	s.lock.Lock()
	oldNormalizedLabel, ok := s.podToLabel[podRef]
	if ok && oldNormalizedLabel != normalizedLabel {
		s.deleteLabelToPod(oldNormalizedLabel, podRef)
	}
	if !ok || oldNormalizedLabel != normalizedLabel {
		s.addLabelToPod(normalizedLabel, podRef)
		s.podToLabel[podRef] = normalizedLabel
	}
	s.lock.Unlock()

	labelID := openflow.UnknownLabelIdentity
	if objs, err := s.labelIdentityInformer.Informer().GetIndexer().ByIndex(labelIndex, normalizedLabel); err == nil && len(objs) == 1 {
		labelIdentity := objs[0].(*v1alpha1.LabelIdentity)
		labelID = labelIdentity.Spec.ID
	}
	return labelID
}

func (s *StretchedNetworkPolicyController) processPodCNIAddEvent(e interface{}) {
	podEvent := e.(antreatypes.PodUpdate)
	if !podEvent.IsAdd {
		return
	}
	podRef := types.NamespacedName{
		Namespace: podEvent.PodNamespace,
		Name:      podEvent.PodName,
	}
	s.queue.Add(podRef)
}

// processPodUpdate handles Pod update events. It only enqueues the Pod if the
// Labels of this Pod have been updated.
func (s *StretchedNetworkPolicyController) processPodUpdate(old, cur interface{}) {
	oldPod, _ := old.(*v1.Pod)
	curPod, _ := cur.(*v1.Pod)
	if curPod.Spec.HostNetwork {
		klog.V(5).InfoS("Skipped processing hostNetwork Pod update event", "name", curPod.Name, "namespace", curPod.Namespace)
		return
	}
	if reflect.DeepEqual(oldPod.Labels, curPod.Labels) {
		klog.V(5).InfoS("Pod UpdateFunc received a Pod update event, "+
			"but labels are the same. Skip it", "name", curPod.Name, "namespace", curPod.Namespace)
		return
	}
	s.queue.Add(getPodReference(curPod))
}

// processPodDelete handles Pod delete events. It deletes the Pod from the
// labelToPods and podToLabel. After Pod is deleted, its classifier flow will also
// be deleted by podConfigurator. So no need to enqueue this Pod to update its
// classifier flow.
func (s *StretchedNetworkPolicyController) processPodDelete(old interface{}) {
	oldPod, _ := old.(*v1.Pod)
	oldPodRef := getPodReference(oldPod)
	s.lock.Lock()
	defer s.lock.Unlock()
	if podLabel, ok := s.podToLabel[oldPodRef]; ok {
		s.deleteLabelToPod(podLabel, oldPodRef)
		delete(s.podToLabel, oldPodRef)
	}
}

// processNamespaceUpdate handles Namespace update events. It only enqueues all
// Pods in this Namespace if the Labels of this Namespace have been updated.
func (s *StretchedNetworkPolicyController) processNamespaceUpdate(old, cur interface{}) {
	oldNS, _ := old.(*v1.Namespace)
	curNS, _ := cur.(*v1.Namespace)
	if reflect.DeepEqual(oldNS.Labels, curNS.Labels) {
		klog.V(5).InfoS("Namespace UpdateFunc received a Namespace update event, but labels are the same. Skip it", "namespace", curNS.Name)
		return
	}
	allPodsInNS, _ := s.podLister.Pods(curNS.Name).List(labels.Everything())
	for _, pod := range allPodsInNS {
		if pod.Spec.HostNetwork {
			continue
		}
		s.queue.Add(getPodReference(pod))
	}
}

// processLabelIdentityEvent handles labelIdentity add/update/delete event.
// It will enqueue all Pods affected by this labelIdentity
func (s *StretchedNetworkPolicyController) processLabelIdentityEvent(cur interface{}) {
	labelIdentity, _ := cur.(*v1alpha1.LabelIdentity)
	s.lock.RLock()
	defer s.lock.RUnlock()
	if podSet, ok := s.labelToPods[labelIdentity.Spec.Label]; ok {
		for podRef := range podSet {
			s.queue.Add(podRef)
		}
	}
}

func (s *StretchedNetworkPolicyController) addLabelToPod(normalizedLabel string, podRef types.NamespacedName) {
	if _, ok := s.labelToPods[normalizedLabel]; ok {
		s.labelToPods[normalizedLabel][podRef] = struct{}{}
	} else {
		s.labelToPods[normalizedLabel] = podSet{podRef: struct{}{}}
	}
}

func (s *StretchedNetworkPolicyController) deleteLabelToPod(normalizedLabel string, podRef types.NamespacedName) {
	if _, ok := s.labelToPods[normalizedLabel]; ok {
		delete(s.labelToPods[normalizedLabel], podRef)
		if len(s.labelToPods[normalizedLabel]) == 0 {
			delete(s.labelToPods, normalizedLabel)
		}
	}
}

func getPodReference(pod *v1.Pod) types.NamespacedName {
	return types.NamespacedName{
		Name:      pod.Name,
		Namespace: pod.Namespace,
	}
}
