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

package egress

import (
	"sort"
	"strconv"
	"sync"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/memberlist"
	"antrea.io/antrea/pkg/agent/types"
	crdv1b1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1beta1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1beta1"
)

const (
	// workItem is the only item that will be enqueued, used to trigger Egress IP scheduling.
	workItem = "key"
)

// scheduleEventHandler is a callback when an Egress is rescheduled.
type scheduleEventHandler func(egress string)

// scheduleResult is the schedule result of an Egress, including the effective Egress IP and Node.
type scheduleResult struct {
	ip   string
	node string
	err  error
}

// egressIPScheduler is responsible for scheduling Egress IPs to appropriate Nodes according to the Node selector of the
// IP pool, taking Node's capacity into consideration.
type egressIPScheduler struct {
	// cluster is responsible for selecting a Node for a given IP and pool.
	cluster memberlist.Interface

	egressLister       crdlisters.EgressLister
	egressListerSynced cache.InformerSynced

	// queue is used to trigger scheduling. Triggering multiple times before the item is consumed will only cause one
	// execution of scheduling.
	queue workqueue.Interface

	// mutex is used to protect scheduleResults.
	mutex           sync.RWMutex
	scheduleResults map[string]*scheduleResult
	// scheduledOnce indicates whether scheduling has been executed at lease once.
	scheduledOnce *atomic.Bool

	// eventHandlers is the registered callbacks.
	eventHandlers []scheduleEventHandler

	// The default maximum number of Egress IPs a Node can accommodate.
	maxEgressIPsPerNode int
	// nodeToMaxEgressIPs caches the maximum number of Egress IPs of each Node gotten from Node annotation.
	// It takes precedence over the default value.
	nodeToMaxEgressIPs      map[string]int
	nodeToMaxEgressIPsMutex sync.RWMutex
}

func NewEgressIPScheduler(cluster memberlist.Interface, egressInformer crdinformers.EgressInformer, nodeInformer corev1informers.NodeInformer, maxEgressIPsPerNode int) *egressIPScheduler {
	s := &egressIPScheduler{
		cluster:             cluster,
		egressLister:        egressInformer.Lister(),
		egressListerSynced:  egressInformer.Informer().HasSynced,
		scheduleResults:     map[string]*scheduleResult{},
		scheduledOnce:       &atomic.Bool{},
		maxEgressIPsPerNode: maxEgressIPsPerNode,
		nodeToMaxEgressIPs:  map[string]int{},
		queue:               workqueue.New(),
	}
	egressInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    s.addEgress,
			UpdateFunc: s.updateEgress,
			DeleteFunc: s.deleteEgress,
		},
		resyncPeriod,
	)
	nodeInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: s.updateNode,
			UpdateFunc: func(_, newObj interface{}) {
				s.updateNode(newObj)
			},
			DeleteFunc: s.deleteNode,
		},
		resyncPeriod,
	)

	s.cluster.AddClusterEventHandler(func(poolName string) {
		// Trigger scheduling regardless of which pool is changed.
		s.queue.Add(workItem)
	})
	return s
}

func getMaxEgressIPsFromAnnotation(node *corev1.Node) (int, bool, error) {
	maxEgressIPsStr, exists := node.Annotations[types.NodeMaxEgressIPsAnnotationKey]
	if !exists {
		return 0, false, nil
	}
	maxEgressIPs, err := strconv.Atoi(maxEgressIPsStr)
	if err != nil {
		return 0, false, err
	}
	return maxEgressIPs, true, nil
}

// updateNode processes Node ADD and UPDATE events.
func (s *egressIPScheduler) updateNode(obj interface{}) {
	node := obj.(*corev1.Node)
	maxEgressIPs, found, err := getMaxEgressIPsFromAnnotation(node)
	if err != nil {
		klog.ErrorS(err, "The Node's max-egress-ips annotation was invalid", "node", node.Name)
		if s.deleteMaxEgressIPsByNode(node.Name) {
			s.queue.Add(workItem)
		}
		return
	}
	if !found {
		if s.deleteMaxEgressIPsByNode(node.Name) {
			s.queue.Add(workItem)
		}
		return
	}
	if s.updateMaxEgressIPsByNode(node.Name, maxEgressIPs) {
		s.queue.Add(workItem)
	}
}

// deleteNode processes Node DELETE events.
func (s *egressIPScheduler) deleteNode(obj interface{}) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Received unexpected object: %v", obj)
			return
		}
		node, ok = deletedState.Obj.(*corev1.Node)
		if !ok {
			klog.Errorf("DeletedFinalStateUnknown contains non-Node object: %v", deletedState.Obj)
			return
		}
	}
	s.deleteMaxEgressIPsByNode(node.Name)
}

// addEgress processes Egress ADD events.
func (s *egressIPScheduler) addEgress(obj interface{}) {
	egress := obj.(*crdv1b1.Egress)
	if !isEgressSchedulable(egress) {
		return
	}
	s.queue.Add(workItem)
	klog.V(2).InfoS("Egress ADD event triggered Egress IP scheduling", "egress", klog.KObj(egress))
}

// updateEgress processes Egress UPDATE events.
func (s *egressIPScheduler) updateEgress(old, cur interface{}) {
	oldEgress := old.(*crdv1b1.Egress)
	curEgress := cur.(*crdv1b1.Egress)
	if !isEgressSchedulable(oldEgress) && !isEgressSchedulable(curEgress) {
		return
	}
	if oldEgress.Spec.EgressIP == curEgress.Spec.EgressIP && oldEgress.Spec.ExternalIPPool == curEgress.Spec.ExternalIPPool {
		return
	}
	s.queue.Add(workItem)
	klog.V(2).InfoS("Egress UPDATE event triggered Egress IP scheduling", "egress", klog.KObj(curEgress))
}

// deleteEgress processes Egress DELETE events.
func (s *egressIPScheduler) deleteEgress(obj interface{}) {
	egress, ok := obj.(*crdv1b1.Egress)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Received unexpected object: %v", obj)
			return
		}
		egress, ok = deletedState.Obj.(*crdv1b1.Egress)
		if !ok {
			klog.Errorf("DeletedFinalStateUnknown contains non-Egress object: %v", deletedState.Obj)
			return
		}
	}
	if !isEgressSchedulable(egress) {
		return
	}
	s.queue.Add(workItem)
	klog.V(2).InfoS("Egress DELETE event triggered Egress IP scheduling", "egress", klog.KObj(egress))
}

func (s *egressIPScheduler) Run(stopCh <-chan struct{}) {
	klog.InfoS("Starting Egress IP scheduler")
	defer klog.InfoS("Shutting down Egress IP scheduler")
	defer s.queue.ShutDown()

	if !cache.WaitForCacheSync(stopCh, s.egressListerSynced) {
		return
	}

	// Schedule at least once even if there is no Egress to unblock clients waiting for HasScheduled to return true.
	s.queue.Add(workItem)

	go func() {
		for {
			obj, quit := s.queue.Get()
			if quit {
				return
			}
			s.schedule()
			s.queue.Done(obj)
		}
	}()

	<-stopCh
}

func (s *egressIPScheduler) HasScheduled() bool {
	return s.scheduledOnce.Load()
}

func (s *egressIPScheduler) AddEventHandler(handler scheduleEventHandler) {
	s.eventHandlers = append(s.eventHandlers, handler)
}

func (s *egressIPScheduler) GetEgressIPAndNode(egress string) (string, string, error, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	result, exists := s.scheduleResults[egress]
	if !exists {
		return "", "", nil, false
	}
	if result.err != nil {
		return "", "", result.err, false
	}
	return result.ip, result.node, nil, true
}

// EgressesByCreationTimestamp sorts a list of Egresses by creation timestamp.
type EgressesByCreationTimestamp []*crdv1b1.Egress

func (o EgressesByCreationTimestamp) Len() int      { return len(o) }
func (o EgressesByCreationTimestamp) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o EgressesByCreationTimestamp) Less(i, j int) bool {
	if o[i].CreationTimestamp.Equal(&o[j].CreationTimestamp) {
		return o[i].Name < o[j].Name
	}
	return o[i].CreationTimestamp.Before(&o[j].CreationTimestamp)
}

// updateMaxEgressIPsByNode updates the maxEgressIPs for a given Node in the cache.
// It returns whether there is a real change, which indicates if rescheduling is required.
func (s *egressIPScheduler) updateMaxEgressIPsByNode(nodeName string, maxEgressIPs int) bool {
	s.nodeToMaxEgressIPsMutex.Lock()
	defer s.nodeToMaxEgressIPsMutex.Unlock()

	oldMaxEgressIPs, exists := s.nodeToMaxEgressIPs[nodeName]
	if exists && oldMaxEgressIPs == maxEgressIPs {
		return false
	}
	// If the value equals to the default value, no need to cache it and trigger rescheduling.
	if !exists && s.maxEgressIPsPerNode == maxEgressIPs {
		return false
	}
	s.nodeToMaxEgressIPs[nodeName] = maxEgressIPs
	return true
}

// deleteMaxEgressIPsByNode deletes the maxEgressIPs for a given Node in the cache.
// It returns whether there is a real change, which indicates if rescheduling is required.
func (s *egressIPScheduler) deleteMaxEgressIPsByNode(nodeName string) bool {
	s.nodeToMaxEgressIPsMutex.Lock()
	defer s.nodeToMaxEgressIPsMutex.Unlock()

	_, exists := s.nodeToMaxEgressIPs[nodeName]
	if !exists {
		return false
	}
	delete(s.nodeToMaxEgressIPs, nodeName)
	return true
}

// getMaxEgressIPsByNode gets the maxEgressIPs for a given Node.
// If there isn't a value for the Node, the default value will be returned.
func (s *egressIPScheduler) getMaxEgressIPsByNode(nodeName string) int {
	s.nodeToMaxEgressIPsMutex.RLock()
	defer s.nodeToMaxEgressIPsMutex.RUnlock()

	maxEgressIPs, exists := s.nodeToMaxEgressIPs[nodeName]
	if exists {
		return maxEgressIPs
	}
	return s.maxEgressIPsPerNode
}

// schedule takes the spec of Egress and ExternalIPPool and the state of memberlist cluster as inputs, generates
// scheduling results deterministically. When every Node's capacity is sufficient, each Egress's schedule is independent
// and is only determined by the consistent hash map. When any Node's capacity is insufficient, one Egress's schedule
// may be affected by Egresses created before it. It will be triggerred when any schedulable Egress changes or the state
// of memberlist cluster changes, and will notify Egress schedule event subscribers of Egresses that are rescheduled.
//
// Note that it's possible that different agents decide different IP - Node assignment because their caches of Egress or
// the states of memberlist cluster are inconsistent at a moment. But all agents should get the same schedule results
// and correct IP assignment when their caches converge.
func (s *egressIPScheduler) schedule() {
	var egressesToUpdate []string
	newResults := map[string]*scheduleResult{}
	nodeToIPs := map[string]sets.Set[string]{}
	egresses, _ := s.egressLister.List(labels.Everything())
	// Sort Egresses by creation timestamp to make the result deterministic and prioritize objected created earlier
	// when the total capacity is insufficient.
	sort.Sort(EgressesByCreationTimestamp(egresses))
	for _, egress := range egresses {
		// Ignore Egresses that shouldn't be scheduled.
		if !isEgressSchedulable(egress) {
			continue
		}

		maxEgressIPsFilter := func(node string) bool {
			// Count the Egress IPs that are already assigned to this Node.
			ipsOnNode, _ := nodeToIPs[node]
			numIPs := ipsOnNode.Len()
			// Check if this Node can accommodate the new Egress IP.
			if !ipsOnNode.Has(egress.Spec.EgressIP) {
				numIPs += 1
			}
			return numIPs <= s.getMaxEgressIPsByNode(node)
		}
		node, err := s.cluster.SelectNodeForIP(egress.Spec.EgressIP, egress.Spec.ExternalIPPool, maxEgressIPsFilter)
		if err != nil {
			if err == memberlist.ErrNoNodeAvailable {
				klog.InfoS("No Node is eligible for Egress", "egress", klog.KObj(egress))
			} else {
				klog.ErrorS(err, "Failed to select Node for Egress", "egress", klog.KObj(egress))
			}
			// Store error in its result to differentiate scheduling error from unprocessed case.
			newResults[egress.Name] = &scheduleResult{err: err}
			continue
		}
		result := &scheduleResult{
			ip:   egress.Spec.EgressIP,
			node: node,
		}
		newResults[egress.Name] = result

		ips, exists := nodeToIPs[node]
		if !exists {
			ips = sets.New[string]()
			nodeToIPs[node] = ips
		}
		ips.Insert(egress.Spec.EgressIP)
	}

	func() {
		s.mutex.Lock()
		defer s.mutex.Unlock()

		// Identify Egresses whose schedule results are updated.
		prevResults := s.scheduleResults
		for egress, result := range newResults {
			prevResult, exists := prevResults[egress]
			if !exists || prevResult.ip != result.ip || prevResult.node != result.node || prevResult.err != result.err {
				egressesToUpdate = append(egressesToUpdate, egress)
			}
			delete(prevResults, egress)
		}
		for egress := range prevResults {
			egressesToUpdate = append(egressesToUpdate, egress)
		}

		// Record the new results.
		s.scheduleResults = newResults
	}()

	for _, egress := range egressesToUpdate {
		for _, handler := range s.eventHandlers {
			handler(egress)
		}
	}

	s.scheduledOnce.Store(true)
}
