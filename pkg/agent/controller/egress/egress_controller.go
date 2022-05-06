// Copyright 2021 Antrea Authors
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
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/ipassigner"
	"antrea.io/antrea/pkg/agent/memberlist"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/route"
	"antrea.io/antrea/pkg/agent/types"
	cpv1b2 "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	clientsetversioned "antrea.io/antrea/pkg/client/clientset/versioned"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	"antrea.io/antrea/pkg/controller/metrics"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	controllerName = "AntreaAgentEgressController"
	// How long to wait before retrying the processing of an Egress change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing an Egress change.
	defaultWorkers = 4
	// Disable resyncing.
	resyncPeriod time.Duration = 0
	// minEgressMark is the minimum mark of Egress IPs can be configured on a Node.
	minEgressMark = 1
	// maxEgressMark is the maximum mark of Egress IPs can be configured on a Node.
	maxEgressMark = 255

	egressIPIndex       = "egressIP"
	externalIPPoolIndex = "externalIPPool"

	// egressDummyDevice is the dummy device that holds the Egress IPs configured to the system by antrea-agent.
	egressDummyDevice = "antrea-egress0"
)

var emptyWatch = watch.NewEmptyWatch()

// egressState keeps the actual state of an Egress that has been realized.
type egressState struct {
	// The actual egress IP of the Egress. If it's different from the desired IP, there is an update to EgressIP, and we
	// need to remove previously installed flows.
	egressIP string
	// The actual datapath mark of this Egress. Used to check if the mark changes since last process.
	mark uint32
	// The actual openflow ports for which we have installed SNAT rules. Used to identify stale openflow ports when
	// updating or deleting an Egress.
	ofPorts sets.Int32
	// The actual Pods of the Egress. Used to identify stale Pods when updating or deleting an Egress.
	pods sets.String
}

// egressIPState keeps the actual state of an Egress IP. It's maintained separately from egressState because
// multiple Egresses can share an EgressIP.
type egressIPState struct {
	egressIP net.IP
	// The names of the Egresses that are currently referring to it.
	egressNames sets.String
	// The datapath mark of this Egress IP. 0 if this is not a local IP.
	mark uint32
	// Whether its flows have been installed.
	flowsInstalled bool
	// Whether its iptables rule has been installed.
	ruleInstalled bool
}

// egressBinding keeps the Egresses applying to a Pod.
// There is one effective Egress for a Pod at any given time.
type egressBinding struct {
	effectiveEgress     string
	alternativeEgresses sets.String
}

type EgressController struct {
	ofClient             openflow.Client
	routeClient          route.Interface
	crdClient            clientsetversioned.Interface
	antreaClientProvider agent.AntreaClientProvider

	egressInformer     cache.SharedIndexInformer
	egressLister       crdlisters.EgressLister
	egressListerSynced cache.InformerSynced
	queue              workqueue.RateLimitingInterface

	// Use an interface for IP detector to enable testing.
	localIPDetector ipassigner.LocalIPDetector
	ifaceStore      interfacestore.InterfaceStore
	nodeName        string
	idAllocator     *idAllocator

	egressGroups      map[string]sets.String
	egressGroupsMutex sync.RWMutex

	egressBindings      map[string]*egressBinding
	egressBindingsMutex sync.RWMutex

	egressStates map[string]*egressState
	// The mutex is to protect the map, not the egressState items. The workqueue guarantees an Egress will only be
	// processed by a single worker at any time. So the returned EgressState has no race condition.
	egressStatesMutex sync.RWMutex

	egressIPStates      map[string]*egressIPState
	egressIPStatesMutex sync.Mutex

	cluster    *memberlist.Cluster
	ipAssigner ipassigner.IPAssigner
}

func NewEgressController(
	ofClient openflow.Client,
	antreaClientGetter agent.AntreaClientProvider,
	crdClient clientsetversioned.Interface,
	ifaceStore interfacestore.InterfaceStore,
	routeClient route.Interface,
	nodeName string,
	nodeTransportInterface string,
	cluster *memberlist.Cluster,
	egressInformer crdinformers.EgressInformer,
	podUpdateSubscriber channel.Subscriber,
) (*EgressController, error) {
	c := &EgressController{
		ofClient:             ofClient,
		routeClient:          routeClient,
		antreaClientProvider: antreaClientGetter,
		crdClient:            crdClient,
		queue:                workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "egressgroup"),
		egressInformer:       egressInformer.Informer(),
		egressLister:         egressInformer.Lister(),
		egressListerSynced:   egressInformer.Informer().HasSynced,
		nodeName:             nodeName,
		ifaceStore:           ifaceStore,
		egressGroups:         map[string]sets.String{},
		egressStates:         map[string]*egressState{},
		egressIPStates:       map[string]*egressIPState{},
		egressBindings:       map[string]*egressBinding{},
		localIPDetector:      ipassigner.NewLocalIPDetector(),
		idAllocator:          newIDAllocator(minEgressMark, maxEgressMark),
		cluster:              cluster,
	}
	ipAssigner, err := ipassigner.NewIPAssigner(nodeTransportInterface, egressDummyDevice)
	if err != nil {
		return nil, fmt.Errorf("initializing egressIP assigner failed: %v", err)
	}
	c.ipAssigner = ipAssigner

	c.egressInformer.AddIndexers(cache.Indexers{egressIPIndex: func(obj interface{}) ([]string, error) {
		egress, ok := obj.(*crdv1a2.Egress)
		if !ok {
			return nil, fmt.Errorf("obj is not Egress: %+v", obj)
		}
		return []string{egress.Spec.EgressIP}, nil
	}})
	// externalIPPoolIndex will be used to get all Egresses associated with a given ExternalIPPool.
	c.egressInformer.AddIndexers(cache.Indexers{externalIPPoolIndex: func(obj interface{}) (strings []string, e error) {
		egress, ok := obj.(*crdv1a2.Egress)
		if !ok {
			return nil, fmt.Errorf("obj is not Egress: %+v", obj)
		}
		if egress.Spec.ExternalIPPool == "" {
			return nil, nil
		}
		return []string{egress.Spec.ExternalIPPool}, nil
	}})
	c.egressInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addEgress,
			UpdateFunc: c.updateEgress,
			DeleteFunc: c.deleteEgress,
		},
		resyncPeriod,
	)
	// Subscribe Pod update events from CNIServer to enforce Egress earlier, instead of waiting for their IPs are
	// reported to kube-apiserver and processed by antrea-controller.
	podUpdateSubscriber.Subscribe(c.processPodUpdate)
	c.localIPDetector.AddEventHandler(c.onLocalIPUpdate)
	c.cluster.AddClusterEventHandler(c.enqueueEgressesByExternalIPPool)
	return c, nil
}

// processPodUpdate will be called when CNIServer publishes a Pod update event.
// It triggers reconciling the effective Egress of the Pod.
func (c *EgressController) processPodUpdate(e interface{}) {
	c.egressBindingsMutex.Lock()
	defer c.egressBindingsMutex.Unlock()
	podEvent := e.(types.PodUpdate)
	pod := k8s.NamespacedName(podEvent.PodNamespace, podEvent.PodName)
	binding, exists := c.egressBindings[pod]
	if !exists {
		return
	}
	c.queue.Add(binding.effectiveEgress)
}

// addEgress processes Egress ADD events.
func (c *EgressController) addEgress(obj interface{}) {
	egress := obj.(*crdv1a2.Egress)
	if egress.Spec.EgressIP == "" {
		return
	}
	c.queue.Add(egress.Name)
	klog.V(2).InfoS("Processed Egress ADD event", "egress", klog.KObj(egress))
}

// updateEgress processes Egress UPDATE events.
func (c *EgressController) updateEgress(old, cur interface{}) {
	oldEgress := old.(*crdv1a2.Egress)
	curEgress := cur.(*crdv1a2.Egress)
	// Ignore handling the Egress Status change if Egress IP already has been assigned on current node.
	if curEgress.Status.EgressNode == c.nodeName && oldEgress.GetGeneration() == curEgress.GetGeneration() {
		return
	}
	c.queue.Add(curEgress.Name)
	klog.V(2).InfoS("Processed Egress UPDATE event", "egress", klog.KObj(curEgress))
}

// deleteEgress processes Egress DELETE events.
func (c *EgressController) deleteEgress(obj interface{}) {
	egress, ok := obj.(*crdv1a2.Egress)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Received unexpected object: %v", obj)
			return
		}
		egress, ok = deletedState.Obj.(*crdv1a2.Egress)
		if !ok {
			klog.Errorf("DeletedFinalStateUnknown contains non-Egress object: %v", deletedState.Obj)
			return
		}
	}
	c.queue.Add(egress.Name)
	klog.V(2).InfoS("Processed Egress DELETE event", "egress", klog.KObj(egress))
}

func (c *EgressController) onLocalIPUpdate(ip string, added bool) {
	egresses, _ := c.egressInformer.GetIndexer().ByIndex(egressIPIndex, ip)
	if len(egresses) == 0 {
		return
	}
	if added {
		klog.Infof("Detected Egress IP address %s added to this Node", ip)
	} else {
		klog.Infof("Detected Egress IP address %s deleted from this Node", ip)
	}
	for _, obj := range egresses {
		egress := obj.(*crdv1a2.Egress)
		c.queue.Add(egress.Name)
	}
}

// enqueueEgressesByExternalIPPool enqueues all Egresses that refer to the provided ExternalIPPool,
// the ExternalIPPool is affected by a Node update/create/delete event or
// Node leaves/join cluster event or ExternalIPPool changed.
func (c *EgressController) enqueueEgressesByExternalIPPool(eipName string) {
	objects, _ := c.egressInformer.GetIndexer().ByIndex(externalIPPoolIndex, eipName)
	for _, object := range objects {
		egress := object.(*crdv1a2.Egress)
		c.queue.Add(egress.Name)
	}
	klog.InfoS("Detected ExternalIPPool event", "ExternalIPPool", eipName, "enqueueEgressNum", len(objects))
}

// Run will create defaultWorkers workers (go routines) which will process the Egress events from the
// workqueue.
func (c *EgressController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	go c.localIPDetector.Run(stopCh)

	go c.ipAssigner.Run(stopCh)
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.egressListerSynced, c.localIPDetector.HasSynced) {
		return
	}

	c.removeStaleEgressIPs()

	go wait.NonSlidingUntil(c.watchEgressGroup, 5*time.Second, stopCh)

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

// removeStaleEgressIPs unassigns stale Egress IPs that shouldn't be present on this Node.
// These Egresses were either deleted from the Kubernetes API or migrated to other Nodes when the agent on this Node
// was not running.
func (c *EgressController) removeStaleEgressIPs() {
	desiredLocalEgressIPs := sets.NewString()
	egresses, _ := c.egressLister.List(labels.Everything())
	for _, egress := range egresses {
		if egress.Spec.EgressIP != "" && egress.Spec.ExternalIPPool != "" && egress.Status.EgressNode == c.nodeName {
			desiredLocalEgressIPs.Insert(egress.Spec.EgressIP)
		}
	}
	actualLocalEgressIPs := c.ipAssigner.AssignedIPs()
	for ip := range actualLocalEgressIPs.Difference(desiredLocalEgressIPs) {
		if err := c.ipAssigner.UnassignIP(ip); err != nil {
			klog.ErrorS(err, "Failed to clean up stale Egress IP", "ip", ip)
		}
	}
}

// worker is a long-running function that will continually call the processNextWorkItem function in
// order to read and process a message on the workqueue.
func (c *EgressController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *EgressController) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)

	// We expect strings (Egress name) to come off the workqueue.
	if key, ok := obj.(string); !ok {
		// As the item in the workqueue is actually invalid, we call Forget here else we'd
		// go into a loop of attempting to process a work item that is invalid.
		// This should not happen.
		c.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else if err := c.syncEgress(key); err == nil {
		// If no error occurs we Forget this item so it does not get queued again until
		// another change happens.
		c.queue.Forget(key)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.Errorf("Error syncing Egress %s, requeuing. Error: %v", key, err)
	}
	return true
}

// realizeEgressIP realizes an Egress IP. Multiple Egresses can share the same Egress IP.
// If it's called the first time for a local Egress IP, it allocates a locally-unique mark for the IP and installs flows
// and iptables rule for this IP and the mark.
// If the Egress IP is changed from local to non local, it uninstalls flows and iptables rule and releases the mark.
// The method returns the mark on success. Non local Egresses use 0 as the mark.
func (c *EgressController) realizeEgressIP(egressName, egressIP string) (uint32, error) {
	isLocalIP := c.localIPDetector.IsLocalIP(egressIP)

	c.egressIPStatesMutex.Lock()
	defer c.egressIPStatesMutex.Unlock()

	ipState, exists := c.egressIPStates[egressIP]
	// Create an egressIPState if this is the first Egress using the IP.
	if !exists {
		ipState = &egressIPState{
			egressIP:    net.ParseIP(egressIP),
			egressNames: sets.NewString(egressName),
		}
		c.egressIPStates[egressIP] = ipState
	} else if !ipState.egressNames.Has(egressName) {
		ipState.egressNames.Insert(egressName)
	}

	var err error
	if isLocalIP {
		// Ensure the Egress IP has a mark allocated when it's a local IP.
		if ipState.mark == 0 {
			ipState.mark, err = c.idAllocator.allocate()
			if err != nil {
				return 0, fmt.Errorf("error allocating mark for IP %s: %v", egressIP, err)
			}
		}
		// Ensure datapath is installed properly.
		if !ipState.flowsInstalled {
			if err := c.ofClient.InstallSNATMarkFlows(ipState.egressIP, ipState.mark); err != nil {
				return 0, fmt.Errorf("error installing SNAT mark flows for IP %s: %v", ipState.egressIP, err)
			}
			ipState.flowsInstalled = true
		}
		if !ipState.ruleInstalled {
			if err := c.routeClient.AddSNATRule(ipState.egressIP, ipState.mark); err != nil {
				return 0, fmt.Errorf("error installing SNAT rule for IP %s: %v", ipState.egressIP, err)
			}
			ipState.ruleInstalled = true
		}
	} else {
		// Ensure datapath is uninstalled properly.
		if ipState.ruleInstalled {
			if err := c.routeClient.DeleteSNATRule(ipState.mark); err != nil {
				return 0, fmt.Errorf("error uninstalling SNAT rule for IP %s: %v", ipState.egressIP, err)
			}
			ipState.ruleInstalled = false
		}
		if ipState.flowsInstalled {
			if err := c.ofClient.UninstallSNATMarkFlows(ipState.mark); err != nil {
				return 0, fmt.Errorf("error uninstalling SNAT mark flows for IP %s: %v", ipState.egressIP, err)
			}
			ipState.flowsInstalled = false
		}
		if ipState.mark != 0 {
			err := c.idAllocator.release(ipState.mark)
			if err != nil {
				return 0, fmt.Errorf("error releasing mark for IP %s: %v", egressIP, err)
			}
			ipState.mark = 0
		}
	}
	return ipState.mark, nil
}

// unrealizeEgressIP unrealizes an Egress IP, reverts what realizeEgressIP does.
// For a local Egress IP, only when the last Egress unrealizes the Egress IP, it will releases the IP's mark and
// uninstalls corresponding flows and iptables rule.
func (c *EgressController) unrealizeEgressIP(egressName, egressIP string) error {
	c.egressIPStatesMutex.Lock()
	defer c.egressIPStatesMutex.Unlock()

	ipState, exist := c.egressIPStates[egressIP]
	// The Egress IP was not configured before, do nothing.
	if !exist {
		return nil
	}
	// Unlink the Egress from the EgressIP. If it's the last Egress referring to it, uninstall its datapath rules and
	// release the mark if installed.
	ipState.egressNames.Delete(egressName)
	if len(ipState.egressNames) > 0 {
		return nil
	}
	if ipState.mark != 0 {
		if ipState.ruleInstalled {
			if err := c.routeClient.DeleteSNATRule(ipState.mark); err != nil {
				return err
			}
			ipState.ruleInstalled = false
		}
		if ipState.flowsInstalled {
			if err := c.ofClient.UninstallSNATMarkFlows(ipState.mark); err != nil {
				return err
			}
			ipState.flowsInstalled = false
		}
		c.idAllocator.release(ipState.mark)
	}
	delete(c.egressIPStates, egressIP)
	return nil
}

func (c *EgressController) getEgressState(egressName string) (*egressState, bool) {
	c.egressStatesMutex.RLock()
	defer c.egressStatesMutex.RUnlock()
	state, exists := c.egressStates[egressName]
	return state, exists
}

func (c *EgressController) deleteEgressState(egressName string) {
	c.egressStatesMutex.Lock()
	defer c.egressStatesMutex.Unlock()
	delete(c.egressStates, egressName)
}

func (c *EgressController) newEgressState(egressName string, egressIP string) *egressState {
	c.egressStatesMutex.Lock()
	defer c.egressStatesMutex.Unlock()
	state := &egressState{
		egressIP: egressIP,
		ofPorts:  sets.NewInt32(),
		pods:     sets.NewString(),
	}
	c.egressStates[egressName] = state
	return state
}

// bindPodEgress binds the Pod with the Egress and returns whether this Egress is the effective one for the Pod.
func (c *EgressController) bindPodEgress(pod, egress string) bool {
	c.egressBindingsMutex.Lock()
	defer c.egressBindingsMutex.Unlock()

	binding, exists := c.egressBindings[pod]
	if !exists {
		// Promote itself as the effective Egress if there was not one.
		c.egressBindings[pod] = &egressBinding{
			effectiveEgress:     egress,
			alternativeEgresses: sets.NewString(),
		}
		return true
	}
	if binding.effectiveEgress == egress {
		return true
	}
	if !binding.alternativeEgresses.Has(egress) {
		binding.alternativeEgresses.Insert(egress)
	}
	return false
}

// unbindPodEgress unbinds the Pod with the Egress.
// If the unbound Egress was the effective one for the Pod and there are any alternative ones, it will return the new
// effective Egress and true. Otherwise it return empty string and false.
func (c *EgressController) unbindPodEgress(pod, egress string) (string, bool) {
	c.egressBindingsMutex.Lock()
	defer c.egressBindingsMutex.Unlock()

	// The binding must exist.
	binding := c.egressBindings[pod]
	if binding.effectiveEgress == egress {
		var popped bool
		binding.effectiveEgress, popped = binding.alternativeEgresses.PopAny()
		if !popped {
			// Remove the Pod's binding if there is no alternative.
			delete(c.egressBindings, pod)
			return "", false
		}
		return binding.effectiveEgress, true
	}
	binding.alternativeEgresses.Delete(egress)
	return "", false
}

func (c *EgressController) updateEgressStatus(egress *crdv1a2.Egress, isLocal bool) error {
	toUpdate := egress.DeepCopy()
	var updateErr, getErr error
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if isLocal {
			// Do nothing if the current EgressNode in status is already this Node.
			if toUpdate.Status.EgressNode == c.nodeName {
				return nil
			}
			toUpdate.Status.EgressNode = c.nodeName
		} else {
			// Do nothing if the current EgressNode in status is not this Node.
			if toUpdate.Status.EgressNode != c.nodeName {
				return nil
			}
			toUpdate.Status.EgressNode = ""
		}
		klog.V(2).InfoS("Updating Egress status", "Egress", egress.Name, "oldNode", egress.Status.EgressNode, "newNode", toUpdate.Status.EgressNode)
		_, updateErr = c.crdClient.CrdV1alpha2().Egresses().UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{})
		if updateErr != nil && errors.IsConflict(updateErr) {
			if toUpdate, getErr = c.crdClient.CrdV1alpha2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{}); getErr != nil {
				return getErr
			}
		}
		// Return the error from UPDATE.
		return updateErr
	}); err != nil {
		return err
	}
	klog.V(2).InfoS("Updated Egress status", "Egress", egress.Name)
	metrics.AntreaEgressStatusUpdates.Inc()
	return nil
}

func (c *EgressController) syncEgress(egressName string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing Egress for %s. (%v)", egressName, time.Since(startTime))
	}()

	egress, err := c.egressLister.Get(egressName)
	if err != nil {
		// The Egress has been removed, clean it up.
		if errors.IsNotFound(err) {
			eState, exist := c.getEgressState(egressName)
			// The Egress hasn't been installed, do nothing.
			if !exist {
				return nil
			}
			if err := c.uninstallEgress(egressName, eState); err != nil {
				return err
			}
			return nil
		}
		return err
	}

	eState, exist := c.getEgressState(egressName)
	// If the EgressIP changes, uninstalls this Egress first.
	if exist && eState.egressIP != egress.Spec.EgressIP {
		if err := c.uninstallEgress(egressName, eState); err != nil {
			return err
		}
		exist = false
	}
	// Do not proceed if EgressIP is empty.
	if egress.Spec.EgressIP == "" {
		return nil
	}
	if !exist {
		eState = c.newEgressState(egressName, egress.Spec.EgressIP)
	}

	localNodeSelected, err := c.cluster.ShouldSelectIP(egress.Spec.EgressIP, egress.Spec.ExternalIPPool)
	if err != nil {
		return err
	}
	if localNodeSelected {
		// Ensure the Egress IP is assigned to the system.
		if err := c.ipAssigner.AssignIP(egress.Spec.EgressIP); err != nil {
			return err
		}
	} else {
		// Unassign the Egress IP from the local Node if it was assigned by the agent.
		if err := c.ipAssigner.UnassignIP(egress.Spec.EgressIP); err != nil {
			return err
		}
	}

	// Realize the latest EgressIP and get the desired mark.
	mark, err := c.realizeEgressIP(egressName, egress.Spec.EgressIP)
	if err != nil {
		return err
	}

	// If the mark changes, uninstall all of the Egress's Pod flows first, then installs them with new mark.
	// It could happen when the Egress IP is added to or removed from the Node.
	if eState.mark != mark {
		// Uninstall all of its Pod flows.
		if err := c.uninstallPodFlows(egressName, eState, eState.ofPorts, eState.pods); err != nil {
			return err
		}
		eState.mark = mark
	}

	if err := c.updateEgressStatus(egress, c.localIPDetector.IsLocalIP(egress.Spec.EgressIP)); err != nil {
		return fmt.Errorf("update Egress %s status error: %v", egressName, err)
	}

	// Copy the previous ofPorts and Pods. They will be used to identify stale ofPorts and Pods.
	staleOFPorts := eState.ofPorts.Union(nil)
	stalePods := eState.pods.Union(nil)

	// Get a copy of the desired Pods.
	pods := func() sets.String {
		c.egressGroupsMutex.RLock()
		defer c.egressGroupsMutex.RUnlock()
		pods, exist := c.egressGroups[egressName]
		if !exist {
			return nil
		}
		return pods.Union(nil)
	}()

	egressIP := net.ParseIP(eState.egressIP)
	// Install SNAT flows for desired Pods.
	for pod := range pods {
		eState.pods.Insert(pod)
		stalePods.Delete(pod)

		// If the Egress is not the effective one for the Pod, do nothing.
		if !c.bindPodEgress(pod, egressName) {
			continue
		}

		// Get the Pod's openflow port.
		parts := strings.Split(pod, "/")
		podNamespace, podName := parts[0], parts[1]
		ifaces := c.ifaceStore.GetContainerInterfacesByPod(podName, podNamespace)
		if len(ifaces) == 0 {
			klog.Infof("Interfaces of Pod %s/%s not found", podNamespace, podName)
			continue
		}

		ofPort := ifaces[0].OFPort
		if eState.ofPorts.Has(ofPort) {
			staleOFPorts.Delete(ofPort)
			continue
		}
		if err := c.ofClient.InstallPodSNATFlows(uint32(ofPort), egressIP, mark); err != nil {
			return err
		}
		eState.ofPorts.Insert(ofPort)
	}

	// Uninstall SNAT flows for stale Pods.
	if err := c.uninstallPodFlows(egressName, eState, staleOFPorts, stalePods); err != nil {
		return err
	}
	return nil
}

func (c *EgressController) uninstallEgress(egressName string, eState *egressState) error {
	// Uninstall all of its Pod flows.
	if err := c.uninstallPodFlows(egressName, eState, eState.ofPorts, eState.pods); err != nil {
		return err
	}
	// Release the EgressIP's mark if the Egress is the last one referring to it.
	if err := c.unrealizeEgressIP(egressName, eState.egressIP); err != nil {
		return err
	}
	// Unassign the Egress IP from the local Node if it was assigned by the agent.
	if err := c.ipAssigner.UnassignIP(eState.egressIP); err != nil {
		return err
	}
	// Remove the Egress's state.
	c.deleteEgressState(egressName)
	return nil
}

func (c *EgressController) uninstallPodFlows(egressName string, egressState *egressState, ofPorts sets.Int32, pods sets.String) error {
	for ofPort := range ofPorts {
		if err := c.ofClient.UninstallPodSNATFlows(uint32(ofPort)); err != nil {
			return err
		}
		egressState.ofPorts.Delete(ofPort)
	}

	// Remove Pods from the Egress state after uninstalling Pod's flows to avoid overlapping. Otherwise another Egress
	// may install new flows for the Pod before this Egress uninstalls its previous flows, causing conflicts.
	// For each Pod, if the Egress was the Pod's effective Egress and there are other Egresses applying to it, it will
	// pick one and trigger its resync.
	newEffectiveEgresses := sets.NewString()
	for pod := range pods {
		delete(egressState.pods, pod)
		newEffectiveEgress, exists := c.unbindPodEgress(pod, egressName)
		if exists {
			newEffectiveEgresses.Insert(newEffectiveEgress)
		}
	}
	// Trigger resyncing of the new effective Egresses of the removed Pods.
	for egress := range newEffectiveEgresses {
		c.queue.Add(egress)
	}
	return nil
}

func (c *EgressController) watchEgressGroup() {
	klog.Info("Starting watch for EgressGroup")
	antreaClient, err := c.antreaClientProvider.GetAntreaClient()
	if err != nil {
		klog.Warningf("Failed to get antrea client: %v", err)
		return
	}
	options := metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("nodeName", c.nodeName).String(),
	}
	watcher, err := antreaClient.ControlplaneV1beta2().EgressGroups().Watch(context.TODO(), options)
	if err != nil {
		klog.Warningf("Failed to start watch for EgressGroup: %v", err)
		return
	}
	// Watch method doesn't return error but "emptyWatch" in case of some partial data errors,
	// e.g. timeout error. Make sure that watcher is not empty and log warning otherwise.
	if reflect.TypeOf(watcher) == reflect.TypeOf(emptyWatch) {
		klog.Warning("Failed to start watch for EgressGroup, please ensure antrea service is reachable for the agent")
		return
	}

	klog.Info("Started watch for EgressGroup")
	eventCount := 0
	defer func() {
		klog.Infof("Stopped watch for EgressGroup, total items received: %d", eventCount)
		watcher.Stop()
	}()

	// First receive init events from the result channel and buffer them until
	// a Bookmark event is received, indicating that all init events have been
	// received.
	var initObjects []*cpv1b2.EgressGroup
loop:
	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				klog.Warningf("Result channel for EgressGroup was closed")
				return
			}
			switch event.Type {
			case watch.Added:
				klog.V(2).Infof("Added EgressGroup (%#v)", event.Object)
				initObjects = append(initObjects, event.Object.(*cpv1b2.EgressGroup))
			case watch.Bookmark:
				break loop
			}
		}
	}
	klog.Infof("Received %d init events for EgressGroup", len(initObjects))

	eventCount += len(initObjects)
	c.replaceEgressGroups(initObjects)

	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return
			}
			switch event.Type {
			case watch.Added:
				c.addEgressGroup(event.Object.(*cpv1b2.EgressGroup))
				klog.V(2).Infof("Added EgressGroup (%#v)", event.Object)
			case watch.Modified:
				c.patchEgressGroup(event.Object.(*cpv1b2.EgressGroupPatch))
				klog.V(2).Infof("Updated EgressGroup (%#v)", event.Object)
			case watch.Deleted:
				c.deleteEgressGroup(event.Object.(*cpv1b2.EgressGroup))
				klog.V(2).Infof("Removed EgressGroup (%#v)", event.Object)
			default:
				klog.Errorf("Unknown event: %v", event)
				return
			}
			eventCount++
		}
	}
}

func (c *EgressController) replaceEgressGroups(groups []*cpv1b2.EgressGroup) {
	c.egressGroupsMutex.Lock()
	defer c.egressGroupsMutex.Unlock()

	oldGroupKeys := make(sets.String, len(c.egressGroups))
	for key := range c.egressGroups {
		oldGroupKeys.Insert(key)
	}

	for _, group := range groups {
		oldGroupKeys.Delete(group.Name)
		pods := sets.NewString()
		for _, member := range group.GroupMembers {
			pods.Insert(k8s.NamespacedName(member.Pod.Namespace, member.Pod.Name))
		}
		prevPods := c.egressGroups[group.Name]
		if pods.Equal(prevPods) {
			continue
		}
		c.egressGroups[group.Name] = pods
		c.queue.Add(group.Name)
	}

	for key := range oldGroupKeys {
		delete(c.egressGroups, key)
		c.queue.Add(key)
	}
}

func (c *EgressController) addEgressGroup(group *cpv1b2.EgressGroup) {
	pods := sets.NewString()
	for _, member := range group.GroupMembers {
		pods.Insert(k8s.NamespacedName(member.Pod.Namespace, member.Pod.Name))
	}

	c.egressGroupsMutex.Lock()
	defer c.egressGroupsMutex.Unlock()

	c.egressGroups[group.Name] = pods
	c.queue.Add(group.Name)
}

func (c *EgressController) patchEgressGroup(patch *cpv1b2.EgressGroupPatch) {
	c.egressGroupsMutex.Lock()
	defer c.egressGroupsMutex.Unlock()

	for _, member := range patch.AddedGroupMembers {
		c.egressGroups[patch.Name].Insert(k8s.NamespacedName(member.Pod.Namespace, member.Pod.Name))

	}
	for _, member := range patch.RemovedGroupMembers {
		c.egressGroups[patch.Name].Delete(k8s.NamespacedName(member.Pod.Namespace, member.Pod.Name))
	}
	c.queue.Add(patch.Name)
}

func (c *EgressController) deleteEgressGroup(group *cpv1b2.EgressGroup) {
	c.egressGroupsMutex.Lock()
	defer c.egressGroupsMutex.Unlock()

	delete(c.egressGroups, group.Name)
	c.queue.Add(group.Name)
}
