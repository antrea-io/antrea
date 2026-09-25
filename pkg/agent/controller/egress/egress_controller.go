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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/client"
	"antrea.io/antrea/v2/pkg/agent/interfacestore"
	"antrea.io/antrea/v2/pkg/agent/ipassigner"
	"antrea.io/antrea/v2/pkg/agent/ipassigner/linkmonitor"
	"antrea.io/antrea/v2/pkg/agent/memberlist"
	"antrea.io/antrea/v2/pkg/agent/openflow"
	"antrea.io/antrea/v2/pkg/agent/route"
	"antrea.io/antrea/v2/pkg/agent/servicecidr"
	"antrea.io/antrea/v2/pkg/agent/types"
	cpv1b2 "antrea.io/antrea/v2/pkg/apis/controlplane/v1beta2"
	crdv1b1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	clientsetversioned "antrea.io/antrea/v2/pkg/client/clientset/versioned"
	"antrea.io/antrea/v2/pkg/client/clientset/versioned/scheme"
	crdinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions/crd/v1beta1"
	crdlisters "antrea.io/antrea/v2/pkg/client/listers/crd/v1beta1"
	"antrea.io/antrea/v2/pkg/controller/metrics"
	"antrea.io/antrea/v2/pkg/util/channel"
	"antrea.io/antrea/v2/pkg/util/k8s"
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

var maxSubnetsPerNodes = types.MaxRequestEgressRouteTable - types.MinRequestEgressRouteTable + 1

var emptyWatch = watch.NewEmptyWatch()

var newIPAssigner = ipassigner.NewIPAssigner

// egressState keeps the actual state of an Egress that has been realized.
type egressState struct {
	// The actual egress IP of the Egress. If it's different from the desired IP, there is an update to EgressIP, and we
	// need to remove previously installed flows.
	egressIP string
	// The actual datapath mark of this Egress. Used to check if the mark changes since last process.
	mark uint32
	// The actual openflow ports for which we have installed SNAT rules. Used to identify stale openflow ports when
	// updating or deleting an Egress.
	ofPorts sets.Set[int32]
	// The actual Pods of the Egress. Used to identify stale Pods when updating or deleting an Egress.
	pods sets.Set[string]
	// Rate-limit of this Egress.
	rateLimitMeter *rateLimitMeter
	// With the l2 dispatch, l2DispatchNode is the remote Egress Node which holds the Egress IP, if it is known, and
	// l2DispatchIndex is the l2 dispatch index of the Egress Node which the Pod flows use, 0 if they are not installed.
	l2DispatchNode  string
	l2DispatchIndex uint32
}

type rateLimitMeter struct {
	MeterID uint32
	Rate    uint32
	Burst   uint32
}

func (r *rateLimitMeter) Equals(rateLimit *rateLimitMeter) bool {
	if r == nil && rateLimit == nil {
		return true
	}
	if r == nil || rateLimit == nil {
		return false
	}
	return r.MeterID == rateLimit.MeterID && r.Rate == rateLimit.Rate && r.Burst == rateLimit.Burst
}

// egressIPState keeps the actual state of an Egress IP. It's maintained separately from egressState because
// multiple Egresses can share an EgressIP.
type egressIPState struct {
	egressIP net.IP
	// The names of the Egresses that are currently referring to it.
	egressNames sets.Set[string]
	// The datapath mark of this Egress IP. 0 if this is not a local IP.
	mark uint32
	// Whether its flows have been installed.
	flowsInstalled bool
	// Whether its iptables rule has been installed.
	ruleInstalled bool
	// The subnet the Egress IP is associated with.
	subnetInfo *crdv1b1.SubnetInfo
	// The IPs of the Pods on other Nodes which use this local Egress IP, by Egress, with the Egress l2 dispatch. The
	// ipset of the Egress IP holds their union.
	remotePodIPs map[string]sets.Set[string]
}

// egressRouteTable stores the route table ID created for a subnet and the marks that are referencing it.
type egressRouteTable struct {
	// The route table ID.
	tableID uint32
	// The marks referencing the table. Once it's empty, the route table should be deleted.
	marks sets.Set[uint32]
}

// egressBinding keeps the Egresses applying to a Pod.
// There is one effective Egress for a Pod at any given time.
type egressBinding struct {
	effectiveEgress     string
	alternativeEgresses sets.Set[string]
}

// egressAddressGroup is an EgressAddressGroup which the Node receives as the Egress Node of one of its Egresses, with
// the Egress l2 dispatch.
type egressAddressGroup struct {
	// egresses are the names of the Egresses whose appliedTo selects the members.
	egresses sets.Set[string]
	// members maps the member Pods, by namespaced name, to their IPs.
	members map[string]sets.Set[string]
}

func newEgressAddressGroup(group *cpv1b2.EgressAddressGroup) *egressAddressGroup {
	g := &egressAddressGroup{
		egresses: sets.New[string](group.Egresses...),
		members:  make(map[string]sets.Set[string], len(group.GroupMembers)),
	}
	for i := range group.GroupMembers {
		g.addMember(&group.GroupMembers[i])
	}
	return g
}

func (g *egressAddressGroup) addMember(member *cpv1b2.GroupMember) {
	ips := sets.New[string]()
	for _, ip := range member.IPs {
		ips.Insert(net.IP(ip).String())
	}
	g.members[k8s.NamespacedName(member.Pod.Namespace, member.Pod.Name)] = ips
}

func (g *egressAddressGroup) removeMember(member *cpv1b2.GroupMember) {
	delete(g.members, k8s.NamespacedName(member.Pod.Namespace, member.Pod.Name))
}

type EgressController struct {
	ofClient             openflow.Client
	routeClient          route.Interface
	k8sClient            kubernetes.Interface
	crdClient            clientsetversioned.Interface
	antreaClientProvider client.AntreaClientProvider

	egressInformer     cache.SharedIndexInformer
	egressLister       crdlisters.EgressLister
	egressListerSynced cache.InformerSynced
	queue              workqueue.TypedRateLimitingInterface[string]

	externalIPPoolLister       crdlisters.ExternalIPPoolLister
	externalIPPoolListerSynced cache.InformerSynced

	// Use an interface for IP detector to enable testing.
	localIPDetector ipassigner.LocalIPDetector
	ifaceStore      interfacestore.InterfaceStore
	nodeName        string
	markAllocator   *idAllocator

	egressGroups      map[string]sets.Set[string]
	egressGroupsMutex sync.RWMutex

	egressBindings      map[string]*egressBinding
	egressBindingsMutex sync.RWMutex

	egressStates map[string]*egressState
	// The mutex is to protect the map, not the egressState items. The workqueue guarantees an Egress will only be
	// processed by a single worker at any time. So the returned EgressState has no race condition.
	egressStatesMutex sync.RWMutex

	egressIPStates      map[string]*egressIPState
	egressIPStatesMutex sync.Mutex

	cluster    memberlist.Interface
	ipAssigner ipassigner.IPAssigner

	egressIPScheduler *egressIPScheduler

	serviceCIDRInterface servicecidr.Interface
	serviceCIDRUpdateCh  chan struct{}
	// Declared for testing.
	serviceCIDRUpdateRetryDelay time.Duration

	trafficShapingEnabled bool

	eventBroadcaster events.EventBroadcaster
	record           events.EventRecorder
	// Whether to support non-default subnets.
	supportSeparateSubnet bool
	// Used to allocate route table ID.
	tableAllocator *idAllocator
	// Each subnet has its own route table.
	egressRouteTables map[crdv1b1.SubnetInfo]*egressRouteTable

	linkMonitor linkmonitor.Interface

	// l2Dispatch is true when Egress uses the l2 dispatch in noEncap mode: the Egress traffic of a Pod reaches an
	// Egress IP on another Node without a tunnel, and the Egress Node maps the source Pod IP to the Egress IP.
	l2Dispatch bool
	// l2DispatchPeers gives the l2 dispatch index of a remote Egress Node.
	l2DispatchPeers L2DispatchPeerQuerier
	// l2DispatchEgresses are the Egresses whose Egress IP is on a remote Node, by Egress Node, with the l2 dispatch.
	// They are synced again when the l2 dispatch routing of their Egress Node changes.
	l2DispatchEgresses      map[string]sets.Set[string]
	l2DispatchEgressesMutex sync.Mutex
	// egressAddressGroups are the EgressAddressGroups which the Node receives as an Egress Node, by name, with the l2
	// dispatch. They give the IPs of the member Pods on other Nodes.
	egressAddressGroups      map[string]*egressAddressGroup
	egressAddressGroupsMutex sync.RWMutex
}

// L2DispatchPeerQuerier gives the index which identifies a peer Node in the l2 dispatch. The NodeRouteController
// allocates the indices and installs their policy routing.
type L2DispatchPeerQuerier interface {
	// GetL2DispatchPeerIndex returns the index of the peer Node, once the policy routing of the index is installed for
	// the IP family. It returns an error if the l2 dispatch cannot reach the Node with the IP family.
	GetL2DispatchPeerIndex(nodeName string, isIPv6 bool) (uint32, bool, error)
	// AddL2DispatchPeerEventHandler adds a handler called with the name of a peer Node when the policy routing of
	// its index is installed, changes, or is about to be removed.
	AddL2DispatchPeerEventHandler(handler func(nodeName string))
}

func NewEgressController(
	ofClient openflow.Client,
	k8sClient kubernetes.Interface,
	antreaClientGetter client.AntreaClientProvider,
	crdClient clientsetversioned.Interface,
	ifaceStore interfacestore.InterfaceStore,
	routeClient route.Interface,
	nodeName string,
	nodeTransportInterface string,
	cluster memberlist.Interface,
	egressInformer crdinformers.EgressInformer,
	externalIPPoolInformer crdinformers.ExternalIPPoolInformer,
	nodeInformers coreinformers.NodeInformer,
	podUpdateSubscriber channel.Subscriber,
	serviceCIDRInterface servicecidr.Interface,
	maxEgressIPsPerNode int,
	trafficShapingEnabled bool,
	supportSeparateSubnet bool,
	linkMonitor linkmonitor.Interface,
	uniqueMACForSubInterfaces bool,
	l2DispatchPeers L2DispatchPeerQuerier,
) (*EgressController, error) {
	if trafficShapingEnabled && !openflow.OVSMetersAreSupported() {
		klog.Info("EgressTrafficShaping feature gate is enabled, but it is ignored because OVS meters are not supported.")
	}

	eventBroadcaster := events.NewBroadcaster(&events.EventSinkImpl{
		Interface: k8sClient.EventsV1(),
	})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, controllerName)

	c := &EgressController{
		ofClient:             ofClient,
		routeClient:          routeClient,
		k8sClient:            k8sClient,
		antreaClientProvider: antreaClientGetter,
		crdClient:            crdClient,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: "egressgroup",
			},
		),
		egressInformer:       egressInformer.Informer(),
		egressLister:         egressInformer.Lister(),
		egressListerSynced:   egressInformer.Informer().HasSynced,
		nodeName:             nodeName,
		ifaceStore:           ifaceStore,
		egressGroups:         map[string]sets.Set[string]{},
		egressStates:         map[string]*egressState{},
		egressIPStates:       map[string]*egressIPState{},
		egressBindings:       map[string]*egressBinding{},
		localIPDetector:      ipassigner.NewLocalIPDetector(),
		markAllocator:        newIDAllocator(minEgressMark, maxEgressMark),
		cluster:              cluster,
		serviceCIDRInterface: serviceCIDRInterface,
		// One buffer is enough as we just use it to ensure the target handler is executed once.
		serviceCIDRUpdateCh:         make(chan struct{}, 1),
		serviceCIDRUpdateRetryDelay: 10 * time.Second,

		trafficShapingEnabled: openflow.OVSMetersAreSupported() && trafficShapingEnabled,

		eventBroadcaster: eventBroadcaster,
		record:           recorder,

		externalIPPoolLister:       externalIPPoolInformer.Lister(),
		externalIPPoolListerSynced: externalIPPoolInformer.Informer().HasSynced,
		supportSeparateSubnet:      supportSeparateSubnet,
		linkMonitor:                linkMonitor,
	}
	// A nil l2DispatchPeers means that Egress does not use the l2 dispatch.
	if l2DispatchPeers != nil {
		c.l2Dispatch = true
		c.l2DispatchPeers = l2DispatchPeers
		c.l2DispatchEgresses = map[string]sets.Set[string]{}
		c.egressAddressGroups = map[string]*egressAddressGroup{}
		l2DispatchPeers.AddL2DispatchPeerEventHandler(c.onL2DispatchPeerUpdate)
	}
	if supportSeparateSubnet {
		c.egressRouteTables = map[crdv1b1.SubnetInfo]*egressRouteTable{}
		c.tableAllocator = newIDAllocator(types.MinRequestEgressRouteTable, types.MaxRequestEgressRouteTable)
		externalIPPoolInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    c.addExternalIPPool,
				UpdateFunc: c.updateExternalIPPool,
			},
			resyncPeriod,
		)
	}
	ipAssigner, err := newIPAssigner(nodeTransportInterface, egressDummyDevice, linkMonitor, uniqueMACForSubInterfaces)
	if err != nil {
		return nil, fmt.Errorf("initializing egressIP assigner failed: %v", err)
	}
	c.ipAssigner = ipAssigner

	c.egressIPScheduler = NewEgressIPScheduler(cluster, egressInformer, nodeInformers, maxEgressIPsPerNode)

	c.egressInformer.AddIndexers(
		cache.Indexers{
			// egressIPIndex will be used to get all Egresses sharing the same Egress IP.
			egressIPIndex: func(obj interface{}) ([]string, error) {
				egress, ok := obj.(*crdv1b1.Egress)
				if !ok {
					return nil, fmt.Errorf("obj is not Egress: %+v", obj)
				}
				var egressIPs []string
				if egress.Spec.EgressIP != "" {
					egressIPs = append(egressIPs, egress.Spec.EgressIP)
				}
				for _, egressIP := range egress.Spec.EgressIPs {
					if egressIP != "" {
						egressIPs = append(egressIPs, egressIP)
					}
				}
				return egressIPs, nil
			},
			externalIPPoolIndex: func(obj interface{}) ([]string, error) {
				egress, ok := obj.(*crdv1b1.Egress)
				if !ok {
					return nil, fmt.Errorf("obj is not Egress: %+v", obj)
				}
				var pools []string
				if egress.Spec.ExternalIPPool != "" {
					pools = append(pools, egress.Spec.ExternalIPPool)
				}
				for _, pool := range egress.Spec.ExternalIPPools {
					if pool != "" {
						pools = append(pools, pool)
					}
				}
				return pools, nil
			},
		})
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
	c.egressIPScheduler.AddEventHandler(c.onEgressIPSchedule)
	c.serviceCIDRInterface.AddEventHandler(c.onServiceCIDRUpdate)
	return c, nil
}

// onEgressIPSchedule will be called when EgressIPScheduler reschedules an Egress's IP.
func (c *EgressController) onEgressIPSchedule(egress string) {
	c.queue.Add(egress)
}

// onServiceCIDRUpdate will be called when ServiceCIDRs change.
// It ensures updateServiceCIDRs will be executed once after this call.
func (c *EgressController) onServiceCIDRUpdate(_ []*net.IPNet) {
	select {
	case c.serviceCIDRUpdateCh <- struct{}{}:
	default:
		// The previous event is not processed yet, discard the new event.
	}
}

func (c *EgressController) updateServiceCIDRs(stopCh <-chan struct{}) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C // Consume the first tick.
	for {
		select {
		case <-stopCh:
			return
		case <-c.serviceCIDRUpdateCh:
			klog.V(2).InfoS("Received service CIDR update")
		case <-timer.C:
			klog.V(2).InfoS("Service CIDR update timer expired")
		}
		serviceCIDRs, err := c.serviceCIDRInterface.GetServiceCIDRs()
		if err != nil {
			klog.ErrorS(err, "Failed to get Service CIDRs")
			// No need to retry in this case as the Service CIDRs won't be available until it receives a service CIDRs update.
			continue
		}
		err = c.ofClient.InstallSNATBypassServiceFlows(serviceCIDRs)
		if err != nil {
			klog.ErrorS(err, "Failed to install SNAT bypass flows for Service CIDRs, will retry", "serviceCIDRs", serviceCIDRs)
			// Schedule a retry as it should be transient error.
			timer.Reset(c.serviceCIDRUpdateRetryDelay)
		}
	}
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
	egress := obj.(*crdv1b1.Egress)
	if egress.Spec.EgressIP == "" {
		return
	}
	c.queue.Add(egress.Name)
	klog.V(2).InfoS("Processed Egress ADD event", "egress", klog.KObj(egress))
}

// updateEgress processes Egress UPDATE events.
func (c *EgressController) updateEgress(old, cur interface{}) {
	oldEgress := old.(*crdv1b1.Egress)
	curEgress := cur.(*crdv1b1.Egress)
	// Ignore handling the Egress Status change if Egress IP already has been assigned on current node.
	if curEgress.Status.EgressNode == c.nodeName && oldEgress.GetGeneration() == curEgress.GetGeneration() {
		return
	}
	c.queue.Add(curEgress.Name)
	klog.V(2).InfoS("Processed Egress UPDATE event", "egress", klog.KObj(curEgress))
}

// deleteEgress processes Egress DELETE events.
func (c *EgressController) deleteEgress(obj interface{}) {
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
	c.queue.Add(egress.Name)
	klog.V(2).InfoS("Processed Egress DELETE event", "egress", klog.KObj(egress))
}

func (c *EgressController) addExternalIPPool(obj interface{}) {
	pool := obj.(*crdv1b1.ExternalIPPool)
	if pool.Spec.SubnetInfo == nil {
		return
	}
	c.onExternalIPPoolUpdated(pool.Name)
	klog.V(2).InfoS("Processed ExternalIPPool ADD event", "externalIPPool", klog.KObj(pool))
}

func (c *EgressController) updateExternalIPPool(old, cur interface{}) {
	oldPool := old.(*crdv1b1.ExternalIPPool)
	curPool := cur.(*crdv1b1.ExternalIPPool)
	// We only care about SubnetInfo here.
	if crdv1b1.CompareSubnetInfo(oldPool.Spec.SubnetInfo, curPool.Spec.SubnetInfo, false) {
		return
	}
	c.onExternalIPPoolUpdated(curPool.Name)
	klog.V(2).InfoS("Processed ExternalIPPool UPDATE event", "externalIPPool", klog.KObj(curPool))
}

func (c *EgressController) onExternalIPPoolUpdated(pool string) {
	egresses, _ := c.egressInformer.GetIndexer().ByIndex(externalIPPoolIndex, pool)
	for _, obj := range egresses {
		egress := obj.(*crdv1b1.Egress)
		c.queue.Add(egress.Name)
	}
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
		egress := obj.(*crdv1b1.Egress)
		c.queue.Add(egress.Name)
	}
}

// Run will create defaultWorkers workers (go routines) which will process the Egress events from the
// workqueue.
func (c *EgressController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	c.eventBroadcaster.StartStructuredLogging(0)
	c.eventBroadcaster.StartRecordingToSink(stopCh)
	defer c.eventBroadcaster.Shutdown()

	go c.localIPDetector.Run(stopCh)
	go c.egressIPScheduler.Run(stopCh)
	go c.ipAssigner.Run(stopCh)
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.egressListerSynced, c.externalIPPoolListerSynced, c.localIPDetector.HasSynced, c.egressIPScheduler.HasScheduled, c.linkMonitor.HasSynced) {
		return
	}

	if err := c.replaceEgressIPs(); err != nil {
		klog.ErrorS(err, "Failed to replace Egress IPs")
	}
	if err := c.routeClient.RestoreEgressRoutesAndRules(types.MinRequestEgressRouteTable, types.MaxRequestEgressRouteTable); err != nil {
		klog.ErrorS(err, "Failed to restore Egress routes and rules")
	}

	go wait.NonSlidingUntil(c.watchEgressGroup, 5*time.Second, stopCh)
	if c.l2Dispatch {
		go wait.NonSlidingUntil(c.watchEgressAddressGroup, 5*time.Second, stopCh)
	}

	go c.updateServiceCIDRs(stopCh)

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

// replaceEgressIPs unassigns stale Egress IPs that shouldn't be present on this Node and assigns the missing IPs
// on this node. The unassigned IPs are from Egresses that were either deleted from the Kubernetes API or migrated
// to other Nodes when the agent on this Node was not running.
func (c *EgressController) replaceEgressIPs() error {
	desiredLocalEgressIPs := map[string]*crdv1b1.SubnetInfo{}
	egresses, _ := c.egressLister.List(labels.Everything())
	for _, egress := range egresses {
		if isEgressSchedulable(egress) && egress.Status.EgressNode == c.nodeName && egress.Status.EgressIP != "" {
			pool, err := c.externalIPPoolLister.Get(egress.Spec.ExternalIPPool)
			// Ignore the Egress if the ExternalIPPool doesn't exist.
			if err != nil {
				continue
			}
			desiredLocalEgressIPs[egress.Status.EgressIP] = pool.Spec.SubnetInfo
			// Record the Egress's state as we assign their IPs to this Node in the following call. It makes sure these
			// Egress IPs will be unassigned when the Egresses are deleted.
			c.newEgressState(egress.Name, egress.Status.EgressIP)
		}
	}
	if err := c.ipAssigner.InitIPs(desiredLocalEgressIPs); err != nil {
		return err
	}
	return nil
}

// worker is a long-running function that will continually call the processNextWorkItem function in
// order to read and process a message on the workqueue.
func (c *EgressController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *EgressController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	if err := c.syncEgress(key); err == nil {
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

// installPolicyRoute ensures Egress traffic with the given mark access external network via the subnet's gateway, and
// tagged with the subnet's VLAN ID if present.
func (c *EgressController) installPolicyRoute(ipState *egressIPState, subnetInfo *crdv1b1.SubnetInfo) error {
	if !c.supportSeparateSubnet {
		return nil
	}
	if crdv1b1.CompareSubnetInfo(ipState.subnetInfo, subnetInfo, false) {
		return nil
	}
	// Deletes stale policy route first.
	if err := c.uninstallPolicyRoute(ipState); err != nil {
		return err
	}
	// If the subnetInfo is nil, policy routing is not needed. The Egress IP should just use the main route table.
	if subnetInfo == nil {
		return nil
	}

	subnetGateway := net.ParseIP(subnetInfo.Gateway)
	// Get or create a route table for this subnet.
	rt, exists := c.egressRouteTables[*subnetInfo]
	if !exists {
		tableID, err := c.tableAllocator.allocate()
		if err != nil {
			return fmt.Errorf("error allocating table for subnet %v due to exceeding max allowed subnets %d: %w", subnetInfo, maxSubnetsPerNodes, err)
		}
		// Get the index of the network interface to which IPs in the subnet are assigned.
		// The network interface will be used as the device via which the Egress traffic leaves.
		devID, ok := c.ipAssigner.GetInterfaceID(subnetInfo)
		// This should never happen.
		if !ok {
			return fmt.Errorf("interface for subnet %v not found", subnetInfo)
		}
		if err := c.routeClient.AddEgressRoutes(tableID, devID, subnetGateway, int(subnetInfo.PrefixLength)); err != nil {
			return fmt.Errorf("error creating route table for subnet %v: %w", subnetInfo, err)
		}
		rt = &egressRouteTable{tableID: tableID, marks: sets.New[uint32]()}
		c.egressRouteTables[*subnetInfo] = rt
	}
	// Add an IP rule to make the marked Egress traffic look up the table.
	if err := c.routeClient.AddEgressRule(rt.tableID, ipState.mark, subnetGateway.To4() == nil); err != nil {
		return fmt.Errorf("error adding ip rule for mark %v: %w", ipState.mark, err)
	}
	// Track the route table's usage.
	rt.marks.Insert(ipState.mark)
	// Track the current subnet of the Egress IP.
	ipState.subnetInfo = subnetInfo
	return nil
}

// uninstallPolicyRoute deletes the policy route of the Egress IP.
func (c *EgressController) uninstallPolicyRoute(ipState *egressIPState) error {
	if !c.supportSeparateSubnet {
		return nil
	}
	if ipState.subnetInfo == nil {
		return nil
	}
	rt, exists := c.egressRouteTables[*ipState.subnetInfo]
	if !exists {
		return nil
	}
	subnetGateway := net.ParseIP(ipState.subnetInfo.Gateway)
	if err := c.routeClient.DeleteEgressRule(rt.tableID, ipState.mark, subnetGateway.To4() == nil); err != nil {
		return fmt.Errorf("error deleting ip rule for mark %v: %w", ipState.mark, err)
	}
	rt.marks.Delete(ipState.mark)
	// Delete the route table if it is not used by any Egress.
	if rt.marks.Len() == 0 {
		if err := c.routeClient.DeleteEgressRoutes(rt.tableID); err != nil {
			return fmt.Errorf("error deleting route table for subnet %v: %w", ipState.subnetInfo, err)
		}
		c.tableAllocator.release(rt.tableID)
		delete(c.egressRouteTables, *ipState.subnetInfo)
	}
	ipState.subnetInfo = nil
	return nil
}

// realizeEgressIP realizes an Egress IP. Multiple Egresses can share the same Egress IP.
// If it's called the first time for a local Egress IP, it allocates a locally-unique mark for the IP and installs flows
// and iptables rule for this IP and the mark.
// If the Egress IP is changed from local to non local, it uninstalls flows and iptables rule and releases the mark.
// The method returns the mark on success. Non local Egresses use 0 as the mark.
func (c *EgressController) realizeEgressIP(egressName, egressIP string, subnetInfo *crdv1b1.SubnetInfo) (uint32, error) {
	isLocalIP := c.localIPDetector.IsLocalIP(egressIP)

	c.egressIPStatesMutex.Lock()
	defer c.egressIPStatesMutex.Unlock()

	ipState, exists := c.egressIPStates[egressIP]
	// Create an egressIPState if this is the first Egress using the IP.
	if !exists {
		ipState = &egressIPState{
			egressIP:    net.ParseIP(egressIP),
			egressNames: sets.New(egressName),
		}
		c.egressIPStates[egressIP] = ipState
	} else if !ipState.egressNames.Has(egressName) {
		ipState.egressNames.Insert(egressName)
	}

	var err error
	if isLocalIP {
		// Ensure the Egress IP has a mark allocated when it's a local IP.
		if ipState.mark == 0 {
			ipState.mark, err = c.markAllocator.allocate()
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
		if err := c.installPolicyRoute(ipState, subnetInfo); err != nil {
			return 0, fmt.Errorf("error installing policy route for IP %s: %v", ipState.egressIP, err)
		}
	} else {
		// Ensure datapath is uninstalled properly.
		if err := c.uninstallPolicyRoute(ipState); err != nil {
			return 0, fmt.Errorf("error uninstalling policy routing for IP %s: %v", ipState.egressIP, err)
		}
		if ipState.ruleInstalled {
			if err := c.routeClient.DeleteSNATRule(ipState.mark); err != nil {
				return 0, fmt.Errorf("error uninstalling SNAT rule for IP %s: %v", ipState.egressIP, err)
			}
			ipState.ruleInstalled = false
			// The ipset of the remote Pods of the Egress IP is deleted with the SNAT rule.
			ipState.remotePodIPs = nil
		}
		if ipState.flowsInstalled {
			if err := c.ofClient.UninstallSNATMarkFlows(ipState.mark); err != nil {
				return 0, fmt.Errorf("error uninstalling SNAT mark flows for IP %s: %v", ipState.egressIP, err)
			}
			ipState.flowsInstalled = false
		}
		if ipState.mark != 0 {
			err := c.markAllocator.release(ipState.mark)
			if err != nil {
				return 0, fmt.Errorf("error releasing mark for IP %s: %v", egressIP, err)
			}
			ipState.mark = 0
		}
	}
	return ipState.mark, nil
}

func bandwidthToRateLimitMeter(bandwidth *crdv1b1.Bandwidth, meterID uint32) *rateLimitMeter {
	if bandwidth == nil {
		return nil
	}
	rate, err := resource.ParseQuantity(bandwidth.Rate)
	if err != nil {
		klog.ErrorS(err, "Invalid bandwidth rate configured for Egress", "rate", bandwidth.Rate)
		return nil
	}
	burst, err := resource.ParseQuantity(bandwidth.Burst)
	if err != nil {
		klog.ErrorS(err, "Invalid bandwidth burst size configured for Egress", "burst", bandwidth.Burst)
		return nil
	}
	return &rateLimitMeter{
		MeterID: meterID,
		Rate:    uint32(rate.Value() / 1000),
		Burst:   uint32(burst.Value() / 1000),
	}
}

func (c *EgressController) realizeEgressQoS(egressName string, eState *egressState, mark uint32, bandwidth *crdv1b1.Bandwidth) error {
	if !c.trafficShapingEnabled {
		if bandwidth != nil {
			klog.InfoS("Bandwidth in the Egress is ignored because OVS meters are not supported or trafficShaping is not enabled in Antrea-agent config.", "EgressName", egressName)
		}
		return nil
	}
	var desiredRateLimit *rateLimitMeter
	// QoS is desired only if the Egress is configured on this Node.
	if mark != 0 {
		desiredRateLimit = bandwidthToRateLimitMeter(bandwidth, mark)
	}
	// Nothing changes.
	if eState.rateLimitMeter.Equals(desiredRateLimit) {
		return nil
	}
	// It's desired to have QoS on this Node, install/override it.
	if desiredRateLimit != nil {
		if err := c.ofClient.InstallEgressQoS(mark, desiredRateLimit.Rate, desiredRateLimit.Burst); err != nil {
			return err
		}
		eState.rateLimitMeter = desiredRateLimit
		return nil
	}
	// It's undesired to have QoS on this Node, uninstall it.
	if eState.rateLimitMeter != nil {
		if err := c.ofClient.UninstallEgressQoS(eState.rateLimitMeter.MeterID); err != nil {
			return err
		}
		eState.rateLimitMeter = nil
	}
	return nil
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
		// The ipset of the remote Pods of the Egress IP keeps the Pods of the other Egresses only.
		if _, exists := ipState.remotePodIPs[egressName]; exists && ipState.mark != 0 {
			if err := c.routeClient.SetEgressRemotePodIPs(ipState.mark, unionRemotePodIPs(ipState, egressName)); err != nil {
				return err
			}
			delete(ipState.remotePodIPs, egressName)
		}
		return nil
	}
	if ipState.mark != 0 {
		if err := c.uninstallPolicyRoute(ipState); err != nil {
			return err
		}
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
		c.markAllocator.release(ipState.mark)
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
		ofPorts:  sets.New[int32](),
		pods:     sets.New[string](),
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
			alternativeEgresses: sets.New[string](),
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

func (c *EgressController) updateEgressStatus(egress *crdv1b1.Egress, egressIP string, scheduleErr error) error {
	isLocal := false
	if egressIP != "" {
		isLocal = c.localIPDetector.IsLocalIP(egressIP)
	}

	desiredStatus := &crdv1b1.EgressStatus{}
	if isLocal {
		desiredStatus.EgressNode = c.nodeName
		desiredStatus.EgressIP = egressIP
		if isEgressSchedulable(egress) {
			desiredStatus.Conditions = []crdv1b1.EgressCondition{
				{
					Type:               crdv1b1.IPAssigned,
					Status:             corev1.ConditionTrue,
					LastTransitionTime: metav1.Now(),
					Reason:             "Assigned",
					Message:            "EgressIP is successfully assigned to EgressNode",
				},
			}
		}
	} else if egressIP == "" {
		// Select one Node to update false status among all Nodes.
		// We don't care about the value of egress.Spec.EgressIP, just use it to reach a consensus among all agents
		// about which one should do the update.
		nodeToUpdateStatus, err := c.cluster.SelectNodeForIP(egress.Spec.EgressIP, "")
		if err != nil {
			return err
		}
		// Skip if the Node is not the selected one.
		if nodeToUpdateStatus != c.nodeName {
			return nil
		}
		desiredStatus.EgressNode = ""
		desiredStatus.EgressIP = ""
		// If the error is nil, it means the Egress hasn't been processed yet.
		// The scheduler will get a result for the Egress very soon regardless of success or failure and trigger the
		// controller to process it another time, so we avoid generating a transient state here, which may lead to some
		// back-off retries due to updating conflict.
		if scheduleErr != nil {
			desiredStatus.Conditions = []crdv1b1.EgressCondition{
				{
					Type:               crdv1b1.IPAssigned,
					Status:             corev1.ConditionFalse,
					LastTransitionTime: metav1.Now(),
					Reason:             "AssignmentError",
					Message:            fmt.Sprintf("Failed to assign the IP to EgressNode: %v", scheduleErr),
				},
			}
		}
	} else {
		// The Egress IP is assigned to a Node (egressIP != "") but it's not this Node (isLocal == false), do nothing.
		return nil
	}

	toUpdate := egress.DeepCopy()
	var updateErr, getErr error
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if compareEgressStatus(&toUpdate.Status, desiredStatus) {
			return nil
		}
		// Must make a copy here as we will append more conditions. If it's appended to desiredStatus directly, there
		// would be duplicate conditions when the function retries.
		statusToUpdate := desiredStatus.DeepCopy()
		// Copy conditions other than crdv1b1.IPAssigned to statusToUpdate.
		for _, c := range toUpdate.Status.Conditions {
			if c.Type != crdv1b1.IPAssigned {
				statusToUpdate.Conditions = append(statusToUpdate.Conditions, c)
			}
		}
		toUpdate.Status = *statusToUpdate

		klog.V(2).InfoS("Updating Egress status", "Egress", egress.Name, "oldNode", egress.Status.EgressNode, "newNode", toUpdate.Status.EgressNode)
		_, updateErr = c.crdClient.CrdV1beta1().Egresses().UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{})
		if updateErr != nil && errors.IsConflict(updateErr) {
			if toUpdate, getErr = c.crdClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{}); getErr != nil {
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
			if err := c.uninstallEgress(egressName, eState, egress); err != nil {
				return err
			}
			return nil
		}
		return err
	}

	var desiredEgressIP string
	var desiredNode string
	var scheduleErr error
	// Only check whether the Egress IP should be assigned to this Node when the Egress is schedulable.
	// Otherwise, users are responsible for assigning the Egress IP to Nodes.
	if isEgressSchedulable(egress) {
		egressIP, egressNode, err, scheduled := c.egressIPScheduler.GetEgressIPAndNode(egressName)
		if scheduled {
			desiredEgressIP = egressIP
			desiredNode = egressNode
		} else {
			scheduleErr = err
		}
	} else {
		desiredEgressIP = egress.Spec.EgressIP
	}

	eState, exist := c.getEgressState(egressName)
	// If the EgressIP changes, uninstalls this Egress first.
	if exist && eState.egressIP != desiredEgressIP {
		if err := c.uninstallEgress(egressName, eState, egress); err != nil {
			return err
		}
		exist = false
	}
	// Do not proceed if EgressIP is empty.
	if desiredEgressIP == "" {
		if err := c.updateEgressStatus(egress, "", scheduleErr); err != nil {
			return fmt.Errorf("update Egress %s status error: %v", egressName, err)
		}
		return nil
	}
	if !exist {
		eState = c.newEgressState(egressName, desiredEgressIP)
	}

	var subnetInfo *crdv1b1.SubnetInfo
	if desiredNode == c.nodeName {
		if c.supportSeparateSubnet && egress.Spec.ExternalIPPool != "" {
			if pool, err := c.externalIPPoolLister.Get(egress.Spec.ExternalIPPool); err != nil {
				return err
			} else {
				subnetInfo = pool.Spec.SubnetInfo
			}
		}
		// Ensure the Egress IP is assigned to the system. Force advertising the IP if it was previously assigned to
		// another Node in the Egress API. This could force refreshing other peers' neighbor cache when the Egress IP is
		// obtained by this Node and another Node at the same time in some situations, e.g. split brain.
		assigned, err := c.ipAssigner.AssignIP(desiredEgressIP, subnetInfo, egress.Status.EgressNode != c.nodeName)
		if err != nil {
			return err
		}
		if assigned {
			c.record.Eventf(egress, nil, corev1.EventTypeNormal, "IPAssigned", "NodeAssignment", "Assigned Egress %s with IP %s on Node %s", egress.Name, desiredEgressIP, desiredNode)
		}
	} else {
		// Unassign the Egress IP from the local Node if it was assigned by the agent.
		unassigned, err := c.ipAssigner.UnassignIP(desiredEgressIP)
		if err != nil {
			return err
		}
		if unassigned {
			c.record.Eventf(egress, nil, corev1.EventTypeNormal, "IPUnassigned", "NodeAssignment", "Unassigned Egress %s with IP %s from Node %s", egress.Name, desiredEgressIP, c.nodeName)
		}
	}

	// Realize the latest EgressIP and get the desired mark.
	mark, err := c.realizeEgressIP(egressName, desiredEgressIP, subnetInfo)
	if err != nil {
		return err
	}

	if err = c.realizeEgressQoS(egressName, eState, mark, egress.Spec.Bandwidth); err != nil {
		return err
	}

	// With the l2 dispatch, the Pod flows for an Egress IP on another Node carry the index of the Egress Node instead
	// of a tunnel destination.
	var l2DispatchIndex uint32
	if c.l2Dispatch {
		l2DispatchIndex = c.getL2DispatchIndex(egress, eState, desiredEgressIP, desiredNode, mark)
	}

	// If the mark changes, uninstall all of the Egress's Pod flows first, then installs them with new mark.
	// It could happen when the Egress IP is added to or removed from the Node. The same applies when the l2 dispatch
	// index of the Egress Node changes.
	if eState.mark != mark || eState.l2DispatchIndex != l2DispatchIndex {
		// Uninstall all of its Pod flows.
		if err := c.uninstallPodFlows(egressName, eState, eState.ofPorts, eState.pods); err != nil {
			return err
		}
		eState.mark = mark
		eState.l2DispatchIndex = l2DispatchIndex
	}

	if err := c.updateEgressStatus(egress, desiredEgressIP, nil); err != nil {
		return fmt.Errorf("update Egress %s status error: %v", egressName, err)
	}

	// Copy the previous ofPorts and Pods. They will be used to identify stale ofPorts and Pods.
	staleOFPorts := eState.ofPorts.Union(nil)
	stalePods := eState.pods.Union(nil)

	// Get a copy of the desired Pods.
	members := c.getEgressMembers(egressName)

	egressIP := net.ParseIP(eState.egressIP)
	isIPv6 := egressIP.To4() == nil
	// With the l2 dispatch, the traffic of the member Pods on other Nodes reaches the local Egress IP without a tunnel,
	// and gets the mark of the Egress IP from its source Pod IP.
	var remotePodIPs sets.Set[string]
	if c.l2Dispatch && mark != 0 {
		remotePodIPs = sets.New[string]()
	}
	// Install SNAT flows for desired Pods.
	for pod, podIPs := range members {
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
			// A member with IPs and no local interface is on another Node: only an Egress Node receives it, in an
			// EgressAddressGroup.
			if len(podIPs) > 0 {
				for podIP := range podIPs {
					if remotePodIPs != nil && (net.ParseIP(podIP).To4() == nil) == isIPv6 {
						remotePodIPs.Insert(podIP)
					}
				}
				continue
			}
			klog.Infof("Interfaces of Pod %s/%s not found", podNamespace, podName)
			continue
		}

		ofPort := ifaces[0].OFPort
		if eState.ofPorts.Has(ofPort) {
			staleOFPorts.Delete(ofPort)
			continue
		}
		switch {
		case mark != 0 || !c.l2Dispatch:
			if err := c.ofClient.InstallPodSNATFlows(uint32(ofPort), egressIP, mark); err != nil {
				return err
			}
		case l2DispatchIndex != 0:
			if err := c.ofClient.InstallPodL2DispatchFlows(uint32(ofPort), egressIP, l2DispatchIndex); err != nil {
				return err
			}
		default:
			// The Egress Node is not known yet, or the l2 dispatch cannot reach it: the Pod keeps the default SNAT.
			continue
		}
		eState.ofPorts.Insert(ofPort)
	}

	// Uninstall SNAT flows for stale Pods.
	if err := c.uninstallPodFlows(egressName, eState, staleOFPorts, stalePods); err != nil {
		return err
	}
	if c.l2Dispatch {
		if err := c.updateRemotePodIPs(egressName, eState.egressIP, remotePodIPs); err != nil {
			return fmt.Errorf("error updating the IPs of the remote Pods of Egress %s: %w", egressName, err)
		}
	}
	return nil
}

// getL2DispatchIndex returns the l2 dispatch index of the Egress Node, when the Egress IP is on another Node. The
// Egress Node is the Node which the scheduler selected for an Egress IP from an ExternalIPPool, and the Node in the
// status for an Egress IP which the user assigned. It returns 0 if the Egress IP is local, if the Egress Node is not
// known yet or its l2 dispatch routing is not installed yet, or if the l2 dispatch cannot reach it. The Pods of the
// Egress then keep the default SNAT.
func (c *EgressController) getL2DispatchIndex(egress *crdv1b1.Egress, eState *egressState, egressIP string,
	desiredNode string, mark uint32) uint32 {
	egressNode := ""
	if mark == 0 {
		egressNode = desiredNode
		if !isEgressSchedulable(egress) {
			egressNode = egress.Status.EgressNode
		}
		// The Egress IP is not on this Node, so a status which names this Node is stale: the new Egress Node has not
		// updated it yet.
		if egressNode == c.nodeName {
			egressNode = ""
		}
	}
	c.setL2DispatchNode(egress.Name, eState, egressNode)
	if egressNode == "" {
		if mark == 0 {
			klog.V(2).InfoS("The Egress Node is not known yet, the Pods of the Egress keep the default SNAT",
				"egress", egress.Name, "egressIP", egressIP)
		}
		return 0
	}
	index, installed, err := c.l2DispatchPeers.GetL2DispatchPeerIndex(egressNode, net.ParseIP(egressIP).To4() == nil)
	if err != nil {
		klog.ErrorS(err, "The l2 dispatch cannot reach the Egress Node, the Pods of the Egress keep the default SNAT",
			"egress", egress.Name, "egressIP", egressIP, "egressNode", egressNode)
		c.record.Eventf(egress, nil, corev1.EventTypeWarning, "EgressNodeUnreachable", "L2Dispatch",
			"The Pods of Egress %s on Node %s keep the default SNAT, as the l2 dispatch cannot reach Egress Node %s: %v",
			egress.Name, c.nodeName, egressNode, err)
		return 0
	}
	if !installed {
		klog.V(2).InfoS("The l2 dispatch routing to the Egress Node is not installed yet, the Pods of the Egress keep "+
			"the default SNAT", "egress", egress.Name, "egressIP", egressIP, "egressNode", egressNode)
		return 0
	}
	return index
}

// setL2DispatchNode records the remote Egress Node of the Egress, so that the Egress is synced again when the l2
// dispatch routing of that Node changes. An empty nodeName means that the Egress has none.
func (c *EgressController) setL2DispatchNode(egressName string, eState *egressState, nodeName string) {
	if eState.l2DispatchNode == nodeName {
		return
	}
	c.l2DispatchEgressesMutex.Lock()
	defer c.l2DispatchEgressesMutex.Unlock()
	if egresses, exists := c.l2DispatchEgresses[eState.l2DispatchNode]; exists {
		egresses.Delete(egressName)
		if egresses.Len() == 0 {
			delete(c.l2DispatchEgresses, eState.l2DispatchNode)
		}
	}
	if nodeName != "" {
		if c.l2DispatchEgresses[nodeName] == nil {
			c.l2DispatchEgresses[nodeName] = sets.New[string]()
		}
		c.l2DispatchEgresses[nodeName].Insert(egressName)
	}
	eState.l2DispatchNode = nodeName
}

// onL2DispatchPeerUpdate is called when the l2 dispatch routing of a peer Node is installed, changes, or is about to
// be removed. It syncs again the Egresses whose Egress IP is on that Node, so that their Pod flows use the current
// index of the Node.
func (c *EgressController) onL2DispatchPeerUpdate(nodeName string) {
	c.l2DispatchEgressesMutex.Lock()
	defer c.l2DispatchEgressesMutex.Unlock()
	for egressName := range c.l2DispatchEgresses[nodeName] {
		c.queue.Add(egressName)
	}
}

// unionRemotePodIPs returns the IPs of the Pods on other Nodes which use the local Egress IP, through all its
// Egresses except the excluded one.
func unionRemotePodIPs(ipState *egressIPState, excludedEgress string) sets.Set[string] {
	podIPs := sets.New[string]()
	for egressName, egressPodIPs := range ipState.remotePodIPs {
		if egressName != excludedEgress {
			podIPs.Insert(egressPodIPs.UnsortedList()...)
		}
	}
	return podIPs
}

// updateRemotePodIPs records the IPs of the Pods on other Nodes which use the local Egress IP through the Egress, and
// sets the ipset of the Egress IP to the IPs of all its Egresses. It does nothing if the Egress IP is not local.
func (c *EgressController) updateRemotePodIPs(egressName, egressIP string, podIPs sets.Set[string]) error {
	c.egressIPStatesMutex.Lock()
	defer c.egressIPStatesMutex.Unlock()
	ipState, exists := c.egressIPStates[egressIP]
	if !exists || ipState.mark == 0 {
		return nil
	}
	if ipState.remotePodIPs[egressName].Equal(podIPs) {
		return nil
	}
	allPodIPs := unionRemotePodIPs(ipState, egressName).Union(podIPs)
	if err := c.routeClient.SetEgressRemotePodIPs(ipState.mark, allPodIPs); err != nil {
		return err
	}
	if podIPs.Len() == 0 {
		delete(ipState.remotePodIPs, egressName)
		return nil
	}
	if ipState.remotePodIPs == nil {
		ipState.remotePodIPs = map[string]sets.Set[string]{}
	}
	ipState.remotePodIPs[egressName] = podIPs
	return nil
}

func (c *EgressController) uninstallEgress(egressName string, eState *egressState, egress *crdv1b1.Egress) error {
	// Uninstall all of its Pod flows.
	if err := c.uninstallPodFlows(egressName, eState, eState.ofPorts, eState.pods); err != nil {
		return err
	}
	if c.l2Dispatch {
		c.setL2DispatchNode(egressName, eState, "")
	}
	// Release the EgressIP's mark if the Egress is the last one referring to it.
	if err := c.unrealizeEgressIP(egressName, eState.egressIP); err != nil {
		return err
	}
	// Uninstall its meter.
	if c.trafficShapingEnabled && eState.rateLimitMeter != nil {
		if err := c.ofClient.UninstallEgressQoS(eState.rateLimitMeter.MeterID); err != nil {
			return err
		}
	}
	// Unassign the Egress IP from the local Node if it was assigned by the agent.
	unassigned, err := c.ipAssigner.UnassignIP(eState.egressIP)
	if err != nil {
		return err
	}
	if unassigned && egress != nil {
		c.record.Eventf(egress, nil, corev1.EventTypeNormal, "IPUnassigned", "NodeAssignment", "Unassigned Egress %s with IP %s from Node %s", egressName, eState.egressIP, c.nodeName)
	}
	// Remove the Egress's state.
	c.deleteEgressState(egressName)
	return nil
}

func (c *EgressController) uninstallPodFlows(egressName string, egressState *egressState, ofPorts sets.Set[int32], pods sets.Set[string]) error {
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
	newEffectiveEgresses := sets.New[string]()
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
		klog.ErrorS(err, "Failed to get antrea client")
		return
	}
	options := metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("nodeName", c.nodeName).String(),
	}
	watcher, err := antreaClient.ControlplaneV1beta2().EgressGroups().Watch(context.TODO(), options)
	if err != nil {
		klog.ErrorS(err, "Failed to start watch for EgressGroup")
		return
	}
	// Watch method doesn't return error but "emptyWatch" in case of some partial data errors,
	// e.g. timeout error. Make sure that watcher is not empty and log error otherwise.
	if reflect.TypeOf(watcher) == reflect.TypeOf(emptyWatch) {
		klog.ErrorS(nil, "Failed to start watch for EgressGroup, please ensure antrea service is reachable for the agent")
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
		event, ok := <-watcher.ResultChan()
		if !ok {
			klog.InfoS("Result channel for EgressGroup was closed")
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
	klog.Infof("Received %d init events for EgressGroup", len(initObjects))

	eventCount += len(initObjects)
	c.replaceEgressGroups(initObjects)

	for {
		event, ok := <-watcher.ResultChan()
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

func (c *EgressController) replaceEgressGroups(groups []*cpv1b2.EgressGroup) {
	c.egressGroupsMutex.Lock()
	defer c.egressGroupsMutex.Unlock()

	oldGroupKeys := make(sets.Set[string], len(c.egressGroups))
	for key := range c.egressGroups {
		oldGroupKeys.Insert(key)
	}

	for _, group := range groups {
		oldGroupKeys.Delete(group.Name)
		pods := sets.New[string]()
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
	pods := sets.New[string]()
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

// getEgressMembers returns a copy of the member Pods of the Egress, by namespaced name, with their IPs. The EgressGroup
// gives the members on this Node, without IPs. With the l2 dispatch, an Egress Node also receives the EgressAddressGroup
// of the Egress, which gives all members with their IPs. It returns nil if the Node has neither group.
func (c *EgressController) getEgressMembers(egressName string) map[string]sets.Set[string] {
	var members map[string]sets.Set[string]
	func() {
		c.egressGroupsMutex.RLock()
		defer c.egressGroupsMutex.RUnlock()
		pods, exist := c.egressGroups[egressName]
		if !exist {
			return
		}
		members = make(map[string]sets.Set[string], len(pods))
		for pod := range pods {
			members[pod] = nil
		}
	}()
	if !c.l2Dispatch {
		return members
	}
	c.egressAddressGroupsMutex.RLock()
	defer c.egressAddressGroupsMutex.RUnlock()
	// An Egress is in one group, but for a short time in two when its appliedTo changes.
	for _, group := range c.egressAddressGroups {
		if !group.egresses.Has(egressName) {
			continue
		}
		if members == nil {
			members = make(map[string]sets.Set[string], len(group.members))
		}
		for pod, ips := range group.members {
			members[pod] = ips.Clone()
		}
	}
	return members
}

func (c *EgressController) watchEgressAddressGroup() {
	klog.Info("Starting watch for EgressAddressGroup")
	antreaClient, err := c.antreaClientProvider.GetAntreaClient()
	if err != nil {
		klog.ErrorS(err, "Failed to get antrea client")
		return
	}
	options := metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("nodeName", c.nodeName).String(),
	}
	watcher, err := antreaClient.ControlplaneV1beta2().EgressAddressGroups().Watch(context.TODO(), options)
	if err != nil {
		klog.ErrorS(err, "Failed to start watch for EgressAddressGroup")
		return
	}
	// Watch method doesn't return error but "emptyWatch" in case of some partial data errors,
	// e.g. timeout error. Make sure that watcher is not empty and log error otherwise.
	if reflect.TypeOf(watcher) == reflect.TypeOf(emptyWatch) {
		klog.ErrorS(nil, "Failed to start watch for EgressAddressGroup, please ensure antrea service is reachable for the agent")
		return
	}

	klog.Info("Started watch for EgressAddressGroup")
	eventCount := 0
	defer func() {
		klog.InfoS("Stopped watch for EgressAddressGroup", "totalItemsReceived", eventCount)
		watcher.Stop()
	}()

	// First receive init events from the result channel and buffer them until
	// a Bookmark event is received, indicating that all init events have been
	// received.
	var initObjects []*cpv1b2.EgressAddressGroup
loop:
	for {
		event, ok := <-watcher.ResultChan()
		if !ok {
			klog.InfoS("Result channel for EgressAddressGroup was closed")
			return
		}
		switch event.Type {
		case watch.Added:
			klog.V(2).InfoS("Added EgressAddressGroup", "object", event.Object)
			initObjects = append(initObjects, event.Object.(*cpv1b2.EgressAddressGroup))
		case watch.Bookmark:
			break loop
		}
	}
	klog.InfoS("Received init events for EgressAddressGroup", "count", len(initObjects))

	eventCount += len(initObjects)
	c.replaceEgressAddressGroups(initObjects)

	for {
		event, ok := <-watcher.ResultChan()
		if !ok {
			return
		}
		switch event.Type {
		case watch.Added:
			c.addEgressAddressGroup(event.Object.(*cpv1b2.EgressAddressGroup))
			klog.V(2).InfoS("Added EgressAddressGroup", "object", event.Object)
		case watch.Modified:
			c.patchEgressAddressGroup(event.Object.(*cpv1b2.EgressAddressGroupPatch))
			klog.V(2).InfoS("Updated EgressAddressGroup", "object", event.Object)
		case watch.Deleted:
			c.deleteEgressAddressGroup(event.Object.(*cpv1b2.EgressAddressGroup))
			klog.V(2).InfoS("Removed EgressAddressGroup", "object", event.Object)
		default:
			klog.ErrorS(nil, "Unknown event", "event", event)
			return
		}
		eventCount++
	}
}

// replaceEgressAddressGroups replaces the EgressAddressGroups with the ones the watch received at its start, and syncs
// the Egresses of the previous and the new groups.
func (c *EgressController) replaceEgressAddressGroups(groups []*cpv1b2.EgressAddressGroup) {
	c.egressAddressGroupsMutex.Lock()
	defer c.egressAddressGroupsMutex.Unlock()

	affectedEgresses := sets.New[string]()
	for _, group := range c.egressAddressGroups {
		affectedEgresses.Insert(group.egresses.UnsortedList()...)
	}
	c.egressAddressGroups = make(map[string]*egressAddressGroup, len(groups))
	for _, group := range groups {
		g := newEgressAddressGroup(group)
		c.egressAddressGroups[group.Name] = g
		affectedEgresses.Insert(g.egresses.UnsortedList()...)
	}
	for egressName := range affectedEgresses {
		c.queue.Add(egressName)
	}
}

func (c *EgressController) addEgressAddressGroup(group *cpv1b2.EgressAddressGroup) {
	g := newEgressAddressGroup(group)

	c.egressAddressGroupsMutex.Lock()
	defer c.egressAddressGroupsMutex.Unlock()

	affectedEgresses := g.egresses.Clone()
	if prev, exists := c.egressAddressGroups[group.Name]; exists {
		affectedEgresses.Insert(prev.egresses.UnsortedList()...)
	}
	c.egressAddressGroups[group.Name] = g
	for egressName := range affectedEgresses {
		c.queue.Add(egressName)
	}
}

func (c *EgressController) patchEgressAddressGroup(patch *cpv1b2.EgressAddressGroupPatch) {
	c.egressAddressGroupsMutex.Lock()
	defer c.egressAddressGroupsMutex.Unlock()

	g, exists := c.egressAddressGroups[patch.Name]
	if !exists {
		klog.InfoS("Ignored the patch of an unknown EgressAddressGroup", "name", patch.Name)
		return
	}
	affectedEgresses := g.egresses.Clone()
	// The patch carries the list of the Egresses only when it changes.
	if len(patch.Egresses) > 0 {
		g.egresses = sets.New[string](patch.Egresses...)
		affectedEgresses.Insert(patch.Egresses...)
	}
	// The IPs of a member are part of its identity, so the patch for a Pod whose IPs change removes the member with
	// the previous IPs and adds the member with the new ones. Both have the same key here, so the removed members are
	// applied first, or the Pod would be dropped from the group.
	for i := range patch.RemovedGroupMembers {
		g.removeMember(&patch.RemovedGroupMembers[i])
	}
	for i := range patch.AddedGroupMembers {
		g.addMember(&patch.AddedGroupMembers[i])
	}
	for egressName := range affectedEgresses {
		c.queue.Add(egressName)
	}
}

func (c *EgressController) deleteEgressAddressGroup(group *cpv1b2.EgressAddressGroup) {
	c.egressAddressGroupsMutex.Lock()
	defer c.egressAddressGroupsMutex.Unlock()

	// A Deleted event carries only the metadata of the group, so the Egresses come from the stored group.
	prev, exists := c.egressAddressGroups[group.Name]
	if !exists {
		return
	}
	delete(c.egressAddressGroups, group.Name)
	for egressName := range prev.egresses {
		c.queue.Add(egressName)
	}
}

// GetEgressIPByMark returns the Egress IP associated with the snatMark.
func (c *EgressController) GetEgressIPByMark(mark uint32) (string, error) {
	c.egressIPStatesMutex.Lock()
	defer c.egressIPStatesMutex.Unlock()
	for _, e := range c.egressIPStates {
		if e.mark == mark {
			return e.egressIP.String(), nil
		}
	}
	return "", fmt.Errorf("no EgressIP associated with mark %v", mark)
}

// GetEgress returns the Egress configuration applied to this Pod.
// If no Egress is applied to the Pod, an error will be returned.
func (c *EgressController) GetEgress(ns, podName string) (types.EgressConfig, error) {
	if c == nil {
		return types.EgressConfig{}, fmt.Errorf("Egress is not enabled")
	}
	pod := k8s.NamespacedName(ns, podName)
	egressName, exists := func() (string, bool) {
		c.egressBindingsMutex.RLock()
		defer c.egressBindingsMutex.RUnlock()
		binding, exists := c.egressBindings[pod]
		if !exists {
			return "", false
		}
		return binding.effectiveEgress, true
	}()
	if !exists {
		return types.EgressConfig{}, fmt.Errorf("no Egress applied to Pod %v", pod)
	}
	egress, err := c.egressLister.Get(egressName)
	if err != nil {
		return types.EgressConfig{}, err
	}
	return types.EgressConfig{
		Name:       egressName,
		UID:        egress.UID,
		EgressIP:   egress.Status.EgressIP,
		EgressNode: egress.Status.EgressNode,
	}, nil
}

// An Egress is schedulable if its Egress IP is allocated from ExternalIPPool.
func isEgressSchedulable(egress *crdv1b1.Egress) bool {
	return egress.Spec.EgressIP != "" && egress.Spec.ExternalIPPool != ""
}

// compareEgressStatus compares two Egress Statuses, ignoring LastTransitionTime and conditions other than IPAssigned, returns true if they are equal.
func compareEgressStatus(currentStatus, desiredStatus *crdv1b1.EgressStatus) bool {
	if currentStatus == nil && desiredStatus == nil {
		return true
	}
	if currentStatus == nil || desiredStatus == nil {
		return false
	}
	if currentStatus.EgressIP != desiredStatus.EgressIP || currentStatus.EgressNode != desiredStatus.EgressNode {
		return false
	}
	currentIPAssignedCondition := crdv1b1.GetEgressCondition(currentStatus.Conditions, crdv1b1.IPAssigned)
	desiredIPAssignedCondition := crdv1b1.GetEgressCondition(desiredStatus.Conditions, crdv1b1.IPAssigned)
	if currentIPAssignedCondition == nil && desiredIPAssignedCondition == nil {
		return true
	}
	if currentIPAssignedCondition == nil || desiredIPAssignedCondition == nil {
		return false
	}
	return currentIPAssignedCondition.Status == desiredIPAssignedCondition.Status && currentIPAssignedCondition.Reason == desiredIPAssignedCondition.Reason && currentIPAssignedCondition.Message == desiredIPAssignedCondition.Message
}
