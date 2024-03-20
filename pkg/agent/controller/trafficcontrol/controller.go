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

package trafficcontrol

import (
	"context"
	"crypto/sha1" // #nosec G505: not used for security purposes
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/k8s"
	utilsets "antrea.io/antrea/pkg/util/sets"
)

const (
	controllerName = "TrafficControlController"
	// How long to wait before retrying the processing of a TrafficControl change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing a TrafficControl change.
	defaultWorkers = 4
	// Disable resyncing.
	resyncPeriod time.Duration = 0

	// Default VXLAN tunnel destination port.
	defaultVXLANTunnelDestinationPort = int32(4789)
	// Default GENEVE tunnel destination port.
	defaultGENEVETunnelDestinationPort = int32(6081)

	portNamePrefixVXLAN  = "vxlan"
	portNamePrefixGENEVE = "geneve"
	portNamePrefixGRE    = "gre"
	portNamePrefixERSPAN = "erspan"
)

var (
	trafficControlPortExternalIDs = map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaTrafficControl,
	}
)

// trafficControlState keeps the actual state of a TrafficControl that has been realized.
type trafficControlState struct {
	// The actual name of target port used by a TrafficControl.
	targetPortName string
	// The actual openflow port for which we have installed for a TrafficControl.
	targetOFPort uint32
	// The actual name of return port used by a TrafficControl.
	returnPortName string
	// The actual action of a TrafficControl.
	action v1alpha2.TrafficControlAction
	// The actual direction of a TrafficControl.
	direction v1alpha2.Direction
	// The actual openflow ports for which we have installed flows for a TrafficControl. Note that, flows are only installed
	// for the Pods whose effective TrafficControl is the current TrafficControl, and the ports are these Pods'.
	ofPorts sets.Set[int32]
	// The actual Pods applied with the TrafficControl. Note that, a TrafficControl can be either effective TrafficControl
	// or alternative TrafficControl for these Pods.
	pods sets.Set[string]
}

// podToTCBinding keeps the TrafficControls applied to a Pod. There is only one effective TrafficControl for a Pod at any
// given time.
type podToTCBinding struct {
	effectiveTC    string
	alternativeTCs sets.Set[string]
}

// portToTCBinding keeps the TrafficControls using an OVS port.
type portToTCBinding struct {
	interfaceConfig *interfacestore.InterfaceConfig
	trafficControls sets.Set[string]
}

type Controller struct {
	ofClient openflow.Client

	portToTCBindings   map[string]*portToTCBinding
	ovsBridgeClient    ovsconfig.OVSBridgeClient
	ovsCtlClient       ovsctl.OVSCtlClient
	ovsPortUpdateMutex sync.Mutex

	interfaceStore interfacestore.InterfaceStore

	podInformer     cache.SharedIndexInformer
	podLister       corelisters.PodLister
	podListerSynced cache.InformerSynced

	namespaceInformer     cache.SharedIndexInformer
	namespaceLister       corelisters.NamespaceLister
	namespaceListerSynced cache.InformerSynced

	podToTCBindings      map[string]*podToTCBinding
	podToTCBindingsMutex sync.RWMutex

	tcStates      map[string]*trafficControlState
	tcStatesMutex sync.RWMutex

	trafficControlInformer     cache.SharedIndexInformer
	trafficControlLister       crdlisters.TrafficControlLister
	trafficControlListerSynced cache.InformerSynced
	queue                      workqueue.RateLimitingInterface
}

func NewTrafficControlController(ofClient openflow.Client,
	interfaceStore interfacestore.InterfaceStore,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	ovsCtlClient ovsctl.OVSCtlClient,
	tcInformer crdinformers.TrafficControlInformer,
	podInformer cache.SharedIndexInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	podUpdateSubscriber channel.Subscriber) *Controller {
	c := &Controller{
		ofClient:                   ofClient,
		ovsBridgeClient:            ovsBridgeClient,
		ovsCtlClient:               ovsCtlClient,
		interfaceStore:             interfaceStore,
		trafficControlInformer:     tcInformer.Informer(),
		trafficControlLister:       tcInformer.Lister(),
		trafficControlListerSynced: tcInformer.Informer().HasSynced,
		podInformer:                podInformer,
		podLister:                  corelisters.NewPodLister(podInformer.GetIndexer()),
		podListerSynced:            podInformer.HasSynced,
		namespaceInformer:          namespaceInformer.Informer(),
		namespaceLister:            namespaceInformer.Lister(),
		namespaceListerSynced:      namespaceInformer.Informer().HasSynced,
		podToTCBindings:            map[string]*podToTCBinding{},
		portToTCBindings:           map[string]*portToTCBinding{},
		tcStates:                   map[string]*trafficControlState{},
		queue:                      workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "trafficControlGroup"),
	}
	c.trafficControlInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addTC,
			UpdateFunc: c.updateTC,
			DeleteFunc: c.deleteTC,
		},
		resyncPeriod,
	)
	c.podInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addPod,
			UpdateFunc: c.updatePod,
			DeleteFunc: c.deletePod,
		},
		resyncPeriod,
	)
	c.namespaceInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addNamespace,
			UpdateFunc: c.updateNamespace,
			DeleteFunc: nil,
		},
		resyncPeriod,
	)
	podUpdateSubscriber.Subscribe(c.processPodUpdate)
	return c
}

// processPodUpdate will be called when CNIServer publishes a Pod update event, and the event of TrafficControl which is
// the effective one of the Pod is triggered.
func (c *Controller) processPodUpdate(e interface{}) {
	c.podToTCBindingsMutex.RLock()
	defer c.podToTCBindingsMutex.RUnlock()
	podEvent := e.(types.PodUpdate)
	pod := k8s.NamespacedName(podEvent.PodNamespace, podEvent.PodName)
	binding, exists := c.podToTCBindings[pod]
	if !exists {
		return
	}
	c.queue.Add(binding.effectiveTC)
}

func (c *Controller) matchedPod(pod *v1.Pod, to *v1alpha2.AppliedTo) bool {
	if to.NamespaceSelector == nil && to.PodSelector == nil {
		return false
	}
	if to.NamespaceSelector != nil {
		namespace, _ := c.namespaceLister.Get(pod.Namespace)
		if namespace == nil {
			return false
		}
		nsSelector, _ := metav1.LabelSelectorAsSelector(to.NamespaceSelector)
		if !nsSelector.Matches(labels.Set(namespace.Labels)) {
			return false
		}
	}
	if to.PodSelector != nil {
		podSelector, _ := metav1.LabelSelectorAsSelector(to.PodSelector)
		if !podSelector.Matches(labels.Set(pod.Labels)) {
			return false
		}
	}

	return true
}

func (c *Controller) filterAffectedTCsByPod(pod *v1.Pod) sets.Set[string] {
	affectedTCs := sets.New[string]()
	allTCs, _ := c.trafficControlLister.List(labels.Everything())
	for _, tc := range allTCs {
		if c.matchedPod(pod, &tc.Spec.AppliedTo) {
			affectedTCs.Insert(tc.GetName())
		}
	}
	return affectedTCs
}

func (c *Controller) addPod(obj interface{}) {
	pod := obj.(*v1.Pod)
	if pod.Spec.HostNetwork {
		return
	}
	affectedTCs := c.filterAffectedTCsByPod(pod)
	if len(affectedTCs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Pod ADD event", "Pod", klog.KObj(pod))
	for affectedTC := range affectedTCs {
		c.queue.Add(affectedTC)
	}
}

func (c *Controller) updatePod(oldObj interface{}, obj interface{}) {
	oldPod := oldObj.(*v1.Pod)
	pod := obj.(*v1.Pod)
	if pod.Spec.HostNetwork {
		return
	}
	if reflect.DeepEqual(pod.GetLabels(), oldPod.GetLabels()) {
		return
	}
	oldAffectedTCs := c.filterAffectedTCsByPod(oldPod)
	nowAffectedTCs := c.filterAffectedTCsByPod(pod)
	affectedTCs := utilsets.SymmetricDifferenceString(oldAffectedTCs, nowAffectedTCs)
	if len(affectedTCs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Pod UPDATE event", "Pod", klog.KObj(pod))
	for affectedTC := range affectedTCs {
		c.queue.Add(affectedTC)
	}
}

func (c *Controller) deletePod(obj interface{}) {
	pod := obj.(*v1.Pod)
	if pod.Spec.HostNetwork {
		return
	}
	affectedTCs := c.filterAffectedTCsByPod(pod)
	if len(affectedTCs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Pod DELETE event", "Pod", klog.KObj(pod))
	for affectedTC := range affectedTCs {
		c.queue.Add(affectedTC)
	}
}

func matchedNamespace(namespace *v1.Namespace, to *v1alpha2.AppliedTo) bool {
	if to.NamespaceSelector != nil {
		nsSelector, _ := metav1.LabelSelectorAsSelector(to.NamespaceSelector)
		if !nsSelector.Matches(labels.Set(namespace.Labels)) {
			return false
		}
	}
	return true
}

func (c *Controller) filterAffectedTCsByNS(namespace *v1.Namespace) sets.Set[string] {
	affectedTCs := sets.New[string]()
	allTCs, _ := c.trafficControlLister.List(labels.Everything())
	for _, tc := range allTCs {
		if matchedNamespace(namespace, &tc.Spec.AppliedTo) {
			affectedTCs.Insert(tc.GetName())
		}
	}
	return affectedTCs
}

func (c *Controller) addNamespace(obj interface{}) {
	ns := obj.(*v1.Namespace)
	affectedTCs := c.filterAffectedTCsByNS(ns)
	if len(affectedTCs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Namespace ADD event", "Namespace", klog.KObj(ns))
	for tc := range affectedTCs {
		c.queue.Add(tc)
	}
}

func (c *Controller) updateNamespace(oldObj, obj interface{}) {
	oldNS := oldObj.(*v1.Namespace)
	ns := obj.(*v1.Namespace)
	if reflect.DeepEqual(oldNS.GetLabels(), ns.GetLabels()) {
		return
	}
	oldAffectedTCs := c.filterAffectedTCsByNS(oldNS)
	nowAffectedTCs := c.filterAffectedTCsByNS(ns)
	affectedTCs := utilsets.SymmetricDifferenceString(oldAffectedTCs, nowAffectedTCs)
	if len(affectedTCs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Namespace UPDATE event", "Namespace", klog.KObj(ns))
	for tc := range affectedTCs {
		c.queue.Add(tc)
	}
}

func (c *Controller) addTC(obj interface{}) {
	tc := obj.(*v1alpha2.TrafficControl)
	klog.V(2).InfoS("Processing TrafficControl ADD event", "TrafficControl", klog.KObj(tc))
	c.queue.Add(tc.Name)
}

func (c *Controller) updateTC(oldObj interface{}, obj interface{}) {
	oldTC := oldObj.(*v1alpha2.TrafficControl)
	tc := obj.(*v1alpha2.TrafficControl)
	if tc.GetGeneration() != oldTC.GetGeneration() {
		klog.V(2).InfoS("Processing TrafficControl UPDATE event", "TrafficControl", klog.KObj(tc))
		c.queue.Add(tc.Name)
	}
}

func (c *Controller) deleteTC(obj interface{}) {
	tc := obj.(*v1alpha2.TrafficControl)
	klog.V(2).InfoS("Processing TrafficControl DELETE event", "TrafficControl", klog.KObj(tc))
	c.queue.Add(tc.Name)
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting", "controllerName", controllerName)
	defer klog.InfoS("Shutting down", "controllerName", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.trafficControlListerSynced, c.podListerSynced, c.namespaceListerSynced) {
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)

	if key, ok := obj.(string); !ok {
		// As the item in the work queue is actually invalid, we call Forget here else we'd
		// go into a loop of attempting to process a work item that is invalid.
		// This should not happen.
		c.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else if err := c.syncTrafficControl(key); err == nil {
		// If no error occurs we Forget this item, so it does not get queued again until
		// another change happens.
		c.queue.Forget(key)
	} else {
		// Put the item back on the work queue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Syncing TrafficControl failed, requeue", "TrafficControl", key)
	}
	return true
}

func (c *Controller) newTrafficControlState(tcName string, action v1alpha2.TrafficControlAction, direction v1alpha2.Direction) *trafficControlState {
	c.tcStatesMutex.Lock()
	defer c.tcStatesMutex.Unlock()
	state := &trafficControlState{
		pods:      sets.New[string](),
		ofPorts:   sets.New[int32](),
		action:    action,
		direction: direction,
	}
	c.tcStates[tcName] = state
	return state
}

func (c *Controller) getTrafficControlState(tcName string) (*trafficControlState, bool) {
	c.tcStatesMutex.RLock()
	defer c.tcStatesMutex.RUnlock()
	state, exists := c.tcStates[tcName]
	return state, exists
}

func (c *Controller) deleteTrafficControlState(tcName string) {
	c.tcStatesMutex.Lock()
	defer c.tcStatesMutex.Unlock()
	delete(c.tcStates, tcName)
}

func (c *Controller) filterPods(appliedTo *v1alpha2.AppliedTo) ([]*v1.Pod, error) {
	// If both selectors are nil, no Pod should be selected.
	if appliedTo.PodSelector == nil && appliedTo.NamespaceSelector == nil {
		return nil, nil
	}
	var podSelector, nsSelector labels.Selector
	var err error
	var selectedPods []*v1.Pod

	if appliedTo.PodSelector != nil {
		// If Pod selector is not nil, use it to select Pods.
		podSelector, err = metav1.LabelSelectorAsSelector(appliedTo.PodSelector)
		if err != nil {
			return nil, err
		}
	} else {
		// If Pod selector is nil, then Namespace selector will not be nil, select all Pods from the selected Namespaces.
		podSelector = labels.Everything()
	}

	if appliedTo.NamespaceSelector != nil {
		// If Namespace selector is not nil, use it to select Namespaces.
		var namespaces []*v1.Namespace
		nsSelector, err = metav1.LabelSelectorAsSelector(appliedTo.NamespaceSelector)
		if err != nil {
			return nil, err
		}
		namespaces, err = c.namespaceLister.List(nsSelector)
		if err != nil {
			return nil, err
		}
		// Select Pods with Pod selector from the selected Namespaces.
		for _, ns := range namespaces {
			pods, err := c.podLister.Pods(ns.Name).List(podSelector)
			if err != nil {
				return nil, err
			}
			selectedPods = append(selectedPods, pods...)
		}
	} else {
		// If Namespace selector is nil, use Pod selector to select Pods from all Namespaces.
		selectedPods, err = c.podLister.List(podSelector)
		if err != nil {
			return nil, err
		}
	}

	var nonHostNetworkPods []*v1.Pod
	// TrafficControl does not support host network Pods.
	for _, pod := range selectedPods {
		if !pod.Spec.HostNetwork {
			nonHostNetworkPods = append(nonHostNetworkPods, pod)
		}
	}

	return nonHostNetworkPods, nil
}

func genVXLANPortName(tunnel *v1alpha2.UDPTunnel) string {
	hash := sha1.New() // #nosec G401: not used for security purposes
	hash.Write(net.ParseIP(tunnel.RemoteIP))

	destinationPort := defaultVXLANTunnelDestinationPort
	if tunnel.DestinationPort != nil {
		destinationPort = *tunnel.DestinationPort
	}
	binary.Write(hash, binary.BigEndian, destinationPort)
	var vni int32
	if tunnel.VNI != nil {
		vni = *tunnel.VNI
	}
	binary.Write(hash, binary.BigEndian, vni)
	return fmt.Sprintf("%s-%s", portNamePrefixVXLAN, hex.EncodeToString(hash.Sum(nil))[:6])
}

func genGENEVEPortName(tunnel *v1alpha2.UDPTunnel) string {
	hash := sha1.New() // #nosec G401: not used for security purposes
	hash.Write(net.ParseIP(tunnel.RemoteIP))

	destinationPort := defaultGENEVETunnelDestinationPort
	if tunnel.DestinationPort != nil {
		destinationPort = *tunnel.DestinationPort
	}
	binary.Write(hash, binary.BigEndian, destinationPort)
	var vni int32
	if tunnel.VNI != nil {
		vni = *tunnel.VNI
	}
	binary.Write(hash, binary.BigEndian, vni)
	return fmt.Sprintf("%s-%s", portNamePrefixGENEVE, hex.EncodeToString(hash.Sum(nil))[:6])
}

func genGREPortName(tunnel *v1alpha2.GRETunnel) string {
	hash := sha1.New() // #nosec G401: not used for security purposes
	hash.Write(net.ParseIP(tunnel.RemoteIP))

	var key int32
	if tunnel.Key != nil {
		key = *tunnel.Key
	}
	binary.Write(hash, binary.BigEndian, key)
	return fmt.Sprintf("%s-%s", portNamePrefixGRE, hex.EncodeToString(hash.Sum(nil))[:6])
}

// genERSPANPortName generates a port name for the given ERSPAN tunnel.
// Note that ERSPAN tunnel's uniqueness is based on the remote IP and the session ID only, which means if there are two
// tunnels having same remote IP and session ID but different other attributes, creating the second port would fail in
// OVS.
func genERSPANPortName(tunnel *v1alpha2.ERSPANTunnel) string {
	hash := sha1.New() // #nosec G401: not used for security purposes
	hash.Write(net.ParseIP(tunnel.RemoteIP))

	var sessionID, index, dir, hardwareID int32
	if tunnel.SessionID != nil {
		sessionID = *tunnel.SessionID
	}
	if tunnel.Index != nil {
		index = *tunnel.Index
	}
	if tunnel.Dir != nil {
		dir = *tunnel.Dir
	}
	if tunnel.HardwareID != nil {
		hardwareID = *tunnel.HardwareID
	}
	binary.Write(hash, binary.BigEndian, sessionID)
	binary.Write(hash, binary.BigEndian, tunnel.Version)
	binary.Write(hash, binary.BigEndian, index)
	binary.Write(hash, binary.BigEndian, dir)
	binary.Write(hash, binary.BigEndian, hardwareID)
	return fmt.Sprintf("%s-%s", portNamePrefixERSPAN, hex.EncodeToString(hash.Sum(nil))[:6])
}

func ParseTrafficControlInterfaceConfig(portData *ovsconfig.OVSPortData, portConfig *interfacestore.OVSPortConfig) *interfacestore.InterfaceConfig {
	return &interfacestore.InterfaceConfig{
		Type:          interfacestore.TrafficControlInterface,
		InterfaceName: portData.Name,
		OVSPortConfig: portConfig}
}

// createOVSInternalPort creates an OVS internal port on OVS and corresponding interface on host. Note that, host interface
// might not be available immediately after creating OVS internal port.
func (c *Controller) createOVSInternalPort(portName string) (string, error) {
	portUUID, err := c.ovsBridgeClient.CreateInternalPort(portName, 0, "", trafficControlPortExternalIDs)
	if err != nil {
		return "", err
	}
	if pollErr := wait.PollUntilContextTimeout(context.TODO(), time.Second, 5*time.Second, true,
		func(ctx context.Context) (bool, error) {
			_, _, err := util.SetLinkUp(portName)
			if err == nil {
				return true, nil
			}
			if _, ok := err.(util.LinkNotFound); ok {
				return false, nil
			}
			return false, err
		}); pollErr != nil {
		return "", pollErr
	}
	return portUUID, nil
}

func (c *Controller) createUDPTunnelPort(portName string, tunnelType ovsconfig.TunnelType, tunnelConfig *v1alpha2.UDPTunnel) (string, error) {
	extraOptions := map[string]interface{}{}
	if tunnelConfig.DestinationPort != nil {
		extraOptions["dst_port"] = strconv.Itoa(int(*tunnelConfig.DestinationPort))
	}
	if tunnelConfig.VNI != nil {
		extraOptions["key"] = strconv.Itoa(int(*tunnelConfig.VNI))
	}
	portUUID, err := c.ovsBridgeClient.CreateTunnelPortExt(portName,
		tunnelType,
		0,
		false,
		"",
		tunnelConfig.RemoteIP,
		"",
		"",
		extraOptions,
		trafficControlPortExternalIDs)
	return portUUID, err
}

func (c *Controller) createGREPort(portName string, tunnelConfig *v1alpha2.GRETunnel) (string, error) {
	extraOptions := map[string]interface{}{}
	if tunnelConfig.Key != nil {
		extraOptions["key"] = strconv.Itoa(int(*tunnelConfig.Key))
	}
	portUUID, err := c.ovsBridgeClient.CreateTunnelPortExt(portName,
		ovsconfig.GRETunnel,
		0,
		false,
		"",
		tunnelConfig.RemoteIP,
		"",
		"",
		extraOptions,
		trafficControlPortExternalIDs)
	return portUUID, err
}

func (c *Controller) createERSPANPort(portName string, tunnelConfig *v1alpha2.ERSPANTunnel) (string, error) {
	extraOptions := make(map[string]interface{})
	extraOptions["erspan_ver"] = strconv.Itoa(int(tunnelConfig.Version))
	if tunnelConfig.SessionID != nil {
		extraOptions["key"] = strconv.Itoa(int(*tunnelConfig.SessionID))
	}
	if tunnelConfig.Version == 1 {
		if tunnelConfig.Index != nil {
			extraOptions["erspan_idx"] = strconv.FormatInt(int64(*tunnelConfig.Index), 16)
		}
	} else if tunnelConfig.Version == 2 {
		if tunnelConfig.Dir != nil {
			extraOptions["erspan_dir"] = strconv.Itoa(int(*tunnelConfig.Dir))
		}
		if tunnelConfig.HardwareID != nil {
			extraOptions["erspan_hwid"] = strconv.Itoa(int(*tunnelConfig.HardwareID))
		}
	}
	portUUID, err := c.ovsBridgeClient.CreateTunnelPortExt(portName,
		ovsconfig.ERSPANTunnel,
		0,
		false,
		"",
		tunnelConfig.RemoteIP,
		"",
		"",
		extraOptions,
		trafficControlPortExternalIDs)
	return portUUID, err
}

func (c *Controller) getPortName(port *v1alpha2.TrafficControlPort) string {
	var portName string
	switch {
	case port.OVSInternal != nil:
		portName = port.OVSInternal.Name
	case port.Device != nil:
		portName = port.Device.Name
	case port.VXLAN != nil:
		portName = genVXLANPortName(port.VXLAN)
	case port.GENEVE != nil:
		portName = genGENEVEPortName(port.GENEVE)
	case port.GRE != nil:
		portName = genGREPortName(port.GRE)
	case port.ERSPAN != nil:
		portName = genERSPANPortName(port.ERSPAN)
	}
	return portName
}

// getOrCreateTrafficControlPort ensures that there is an OVS port for the given TrafficControlPort and binds the port
// to the TrafficControl. The OVS port will be created if the port doesn't exist. It returns the ofPort of the OVS port
// on success, an error if there is.
func (c *Controller) getOrCreateTrafficControlPort(port *v1alpha2.TrafficControlPort, portName, tcName string, isReturnPort bool) (uint32, error) {
	c.ovsPortUpdateMutex.Lock()
	defer c.ovsPortUpdateMutex.Unlock()

	// Query the port binding information from portToTCBindings. If the corresponding binding information exists, indicating
	// that the port has been created, then insert the TrafficControl to the set of TrafficControls using the port.
	if binding, exists := c.portToTCBindings[portName]; exists {
		c.portToTCBindings[portName].trafficControls.Insert(tcName)
		return uint32(binding.interfaceConfig.OFPort), nil
	}

	// If there is no binding information of the port in portToTCBindings, query the interface store. If corresponding
	// config is found, create binding information for the port. Note that, this is used to rebuild portToTCBindings
	// after restarting Antrea Agent.
	if itf, ok := c.interfaceStore.GetInterfaceByName(portName); ok {
		// If the port is a return port, although the port is not newly created here, return flow should be installed for
		// the port when it is used by a TrafficControl for the first time.
		if isReturnPort {
			if err := c.ofClient.InstallTrafficControlReturnPortFlow(uint32(itf.OFPort)); err != nil {
				return 0, err
			}
		}
		c.portToTCBindings[portName] = &portToTCBinding{
			interfaceConfig: itf,
			trafficControls: sets.New[string](tcName),
		}
		return uint32(itf.OFPort), nil
	}

	var portUUID string
	var err error

	switch {
	case port.OVSInternal != nil:
		portUUID, err = c.createOVSInternalPort(portName)
	case port.Device != nil:
		portUUID, err = c.ovsBridgeClient.CreatePort(portName, portName, trafficControlPortExternalIDs)
	case port.VXLAN != nil:
		portUUID, err = c.createUDPTunnelPort(portName, ovsconfig.VXLANTunnel, port.VXLAN)
	case port.GENEVE != nil:
		portUUID, err = c.createUDPTunnelPort(portName, ovsconfig.GeneveTunnel, port.GENEVE)
	case port.GRE != nil:
		portUUID, err = c.createGREPort(portName, port.GRE)
	case port.ERSPAN != nil:
		portUUID, err = c.createERSPANPort(portName, port.ERSPAN)
	}

	if err != nil {
		return 0, err
	}

	ofPort, err := c.ovsBridgeClient.GetOFPort(portName, false)
	if err != nil {
		return 0, err
	}
	// Set the port with no-flood to reject ARP flood packets.
	if err = c.ovsCtlClient.SetPortNoFlood(int(ofPort)); err != nil {
		return 0, fmt.Errorf("failed to set port %s with no-flood config: %w", portName, err)
	}

	// If the port is a return port and is newly created, install a return flow for the port.
	if isReturnPort {
		if err = c.ofClient.InstallTrafficControlReturnPortFlow(uint32(ofPort)); err != nil {
			return 0, err
		}
	}
	itf := interfacestore.NewTrafficControlInterface(portName, &interfacestore.OVSPortConfig{PortUUID: portUUID, OFPort: ofPort})
	c.interfaceStore.AddInterface(itf)
	// Create binding for the newly created port.
	c.portToTCBindings[portName] = &portToTCBinding{
		interfaceConfig: itf,
		trafficControls: sets.New[string](tcName),
	}
	return uint32(ofPort), nil
}

// releaseTrafficControlPort releases the port from the TrafficControl and deletes the port if it is no longer used by
// any TrafficControl.
func (c *Controller) releaseTrafficControlPort(portName, tcName string, isReturnPort bool) error {
	c.ovsPortUpdateMutex.Lock()
	defer c.ovsPortUpdateMutex.Unlock()
	portBinding, exists := c.portToTCBindings[portName]
	if !exists {
		klog.InfoS("Port used by TrafficControl has been deleted", "port", portName, "TrafficControl", tcName)
		return nil
	}

	portBinding.trafficControls.Delete(tcName)
	if len(portBinding.trafficControls) == 0 {
		// If the port is no longer used by any TrafficControl, delete the port.
		if err := c.ovsBridgeClient.DeletePort(portBinding.interfaceConfig.PortUUID); err != nil {
			return err
		}
		// Uninstall corresponding return flow if the port is a return port.
		if isReturnPort {
			if err := c.ofClient.UninstallTrafficControlReturnPortFlow(uint32(portBinding.interfaceConfig.OFPort)); err != nil {
				return err
			}
		}
		c.interfaceStore.DeleteInterface(portBinding.interfaceConfig)
		delete(c.portToTCBindings, portName)
	}
	return nil
}

func (c *Controller) syncTrafficControl(tcName string) error {
	startTime := time.Now()
	defer func() {
		klog.V(2).InfoS("Finished syncing TrafficControl", "TrafficControl", tcName, "durationTime", time.Since(startTime))
	}()

	tc, err := c.trafficControlLister.Get(tcName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// If the TrafficControl is deleted and the corresponding state doesn't exist, just return.
			tcState, exists := c.getTrafficControlState(tcName)
			if !exists {
				return nil
			}
			// If a TrafficControl is deleted but the corresponding state exists, do some cleanup for the deleted
			// TrafficControl.
			if err = c.uninstallTrafficControl(tcName, tcState); err != nil {
				return err
			}
			// Delete the state of the deleted TrafficControl.
			c.deleteTrafficControlState(tcName)
			return nil
		}
		return err
	}

	// Get the TrafficControl state.
	tcState, exists := c.getTrafficControlState(tcName)
	// If the TrafficControl exists and corresponding state doesn't exist, create state for the TrafficControl.
	if !exists {
		tcState = c.newTrafficControlState(tcName, tc.Spec.Action, tc.Spec.Direction)
	}

	if tc.Spec.ReturnPort != nil {
		// Get name of the return port.
		returnPortName := c.getPortName(tc.Spec.ReturnPort)
		// If the name is different from the cached name in the TrafficControl state, it could be caused by the return
		// port update of the TrafficControl or the creation of the TrafficControl.
		if returnPortName != tcState.returnPortName {
			if tcState.returnPortName != "" {
				// If the stale return port name cached in TrafficControl state is not empty, release the stale return port
				// from the TrafficControl.
				if err = c.releaseTrafficControlPort(returnPortName, tcName, true); err != nil {
					return err
				}
			}
			// Get or create the return port.
			if _, err = c.getOrCreateTrafficControlPort(tc.Spec.ReturnPort, returnPortName, tcName, true); err != nil {
				return err
			}
			// Update return port name in state.
			tcState.returnPortName = returnPortName
		}
	}

	// Get name of the target port.
	targetPortName := c.getPortName(&tc.Spec.TargetPort)
	// If the name is different from the cached name in the TrafficControl state, it could be caused by the target port
	// update of the TrafficControl or the creation of the TrafficControl.
	if targetPortName != tcState.targetPortName {
		if tcState.targetPortName != "" {
			// If the stale target port name cached in TrafficControl state is not empty, release the stale target port
			// from the TrafficControl.
			if err = c.releaseTrafficControlPort(tcState.targetPortName, tcName, false); err != nil {
				return err
			}
		}
		// Update target port name in state.
		tcState.targetPortName = targetPortName
	}

	// Get or create the target port.
	targetOFPort, err := c.getOrCreateTrafficControlPort(&tc.Spec.TargetPort, targetPortName, tcName, false)
	if err != nil {
		return err
	}

	// Check if the mark flows should be updated.
	var needUpdateMarkFlows bool
	if tcState.targetOFPort != targetOFPort || tcState.action != tc.Spec.Action || tcState.direction != tc.Spec.Direction {
		needUpdateMarkFlows = true
	}

	// Get the list of Pods applying to the TrafficControl.
	var pods []*v1.Pod
	if pods, err = c.filterPods(&tc.Spec.AppliedTo); err != nil {
		return err
	}

	stalePods := tcState.pods.Union(nil)
	newPods := sets.New[string]()
	newOfPorts := sets.New[int32]()
	for _, pod := range pods {
		podNN := k8s.NamespacedName(pod.Namespace, pod.Name)
		newPods.Insert(podNN)
		stalePods.Delete(podNN)

		// If the TrafficControl is not the effective TrafficControl for the Pod, do nothing.
		if !c.bindPodToTrafficControl(podNN, tcName) {
			continue
		}

		// If the TrafficControl is the effective TrafficControl for the Pod, insert the port to the new set in
		// TrafficControl state.
		podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(pod.Name, pod.Namespace)
		if len(podInterfaces) == 0 {
			klog.InfoS("Interfaces of Pod not found", "Pod", klog.KObj(pod))
			continue
		}
		newOfPorts.Insert(podInterfaces[0].OFPort)
	}

	// If target ofPort / direction / action in TrafficControl is updated, the mark flows should be reinstalled; if the
	// new ofPort set is different from the old ofPort set, the mark flows should be also reinstalled.
	if needUpdateMarkFlows || !newOfPorts.Equal(tcState.ofPorts) {
		var ofPorts []uint32
		for _, port := range sets.List(newOfPorts) {
			ofPorts = append(ofPorts, uint32(port))
		}
		if err = c.ofClient.InstallTrafficControlMarkFlows(tc.Name,
			ofPorts,
			targetOFPort,
			tc.Spec.Direction,
			tc.Spec.Action,
			types.TrafficControlFlowPriorityMedium); err != nil {
			return err
		}
	}
	// Update TrafficControl state.
	tcState.pods = newPods
	tcState.ofPorts = newOfPorts
	tcState.targetOFPort = targetOFPort
	tcState.action = tc.Spec.Action
	tcState.direction = tc.Spec.Direction

	if len(stalePods) != 0 {
		// Resync the Pods applying to the TrafficControl to be deleted.
		c.podsResync(stalePods, tcName)
	}

	return nil
}

func (c *Controller) uninstallTrafficControl(tcName string, tcState *trafficControlState) error {
	// Uninstall the mark flows of the TrafficControl.
	if err := c.ofClient.UninstallTrafficControlMarkFlows(tcName); err != nil {
		return err
	}

	// Release the target port from the deleted TrafficControl.
	if tcState.targetPortName != "" {
		if err := c.releaseTrafficControlPort(tcState.targetPortName, tcName, false); err != nil {
			return err
		}
	}
	// Release the return port from the deleted TrafficControl.
	if tcState.returnPortName != "" {
		if err := c.releaseTrafficControlPort(tcState.returnPortName, tcName, true); err != nil {
			return err
		}
	}
	// Resync the Pods applying to the deleted TrafficControl.
	if len(tcState.pods) != 0 {
		c.podsResync(tcState.pods, tcName)
	}
	return nil
}

func (c *Controller) podsResync(pods sets.Set[string], tcName string) {
	// Resync the Pods that have new effective TrafficControl.
	newEffectiveTCs := sets.New[string]()
	for pod := range pods {
		if newEffectiveTC := c.unbindPodFromTrafficControl(pod, tcName); newEffectiveTC != "" {
			newEffectiveTCs.Insert(newEffectiveTC)
		}
	}
	// Trigger resyncing of the new effective TrafficControls of the Pods.
	for tc := range newEffectiveTCs {
		c.queue.Add(tc)
	}
}

// bindPodToTrafficControl binds the Pod with the TrafficControl and returns whether this TrafficControl is the effective
// one for the Pod.
func (c *Controller) bindPodToTrafficControl(pod, tc string) bool {
	c.podToTCBindingsMutex.Lock()
	defer c.podToTCBindingsMutex.Unlock()

	binding, exists := c.podToTCBindings[pod]
	if !exists {
		// Promote itself as the effective TrafficControl for the Pod if there is no binding information for the Pod.
		c.podToTCBindings[pod] = &podToTCBinding{
			effectiveTC:    tc,
			alternativeTCs: sets.New[string](),
		}
		return true
	}
	if binding.effectiveTC == tc {
		return true
	}
	if !binding.alternativeTCs.Has(tc) {
		binding.alternativeTCs.Insert(tc)
	}
	return false
}

// unbindPodFromTrafficControl unbinds the Pod with the TrafficControl. If the unbound TrafficControl was the effective
// one for the Pod and there are alternative ones, it will return the new effective TrafficControl, otherwise return empty
// string.
func (c *Controller) unbindPodFromTrafficControl(pod, tcName string) string {
	c.podToTCBindingsMutex.Lock()
	defer c.podToTCBindingsMutex.Unlock()

	// The binding must exist.
	binding := c.podToTCBindings[pod]
	if binding.effectiveTC == tcName {
		var popped bool
		// Select a new effective TrafficControl.
		binding.effectiveTC, popped = binding.alternativeTCs.PopAny()
		if !popped {
			// Remove the binding information for the Pod if there is no alternative TrafficControls.
			delete(c.podToTCBindings, pod)
			return ""
		}
		return binding.effectiveTC
	}
	binding.alternativeTCs.Delete(tcName)
	return ""
}
