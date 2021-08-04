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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/contiv/libOpenflow/protocol"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/util"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	clientsetversioned "antrea.io/antrea/pkg/client/clientset/versioned"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	"antrea.io/antrea/pkg/features"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/querier"
)

const (
	controllerName = "AntreaAgentTraceflowController"
	// Set resyncPeriod to 0 to disable resyncing.
	resyncPeriod time.Duration = 0
	// How long to wait before retrying the processing of a traceflow.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing traceflow request.
	defaultWorkers = 4
	// Delay in milliseconds before injecting packet into OVS. The time of different nodes may not be completely
	// synchronized, which requires a delay before inject packet.
	injectPacketDelay      = 2000
	injectLocalPacketDelay = 100

	// ICMP Echo Request type and code.
	icmpEchoRequestType   uint8 = 8
	icmpv6EchoRequestType uint8 = 128
	icmpEchoRequestCode   uint8 = 0

	defaultTTL uint8 = 64
)

type traceflowState struct {
	name        string
	tag         uint8
	liveTraffic bool
	droppedOnly bool
	// Live-traffic Traceflow with only destination Pod specified.
	receiverOnly bool
	isSender     bool
	// Agent received the first Traceflow packet from OVS.
	receivedPacket bool
}

// Controller is responsible for setting up Openflow entries and injecting traceflow packet into
// the switch for traceflow request.
type Controller struct {
	kubeClient             clientset.Interface
	serviceLister          corelisters.ServiceLister
	serviceListerSynced    cache.InformerSynced
	traceflowClient        clientsetversioned.Interface
	traceflowInformer      crdinformers.TraceflowInformer
	traceflowLister        crdlisters.TraceflowLister
	traceflowListerSynced  cache.InformerSynced
	ovsBridgeClient        ovsconfig.OVSBridgeClient
	ofClient               openflow.Client
	networkPolicyQuerier   querier.AgentNetworkPolicyInfoQuerier
	interfaceStore         interfacestore.InterfaceStore
	networkConfig          *config.NetworkConfig
	nodeConfig             *config.NodeConfig
	serviceCIDR            *net.IPNet // K8s Service ClusterIP CIDR
	queue                  workqueue.RateLimitingInterface
	runningTraceflowsMutex sync.RWMutex
	// runningTraceflows is a map for storing the running Traceflow state
	// with dataplane tag to be the key.
	runningTraceflows map[uint8]*traceflowState
}

// NewTraceflowController instantiates a new Controller object which will process Traceflow
// events.
func NewTraceflowController(
	kubeClient clientset.Interface,
	informerFactory informers.SharedInformerFactory,
	traceflowClient clientsetversioned.Interface,
	traceflowInformer crdinformers.TraceflowInformer,
	client openflow.Client,
	npQuerier querier.AgentNetworkPolicyInfoQuerier,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	interfaceStore interfacestore.InterfaceStore,
	networkConfig *config.NetworkConfig,
	nodeConfig *config.NodeConfig,
	serviceCIDR *net.IPNet) *Controller {
	c := &Controller{
		kubeClient:            kubeClient,
		traceflowClient:       traceflowClient,
		traceflowInformer:     traceflowInformer,
		traceflowLister:       traceflowInformer.Lister(),
		traceflowListerSynced: traceflowInformer.Informer().HasSynced,
		ovsBridgeClient:       ovsBridgeClient,
		ofClient:              client,
		networkPolicyQuerier:  npQuerier,
		interfaceStore:        interfaceStore,
		networkConfig:         networkConfig,
		nodeConfig:            nodeConfig,
		serviceCIDR:           serviceCIDR,
		queue:                 workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "traceflow"),
		runningTraceflows:     make(map[uint8]*traceflowState),
	}

	// Add handlers for Traceflow events.
	traceflowInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addTraceflow,
			UpdateFunc: c.updateTraceflow,
			DeleteFunc: c.deleteTraceflow,
		},
		resyncPeriod,
	)
	// Register packetInHandler
	c.ofClient.RegisterPacketInHandler(uint8(openflow.PacketInReasonTF), "traceflow", c)
	// Add serviceLister if AntreaProxy enabled
	if features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		c.serviceLister = informerFactory.Core().V1().Services().Lister()
		c.serviceListerSynced = informerFactory.Core().V1().Services().Informer().HasSynced
	}
	return c
}

// enqueueTraceflow adds an object to the controller work queue.
func (c *Controller) enqueueTraceflow(tf *crdv1alpha1.Traceflow) {
	c.queue.Add(tf.Name)
}

// Run will create defaultWorkers workers (go routines) which will process the Traceflow events from the
// workqueue.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	cacheSyncs := []cache.InformerSynced{c.traceflowListerSynced}
	if features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		cacheSyncs = append(cacheSyncs, c.serviceListerSynced)
	}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSyncs...) {
		return
	}

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
	c.enqueueTraceflow(tf)
}

// worker is a long-running function that will continually call the processTraceflowItem function
// in order to read and process a message on the workqueue.
func (c *Controller) worker() {
	for c.processTraceflowItem() {
	}
}

// processTraceflowItem processes an item in the "traceflow" work queue, by calling syncTraceflow
// after casting the item to a string (Traceflow name). If syncTraceflow returns an error, this
// function logs error. If syncTraceflow is successful, the Traceflow is removed from the queue
// until we get notified of a new change. This function returns false if and only if the work queue
// was shutdown (no more items will be processed).
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
	} else if err := c.syncTraceflow(key); err == nil {
		// If no error occurs we Forget this item so it does not get queued again.
		c.queue.Forget(key)
	} else {
		// If error occurs we log error.
		klog.Errorf("Error syncing Traceflow %s, exiting. Error: %v", key, err)
	}
	return true
}

// TODO: Let controller compute which Node is the sender, and each Node watch the TF CRD with some
//  filter to get and process only TF from the Node.
// syncTraceflow gets Traceflow CRD by name, update cache and start syncing.
func (c *Controller) syncTraceflow(traceflowName string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing Traceflow for %s. (%v)", traceflowName, time.Since(startTime))
	}()

	tf, err := c.traceflowLister.Get(traceflowName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			c.cleanupTraceflow(traceflowName)
			return nil
		}
		return err
	}

	switch tf.Status.Phase {
	case crdv1alpha1.Running:
		if tf.Status.DataplaneTag != 0 {
			start := false
			c.runningTraceflowsMutex.Lock()
			if _, ok := c.runningTraceflows[tf.Status.DataplaneTag]; !ok {
				start = true
			}
			c.runningTraceflowsMutex.Unlock()
			if start {
				err = c.startTraceflow(tf)
			}
		} else {
			klog.Warningf("Invalid data plane tag %d for Traceflow %s", tf.Status.DataplaneTag, tf.Name)
		}
	default:
		c.cleanupTraceflow(traceflowName)
	}
	return err
}

// startTraceflow deploys OVS flow entries for Traceflow and inject packet if current Node
// is Sender Node.
func (c *Controller) startTraceflow(tf *crdv1alpha1.Traceflow) error {
	err := c.validateTraceflow(tf)
	defer func() {
		if err != nil {
			c.cleanupTraceflow(tf.Name)
			c.errorTraceflowCRD(tf, fmt.Sprintf("Node: %s, error: %+v", c.nodeConfig.Name, err))
		}
	}()
	if err != nil {
		return err
	}

	liveTraffic := tf.Spec.LiveTraffic
	if tf.Spec.Source.Pod == "" && tf.Spec.Destination.Pod == "" {
		klog.Errorf("Traceflow %s has neither source nor destination Pod specified", tf.Name)
		return nil
	}
	if tf.Spec.Source.Pod == "" && !liveTraffic {
		klog.Errorf("Traceflow %s does not have source Pod specified", tf.Name)
		return nil
	}

	receiverOnly := false
	var pod, ns string
	if tf.Spec.Source.Pod != "" {
		pod = tf.Spec.Source.Pod
		ns = tf.Spec.Source.Namespace
	} else {
		// Live-traffic Traceflow with only the Destination Pod specified.
		pod = tf.Spec.Destination.Pod
		ns = tf.Spec.Destination.Namespace
		receiverOnly = true
	}

	// TODO: let controller compute the sender/receiver Node, and the sender
	// /receiver Node can just return an error, if fails to find the Pod.
	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(pod, ns)
	isSender := len(podInterfaces) > 0 && !receiverOnly

	var packet, matchPacket *binding.Packet
	var ofPort uint32
	if len(podInterfaces) > 0 {
		packet, err = c.preparePacket(tf, podInterfaces[0], receiverOnly)
		if err != nil {
			return err
		}
		ofPort = uint32(podInterfaces[0].OFPort)
		// On the sender or receiver (the receiverOnly case) Node, trace
		// the first packet of the first connection that matches the
		// Traceflow spec.
		if liveTraffic {
			matchPacket = packet
		}
		klog.V(2).Infof("Traceflow packet %v", *packet)
	}

	// Store Traceflow to cache.
	c.runningTraceflowsMutex.Lock()
	tfState := traceflowState{
		name: tf.Name, tag: tf.Status.DataplaneTag,
		liveTraffic: liveTraffic, droppedOnly: tf.Spec.DroppedOnly && liveTraffic,
		receiverOnly: receiverOnly, isSender: isSender}
	c.runningTraceflows[tfState.tag] = &tfState
	c.runningTraceflowsMutex.Unlock()

	// Install flow entries for traceflow.
	klog.V(2).Infof("Installing flow entries for Traceflow %s", tf.Name)
	timeout := tf.Spec.Timeout
	if timeout == 0 {
		timeout = crdv1alpha1.DefaultTraceflowTimeout
	}
	err = c.ofClient.InstallTraceflowFlows(tfState.tag, liveTraffic, tfState.droppedOnly, receiverOnly, matchPacket, ofPort, timeout)
	if err != nil {
		return err
	}

	// Skip packet injection if the source Pod is not found on the local Node.
	if !liveTraffic && isSender {
		if packet.DestinationMAC == nil {
			// If the destination is Service/IP or the packet will
			// be sent to remote Node, wait a small period for other
			// Nodes.
			time.Sleep(time.Duration(injectPacketDelay) * time.Millisecond)
		} else {
			// Issue #2116
			// Wait a small period after flows installed to avoid unexpected behavior.
			time.Sleep(time.Duration(injectLocalPacketDelay) * time.Millisecond)
		}
		klog.V(2).Infof("Injecting packet for Traceflow %s", tf.Name)
		err = c.ofClient.SendTraceflowPacket(tfState.tag, packet, ofPort, -1)
	}
	return err
}

func (c *Controller) validateTraceflow(tf *crdv1alpha1.Traceflow) error {
	if tf.Spec.Destination.Service != "" && !features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		return errors.New("using Service destination requires AntreaProxy feature enabled")
	}
	if tf.Spec.Destination.IP != "" {
		destIP := net.ParseIP(tf.Spec.Destination.IP)
		if destIP == nil {
			return fmt.Errorf("destination IP is not valid: %s", tf.Spec.Destination.IP)
		}
		// When AntreaProxy is enabled, serviceCIDR is not required and may be set to a
		// default value which does not match the cluster configuration.
		if !features.DefaultFeatureGate.Enabled(features.AntreaProxy) && c.serviceCIDR.Contains(destIP) {
			return errors.New("using ClusterIP destination requires AntreaProxy feature enabled")
		}
	}
	return nil
}

func (c *Controller) preparePacket(tf *crdv1alpha1.Traceflow, intf *interfacestore.InterfaceConfig, receiverOnly bool) (*binding.Packet, error) {
	liveTraffic := tf.Spec.LiveTraffic
	isICMP := false
	packet := new(binding.Packet)
	packet.IsIPv6 = tf.Spec.Packet.IPv6Header != nil
	if !liveTraffic {
		if packet.IsIPv6 {
			packet.SourceIP = intf.GetIPv6Addr()
			if packet.SourceIP == nil {
				return nil, errors.New("source Pod does not have an IPv6 address")
			}
		} else {
			packet.SourceIP = intf.GetIPv4Addr()
			if packet.SourceIP == nil {
				return nil, errors.New("source Pod does not have an IPv4 address")
			}
		}
		packet.SourceMAC = intf.MAC
	}

	if receiverOnly {
		if tf.Spec.Source.IP != "" {
			packet.SourceIP = net.ParseIP(tf.Spec.Source.IP)
			isIPv6 := packet.SourceIP.To4() == nil
			if isIPv6 != packet.IsIPv6 {
				return nil, errors.New("source IP does not match the IP header family")
			}
		}
		// The packet will be matched with the Pod MAC.
		packet.DestinationMAC = intf.MAC
	} else if tf.Spec.Destination.IP != "" {
		packet.DestinationIP = net.ParseIP(tf.Spec.Destination.IP)
		if packet.DestinationIP == nil {
			return nil, errors.New("invalid destination IP address")
		}
		isIPv6 := packet.DestinationIP.To4() == nil
		if isIPv6 != packet.IsIPv6 {
			return nil, errors.New("destination IP does not match the IP header family")
		}
		if !liveTraffic {
			dstPodInterface, hasInterface := c.interfaceStore.GetInterfaceByIP(tf.Spec.Destination.IP)
			if hasInterface {
				packet.DestinationMAC = dstPodInterface.MAC
			}
		}
	} else if tf.Spec.Destination.Pod != "" {
		dstPodInterfaces := c.interfaceStore.GetContainerInterfacesByPod(tf.Spec.Destination.Pod, tf.Spec.Destination.Namespace)
		if len(dstPodInterfaces) > 0 {
			if packet.IsIPv6 {
				packet.DestinationIP = dstPodInterfaces[0].GetIPv6Addr()
			} else {
				packet.DestinationIP = dstPodInterfaces[0].GetIPv4Addr()
			}
			if !liveTraffic {
				packet.DestinationMAC = dstPodInterfaces[0].MAC
			}
		} else {
			dstPod, err := c.kubeClient.CoreV1().Pods(tf.Spec.Destination.Namespace).Get(context.TODO(), tf.Spec.Destination.Pod, metav1.GetOptions{})
			if err != nil {
				return nil, fmt.Errorf("failed to get the destination Pod: %v", err)
			}
			// DestinationMAC is nil here, will be set to gateway
			// MAC in ofClient.SendTraceflowPacket()
			podIPs := make([]net.IP, len(dstPod.Status.PodIPs))
			for i, ip := range dstPod.Status.PodIPs {
				podIPs[i] = net.ParseIP(ip.IP)
			}
			if packet.IsIPv6 {
				packet.DestinationIP, _ = util.GetIPWithFamily(podIPs, util.FamilyIPv6)
			} else {
				packet.DestinationIP = util.GetIPv4Addr(podIPs)
			}
		}
		if packet.DestinationIP == nil {
			if packet.IsIPv6 {
				return nil, errors.New("destination Pod does not have an IPv6 address")
			}
			return nil, errors.New("destination Pod does not have an IPv4 address")
		}
	} else if tf.Spec.Destination.Service != "" {
		dstSvc, err := c.serviceLister.Services(tf.Spec.Destination.Namespace).Get(tf.Spec.Destination.Service)
		if err != nil {
			return nil, fmt.Errorf("failed to get the destination Service: %v", err)
		}
		if dstSvc.Spec.ClusterIP == "" {
			return nil, errors.New("destination Service does not have a ClusterIP")
		}
		packet.DestinationIP = net.ParseIP(dstSvc.Spec.ClusterIP)
		if !packet.IsIPv6 {
			packet.DestinationIP = packet.DestinationIP.To4()
			if packet.DestinationIP == nil {
				return nil, errors.New("destination Service does not have an IPv4 ClusterIP")
			}
		} else if packet.DestinationIP.To4() != nil {
			return nil, errors.New("destination Service does not have an IPv6 ClusterIP")
		}

		if !liveTraffic {
			// Set the SYN flag. In encap mode, the SYN flag is only required for
			// Service traffic, but probably we should always set it.
			packet.TCPFlags = 2
		}
	} else if !liveTraffic {
		return nil, errors.New("destination is not specified")
	}

	if tf.Spec.Packet.IPv6Header != nil {
		// IP Protocol 0 (IPv6 Hop-by-Hop Option) is not supported by
		// Traceflow. If NextHeader is not provided, protocol ICMPv6
		// will be used as the default.
		if tf.Spec.Packet.IPv6Header.NextHeader != nil {
			packet.IPProto = uint8(*tf.Spec.Packet.IPv6Header.NextHeader)
		}
		if !liveTraffic {
			packet.TTL = uint8(tf.Spec.Packet.IPv6Header.HopLimit)
			packet.IPFlags = 0
		}
	} else {
		packet.IPProto = uint8(tf.Spec.Packet.IPHeader.Protocol)
		if !liveTraffic {
			packet.TTL = uint8(tf.Spec.Packet.IPHeader.TTL)
			packet.IPFlags = uint16(tf.Spec.Packet.IPHeader.Flags)
		}
	}
	if !liveTraffic && packet.TTL == 0 {
		packet.TTL = defaultTTL
	}

	// TCP > UDP > ICMP > other IP protocol.
	if tf.Spec.Packet.TransportHeader.TCP != nil {
		packet.IPProto = protocol.Type_TCP
		packet.SourcePort = uint16(tf.Spec.Packet.TransportHeader.TCP.SrcPort)
		packet.DestinationPort = uint16(tf.Spec.Packet.TransportHeader.TCP.DstPort)
		if tf.Spec.Packet.TransportHeader.TCP.Flags != 0 {
			packet.TCPFlags = uint8(tf.Spec.Packet.TransportHeader.TCP.Flags)
		}
	} else if tf.Spec.Packet.TransportHeader.UDP != nil {
		packet.IPProto = protocol.Type_UDP
		packet.SourcePort = uint16(tf.Spec.Packet.TransportHeader.UDP.SrcPort)
		packet.DestinationPort = uint16(tf.Spec.Packet.TransportHeader.UDP.DstPort)
	} else if tf.Spec.Packet.TransportHeader.ICMP != nil {
		isICMP = true
		if !liveTraffic {
			packet.ICMPEchoID = uint16(tf.Spec.Packet.TransportHeader.ICMP.ID)
			packet.ICMPEchoSeq = uint16(tf.Spec.Packet.TransportHeader.ICMP.Sequence)
		}
	}

	// Defaults to ICMP if not live-traffic Traceflow.
	if packet.IPProto == 0 && !liveTraffic || packet.IPProto == protocol.Type_ICMP || packet.IPProto == protocol.Type_IPv6ICMP {
		isICMP = true
	}
	if isICMP {
		if packet.IsIPv6 {
			packet.IPProto = protocol.Type_IPv6ICMP
			if !liveTraffic {
				packet.ICMPType = icmpv6EchoRequestType
			}
		} else {
			packet.IPProto = protocol.Type_ICMP
			if !liveTraffic {
				packet.ICMPType = icmpEchoRequestType
			}
		}
		if !liveTraffic {
			packet.ICMPCode = icmpEchoRequestCode
		}
	}

	return packet, nil
}

func (c *Controller) errorTraceflowCRD(tf *crdv1alpha1.Traceflow, reason string) (*crdv1alpha1.Traceflow, error) {
	tf.Status.Phase = crdv1alpha1.Failed

	type Traceflow struct {
		Status crdv1alpha1.TraceflowStatus `json:"status,omitempty"`
	}
	patchData := Traceflow{Status: crdv1alpha1.TraceflowStatus{Phase: tf.Status.Phase, Reason: reason}}
	payloads, _ := json.Marshal(patchData)
	return c.traceflowClient.CrdV1alpha1().Traceflows().Patch(context.TODO(), tf.Name, types.MergePatchType, payloads, metav1.PatchOptions{}, "status")
}

// Delete Traceflow from cache.
func (c *Controller) deleteTraceflowState(tfName string) *traceflowState {
	c.runningTraceflowsMutex.Lock()
	defer c.runningTraceflowsMutex.Unlock()
	// Controller could have deallocated the tag and cleared the DataplaneTag
	// field in the Traceflow Status, so try looking up the tag from the
	// cache by Traceflow name.
	for tag, tfState := range c.runningTraceflows {
		if tfName == tfState.name {
			delete(c.runningTraceflows, tag)
			return tfState
		}
	}
	return nil
}

// Delete Traceflow state and OVS flows.
func (c *Controller) cleanupTraceflow(tfName string) {
	tfState := c.deleteTraceflowState(tfName)
	if tfState != nil {
		err := c.ofClient.UninstallTraceflowFlows(tfState.tag)
		if err != nil {
			klog.Errorf("Failed to uninstall Traceflow %s flows: %v", tfName, err)
		}
	}
}
