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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	opsv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
	clientsetversioned "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	opsinformers "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions/ops/v1alpha1"
	opslisters "github.com/vmware-tanzu/antrea/pkg/client/listers/ops/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/features"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	"github.com/vmware-tanzu/antrea/pkg/querier"
)

type icmpType uint8
type icmpCode uint8

const (
	controllerName = "AntreaAgentTraceflowController"
	// Set resyncPeriod to 0 to disable resyncing.
	resyncPeriod time.Duration = 0
	// How long to wait before retrying the processing of a traceflow.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing traceflow request.
	defaultWorkers = 4
	// Seconds delay before injecting packet into OVS. The time of different nodes may not be completely
	// synchronized, which requires a delay before inject packet.
	injectPacketDelay = 5
	// ICMP Echo Request type and code.
	icmpEchoRequestType icmpType = 8
	icmpEchoRequestCode icmpCode = 0
)

// Controller is responsible for setting up Openflow entries and injecting traceflow packet into
// the switch for traceflow request.
type Controller struct {
	kubeClient             clientset.Interface
	serviceLister          corelisters.ServiceLister
	serviceListerSynced    cache.InformerSynced
	traceflowClient        clientsetversioned.Interface
	traceflowInformer      opsinformers.TraceflowInformer
	traceflowLister        opslisters.TraceflowLister
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
	runningTraceflows      map[uint8]string // tag->traceflowName if tf.Status.Phase is Running.
	injectedTagsMutex      sync.RWMutex
	injectedTags           map[uint8]string // tag->traceflowName if this Node is sender.
}

// NewTraceflowController instantiates a new Controller object which will process Traceflow
// events.
func NewTraceflowController(
	kubeClient clientset.Interface,
	informerFactory informers.SharedInformerFactory,
	traceflowClient clientsetversioned.Interface,
	traceflowInformer opsinformers.TraceflowInformer,
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
		runningTraceflows:     make(map[uint8]string),
		injectedTags:          make(map[uint8]string)}

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
func (c *Controller) enqueueTraceflow(tf *opsv1alpha1.Traceflow) {
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
	tf := obj.(*opsv1alpha1.Traceflow)
	klog.Infof("Processing Traceflow %s ADD event", tf.Name)
	c.enqueueTraceflow(tf)
}

func (c *Controller) updateTraceflow(_, curObj interface{}) {
	tf := curObj.(*opsv1alpha1.Traceflow)
	klog.Infof("Processing Traceflow %s UPDATE event", tf.Name)
	c.enqueueTraceflow(tf)
}

func (c *Controller) deleteTraceflow(old interface{}) {
	tf := old.(*opsv1alpha1.Traceflow)
	klog.Infof("Processing Traceflow %s DELETE event", tf.Name)
	c.deallocateTag(tf)
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
		klog.Errorf("Error syncing Traceflow %s, Aborting. Error: %v", key, err)
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
		return err
	}
	switch tf.Status.Phase {
	case opsv1alpha1.Running:
		if tf.Status.DataplaneTag != 0 {
			start := false
			c.runningTraceflowsMutex.Lock()
			if _, ok := c.runningTraceflows[tf.Status.DataplaneTag]; !ok {
				c.runningTraceflows[tf.Status.DataplaneTag] = tf.Name
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
		c.deallocateTag(tf)
	}
	return err
}

// startTraceflow deploys OVS flow entries for Traceflow and inject packet if current Node
// is Sender Node.
func (c *Controller) startTraceflow(tf *opsv1alpha1.Traceflow) error {
	err := c.validateTraceflow(tf)
	defer func() {
		if err != nil {
			c.errorTraceflowCRD(tf, fmt.Sprintf("Node: %s, error: %+v", c.nodeConfig.Name, err))
		}
	}()
	if err != nil {
		return err
	}
	// Deploy flow entries for traceflow
	klog.V(2).Infof("Deploy flow entries for Traceflow %s", tf.Name)
	err = c.ofClient.InstallTraceflowFlows(tf.Status.DataplaneTag)
	if err != nil {
		return err
	}

	// TODO: let controller compute the source Node, and the source Node can just return an error,
	//  if fails to find the Pod.
	// Inject packet if this Node is sender.
	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(tf.Spec.Source.Pod, tf.Spec.Source.Namespace)
	// Skip inject packet if Pod not found in current Node.
	if len(podInterfaces) == 0 {
		return nil
	}
	err = c.injectPacket(tf)
	return err
}

func (c *Controller) validateTraceflow(tf *opsv1alpha1.Traceflow) error {
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

func (c *Controller) injectPacket(tf *opsv1alpha1.Traceflow) error {
	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(tf.Spec.Source.Pod, tf.Spec.Source.Namespace)
	// Update Traceflow phase to Running.
	klog.V(2).Infof("Injecting packet for Traceflow %s", tf.Name)
	c.injectedTagsMutex.Lock()
	c.injectedTags[tf.Status.DataplaneTag] = tf.Name
	c.injectedTagsMutex.Unlock()

	var srcTCPPort, dstTCPPort, srcUDPPort, dstUDPPort, idICMP, sequenceICMP uint16
	var flagsTCP uint8

	// Calculate destination MAC/IP.
	dstMAC := ""
	dstIP := tf.Spec.Destination.IP
	if dstIP != "" {
		dstPodInterface, hasInterface := c.interfaceStore.GetInterfaceByIP(dstIP)
		if hasInterface {
			dstMAC = dstPodInterface.MAC.String()
		}
	} else if tf.Spec.Destination.Pod != "" {
		dstPodInterfaces := c.interfaceStore.GetContainerInterfacesByPod(tf.Spec.Destination.Pod, tf.Spec.Destination.Namespace)
		if len(dstPodInterfaces) > 0 {
			dstMAC = dstPodInterfaces[0].MAC.String()
			dstIP = dstPodInterfaces[0].GetIPv4Addr().String()
		} else {
			dstPod, err := c.kubeClient.CoreV1().Pods(tf.Spec.Destination.Namespace).Get(context.TODO(), tf.Spec.Destination.Pod, metav1.GetOptions{})
			if err != nil {
				return err
			}
			// dstMAC is "" here, will be set to Gateway MAC in ofClient.SendTraceflowPacket
			dstIP = dstPod.Status.PodIP
		}
	} else if tf.Spec.Destination.Service != "" {
		dstSvc, err := c.serviceLister.Services(tf.Spec.Destination.Namespace).Get(tf.Spec.Destination.Service)
		if err != nil {
			return err
		}
		dstIP = dstSvc.Spec.ClusterIP
		flagsTCP = 2
	}
	if dstMAC == "" {
		// If the destination is Service/IP or the packet will be sent to remote Node, wait a small period for other Nodes.
		time.Sleep(time.Duration(injectPacketDelay) * time.Second)
	}

	// Protocol is 0 (IPv6 Hop-by-Hop Option) if not set in CRD, which is not supported by Traceflow
	// Use Protocol=1 (ICMP) as default.
	if tf.Spec.Packet.IPHeader.Protocol == 0 {
		tf.Spec.Packet.IPHeader.Protocol = 1
	}

	if tf.Spec.Packet.TransportHeader.TCP != nil {
		srcTCPPort = uint16(tf.Spec.Packet.TransportHeader.TCP.SrcPort)
		dstTCPPort = uint16(tf.Spec.Packet.TransportHeader.TCP.DstPort)
		if tf.Spec.Packet.TransportHeader.TCP.Flags != 0 {
			flagsTCP = uint8(tf.Spec.Packet.TransportHeader.TCP.Flags)
		}
	}
	if tf.Spec.Packet.TransportHeader.UDP != nil {
		srcUDPPort = uint16(tf.Spec.Packet.TransportHeader.UDP.SrcPort)
		dstUDPPort = uint16(tf.Spec.Packet.TransportHeader.UDP.DstPort)
	}
	if tf.Spec.Packet.TransportHeader.ICMP != nil {
		idICMP = uint16(tf.Spec.Packet.TransportHeader.ICMP.ID)
		sequenceICMP = uint16(tf.Spec.Packet.TransportHeader.ICMP.Sequence)
	}
	return c.ofClient.SendTraceflowPacket(
		tf.Status.DataplaneTag,
		podInterfaces[0].MAC.String(),
		dstMAC,
		podInterfaces[0].GetIPv4Addr().String(),
		dstIP,
		uint8(tf.Spec.Packet.IPHeader.Protocol),
		uint8(tf.Spec.Packet.IPHeader.TTL),
		uint16(tf.Spec.Packet.IPHeader.Flags),
		srcTCPPort,
		dstTCPPort,
		flagsTCP,
		srcUDPPort,
		dstUDPPort,
		uint8(icmpEchoRequestType),
		uint8(icmpEchoRequestCode),
		idICMP,
		sequenceICMP,
		uint32(podInterfaces[0].OFPort),
		-1)
}

func (c *Controller) errorTraceflowCRD(tf *opsv1alpha1.Traceflow, reason string) (*opsv1alpha1.Traceflow, error) {
	tf.Status.Phase = opsv1alpha1.Failed

	type Traceflow struct {
		Status opsv1alpha1.TraceflowStatus `json:"status,omitempty"`
	}
	patchData := Traceflow{Status: opsv1alpha1.TraceflowStatus{Phase: tf.Status.Phase, Reason: reason}}
	payloads, _ := json.Marshal(patchData)
	return c.traceflowClient.OpsV1alpha1().Traceflows().Patch(context.TODO(), tf.Name, types.MergePatchType, payloads, metav1.PatchOptions{}, "status")
}

// Deallocate tag from cache.
func (c *Controller) deallocateTag(tf *opsv1alpha1.Traceflow) {
	dataplaneTag := uint8(0)
	c.runningTraceflowsMutex.Lock()
	// Controller could have deallocated the tag and cleared the DataplaneTag
	// field in the Traceflow Status, so try looking up the tag from the
	// cache by Traceflow name.
	for tag, existingTraceflowName := range c.runningTraceflows {
		if tf.Name == existingTraceflowName {
			delete(c.runningTraceflows, tag)
			dataplaneTag = tag
			break
		}
	}
	c.runningTraceflowsMutex.Unlock()
	if dataplaneTag == 0 {
		return
	}
	c.injectedTagsMutex.Lock()
	if existingTraceflowName, ok := c.injectedTags[dataplaneTag]; ok {
		if tf.Name == existingTraceflowName {
			delete(c.injectedTags, dataplaneTag)
		} else {
			klog.Warningf("runningTraceflows cache mismatch tag: %d name: %s existingName: %s",
				dataplaneTag, tf.Name, existingTraceflowName)
		}
	}
	c.injectedTagsMutex.Unlock()
}

func (c *Controller) isSender(tag uint8) bool {
	c.injectedTagsMutex.RLock()
	defer c.injectedTagsMutex.RUnlock()
	if _, ok := c.injectedTags[tag]; ok {
		return true
	}
	return false
}

// getTraceflowCRD gets traceflow CRD by data plane tag.
func (c *Controller) GetRunningTraceflowCRD(tag uint8) (*opsv1alpha1.Traceflow, error) {
	c.runningTraceflowsMutex.RLock()
	defer c.runningTraceflowsMutex.RUnlock()
	if traceflowName, ok := c.runningTraceflows[tag]; ok {
		return c.traceflowLister.Get(traceflowName)
	}
	return nil, errors.New(fmt.Sprintf("traceflow with the data plane tag %d doesn't exist", tag))
}
