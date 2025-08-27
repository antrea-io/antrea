// Copyright 2025 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package flowexporter

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/controller/noderoute"
	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/filter"
	"antrea.io/antrea/pkg/agent/flowexporter/options"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/agent/proxy"
	api "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/client/informers/externalversions/crd/v1beta1"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/objectstore"
)

// When initializing flowExporter, a slice is allocated with a fixed size to
// store expired connections. The advantage is every time we export, the connection
// store lock will only be held for a bounded time. The disadvantages are: 1. the
// constant is independent of actual number of expired connections 2. when the
// number of expired connections goes over the constant, the export can not be
// finished in a single round. It could be delayed by conntrack connections polling
// routine, which also acquires the connection store lock. The possible solution
// can be taking a fraction of the size of connection store to approximate the
// number of expired connections, while having a min and a max to handle edge cases,
// e.g. min(50 + 0.1 * connectionStore.size(), 200)
const maxConnsToExport = 64

type FlowExporter struct {
	conntrackConnStore  *connections.ConntrackConnectionStore
	denyConnStore       *connections.DenyConnectionStore
	numConnsExported    uint64 // used for unit tests.
	v4Enabled           bool
	v6Enabled           bool
	k8sClient           kubernetes.Interface
	nodeRouteController *noderoute.Controller
	isNetworkPolicyOnly bool
	expiredConns        []connection.Connection
	egressQuerier       querier.EgressQuerier
	podStore            objectstore.PodStore
	l7Listener          *connections.L7Listener
	nodeName            string
	obsDomainID         uint32
	nodeUID             string

	targetInformer v1beta1.FlowExporterTargetInformer

	consumerMutex sync.RWMutex
	consumers     map[string]chan struct{} // Consumers are added and removed dynamically.
}

func NewFlowExporter(podStore objectstore.PodStore, proxier proxy.Proxier, k8sClient kubernetes.Interface, nodeRouteController *noderoute.Controller,
	trafficEncapMode config.TrafficEncapModeType, nodeConfig *config.NodeConfig, v4Enabled, v6Enabled bool, serviceCIDRNet, serviceCIDRNetv6 *net.IPNet,
	ovsDatapathType ovsconfig.OVSDatapathType, proxyEnabled bool, npQuerier querier.AgentNetworkPolicyInfoQuerier, o *options.FlowExporterOptions,
	egressQuerier querier.EgressQuerier, podL7FlowExporterAttrGetter connections.PodL7FlowExporterAttrGetter, l7FlowExporterEnabled bool) (*FlowExporter, error) {

	return NewFlowExporterWithInformer(podStore, proxier, k8sClient, nodeRouteController,
		trafficEncapMode, nodeConfig, v4Enabled, v6Enabled, serviceCIDRNet, serviceCIDRNetv6,
		ovsDatapathType, proxyEnabled, npQuerier, o,
		egressQuerier, podL7FlowExporterAttrGetter, l7FlowExporterEnabled, nil)
}

func NewFlowExporterWithInformer(podStore objectstore.PodStore, proxier proxy.Proxier, k8sClient kubernetes.Interface, nodeRouteController *noderoute.Controller,
	trafficEncapMode config.TrafficEncapModeType, nodeConfig *config.NodeConfig, v4Enabled, v6Enabled bool, serviceCIDRNet, serviceCIDRNetv6 *net.IPNet,
	ovsDatapathType ovsconfig.OVSDatapathType, proxyEnabled bool, npQuerier querier.AgentNetworkPolicyInfoQuerier, o *options.FlowExporterOptions,
	egressQuerier querier.EgressQuerier, podL7FlowExporterAttrGetter connections.PodL7FlowExporterAttrGetter, l7FlowExporterEnabled bool, targetInformer v1beta1.FlowExporterTargetInformer) (*FlowExporter, error) {

	protocolFilter := filter.NewProtocolFilter(o.ProtocolFilter)
	connTrackDumper := connections.InitializeConnTrackDumper(nodeConfig, serviceCIDRNet, serviceCIDRNetv6, ovsDatapathType, proxyEnabled, protocolFilter)
	denyConnStore := connections.NewDenyConnectionStore(podStore, proxier, o, protocolFilter)
	var l7Listener *connections.L7Listener
	var eventMapGetter connections.L7EventMapGetter
	if l7FlowExporterEnabled {
		l7Listener = connections.NewL7Listener(podL7FlowExporterAttrGetter, podStore)
		eventMapGetter = l7Listener
	}
	conntrackConnStore := connections.NewConntrackConnectionStore(connTrackDumper, v4Enabled, v6Enabled, npQuerier, podStore, proxier, eventMapGetter, o)
	if nodeRouteController == nil {
		klog.InfoS("NodeRouteController is nil, will not be able to determine flow type for connections")
	}

	nodeName, err := env.GetNodeName()
	if err != nil {
		return nil, err
	}
	obsDomainID := genObservationID(nodeName)

	klog.InfoS("Retrieving this Node's UID from K8s", "nodeName", nodeName)
	node, err := k8sClient.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get Node with name %s from K8s: %w", nodeName, err)
	}
	nodeUID := string(node.UID)
	klog.InfoS("Retrieved this Node's UID from K8s", "nodeName", nodeName, "nodeUID", nodeUID)

	fe := &FlowExporter{
		conntrackConnStore:  conntrackConnStore,
		denyConnStore:       denyConnStore,
		v4Enabled:           v4Enabled,
		v6Enabled:           v6Enabled,
		k8sClient:           k8sClient,
		nodeRouteController: nodeRouteController,
		isNetworkPolicyOnly: trafficEncapMode.IsNetworkPolicyOnly(),
		expiredConns:        make([]connection.Connection, 0, maxConnsToExport*2),
		egressQuerier:       egressQuerier,
		podStore:            podStore,
		l7Listener:          l7Listener,
		nodeName:            nodeName,
		obsDomainID:         obsDomainID,
		nodeUID:             nodeUID,
		targetInformer:      targetInformer,
		consumers:           make(map[string]chan struct{}),
	}

	// TODO: Should this be moved to `Run`?
	targetInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    fe.onNewTarget,
		UpdateFunc: fe.onTargetUpdate,
		DeleteFunc: fe.onTargetDelete,
	})

	return fe, nil
}

func genObservationID(nodeName string) uint32 {
	h := fnv.New32()
	h.Write([]byte(nodeName))
	return h.Sum32()
}

func (exp *FlowExporter) GetDenyConnStore() *connections.DenyConnectionStore {
	return exp.denyConnStore
}

func (exp *FlowExporter) Run(stopCh <-chan struct{}) {
	// Start L7 connection flow socket
	if features.DefaultFeatureGate.Enabled(features.L7FlowExporter) {
		go exp.l7Listener.Run(stopCh)
	}
	// Start the goroutine to periodically delete stale deny connections.
	go exp.denyConnStore.RunPeriodicDeletion(stopCh)

	// Start the goroutine to poll conntrack flows.
	go exp.conntrackConnStore.Run(stopCh)

	if exp.nodeRouteController != nil {
		// Wait for NodeRouteController to have processed the initial list of Nodes so that
		// the list of Pod subnets is up-to-date.
		if !cache.WaitForCacheSync(stopCh, exp.nodeRouteController.HasSynced) {
			return
		}
	}

	cacheSyncs := []cache.InformerSynced{exp.targetInformer.Informer().HasSynced}
	if !cache.WaitForNamedCacheSync("FlowExporter", stopCh, cacheSyncs...) {
		return
	}

	<-stopCh

	exp.consumerMutex.RLock()
	defer exp.consumerMutex.RUnlock()
	// We want to stop all the consumers
	for _, ch := range exp.consumers {
		close(ch)
	}
}

func (exp *FlowExporter) findFlowType(conn connection.Connection) uint8 {
	// TODO: support Pod-To-External flows in network policy only mode.
	if exp.isNetworkPolicyOnly {
		if conn.SourcePodName == "" || conn.DestinationPodName == "" {
			return utils.FlowTypeInterNode
		}
		return utils.FlowTypeIntraNode
	}

	if exp.nodeRouteController == nil {
		klog.V(5).InfoS("Can't find flow type without nodeRouteController")
		return utils.FlowTypeUnspecified
	}
	srcIsPod, srcIsGw := exp.nodeRouteController.LookupIPInPodSubnets(conn.FlowKey.SourceAddress)
	dstIsPod, dstIsGw := exp.nodeRouteController.LookupIPInPodSubnets(conn.FlowKey.DestinationAddress)
	if srcIsGw || dstIsGw {
		// This matches what we do in filterAntreaConns but is more general as we consider
		// remote gateways as well.
		klog.V(5).InfoS("Flows where the source or destination IP is a gateway IP will not be exported")
		return utils.FlowTypeUnsupported
	}
	if !srcIsPod {
		klog.V(5).InfoS("Flows where the source is not a Pod will not be exported")
		return utils.FlowTypeUnsupported
	}
	if !dstIsPod {
		return utils.FlowTypeToExternal
	}
	if conn.SourcePodName == "" || conn.DestinationPodName == "" {
		return utils.FlowTypeInterNode
	}
	return utils.FlowTypeIntraNode
}

func (exp *FlowExporter) fillEgressInfo(conn *connection.Connection) {
	egress, err := exp.egressQuerier.GetEgress(conn.SourcePodNamespace, conn.SourcePodName)
	if err != nil {
		// Egress is not enabled or no Egress is applied to this Pod
		return
	}
	conn.EgressName = egress.Name
	conn.EgressUID = string(egress.UID)
	conn.EgressIP = egress.EgressIP
	conn.EgressNodeName = egress.EgressNode
	klog.V(5).InfoS("Filling Egress Info for flow", "Egress", conn.EgressName, "EgressIP", conn.EgressIP, "EgressNode", conn.EgressNodeName, "SourcePod", klog.KRef(conn.SourcePodNamespace, conn.SourcePodName))
}

func getMinTime(t1, t2 time.Duration) time.Duration {
	if t1 <= t2 {
		return t1
	}
	return t2
}

func (fe *FlowExporter) onNewTarget(obj interface{}) {
	targetRes := obj.(*api.FlowExporterTarget)
	klog.V(5).InfoS("DEBUG: Received new FlowExporterTarget", "resource", klog.KObj(targetRes))

	fe.addConsumer(targetRes)
}

func (fe *FlowExporter) onTargetUpdate(oldObj interface{}, newObj interface{}) {
	targetRes := newObj.(*api.FlowExporterTarget)
	oldTargetRes := newObj.(*api.FlowExporterTarget)
	klog.V(5).InfoS("DEBUG: FlowExporterTarget updated", "old", klog.KObj(oldTargetRes), "new", klog.KObj(targetRes))

	fe.deleteConsumer(oldTargetRes)
	fe.addConsumer(targetRes)
}

func (fe *FlowExporter) onTargetDelete(obj interface{}) {
	var targetRes *api.FlowExporterTarget
	switch o := obj.(type) {
	case cache.DeletedFinalStateUnknown:
		targetRes = o.Obj.(*api.FlowExporterTarget)
	default:
		targetRes = obj.(*api.FlowExporterTarget)
	}

	klog.V(5).InfoS("DEBUG: FlowExporterTarget deleted", "resource", klog.KObj(targetRes))

	fe.deleteConsumer(targetRes)
}

func (fe *FlowExporter) addConsumer(targetRes *api.FlowExporterTarget) error {
	fe.consumerMutex.Lock()
	defer fe.consumerMutex.Unlock()

	key := consumerID(targetRes)
	if _, ok := fe.consumers[key]; ok {
		// Consumer already exist. Report a warning and update/reset it.
		return nil
	}

	consumer := fe.createConsumerFromFlowExporterTarget(targetRes)
	stopCh := make(chan struct{})
	go consumer.Run(stopCh)
	fe.consumers[key] = stopCh

	return nil
}

func (fe *FlowExporter) deleteConsumer(targetRes *api.FlowExporterTarget) error {
	fe.consumerMutex.Lock()
	defer fe.consumerMutex.Unlock()

	key := consumerID(targetRes)
	ch, ok := fe.consumers[key]
	if !ok {
		// Consumer never existing, how did that happen?
		klog.InfoS("consumer not found", "id", key)
		return nil
	}
	close(ch)
	delete(fe.consumers, key)

	return nil
}

func consumerID(target *api.FlowExporterTarget) string {
	return fmt.Sprintf("%s", target.Name)
}

func (fe *FlowExporter) createConsumerFromFlowExporterTarget(target *api.FlowExporterTarget) *Consumer {
	activeFlowExportTimeout, err := time.ParseDuration(ptr.Deref(target.Spec.ActiveFlowExportTimeout, "5s"))
	if err != nil {
		klog.V(5).ErrorS(err, "Failed to parse ActiveFlowExportTimeout from FlowExporterTarget", "FlowExporterTarget", klog.KObj(target))
		activeFlowExportTimeout = 5 * time.Second // TODO: Create constant for default
	}
	idleFlowExportTimeout, err := time.ParseDuration(ptr.Deref(target.Spec.IdleFlowExportTimeout, "15s"))
	if err != nil {
		klog.V(5).ErrorS(err, "Failed to parse IdleFlowExportTimeout from FlowExporterTarget", "FlowExporterTarget", klog.KObj(target))
		idleFlowExportTimeout = 15 * time.Second
	}

	consumerConfig := &ConsumerConfig{
		address:           target.Spec.Address,
		commProtocol:      target.Spec.Protocol,
		transportProtocol: api.ProtoTLS,

		nodeName:    fe.nodeName,
		nodeUID:     fe.nodeUID,
		obsDomainID: fe.obsDomainID,

		v4Enabled: fe.v4Enabled,
		v6Enabled: fe.v6Enabled,
	}

	if target.Spec.Protocol == api.ProtoIPFix {
		consumerConfig.transportProtocol = target.Spec.IPFixConfig.Transport
	}

	return &Consumer{
		id:                                target.Name,
		ConsumerConfig:                    consumerConfig,
		k8sClient:                         fe.k8sClient,
		conntrackConnStore:                fe.conntrackConnStore,
		conntackExpirePriorityQueue:       priorityqueue.NewExpirePriorityQueue(activeFlowExportTimeout, idleFlowExportTimeout),
		denyConnStore:                     fe.denyConnStore,
		denyConnectionExpirePriorityQueue: priorityqueue.NewExpirePriorityQueue(activeFlowExportTimeout, idleFlowExportTimeout),

		egressQuerier: fe.egressQuerier,
		flowTypeFn:    fe.findFlowType,
	}
}
