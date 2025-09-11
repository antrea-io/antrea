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
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/controller/noderoute"
	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/exporter"
	"antrea.io/antrea/pkg/agent/flowexporter/filter"
	"antrea.io/antrea/pkg/agent/flowexporter/options"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/proxy"
	api "antrea.io/antrea/pkg/apis/crd/v1beta1"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1beta1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1beta1"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/env"
	k8sutil "antrea.io/antrea/pkg/util/k8s"
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
const (
	maxConnsToExport = 64
	// How long to wait before retrying the processing of a FlowExporterTarget.
	minRetryDelay  = 5 * time.Second
	maxRetryDelay  = 300 * time.Second
	defaultWorkers = 4
)

type FlowExporter struct {
	collectorProto         string
	collectorAddr          string
	exporter               exporter.Interface
	exporterConnected      bool
	conntrackConnStore     *connections.ConntrackConnectionStore
	denyConnStore          *connections.DenyConnectionStore
	numConnsExported       uint64 // used for unit tests.
	v4Enabled              bool
	v6Enabled              bool
	k8sClient              kubernetes.Interface
	nodeRouteController    *noderoute.Controller
	isNetworkPolicyOnly    bool
	conntrackPriorityQueue *priorityqueue.ExpirePriorityQueue
	denyPriorityQueue      *priorityqueue.ExpirePriorityQueue
	expiredConns           []connection.Connection
	egressQuerier          querier.EgressQuerier
	podStore               objectstore.PodStore
	l7Listener             *connections.L7Listener
	nodeName               string
	nodeUID                string
	obsDomainID            uint32

	targetInformer crdinformers.FlowExporterTargetInformer
	fetLister      crdlisters.FlowExporterTargetLister
	queue          workqueue.TypedRateLimitingInterface[string]

	consumerStopChs map[string]chan struct{}
	addConsumerCh   chan *api.FlowExporterTarget
	rmConsumerCh    chan string

	store     connections.CTStore
	ctFetcher *connections.ConntrackFetcher
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
	egressQuerier querier.EgressQuerier, podL7FlowExporterAttrGetter connections.PodL7FlowExporterAttrGetter, l7FlowExporterEnabled bool, targetInformer crdinformers.FlowExporterTargetInformer) (*FlowExporter, error) {

	protocolFilter := filter.NewProtocolFilter(o.ProtocolFilter)
	connTrackDumper := connections.InitializeConnTrackDumper(nodeConfig, serviceCIDRNet, serviceCIDRNetv6, ovsDatapathType, proxyEnabled, protocolFilter)
	denyConnStore := connections.NewDenyConnectionStore(npQuerier, podStore, proxier, o, protocolFilter)
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
	ctFetcher := connections.NewConntrackFetcher(connTrackDumper, v4Enabled, v6Enabled, npQuerier, podStore, proxier, eventMapGetter, egressQuerier, nodeRouteController, trafficEncapMode.IsNetworkPolicyOnly(), o)

	ctStore := connections.NewConnStore(o.StaleConnectionTimeout)

	nodeName, err := env.GetNodeName()
	if err != nil {
		return nil, err
	}
	obsDomainID := genObservationID(nodeName)

	klog.InfoS("Retrieveing this Node's UID from K8s", "nodeName", nodeName)
	node, err := k8sClient.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get Node with name %s from K8s: %w", nodeName, err)
	}
	nodeUID := string(node.UID)
	klog.InfoS("Retrieved this Node's UID from K8s", "nodeName", nodeName, "nodeUID", nodeUID)

	var exp exporter.Interface
	if o.FlowCollectorProto == "grpc" {
		exp = exporter.NewGRPCExporter(nodeName, nodeUID, obsDomainID)
	} else {
		var collectorProto string
		if o.FlowCollectorProto == "tls" {
			collectorProto = "tcp"
		} else {
			collectorProto = o.FlowCollectorProto
		}
		exp = exporter.NewIPFIXExporter(collectorProto, nodeName, obsDomainID, v4Enabled, v6Enabled)
	}

	fe := &FlowExporter{
		collectorProto:         o.FlowCollectorProto,
		collectorAddr:          o.FlowCollectorAddr,
		exporter:               exp,
		conntrackConnStore:     conntrackConnStore,
		denyConnStore:          denyConnStore,
		v4Enabled:              v4Enabled,
		v6Enabled:              v6Enabled,
		k8sClient:              k8sClient,
		nodeRouteController:    nodeRouteController,
		isNetworkPolicyOnly:    trafficEncapMode.IsNetworkPolicyOnly(),
		conntrackPriorityQueue: conntrackConnStore.GetPriorityQueue(),
		denyPriorityQueue:      denyConnStore.GetPriorityQueue(),
		expiredConns:           make([]connection.Connection, 0, maxConnsToExport*2),
		egressQuerier:          egressQuerier,
		podStore:               podStore,
		l7Listener:             l7Listener,
		nodeName:               nodeName,
		nodeUID:                nodeUID,
		obsDomainID:            obsDomainID,
		targetInformer:         targetInformer,
		fetLister:              targetInformer.Lister(),
		store:                  ctStore,
		ctFetcher:              ctFetcher,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: "flowexportertarget",
			},
		),
		addConsumerCh:   make(chan *api.FlowExporterTarget),
		rmConsumerCh:    make(chan string),
		consumerStopChs: make(map[string]chan struct{}),
	}

	targetInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    fe.onNewTarget,
		DeleteFunc: fe.onTargetDelete,
	}, 0)

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

	if exp.nodeRouteController != nil {
		// Wait for NodeRouteController to have processed the initial list of Nodes so that
		// the list of Pod subnets is up-to-date.
		if !cache.WaitForCacheSync(stopCh, exp.nodeRouteController.HasSynced) {
			return
		}
	}

	klog.V(5).Info("DEBUG A3: waiting for FlowExporterTarget informer cache")
	cacheSyncs := []cache.InformerSynced{exp.targetInformer.Informer().HasSynced}
	if !cache.WaitForNamedCacheSync("FlowExporter", stopCh, cacheSyncs...) {
		return
	}
	klog.V(5).Info("DEBUG A3: FlowExporterTarget informer cache synced")

	go exp.store.Run(stopCh)

	go exp.ctFetcher.Run(stopCh, exp.store)

	for range defaultWorkers {
		go wait.Until(exp.worker, time.Second, stopCh)
	}

	for {
		select {
		case <-stopCh:
			for k, ch := range exp.consumerStopChs {
				close(ch)
				delete(exp.consumerStopChs, k)
			}
			return
		case res := <-exp.addConsumerCh:
			klog.V(5).InfoS("DEBUG A3: Adding consumer", "name", res.Name)

			consumer := exp.createConsumerFromFlowExporterTarget(res)
			stopCh := make(chan struct{})
			go consumer.Run(stopCh)
			exp.consumerStopChs[res.Name] = stopCh
		case name := <-exp.rmConsumerCh:
			klog.V(5).InfoS("DEBUG A3: Adding consumer", "name", name)
			ch, ok := exp.consumerStopChs[name]
			if ok {
				close(ch)
				delete(exp.consumerStopChs, name)
			}
		}
	}
}

func (exp *FlowExporter) worker() {
	for exp.processNextWorkItem() {
	}
}

func (exp *FlowExporter) processNextWorkItem() bool {
	key, quit := exp.queue.Get()
	if quit {
		return false
	}
	defer exp.queue.Done(key)
	if err := exp.syncFlowExporterTarget(key); err == nil {
		// If no error occurs we Forget this item so it does not get queued again until
		// another change happens.
		exp.queue.Forget(key)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		exp.queue.AddRateLimited(key)
		klog.ErrorS(err, "Error syncing FlowExporterTarget", "key", key)
	}
	return true
}

func (exp *FlowExporter) syncFlowExporterTarget(key string) error {
	res, err := exp.fetLister.Get(key)
	if err != nil {
		if apierrors.IsNotFound(err) {
			exp.rmConsumerCh <- key
			return nil
		}
		return err
	}

	exp.addConsumerCh <- res.DeepCopy()
	return nil
}

func (exp *FlowExporter) sendFlowRecords() (time.Duration, error) {
	currTime := time.Now()
	var expireTime1, expireTime2 time.Duration
	exp.expiredConns, expireTime1 = exp.denyConnStore.GetExpiredConns(exp.expiredConns, currTime, maxConnsToExport)
	exp.expiredConns, expireTime2 = exp.conntrackConnStore.GetExpiredConns(exp.expiredConns, currTime, maxConnsToExport)
	// Select the shorter time out among two connection stores to do the next round of export.
	nextExpireTime := getMinTime(expireTime1, expireTime2)
	for i := range exp.expiredConns {
		if err := exp.exportConn(&exp.expiredConns[i]); err != nil {
			klog.ErrorS(err, "Error when sending expired flow record")
			return nextExpireTime, err
		}
	}
	// Clear expiredConns slice after exporting. Allocated memory is kept.
	exp.expiredConns = exp.expiredConns[:0]
	return nextExpireTime, nil
}

// resolveCollectorAddress resolves the collector address provided in the config to an IP address or
// DNS name. The collector address can be a namespaced reference to a K8s Service, and hence needs
// resolution (to the Service's ClusterIP). The function also returns a server name to be used in
// the TLS handshake (when TLS is enabled).
func (exp *FlowExporter) resolveCollectorAddress(ctx context.Context) (string, string, error) {
	host, port, err := net.SplitHostPort(exp.collectorAddr)
	if err != nil {
		return "", "", err
	}
	ns, name := k8sutil.SplitNamespacedName(host)
	if ns == "" {
		return exp.collectorAddr, "", nil
	}
	svc, err := exp.k8sClient.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("failed to resolve Service: %s/%s", ns, name)
	}
	if svc.Spec.ClusterIP == "" {
		return "", "", fmt.Errorf("ClusterIP is not available for Service: %s/%s", ns, name)
	}
	addr := net.JoinHostPort(svc.Spec.ClusterIP, port)
	dns := fmt.Sprintf("%s.%s.svc", name, ns)
	klog.V(2).InfoS("Resolved Service address", "address", addr)
	return addr, dns, nil
}

func (exp *FlowExporter) initFlowExporter(ctx context.Context) error {
	addr, name, err := exp.resolveCollectorAddress(ctx)
	if err != nil {
		return err
	}
	var tlsConfig *exporter.TLSConfig
	if exp.collectorProto == "tls" || exp.collectorProto == "grpc" {
		// if CA certificate, client certificate and key do not exist during initialization,
		// it will retry to obtain the credentials in next export cycle
		ca, err := getCACert(ctx, exp.k8sClient)
		if err != nil {
			return fmt.Errorf("cannot retrieve CA cert: %w", err)
		}
		cert, key, err := getClientCertKey(ctx, exp.k8sClient)
		if err != nil {
			return fmt.Errorf("cannot retrieve client cert and key: %v", err)
		}
		tlsConfig = &exporter.TLSConfig{
			ServerName: name,
			CAData:     ca,
			CertData:   cert,
			KeyData:    key,
		}
	}

	if err := exp.exporter.ConnectToCollector(addr, tlsConfig); err != nil {
		return err
	}

	exp.exporterConnected = true
	metrics.ReconnectionsToFlowCollector.Inc()

	return nil
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
	if klog.V(5).Enabled() {
		klog.InfoS("Filling Egress Info for flow", "Egress", conn.EgressName, "EgressIP", conn.EgressIP, "EgressNode", conn.EgressNodeName, "SourcePod", klog.KRef(conn.SourcePodNamespace, conn.SourcePodName))
	}
}

func (exp *FlowExporter) exportConn(conn *connection.Connection) error {
	conn.FlowType = exp.findFlowType(*conn)
	if conn.FlowType == utils.FlowTypeUnsupported {
		return nil
	}
	if conn.FlowType == utils.FlowTypeToExternal {
		if conn.SourcePodNamespace != "" && conn.SourcePodName != "" {
			exp.fillEgressInfo(conn)
		} else {
			// Skip exporting the Pod-to-External connection at the Egress Node if it's different from the Source Node
			return nil
		}
	}
	if err := exp.exporter.Export(conn); err != nil {
		return err
	}
	exp.numConnsExported += 1
	if klog.V(5).Enabled() {
		klog.InfoS("Record for connection sent successfully", "flowKey", conn.FlowKey, "connection", conn)
	}
	return nil
}

func getMinTime(t1, t2 time.Duration) time.Duration {
	if t1 <= t2 {
		return t1
	}
	return t2
}

func (fe *FlowExporter) createConsumerFromFlowExporterTarget(target *api.FlowExporterTarget) *Consumer {
	activeFlowExportTimeout, err := time.ParseDuration(*target.Spec.ActiveFlowExportTimeout)
	if err != nil {
		klog.V(5).ErrorS(err, "Failed to parse ActiveFlowExportTimeout from FlowExporterTarget", "FlowExporterTarget", klog.KObj(target))
		activeFlowExportTimeout = 5 * time.Second // TODO: Create constant for default
	}
	idleFlowExportTimeout, err := time.ParseDuration(*target.Spec.IdleFlowExportTimeout)
	if err != nil {
		klog.V(5).ErrorS(err, "Failed to parse IdleFlowExportTimeout from FlowExporterTarget", "FlowExporterTarget", klog.KObj(target))
		idleFlowExportTimeout = 15 * time.Second
	}

	consumerConfig := ConsumerConfig{
		address:           target.Spec.Address,
		commProtocol:      target.Spec.Protocol,
		transportProtocol: api.ProtoTLS,

		nodeName:    fe.nodeName,
		nodeUID:     fe.nodeUID,
		obsDomainID: fe.obsDomainID,

		v4Enabled: fe.v4Enabled,
		v6Enabled: fe.v6Enabled,

		activeFlowTimeout: activeFlowExportTimeout,
		idleFlowTimeout:   idleFlowExportTimeout,
	}

	if target.Spec.Protocol == api.ProtoIPFix {
		consumerConfig.transportProtocol = target.Spec.IPFixConfig.Transport
	}

	return CreateConsumer(fe.k8sClient, fe.store, fe.denyConnStore, consumerConfig)
}

func (fe *FlowExporter) onNewTarget(obj any) {
	targetRes := obj.(*api.FlowExporterTarget)
	klog.V(5).InfoS("DEBUG: Received new FlowExporterTarget", "resource", klog.KObj(targetRes))
	fe.queue.Add(targetRes.Name)
}

func (fe *FlowExporter) onTargetDelete(obj any) {
	targetRes, ok := obj.(*api.FlowExporterTarget)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Received unexpected object: %v", obj)
			return
		}
		targetRes, ok = deletedState.Obj.(*api.FlowExporterTarget)
		if !ok {
			klog.Errorf("DeletedFinalStateUnknown contains non-FlowExportTarget object: %v", deletedState.Obj)
			return
		}
	}

	klog.V(5).InfoS("DEBUG: FlowExporterTarget deleted", "resource", klog.KObj(targetRes))
	fe.queue.Add(targetRes.Name)
}
