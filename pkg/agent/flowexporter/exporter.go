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
	"reflect"
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
	"antrea.io/antrea/pkg/agent/proxy"
	api "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/objectstore"
	utilwait "antrea.io/antrea/pkg/util/wait"
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

type consumerStore struct {
	consumer *Consumer
	stopCh   chan struct{}
}

type FlowExporter struct {
	collectorProto      string
	collectorAddr       string
	exporter            exporter.Interface
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
	nodeUID             string
	obsDomainID         uint32

	targetInformer crdinformers.FlowExporterTargetInformer
	fetLister      crdlisters.FlowExporterTargetLister
	queue          workqueue.TypedRateLimitingInterface[string]

	consumerStopChs map[string]consumerStore
	addConsumerCh   chan *api.FlowExporterTarget
	rmConsumerCh    chan string

	store connections.Store
}

func NewFlowExporter(podStore objectstore.PodStore, proxier proxy.Proxier, k8sClient kubernetes.Interface, nodeRouteController *noderoute.Controller,
	trafficEncapMode config.TrafficEncapModeType, nodeConfig *config.NodeConfig, v4Enabled, v6Enabled bool, serviceCIDRNet, serviceCIDRNetv6 *net.IPNet,
	ovsDatapathType ovsconfig.OVSDatapathType, proxyEnabled bool, npQuerier querier.AgentNetworkPolicyInfoQuerier, o *options.FlowExporterOptions,
	egressQuerier querier.EgressQuerier, podNetworkWait *utilwait.Group,
	podL7FlowExporterAttrGetter connections.PodL7FlowExporterAttrGetter, l7FlowExporterEnabled bool,
) (*FlowExporter, error) {

	return NewFlowExporterWithInformer(podStore, proxier, k8sClient, nodeRouteController,
		trafficEncapMode, nodeConfig, v4Enabled, v6Enabled, serviceCIDRNet, serviceCIDRNetv6,
		ovsDatapathType, proxyEnabled, npQuerier, o,
		egressQuerier, podNetworkWait, podL7FlowExporterAttrGetter, l7FlowExporterEnabled, nil)
}

func NewFlowExporterWithInformer(podStore objectstore.PodStore, proxier proxy.Proxier, k8sClient kubernetes.Interface, nodeRouteController *noderoute.Controller,
	trafficEncapMode config.TrafficEncapModeType, nodeConfig *config.NodeConfig, v4Enabled, v6Enabled bool, serviceCIDRNet, serviceCIDRNetv6 *net.IPNet,
	ovsDatapathType ovsconfig.OVSDatapathType, proxyEnabled bool, npQuerier querier.AgentNetworkPolicyInfoQuerier, o *options.FlowExporterOptions,
	egressQuerier querier.EgressQuerier, podNetworkWait *utilwait.Group, podL7FlowExporterAttrGetter connections.PodL7FlowExporterAttrGetter, l7FlowExporterEnabled bool,
	targetInformer crdinformers.FlowExporterTargetInformer) (*FlowExporter, error) {
	protocolFilter := filter.NewProtocolFilter(o.ProtocolFilter)
	connTrackDumper := connections.InitializeConnTrackDumper(nodeConfig, serviceCIDRNet, serviceCIDRNetv6, ovsDatapathType, proxyEnabled, protocolFilter)
	var l7Listener *connections.L7Listener
	var eventMapGetter connections.L7EventMapGetter
	if l7FlowExporterEnabled {
		l7Listener = connections.NewL7Listener(podL7FlowExporterAttrGetter, podStore)
		eventMapGetter = l7Listener
	}
	if nodeRouteController == nil {
		klog.InfoS("NodeRouteController is nil, will not be able to determine flow type for connections")
	}

	ctStore := connections.NewConnStore(
		connTrackDumper,
		v4Enabled, v6Enabled,
		podStore,
		proxier,
		npQuerier,
		egressQuerier,
		podNetworkWait,
		nodeRouteController,
		eventMapGetter,
		trafficEncapMode.IsNetworkPolicyOnly(),
		o,
	)

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
		collectorProto:      o.FlowCollectorProto,
		collectorAddr:       o.FlowCollectorAddr,
		exporter:            exp,
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
		nodeUID:             nodeUID,
		obsDomainID:         obsDomainID,
		targetInformer:      targetInformer,
		fetLister:           targetInformer.Lister(),
		store:               ctStore,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: "flowexportertarget",
			},
		),
		addConsumerCh:   make(chan *api.FlowExporterTarget),
		rmConsumerCh:    make(chan string),
		consumerStopChs: make(map[string]consumerStore),
	}

	targetInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    fe.onNewTarget,
		UpdateFunc: fe.OnUpdateTarget,
		DeleteFunc: fe.onTargetDelete,
	}, 0)

	return fe, nil
}

func genObservationID(nodeName string) uint32 {
	h := fnv.New32()
	h.Write([]byte(nodeName))
	return h.Sum32()
}

func (exp *FlowExporter) GetDenyStore() connections.DenyStore {
	return exp.store
}

func (exp *FlowExporter) Run(stopCh <-chan struct{}) {
	// Start L7 connection flow socket
	if features.DefaultFeatureGate.Enabled(features.L7FlowExporter) {
		go exp.l7Listener.Run(stopCh)
	}

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

	go exp.store.Run(stopCh)

	for range defaultWorkers {
		go wait.Until(exp.worker, time.Second, stopCh)
	}

	for {
		select {
		case <-stopCh:
			for k, ch := range exp.consumerStopChs {
				close(ch.stopCh)
				delete(exp.consumerStopChs, k)
			}
			return
		case res := <-exp.addConsumerCh:
			oldConsumerCh, ok := exp.consumerStopChs[res.Name]
			if ok {
				klog.V(3).InfoS("Consumer was updated, removing old instance", "name", res.Name)
				close(oldConsumerCh.stopCh)
				delete(exp.consumerStopChs, res.Name)
			}

			klog.V(3).InfoS("Adding consumer", "name", res.Name)
			consumer := exp.createConsumerFromFlowExporterTarget(res)
			stopCh := make(chan struct{})
			go consumer.Run(stopCh)
			exp.consumerStopChs[res.Name] = consumerStore{
				consumer: consumer,
				stopCh:   stopCh,
			}
		case name := <-exp.rmConsumerCh:
			klog.V(3).InfoS("Removing consumer", "name", name)
			ch, ok := exp.consumerStopChs[name]
			if ok {
				close(ch.stopCh)
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

		allowProtocolFilter: target.Spec.Filter,
	}

	if target.Spec.Protocol == api.ProtoIPFix {
		consumerConfig.transportProtocol = target.Spec.IPFixConfig.Transport
	}

	return CreateConsumer(fe.k8sClient, fe.store, consumerConfig)
}

func (fe *FlowExporter) onNewTarget(obj any) {
	targetRes := obj.(*api.FlowExporterTarget)
	klog.V(5).InfoS("Received new FlowExporterTarget", "resource", klog.KObj(targetRes))
	fe.queue.Add(targetRes.Name)
}

func (fe *FlowExporter) OnUpdateTarget(old any, new any) {
	oldRes := old.(*api.FlowExporterTarget)
	newRes := new.(*api.FlowExporterTarget)

	klog.V(5).InfoS("Received updated FlowExporterTarget", "resource", klog.KObj(newRes))

	if reflect.DeepEqual(oldRes.Spec, newRes.Spec) {
		return
	}

	fe.queue.Add(newRes.Name)
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

	klog.V(5).InfoS("FlowExporterTarget deleted", "resource", klog.KObj(targetRes))
	fe.queue.Add(targetRes.Name)
}
