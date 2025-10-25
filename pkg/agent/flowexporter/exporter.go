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
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/controller/noderoute"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/filter"
	"antrea.io/antrea/pkg/agent/flowexporter/options"
	"antrea.io/antrea/pkg/agent/proxy"
	api "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/client/clientset/versioned"
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
	generation int64
	consumer   *Consumer
	stopCh     chan struct{}
}

type FlowExporter struct {
	k8sClient kubernetes.Interface
	crdClient versioned.Interface

	v4Enabled           bool
	v6Enabled           bool
	nodeRouteController *noderoute.Controller
	isNetworkPolicyOnly bool
	egressQuerier       querier.EgressQuerier
	podStore            objectstore.PodStore
	l7Listener          *connections.L7Listener
	nodeName            string
	nodeUID             string
	obsDomainID         uint32

	destinationInformer crdinformers.FlowExporterDestinationInformer
	destinationLister   crdlisters.FlowExporterDestinationLister
	queue               workqueue.TypedRateLimitingInterface[string]

	consumers     map[string]consumerStore
	addConsumerCh chan *api.FlowExporterDestination
	rmConsumerCh  chan string

	store             connections.Store
	staticConsumerRes *api.FlowExporterDestination
}

func NewFlowExporter(k8sClient kubernetes.Interface, crdClient versioned.Interface, podStore objectstore.PodStore, proxier proxy.Proxier, nodeRouteController *noderoute.Controller,
	trafficEncapMode config.TrafficEncapModeType, nodeConfig *config.NodeConfig, v4Enabled, v6Enabled bool, serviceCIDRNet, serviceCIDRNetv6 *net.IPNet,
	ovsDatapathType ovsconfig.OVSDatapathType, proxyEnabled bool, npQuerier querier.AgentNetworkPolicyInfoQuerier, o *options.FlowExporterOptions,
	egressQuerier querier.EgressQuerier, podNetworkWait *utilwait.Group, podL7FlowExporterAttrGetter connections.PodL7FlowExporterAttrGetter, l7FlowExporterEnabled bool,
	destinationInformer crdinformers.FlowExporterDestinationInformer) (*FlowExporter, error) {
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

	var staticConsumerRes = createDestinationResFromOptions(o)

	fe := &FlowExporter{
		k8sClient: k8sClient,
		crdClient: crdClient,

		staticConsumerRes:   staticConsumerRes,
		v4Enabled:           v4Enabled,
		v6Enabled:           v6Enabled,
		nodeRouteController: nodeRouteController,
		isNetworkPolicyOnly: trafficEncapMode.IsNetworkPolicyOnly(),
		egressQuerier:       egressQuerier,
		podStore:            podStore,
		l7Listener:          l7Listener,
		nodeName:            nodeName,
		nodeUID:             nodeUID,
		obsDomainID:         obsDomainID,
		destinationInformer: destinationInformer,
		destinationLister:   destinationInformer.Lister(),
		store:               ctStore,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: "flowexporterdestination",
			},
		),
		addConsumerCh: make(chan *api.FlowExporterDestination),
		rmConsumerCh:  make(chan string),
		consumers:     make(map[string]consumerStore),
	}

	destinationInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    fe.onNewTarget,
		UpdateFunc: fe.OnUpdateTarget,
		DeleteFunc: fe.onTargetDelete,
	}, 0)

	return fe, nil
}

func createDestinationResFromOptions(o *options.FlowExporterOptions) *api.FlowExporterDestination {
	if !o.EnableStaticDestination {
		return nil
	}
	feProtocol := api.FlowExporterProtocol{}
	if o.FlowCollectorProto == "grpc" {
		feProtocol.GRPC = &api.FlowExporterGRPCConfig{}
	} else {
		feProtocol.IPFIX = &api.FlowExporterIPFIXConfig{
			Transport: api.FlowExporterTransportProtocol(o.FlowCollectorProto),
		}
	}

	return &api.FlowExporterDestination{
		Spec: api.FlowExporterDestinationSpec{
			Address:  o.FlowCollectorAddr,
			Protocol: feProtocol,
			Filter: &api.FlowExporterFilter{
				Protocols: o.ProtocolFilter,
			},
			ActiveFlowExportTimeoutSeconds: int32(o.ActiveFlowTimeout.Seconds()),
			IdleFlowExportTimeoutSeconds:   int32(o.IdleFlowTimeout.Seconds()),
		},
	}
}

func (exp *FlowExporter) GetDenyStore() connections.DenyStore {
	return exp.store
}

func (exp *FlowExporter) Run(stopCh <-chan struct{}) {
	klog.Info("Flow exporter is started")

	// Start L7 connection flow socket
	if features.DefaultFeatureGate.Enabled(features.L7FlowExporter) {
		klog.Info("L7 flow export is enabled")
		go exp.l7Listener.Run(stopCh)
	}

	cacheSyncs := []cache.InformerSynced{exp.destinationInformer.Informer().HasSynced}
	if exp.nodeRouteController != nil {
		// Wait for NodeRouteController to have processed the initial list of Nodes so that
		// the list of Pod subnets is up-to-date.
		cacheSyncs = append(cacheSyncs, exp.nodeRouteController.HasSynced)
	}

	if !cache.WaitForNamedCacheSync("FlowExporter", stopCh, cacheSyncs...) {
		return
	}
	klog.Info("caches synced")

	go exp.store.Run(stopCh)

	for range defaultWorkers {
		go wait.Until(exp.worker, time.Second, stopCh)
	}

	if exp.staticConsumerRes != nil {
		consumer := exp.createConsumerFromResource(exp.staticConsumerRes)
		go consumer.Run(stopCh)
	}

	for {
		select {
		case <-stopCh:
			exp.stopConsumers()
			return
		case res := <-exp.addConsumerCh:
			exp.handleDestination(res)
		case name := <-exp.rmConsumerCh:
			exp.handleDestinationDelete(name)
		}
	}
}

func (exp *FlowExporter) stopConsumers() {
	for k, ch := range exp.consumers {
		close(ch.stopCh)
		delete(exp.consumers, k)
	}
}

func (exp *FlowExporter) handleDestinationDelete(name string) {
	ch, ok := exp.consumers[name]
	if ok {
		close(ch.stopCh)
		delete(exp.consumers, name)
	}
}

func (exp *FlowExporter) handleDestination(res *api.FlowExporterDestination) {
	obj, ok := exp.consumers[res.Name]
	if ok {
		if obj.generation == res.Generation {
			return
		}
		klog.V(3).InfoS("Consumer was updated, removing old instance", "name", res.Name)
		close(obj.stopCh)
		delete(exp.consumers, res.Name)
	}

	klog.V(3).InfoS("Adding consumer", "name", res.Name)
	consumer := exp.createConsumerFromResource(res)
	stopCh := make(chan struct{})
	go consumer.Run(stopCh)
	exp.consumers[res.Name] = consumerStore{
		consumer:   consumer,
		generation: res.Generation,
		stopCh:     stopCh,
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
	klog.InfoS("Syncing FlowExporterDestination", "key", key)
	res, err := exp.destinationLister.Get(key)
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.InfoS("Removing consumer because it wasn't found")
			exp.rmConsumerCh <- key
			return nil
		}
		return err
	}

	copy := res.DeepCopy()
	if err != nil {
		return err
	}
	exp.addConsumerCh <- copy

	return nil
}

func (fe *FlowExporter) createConsumerFromResource(res *api.FlowExporterDestination) *Consumer {
	consumerConfig := ConsumerConfig{
		name: res.Name,

		address:  res.Spec.Address,
		protocol: getExporterProtocol(res.Spec.Protocol),

		nodeName:    fe.nodeName,
		nodeUID:     fe.nodeUID,
		obsDomainID: fe.obsDomainID,

		v4Enabled: fe.v4Enabled,
		v6Enabled: fe.v6Enabled,

		activeFlowTimeout: time.Second * time.Duration(res.Spec.ActiveFlowExportTimeoutSeconds),
		idleFlowTimeout:   time.Second * time.Duration(res.Spec.IdleFlowExportTimeoutSeconds),

		allowProtocolFilter: ptr.Deref(res.Spec.Filter, api.FlowExporterFilter{}).Protocols,
	}

	return CreateConsumer(fe.k8sClient, fe.store, consumerConfig)
}

func (fe *FlowExporter) onNewTarget(obj any) {
	targetRes := obj.(*api.FlowExporterDestination)
	klog.V(4).InfoS("Received new FlowExporterDestination", "resource", klog.KObj(targetRes))
	fe.queue.Add(targetRes.Name)
}

func (fe *FlowExporter) OnUpdateTarget(old any, new any) {
	oldRes := old.(*api.FlowExporterDestination)
	newRes := new.(*api.FlowExporterDestination)

	klog.V(4).InfoS("Received updated FlowExporterDestination", "resource", klog.KObj(newRes))

	if reflect.DeepEqual(oldRes.Spec, newRes.Spec) {
		return
	}

	fe.queue.Add(newRes.Name)
}

func (fe *FlowExporter) onTargetDelete(obj any) {
	targetRes, ok := obj.(*api.FlowExporterDestination)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Received unexpected object: %v", obj)
			return
		}
		targetRes, ok = deletedState.Obj.(*api.FlowExporterDestination)
		if !ok {
			klog.Errorf("DeletedFinalStateUnknown contains non-FlowExporterDestination object: %v", deletedState.Obj)
			return
		}
	}

	klog.V(4).InfoS("FlowExporterDestination deleted", "resource", klog.KObj(targetRes))
	fe.queue.Add(targetRes.Name)
}

func genObservationID(nodeName string) uint32 {
	h := fnv.New32()
	h.Write([]byte(nodeName))
	return h.Sum32()
}

func getExporterProtocol(proto api.FlowExporterProtocol) exporterProtocol {
	switch {
	case proto.IPFIX != nil:
		return proto.IPFIX
	case proto.GRPC != nil:
		return proto.GRPC
	default:
		// This case should never happen on real usage. API server requires at least one to be defined.
		return &api.FlowExporterGRPCConfig{}
	}
}
