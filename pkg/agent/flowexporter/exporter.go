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
	"sync"
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
	"antrea.io/antrea/pkg/agent/flowexporter/broadcaster"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/exporter"
	"antrea.io/antrea/pkg/agent/flowexporter/filter"
	"antrea.io/antrea/pkg/agent/flowexporter/options"
	"antrea.io/antrea/pkg/agent/proxy"
	api "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/env"
	k8sutil "antrea.io/antrea/pkg/util/k8s"

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
	// How long to wait before retrying the processing of a FlowExporterDestination.
	minRetryDelay  = 5 * time.Second
	maxRetryDelay  = 300 * time.Second
	defaultWorkers = 2
)

type destinationObj struct {
	stopCh      chan struct{}
	destination *Destination
}

type FlowExporter struct {
	k8sClient kubernetes.Interface

	destinationInformer crdinformers.FlowExporterDestinationInformer
	destinationLister   crdlisters.FlowExporterDestinationLister

	staleConnectionTimeout time.Duration
	v4Enabled              bool
	v6Enabled              bool
	isNetworkPolicyOnly    bool

	// Destination dependencies
	nodeRouteController *noderoute.Controller
	podStore            objectstore.PodStore
	proxier             proxy.ProxyQuerier
	egressQuerier       querier.EgressQuerier
	npQuerier           querier.AgentNetworkPolicyInfoQuerier
	podNetworkWait      *utilwait.Group

	poller      *connections.Poller
	broadcaster broadcaster.Broadcaster

	staticDestinationRes *api.FlowExporterDestination
	destinations         map[string]destinationObj
	destinationsMu       sync.Mutex

	// Used to create exporter
	nodeName    string
	nodeUID     string
	obsDomainID uint32

	queue workqueue.TypedRateLimitingInterface[string]
}

func NewFlowExporter(
	k8sClient kubernetes.Interface,
	destinationInformer crdinformers.FlowExporterDestinationInformer,
	nodeConfig *config.NodeConfig,
	nodeRouteController *noderoute.Controller,
	podStore objectstore.PodStore,
	proxier proxy.ProxyQuerier,
	egressQuerier querier.EgressQuerier,
	npQuerier querier.AgentNetworkPolicyInfoQuerier,
	podNetworkWait *utilwait.Group,
	trafficEncapMode config.TrafficEncapModeType,
	v4Enabled,
	v6Enabled bool,
	serviceCIDRNet,
	serviceCIDRNetv6 *net.IPNet,
	ovsDatapathType ovsconfig.OVSDatapathType,
	proxyEnabled bool,
	o *options.FlowExporterOptions,
) (*FlowExporter, error) {
	connBroadcaster := broadcaster.New()
	connTrackDumper := connections.InitializeConnTrackDumper(nodeConfig, serviceCIDRNet, serviceCIDRNetv6, ovsDatapathType, proxyEnabled, filter.NewProtocolFilter(nil)) // Use nil filter because the filter will happen per destination
	poller := connections.NewPoller(connTrackDumper, connBroadcaster, connections.PollerConfig{
		PollInterval:          o.PollInterval,
		V4Enabled:             v4Enabled,
		V6Enabled:             v6Enabled,
		ConnectUplinkToBridge: o.ConnectUplinkToBridge,
	})

	if nodeRouteController == nil {
		klog.InfoS("NodeRouteController is nil, will not be able to determine flow type for connections")
	}

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

	staticDestination, err := createDestinationResFromOptions(o)
	if err != nil {
		klog.ErrorS(err, "failed to create static destination")
	}

	fe := &FlowExporter{
		k8sClient: k8sClient,

		destinationInformer: destinationInformer,
		destinationLister:   destinationInformer.Lister(),

		staleConnectionTimeout: o.StaleConnectionTimeout,
		v4Enabled:              v4Enabled,
		v6Enabled:              v6Enabled,
		isNetworkPolicyOnly:    trafficEncapMode.IsNetworkPolicyOnly(),

		nodeRouteController: nodeRouteController,
		podStore:            podStore,
		proxier:             proxier,
		egressQuerier:       egressQuerier,
		npQuerier:           npQuerier,
		podNetworkWait:      podNetworkWait,

		poller:      poller,
		broadcaster: connBroadcaster,

		staticDestinationRes: staticDestination,
		destinations:         make(map[string]destinationObj),

		nodeName:    nodeName,
		nodeUID:     nodeUID,
		obsDomainID: obsDomainID,

		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: "flowexporterdestination",
			},
		),
	}

	destinationInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    fe.addDestination,
		UpdateFunc: fe.updateDestination,
		DeleteFunc: fe.deleteDestination,
	}, 0)

	return fe, nil
}

func (fe *FlowExporter) addDestination(obj any) {
	res := obj.(*api.FlowExporterDestination)
	klog.V(4).InfoS("Received new FlowExporterDestination", "resource", klog.KObj(res))
	fe.queue.Add(res.Name)
}

func (fe *FlowExporter) updateDestination(old any, new any) {
	oldRes := old.(*api.FlowExporterDestination)
	newRes := new.(*api.FlowExporterDestination)

	klog.V(4).InfoS("Received updated FlowExporterDestination", "resource", klog.KObj(newRes))

	if reflect.DeepEqual(oldRes.Spec, newRes.Spec) {
		return
	}

	fe.queue.Add(newRes.Name)
}

func (fe *FlowExporter) deleteDestination(obj any) {
	res, ok := obj.(*api.FlowExporterDestination)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Received unexpected object: %v", obj)
			return
		}
		res, ok = deletedState.Obj.(*api.FlowExporterDestination)
		if !ok {
			klog.Errorf("DeletedFinalStateUnknown contains non FlowExporterDestination object: %v", deletedState.Obj)
			return
		}
	}

	klog.V(4).InfoS("FlowExporterDestination deleted", "resource", klog.KObj(res))
	fe.queue.Add(res.Name)
}

func (exp *FlowExporter) GetDenyConnPublisher() broadcaster.Publisher {
	return exp.broadcaster
}

func (exp *FlowExporter) Run(stopCh <-chan struct{}) {
	klog.Info("Flow Exporter started")

	cacheSyncs := []cache.InformerSynced{exp.destinationInformer.Informer().HasSynced}
	if exp.nodeRouteController != nil {
		// Wait for NodeRouteController to have processed the initial list of Nodes so that
		// the list of Pod subnets is up-to-date.
		cacheSyncs = append(cacheSyncs, exp.nodeRouteController.HasSynced)
	}

	if !cache.WaitForNamedCacheSync("FlowExporter", stopCh, cacheSyncs...) {
		return
	}

	go exp.poller.Run(stopCh)
	go exp.broadcaster.Start(stopCh)

	for range defaultWorkers {
		go wait.Until(exp.worker, time.Second, stopCh)
	}

	if exp.staticDestinationRes != nil {
		staticDest, err := exp.createDestinationFromResource(exp.staticDestinationRes)
		if err != nil {
			klog.ErrorS(err, "Unable to create a flow exporter destination from static configuation")
		} else {
			go staticDest.Run(stopCh)
		}
	}

	<-stopCh

	for key, destination := range exp.destinations {
		close(destination.stopCh)
		delete(exp.destinations, key)
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
	if err := exp.syncFlowExporterDestination(key); err == nil {
		// If no error occurs we Forget this item so it does not get queued again until
		// another change happens.
		exp.queue.Forget(key)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		exp.queue.AddRateLimited(key)
		klog.ErrorS(err, "Error syncing FlowExporterDestination", "key", key)
	}
	return true
}

func (exp *FlowExporter) syncFlowExporterDestination(key string) error {
	klog.InfoS("Syncing FlowExporterDestination", "key", key)
	exp.destinationsMu.Lock()
	defer exp.destinationsMu.Unlock()

	res, err := exp.destinationLister.Get(key)
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.InfoS("Removing consumer because resource was deleted")
			dest, ok := exp.destinations[key]
			if ok {
				close(dest.stopCh)
				delete(exp.destinations, key)
			}
			return nil
		}
		return err
	}

	destObj, ok := exp.destinations[key]
	if ok {
		klog.V(3).InfoS("Destination was updated, removing old instance", "name", res.Name)
		close(destObj.stopCh)
		delete(exp.destinations, res.Name)
	}

	klog.V(3).InfoS("Adding consumer", "name", res.Name)
	dest, err := exp.createDestinationFromResource(res)
	if err != nil {
		return fmt.Errorf("unable to create destination from resource: %w", err)
	}
	stopCh := make(chan struct{})
	go dest.Run(stopCh)
	exp.destinations[res.Name] = destinationObj{
		destination: dest,
		stopCh:      stopCh,
	}

	return nil
}

func (fe *FlowExporter) createExporter(protocol exporterProtocol) exporter.Interface {
	var exp exporter.Interface
	if protocol.Name() == grpcExporterProtocol {
		exp = exporter.NewGRPCExporter(fe.nodeName, fe.nodeUID, fe.obsDomainID)
	} else {
		var collectorProto string
		if protocol.TransportProtocol() == api.FlowExporterTransportTLS {
			collectorProto = string(api.FlowExporterTransportTCP)
		} else {
			collectorProto = string(protocol.TransportProtocol())
		}
		exp = exporter.NewIPFIXExporter(collectorProto, fe.nodeName, fe.obsDomainID, fe.v4Enabled, fe.v6Enabled)
	}

	return exp
}

func ServiceAddressToDNS(address string) (string, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}

	ns, name := k8sutil.SplitNamespacedName(host)
	if ns == "" {
		return "", nil
	}

	return fmt.Sprintf("%s.%s.svc", name, ns), nil
}

func (fe *FlowExporter) createDestinationFromResource(res *api.FlowExporterDestination) (*Destination, error) {
	protocol := getExporterProtocol(res.Spec.Protocol)
	exp := fe.createExporter(protocol)
	config := DestinationConfig{
		name:    res.Name,
		address: res.Spec.Address,

		activeFlowTimeout:      time.Second * time.Duration(res.Spec.ActiveFlowExportTimeoutSeconds),
		idleFlowTimeout:        time.Second * time.Duration(res.Spec.IdleFlowExportTimeoutSeconds),
		staleConnectionTimeout: fe.staleConnectionTimeout,

		isNetworkPolicyOnly: fe.isNetworkPolicyOnly,
		tlsConfig:           res.Spec.TLSConfig,
		allowProtocolFilter: ptr.Deref(res.Spec.Filter, api.FlowExporterFilter{}).Protocols,
	}
	return NewDestination(
		fe.broadcaster,
		exp,
		fe.k8sClient,
		fe.nodeRouteController,
		fe.podStore,
		fe.npQuerier,
		fe.proxier,
		fe.egressQuerier,
		fe.podNetworkWait,
		config,
	), nil
}

func createDestinationResFromOptions(o *options.FlowExporterOptions) (*api.FlowExporterDestination, error) {
	if !o.EnableStaticDestination {
		return nil, nil
	}
	feProtocol := api.FlowExporterProtocol{}
	var feTLSConfig *api.FlowExporterTLSConfig

	dnsName, err := ServiceAddressToDNS(o.FlowCollectorAddr)
	if err != nil {
		return nil, fmt.Errorf("fail")
	}

	if o.FlowCollectorProto == "grpc" {
		feProtocol.GRPC = &api.FlowExporterGRPCConfig{}
		feTLSConfig = &api.FlowExporterTLSConfig{
			ServerName: dnsName,
			CAConfigMap: api.NamespacedName{
				Name:      CAConfigMapName,
				Namespace: CAConfigMapNamespace,
			},
			ClientSecret: &api.NamespacedName{
				Name:      ClientSecretName,
				Namespace: ClientSecretNamespace,
			},
		}
	} else {
		feProtocol.IPFIX = &api.FlowExporterIPFIXConfig{
			Transport: api.FlowExporterTransportProtocol(o.FlowCollectorProto),
		}
		if o.FlowCollectorProto == "tls" {
			feTLSConfig = &api.FlowExporterTLSConfig{
				ServerName: dnsName,
				CAConfigMap: api.NamespacedName{
					Name:      CAConfigMapName,
					Namespace: CAConfigMapNamespace,
				},
				ClientSecret: &api.NamespacedName{
					Name:      ClientSecretName,
					Namespace: ClientSecretNamespace,
				},
			}
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
			TLSConfig:                      feTLSConfig,
		},
	}, nil
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

func genObservationID(nodeName string) uint32 {
	h := fnv.New32()
	h.Write([]byte(nodeName))
	return h.Sum32()
}
