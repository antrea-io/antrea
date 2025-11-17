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
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/exporter"
	"antrea.io/antrea/pkg/agent/flowexporter/options"
	"antrea.io/antrea/pkg/agent/proxy"
	api "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/channel"
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
	defaultWorkers = 1

	// We use a buffer of 1 since we batch the connections and send it as a slice.
	ctConnsUpdateChannelBufferSize int = 1
	// We use a buffer of 100 to handle situations where we get a burst of denied
	// denied connections
	denyConnUpdateChannelBufferSize int = 100
)

type destinationObj struct {
	stopCh      chan struct{}
	destination *Destination
}

type FlowExporter struct {
	k8sClient kubernetes.Interface

	destinationInformer crdinformers.FlowExporterDestinationInformer
	destinationSynced   cache.InformerSynced
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

	// networkPolicyWait is used to determine when NetworkPolicy flows have been installed and
	// when the mapping from flow ID to NetworkPolicy rule is available. We will ignore
	// connections which started prior to that time to avoid reporting invalid NetworkPolicy
	// metadata in flow records. This is because the mapping is not "stable" and is expected to
	// change when the Agent restarts.
	networkPolicyWait      *utilwait.Group
	networkPolicyReadyTime time.Time

	poller                *connections.Poller
	ctConnUpdateChannel   *channel.SubscribableChannel
	denyConnUpdateChannel *channel.SubscribableChannel

	staticDestinationRes *api.FlowExporterDestination
	destinations         map[string]destinationObj
	destinationsMutex    sync.Mutex

	// Used to create exporter
	nodeName    string
	nodeUID     string
	obsDomainID uint32

	queue workqueue.TypedRateLimitingInterface[string]
}

func NewFlowExporter(
	podStore objectstore.PodStore,
	proxier proxy.ProxyQuerier,
	k8sClient kubernetes.Interface,
	nodeRouteController *noderoute.Controller,
	trafficEncapMode config.TrafficEncapModeType,
	nodeConfig *config.NodeConfig,
	v4Enabled, v6Enabled bool,
	serviceCIDRNet, serviceCIDRNetv6 *net.IPNet,
	ovsDatapathType ovsconfig.OVSDatapathType,
	proxyEnabled bool,
	npQuerier querier.AgentNetworkPolicyInfoQuerier,
	o *options.FlowExporterOptions,
	destinationInformer crdinformers.FlowExporterDestinationInformer,
	egressQuerier querier.EgressQuerier,
	networkPolicyWait *utilwait.Group,
) (*FlowExporter, error) {
	ctConnsUpdateChannel := channel.NewSubscribableChannel("Conntrack Connections", ctConnsUpdateChannelBufferSize)
	denyConnUpdateChannel := channel.NewSubscribableChannel("Deny Connections", denyConnUpdateChannelBufferSize)
	connTrackDumper := connections.InitializeConnTrackDumper(nodeConfig, serviceCIDRNet, serviceCIDRNetv6, ovsDatapathType, proxyEnabled)
	poller := connections.NewPoller(connTrackDumper, ctConnsUpdateChannel, o.PollInterval, v4Enabled, v6Enabled, o.ConnectUplinkToBridge)

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

	staticDestination, err := createStaticDestinationResFromOptions(o)
	if err != nil {
		klog.ErrorS(err, "Failed to create static destination")
	}

	fe := &FlowExporter{
		k8sClient: k8sClient,

		destinationInformer: destinationInformer,
		destinationLister:   destinationInformer.Lister(),
		destinationSynced:   destinationInformer.Informer().HasSynced,

		staleConnectionTimeout: o.StaleConnectionTimeout,
		v4Enabled:              v4Enabled,
		v6Enabled:              v6Enabled,
		isNetworkPolicyOnly:    trafficEncapMode.IsNetworkPolicyOnly(),

		nodeRouteController: nodeRouteController,
		podStore:            podStore,
		proxier:             proxier,
		egressQuerier:       egressQuerier,
		npQuerier:           npQuerier,
		networkPolicyWait:   networkPolicyWait,

		poller:                poller,
		ctConnUpdateChannel:   ctConnsUpdateChannel,
		denyConnUpdateChannel: denyConnUpdateChannel,

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
	klog.V(4).InfoS("Received new FlowExporterDestination", "flowExporterDestination", klog.KObj(res))
	fe.queue.Add(res.Name)
}

func (fe *FlowExporter) updateDestination(old any, new any) {
	oldRes := old.(*api.FlowExporterDestination)
	newRes := new.(*api.FlowExporterDestination)

	klog.V(4).InfoS("Received updated FlowExporterDestination", "flowExporterDestination", klog.KObj(newRes))

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
			klog.ErrorS(fmt.Errorf("unexpected object type"), "Could not determine type when handling deleted FlowExporterDestination", "obj", obj)
			return
		}
		res, ok = deletedState.Obj.(*api.FlowExporterDestination)
		if !ok {
			klog.ErrorS(fmt.Errorf("unexpected object type"), "DeletedFinalStateUnknown did not contain FlowExporterDestination object", "obj", deletedState.Obj)
			return
		}
	}

	klog.V(4).InfoS("FlowExporterDestination deleted", "resource", klog.KObj(res))
	fe.queue.Add(res.Name)
}

func (exp *FlowExporter) GetDenyConnStoreNotifier() channel.Notifier {
	return exp.denyConnUpdateChannel
}

func (exp *FlowExporter) Run(stopCh <-chan struct{}) {
	klog.InfoS("Flow Exporter started")

	cacheSyncs := []cache.InformerSynced{exp.destinationSynced}
	if exp.nodeRouteController != nil {
		// Wait for NodeRouteController to have processed the initial list of Nodes so that
		// the list of Pod subnets is up-to-date.
		cacheSyncs = append(cacheSyncs, exp.nodeRouteController.HasSynced)
	}

	if !cache.WaitForNamedCacheSync("FlowExporter", stopCh, cacheSyncs...) {
		return
	}

	if exp.networkPolicyWait != nil {
		klog.InfoS("Waiting for NetworkPolicies to become ready")
		if err := exp.networkPolicyWait.WaitUntil(stopCh); err != nil {
			klog.ErrorS(err, "Error while waiting for NetworkPolicies to become ready")
			return
		}
	} else {
		klog.InfoS("Skip waiting for NetworkPolicies to become ready")
	}
	exp.networkPolicyReadyTime = time.Now()

	go exp.ctConnUpdateChannel.Run(stopCh)
	go exp.denyConnUpdateChannel.Run(stopCh)
	go exp.poller.Run(stopCh)

	for range defaultWorkers {
		go wait.Until(exp.worker, time.Second, stopCh)
	}

	if exp.staticDestinationRes != nil {
		staticDest, err := exp.createDestinationFromResource(exp.staticDestinationRes)
		if err != nil {
			klog.ErrorS(err, "Could not create FlowExporterDestination from static configuration")
		} else {
			go staticDest.Run(stopCh)
		}
	}

	<-stopCh

	exp.destinationsMutex.Lock()
	for key, destination := range exp.destinations {
		close(destination.stopCh)
		delete(exp.destinations, key)
	}
	exp.destinationsMutex.Unlock()
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
		klog.ErrorS(err, "Failed to sync FlowExporterDestination", "key", key)
	}
	return true
}

func (exp *FlowExporter) syncFlowExporterDestination(key string) error {
	klog.InfoS("Syncing FlowExporterDestination", "key", key)
	exp.destinationsMutex.Lock()
	defer exp.destinationsMutex.Unlock()

	res, err := exp.destinationLister.Get(key)
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.InfoS("Removing destination because resource was deleted")
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
		klog.V(3).InfoS("Removing old instance", "flowExporterDestination", klog.KObj(res))
		close(destObj.stopCh)
		delete(exp.destinations, res.Name)
	}

	klog.V(3).InfoS("Adding destination", "flowExporterDestination", klog.KObj(res))
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
	switch protocol.Name() {
	case grpcExporterProtocol:
		exp = exporter.NewGRPCExporter(fe.nodeName, fe.nodeUID, fe.obsDomainID)
	case ipfixExporterProtocol:
		var collectorProto string
		if protocol.TransportProtocol() == api.FlowExporterTransportTLS {
			collectorProto = string(api.FlowExporterTransportTCP)
		} else {
			collectorProto = string(protocol.TransportProtocol())
		}
		exp = exporter.NewIPFIXExporter(collectorProto, fe.nodeName, fe.obsDomainID, fe.v4Enabled, fe.v6Enabled)
	default:
		klog.InfoS("Unsupported exporter protocol", "protocol", protocol.Name())
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
	validateResource(res)
	protocol := getExporterProtocol(res.Spec.Protocol)
	exp := fe.createExporter(protocol)
	if exp == nil {
		return nil, fmt.Errorf("failed to create exporter")
	}

	config := DestinationConfig{
		name:    res.Name,
		address: res.Spec.Address,

		activeFlowTimeout:      time.Second * time.Duration(res.Spec.ActiveFlowExportTimeoutSeconds),
		idleFlowTimeout:        time.Second * time.Duration(res.Spec.IdleFlowExportTimeoutSeconds),
		staleConnectionTimeout: fe.staleConnectionTimeout,

		isNetworkPolicyOnly: fe.isNetworkPolicyOnly,
		tlsConfig:           res.Spec.TLSConfig,
		allowProtocolFilter: ptr.Deref(res.Spec.Filter, api.FlowExporterFilter{}).Protocols,

		networkPolicyReadyTime: fe.networkPolicyReadyTime,
	}
	return NewDestination(
		fe.ctConnUpdateChannel,
		fe.denyConnUpdateChannel,
		exp,
		fe.k8sClient,
		fe.nodeRouteController,
		fe.podStore,
		fe.npQuerier,
		fe.proxier,
		fe.egressQuerier,
		fe.networkPolicyReadyTime,
		config,
	), nil
}

func createStaticDestinationResFromOptions(o *options.FlowExporterOptions) (*api.FlowExporterDestination, error) {
	if !o.EnableStaticDestination {
		return nil, nil
	}
	feProtocol := api.FlowExporterProtocol{}
	var feTLSConfig *api.FlowExporterTLSConfig

	dnsName, err := ServiceAddressToDNS(o.FlowCollectorAddr)
	if err != nil {
		return nil, fmt.Errorf("unable to determine transform service address to DNS name: %w", err)
	}

	if o.FlowCollectorProto == "grpc" {
		feProtocol.GRPC = &api.FlowExporterGRPCConfig{}
		feTLSConfig = &api.FlowExporterTLSConfig{
			ServerName: dnsName,
			CAConfigMap: api.NamespacedName{
				Name:      caConfigMapName,
				Namespace: caConfigMapNamespace,
			},
			ClientSecret: &api.NamespacedName{
				Name:      clientSecretName,
				Namespace: clientSecretNamespace,
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
					Name:      caConfigMapName,
					Namespace: caConfigMapNamespace,
				},
				ClientSecret: &api.NamespacedName{
					Name:      clientSecretName,
					Namespace: clientSecretNamespace,
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

func validateResource(res *api.FlowExporterDestination) error {
	protocol := getExporterProtocol(res.Spec.Protocol)
	switch protocol.Name() {
	case grpcExporterProtocol:
		if res.Spec.TLSConfig == nil {
			return fmt.Errorf("missing spec.TLSConfig for grpc connection")
		}
	case ipfixExporterProtocol:
		if protocol.TransportProtocol() == api.FlowExporterTransportTLS && res.Spec.TLSConfig == nil {
			return fmt.Errorf("missing spec.TLSConfig for IPFIX connection over TLS")
		}
	}

	return nil
}
