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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
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
const maxConnsToExport = 64

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
	nodeName               string
	obsDomainID            uint32
}

func NewFlowExporter(podStore objectstore.PodStore, proxier proxy.ProxyQuerier, k8sClient kubernetes.Interface, nodeRouteController *noderoute.Controller,
	trafficEncapMode config.TrafficEncapModeType, nodeConfig *config.NodeConfig, v4Enabled, v6Enabled bool, serviceCIDRNet, serviceCIDRNetv6 *net.IPNet,
	ovsDatapathType ovsconfig.OVSDatapathType, proxyEnabled bool, npQuerier querier.AgentNetworkPolicyInfoQuerier, o *options.FlowExporterOptions,
	egressQuerier querier.EgressQuerier, podNetworkWait *utilwait.Group,
) (*FlowExporter, error) {
	protocolFilter := filter.NewProtocolFilter(o.ProtocolFilter)
	connTrackDumper := connections.InitializeConnTrackDumper(nodeConfig, serviceCIDRNet, serviceCIDRNetv6, ovsDatapathType, proxyEnabled, protocolFilter)
	denyConnStore := connections.NewDenyConnectionStore(npQuerier, podStore, proxier, o, protocolFilter)
	conntrackConnStore := connections.NewConntrackConnectionStore(connTrackDumper, v4Enabled, v6Enabled, npQuerier, podStore, proxier, podNetworkWait, o)
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

	return &FlowExporter{
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
		nodeName:               nodeName,
		obsDomainID:            obsDomainID,
	}, nil
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

	defaultTimeout := exp.conntrackPriorityQueue.ActiveFlowTimeout
	expireTimer := time.NewTimer(defaultTimeout)
	for {
		select {
		case <-stopCh:
			if exp.exporterConnected {
				exp.resetFlowExporter()
			}
			expireTimer.Stop()
			return
		case <-expireTimer.C:
			if !exp.exporterConnected {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				err := exp.initFlowExporter(ctx)
				cancel()
				if err != nil {
					klog.ErrorS(err, "Error when initializing flow exporter")
					exp.resetFlowExporter()
					// Initializing flow exporter fails, will retry in next cycle.
					expireTimer.Reset(defaultTimeout)
					continue
				}
			}
			// Pop out the expired connections from the conntrack priority queue
			// and the deny priority queue, and send the data records.
			nextExpireTime, err := exp.sendFlowRecords()
			if err != nil {
				klog.ErrorS(err, "Error when sending expired flow records")
				// If there is an error when sending flow records because of
				// intermittent connectivity, we reset the connection to collector
				// and retry in the next export cycle to reinitialize the connection
				// and send flow records.
				exp.resetFlowExporter()
				expireTimer.Reset(defaultTimeout)
				continue
			}
			expireTimer.Reset(nextExpireTime)
		}
	}
}

func (exp *FlowExporter) resetFlowExporter() {
	exp.exporter.CloseConnToCollector()
	exp.exporterConnected = false
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
