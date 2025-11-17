package flowexporter

import (
	"context"
	"fmt"
	"net"
	"time"

	"antrea.io/antrea/pkg/agent/controller/noderoute"
	"antrea.io/antrea/pkg/agent/flowexporter/broadcaster"
	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/exporter"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/proxy"
	api "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/querier"
	k8sutil "antrea.io/antrea/pkg/util/k8s"
	"antrea.io/antrea/pkg/util/objectstore"
	utilwait "antrea.io/antrea/pkg/util/wait"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

const (
	grpcExporterProtocol  string = "grpc"
	ipfixExporterProtocol string = "ipfix"
)

type exporterProtocol interface {
	Name() string
	TransportProtocol() api.FlowExporterTransportProtocol
}

type DestinationConfig struct {
	name    string
	address string

	activeFlowTimeout      time.Duration
	idleFlowTimeout        time.Duration
	staleConnectionTimeout time.Duration

	isNetworkPolicyOnly bool
	tlsConfig           *api.FlowExporterTLSConfig

	// allowProtocolFilter specifies whether the incoming connections will be accepted
	allowProtocolFilter []string
}

type Destination struct {
	DestinationConfig

	k8sClient  kubernetes.Interface
	subscriber broadcaster.Subscriber
	ctChannel  chan broadcaster.Payload

	conntrackConnStore     *connections.ConntrackConnectionStore
	conntrackPriorityQueue *priorityqueue.ExpirePriorityQueue

	denyConnStore     *connections.DenyConnectionStore
	denyPriorityQueue *priorityqueue.ExpirePriorityQueue

	nodeRouteController *noderoute.Controller
	egressQuerier       querier.EgressQuerier
	podNetworkWait      *utilwait.Group

	exp       exporter.Interface
	connected bool

	exportConns      []connection.Connection
	numConnsExported uint64
}

func NewDestination(
	subscriber broadcaster.Subscriber,
	exporter exporter.Interface,
	k8sClient kubernetes.Interface,

	nodeRouteController *noderoute.Controller,
	podStore objectstore.PodStore,
	npQuerier querier.AgentNetworkPolicyInfoQuerier,
	proxier proxy.ProxyQuerier,
	egressQuerier querier.EgressQuerier,
	podNetworkWait *utilwait.Group,
	destinationConfig DestinationConfig,
) *Destination {
	ctChannel := make(chan broadcaster.Payload, 2)
	connectionStoreConfig := connections.ConnectionStoreConfig{
		ActiveFlowTimeout:      destinationConfig.activeFlowTimeout,
		IdleFlowTimeout:        destinationConfig.idleFlowTimeout,
		StaleConnectionTimeout: destinationConfig.staleConnectionTimeout,
		AllowedProtocols:       destinationConfig.allowProtocolFilter,
	}
	conntrackConnStore := connections.NewConntrackConnectionStore(ctChannel, npQuerier, podStore, proxier, podNetworkWait, connectionStoreConfig)
	denyConnStore := connections.NewDenyConnectionStore(npQuerier, podStore, proxier, connectionStoreConfig)

	return &Destination{
		DestinationConfig:      destinationConfig,
		subscriber:             subscriber,
		k8sClient:              k8sClient,
		ctChannel:              ctChannel,
		conntrackConnStore:     conntrackConnStore,
		conntrackPriorityQueue: conntrackConnStore.GetPriorityQueue(),
		denyConnStore:          denyConnStore,
		denyPriorityQueue:      denyConnStore.GetPriorityQueue(),

		nodeRouteController: nodeRouteController,
		egressQuerier:       egressQuerier,
		podNetworkWait:      podNetworkWait,

		exp:         exporter,
		exportConns: make([]connection.Connection, 0, maxConnsToExport*2),
	}
}

func (d *Destination) getExporterTLSConfig(ctx context.Context) (*exporter.TLSConfig, error) {
	if d.tlsConfig == nil {
		return nil, nil
	}

	var serverName = d.tlsConfig.ServerName
	if serverName == "" {
		serverName = d.address
	}

	tlsConfig := &exporter.TLSConfig{
		ServerName:    serverName,
		MinTLSVersion: d.tlsConfig.MinTLSVersion,
	}

	// if CA certificate, client certificate and key do not exist during initialization,
	// it will retry to obtain the credentials in next export cycle
	ca, err := getCACert(ctx, d.k8sClient, d.tlsConfig.CAConfigMap.Namespace, d.tlsConfig.CAConfigMap.Name)
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve CA cert: %w", err)
	}
	tlsConfig.CAData = ca

	if d.tlsConfig.ClientSecret != nil {
		cert, key, err := getClientCertKey(ctx, d.k8sClient, d.tlsConfig.ClientSecret.Namespace, d.tlsConfig.ClientSecret.Name)
		if err != nil {
			return nil, fmt.Errorf("cannot retrieve client cert and key: %v", err)
		}
		tlsConfig.CertData = cert
		tlsConfig.KeyData = key
	}

	return tlsConfig, nil
}

func (d *Destination) Connect(ctx context.Context) error {
	klog.V(4).Infof("Connecting consumer with address %s", d.address)

	addr, err := resolveCollectorAddress(ctx, d.k8sClient, d.address)
	if err != nil {
		return err
	}

	var tlsConfig *exporter.TLSConfig
	tlsConfig, err = d.getExporterTLSConfig(ctx)
	if err != nil {
		return err
	}

	if err = d.exp.ConnectToCollector(addr, tlsConfig); err != nil {
		return err
	}

	metrics.ReconnectionsToFlowCollector.Inc()
	d.connected = true
	return nil
}

func (d *Destination) resetFlowExporter() {
	d.exp.CloseConnToCollector()
	d.connected = false
}

func (d *Destination) Run(stopCh <-chan struct{}) {
	klog.InfoS("Started flow exporter for destination", "name", d.name, "destination", d.address)

	sub := d.subscriber.Subscribe()
	defer d.subscriber.Unsubscribe(sub)

	// Start the goroutine to periodically delete stale deny connections.
	go d.denyConnStore.RunPeriodicDeletion(stopCh)

	// Start the goroutine to process conntrack connections.
	go d.conntrackConnStore.Run(stopCh)

	exportTicker := time.NewTicker(d.activeFlowTimeout)
	defer exportTicker.Stop()
	for {
		select {
		case <-stopCh:
			d.resetFlowExporter()
			return
		case payload := <-sub.C():
			// It may a denied connection if the payload has a single connection.
			if len(payload.Conns) == 1 {
				conn := payload.Conns[0]
				if conn.IsDenyFlow {
					d.denyConnStore.AddOrUpdateConn(conn)
					continue
				}
			}
			d.ctChannel <- payload
		case <-exportTicker.C:
			if !d.connected {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				err := d.Connect(ctx)
				cancel()
				if err != nil {
					klog.ErrorS(err, "Error when connecting flow exporter to destination", "name", d.name)
					d.resetFlowExporter()
					// Initializing flow exporter fails, will retry in next cycle.
					exportTicker.Reset(d.activeFlowTimeout)
					continue
				}
			}

			nextExpireTime, err := d.sendFlowRecords()
			if err != nil {
				klog.ErrorS(err, "Error when sending expired flow records")
				// If there is an error when sending flow records because of
				// intermittent connectivity, we reset the connection to collector
				// and retry in the next export cycle to reinitialize the connection
				// and send flow records.
				d.resetFlowExporter()
				exportTicker.Reset(d.activeFlowTimeout)
				continue
			}
			exportTicker.Reset(nextExpireTime)
		}
	}
}

func (d *Destination) sendFlowRecords() (time.Duration, error) {
	currTime := time.Now()
	var expireTime1, expireTime2 time.Duration
	d.exportConns, expireTime1 = d.denyConnStore.GetExpiredConns(d.exportConns, currTime, maxConnsToExport)
	d.exportConns, expireTime2 = d.conntrackConnStore.GetExpiredConns(d.exportConns, currTime, maxConnsToExport)
	// Select the shorter time out among two connection stores to do the next round of export.
	nextExpireTime := getMinTime(expireTime1, expireTime2)
	for i := range d.exportConns {
		if err := d.exportConn(&d.exportConns[i]); err != nil {
			klog.ErrorS(err, "Error when sending expired flow record")
			return nextExpireTime, err
		}
	}
	// Clear expiredConns slice after exporting. Allocated memory is kept.
	d.exportConns = d.exportConns[:0]
	return nextExpireTime, nil
}

func (d *Destination) exportConn(conn *connection.Connection) error {
	conn.FlowType = d.findFlowType(*conn)
	if conn.FlowType == utils.FlowTypeUnsupported {
		return nil
	}
	if conn.FlowType == utils.FlowTypeToExternal {
		if conn.SourcePodNamespace != "" && conn.SourcePodName != "" {
			d.fillEgressInfo(conn)
		} else {
			// Skip exporting the Pod-to-External connection at the Egress Node if it's different from the Source Node
			return nil
		}
	}
	if err := d.exp.Export(conn); err != nil {
		return err
	}
	d.numConnsExported += 1
	if klog.V(5).Enabled() {
		klog.InfoS("Record for connection sent successfully", "flowKey", conn.FlowKey, "connection", conn)
	}
	return nil
}

func (d *Destination) findFlowType(conn connection.Connection) uint8 {
	// TODO: support Pod-To-External flows in network policy only mode.
	if d.isNetworkPolicyOnly {
		if conn.SourcePodName == "" || conn.DestinationPodName == "" {
			return utils.FlowTypeInterNode
		}
		return utils.FlowTypeIntraNode
	}

	if d.nodeRouteController == nil {
		klog.V(5).InfoS("Can't find flow type without nodeRouteController")
		return utils.FlowTypeUnspecified
	}
	srcIsPod, srcIsGw := d.nodeRouteController.LookupIPInPodSubnets(conn.FlowKey.SourceAddress)
	dstIsPod, dstIsGw := d.nodeRouteController.LookupIPInPodSubnets(conn.FlowKey.DestinationAddress)
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

func (d *Destination) fillEgressInfo(conn *connection.Connection) {
	egress, err := d.egressQuerier.GetEgress(conn.SourcePodNamespace, conn.SourcePodName)
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

func getMinTime(t1, t2 time.Duration) time.Duration {
	if t1 <= t2 {
		return t1
	}
	return t2
}

// resolveCollectorAddress resolves the collector address provided to an IP address if applicable or
// DNS name. The collector address can be a namespaced reference to a K8s Service, and hence needs
// resolution (to the Service's ClusterIP).
func resolveCollectorAddress(ctx context.Context, k8sClient kubernetes.Interface, address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	ns, name := k8sutil.SplitNamespacedName(host)
	if ns == "" {
		return address, nil
	}
	svc, err := k8sClient.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to resolve Service: %s/%s", ns, name)
	}
	if svc.Spec.ClusterIP == "" {
		return "", fmt.Errorf("ClusterIP is not available for Service: %s/%s", ns, name)
	}
	addr := net.JoinHostPort(svc.Spec.ClusterIP, port)
	klog.V(2).InfoS("Resolved Service address", "address", addr)
	return addr, nil
}
