package flowexporter

import (
	"context"
	"fmt"
	"net"
	"time"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/exporter"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/agent/metrics"
	api "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/querier"
	k8sutil "antrea.io/antrea/pkg/util/k8s"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

type ConsumerConfig struct {
	address string

	nodeName    string
	nodeUID     string
	obsDomainID uint32

	v4Enabled bool
	v6Enabled bool

	commProtocol      api.CommunicationProtocol
	transportProtocol api.TransportProtocol
}

type Consumer struct {
	*ConsumerConfig

	id string

	k8sClient     kubernetes.Interface
	egressQuerier querier.EgressQuerier

	conntrackConnStore          *connections.ConntrackConnectionStore
	conntackExpirePriorityQueue *priorityqueue.ExpirePriorityQueue

	denyConnStore                     *connections.DenyConnectionStore
	denyConnectionExpirePriorityQueue *priorityqueue.ExpirePriorityQueue

	exp       exporter.Interface
	connected bool

	expiredConns []connection.Connection

	// TODO: This is not the right way to do it. How do we pull this out?
	flowTypeFn func(conn connection.Connection) uint8
}

func (c *Consumer) GetID() string {
	return c.id
}

func (c *Consumer) Reset() {
	if c.exp == nil {
		return
	}

	c.exp.CloseConnToCollector()
	c.connected = false
}

func (c *Consumer) Run(stopCh <-chan struct{}) {
	klog.V(4).InfoS("Consumer started", "id", c.id)

	c.expiredConns = make([]connection.Connection, 0, 2*maxConnsToExport)

	conntrackStoreSubCh := c.conntrackConnStore.Subscribe(c.id)
	denyStoreSubCh := c.denyConnStore.Subscribe(c.id)

	defaultTimeout := c.conntackExpirePriorityQueue.ActiveFlowTimeout
	expireTimer := time.NewTimer(defaultTimeout)
	for {
		select {
		case <-stopCh:
			c.Reset()
			expireTimer.Stop()
			return
		case msg := <-conntrackStoreSubCh:
			klog.V(5).InfoS("DEBUG: received event from conntrack store", "msg", msg)
			connKey := connection.NewConnectionKey(msg.Conn)

			switch msg.Action {
			case connections.AddOrUpdate:
				existingItem, exists := c.conntackExpirePriorityQueue.KeyToItem[connKey]
				if !exists {
					// If the connKey:pqItem pair does not exist in the map, it shows the
					// conn was inactive, and was removed from PQ and map. Since it becomes
					// active again now, we create a new pqItem and add it to PQ and map.
					c.conntackExpirePriorityQueue.WriteItemToQueue(connKey, msg.Conn)
				} else {
					c.conntackExpirePriorityQueue.Update(existingItem, existingItem.ActiveExpireTime,
						time.Now().Add(c.conntackExpirePriorityQueue.IdleFlowTimeout))
				}
			case connections.Remove:
				c.conntackExpirePriorityQueue.RemoveItemFromMap(msg.Conn)
			case connections.Requeue:
				existingItem, exists := c.conntackExpirePriorityQueue.KeyToItem[connKey]
				if exists {
					// TODO: Requeue time might be better included as part of message.
					c.conntackExpirePriorityQueue.ResetActiveExpireTimeAndPush(existingItem, time.Now())
				}
			}
		case msg := <-denyStoreSubCh:
			klog.V(5).InfoS("DEBUG: received event from deny store", "msg", msg)
			connKey := connection.NewConnectionKey(msg.Conn)

			switch msg.Action {
			case connections.AddOrUpdate:
				existingItem, exists := c.denyConnectionExpirePriorityQueue.KeyToItem[connKey]
				if !exists {
					// If the connKey:pqItem pair does not exist in the map, it shows the
					// conn was inactive, and was removed from PQ and map. Since it becomes
					// active again now, we create a new pqItem and add it to PQ and map.
					c.denyConnectionExpirePriorityQueue.WriteItemToQueue(connKey, msg.Conn)
				} else {
					c.denyConnectionExpirePriorityQueue.Update(existingItem, existingItem.ActiveExpireTime,
						time.Now().Add(c.denyConnectionExpirePriorityQueue.IdleFlowTimeout))
				}
			case connections.Remove:
				c.denyConnectionExpirePriorityQueue.RemoveItemFromMap(msg.Conn)
			case connections.Requeue:
				existingItem, exists := c.denyConnectionExpirePriorityQueue.KeyToItem[connKey]
				if exists {
					// TODO: Requeue time might be better included as part of message.
					c.denyConnectionExpirePriorityQueue.ResetActiveExpireTimeAndPush(existingItem, time.Now())
				}
			}
		case <-expireTimer.C:
			klog.V(5).InfoS("DEBUG: Begin sending flow records")

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := c.Connect(ctx)
			cancel()
			if err != nil {
				klog.ErrorS(err, "Error when initializing flow exporter consumer")
				c.Reset()
				// Initializing flow exporter fails, will retry in next cycle.
				expireTimer.Reset(defaultTimeout)
				continue
			}

			// Pop out the expired connections from the conntrack priority queue
			// and the deny priority queue, and send the data records.
			nextExpireTime, err := c.sendFlowRecords()
			if err != nil {
				klog.ErrorS(err, "Error when sending expired flow records")
				// If there is an error when sending flow records because of
				// intermittent connectivity, we reset the connection to collector
				// and retry in the next export cycle to reinitialize the connection
				// and send flow records.
				expireTimer.Reset(defaultTimeout)
				continue
			}
			expireTimer.Reset(nextExpireTime)
		}
	}
}

func (c *Consumer) sendFlowRecords() (time.Duration, error) {
	currTime := time.Now()
	var expireTime1, expireTime2 time.Duration
	// We export records from denyConnStore first, then conntrackConnStore. We enforce the ordering to handle a
	// special case: for an inter-node connection with egress drop network policy, both conntrackConnStore and
	// denyConnStore from the same Node will send out records to Flow Aggregator. If the record from conntrackConnStore
	// arrives FA first, FA will not be able to capture the deny network policy metadata, and it will keep waiting
	// for a record from destination Node to finish flow correlation until timeout. Later on we probably should
	// consider doing a record deduplication between conntrackConnStore and denyConnStore before exporting records.
	c.expiredConns, expireTime1 = c.denyConnStore.GetExpiredConns(c.denyConnectionExpirePriorityQueue, c.expiredConns, currTime, maxConnsToExport)
	c.expiredConns, expireTime2 = c.conntrackConnStore.GetExpiredConns(c.conntackExpirePriorityQueue, c.expiredConns, currTime, maxConnsToExport)
	// Select the shorter time out among two connection stores to do the next round of export.
	nextExpireTime := getMinTime(expireTime1, expireTime2)
	klog.V(5).InfoS("DEBUG: About to send flows", "Len", len(c.expiredConns))
	for i := range c.expiredConns {
		conn := &c.expiredConns[i]
		klog.InfoS("DEBUG: Sending flow records", "Connection", conn)
		if err := c.exportConn(conn); err != nil {
			klog.ErrorS(err, "Error when sending expired flow record")
			return nextExpireTime, err
		}
	}
	// Clear expiredConns slice after exporting. Allocated memory is kept.
	c.expiredConns = c.expiredConns[:0]
	klog.V(5).InfoS("DEBUG: Send complete")
	return nextExpireTime, nil
}

func (c *Consumer) exportConn(conn *connection.Connection) error {
	klog.V(5).InfoS("DEBUG: ExportConn", "Key", conn.FlowKey)
	conn.FlowType = c.flowTypeFn(*conn)
	if conn.FlowType == utils.FlowTypeUnsupported {
		return nil
	}
	if conn.FlowType == utils.FlowTypeToExternal {
		if conn.SourcePodNamespace != "" && conn.SourcePodName != "" {
			c.fillEgressInfo(conn)
		} else {
			// Skip exporting the Pod-to-External connection at the Egress Node if it's different from the Source Node
			return nil
		}
	}

	if err := c.Export(conn); err != nil {
		c.Reset()
		return err
	}

	// exp.numConnsExported += 1
	klog.V(5).InfoS("Record for connection sent successfully", "flowKey", conn.FlowKey, "connection", conn)
	return nil
}

func (c *Consumer) fillEgressInfo(conn *connection.Connection) {
	egress, err := c.egressQuerier.GetEgress(conn.SourcePodNamespace, conn.SourcePodName)
	if err != nil {
		// Egress is not enabled or no Egress is applied to this Pod
		return
	}

	// TODO: This should only happen once.
	// Right now this happens with ALL consumers which is bad. We're duplicating the work.
	conn.EgressName = egress.Name
	conn.EgressUID = string(egress.UID)
	conn.EgressIP = egress.EgressIP
	conn.EgressNodeName = egress.EgressNode
	if klog.V(5).Enabled() {
		klog.InfoS("Filling Egress Info for flow", "Egress", conn.EgressName, "EgressIP", conn.EgressIP, "EgressNode", conn.EgressNodeName, "SourcePod", klog.KRef(conn.SourcePodNamespace, conn.SourcePodName))
	}
}

func (c *Consumer) Connect(ctx context.Context) error {
	if c.connected {
		klog.V(5).Info("DEBUG: Already connected", "ID", c.GetID())
		return nil
	}

	klog.V(4).Infof("DEBUG: Connecting consumer with address %s", c.address)

	if c.exp == nil {
		c.exp = c.createExporter()
	}

	addr, name, err := c.resolveAddress(ctx)
	if err != nil {
		return err
	}

	var tlsConfig *exporter.TLSConfig
	if c.transportProtocol == api.ProtoTLS {
		// if CA certificate, client certificate and key do not exist during initialization,
		// it will retry to obtain the credentials in next export cycle
		ca, err := getCACert(ctx, c.k8sClient)
		if err != nil {
			return fmt.Errorf("cannot retrieve CA cert: %w", err)
		}
		cert, key, err := getClientCertKey(ctx, c.k8sClient)
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

	err = c.exp.ConnectToCollector(addr, tlsConfig)
	if err != nil {
		return err
	}

	c.connected = true
	metrics.ReconnectionsToFlowCollector.Inc()
	return nil
}

func (c *Consumer) Export(conn *connection.Connection) error {
	if c.exp == nil {
		return nil // TODO: Return an error??
	}
	klog.V(2).InfoS("DEBUG: Exporting connection", "Consumer", c.address)
	return c.exp.Export(conn)
}

// resolveAddress resolves the collector address provided in the config to an IP address or
// DNS name. The collector address can be a namespaced reference to a K8s Service, and hence needs
// resolution (to the Service's ClusterIP). The function also returns a server name to be used in
// the TLS handshake (when TLS is enabled).
func (c *Consumer) resolveAddress(ctx context.Context) (string, string, error) {
	host, port, err := net.SplitHostPort(c.address)
	if err != nil {
		return "", "", err
	}
	ns, name := k8sutil.SplitNamespacedName(host)
	if ns == "" {
		return c.address, "", nil
	}
	svc, err := c.k8sClient.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("failed to resolve Service: %s/%s", ns, name)
	}
	if svc.Spec.ClusterIP == "" {
		return "", "", fmt.Errorf("ClusterIP is not available for Service: %s/%s", ns, name)
	}
	addr := net.JoinHostPort(svc.Spec.ClusterIP, port)
	dns := fmt.Sprintf("%s.%s.svc", name, ns)
	klog.V(2).InfoS("DEBUG: Resolved Service address", "address", addr)
	return addr, dns, nil
}

func (fe *Consumer) createExporter() exporter.Interface {
	switch fe.commProtocol {
	case api.ProtoGRPC:
		// TODO: Validate gRPC config
		return exporter.NewGRPCExporter(fe.nodeName, fe.nodeUID, fe.obsDomainID)
	case api.ProtoIPFix:
		// TODO: Validate ipfix config
		var collectorProto api.TransportProtocol
		if fe.transportProtocol == api.ProtoTLS {
			collectorProto = api.ProtoTCP
		} else {
			collectorProto = fe.transportProtocol
		}
		return exporter.NewIPFIXExporter(string(collectorProto), fe.nodeName, fe.obsDomainID, fe.v4Enabled, fe.v6Enabled)
	default:
		klog.V(4).InfoS("DEBUG: invalid protocol for FlowExporterTarget", "communicationProtocol", fe.commProtocol, "transportProtocol", fe.transportProtocol)
		return nil
	}
}
