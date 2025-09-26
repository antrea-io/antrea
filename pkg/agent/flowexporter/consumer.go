package flowexporter

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"time"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/exporter"
	"antrea.io/antrea/pkg/agent/flowexporter/filter"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	api "antrea.io/antrea/pkg/apis/crd/v1beta1"
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

	activeFlowTimeout time.Duration
	idleFlowTimeout   time.Duration

	// allowProtocolFilter specifies whether the incoming connections will be accepted
	allowProtocolFilter []string
}

type prevState struct {
	stats    connection.Stats
	tcpState string
}

type Consumer struct {
	*ConsumerConfig

	k8sClient kubernetes.Interface
	store     connections.StoreSubscriber

	expirePriorityQueue *priorityqueue.ExpirePriorityQueue

	exp       exporter.Interface
	connected bool

	l7Events   map[connection.ConnectionKey]connections.L7ProtocolFields
	prevStates map[connection.ConnectionKey]prevState

	protocolFilter filter.ProtocolFilter
	exportConns    []*connection.Connection
}

func CreateConsumer(k8sClient kubernetes.Interface, store connections.StoreSubscriber, config ConsumerConfig) *Consumer {
	c := &Consumer{
		ConsumerConfig:      &config,
		k8sClient:           k8sClient,
		expirePriorityQueue: priorityqueue.NewExpirePriorityQueue(config.activeFlowTimeout, config.idleFlowTimeout),
		store:               store,
		prevStates:          make(map[connection.ConnectionKey]prevState),
		exportConns:         make([]*connection.Connection, 0, maxConnsToExport),
		protocolFilter:      filter.NewProtocolFilter(config.allowProtocolFilter),
		l7Events:            make(map[connection.ConnectionKey]connections.L7ProtocolFields),
	}

	return c
}

func (c *Consumer) Reset() {
	if c.exp == nil {
		return
	}

	c.exp.CloseConnToCollector()
	c.connected = false
}

func (c *Consumer) Connect(ctx context.Context) error {
	if c.connected {
		return nil
	}

	klog.V(5).Infof("Connecting consumer with address %s", c.address)

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

	if err = c.exp.ConnectToCollector(addr, tlsConfig); err != nil {
		return err
	}

	c.connected = true
	return nil
}

func (c *Consumer) Export(conn *connection.Connection) error {
	if c.exp == nil {
		return nil // TODO: Return an error??
	}
	klog.V(5).InfoS("DEBUG A2: Exporting connection", "Consumer", c.address, "conn", conn)
	return c.exp.Export(conn)
}

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
	klog.V(2).InfoS("Resolved Service address", "address", addr)
	return addr, dns, nil
}

func (fe *Consumer) createExporter() exporter.Interface {
	switch fe.commProtocol {
	case api.ProtoGRPC:
		// TODO Andrew: Validate gRPC config
		return exporter.NewGRPCExporter(fe.nodeName, fe.nodeUID, fe.obsDomainID)
	case api.ProtoIPFix:
		// TODO Andrew: Validate ipfix config
		var collectorProto api.TransportProtocol
		if fe.transportProtocol == api.ProtoTLS {
			collectorProto = api.ProtoTCP
		} else {
			collectorProto = fe.transportProtocol
		}
		return exporter.NewIPFIXExporter(string(collectorProto), fe.nodeName, fe.obsDomainID, fe.v4Enabled, fe.v6Enabled)
	default:
		klog.V(5).InfoS("invalid protocol for FlowExporterTarget", "communicationProtocol", fe.commProtocol, "transportProtocol", fe.transportProtocol)
		return nil
	}
}

func (c *Consumer) Run(stopCh <-chan struct{}) {
	sub := c.store.Subscribe()
	defer c.store.Unsubscribe(sub)

	exportTicker := time.NewTicker(c.activeFlowTimeout)
	defer exportTicker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case msg := <-sub.C():
			if msg.Deleted {
				c.handleDeletedConns(msg.Conns)
			} else {
				maps.Copy(c.l7Events, msg.L7Events)
				c.handleUpdatedConns(msg.Conns, msg.L7Events)
			}
		case <-exportTicker.C:
			if !c.connected {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				err := c.Connect(ctx)
				cancel()
				if err != nil {
					klog.ErrorS(err, "Error when initializing flow exporter")
					c.Reset()
					// Initializing flow exporter fails, will retry in next cycle.
					exportTicker.Reset(c.activeFlowTimeout)
					continue
				}
			}

			nextExpireTime, err := c.sendFlowRecords()
			if err != nil {
				klog.ErrorS(err, "Error when sending expired flow records")
				// If there is an error when sending flow records because of
				// intermittent connectivity, we reset the connection to collector
				// and retry in the next export cycle to reinitialize the connection
				// and send flow records.
				c.Reset()
				exportTicker.Reset(c.activeFlowTimeout)
				continue
			}
			exportTicker.Reset(nextExpireTime)
		}
	}
}

func (c *Consumer) handleUpdatedL7Events(conns []*connection.Connection, l7Events map[connection.ConnectionKey]connections.L7ProtocolFields) {

	for _, conn := range conns {
		connKey := connection.NewConnectionKey(conn)

		// In case L7 event is received after the last planned export of the TCP connection, add
		// the event back to the queue to be exported in next export cycle
		_, ok := c.expirePriorityQueue.KeyToItem[connKey]
		if !ok {
			c.expirePriorityQueue.WriteItemToQueue(connKey, conn)
		}
	}

}

func (c *Consumer) sendFlowRecords() (time.Duration, error) {
	currTime := time.Now()
	var nextExpireTime time.Duration
	// We export records from denyConnStore first, then conntrackConnStore. We enforce the ordering to handle a
	// special case: for an inter-node connection with egress drop network policy, both conntrackConnStore and
	// denyConnStore from the same Node will send out records to Flow Aggregator. If the record from conntrackConnStore
	// arrives FA first, FA will not be able to capture the deny network policy metadata, and it will keep waiting
	// for a record from destination Node to finish flow correlation until timeout. Later on we probably should
	// consider doing a record deduplication between conntrackConnStore and denyConnStore before exporting records.
	c.exportConns, nextExpireTime = c.getExpiredConns(c.exportConns, currTime, maxConnsToExport)
	// Select the shorter time out among two connection stores to do the next round of export.
	for i := range c.exportConns {
		conn := c.exportConns[i]
		c.fillL7Info(conn)

		klog.InfoS("DEBUG: Sending flow records", "Connection", conn)
		if err := c.Export(conn); err != nil {
			klog.ErrorS(err, "Error when sending expired flow record")
			return nextExpireTime, err
		}

		connKey := connection.NewConnectionKey(conn)
		delete(c.l7Events, connKey)
	}
	// Clear exportConns slice after exporting. Allocated memory is kept.
	c.exportConns = c.exportConns[:0]
	return nextExpireTime, nil
}

func (c *Consumer) fillL7Info(conn *connection.Connection) {
	connKey := connection.NewConnectionKey(conn)
	l7Event, ok := c.l7Events[connKey]
	if !ok || len(l7Event.Http) == 0 {
		return
	}

	jsonBytes, err := json.Marshal(l7Event.Http)
	if err != nil {
		klog.ErrorS(err, "Converting l7Event http failed")
	}
	conn.HttpVals += string(jsonBytes)
	conn.AppProtocolName = "http"
}

func (c *Consumer) getExpiredConns(expiredConns []*connection.Connection, currTime time.Time, maxSize int) ([]*connection.Connection, time.Duration) {
	for i := 0; i < maxSize; i++ {
		pqItem := c.expirePriorityQueue.GetTopExpiredItem(currTime)
		if pqItem == nil {
			break
		}
		key := connection.NewConnectionKey(pqItem.Conn)

		conn := pqItem.Conn.Clone()

		oldState := c.prevStates[key]
		conn.PreviousStats = oldState.stats
		conn.PrevTCPState = oldState.tcpState

		conn.IsActive = utils.CheckConntrackConnActive(conn)

		isIdle := pqItem.IdleExpireTime.Before(currTime)
		if isIdle {
			conn.IsActive = false
		}

		if utils.IsConnectionDying(pqItem.Conn) || !conn.IsActive {
			c.expirePriorityQueue.RemoveItemFromMap(pqItem.Conn) // TODO Andrew: Why can't we just use `Remove`?
		} else {
			// For active connections, we update their "prev" stats fields,
			// reset active expire time and push back into the PQ.
			c.prevStates[key] = prevState{
				stats:    conn.OriginalStats,
				tcpState: conn.TCPState,
			}
			c.expirePriorityQueue.ResetActiveExpireTimeAndPush(pqItem, currTime)
		}

		expiredConns = append(expiredConns, conn)
	}

	return expiredConns, c.expirePriorityQueue.GetExpiryFromExpirePriorityQueue()
}

func (c *Consumer) handleUpdatedConns(conns []*connection.Connection, l7Events map[connection.ConnectionKey]connections.L7ProtocolFields) {
	for _, conn := range conns {
		if !c.protocolFilter.Allow(conn.FlowKey.Protocol) {
			continue
		}

		key := connection.NewConnectionKey(conn)
		existingItem, ok := c.expirePriorityQueue.KeyToItem[key]
		if ok {
			if existingItem.Conn.IsDenyFlow && !conn.IsDenyFlow {
				// Drop flows that are denied
				continue
			}
			if conn.IsDenyFlow && !existingItem.Conn.IsDenyFlow {
				// Deny flows take priority when exporting.
				c.expirePriorityQueue.RemoveItemFromMap(conn)
				delete(c.prevStates, key)
			}
		}
		_, isL7Conn := l7Events[key]
		oldState, ok := c.prevStates[key]
		// Check if there is any activity on this conn.
		// If there is no activity since the last time we sent it then no point in
		// updating it's spot in the queue.
		if !isL7Conn && ok && !((conn.OriginalStats.Packets > oldState.stats.Packets) ||
			(conn.OriginalStats.ReversePackets > oldState.stats.ReversePackets) ||
			(conn.TCPState != oldState.tcpState)) {
			continue
		}

		if item, ok := c.expirePriorityQueue.KeyToItem[key]; !ok {
			c.expirePriorityQueue.WriteItemToQueue(key, conn)
		} else {
			c.expirePriorityQueue.Update(item, item.ActiveExpireTime, time.Now().Add(c.idleFlowTimeout))
		}
	}
}

func (c *Consumer) handleDeletedConns(conns []*connection.Connection) {
	for _, conn := range conns {
		key := connection.NewConnectionKey(conn)

		delete(c.prevStates, key)
		item := c.expirePriorityQueue.Remove(key)
		if item != nil {
			klog.V(4).InfoS("Conn removed from cs pq due to stale timeout", "key", key, "conn", item.Conn)
		}
	}
}
