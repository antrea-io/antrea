// Copyright 2025 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package flowexporter

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"strings"
	"sync/atomic"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/exporter"
	"antrea.io/antrea/pkg/agent/flowexporter/filter"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/agent/metrics"
	api "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	k8sutil "antrea.io/antrea/pkg/util/k8s"
)

const (
	grpcExporterProtocol  string = "grpc"
	ipfixExporterProtocol string = "ipfix"
)

type exporterProtocol interface {
	Name() string
	TransportProtocol() api.FlowExporterTransportProtocol
}

type ConsumerConfig struct {
	name    string
	address string

	nodeName    string
	nodeUID     string
	obsDomainID uint32

	v4Enabled bool
	v6Enabled bool

	protocol exporterProtocol

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

	protocolFilter   filter.ProtocolFilter
	exportConns      []*connection.Connection
	numFlowsExported atomic.Int64
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

	klog.V(4).Infof("Connecting consumer with address %s", c.address)

	if c.exp == nil {
		c.exp = c.createExporter()
	}

	addr, name, err := c.resolveAddress(ctx)
	if err != nil {
		return err
	}

	var tlsConfig *exporter.TLSConfig
	tlsConfig, err = c.getExporterTLSConfig(ctx, name)
	if err != nil {
		return err
	}

	if err = c.exp.ConnectToCollector(addr, tlsConfig); err != nil {
		return err
	}

	metrics.ReconnectionsToFlowCollector.Inc()
	c.connected = true
	return nil
}

func (c *Consumer) getExporterTLSConfig(ctx context.Context, dnsName string) (*exporter.TLSConfig, error) {
	if c.protocol.TransportProtocol() != api.FlowExporterTransportTLS {
		return nil, nil
	}
	// TODO: Extend the CRD to support custom TLS config
	var namespace = CAConfigMapNamespace
	if dnsName != "" {
		parts := strings.Split(dnsName, ".")
		namespace = parts[1]
	}

	// if CA certificate, client certificate and key do not exist during initialization,
	// it will retry to obtain the credentials in next export cycle
	ca, err := getCACert(ctx, c.k8sClient, namespace)
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve CA cert: %w", err)
	}
	cert, key, err := getClientCertKey(ctx, c.k8sClient, namespace)
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve client cert and key: %v", err)
	}
	return &exporter.TLSConfig{
		ServerName: dnsName,
		CAData:     ca,
		CertData:   cert,
		KeyData:    key,
	}, nil
}

func (c *Consumer) Export(conn *connection.Connection) error {
	if c.exp == nil {
		return nil // TODO: Return an error??
	}

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
	klog.V(2).InfoS("Resolved Service address", "address", addr)
	return addr, dns, nil
}

func (c *Consumer) createExporter() exporter.Interface {
	switch c.protocol.Name() {
	case grpcExporterProtocol:
		return exporter.NewGRPCExporter(c.nodeName, c.nodeUID, c.obsDomainID)
	case ipfixExporterProtocol:
		var collectorProto string
		if c.protocol.TransportProtocol() == api.FlowExporterTransportTLS {
			collectorProto = "tcp"
		} else {
			collectorProto = string(c.protocol.TransportProtocol())
		}
		return exporter.NewIPFIXExporter(collectorProto, c.nodeName, c.obsDomainID, c.v4Enabled, c.v6Enabled)
	default:
		klog.V(5).InfoS("invalid protocol for FlowExporterDestination", "exporterProtocol", c.protocol.Name(), "transportProtocol", c.protocol.TransportProtocol())
		return nil
	}
}

func (c *Consumer) Run(stopCh <-chan struct{}) {
	klog.Info("Consumer started")
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
				c.handleUpdatedConns(msg.Conns, msg.L7Events)
			}
		case <-exportTicker.C:
			if !c.connected {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				err := c.Connect(ctx)
				cancel()
				if err != nil {
					klog.ErrorS(err, "Error when connecting flow exporter to destination", "name", c.name)
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

		if err := c.Export(conn); err != nil {
			klog.ErrorS(err, "Error when sending flow record")
			return nextExpireTime, err
		}

		c.numFlowsExported.Add(1)
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
	for range maxSize {
		pqItem := c.expirePriorityQueue.GetTopExpiredItem(currTime)
		if pqItem == nil {
			break
		}
		key := connection.NewConnectionKey(pqItem.Conn)

		copy := *pqItem.Conn
		conn := &copy

		oldState := c.prevStates[key]
		conn.PreviousStats = oldState.stats
		conn.PrevTCPState = oldState.tcpState

		conn.IsActive = utils.CheckConntrackConnActive(conn)

		// Connection is idle
		if pqItem.IdleExpireTime.Before(currTime) {
			conn.IsActive = false
		}

		if !conn.IsActive || (!conn.IsDenyFlow && utils.IsConnectionDying(conn)) {
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
	// cache l7Events to use during export
	maps.Copy(c.l7Events, l7Events)

	for _, conn := range conns {
		if !c.protocolFilter.Allow(conn.FlowKey.Protocol) {
			continue
		}

		key := connection.NewConnectionKey(conn)
		item, ok := c.expirePriorityQueue.KeyToItem[key]

		// Incoming connection is a new connection with same key
		if ok && conn.ID != item.Conn.ID {
			delete(c.prevStates, key)
			ok = false
		}

		_, isL7Conn := l7Events[key]
		if !isL7Conn {
			oldState, ok := c.prevStates[key]
			// Check if there is any activity on this conn.
			// If there is no activity since the last time we sent it then no point in
			// updating it's spot in the queue.
			if ok && (!utils.HasActivity(oldState.stats, conn.OriginalStats) &&
				conn.TCPState == oldState.tcpState) {
				continue
			}
		}

		if !ok {
			c.expirePriorityQueue.WriteItemToQueue(key, conn)
		} else {
			c.expirePriorityQueue.Update(item, item.ActiveExpireTime, time.Now().Add(c.expirePriorityQueue.IdleFlowTimeout))
		}
	}
}

func (c *Consumer) handleDeletedConns(conns []*connection.Connection) {
	for _, conn := range conns {
		key := connection.NewConnectionKey(conn)

		delete(c.prevStates, key)
		delete(c.l7Events, key)
		item := c.expirePriorityQueue.Remove(key)
		if item != nil {
			klog.V(4).InfoS("Conn removed from pq due to stale timeout", "key", key)
		}
	}
}
