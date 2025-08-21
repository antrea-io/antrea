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
}

type Consumer struct {
	*ConsumerConfig

	id string

	k8sClient kubernetes.Interface

	expirePriorityQueue *priorityqueue.ExpirePriorityQueue

	conntrackConnStore *connections.ConntrackConnectionStore
	denyConnStore      *connections.DenyConnectionStore

	exp       exporter.Interface
	connected bool
}

func (c *Consumer) Reset() {
	if c.exp == nil {
		return
	}

	c.exp.CloseConnToCollector()
	c.connected = false
}

func (c *Consumer) Run(stopCh <-chan struct{}) {
	klog.V(4).Info("Consumer started", "id", c.id)

	defaultTimeout := c.expirePriorityQueue.ActiveFlowTimeout
	expireTimer := time.NewTimer(defaultTimeout)
	for {
		select {
		case <-stopCh:
			c.Reset()
			expireTimer.Stop()
			return
		case <-expireTimer.C:
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

			// Get

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
	return 0, nil
}

// TODO:
const maxSize = maxConnsToExport

func (c *Consumer) getConntrackFlowsToSend() ([]connection.Connection, time.Duration) {
	currTime := time.Now()
	expiredConns := make([]connection.Connection, 0, maxSize)
	for i := 0; i < maxSize; i++ {
		pqItem := c.expirePriorityQueue.GetTopExpiredItem(currTime)
		if pqItem == nil {
			break
		}
		expiredConns = append(expiredConns, *pqItem.Conn)
		if utils.IsConnectionDying(pqItem.Conn) {
			// If a conntrack connection is in dying state or connection is not
			// in the conntrack table, we set the ReadyToDelete flag to true to
			// do the deletion later.
			pqItem.Conn.ReadyToDelete = true
		}
		if pqItem.IdleExpireTime.Before(currTime) {
			// No packets have been received during the idle timeout interval,
			// the connection is therefore considered inactive.
			pqItem.Conn.IsActive = false
		}
		cs.UpdateConnAndQueue(pqItem, currTime)
	}
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
	return nil
}

func (c *Consumer) Export(conn *connection.Connection) error {
	if c.exp == nil {
		return nil // TODO: Return an error??
	}
	klog.V(2).InfoS("DEBUG: Exporting connection", "Consumer", c.address)
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
		klog.V(4).InfoS("invalid protocol for FlowExporterTarget", "communicationProtocol", fe.commProtocol, "transportProtocol", fe.transportProtocol)
		return nil
	}
}
