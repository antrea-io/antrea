// Copyright 2024 Antrea Authors
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

package monitortool

import (
	"context"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	"antrea.io/antrea/pkg/agent/client"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
)

// #nosec G404: random number generator not used for security purposes.
var icmpEchoID = rand.Int31n(1 << 16)

const (
	ipv4ProtocolICMPRaw = "ip4:icmp"
	ipv6ProtocolICMPRaw = "ip6:ipv6-icmp"
	protocolICMP        = 1
	protocolICMPv6      = 58
	minReportInterval   = 10 * time.Second
)

type PacketListener interface {
	ListenPacket(network, address string) (net.PacketConn, error)
}

type ICMPListener struct{}

func (l *ICMPListener) ListenPacket(network, address string) (net.PacketConn, error) {
	return icmp.ListenPacket(network, address)
}

// NodeLatencyMonitor is a tool to monitor the latency of the Node.
type NodeLatencyMonitor struct {
	// latencyStore is the cache to store the latency of each Nodes.
	latencyStore *LatencyStore
	// latencyConfigChanged is the channel to notify the latency config changed.
	latencyConfigChanged chan latencyConfig
	// isIPv4Enabled is the flag to indicate whether the IPv4 is enabled.
	isIPv4Enabled bool
	// isIPv6Enabled is the flag to indicate whether the IPv6 is enabled.
	isIPv6Enabled bool

	// antreaClientProvider provides interfaces to get antreaClient, which will be used to report the statistics
	antreaClientProvider client.AntreaClientProvider
	// nodeName is the name of the current Node, used to filter out the current Node from the latency monitor.
	nodeName string

	nodeInformerSynced cache.InformerSynced
	nlmInformerSynced  cache.InformerSynced

	clock    clock.WithTicker
	listener PacketListener

	icmpSeqNum atomic.Uint32
}

// latencyConfig is the config for the latency monitor.
type latencyConfig struct {
	// Enable is the flag to enable the latency monitor.
	Enable bool
	// Interval is the interval time to ping all Nodes.
	Interval time.Duration
}

// NewNodeLatencyMonitor creates a new NodeLatencyMonitor.
func NewNodeLatencyMonitor(
	antreaClientProvider client.AntreaClientProvider,
	nodeInformer coreinformers.NodeInformer,
	nlmInformer crdinformers.NodeLatencyMonitorInformer,
	nodeConfig *config.NodeConfig,
	trafficEncapMode config.TrafficEncapModeType,
) *NodeLatencyMonitor {
	m := &NodeLatencyMonitor{
		latencyStore:         NewLatencyStore(trafficEncapMode.IsNetworkPolicyOnly()),
		latencyConfigChanged: make(chan latencyConfig),
		antreaClientProvider: antreaClientProvider,
		nodeInformerSynced:   nodeInformer.Informer().HasSynced,
		nlmInformerSynced:    nlmInformer.Informer().HasSynced,
		nodeName:             nodeConfig.Name,
		clock:                clock.RealClock{},
		listener:             &ICMPListener{},
	}

	m.isIPv4Enabled, _ = config.IsIPv4Enabled(nodeConfig, trafficEncapMode)
	m.isIPv6Enabled, _ = config.IsIPv6Enabled(nodeConfig, trafficEncapMode)

	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    m.onNodeAdd,
		UpdateFunc: m.onNodeUpdate,
		DeleteFunc: m.onNodeDelete,
	})

	nlmInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    m.onNodeLatencyMonitorAdd,
		UpdateFunc: m.onNodeLatencyMonitorUpdate,
		DeleteFunc: m.onNodeLatencyMonitorDelete,
	})

	return m
}

// Is current node
func (m *NodeLatencyMonitor) isCurrentNode(node *corev1.Node) bool {
	return node.Name == m.nodeName
}

// onNodeAdd is the event handler for adding Node.
func (m *NodeLatencyMonitor) onNodeAdd(obj interface{}) {
	node := obj.(*corev1.Node)
	if m.isCurrentNode(node) {
		return
	}

	m.latencyStore.addNode(node)

	klog.V(4).InfoS("Node added", "Node", klog.KObj(node))
}

// onNodeUpdate is the event handler for updating Node.
func (m *NodeLatencyMonitor) onNodeUpdate(oldObj, newObj interface{}) {
	node := newObj.(*corev1.Node)
	if m.isCurrentNode(node) {
		return
	}

	m.latencyStore.updateNode(node)

	klog.V(4).InfoS("Node updated", "Node", klog.KObj(node))
}

// onNodeDelete is the event handler for deleting Node.
func (m *NodeLatencyMonitor) onNodeDelete(obj interface{}) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(nil, "Received unexpected object", "obj", obj)
			return
		}
		node, ok = deletedState.Obj.(*corev1.Node)
		if !ok {
			klog.ErrorS(nil, "DeletedFinalStateUnknown contains non-Node object", "obj", deletedState.Obj)
			return
		}
	}

	if m.isCurrentNode(node) {
		return
	}

	m.latencyStore.deleteNode(node)
}

// onNodeLatencyMonitorAdd is the event handler for adding NodeLatencyMonitor.
func (m *NodeLatencyMonitor) onNodeLatencyMonitorAdd(obj interface{}) {
	nlm := obj.(*v1alpha1.NodeLatencyMonitor)
	klog.V(4).InfoS("NodeLatencyMonitor added", "NodeLatencyMonitor", klog.KObj(nlm))

	m.updateLatencyConfig(nlm)
}

// onNodeLatencyMonitorUpdate is the event handler for updating NodeLatencyMonitor.
func (m *NodeLatencyMonitor) onNodeLatencyMonitorUpdate(oldObj, newObj interface{}) {
	oldNLM := oldObj.(*v1alpha1.NodeLatencyMonitor)
	newNLM := newObj.(*v1alpha1.NodeLatencyMonitor)
	klog.V(4).InfoS("NodeLatencyMonitor updated", "NodeLatencyMonitor", klog.KObj(newNLM))

	if oldNLM.GetGeneration() == newNLM.GetGeneration() {
		return
	}

	m.updateLatencyConfig(newNLM)
}

// updateLatencyConfig updates the latency config based on the NodeLatencyMonitor CRD.
func (m *NodeLatencyMonitor) updateLatencyConfig(nlm *v1alpha1.NodeLatencyMonitor) {
	pingInterval := time.Duration(nlm.Spec.PingIntervalSeconds) * time.Second

	latencyConfig := latencyConfig{
		Enable:   true,
		Interval: pingInterval,
	}

	m.latencyConfigChanged <- latencyConfig
}

// onNodeLatencyMonitorDelete is the event handler for deleting NodeLatencyMonitor.
func (m *NodeLatencyMonitor) onNodeLatencyMonitorDelete(obj interface{}) {
	klog.V(4).InfoS("NodeLatencyMonitor deleted")
	latencyConfig := latencyConfig{Enable: false}

	m.latencyConfigChanged <- latencyConfig
}

// sendPing sends an ICMP message to the target IP address.
func (m *NodeLatencyMonitor) sendPing(socket net.PacketConn, addr net.IP) error {
	var requestType icmp.Type

	ip := &net.IPAddr{IP: addr}

	if addr.To4() == nil {
		requestType = ipv6.ICMPTypeEchoRequest
	} else {
		requestType = ipv4.ICMPTypeEcho
	}

	timeStart := m.clock.Now()
	seqID := m.getICMPSeqNum()
	body := &icmp.Echo{
		ID:   int(icmpEchoID),
		Seq:  int(seqID),
		Data: []byte(timeStart.Format(time.RFC3339Nano)),
	}
	msg := icmp.Message{
		Type: requestType,
		Code: 0,
		Body: body,
	}
	klog.V(4).InfoS("Sending ICMP message", "IP", ip, "SeqID", seqID, "body", body)

	// Serialize the ICMP message
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	// Send the ICMP message
	if _, err = socket.WriteTo(msgBytes, ip); err != nil {
		return err
	}

	// Create or update the latency store
	mutator := func(entry *NodeIPLatencyEntry) {
		entry.LastSendTime = timeStart
	}
	m.latencyStore.SetNodeIPLatencyEntry(addr.String(), mutator)

	return nil
}

func (m *NodeLatencyMonitor) handlePing(buffer []byte, peerIP string, isIPv4 bool) {
	// Parse the ICMP message
	var msg *icmp.Message
	if isIPv4 {
		var err error
		msg, err = icmp.ParseMessage(protocolICMP, buffer)
		if err != nil {
			klog.ErrorS(err, "Failed to parse ICMP message")
			return
		}
		if msg.Type != ipv4.ICMPTypeEcho && msg.Type != ipv4.ICMPTypeEchoReply {
			klog.V(5).InfoS("Ignoring non-ping ICMP message", "msg", msg)
			return
		}
		// Ignore ICMP echo messages received from other Nodes (they will be answered by the system)
		if msg.Type == ipv4.ICMPTypeEcho {
			klog.V(7).InfoS("Ignoring ICMP echo request message", "msg", msg)
			return
		}
	} else {
		var err error
		msg, err = icmp.ParseMessage(protocolICMPv6, buffer)
		if err != nil {
			klog.ErrorS(err, "Failed to parse ICMP message")
			return
		}
		if msg.Type != ipv6.ICMPTypeEchoRequest && msg.Type != ipv6.ICMPTypeEchoReply {
			klog.V(5).InfoS("Ignoring non-ping ICMP message", "msg", msg)
			return
		}
		// Ignore ICMP echo messages received from other Nodes (they will be answered by the system)
		if msg.Type == ipv6.ICMPTypeEchoRequest {
			klog.V(7).InfoS("Ignoring ICMP echo request message", "msg", msg)
			return
		}
	}

	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		klog.ErrorS(nil, "Failed to assert type as *icmp.Echo")
		return
	}
	if echo.ID != int(icmpEchoID) {
		klog.V(4).InfoS("Ignoring ICMP message with wrong echo ID", "msg", msg)
		return
	}

	klog.V(4).InfoS("Received ICMP message", "IP", peerIP, "msg", msg)

	// Parse the time from the ICMP data
	sentTime, err := time.Parse(time.RFC3339Nano, string(echo.Data))
	if err != nil {
		klog.ErrorS(err, "Failed to parse time from ICMP data")
		return
	}

	// Calculate the round-trip time
	end := m.clock.Now()
	rtt := end.Sub(sentTime)
	klog.V(4).InfoS("Updating latency entry for Node IP", "IP", peerIP, "lastSendTime", sentTime, "lastRecvTime", end, "RTT", rtt)

	// Update the latency store
	mutator := func(entry *NodeIPLatencyEntry) {
		entry.LastRecvTime = end
		entry.LastMeasuredRTT = rtt
	}
	m.latencyStore.SetNodeIPLatencyEntry(peerIP, mutator)
}

// recvPings receives ICMP messages.
func (m *NodeLatencyMonitor) recvPings(socket net.PacketConn, isIPv4 bool) {
	// We only expect small packets, if we receive a larger packet, we will drop the extra data.
	readBuffer := make([]byte, 128)
	for {
		n, peer, err := socket.ReadFrom(readBuffer)
		if err != nil {
			// When the socket is closed in the Run method, this error will be logged, which is not ideal.
			// In the future, we may try setting a ReadDeadline on the socket before each ReadFrom and using
			// a channel to signal that the loop should terminate.
			klog.ErrorS(err, "Failed to read ICMP message")
			return
		}

		m.handlePing(readBuffer[:n], peer.String(), isIPv4)
	}
}

// pingAll sends ICMP messages to all the Nodes.
func (m *NodeLatencyMonitor) pingAll(ipv4Socket, ipv6Socket net.PacketConn) {
	klog.V(4).InfoS("Pinging all Nodes")
	nodeIPs := m.latencyStore.ListNodeIPs()
	for _, toIP := range nodeIPs {
		if toIP.To4() != nil && ipv4Socket != nil {
			if err := m.sendPing(ipv4Socket, toIP); err != nil {
				klog.ErrorS(err, "Cannot send ICMP message to Node IP", "IP", toIP)
			}
		} else if toIP.To16() != nil && ipv6Socket != nil {
			if err := m.sendPing(ipv6Socket, toIP); err != nil {
				klog.ErrorS(err, "Cannot send ICMP message to Node IP", "IP", toIP)
			}
		} else {
			klog.V(3).InfoS("Cannot send ICMP message to Node IP because socket is not initialized for IP family", "IP", toIP)
		}
	}
	klog.V(4).InfoS("Done pinging all Nodes")
}

// getSummary returns the latency summary of the given Node IP.
func (m *NodeLatencyMonitor) getSummary() *statsv1alpha1.NodeLatencyStats {
	return &statsv1alpha1.NodeLatencyStats{
		ObjectMeta: metav1.ObjectMeta{
			Name: m.nodeName,
		},
		PeerNodeLatencyStats: m.latencyStore.ConvertList(m.nodeName),
	}
}

func (m *NodeLatencyMonitor) report() {
	summary := m.getSummary()
	antreaClient, err := m.antreaClientProvider.GetAntreaClient()
	if err != nil {
		klog.ErrorS(err, "Failed to get Antrea client")
		return
	}
	if _, err := antreaClient.StatsV1alpha1().NodeLatencyStats().Create(context.TODO(), summary, metav1.CreateOptions{}); err != nil {
		klog.ErrorS(err, "Failed to create NodeIPLatencyStats")
	}
}

// Run starts the NodeLatencyMonitor.
func (m *NodeLatencyMonitor) Run(stopCh <-chan struct{}) {
	if !cache.WaitForNamedCacheSync("NodeLatencyMonitor", stopCh, m.nodeInformerSynced, m.nlmInformerSynced) {
		return
	}

	go m.monitorLoop(stopCh)

	<-stopCh
}

// monitorLoop is the main loop to monitor the latency of the Node.
func (m *NodeLatencyMonitor) monitorLoop(stopCh <-chan struct{}) {
	klog.InfoS("NodeLatencyMonitor is running")
	var pingTicker, reportTicker clock.Ticker
	var pingTickerCh, reportTickerCh <-chan time.Time
	var ipv4Socket, ipv6Socket net.PacketConn
	var err error

	defer func() {
		if ipv4Socket != nil {
			ipv4Socket.Close()
		}
		if ipv6Socket != nil {
			ipv6Socket.Close()
		}
		if pingTicker != nil {
			pingTicker.Stop()
		}
		if reportTicker != nil {
			reportTicker.Stop()
		}
	}()

	// Update the ping ticker based on latencyConfig
	updatePingTicker := func(interval time.Duration) {
		if pingTicker != nil {
			pingTicker.Stop() // Stop the  pingTicker
		}
		pingTicker = m.clock.NewTicker(interval)
		pingTickerCh = pingTicker.C()
	}
	//  report ticker with minimum interval and jitter
	updateReportTicker := func(interval time.Duration) {
		// Set minimum reporting interval to 10 seconds if needed
		reportInterval := interval
		if reportInterval < minReportInterval{
			reportInterval = minReportInterval
		} else {
			// Add jitter (1 second) to avoid lockstep with ping ticker
			reportInterval += time.Second
		}

		if reportTicker != nil {
			reportTicker.Stop()
		}
		reportTicker = m.clock.NewTicker(reportInterval)
		reportTickerCh = reportTicker.C()
	}

        wg := sync.WaitGroup{}
	// Start the pingAll goroutine
	for {
		select {
		case <-pingTickerCh:
			// Try to send pingAll signal
			m.pingAll(ipv4Socket, ipv6Socket)
			// We no not delete IPs from nodeIPLatencyMap as part of the Node delete event handler
			// to avoid consistency issues and because it would not be sufficient to avoid stale entries completely.
			// This means that we have to periodically invoke DeleteStaleNodeIPs to avoid stale entries in the map.
			m.latencyStore.DeleteStaleNodeIPs()
		case <-reportTickerCh:
			// Report the latency stats
			m.report()
		case <-stopCh:
			return
		case latencyConfig := <-m.latencyConfigChanged:
			klog.InfoS("NodeLatencyMonitor configuration has changed", "enabled", latencyConfig.Enable, "interval", latencyConfig.Interval)
			// Start or stop the pingAll goroutine based on the latencyConfig
			if latencyConfig.Enable {
				// latencyConfig changed for both of tickers
				updatePingTicker(latencyConfig.Interval)
				updateReportTicker(latencyConfig.Interval)

				// If the recvPing socket is closed,
				// recreate it if it is closed(CRD is deleted).
				if ipv4Socket == nil && m.isIPv4Enabled {
					// Create a new socket for IPv4 when it is IPv4-only
					ipv4Socket, err = m.listener.ListenPacket(ipv4ProtocolICMPRaw, "0.0.0.0")
					if err != nil {
						klog.ErrorS(err, "Failed to create ICMP socket for IPv4")
						return
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						m.recvPings(ipv4Socket, true)
					}()
				}
				if ipv6Socket == nil && m.isIPv6Enabled {
					// Create a new socket for IPv6 when it is IPv6-only
					ipv6Socket, err = m.listener.ListenPacket(ipv6ProtocolICMPRaw, "::")
					if err != nil {
						klog.ErrorS(err, "Failed to create ICMP socket for IPv6")
						return
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						m.recvPings(ipv6Socket, false)
					}()
				}
			} else {
				//stop the ping ticker and report ticker if latencyConfig monitorting is disabled
				if pingTicker != nil {
					pingTicker.Stop()
					pingTicker = nil
				}
				
				if reportTicker != nil {
					reportTicker.Stop()
					reportTicker = nil
				}
				pingTickerCh, reportTickerCh = nil, nil

				// We close the sockets as a signal to recvPing that it needs to stop.
				// Note that at that point, we are guaranteed that there is no ongoing Write
				// to the socket, because pingAll runs in the same goroutine as this code.
				if ipv4Socket != nil {
					ipv4Socket.Close()
				}
				if ipv6Socket != nil {
					ipv6Socket.Close()
				}

				// After closing the sockets, wait for the recvPing goroutines to return
				wg.Wait()
				ipv4Socket = nil
				ipv6Socket = nil
			}
		}
	}
}

// getICMPSeqNum returns the sequence number to be used when sending the next
// ICMP echo request. It wraps around to 0 after reaching the maximum value for
// uint16.
func (m *NodeLatencyMonitor) getICMPSeqNum() uint16 {
	newSeqNum := m.icmpSeqNum.Add(1)
	return uint16(newSeqNum)
}
