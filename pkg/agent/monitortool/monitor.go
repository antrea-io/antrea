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
	"net"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	corev1 "k8s.io/api/core/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	config "antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
)

var (
	icmpSeq uint32
)

const (
	// For non-privileged
	IPv4ProtocolICMP = "udp4"
	IPv6ProtocolICMP = "udp6"
	// For privileged
	IPv4ProtocolICMPRaw = "ip4:icmp"
	IPv6ProtocolICMPRaw = "ip6:ipv6-icmp"
	// IP Protocol
	IPProtocol = "ip"
	// ProtocolICMP is the ICMP protocol number.
	ProtocolICMP = 1
	// ProtocolIPv6ICMP is the ICMPv6 protocol number.
	ProtocolIPv6ICMP = 58
)

// getICMPSeq returns the next sequence number as uint16,
// wrapping around to 0 after reaching the maximum value of uint16.
func getICMPSeq() uint32 {
	// Increment the sequence number atomically and get the new value.
	// We use atomic.AddUint32 and pass 1 as the increment.
	// The returned value is the new value post-increment.
	newVal := atomic.AddUint32(&icmpSeq, 1)

	return newVal
}

// NodeLatencyMonitor is a tool to monitor the latency of the node.
type NodeLatencyMonitor struct {
	// Node config
	nodeConfig *config.NodeConfig
	// latencyStore is the cache to store the latency of each nodes.
	latencyStore *LatencyStore
	// latencyConfig is the config for the latency monitor.
	latencyConfig *LatencyConfig
	// latencyConfigChanged is the channel to notify the latency config changed.
	latencyConfigChanged chan struct{}
	// gatewayConfig is the traffic encap mode for the latency monitor,
	// indicate if the Antrea Agent is running in network policy only mode.
	trafficEncapMode config.TrafficEncapModeType
	// isIPv4Enabled is the flag to indicate if the IPv4 is enabled.
	isIPv4Enabled bool
	// isIPv6Enabled is the flag to indicate if the IPv6 is enabled.
	isIPv6Enabled bool

	// The map of node name to node info, it will changed by node watcher
	nodeInformer coreinformers.NodeInformer
	// nodeLatencyMonitorInformer is the informer for the NodeLatencyMonitor CRD.
	nodeLatencyMonitorInformer crdinformers.NodeLatencyMonitorInformer
}

// LatencyConfig is the config for the latency monitor.
type LatencyConfig struct {
	// Enable is the flag to enable the latency monitor.
	Enable bool
	// Interval is the interval time to ping all nodes.
	Interval time.Duration
}

func NewNodeLatencyMonitor(nodeInformer coreinformers.NodeInformer,
	nlmInformer crdinformers.NodeLatencyMonitorInformer,
	nodeConfig *config.NodeConfig,
	trafficEncapMode config.TrafficEncapModeType) *NodeLatencyMonitor {
	m := &NodeLatencyMonitor{
		nodeConfig:                 nodeConfig,
		trafficEncapMode:           trafficEncapMode,
		latencyStore:               NewLatencyStore(trafficEncapMode.IsNetworkPolicyOnly()),
		latencyConfig:              &LatencyConfig{Enable: false},
		latencyConfigChanged:       make(chan struct{}, 1),
		nodeInformer:               nodeInformer,
		nodeLatencyMonitorInformer: nlmInformer,
	}

	// Get the IPv4/IPv6 enabled status
	isIPv4Enabled, err := config.IsIPv4Enabled(m.nodeConfig, m.trafficEncapMode)
	if err != nil {
		klog.ErrorS(err, "Failed to get IPv4 enabled status")
	}
	isIPv6Enabled, err := config.IsIPv6Enabled(m.nodeConfig, m.trafficEncapMode)
	if err != nil {
		klog.ErrorS(err, "Failed to get IPv6 enabled status")
	}
	m.isIPv4Enabled = isIPv4Enabled
	m.isIPv6Enabled = isIPv6Enabled

	// Add node informer event handler for Node
	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    m.onNodeAdd,
		UpdateFunc: m.onNodeUpdate,
		DeleteFunc: m.onNodeDelete,
	})

	// Add crd informer event handler for NodeLatencyMonitor
	nlmInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    m.onNodeLatencyMonitorAdd,
		UpdateFunc: m.onNodeLatencyMonitorUpdate,
		DeleteFunc: m.onNodeLatencyMonitorDelete,
	})

	return m
}

// onNodeAdd is the event handler for adding Node.
func (m *NodeLatencyMonitor) onNodeAdd(obj interface{}) {
	node := obj.(*corev1.Node)
	m.latencyStore.addNode(node)

	klog.InfoS("Node added", "Node", klog.KObj(node))
}

// onNodeUpdate is the event handler for updating Node.
func (m *NodeLatencyMonitor) onNodeUpdate(oldObj, newObj interface{}) {
	oldNode := oldObj.(*corev1.Node)
	node := newObj.(*corev1.Node)
	m.latencyStore.updateNode(oldNode, node)

	klog.InfoS("Node updated", "Node", klog.KObj(node))
}

// onNodeDelete is the event handler for deleting Node.
func (m *NodeLatencyMonitor) onNodeDelete(obj interface{}) {
	// Check if the object is a not a node
	node, ok := obj.(*corev1.Node)
	if !ok {
		return
	}

	m.latencyStore.deleteNode(node)
}

// onNodeLatencyMonitorAdd is the event handler for adding NodeLatencyMonitor.
func (m *NodeLatencyMonitor) onNodeLatencyMonitorAdd(obj interface{}) {
	nlm := obj.(*v1alpha1.NodeLatencyMonitor)
	klog.InfoS("NodeLatencyMonitor added", "NodeLatencyMonitor", klog.KObj(nlm))

	if err := m.updateLatencyConfig(nlm); err != nil {
		klog.ErrorS(err, "Failed to update latency config")
	}
}

// onNodeLatencyMonitorUpdate is the event handler for updating NodeLatencyMonitor.
func (m *NodeLatencyMonitor) onNodeLatencyMonitorUpdate(oldObj, newObj interface{}) {
	oldNLM := oldObj.(*v1alpha1.NodeLatencyMonitor)
	newNLM := newObj.(*v1alpha1.NodeLatencyMonitor)
	klog.InfoS("NodeLatencyMonitor updated", "NodeLatencyMonitor", klog.KObj(newNLM))

	if oldNLM.GetGeneration() == newNLM.GetGeneration() {
		return
	}

	if err := m.updateLatencyConfig(newNLM); err != nil {
		klog.ErrorS(err, "Failed to update latency config")
	}
}

func (m *NodeLatencyMonitor) updateLatencyConfig(nlm *v1alpha1.NodeLatencyMonitor) error {
	// Parse the ping interval
	pingInterval := time.Duration(nlm.Spec.PingIntervalSeconds) * time.Second

	// Update the latency config
	m.latencyConfig = &LatencyConfig{
		Enable:   true,
		Interval: pingInterval,
	}

	// Notify the latency config changed
	m.latencyConfigChanged <- struct{}{}

	return nil
}

// onNodeLatencyMonitorDelete is the event handler for deleting NodeLatencyMonitor.
func (m *NodeLatencyMonitor) onNodeLatencyMonitorDelete(obj interface{}) {
	// Update the latency config
	m.latencyConfig = &LatencyConfig{Enable: false}

	// Notify the latency config changed
	m.latencyConfigChanged <- struct{}{}
}

func (m *NodeLatencyMonitor) sendPing(socket net.PacketConn, addr net.IP) error {
	var requestType icmp.Type

	// Resolve the IP address
	ip := &net.IPAddr{IP: addr}

	// Create a new ICMP packet
	if addr.To4() == nil {
		requestType = ipv6.ICMPTypeEchoRequest
	} else {
		requestType = ipv4.ICMPTypeEcho
	}

	timeStart := time.Now()
	seqID := getICMPSeq()
	body := &icmp.Echo{
		ID:   os.Getpid() & 0xffff,                       // Use the current process ID as the ICMP ID
		Seq:  int(seqID),                                 // Use the current sequence number as the ICMP sequence number
		Data: []byte(timeStart.Format(time.RFC3339Nano)), // Store the current time in the ICMP data
	}
	msg := icmp.Message{
		Type: requestType,
		Code: 0,
		Body: body,
	}
	klog.InfoS("Send ICMP message", "IP", ip, "SeqID", seqID, "body", body)

	// Serialize the ICMP message
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	// Send the ICMP message
	_, err = socket.WriteTo(msgBytes, ip)
	if err != nil {
		return err
	}

	// Store current send info
	// Read the ICMP message
	oldEntry := m.latencyStore.GetNodeIPLatencyEntryByKey(addr.String())
	if oldEntry != nil {
		// Update the latency store
		oldEntry.LastSendTime = timeStart
		oldEntry.SeqID = seqID
		m.latencyStore.UpdateNodeIPLatencyEntryByKey(addr.String(), oldEntry)
		return nil
	} else {
		// New entry
		m.latencyStore.UpdateNodeIPLatencyEntryByKey(addr.String(), &NodeIPLatencyEntry{
			SeqID:           seqID,
			LastSendTime:    timeStart,
			LastRecvTime:    time.Time{},
			LastMeasuredRTT: 0,
		})
	}

	return nil
}

func (m *NodeLatencyMonitor) recvPing(socket net.PacketConn, isIPv4 bool, stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		default:
			readBuffer := make([]byte, 1500)
			n, peer, err := socket.ReadFrom(readBuffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					klog.ErrorS(err, "Timeout reading ICMP message")
					continue
				}
				klog.ErrorS(err, "Failed to read ICMP message")
			}

			destIP := peer.String()
			// Get the node name by destIP
			entry := m.latencyStore.GetNodeIPLatencyEntryByKey(destIP)
			if entry == nil {
				klog.Warning("Failed to get node entry by destIP", "destIP", destIP)
				continue
			}

			// Parse the ICMP message
			var msg *icmp.Message
			if isIPv4 {
				msg, err = icmp.ParseMessage(ProtocolICMP, readBuffer[:n])
				if err != nil {
					klog.ErrorS(err, "Failed to parse ICMP message")
					continue
				}
				if msg.Type != ipv4.ICMPTypeEchoReply {
					klog.Warning("Failed to match ICMPTypeEchoReply")
					continue
				}
			} else {
				msg, err = icmp.ParseMessage(ProtocolIPv6ICMP, readBuffer)
				if err != nil {
					klog.ErrorS(err, "Failed to parse ICMP message")
					continue
				}
				if msg.Type != ipv6.ICMPTypeEchoReply {
					klog.Warning("Failed to match ICMPTypeEchoReply")
					continue
				}
			}

			echo, ok := msg.Body.(*icmp.Echo)
			if !ok {
				klog.Warning(nil, "Failed to assert type as *icmp.Echo")
				continue
			}

			klog.InfoS("Recv ICMP message", "IP", destIP, "SeqID", entry.SeqID, "echo", echo)

			// Parse the ICMP data
			if entry.SeqID != uint32(echo.Seq) {
				klog.Warning("Failed to match seqID", "entry.SeqID", entry.SeqID, "echo.Seq", echo.Seq)
				continue
			}

			// Calculate the round-trip time
			end := time.Now()
			rtt := end.Sub(entry.LastSendTime)

			// Update the latency store
			m.latencyStore.UpdateNodeIPLatencyEntryByKey(destIP, &NodeIPLatencyEntry{
				SeqID:           entry.SeqID,
				LastSendTime:    entry.LastSendTime,
				LastRecvTime:    end,
				LastMeasuredRTT: rtt,
			})
		}
	}
}

func (m *NodeLatencyMonitor) pingAll(ipv4Socket, ipv6Socket net.PacketConn) {
	// Get all node internal/external IP.
	nodeIPs := m.latencyStore.ListNodeIPs()
	klog.InfoS("Start to ping all nodes")
	for name, toIPs := range nodeIPs {
		for _, toIP := range toIPs {
			klog.InfoS("Start to ping node", "Node name", name, "Node IP", toIP)
			if toIP.To4() != nil && ipv4Socket != nil {
				if err := m.sendPing(ipv4Socket, toIP); err != nil {
					klog.InfoS("Failed to send ICMP message to node", "Node name", name, "Node IP", toIP)
				}
			} else if toIP.To16() != nil && ipv6Socket != nil {
				if err := m.sendPing(ipv6Socket, toIP); err != nil {
					klog.InfoS("Failed to send ICMP message to node", "Node name", name, "Node IP", toIP)
				}
			} else {
				klog.InfoS("Failed to send ICMP message to node", "Node name", name, "Node IP", toIP)
			}
		}
	}
}

func (m *NodeLatencyMonitor) testPrint() {
	// Print all connection status for debug
	// It will be removed when collector is ready
	klog.InfoS("Finish to ping all nodes")
	entries := m.latencyStore.ListLatencies()
	for key, entry := range entries {
		klog.InfoS("NodeIPLatency status", "Key", key, "Entry", entry)
	}
}

func (m *NodeLatencyMonitor) Run(stopCh <-chan struct{}) {
	// Top level goroutine to handle termination
	go func() {
		<-stopCh
	}()

	// Start the monitor loop
	go m.nodeLatencyMonitorInformer.Informer().Run(stopCh)
	go m.nodeInformer.Informer().Run(stopCh)
	go m.monitorLoop(stopCh)
}

func (m *NodeLatencyMonitor) monitorLoop(stopCh <-chan struct{}) {
	// Low level goroutine to handle ping loop
	var ticker *time.Ticker
	var tickerCh <-chan time.Time
	var ipv4Socket, ipv6Socket net.PacketConn
	var err error
	tickerStopCh := make(chan struct{})

	defer func() {
		if ipv4Socket != nil {
			ipv4Socket.Close()
		}
		if ipv6Socket != nil {
			ipv6Socket.Close()
		}
		if ticker != nil {
			ticker.Stop()
		}
		if tickerStopCh != nil {
			close(tickerStopCh)
		}
	}()

	// Update current ticker based on the latencyConfig
	updateTicker := func(interval time.Duration) {
		if ticker != nil {
			ticker.Stop() // Stop the current ticker
		}
		ticker = time.NewTicker(interval)
		tickerCh = ticker.C
	}

	// Start the pingAll goroutine
	for {
		select {
		case <-tickerCh:
			// Try to send pingAll signal
			m.pingAll(ipv4Socket, ipv6Socket)
			// Test print
			m.testPrint()
		case <-tickerStopCh:
			// Close current sockets
			if ipv4Socket != nil {
				ipv4Socket.Close()
			}
			if ipv6Socket != nil {
				ipv6Socket.Close()
			}
		case <-stopCh:
			// Stop the ticker loop
			if ticker != nil {
				ticker.Stop()
			}
			tickerStopCh <- struct{}{}
			return
		case <-m.latencyConfigChanged:
			// Start or stop the pingAll goroutine based on the latencyConfig
			if m.latencyConfig.Enable {
				// latencyConfig changed
				updateTicker(m.latencyConfig.Interval)

				// If the recvPing socket is closed, restart it
				// In case of IPv4-only or IPv6-only, we need to check the socket status,
				// and restart it if it is closed(CRD is deleted).
				if ipv4Socket == nil && m.isIPv4Enabled {
					// Create a new socket for IPv4 when the gatewayConfig is IPv4-only
					ipv4Socket, err = icmp.ListenPacket(IPv4ProtocolICMPRaw, "0.0.0.0")
					if err != nil {
						klog.ErrorS(err, "Failed to create ICMP socket for IPv4")
						return
					}
					go m.recvPing(ipv4Socket, true, tickerStopCh)
				}
				if ipv6Socket == nil && m.isIPv6Enabled {
					// Create a new socket for IPv6 when the gatewayConfig is IPv6-only
					ipv6Socket, err = icmp.ListenPacket(IPv6ProtocolICMPRaw, "::")
					if err != nil {
						klog.ErrorS(err, "Failed to create ICMP socket for IPv6")
						return
					}
					go m.recvPing(ipv6Socket, false, tickerStopCh)
				}
			} else {
				// latencyConfig deleted
				if ticker != nil {
					ticker.Stop()
					ticker = nil
				}
				tickerStopCh <- struct{}{}
			}
		}
	}
}
