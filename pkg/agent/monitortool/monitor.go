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
	// For privileged
	IPv4ProtocolICMPRaw = "ip4:icmp"
	IPv6ProtocolICMPRaw = "ip6:ipv6-icmp"
	// IP Protocol
	IPProtocol = "ip"
	// ProtocolICMP is the ICMP protocol number.
	ProtocolICMP = 1
	// ProtocolICMPv6 is the ICMPv6 protocol number.
	ProtocolICMPv6 = 58
)

// getICMPSeq returns the next sequence number as uint32,
// wrapping around to 0 after reaching the maximum value of uint32.
func getICMPSeq() uint32 {
	// Increment the sequence number atomically and get the new value.
	// We use atomic.AddUint32 and pass 1 as the increment.
	// The returned value is the new value post-increment.
	newVal := atomic.AddUint32(&icmpSeq, 1)

	return newVal
}

// NodeLatencyMonitor is a tool to monitor the latency of the Node.
type NodeLatencyMonitor struct {
	// latencyStore is the cache to store the latency of each Nodes.
	latencyStore *LatencyStore
	// latencyConfig is the config for the latency monitor.
	latencyConfig *LatencyConfig
	// latencyConfigChanged is the channel to notify the latency config changed.
	latencyConfigChanged chan struct{}
	// isIPv4Enabled is the flag to indicate if the IPv4 is enabled.
	isIPv4Enabled bool
	// isIPv6Enabled is the flag to indicate if the IPv6 is enabled.
	isIPv6Enabled bool

	// The informer of Nodes, it will changed by Node watcher
	nodeInformer coreinformers.NodeInformer
	// nodeLatencyMonitorInformer is the informer for the NodeLatencyMonitor CRD.
	nodeLatencyMonitorInformer crdinformers.NodeLatencyMonitorInformer
}

// LatencyConfig is the config for the latency monitor.
type LatencyConfig struct {
	// Enable is the flag to enable the latency monitor.
	Enable bool
	// Interval is the interval time to ping all Nodes.
	Interval time.Duration
}

func NewNodeLatencyMonitor(nodeInformer coreinformers.NodeInformer,
	nlmInformer crdinformers.NodeLatencyMonitorInformer,
	nodeConfig *config.NodeConfig,
	trafficEncapMode config.TrafficEncapModeType) *NodeLatencyMonitor {
	m := &NodeLatencyMonitor{
		latencyStore:               NewLatencyStore(trafficEncapMode.IsNetworkPolicyOnly()),
		latencyConfig:              &LatencyConfig{Enable: false},
		latencyConfigChanged:       make(chan struct{}, 1),
		nodeInformer:               nodeInformer,
		nodeLatencyMonitorInformer: nlmInformer,
	}

	// Get the IPv4/IPv6 enabled status
	isIPv4Enabled, err := config.IsIPv4Enabled(nodeConfig, trafficEncapMode)
	if err != nil {
		klog.ErrorS(err, "Failed to get IPv4 enabled status")
	}
	isIPv6Enabled, err := config.IsIPv6Enabled(nodeConfig, trafficEncapMode)
	if err != nil {
		klog.ErrorS(err, "Failed to get IPv6 enabled status")
	}
	m.isIPv4Enabled = isIPv4Enabled
	m.isIPv6Enabled = isIPv6Enabled

	// Add Node informer event handler for Node
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

	klog.V(4).InfoS("Node added", "Node", klog.KObj(node))
}

// onNodeUpdate is the event handler for updating Node.
func (m *NodeLatencyMonitor) onNodeUpdate(oldObj, newObj interface{}) {
	oldNode := oldObj.(*corev1.Node)
	node := newObj.(*corev1.Node)
	m.latencyStore.updateNode(oldNode, node)

	klog.V(4).InfoS("Node updated", "Node", klog.KObj(node))
}

// onNodeDelete is the event handler for deleting Node.
func (m *NodeLatencyMonitor) onNodeDelete(obj interface{}) {
	// Check if the object is a not a Node
	node, ok := obj.(*corev1.Node)
	if !ok {
		// Check if the object is a DeletedFinalStateUnknown in k8s
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(nil, "Received unexpected object", "obj", obj)
			return
		}
		// Convert the DeletedFinalStateUnknown to a Node
		node, ok = deletedState.Obj.(*corev1.Node)
		if !ok {
			klog.ErrorS(nil, "DeletedFinalStateUnknown contains non-Node object", "obj", deletedState.Obj)
			return
		}
	}

	m.latencyStore.deleteNode(node)
}

// onNodeLatencyMonitorAdd is the event handler for adding NodeLatencyMonitor.
func (m *NodeLatencyMonitor) onNodeLatencyMonitorAdd(obj interface{}) {
	nlm := obj.(*v1alpha1.NodeLatencyMonitor)
	klog.V(4).InfoS("NodeLatencyMonitor added", "NodeLatencyMonitor", klog.KObj(nlm))

	if err := m.updateLatencyConfig(nlm); err != nil {
		klog.ErrorS(err, "Failed to update latency config")
	}
}

// onNodeLatencyMonitorUpdate is the event handler for updating NodeLatencyMonitor.
func (m *NodeLatencyMonitor) onNodeLatencyMonitorUpdate(oldObj, newObj interface{}) {
	oldNLM := oldObj.(*v1alpha1.NodeLatencyMonitor)
	newNLM := newObj.(*v1alpha1.NodeLatencyMonitor)
	klog.V(4).InfoS("NodeLatencyMonitor updated", "NodeLatencyMonitor", klog.KObj(newNLM))

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
	klog.V(4).InfoS("Send ICMP message", "IP", ip, "SeqID", seqID, "body", body)

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

	// Create or update the latency store
	mutator := func(entry *NodeIPLatencyEntry) {
		entry.LastSendTime = timeStart
	}
	m.latencyStore.SetNodeIPLatencyEntry(addr.String(), mutator)

	return nil
}

func (m *NodeLatencyMonitor) recvPing(socket net.PacketConn, isIPv4 bool, stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		default:
			// max size of the ICMP message is 1500 bytes, which is the maximum size of an Ethernet frame.
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

			// Parse the ICMP message
			var msg *icmp.Message
			if isIPv4 {
				msg, err = icmp.ParseMessage(ProtocolICMP, readBuffer[:n])
				if err != nil {
					klog.ErrorS(err, "Failed to parse ICMP message")
					continue
				}
				if msg.Type != ipv4.ICMPTypeEchoReply {
					klog.V(4).InfoS("Failed to match ICMPTypeEchoReply")
					continue
				}
			} else {
				msg, err = icmp.ParseMessage(ProtocolICMPv6, readBuffer)
				if err != nil {
					klog.ErrorS(err, "Failed to parse ICMP message")
					continue
				}
				if msg.Type != ipv6.ICMPTypeEchoReply {
					klog.V(4).InfoS("Failed to match ICMPTypeEchoReply")
					continue
				}
			}

			echo, ok := msg.Body.(*icmp.Echo)
			if !ok {
				klog.V(4).Info("Failed to assert type as *icmp.Echo")
				continue
			}

			klog.V(4).InfoS("Recv ICMP message", "IP", destIP, "echo", echo)

			// Parse the time from the ICMP data
			sentTime, err := time.Parse(time.RFC3339Nano, string(echo.Data))
			if err != nil {
				klog.ErrorS(err, "Failed to parse time from ICMP data")
				continue
			}

			// Calculate the round-trip time
			end := time.Now()
			rtt := end.Sub(sentTime)

			// Update the latency store
			mutator := func(entry *NodeIPLatencyEntry) {
				entry.LastSendTime = sentTime
				entry.LastRecvTime = end
				entry.LastMeasuredRTT = rtt
			}
			m.latencyStore.SetNodeIPLatencyEntry(destIP, mutator)
		}
	}
}

func (m *NodeLatencyMonitor) pingAll(ipv4Socket, ipv6Socket net.PacketConn) {
	nodeIPs := m.latencyStore.ListNodeIPs()
	for name, toIPs := range nodeIPs {
		for _, toIP := range toIPs {
			klog.V(4).InfoS("Start to ping Node", "Node name", name, "Node IP", toIP)
			if toIP.To4() != nil && ipv4Socket != nil {
				if err := m.sendPing(ipv4Socket, toIP); err != nil {
					klog.V(4).InfoS("Failed to send ICMP message to Node", "Node name", name, "Node IP", toIP)
				}
			} else if toIP.To16() != nil && ipv6Socket != nil {
				if err := m.sendPing(ipv6Socket, toIP); err != nil {
					klog.V(4).InfoS("Failed to send ICMP message to Node", "Node name", name, "Node IP", toIP)
				}
			} else {
				klog.V(4).InfoS("Failed to send ICMP message to Node", "Node name", name, "Node IP", toIP)
			}
		}
	}
}

func (m *NodeLatencyMonitor) Run(stopCh <-chan struct{}) {
	// Start the monitor loop
	go m.nodeLatencyMonitorInformer.Informer().Run(stopCh)
	go m.nodeInformer.Informer().Run(stopCh)
	go m.monitorLoop(stopCh)

	<-stopCh
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
