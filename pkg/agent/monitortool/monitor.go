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
	"net"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"k8s.io/klog/v2"

	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"

	config "antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
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

// MonitorTool is a tool to monitor the latency of the node.
type MonitorTool struct {
	// Gateway config
	gatewayConfig *config.GatewayConfig
	// latencyStore is the cache to store the latency of each nodes.
	latencyStore *LatencyStore
	// latencyConfig is the config for the latency monitor.
	latencyConfig *LatencyConfig
	// latencyConfigChanged is the channel to notify the latency config changed.
	latencyConfigChanged chan struct{}

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
	gatewayConfig *config.GatewayConfig,
	isNetworkPolicyOnly bool) *MonitorTool {
	m := &MonitorTool{
		gatewayConfig:              gatewayConfig,
		latencyStore:               NewLatencyStore(nodeInformer, isNetworkPolicyOnly),
		latencyConfig:              &LatencyConfig{Enable: false},
		latencyConfigChanged:       make(chan struct{}, 1),
		nodeLatencyMonitorInformer: nlmInformer,
	}

	// Add crd informer event handler for NodeLatencyMonitor
	nlmInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    m.onNodeLatencyMonitorAdd,
		UpdateFunc: m.onNodeLatencyMonitorUpdate,
		DeleteFunc: m.onNodeLatencyMonitorDelete,
	})

	return m
}

// onNodeLatencyMonitorAdd is the event handler for adding NodeLatencyMonitor.
func (m *MonitorTool) onNodeLatencyMonitorAdd(obj interface{}) {
	nlm := obj.(*v1alpha2.NodeLatencyMonitor)
	klog.InfoS("NodeLatencyMonitor added", "NodeLatencyMonitor", klog.KObj(nlm))

	if err := m.updateLatencyConfig(nlm); err != nil {
		klog.ErrorS(err, "Failed to update latency config")
	}
}

// onNodeLatencyMonitorUpdate is the event handler for updating NodeLatencyMonitor.
func (m *MonitorTool) onNodeLatencyMonitorUpdate(oldObj, newObj interface{}) {
	oldNLM := oldObj.(*v1alpha2.NodeLatencyMonitor)
	newNLM := newObj.(*v1alpha2.NodeLatencyMonitor)
	klog.InfoS("NodeLatencyMonitor updated", "NodeLatencyMonitor", klog.KObj(newNLM))

	if oldNLM.GetGeneration() == newNLM.GetGeneration() {
		return
	}

	if err := m.updateLatencyConfig(newNLM); err != nil {
		klog.ErrorS(err, "Failed to update latency config")
	}
}

func (m *MonitorTool) updateLatencyConfig(nlm *v1alpha2.NodeLatencyMonitor) error {
	// Parse the ping interval
	pingInterval := time.Duration(nlm.Spec.PingInterval) * time.Second

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
func (m *MonitorTool) onNodeLatencyMonitorDelete(obj interface{}) {
	klog.InfoS("NodeLatencyMonitor deleted", "NodeLatencyMonitor")

	// Update the latency config
	m.latencyConfig = &LatencyConfig{Enable: false}

	// Notify the latency config changed
	m.latencyConfigChanged <- struct{}{}
}

func (m *MonitorTool) sendPing(socket net.PacketConn, addr net.IP) error {
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
	m.latencyStore.UpdateNodeIPLatencyEntryByKey(addr.String(), &NodeIPLatencyEntry{
		SeqID:           seqID,
		LastSendTime:    timeStart,
		LastRecvTime:    time.Time{},
		LastMeasuredRTT: 0,
	})

	return nil
}

func (m *MonitorTool) recvPing(socket net.PacketConn, isIPv4 bool, stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		default:
			readBuffer := make([]byte, 1024)
			_, peer, err := socket.ReadFrom(readBuffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					klog.ErrorS(err, "Timeout reading ICMP message")
					continue
				}
				klog.ErrorS(err, "Failed to read ICMP message")
			}

			destIP := peer.String()
			// Get the node name by destIP
			entry, ok := m.latencyStore.GetNodeIPLatencyEntryByKey(destIP)
			if !ok {
				klog.ErrorS(err, "Failed to get node name by destIP")
				continue
			}

			// Parse the ICMP message
			var msg *icmp.Message
			if isIPv4 {
				msg, err = icmp.ParseMessage(ProtocolICMP, readBuffer)
				if err != nil {
					klog.ErrorS(err, "Failed to parse ICMP message")
					continue
				}
			} else {
				msg, err = icmp.ParseMessage(ProtocolIPv6ICMP, readBuffer)
				if err != nil {
					klog.ErrorS(err, "Failed to parse ICMP message")
					continue
				}
			}

			// Parse the ICMP data
			if entry.SeqID != uint32(msg.Body.(*icmp.Echo).Seq) {
				klog.ErrorS(err, "Failed to match seqID")
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

func (m *MonitorTool) PingAll(stopCh <-chan struct{}) {
	// Create a new socket for IPv4
	ipv4Socket, err := icmp.ListenPacket(IPv4ProtocolICMPRaw, "0.0.0.0")
	if err != nil {
		klog.ErrorS(err, "Failed to create ICMP socket for IPv4")
		return
	}
	defer ipv4Socket.Close()
	// Create a new socket for IPv6
	ipv6Socket, err := icmp.ListenPacket(IPv6ProtocolICMPRaw, "::")
	if err != nil {
		klog.ErrorS(err, "Failed to create ICMP socket for IPv6")
		return
	}
	defer ipv6Socket.Close()

	// Start the goroutine to receive ICMP messages
	go m.recvPing(ipv4Socket, true, stopCh)
	go m.recvPing(ipv6Socket, false, stopCh)

	// Start to ping all nodes
	pingAll := func() {
		m.pingAll(ipv4Socket, ipv6Socket)
	}
	go wait.Until(pingAll, m.latencyConfig.Interval, stopCh)

	<-stopCh
}

func (m *MonitorTool) pingAll(ipv4Socket, ipv6Socket net.PacketConn) {
	// Get all node internal/external IP.
	nodeIPs := m.latencyStore.ListNodeIPs()
	klog.InfoS("Start to ping all nodes")
	for name, toIPs := range nodeIPs {
		for _, toIP := range toIPs {
			if toIP.To4() != nil {
				if err := m.sendPing(ipv4Socket, toIP); err != nil {
					klog.ErrorS(err, "Failed to send ICMP message to node", "Node", name)
				}
			} else {
				if err := m.sendPing(ipv6Socket, toIP); err != nil {
					klog.ErrorS(err, "Failed to send ICMP message to node", "Node", name)
				}
			}
		}
	}
}

func (m *MonitorTool) testPrint() {
	// TODO: Print all connection status for debug
	klog.InfoS("Finish to ping all nodes")
	entries := m.latencyStore.ListLatencies()
	for _, entry := range entries {
		klog.InfoS("Connection status", "Connection", entry)
	}
}

func (m *MonitorTool) Run(stopCh <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())

	// Top level goroutine to handle termination
	go func() {
		<-stopCh
		cancel()
	}()

	// Start the monitor loop
	go m.nodeLatencyMonitorInformer.Informer().Run(stopCh)
	go m.monitorLoop(ctx)
}

func (m *MonitorTool) monitorLoop(ctx context.Context) {
	// Low level goroutine to handle ping loop
	var innerStopCh chan struct{}
	var cancelInnerStopCh func()

	for {
		select {
		case <-ctx.Done():
			// Stop the inner ping loop
			if cancelInnerStopCh != nil {
				cancelInnerStopCh()
			}
			return
		case <-m.latencyConfigChanged:
			// Start or stop the pingAll goroutine based on the latencyConfig
			if m.latencyConfig.Enable {
				// Stop previous pingAll goroutine
				if cancelInnerStopCh != nil {
					cancelInnerStopCh()
				}

				// Create a new stop channel for the new pingAll goroutine
				innerStopCh = make(chan struct{})
				cancelInnerStopCh = func() {
					close(innerStopCh)

					// Clean up the latency store
					m.latencyStore.CleanUp()
				}

				// Start new pingAll goroutine
				go m.latencyStore.Run(innerStopCh)
				go m.PingAll(innerStopCh)
				go wait.Until(m.testPrint, m.latencyConfig.Interval, innerStopCh)
			} else {
				// Stop current pingAll goroutine
				if cancelInnerStopCh != nil {
					cancelInnerStopCh()
					cancelInnerStopCh = nil
				}
			}
		}
	}
}
