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
	"bytes"
	"context"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"

	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"

	config "antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
)

var (
	icmpSeq      uint16
	icmpSeqMutex sync.Mutex
	srcIP        = net.ParseIP("0.0.0.0")
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
)

func getICMPSeq() uint16 {
	icmpSeqMutex.Lock()
	defer icmpSeqMutex.Unlock()
	icmpSeq++
	return icmpSeq
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
	// Timeout is the timeout time for each ping.
	Timeout time.Duration
	// Limit is the conncurrent limit of the ping.
	Limit int
}

func NewNodeLatencyMonitor(nodeInformer coreinformers.NodeInformer,
	nlmInformer crdinformers.NodeLatencyMonitorInformer,
	gatewayConfig *config.GatewayConfig) *MonitorTool {
	m := &MonitorTool{
		gatewayConfig:              gatewayConfig,
		latencyStore:               NewLatencyStore(nodeInformer),
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

	// Parse the ping interval and timeout
	pingInterval, err := time.ParseDuration(nlm.Spec.PingInterval)
	if err != nil {
		klog.ErrorS(err, "Failed to parse ping interval")
		return
	}
	pingTimeout, err := time.ParseDuration(nlm.Spec.PingTimeout)
	if err != nil {
		klog.ErrorS(err, "Failed to parse ping timeout")
		return
	}

	// Update the latency config
	m.latencyConfig = &LatencyConfig{
		Enable:   true,
		Interval: pingInterval,
		Timeout:  pingTimeout,
		Limit:    nlm.Spec.PingConcurrentLimit,
	}

	// Notify the latency config changed
	m.latencyConfigChanged <- struct{}{}
}

// onNodeLatencyMonitorUpdate is the event handler for updating NodeLatencyMonitor.
func (m *MonitorTool) onNodeLatencyMonitorUpdate(oldObj, newObj interface{}) {
	oldNLM := oldObj.(*v1alpha2.NodeLatencyMonitor)
	newNLM := newObj.(*v1alpha2.NodeLatencyMonitor)
	klog.InfoS("NodeLatencyMonitor updated", "NodeLatencyMonitor", klog.KObj(newNLM))

	if oldNLM.GetGeneration() == newNLM.GetGeneration() {
		return
	}

	// Parse the ping interval and timeout
	pingInterval, err := time.ParseDuration(newNLM.Spec.PingInterval)
	if err != nil {
		klog.ErrorS(err, "Failed to parse ping interval")
		return
	}
	pingTimeout, err := time.ParseDuration(newNLM.Spec.PingTimeout)
	if err != nil {
		klog.ErrorS(err, "Failed to parse ping timeout")
		return
	}

	// Update the latency config
	m.latencyConfig = &LatencyConfig{
		Enable:   true,
		Interval: pingInterval,
		Timeout:  pingTimeout,
		Limit:    newNLM.Spec.PingConcurrentLimit,
	}

	// Notify the latency config changed
	m.latencyConfigChanged <- struct{}{}
}

// onNodeLatencyMonitorDelete is the event handler for deleting NodeLatencyMonitor.
func (m *MonitorTool) onNodeLatencyMonitorDelete(obj interface{}) {
	klog.InfoS("NodeLatencyMonitor deleted", "NodeLatencyMonitor")

	// Update the latency config
	m.latencyConfig = &LatencyConfig{Enable: false}

	// Notify the latency config changed
	m.latencyConfigChanged <- struct{}{}
}

func getRate(count int, d time.Duration, burst int) *rate.Limiter {
	r := float64(count) / (d.Seconds() * 0.9)
	return rate.NewLimiter(rate.Limit(r), burst)
}

func (m *MonitorTool) pingAll() {
	// Get all node internal/external IP.
	nodeIPs := m.latencyStore.ListNodeIPs()

	// TODO: Get current node internal/external IP.
	var fromIP string
	if m.gatewayConfig.IPv4 != nil {
		fromIP = m.gatewayConfig.IPv4.String()
	} else {
		fromIP = m.gatewayConfig.IPv6.String()
	}

	// A simple rate limiter
	limiter := getRate(len(nodeIPs), m.latencyConfig.Interval, m.latencyConfig.Limit)
	limitGroup := make(chan bool, int(m.latencyConfig.Limit))

	klog.InfoS("Start to ping all nodes")
	wg := sync.WaitGroup{}
	for name, toIP := range nodeIPs {
		limitGroup <- true
		limiter.Wait(context.Background())
		wg.Add(1)

		go func(toIP string, name string) {
			ctx, cancel := context.WithTimeout(context.Background(), m.latencyConfig.Timeout)
			defer cancel()
			defer wg.Done()

			ok, rtt := m.pingNode(ctx, toIP)
			if ok {
				m.latencyStore.UpdateConnByKey(name, &Connection{
					FromIP:      fromIP,
					ToIP:        toIP,
					Latency:     rtt,
					Status:      true,
					LastUpdated: time.Now(),
				})
			} else {
				m.latencyStore.UpdateConnByKey(name, &Connection{
					FromIP:      fromIP,
					ToIP:        toIP,
					Latency:     0,
					Status:      false,
					LastUpdated: time.Now(),
				})
			}

			<-limitGroup

		}(toIP, name)
	}

	wg.Wait()

	// TODO: Print all connection status for debug
	klog.InfoS("Finish to ping all nodes")
	conns := m.latencyStore.ListConns()
	for _, conn := range conns {
		klog.InfoS("Connection status", "Connection", conn)
	}
}

func (m *MonitorTool) pingNode(ctx context.Context, addr string) (bool, time.Duration) {
	var (
		socket      net.PacketConn
		requestType icmp.Type
		replyType   icmp.Type
	)

	// Resolve the IP address
	ip, err := net.ResolveIPAddr(IPProtocol, addr)
	if err != nil {
		klog.ErrorS(err, "Failed to resolve IP address")

		return false, 0
	}

	// Create a new ICMP packet connection
	if ip.IP.To4() == nil {
		requestType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply

		srcIP = net.ParseIP("::")

		// Try to use ipv6
		socket, err = icmp.ListenPacket(IPv6ProtocolICMPRaw, srcIP.String())
		if err != nil {
			klog.ErrorS(err, "Failed to listen on ICMP")
			return false, 0
		}
	} else {
		requestType = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply

		socket, err = icmp.ListenPacket(IPv4ProtocolICMPRaw, srcIP.String())
		if err != nil {
			klog.ErrorS(err, "Failed to listen on ICMP")
			return false, 0
		}
	}
	defer socket.Close()

	// Create a new ICMP packet
	body := &icmp.Echo{
		ID:   os.Getpid() & 0xffff, // Use the current process ID as the ICMP ID
		Seq:  int(getICMPSeq()),
		Data: []byte("HELLO-ANTREA-AGENT"),
	}
	msg := icmp.Message{
		Type: requestType,
		Code: 0,
		Body: body,
	}

	// Serialize the ICMP message
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		klog.ErrorS(err, "Failed to marshal ICMP message")
		return false, 0
	}
	rttStart := time.Now()
	if _, err = socket.WriteTo(msgBytes, ip); err != nil {
		klog.ErrorS(err, "Failed to write ICMP message")
		return false, 0
	}

	// Reply message
	msg.Type = replyType
	msgBytes, err = msg.Marshal(nil)
	if err != nil {
		klog.ErrorS(err, "Failed to marshal ICMP message")
		return false, 0
	}

	readBuffer := make([]byte, 1024)
	deadline, _ := ctx.Deadline()
	if err := socket.SetReadDeadline(deadline); err != nil {
		klog.ErrorS(err, "Failed to set read deadline")
		return false, 0
	}

	// Receive the ICMP message
	for {
		n, peer, err := socket.ReadFrom(readBuffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				klog.ErrorS(err, "Timeout reading ICMP message")
				return false, 0
			}

			klog.ErrorS(err, "Failed to read ICMP message")
			return false, 0
		}
		if peer.String() != ip.String() {
			klog.ErrorS(err, "Received ICMP message from unexpected peer")
			return false, 0
		}
		if replyType == ipv6.ICMPTypeEchoReply {
			// Clear checksum
			readBuffer[2] = 0
			readBuffer[3] = 0
		}
		if bytes.Equal(readBuffer[:n], msgBytes) {
			rtt := time.Since(rttStart)

			klog.InfoS("Received ICMP reply")
			return true, rtt
		}
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
				}

				// Start new pingAll goroutine
				go m.latencyStore.Run(innerStopCh)
				go wait.Until(m.pingAll, m.latencyConfig.Interval, innerStopCh)
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
