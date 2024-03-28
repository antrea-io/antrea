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
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"

	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
)

var (
	icmpSeq      uint16
	icmpSeqMutex sync.Mutex
)

func getICMPSeq() uint16 {
	icmpSeqMutex.Lock()
	defer icmpSeqMutex.Unlock()
	icmpSeq++
	return icmpSeq
}

// MonitorTool is a tool to monitor the latency of the node.
type MonitorTool struct {
	latencyStore *LatencyStore

	// interval is the interval time to ping all nodes.
	interval time.Duration
	// timeout is the timeout time for each ping.
	timeout time.Duration
	// limit is the conncurrent limit of the ping.
	limit int
}

// TODO: Maybe we need to implement it like podStore.
// Simple nodeStore struct
type NodeStore struct {
	mutex     sync.RWMutex
	PingItems map[string]PingItem
}

// TODO: NodeInternalIP/NodeExternalIP
// We only need to store the NodeInternalIP of the node.
// In first step, we only use the nodeip tracker to get the node internal/external IP.
type PingItem struct {
	// Name is the name of the node.
	Name string
	// IP is the IP of the node.
	IPs []string
}

func NewNodeStore() *NodeStore {
	return &NodeStore{
		PingItems: make(map[string]PingItem),
	}
}

func (n *NodeStore) Clear() {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.PingItems = make(map[string]PingItem)
}

func (n *NodeStore) AddPingItem(name string, ips []string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.PingItems[name] = PingItem{
		Name: name,
		IPs:  ips,
	}
}

func (n *NodeStore) GetPingItem(name string) (PingItem, bool) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	item, found := n.PingItems[name]
	return item, found
}

func (n *NodeStore) DeletePingItem(name string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	delete(n.PingItems, name)
}

func (n *NodeStore) ListPingItems() []PingItem {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	items := make([]PingItem, 0, len(n.PingItems))
	for _, item := range n.PingItems {
		items = append(items, item)
	}
	return items
}

func (n *NodeStore) UpdatePingItem(name string, ips []string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.PingItems[name] = PingItem{
		Name: name,
		IPs:  ips,
	}
}

func NewNodeLatencyMonitor(nodeInformer coreinformers.NodeInformer, interval, timeout time.Duration, limit int) *MonitorTool {
	return &MonitorTool{
		latencyStore: NewLatencyStore(nodeInformer),
		interval:     interval,
		timeout:      timeout,
		limit:        limit,
	}
}

func getRate(count int, d time.Duration, burst int) *rate.Limiter {
	r := float64(count) / (d.Seconds() * 0.9)
	return rate.NewLimiter(rate.Limit(r), burst)
}

func (m *MonitorTool) pingAll() {
	// Get all node internal/external IP.
	nodeIPs := m.latencyStore.ListNodeIPs()

	// TODO: Get current node internal/external IP.
	fromIP := ""

	// A simple rate limiter
	limiter := getRate(len(nodeIPs), m.interval, m.limit)
	limitGroup := make(chan bool, int(m.limit))

	klog.InfoS("Start to ping all nodes")
	wg := sync.WaitGroup{}
	for toIP, name := range nodeIPs {
		limitGroup <- true
		limiter.Wait(context.Background())
		wg.Add(1)

		go func(toIP string, name string) {
			ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
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

// resolveIP resolves the target address to an IP address.
func resolveIPV4(ctx context.Context, target string) (*net.IPAddr, error) {
	IPProtocol := "ip4"

	klog.InfoS("Resolving target address", "ip_protocol", IPProtocol)

	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, target)
	if err != nil {
		klog.ErrorS(err, "Resolution with IP protocol failed")
		return nil, err
	}

	// Return the first IPv4 address
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			klog.InfoS("Resolved target address", "ip", ip.String())
			return &ip, nil
		}
	}

	return nil, fmt.Errorf("unable to find IPv4 address for target")
}

func (m *MonitorTool) pingNode(ctx context.Context, addr string) (bool, time.Duration) {
	// Resolve the IP address
	ip, err := resolveIPV4(ctx, addr)
	if err != nil {
		klog.ErrorS(err, "Failed to resolve IP address")

		return false, 0
	}

	srcIP := net.ParseIP("0.0.0.0")
	requestType := ipv4.ICMPTypeEcho
	replyType := ipv4.ICMPTypeEchoReply

	// TODO: Enable DontFragment?
	socket, err := net.ListenPacket("ip4:icmp", srcIP.String())
	if err != nil {
		klog.ErrorS(err, "Failed to listen on ICMP")
		return false, 0
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
		if replyType == ipv4.ICMPTypeTimeExceeded {
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
	// Watch node informer
	go m.latencyStore.Run(stopCh)
	// Run pingAll every interval
	go wait.Until(m.pingAll, m.interval, stopCh)

	<-stopCh
}
