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
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/go-ping/ping"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
)

// MonitorTool is a tool to monitor the latency of the node.
type MonitorTool struct {
	latencyStore *LatencyStore

	interval time.Duration
	timeout  time.Duration
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

func NewNodeLatencyMonitor(nodeInformer coreinformers.NodeInformer, interval, timeout time.Duration) *MonitorTool {
	return &MonitorTool{
		latencyStore: NewLatencyStore(nodeInformer),
		interval:     interval,
		timeout:      timeout,
	}
}

func (m *MonitorTool) pingAll() {
	// Get all node internal/external IP.
	nodeIPs := m.latencyStore.ListNodeIPs()

	// TODO: Get current node internal/external IP.
	fromIP := ""

	klog.InfoS("Start to ping all nodes")
	wg := sync.WaitGroup{}
	for toIP, name := range nodeIPs {
		wg.Add(1)

		// TODO: Add ping limiter
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

func (m *MonitorTool) pingNode(ctx context.Context, ip string) (bool, time.Duration) {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		// Try to show log
		return false, 0
	}
	defer pinger.Stop()

	// Get timeout channel
	go func() {
		<-ctx.Done()
		pinger.Stop()
	}()

	err = pinger.Run()
	if err != nil {
		// Try to show log
		return false, 0
	}

	stats := pinger.Statistics()
	klog.InfoS("Ping statistics", "Statistics", stats)

	return true, stats.AvgRtt
}

func (m *MonitorTool) Run(stopCh <-chan struct{}) {
	// Watch node informer
	go m.latencyStore.Run(stopCh)
	// Run pingAll every interval
	go wait.Until(m.pingAll, m.interval, stopCh)

	<-stopCh
}
