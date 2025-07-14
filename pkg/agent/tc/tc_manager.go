// Copyright 2024 Antrea Authors
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

package tc

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

// Manager handles traffic control (tc) rules for bypassing netfilter
// in noEncap mode to improve Pod-to-Pod performance.
type Manager struct {
	mu sync.RWMutex

	// Interface names
	transportInterface string
	gatewayInterface   string

	// Pod CIDR for local Pods
	localPodCIDR *net.IPNet

	// Maps to track installed rules
	localPodRules   map[string]*TCRule // key: Pod IP
	remoteNodeRules map[string]*TCRule // key: Node IP

	// Node MAC addresses for remote Nodes
	nodeMACs map[string]net.HardwareAddr // key: Node IP

	enabled bool
}

// TCRule represents a traffic control rule
type TCRule struct {
	Interface string
	Direction string // "ingress" or "egress"
	Protocol  string // "ip" or "ipv6"
	Match     string // e.g., "dst_ip 10.0.0.1"
	Action    string // e.g., "pedit ex munge eth dst set 00:11:22:33:44:55 pipe mirred egress redirect dev antrea-gw0"
}

// NewManager creates a new TC manager
func NewManager(transportInterface, gatewayInterface string, localPodCIDR *net.IPNet) *Manager {
	return &Manager{
		transportInterface: transportInterface,
		gatewayInterface:   gatewayInterface,
		localPodCIDR:       localPodCIDR,
		localPodRules:      make(map[string]*TCRule),
		remoteNodeRules:    make(map[string]*TCRule),
		nodeMACs:           make(map[string]net.HardwareAddr),
	}
}

// Enable activates the TC manager and sets up the basic infrastructure
func (m *Manager) Enable() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.enabled {
		return nil
	}

	// Add clsact qdisc to both interfaces
	if err := m.addClsactQdisc(m.transportInterface); err != nil {
		return fmt.Errorf("failed to add clsact qdisc to transport interface: %v", err)
	}
	if err := m.addClsactQdisc(m.gatewayInterface); err != nil {
		return fmt.Errorf("failed to add clsact qdisc to gateway interface: %v", err)
	}

	m.enabled = true
	klog.InfoS("TC manager enabled", "transportInterface", m.transportInterface, "gatewayInterface", m.gatewayInterface)
	return nil
}

// Disable deactivates the TC manager and removes all rules
func (m *Manager) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled {
		return nil
	}

	// Remove all rules
	for podIP := range m.localPodRules {
		if err := m.removeLocalPodRule(podIP); err != nil {
			klog.ErrorS(err, "Failed to remove local Pod TC rule", "podIP", podIP)
		}
	}

	for nodeIP := range m.remoteNodeRules {
		if err := m.removeRemoteNodeRule(nodeIP); err != nil {
			klog.ErrorS(err, "Failed to remove remote Node TC rule", "nodeIP", nodeIP)
		}
	}

	m.enabled = false
	klog.InfoS("TC manager disabled")
	return nil
}

// AddLocalPod adds a TC rule for a local Pod to redirect traffic from transport interface to gateway interface
func (m *Manager) AddLocalPod(podIP net.IP, podMAC net.HardwareAddr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled {
		return fmt.Errorf("TC manager is not enabled")
	}

	podIPStr := podIP.String()
	if _, exists := m.localPodRules[podIPStr]; exists {
		return nil // Rule already exists
	}

	// Create TC rule: transport interface -> gateway interface
	rule := &TCRule{
		Interface: m.transportInterface,
		Direction: "ingress",
		Protocol:  "ip",
		Match:     fmt.Sprintf("dst_ip %s", podIPStr),
		Action:    fmt.Sprintf("pedit ex munge eth dst set %s pipe mirred egress redirect dev %s", podMAC.String(), m.gatewayInterface),
	}

	if err := m.addTCRule(rule); err != nil {
		return fmt.Errorf("failed to add TC rule for local Pod %s: %v", podIPStr, err)
	}

	m.localPodRules[podIPStr] = rule
	klog.V(2).InfoS("Added TC rule for local Pod", "podIP", podIPStr, "podMAC", podMAC.String())
	return nil
}

// RemoveLocalPod removes the TC rule for a local Pod
func (m *Manager) RemoveLocalPod(podIP net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.removeLocalPodRule(podIP.String())
}

// AddRemoteNode adds a TC rule for a remote Node to redirect traffic from gateway interface to transport interface
func (m *Manager) AddRemoteNode(nodeIP net.IP, nodeMAC net.HardwareAddr, podCIDR *net.IPNet) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled {
		return fmt.Errorf("TC manager is not enabled")
	}

	nodeIPStr := nodeIP.String()
	if _, exists := m.remoteNodeRules[nodeIPStr]; exists {
		return nil // Rule already exists
	}

	// Create TC rule: gateway interface -> transport interface
	rule := &TCRule{
		Interface: m.gatewayInterface,
		Direction: "ingress",
		Protocol:  "ip",
		Match:     fmt.Sprintf("dst_ip %s", podCIDR.String()),
		Action:    fmt.Sprintf("pedit ex munge eth dst set %s pipe mirred egress redirect dev %s", nodeMAC.String(), m.transportInterface),
	}

	if err := m.addTCRule(rule); err != nil {
		return fmt.Errorf("failed to add TC rule for remote Node %s: %v", nodeIPStr, err)
	}

	m.remoteNodeRules[nodeIPStr] = rule
	m.nodeMACs[nodeIPStr] = nodeMAC
	klog.V(2).InfoS("Added TC rule for remote Node", "nodeIP", nodeIPStr, "nodeMAC", nodeMAC.String(), "podCIDR", podCIDR.String())
	return nil
}

// RemoveRemoteNode removes the TC rule for a remote Node
func (m *Manager) RemoveRemoteNode(nodeIP net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.removeRemoteNodeRule(nodeIP.String())
}

// addClsactQdisc adds a clsact qdisc to the specified interface
// Uses netlink to check if qdisc exists, falls back to tc command for creation
func (m *Manager) addClsactQdisc(interfaceName string) error {
	// First check if the interface exists using netlink
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %v", interfaceName, err)
	}

	// Use tc command to add clsact qdisc (netlink doesn't have good TC support)
	cmd := exec.Command("tc", "qdisc", "add", "dev", interfaceName, "clsact")
	if output, err := cmd.CombinedOutput(); err != nil {
		// If qdisc already exists, that's fine
		if !strings.Contains(string(output), "File exists") {
			return fmt.Errorf("failed to add clsact qdisc: %v, output: %s", err, string(output))
		}
	}

	klog.V(4).InfoS("Added clsact qdisc to interface", "interface", interfaceName, "linkIndex", link.Attrs().Index)
	return nil
}

// addTCRule adds a TC rule using the tc command
// Note: Using tc command because netlink TC support is limited and complex
func (m *Manager) addTCRule(rule *TCRule) error {
	args := []string{
		"filter", "add", "dev", rule.Interface, rule.Direction,
		"protocol", rule.Protocol,
		"flower", rule.Match,
		"action", rule.Action,
	}

	cmd := exec.Command("tc", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add TC rule: %v, output: %s", err, string(output))
	}

	klog.V(4).InfoS("Added TC rule", "interface", rule.Interface, "direction", rule.Direction, "match", rule.Match)
	return nil
}

// removeTCRule removes a TC rule using the tc command
func (m *Manager) removeTCRule(rule *TCRule) error {
	args := []string{
		"filter", "del", "dev", rule.Interface, rule.Direction,
		"protocol", rule.Protocol,
		"flower", rule.Match,
	}

	cmd := exec.Command("tc", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		// If rule doesn't exist, that's fine
		if !strings.Contains(string(output), "No such file or directory") {
			return fmt.Errorf("failed to remove TC rule: %v, output: %s", err, string(output))
		}
	}

	klog.V(4).InfoS("Removed TC rule", "interface", rule.Interface, "direction", rule.Direction, "match", rule.Match)
	return nil
}

// removeLocalPodRule removes a local Pod TC rule
func (m *Manager) removeLocalPodRule(podIP string) error {
	rule, exists := m.localPodRules[podIP]
	if !exists {
		return nil
	}

	if err := m.removeTCRule(rule); err != nil {
		return fmt.Errorf("failed to remove local Pod TC rule: %v", err)
	}

	delete(m.localPodRules, podIP)
	klog.V(2).InfoS("Removed TC rule for local Pod", "podIP", podIP)
	return nil
}

// removeRemoteNodeRule removes a remote Node TC rule
func (m *Manager) removeRemoteNodeRule(nodeIP string) error {
	rule, exists := m.remoteNodeRules[nodeIP]
	if !exists {
		return nil
	}

	if err := m.removeTCRule(rule); err != nil {
		return fmt.Errorf("failed to remove remote Node TC rule: %v", err)
	}

	delete(m.remoteNodeRules, nodeIP)
	delete(m.nodeMACs, nodeIP)
	klog.V(2).InfoS("Removed TC rule for remote Node", "nodeIP", nodeIP)
	return nil
}

// IsEnabled returns whether the TC manager is enabled
func (m *Manager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// GetStats returns statistics about the TC manager
func (m *Manager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"enabled":            m.enabled,
		"localPodRules":      len(m.localPodRules),
		"remoteNodeRules":    len(m.remoteNodeRules),
		"transportInterface": m.transportInterface,
		"gatewayInterface":   m.gatewayInterface,
	}
}

// AddPodRules is a convenience method for adding Pod rules
func (m *Manager) AddPodRules(interfaceName string, podIP net.IP, ofPort uint32) error {
	// This method can be used for additional Pod-specific rules if needed
	// For now, it's a placeholder for future extensions
	return nil
}
