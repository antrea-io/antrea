// Copyright 2019 Antrea Authors
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

package openflow

import (
	"fmt"
	"net"

	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow/cookie"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

const maxRetryForOFSwitch = 5

// Client is the interface to program OVS flows for entity connectivity of Antrea.
type Client interface {
	// Initialize sets up all basic flows on the specific OVS bridge.
	Initialize(roundNum uint64) (<-chan struct{}, error)

	// InstallGatewayFlows sets up flows related to an OVS gateway port, the gateway must exist.
	InstallGatewayFlows(gatewayAddr net.IP, gatewayMAC net.HardwareAddr, gatewayOFPort uint32) error

	// InstallClusterServiceCIDRFlows sets up the appropriate flows so that traffic can reach
	// the different Services running in the Cluster. This method needs to be invoked once with
	// the Cluster Service CIDR as a parameter.
	InstallClusterServiceCIDRFlows(serviceNet *net.IPNet, gatewayOFPort uint32) error

	// InstallDefaultTunnelFlows sets up the classification flow for the default (flow based) tunnel.
	InstallDefaultTunnelFlows(tunnelOFPort uint32) error

	// InstallNodeFlows should be invoked when a connection to a remote Node is going to be set
	// up. The hostname is used to identify the added flows. When using the flow based tunnel,
	// tunnelPeerIP must be provided, otherwise it should be set to nil.
	// Calls to InstallNodeFlows are idempotent. Concurrent calls to InstallNodeFlows and / or
	// UninstallNodeFlows are supported as long as they are all for different hostnames.
	InstallNodeFlows(hostname string, localGatewayMAC net.HardwareAddr, peerGatewayIP net.IP, peerPodCIDR net.IPNet, tunnelPeerAddr net.IP, tunOFPort uint32) error

	// UninstallNodeFlows removes the connection to the remote Node specified with the
	// hostname. UninstallNodeFlows will do nothing if no connection to the host was established.
	UninstallNodeFlows(hostname string) error

	// InstallPodFlows should be invoked when a connection to a Pod on current Node. The
	// containerID is used to identify the added flows. Calls to InstallPodFlows are
	// idempotent. Concurrent calls to InstallPodFlows and / or UninstallPodFlows are
	// supported as long as they are all for different containerIDs.
	InstallPodFlows(containerID string, podInterfaceIP net.IP, podInterfaceMAC, gatewayMAC net.HardwareAddr, ofPort uint32) error

	// UninstallPodFlows removes the connection to the local Pod specified with the
	// containerID. UninstallPodFlows will do nothing if no connection to the Pod was established.
	UninstallPodFlows(containerID string) error

	// GetFlowTableStatus should return an array of flow table status, all existing flow tables should be included in the list.
	GetFlowTableStatus() []binding.TableStatus

	// InstallPolicyRuleFlows installs flows for a new NetworkPolicy rule. Rule should include all fields in the
	// NetworkPolicy rule. Each ingress/egress policy rule installs Openflow entries on two tables, one for
	// ruleTable and the other for dropTable. If a packet does not pass the ruleTable, it will be dropped by the
	// dropTable.
	InstallPolicyRuleFlows(rule *types.PolicyRule) error

	// UninstallPolicyRuleFlows removes the Openflow entry relevant to the specified NetworkPolicy rule.
	// UninstallPolicyRuleFlows will do nothing if no Openflow entry for the rule is installed.
	UninstallPolicyRuleFlows(ruleID uint32) error

	// AddPolicyRuleAddress adds one or multiple addresses to the specified NetworkPolicy rule. If addrType is true, the
	// addresses are added to PolicyRule.From, else to PolicyRule.To.
	AddPolicyRuleAddress(ruleID uint32, addrType types.AddressType, addresses []types.Address) error

	// DeletePolicyRuleAddress removes addresses from the specified NetworkPolicy rule. If addrType is srcAddress, the addresses
	// are removed from PolicyRule.From, else from PolicyRule.To.
	DeletePolicyRuleAddress(ruleID uint32, addrType types.AddressType, addresses []types.Address) error

	// Disconnect disconnects the connection between client and OFSwitch.
	Disconnect() error

	// IsConnected returns the connection status between client and OFSwitch. The return value is true if the OFSwitch is connected.
	IsConnected() bool

	// Reconcile should be called when a spurious disconnection occurs. After we reconnect to
	// the OFSwitch, we need to replay all the flows cached by the client. Reconcile will try to
	// replay as many flows as possible, and will log an error when a flow cannot be installed.
	Reconcile()
}

// GetFlowTableStatus returns an array of flow table status.
func (c *client) GetFlowTableStatus() []binding.TableStatus {
	return c.bridge.DumpTableStatus()
}

// IsConnected returns the connection status between client and OFSwitch.
func (c *client) IsConnected() bool {
	return c.bridge.IsConnected()
}

// addMissingFlows adds any flow from flows which is not currently in the flow cache. The function
// returns immediately in case of error when adding a flow. If a flow is added successfully, it is
// added to the flow cache. If the flow cache has not been initialized yet (i.e. there is no
// flowCacheKey key in the cache map), we create it first.
func (c *client) addMissingFlows(cache *flowCategoryCache, flowCacheKey string, flows []binding.Flow) error {
	// initialize flow cache if needed
	fCacheI, _ := cache.LoadOrStore(flowCacheKey, flowCache{})
	fCache := fCacheI.(flowCache)

	for _, flow := range flows {
		flowKey := flow.MatchString()
		if _, ok := fCache[flowKey]; ok {
			continue
		}
		if err := c.flowOperations.Add(flow); err != nil {
			return err
		}
		fCache[flow.MatchString()] = flow
	}
	return nil
}

// deleteFlows deletes all the flows in the flow cache indexed by the provided flowCacheKey.
func (c *client) deleteFlows(cache *flowCategoryCache, flowCacheKey string) error {
	fCacheI, ok := cache.Load(flowCacheKey)
	if !ok {
		// no matching flows found in the cache
		return nil
	}
	fCache := fCacheI.(flowCache)

	// delete flowCache from the top-level cache if all flows were successfully deleted
	defer func() {
		if len(fCache) == 0 {
			cache.Delete(flowCacheKey)
		}
	}()

	for flowKey, flow := range fCache {
		if err := c.flowOperations.Delete(flow); err != nil {
			return err
		}
		delete(fCache, flowKey)
	}
	return nil
}

func (c *client) InstallNodeFlows(hostname string,
	localGatewayMAC net.HardwareAddr,
	peerGatewayIP net.IP,
	peerPodCIDR net.IPNet,
	tunnelPeerAddr net.IP,
	tunOFPort uint32,
) error {
	c.reconcileMutex.RLock()
	defer c.reconcileMutex.RUnlock()
	flows := make([]binding.Flow, 2, 3)
	flows[0] = c.arpResponderFlow(peerGatewayIP, cookie.Node)
	flows[1] = c.l3FwdFlowToRemote(localGatewayMAC, peerPodCIDR, tunnelPeerAddr, tunOFPort, cookie.Node)
	if tunnelPeerAddr == nil {
		// Not the default (flow based) tunnel. Add a separate tunnelClassifierFlow.
		flows = append(flows, c.tunnelClassifierFlow(tunOFPort, cookie.Node))
	}
	return c.addMissingFlows(c.nodeFlowCache, hostname, flows)
}

func (c *client) UninstallNodeFlows(hostname string) error {
	c.reconcileMutex.RLock()
	defer c.reconcileMutex.RUnlock()
	return c.deleteFlows(c.nodeFlowCache, hostname)
}

func (c *client) InstallPodFlows(containerID string, podInterfaceIP net.IP, podInterfaceMAC, gatewayMAC net.HardwareAddr, ofPort uint32) error {
	c.reconcileMutex.RLock()
	defer c.reconcileMutex.RUnlock()
	flows := []binding.Flow{
		c.podClassifierFlow(ofPort, cookie.Pod),
		c.podIPSpoofGuardFlow(podInterfaceIP, podInterfaceMAC, ofPort, cookie.Pod),
		c.arpSpoofGuardFlow(podInterfaceIP, podInterfaceMAC, ofPort, cookie.Pod),
		c.l2ForwardCalcFlow(podInterfaceMAC, ofPort, cookie.Pod),
		c.l3FlowsToPod(gatewayMAC, podInterfaceIP, podInterfaceMAC, cookie.Pod),
	}

	return c.addMissingFlows(c.podFlowCache, containerID, flows)
}

func (c *client) UninstallPodFlows(containerID string) error {
	c.reconcileMutex.RLock()
	defer c.reconcileMutex.RUnlock()
	return c.deleteFlows(c.podFlowCache, containerID)
}

func (c *client) InstallClusterServiceCIDRFlows(serviceNet *net.IPNet, gatewayOFPort uint32) error {
	flow := c.serviceCIDRDNATFlow(serviceNet, gatewayOFPort, cookie.Service)
	if err := c.flowOperations.Add(flow); err != nil {
		return err
	}
	c.clusterServiceCIDRFlows = []binding.Flow{flow}
	return nil
}

func (c *client) InstallGatewayFlows(gatewayAddr net.IP, gatewayMAC net.HardwareAddr, gatewayOFPort uint32) error {
	flows := []binding.Flow{
		c.gatewayClassifierFlow(gatewayOFPort, cookie.Default),
		c.gatewayIPSpoofGuardFlow(gatewayOFPort, cookie.Default),
		c.gatewayARPSpoofGuardFlow(gatewayOFPort, gatewayAddr, gatewayMAC, cookie.Default),
		c.ctRewriteDstMACFlow(gatewayMAC, cookie.Default),
		c.l3ToGatewayFlow(gatewayAddr, gatewayMAC, cookie.Default),
		c.l2ForwardCalcFlow(gatewayMAC, gatewayOFPort, cookie.Default),
		c.localProbeFlow(gatewayAddr, cookie.Default),
	}
	for _, flow := range flows {
		if err := c.flowOperations.Add(flow); err != nil {
			return err
		}
	}
	c.gatewayFlows = flows
	return nil
}

func (c *client) InstallDefaultTunnelFlows(tunnelOFPort uint32) error {
	flow := c.tunnelClassifierFlow(tunnelOFPort, cookie.Default)
	if err := c.flowOperations.Add(flow); err != nil {
		return err
	}
	c.defaultTunnelFlows = []binding.Flow{flow}
	return nil
}

func (c *client) initialize() error {
	for _, flow := range c.defaultFlows() {
		if err := c.flowOperations.Add(flow); err != nil {
			return fmt.Errorf("failed to install default flows: %v", err)
		}
	}
	if err := c.flowOperations.Add(c.arpNormalFlow(cookie.Default)); err != nil {
		return fmt.Errorf("failed to install arp normal flow: %v", err)
	}
	if err := c.flowOperations.Add(c.l2ForwardOutputFlow(cookie.Default)); err != nil {
		return fmt.Errorf("failed to install l2 forward output flows: %v", err)
	}
	for _, flow := range c.connectionTrackFlows(cookie.Default) {
		if err := c.flowOperations.Add(flow); err != nil {
			return fmt.Errorf("failed to install connection track flows: %v", err)
		}
	}
	for _, flow := range c.establishedConnectionFlows(cookie.Default) {
		if err := flow.Add(); err != nil {
			return fmt.Errorf("failed to install flows to skip established connections: %v", err)
		}
	}
	return nil
}

func (c *client) Initialize(roundNum uint64) (<-chan struct{}, error) {
	// Initiate connections to target OFswitch, and create tables on the switch.
	connCh := make(chan struct{})
	if err := c.bridge.Connect(maxRetryForOFSwitch, connCh); err != nil {
		return nil, err
	}

	// Ignore first notification, it is not a "reconnection".
	<-connCh

	c.cookieAllocator = cookie.NewAllocator(roundNum)

	return connCh, c.initialize()
}

func (c *client) Reconcile() {
	c.reconcileMutex.Lock()
	defer c.reconcileMutex.Unlock()

	if err := c.initialize(); err != nil {
		klog.Errorf("Error during flow replay: %v", err)
	}

	addFixedFlows := func(flows []binding.Flow) {
		for _, flow := range flows {
			flow.Reset()
			if err := c.flowOperations.Add(flow); err != nil {
				klog.Errorf("Error when replaying flow: %v", err)
			}
		}
	}

	addFixedFlows(c.gatewayFlows)
	addFixedFlows(c.clusterServiceCIDRFlows)
	addFixedFlows(c.defaultTunnelFlows)

	installCachedFlows := func(key, value interface{}) bool {
		fCache := value.(flowCache)
		for _, flow := range fCache {
			flow.Reset()
			if err := c.flowOperations.Add(flow); err != nil {
				klog.Errorf("Error when replaying flow: %v", err)
			}
		}
		return true
	}

	c.nodeFlowCache.Range(installCachedFlows)
	c.podFlowCache.Range(installCachedFlows)

	c.reconcilePolicyFlows()
}
