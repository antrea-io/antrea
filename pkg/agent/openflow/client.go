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

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow/cookie"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

const maxRetryForOFSwitch = 5

// Client is the interface to program OVS flows for entity connectivity of Antrea.
type Client interface {
	// Initialize sets up all basic flows on the specific OVS bridge. It returns a channel which
	// is used to notify the caller in case of a reconnection, in which case ReplayFlows should
	// be called to ensure that the set of OVS flows is correct. All flows programmed in the
	// switch which match the current round number will be deleted before any new flow is
	// installed.
	Initialize(roundInfo types.RoundInfo, config *config.NodeConfig, encapMode config.TrafficEncapModeType, gatewayOFPort uint32) (<-chan struct{}, error)

	// InstallGatewayFlows sets up flows related to an OVS gateway port, the gateway must exist.
	InstallGatewayFlows(gatewayAddr net.IP, gatewayMAC net.HardwareAddr, gatewayOFPort uint32) error

	// InstallClusterServiceCIDRFlows sets up the appropriate flows so that traffic can reach
	// the different Services running in the Cluster. This method needs to be invoked once with
	// the Cluster Service CIDR as a parameter.
	InstallClusterServiceCIDRFlows(serviceNet *net.IPNet, gatewayMAC net.HardwareAddr, gatewayOFPort uint32) error

	// InstallDefaultTunnelFlows sets up the classification flow for the default (flow based) tunnel.
	InstallDefaultTunnelFlows(tunnelOFPort uint32) error

	// InstallNodeFlows should be invoked when a connection to a remote Node is going to be set
	// up. The hostname is used to identify the added flows. When IPSec tunnel is enabled,
	// ipsecTunOFPort must be set to the OFPort number of the IPSec tunnel port to the remote Node;
	// otherwise ipsecTunOFPort must be set to 0.
	// InstallNodeFlows has all-or-nothing semantics(call succeeds if all the flows are installed
	// successfully, otherwise no flows will be installed). Calls to InstallNodeFlows are idempotent.
	// Concurrent calls to InstallNodeFlows and / or UninstallNodeFlows are supported as long as they
	// are all for different hostnames.
	InstallNodeFlows(
		hostname string,
		localGatewayMAC net.HardwareAddr,
		peerPodCIDR net.IPNet,
		peerGatewayIP, tunnelPeerIP net.IP,
		tunOFPort, ipsecTunOFPort uint32) error

	// UninstallNodeFlows removes the connection to the remote Node specified with the
	// hostname. UninstallNodeFlows will do nothing if no connection to the host was established.
	UninstallNodeFlows(hostname string) error

	// InstallPodFlows should be invoked when a connection to a Pod on current Node. The
	// interfaceName is used to identify the added flows. InstallPodFlows has all-or-nothing
	// semantics(call succeeds if all the flows are installed successfully, otherwise no
	// flows will be installed). Calls to InstallPodFlows are idempotent. Concurrent calls
	// to InstallPodFlows and / or UninstallPodFlows are supported as long as they are all
	// for different interfaceNames.
	InstallPodFlows(interfaceName string, podInterfaceIP net.IP, podInterfaceMAC, gatewayMAC net.HardwareAddr, ofPort uint32) error

	// UninstallPodFlows removes the connection to the local Pod specified with the
	// interfaceName. UninstallPodFlows will do nothing if no connection to the Pod was established.
	UninstallPodFlows(interfaceName string) error

	// GetFlowTableStatus should return an array of flow table status, all existing flow tables should be included in the list.
	GetFlowTableStatus() []binding.TableStatus

	// InstallPolicyRuleFlows installs flows for a new NetworkPolicy rule. Rule should include all fields in the
	// NetworkPolicy rule. Each ingress/egress policy rule installs Openflow entries on two tables, one for
	// ruleTable and the other for dropTable. If a packet does not pass the ruleTable, it will be dropped by the
	// dropTable.
	InstallPolicyRuleFlows(ruleID uint32, rule *types.PolicyRule, npName, npNamespace string) error

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

	// ReplayFlows should be called when a spurious disconnection occurs. After we reconnect to
	// the OFSwitch, we need to replay all the flows cached by the client. ReplayFlows will try
	// to replay as many flows as possible, and will log an error when a flow cannot be
	// installed.
	ReplayFlows()

	// DeleteStaleFlows deletes all flows from the previous round which are no longer needed. It
	// should be called by the agent after all required flows have been installed / updated with
	// the new round number.
	DeleteStaleFlows() error

	// GetPodFlowKeys returns the keys (match strings) of the cached flows for a
	// Pod.
	GetPodFlowKeys(interfaceName string) []string

	// GetNetworkPolicyFlowKeys returns the keys (match strings) of the cached
	// flows for a NetworkPolicy. Flows are grouped by policy rules, and duplicated
	// entries can be added due to conjunctive match flows shared by multiple
	// rules.
	GetNetworkPolicyFlowKeys(npName, npNamespace string) []string
}

// GetFlowTableStatus returns an array of flow table status.
func (c *client) GetFlowTableStatus() []binding.TableStatus {
	return c.bridge.DumpTableStatus()
}

// IsConnected returns the connection status between client and OFSwitch.
func (c *client) IsConnected() bool {
	return c.bridge.IsConnected()
}

// addFlows installs the flows on the OVS bridge and then add them into the flow cache. If the flow cache exists,
// it will return immediately, otherwise it will use Bundle to add all flows, and then add them into the flow cache.
// If it fails to add the flows with Bundle, it will return the error and no flow cache is created.
func (c *client) addFlows(cache *flowCategoryCache, flowCacheKey string, flows []binding.Flow) error {
	_, ok := cache.Load(flowCacheKey)
	// If a flow cache entry already exists for the key, return immediately. Otherwise, add the flows to the switch
	// and populate the cache with them.
	if ok {
		klog.V(2).Infof("Flows with cache key %s are already installed", flowCacheKey)
		return nil
	}
	err := c.ofEntryOperations.AddAll(flows)
	if err != nil {
		return err
	}
	fCache := flowCache{}
	// Add the successfully installed flows into the flow cache.
	for _, flow := range flows {
		fCache[flow.MatchString()] = flow
	}
	cache.Store(flowCacheKey, fCache)
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
	// Delete flows from OVS.
	delFlows := make([]binding.Flow, 0, len(fCache))
	for _, flow := range fCache {
		delFlows = append(delFlows, flow)
	}
	if err := c.ofEntryOperations.DeleteAll(delFlows); err != nil {
		return err
	}
	cache.Delete(flowCacheKey)
	return nil
}

func (c *client) InstallNodeFlows(hostname string,
	localGatewayMAC net.HardwareAddr,
	peerPodCIDR net.IPNet,
	peerGatewayIP, tunnelPeerIP net.IP,
	tunOFPort, ipsecTunOFPort uint32) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	flows := []binding.Flow{
		c.arpResponderFlow(peerGatewayIP, cookie.Node),
	}
	if c.encapMode.NeedsEncapToPeer(tunnelPeerIP, c.nodeConfig.NodeIPAddr) {
		flows = append(flows, c.l3FwdFlowToRemote(localGatewayMAC, peerPodCIDR, tunnelPeerIP, tunOFPort, cookie.Node))
	} else {
		flows = append(flows, c.l3FwdFlowToRemoteViaGW(localGatewayMAC, peerPodCIDR, cookie.Node))
	}
	if ipsecTunOFPort != 0 {
		// When IPSec tunnel is enabled, packets received from the remote Node are
		// input from the Node's IPSec tunnel port, not the default tunnel port. So,
		// add a separate tunnelClassifierFlow for the IPSec tunnel port.
		flows = append(flows, c.tunnelClassifierFlow(ipsecTunOFPort, cookie.Node))
	}

	return c.addFlows(c.nodeFlowCache, hostname, flows)
}

func (c *client) UninstallNodeFlows(hostname string) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	return c.deleteFlows(c.nodeFlowCache, hostname)
}

func (c *client) InstallPodFlows(interfaceName string, podInterfaceIP net.IP, podInterfaceMAC, gatewayMAC net.HardwareAddr, ofPort uint32) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	flows := []binding.Flow{
		c.podClassifierFlow(ofPort, cookie.Pod),
		c.podIPSpoofGuardFlow(podInterfaceIP, podInterfaceMAC, ofPort, cookie.Pod),
		c.arpSpoofGuardFlow(podInterfaceIP, podInterfaceMAC, ofPort, cookie.Pod),
		c.l2ForwardCalcFlow(podInterfaceMAC, ofPort, cookie.Pod),
	}

	// NoEncap mode has no tunnel.
	if c.encapMode.SupportsEncap() {
		flows = append(flows, c.l3FlowsToPod(gatewayMAC, podInterfaceIP, podInterfaceMAC, cookie.Pod))
	}
	if c.encapMode.IsNetworkPolicyOnly() {
		// In policy-only mode, traffic to local Pod is routed based on destination IP.
		flows = append(flows,
			c.l3ToPodFlow(podInterfaceIP, podInterfaceMAC, cookie.Pod),
		)
	}
	return c.addFlows(c.podFlowCache, interfaceName, flows)
}

func (c *client) UninstallPodFlows(interfaceName string) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	return c.deleteFlows(c.podFlowCache, interfaceName)
}

func (c *client) GetPodFlowKeys(interfaceName string) []string {
	fCacheI, ok := c.podFlowCache.Load(interfaceName)
	if !ok {
		return nil
	}

	fCache := fCacheI.(flowCache)
	flowKeys := make([]string, 0, len(fCache))
	// ReplayFlows() could change Flow internal state. Although its current
	// implementation does not impact Flow match string generation, we still
	// acquire read lock of replayMutex here for logic cleanliness.
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	for _, flow := range fCache {
		flowKeys = append(flowKeys, flow.MatchString())
	}
	return flowKeys
}

func (c *client) InstallClusterServiceCIDRFlows(serviceNet *net.IPNet, gatewayMAC net.HardwareAddr, gatewayOFPort uint32) error {
	flow := c.serviceCIDRDNATFlow(serviceNet, gatewayMAC, gatewayOFPort, cookie.Service)
	if err := c.ofEntryOperations.Add(flow); err != nil {
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
		c.l2ForwardCalcFlow(gatewayMAC, gatewayOFPort, cookie.Default),
		c.localProbeFlow(gatewayAddr, cookie.Default),
	}

	// In NoEncap , no traffic from tunnel port
	if c.encapMode.SupportsEncap() {
		flows = append(flows, c.l3ToGatewayFlow(gatewayAddr, gatewayMAC, cookie.Default))
	}

	if c.encapMode.SupportsNoEncap() {
		flows = append(flows, c.reEntranceBypassCTFlow(gatewayOFPort, gatewayOFPort, cookie.Default))
	}

	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return err
	}
	c.gatewayFlows = flows
	return nil
}

func (c *client) InstallDefaultTunnelFlows(tunnelOFPort uint32) error {
	flow := c.tunnelClassifierFlow(tunnelOFPort, cookie.Default)
	if err := c.ofEntryOperations.Add(flow); err != nil {
		return err
	}
	c.defaultTunnelFlows = []binding.Flow{flow}
	return nil
}

func (c *client) initialize() error {
	if err := c.ofEntryOperations.AddAll(c.defaultFlows()); err != nil {
		return fmt.Errorf("failed to install default flows: %v", err)
	}
	if err := c.ofEntryOperations.Add(c.arpNormalFlow(cookie.Default)); err != nil {
		return fmt.Errorf("failed to install arp normal flow: %v", err)
	}
	if err := c.ofEntryOperations.Add(c.l2ForwardOutputFlow(cookie.Default)); err != nil {
		return fmt.Errorf("failed to install L2 forward output flows: %v", err)
	}
	if err := c.ofEntryOperations.AddAll(c.connectionTrackFlows(cookie.Default)); err != nil {
		return fmt.Errorf("failed to install connection track flows: %v", err)
	}
	if err := c.ofEntryOperations.AddAll(c.establishedConnectionFlows(cookie.Default)); err != nil {
		return fmt.Errorf("failed to install flows to skip established connections: %v", err)
	}

	if c.encapMode.SupportsNoEncap() {
		if err := c.ofEntryOperations.Add(c.l2ForwardOutputReentInPortFlow(c.gatewayPort, cookie.Default)); err != nil {
			return fmt.Errorf("failed to install L2 forward same in-port and out-port flow: %v", err)
		}
	}
	if c.encapMode.IsNetworkPolicyOnly() {
		if err := c.setupPolicyOnlyFlows(); err != nil {
			return fmt.Errorf("failed to setup policy only flows: %w", err)
		}
	}
	return nil
}

func (c *client) Initialize(roundInfo types.RoundInfo, nodeConfig *config.NodeConfig, encapMode config.TrafficEncapModeType, gatewayOFPort uint32) (<-chan struct{}, error) {
	c.nodeConfig = nodeConfig
	c.encapMode = encapMode
	c.gatewayPort = gatewayOFPort

	// Initiate connections to target OFswitch, and create tables on the switch.
	connCh := make(chan struct{})
	if err := c.bridge.Connect(maxRetryForOFSwitch, connCh); err != nil {
		return nil, err
	}

	// Ignore first notification, it is not a "reconnection".
	<-connCh

	c.roundInfo = roundInfo
	c.cookieAllocator = cookie.NewAllocator(roundInfo.RoundNum)

	// In the normal case, there should be no existing flows with the current round number. This
	// is needed in case the agent was restarted before we had a chance to increment the round
	// number (incrementing the round number happens once we are satisfied that stale flows from
	// the previous round have been deleted).
	if err := c.deleteFlowsByRoundNum(roundInfo.RoundNum); err != nil {
		return nil, fmt.Errorf("error when deleting exiting flows for current round number: %v", err)
	}

	return connCh, c.initialize()
}

func (c *client) ReplayFlows() {
	c.replayMutex.Lock()
	defer c.replayMutex.Unlock()

	if err := c.initialize(); err != nil {
		klog.Errorf("Error during flow replay: %v", err)
	}

	addFixedFlows := func(flows []binding.Flow) {
		for _, flow := range flows {
			flow.Reset()
		}
		if err := c.ofEntryOperations.AddAll(flows); err != nil {
			klog.Errorf("Error when replaying fixed flows: %v", err)
		}

	}

	addFixedFlows(c.gatewayFlows)
	addFixedFlows(c.clusterServiceCIDRFlows)
	addFixedFlows(c.defaultTunnelFlows)

	installCachedFlows := func(key, value interface{}) bool {
		fCache := value.(flowCache)
		cachedFlows := make([]binding.Flow, 0)

		for _, flow := range fCache {
			flow.Reset()
			cachedFlows = append(cachedFlows, flow)
		}

		if err := c.ofEntryOperations.AddAll(cachedFlows); err != nil {
			klog.Errorf("Error when replaying cached flows: %v", err)
		}
		return true
	}

	c.nodeFlowCache.Range(installCachedFlows)
	c.podFlowCache.Range(installCachedFlows)

	c.replayPolicyFlows()
}

func (c *client) deleteFlowsByRoundNum(roundNum uint64) error {
	cookieID, cookieMask := cookie.CookieMaskForRound(roundNum)
	return c.bridge.DeleteFlowsByCookie(cookieID, cookieMask)
}

func (c *client) DeleteStaleFlows() error {
	if c.roundInfo.PrevRoundNum == nil {
		klog.V(2).Info("Previous round number is unset, no flows to delete")
		return nil
	}
	return c.deleteFlowsByRoundNum(*c.roundInfo.PrevRoundNum)
}

func (c *client) setupPolicyOnlyFlows() error {
	flows := []binding.Flow{
		// Bypasses remaining l3forwarding flows if the MAC is set via ctRewriteDstMACFlow.
		c.l3BypassMACRewriteFlow(c.nodeConfig.GatewayConfig.MAC, cookie.Default),
		// Rewrites MAC to gw port if the packet received is unmatched by local Pod flows.
		c.l3ToGWFlow(c.nodeConfig.GatewayConfig.MAC, cookie.Default),
		// Replies any ARP request with the same global virtual MAC.
		c.arpResponderStaticFlow(cookie.Default),
	}
	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return fmt.Errorf("failed to setup policy-only flows: %w", err)
	}
	return nil
}
