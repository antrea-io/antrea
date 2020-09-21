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
	"math/rand"
	"net"

	"github.com/contiv/ofnet/ofctrl"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow/cookie"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	"github.com/vmware-tanzu/antrea/third_party/proxy"
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
	InstallGatewayFlows(gatewayAddrs []net.IP, gatewayMAC net.HardwareAddr, gatewayOFPort uint32) error

	// InstallBridgeUplinkFlows installs Openflow flows between bridge local port and uplink port to support
	// host networking. These flows are only needed on windows platform.
	InstallBridgeUplinkFlows(uplinkPort uint32, bridgeLocalPort uint32) error

	// InstallClusterServiceCIDRFlows sets up the appropriate flows so that traffic can reach
	// the different Services running in the Cluster. This method needs to be invoked once with
	// the Cluster Service CIDR as a parameter.
	InstallClusterServiceCIDRFlows(serviceNets []*net.IPNet, gatewayMAC net.HardwareAddr, gatewayOFPort uint32) error

	// InstallClusterServiceFlows sets up the appropriate flows so that traffic can reach
	// the different Services running in the Cluster. This method needs to be invoked once.
	InstallClusterServiceFlows() error

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
		peerConfigs map[*net.IPNet]net.IP,
		tunnelPeerIP net.IP,
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
	InstallPodFlows(interfaceName string, podInterfaceIPs []net.IP, podInterfaceMAC, gatewayMAC net.HardwareAddr, ofPort uint32) error

	// UninstallPodFlows removes the connection to the local Pod specified with the
	// interfaceName. UninstallPodFlows will do nothing if no connection to the Pod was established.
	UninstallPodFlows(interfaceName string) error

	// InstallServiceGroup installs a group for Service LB. Each endpoint
	// is a bucket of the group. For now, each bucket has the same weight.
	InstallServiceGroup(groupID binding.GroupIDType, withSessionAffinity bool, endpoints []proxy.Endpoint) error
	// UninstallServiceGroup removes the group and its buckets that are
	// installed by InstallServiceGroup.
	UninstallServiceGroup(groupID binding.GroupIDType) error

	// InstallEndpointFlows installs flows for accessing Endpoints.
	// If an Endpoint is on the current Node, then flows for hairpin and endpoint
	// L2 forwarding should also be installed.
	InstallEndpointFlows(protocol binding.Protocol, endpoints []proxy.Endpoint) error
	// UninstallEndpointFlows removes flows of the Endpoint installed by
	// InstallEndpointFlows.
	UninstallEndpointFlows(protocol binding.Protocol, endpoint proxy.Endpoint) error

	// InstallServiceFlows installs flows for accessing Service with clusterIP.
	// It installs the flow that uses the group/bucket to do service LB. If the
	// affinityTimeout is not zero, it also installs the flow which has a learn
	// action to maintain the LB decision.
	// The group with the groupID must be installed before, otherwise the
	// installation will fail.
	InstallServiceFlows(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol, affinityTimeout uint16) error
	// UninstallServiceFlows removes flows installed by InstallServiceFlows.
	UninstallServiceFlows(svcIP net.IP, svcPort uint16, protocol binding.Protocol) error
	// InstallLoadBalancerServiceFromOutsideFlows installs flows for LoadBalancer Service traffic from outside node.
	// The traffic is received from uplink port and will be forwarded to gateway by the installed flows. And then
	// kube-proxy will handle the traffic.
	// This function is only used for Windows platform.
	InstallLoadBalancerServiceFromOutsideFlows(svcIP net.IP, svcPort uint16, protocol binding.Protocol) error

	// GetFlowTableStatus should return an array of flow table status, all existing flow tables should be included in the list.
	GetFlowTableStatus() []binding.TableStatus

	// InstallPolicyRuleFlows installs flows for a new NetworkPolicy rule. Rule should include all fields in the
	// NetworkPolicy rule. Each ingress/egress policy rule installs Openflow entries on two tables, one for
	// ruleTable and the other for dropTable. If a packet does not pass the ruleTable, it will be dropped by the
	// dropTable.
	InstallPolicyRuleFlows(ofPolicyRule *types.PolicyRule) error

	// BatchInstallPolicyRuleFlows installs multiple flows for NetworkPolicy rules in batch.
	BatchInstallPolicyRuleFlows(ofPolicyRules []*types.PolicyRule) error

	// UninstallPolicyRuleFlows removes the Openflow entry relevant to the specified NetworkPolicy rule.
	// It also returns a slice of stale ofPriorities used by ClusterNetworkPolicies.
	// UninstallPolicyRuleFlows will do nothing if no Openflow entry for the rule is installed.
	UninstallPolicyRuleFlows(ruleID uint32) ([]string, error)

	// AddPolicyRuleAddress adds one or multiple addresses to the specified NetworkPolicy rule. If addrType is true, the
	// addresses are added to PolicyRule.From, else to PolicyRule.To.
	AddPolicyRuleAddress(ruleID uint32, addrType types.AddressType, addresses []types.Address, priority *uint16) error

	// DeletePolicyRuleAddress removes addresses from the specified NetworkPolicy rule. If addrType is srcAddress, the addresses
	// are removed from PolicyRule.From, else from PolicyRule.To.
	DeletePolicyRuleAddress(ruleID uint32, addrType types.AddressType, addresses []types.Address, priority *uint16) error

	// InstallExternalFlows sets up flows to enable Pods to communicate to the external IP addresses. The corresponding
	// OpenFlow entries include: 1) identify the packets from local Pods to the external IP address, 2) mark the traffic
	// in the connection tracking context, and 3) SNAT the packets with Node IP.
	InstallExternalFlows(nodeIP net.IP, localSubnet net.IPNet) error

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

	// GetTunnelVirtualMAC() returns globalVirtualMAC used for tunnel traffic.
	GetTunnelVirtualMAC() net.HardwareAddr

	// GetPodFlowKeys returns the keys (match strings) of the cached flows for a
	// Pod.
	GetPodFlowKeys(interfaceName string) []string

	// GetNetworkPolicyFlowKeys returns the keys (match strings) of the cached
	// flows for a NetworkPolicy. Flows are grouped by policy rules, and duplicated
	// entries can be added due to conjunctive match flows shared by multiple
	// rules.
	GetNetworkPolicyFlowKeys(npName, npNamespace string) []string

	// ReassignFlowPriorities takes a list of priority updates, and update the actionFlows to replace
	// the old priority with the desired one, for each priority update on that table.
	ReassignFlowPriorities(updates map[uint16]uint16, table binding.TableIDType) error

	// SubscribePacketIn subscribes packet-in channel in bridge. This method requires a receiver to
	// pop data from "ch" timely, otherwise it will block all inbound messages from OVS.
	SubscribePacketIn(reason uint8, ch chan *ofctrl.PacketIn) error

	// SendTraceflowPacket injects packet to specified OVS port for Openflow.
	SendTraceflowPacket(
		dataplaneTag uint8,
		srcMAC string,
		dstMAC string,
		srcIP string,
		dstIP string,
		IPProtocol uint8,
		ttl uint8,
		IPFlags uint16,
		TCPSrcPort uint16,
		TCPDstPort uint16,
		TCPFlags uint8,
		UDPSrcPort uint16,
		UDPDstPort uint16,
		ICMPType uint8,
		ICMPCode uint8,
		ICMPID uint16,
		ICMPSequence uint16,
		inPort uint32,
		outPort int32) error

	// InstallTraceflowFlows installs flows for specific traceflow request.
	InstallTraceflowFlows(dataplaneTag uint8) error

	// Initial tun_metadata0 in TLV map for Traceflow.
	InitialTLVMap() error

	// Find network policy and namespace by conjunction ID.
	GetPolicyFromConjunction(ruleID uint32) (string, string)

	// RegisterPacketInHandler registers PacketIn handler to process PacketIn event.
	RegisterPacketInHandler(packetHandlerName string, packetInHandler interface{})
	// RegisterPacketInHandler uses SubscribePacketIn to get PacketIn message and process received
	// packets through registered handlers.
	StartPacketInHandler(stopCh <-chan struct{})
	// Get traffic metrics of each NetworkPolicy rule.
	NetworkPolicyMetrics() map[uint32]*types.RuleMetric
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
	peerConfigs map[*net.IPNet]net.IP,
	tunnelPeerIP net.IP,
	tunOFPort, ipsecTunOFPort uint32) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	var flows []binding.Flow

	for peerPodCIDR, peerGatewayIP := range peerConfigs {
		if peerGatewayIP.To4() != nil {
			// Since broadcast is not supported in IPv6, ARP should happen only with IPv4 address, and ARP responder flows
			// only work for IPv4 addresses.
			flows = append(flows, c.arpResponderFlow(peerGatewayIP, cookie.Node))
		}
		if c.encapMode.NeedsEncapToPeer(tunnelPeerIP, c.nodeConfig.NodeIPAddr) {
			flows = append(flows, c.l3FwdFlowToRemote(localGatewayMAC, *peerPodCIDR, tunnelPeerIP, tunOFPort, cookie.Node))
		} else {
			flows = append(flows, c.l3FwdFlowToRemoteViaGW(localGatewayMAC, *peerPodCIDR, cookie.Node))
		}
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

func (c *client) InstallPodFlows(interfaceName string, podInterfaceIPs []net.IP, podInterfaceMAC, gatewayMAC net.HardwareAddr, ofPort uint32) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	flows := []binding.Flow{
		c.podClassifierFlow(ofPort, cookie.Pod),
		c.l2ForwardCalcFlow(podInterfaceMAC, ofPort, cookie.Pod),
	}
	// Add support for IPv4 ARP responder.
	podInterfaceIPv4 := util.GetIPv4Addr(podInterfaceIPs)
	if podInterfaceIPv4 != nil {
		flows = append(flows, c.arpSpoofGuardFlow(podInterfaceIPv4, podInterfaceMAC, ofPort, cookie.Pod))
	}
	// Add IP SpoofGuard flows for all validate IPs.
	flows = append(flows, c.podIPSpoofGuardFlow(podInterfaceIPs, podInterfaceMAC, ofPort, cookie.Pod)...)
	// Add L3 Routing flows to rewrite Pod's dst MAC for all validate IPs.
	flows = append(flows, c.l3FlowsToPod(gatewayMAC, podInterfaceIPs, podInterfaceMAC, cookie.Pod)...)

	if c.encapMode.IsNetworkPolicyOnly() {
		// In policy-only mode, traffic to local Pod is routed based on destination IP.
		flows = append(flows,
			c.l3ToPodFlow(podInterfaceIPs, podInterfaceMAC, cookie.Pod)...,
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

func (c *client) InstallServiceGroup(groupID binding.GroupIDType, withSessionAffinity bool, endpoints []proxy.Endpoint) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	group := c.serviceEndpointGroup(groupID, withSessionAffinity, endpoints...)
	if err := group.Add(); err != nil {
		return fmt.Errorf("error when installing Service Endpoints Group: %w", err)
	}
	c.groupCache.Store(groupID, group)
	return nil
}

func (c *client) UninstallServiceGroup(groupID binding.GroupIDType) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	if !c.bridge.DeleteGroup(groupID) {
		return fmt.Errorf("group %d delete failed", groupID)
	}
	c.groupCache.Delete(groupID)
	return nil
}

func (c *client) InstallEndpointFlows(protocol binding.Protocol, endpoints []proxy.Endpoint) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	for _, endpoint := range endpoints {
		var flows []binding.Flow
		endpointPort, _ := endpoint.Port()
		endpointIP := net.ParseIP(endpoint.IP()).To4()
		portVal := uint16(endpointPort)
		cacheKey := fmt.Sprintf("Endpoints:%s:%d:%s", endpointIP, endpointPort, protocol)
		flows = append(flows, c.endpointDNATFlow(endpointIP, portVal, protocol))
		if endpoint.GetIsLocal() {
			flows = append(flows, c.hairpinSNATFlow(endpointIP))
		}
		if err := c.addFlows(c.serviceFlowCache, cacheKey, flows); err != nil {
			return err
		}
	}
	return nil
}

func (c *client) UninstallEndpointFlows(protocol binding.Protocol, endpoint proxy.Endpoint) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	port, err := endpoint.Port()
	if err != nil {
		return fmt.Errorf("error when getting port: %w", err)
	}
	cacheKey := fmt.Sprintf("Endpoints:%s:%d:%s", endpoint.IP(), port, protocol)
	return c.deleteFlows(c.serviceFlowCache, cacheKey)
}

func (c *client) InstallServiceFlows(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol, affinityTimeout uint16) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	var flows []binding.Flow
	flows = append(flows, c.serviceLBFlow(groupID, svcIP, svcPort, protocol))
	if affinityTimeout != 0 {
		flows = append(flows, c.serviceLearnFlow(groupID, svcIP, svcPort, protocol, affinityTimeout))
	}
	cacheKey := fmt.Sprintf("Service:%s:%d:%s", svcIP, svcPort, protocol)
	return c.addFlows(c.serviceFlowCache, cacheKey, flows)
}

func (c *client) UninstallServiceFlows(svcIP net.IP, svcPort uint16, protocol binding.Protocol) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	cacheKey := fmt.Sprintf("Service:%s:%d:%s", svcIP, svcPort, protocol)
	return c.deleteFlows(c.serviceFlowCache, cacheKey)
}

func (c *client) InstallLoadBalancerServiceFromOutsideFlows(svcIP net.IP, svcPort uint16, protocol binding.Protocol) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	var flows []binding.Flow
	flows = append(flows, c.loadBalancerServiceFromOutsideFlow(config.UplinkOFPort, config.HostGatewayOFPort, svcIP, svcPort, protocol))
	cacheKey := fmt.Sprintf("LoadBalancerService:%s:%d:%s", svcIP, svcPort, protocol)
	return c.addFlows(c.serviceFlowCache, cacheKey, flows)
}

func (c *client) InstallClusterServiceFlows() error {
	flows := []binding.Flow{
		c.l2ForwardOutputServiceHairpinFlow(),
		c.serviceHairpinResponseDNATFlow(),
		c.serviceNeedLBFlow(),
		c.sessionAffinityReselectFlow(),
		c.serviceLBBypassFlow(),
	}
	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return err
	}
	c.defaultServiceFlows = flows
	return nil
}

func (c *client) InstallClusterServiceCIDRFlows(serviceNets []*net.IPNet, gatewayMAC net.HardwareAddr, gatewayOFPort uint32) error {
	flows := c.serviceCIDRDNATFlows(serviceNets, gatewayMAC, gatewayOFPort)
	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return err
	}
	c.defaultServiceFlows = flows
	return nil
}

func (c *client) InstallGatewayFlows(gatewayAddrs []net.IP, gatewayMAC net.HardwareAddr, gatewayOFPort uint32) error {
	flows := []binding.Flow{
		c.gatewayClassifierFlow(gatewayOFPort, cookie.Default),
		c.l2ForwardCalcFlow(gatewayMAC, gatewayOFPort, cookie.Default),
	}
	hasV4, hasV6 := util.CheckAddressFamilies(gatewayAddrs)
	flows = append(flows, c.gatewayIPSpoofGuardFlows(gatewayOFPort, hasV4, hasV6, cookie.Default)...)

	// Add ARP SpoofGuard flow for local gateway interface.
	gwIPv4 := util.GetIPv4Addr(gatewayAddrs)
	if gwIPv4 != nil {
		flows = append(flows, c.gatewayARPSpoofGuardFlow(gatewayOFPort, gwIPv4, gatewayMAC, cookie.Default))
	}
	// Add flow to ensure the liveness check packet could be forwarded correctly.
	flows = append(flows, c.localProbeFlow(gatewayAddrs, cookie.Default)...)
	flows = append(flows, c.ctRewriteDstMACFlow(gatewayMAC, hasV4, hasV6, cookie.Default)...)
	// In NoEncap , no traffic from tunnel port
	if c.encapMode.SupportsEncap() {
		flows = append(flows, c.l3ToGatewayFlow(gatewayAddrs, gatewayMAC, cookie.Default)...)
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

func (c *client) InstallBridgeUplinkFlows(uplinkPort uint32, bridgeLocalPort uint32) error {
	flows := c.hostBridgeUplinkFlows(uplinkPort, bridgeLocalPort, cookie.Default)
	c.hostNetworkingFlows = flows
	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return err
	}
	c.hostNetworkingFlows = flows
	return nil
}

func (c *client) initialize() error {
	if err := c.ofEntryOperations.AddAll(c.defaultFlows()); err != nil {
		return fmt.Errorf("failed to install default flows: %v", err)
	}
	if err := c.ofEntryOperations.Add(c.arpNormalFlow(cookie.Default)); err != nil {
		return fmt.Errorf("failed to install arp normal flow: %v", err)
	}
	if err := c.ofEntryOperations.AddAll(c.ipv6Flows(cookie.Default)); err != nil {
		return fmt.Errorf("failed to install ipv6 flows: %v", err)
	}
	if err := c.ofEntryOperations.AddAll(c.l2ForwardOutputFlows(cookie.Default)); err != nil {
		return fmt.Errorf("failed to install L2 forward output flows: %v", err)
	}
	if err := c.ofEntryOperations.AddAll(c.connectionTrackFlows(cookie.Default)); err != nil {
		return fmt.Errorf("failed to install connection track flows: %v", err)
	}
	if err := c.ofEntryOperations.AddAll(c.establishedConnectionFlows(cookie.Default)); err != nil {
		return fmt.Errorf("failed to install flows to skip established connections: %v", err)
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

func (c *client) InstallExternalFlows(nodeIP net.IP, localSubnet net.IPNet) error {
	flows := c.bridgeAndUplinkFlows(config.UplinkOFPort, config.BridgeOFPort, nodeIP, localSubnet, cookie.SNAT)
	flows = append(flows, c.l3ToExternalFlows(nodeIP, localSubnet, config.HostGatewayOFPort, cookie.SNAT)...)
	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return fmt.Errorf("failed to install flows for external communication: %v", err)
	}
	c.hostNetworkingFlows = append(c.hostNetworkingFlows, flows...)
	return nil
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
	addFixedFlows(c.defaultServiceFlows)
	addFixedFlows(c.defaultTunnelFlows)
	// hostNetworkingFlows is used only on Windows. Replay the flows only when there are flows in this cache.
	if len(c.hostNetworkingFlows) > 0 {
		addFixedFlows(c.hostNetworkingFlows)
	}

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

	c.groupCache.Range(func(id, gEntry interface{}) bool {
		if err := gEntry.(binding.Group).Add(); err != nil {
			klog.Errorf("Error when replaying cached group %d: %v", id, err)
		}
		return true
	})
	c.nodeFlowCache.Range(installCachedFlows)
	c.podFlowCache.Range(installCachedFlows)
	c.serviceFlowCache.Range(installCachedFlows)

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

func (c *client) SubscribePacketIn(reason uint8, ch chan *ofctrl.PacketIn) error {
	return c.bridge.SubscribePacketIn(reason, ch)
}

func (c *client) SendTraceflowPacket(
	dataplaneTag uint8,
	srcMAC string,
	dstMAC string,
	srcIP string,
	dstIP string,
	IPProtocol uint8,
	ttl uint8,
	IPFlags uint16,
	TCPSrcPort uint16,
	TCPDstPort uint16,
	TCPFlags uint8,
	UDPSrcPort uint16,
	UDPDstPort uint16,
	ICMPType uint8,
	ICMPCode uint8,
	ICMPID uint16,
	ICMPSequence uint16,
	inPort uint32,
	outPort int32) error {

	regName := fmt.Sprintf("%s%d", binding.NxmFieldReg, TraceflowReg)

	packetOutBuilder := c.bridge.BuildPacketOut()
	parsedSrcMAC, _ := net.ParseMAC(srcMAC)
	parsedDstMAC, _ := net.ParseMAC(dstMAC)
	if dstMAC == "" {
		parsedDstMAC = c.nodeConfig.GatewayConfig.MAC
	}

	packetOutBuilder = packetOutBuilder.SetSrcMAC(parsedSrcMAC)
	packetOutBuilder = packetOutBuilder.SetDstMAC(parsedDstMAC)
	packetOutBuilder = packetOutBuilder.SetSrcIP(net.ParseIP(srcIP))
	packetOutBuilder = packetOutBuilder.SetDstIP(net.ParseIP(dstIP))

	if ttl == 0 {
		packetOutBuilder = packetOutBuilder.SetTTL(128)
	} else {
		packetOutBuilder = packetOutBuilder.SetTTL(ttl)
	}
	packetOutBuilder = packetOutBuilder.SetIPFlags(IPFlags)

	switch IPProtocol {
	case 1:
		packetOutBuilder = packetOutBuilder.SetIPProtocol(binding.ProtocolICMP)
		packetOutBuilder = packetOutBuilder.SetICMPType(ICMPType)
		packetOutBuilder = packetOutBuilder.SetICMPCode(ICMPCode)
		packetOutBuilder = packetOutBuilder.SetICMPID(ICMPID)
		packetOutBuilder = packetOutBuilder.SetICMPSequence(ICMPSequence)
	case 6:
		packetOutBuilder = packetOutBuilder.SetIPProtocol(binding.ProtocolTCP)
		if TCPSrcPort == 0 {
			TCPSrcPort = uint16(rand.Uint32())
		}
		packetOutBuilder = packetOutBuilder.SetTCPSrcPort(TCPSrcPort)
		packetOutBuilder = packetOutBuilder.SetTCPDstPort(TCPDstPort)
		packetOutBuilder = packetOutBuilder.SetTCPFlags(TCPFlags)
	case 17:
		packetOutBuilder = packetOutBuilder.SetIPProtocol(binding.ProtocolUDP)
		packetOutBuilder = packetOutBuilder.SetUDPSrcPort(UDPSrcPort)
		packetOutBuilder = packetOutBuilder.SetUDPDstPort(UDPDstPort)
	}

	packetOutBuilder = packetOutBuilder.SetInport(inPort)
	if outPort != -1 {
		packetOutBuilder = packetOutBuilder.SetOutport(uint32(outPort))
	}
	packetOutBuilder = packetOutBuilder.AddLoadAction(regName, uint64(dataplaneTag), OfTraceflowMarkRange)

	packetOutObj := packetOutBuilder.Done()
	return c.bridge.SendPacketOut(packetOutObj)
}

func (c *client) InstallTraceflowFlows(dataplaneTag uint8) error {
	flow := c.traceflowL2ForwardOutputFlow(dataplaneTag, cookie.Default)
	if err := c.Add(flow); err != nil {
		return err
	}
	flow = c.traceflowConnectionTrackFlows(dataplaneTag, cookie.Default)
	if err := c.Add(flow); err != nil {
		return err
	}
	flows := []binding.Flow{}
	c.conjMatchFlowLock.Lock()
	defer c.conjMatchFlowLock.Unlock()
	for _, ctx := range c.globalConjMatchFlowCache {
		if ctx.dropFlow != nil {
			flows = append(
				flows,
				ctx.dropFlow.CopyToBuilder(priorityNormal+2, false).
					MatchRegRange(int(TraceflowReg), uint32(dataplaneTag), OfTraceflowMarkRange).
					SetHardTimeout(300).
					Action().SendToController(1).
					Done())
		}
	}
	return c.AddAll(flows)
}

// Add TLV map optClass 0x0104, optType 0x80 optLength 4 tunMetadataIndex 0 to store data plane tag
// in tunnel. Data plane tag will be stored to NXM_NX_TUN_METADATA0[28..31] when packet get encapsulated
// into geneve, and will be stored back to NXM_NX_REG9[28..31] when packet get decapsulated.
func (c *client) InitialTLVMap() error {
	return c.bridge.AddTLVMap(0x0104, 0x80, 4, 0)
}
