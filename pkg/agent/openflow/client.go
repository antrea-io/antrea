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

	"github.com/contiv/libOpenflow/protocol"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/third_party/proxy"
)

const maxRetryForOFSwitch = 5

// Client is the interface to program OVS flows for entity connectivity of Antrea.
type Client interface {
	// Initialize sets up all basic flows on the specific OVS bridge. It returns a channel which
	// is used to notify the caller in case of a reconnection, in which case ReplayFlows should
	// be called to ensure that the set of OVS flows is correct. All flows programmed in the
	// switch which match the current round number will be deleted before any new flow is
	// installed.
	Initialize(roundInfo types.RoundInfo, config *config.NodeConfig, encapMode config.TrafficEncapModeType) (<-chan struct{}, error)

	// InstallGatewayFlows sets up flows related to an OVS gateway port, the gateway must exist.
	InstallGatewayFlows() error

	// InstallClusterServiceCIDRFlows sets up the appropriate flows so that traffic can reach
	// the different Services running in the Cluster. This method needs to be invoked once with
	// the Cluster Service CIDR as a parameter.
	InstallClusterServiceCIDRFlows(serviceNets []*net.IPNet) error

	// InstallClusterServiceFlows sets up the appropriate flows so that traffic can reach
	// the different Services running in the Cluster. This method needs to be invoked once.
	InstallClusterServiceFlows() error

	// InstallDefaultTunnelFlows sets up the classification flow for the default (flow based) tunnel.
	InstallDefaultTunnelFlows() error

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
		peerConfigs map[*net.IPNet]net.IP,
		tunnelPeerIP net.IP,
		ipsecTunOFPort uint32,
		peerNodeMAC net.HardwareAddr) error

	// UninstallNodeFlows removes the connection to the remote Node specified with the
	// hostname. UninstallNodeFlows will do nothing if no connection to the host was established.
	UninstallNodeFlows(hostname string) error

	// InstallPodFlows should be invoked when a connection to a Pod on current Node. The
	// interfaceName is used to identify the added flows. InstallPodFlows has all-or-nothing
	// semantics(call succeeds if all the flows are installed successfully, otherwise no
	// flows will be installed). Calls to InstallPodFlows are idempotent. Concurrent calls
	// to InstallPodFlows and / or UninstallPodFlows are supported as long as they are all
	// for different interfaceNames.
	InstallPodFlows(interfaceName string, podInterfaceIPs []net.IP, podInterfaceMAC net.HardwareAddr, ofPort uint32) error

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
	// UninstallLoadBalancerServiceFromOutsideFlows removes flows installed by InstallLoadBalancerServiceFromOutsideFlows.
	UninstallLoadBalancerServiceFromOutsideFlows(svcIP net.IP, svcPort uint16, protocol binding.Protocol) error

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

	// InstallBridgeUplinkFlows installs Openflow flows between bridge local port and uplink port to support
	// host networking.
	// This function is only used for Windows platform.
	InstallBridgeUplinkFlows() error

	// InstallExternalFlows sets up flows to enable Pods to communicate to
	// the external IP addresses. The flows identify the packets from local
	// Pods to the external IP address, and mark the packets to be SNAT'd
	// with the configured SNAT IPs. On Windows Node, the flows also perform
	// SNAT with the Openflow NAT action.
	InstallExternalFlows() error

	// InstallSNATMarkFlows installs flows for a local SNAT IP. On Linux, a
	// single flow is added to mark the packets tunnelled from remote Nodes
	// that should be SNAT'd with the SNAT IP. On Windows, an extra flow is
	// added to perform SNAT for the marked packets with the SNAT IP.
	InstallSNATMarkFlows(snatIP net.IP, mark uint32) error

	// UninstallSNATMarkFlows removes the flows installed to set the packet
	// mark for a SNAT IP.
	UninstallSNATMarkFlows(mark uint32) error

	// InstallPodSNATFlows installs the SNAT flows for a local Pod. If the
	// SNAT IP for the Pod is on the local Node, a non-zero SNAT ID should
	// allocated for the SNAT IP, and the installed flow sets the SNAT IP
	// mark on the egress packets from the ofPort; if the SNAT IP is on a
	// remote Node, snatMark should be set to 0, and the installed flow
	// tunnels egress packets to the remote Node using the SNAT IP as the
	// tunnel destination, and the packets should be SNAT'd on the remote
	// Node. As of now, a Pod can be configured to use only a single SNAT
	// IP in a single address family (IPv4 or IPv6).
	InstallPodSNATFlows(ofPort uint32, snatIP net.IP, snatMark uint32) error

	// UninstallPodSNATFlows removes the SNAT flows for the local Pod.
	UninstallPodSNATFlows(ofPort uint32) error

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

	// GetServiceFlowKeys returns the keys (match strings) of the cached
	// flows for a Service (port) and its endpoints.
	GetServiceFlowKeys(svcIP net.IP, svcPort uint16, protocol binding.Protocol, endpoints []proxy.Endpoint) []string

	// GetNetworkPolicyFlowKeys returns the keys (match strings) of the cached
	// flows for a NetworkPolicy. Flows are grouped by policy rules, and duplicated
	// entries can be added due to conjunctive match flows shared by multiple
	// rules.
	GetNetworkPolicyFlowKeys(npName, npNamespace string) []string

	// ReassignFlowPriorities takes a list of priority updates, and update the actionFlows to replace
	// the old priority with the desired one, for each priority update on that table.
	ReassignFlowPriorities(updates map[uint16]uint16, table binding.TableIDType) error

	// SubscribePacketIn subscribes to packet in messages for the given reason. Packets
	// will be placed in the queue and if the queue is full, the packet in messages
	// will be dropped. pktInQueue supports rate-limiting for the consumer, in order to
	// constrain the compute resources that may be used by the consumer.
	SubscribePacketIn(reason uint8, pktInQueue *binding.PacketInQueue) error

	// SendTraceflowPacket injects packet to specified OVS port for Openflow.
	SendTraceflowPacket(dataplaneTag uint8, packet *binding.Packet, inPort uint32, outPort int32) error

	// InstallTraceflowFlows installs flows for a Traceflow request.
	InstallTraceflowFlows(dataplaneTag uint8, liveTraffic, droppedOnly, receiverOnly bool, packet *binding.Packet, ofPort uint32, timeoutSeconds uint16) error

	// UninstallTraceflowFlows uninstalls flows for a Traceflow request.
	UninstallTraceflowFlows(dataplaneTag uint8) error

	// Initial tun_metadata0 in TLV map for Traceflow.
	InitialTLVMap() error

	// Find Network Policy reference and OFpriority by conjunction ID.
	GetPolicyInfoFromConjunction(ruleID uint32) (string, string)

	// RegisterPacketInHandler uses SubscribePacketIn to get PacketIn message and process received
	// packets through registered handlers.
	RegisterPacketInHandler(packetHandlerReason uint8, packetHandlerName string, packetInHandler interface{})

	StartPacketInHandler(packetInStartedReason []uint8, stopCh <-chan struct{})
	// Get traffic metrics of each NetworkPolicy rule.
	NetworkPolicyMetrics() map[uint32]*types.RuleMetric
	// Returns if IPv4 is supported on this Node or not.
	IsIPv4Enabled() bool
	// Returns if IPv6 is supported on this Node or not.
	IsIPv6Enabled() bool
	// SendTCPPacketOut sends TCP packet as a packet-out to OVS.
	SendTCPPacketOut(
		srcMAC string,
		dstMAC string,
		srcIP string,
		dstIP string,
		inPort uint32,
		outPort int32,
		isIPv6 bool,
		tcpSrcPort uint16,
		tcpDstPort uint16,
		tcpAckNum uint32,
		tcpFlag uint8,
		isReject bool) error
	// SendICMPPacketOut sends ICMP packet as a packet-out to OVS.
	SendICMPPacketOut(
		srcMAC string,
		dstMAC string,
		srcIP string,
		dstIP string,
		inPort uint32,
		outPort int32,
		isIPv6 bool,
		icmpType uint8,
		icmpCode uint8,
		icmpData []byte,
		isReject bool) error
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
	return c.addFlowsWithMultipleKeys(cache, map[string][]binding.Flow{flowCacheKey: flows})
}

// addFlowsWithMultipleKeys installs the flows with different flowCache keys and adds them into the cache on success.
// It will skip flows whose cache already exists. All flows will be installed via a bundle.
func (c *client) addFlowsWithMultipleKeys(cache *flowCategoryCache, keyToFlows map[string][]binding.Flow) error {
	// allFlows keeps the flows we will install via a bundle.
	var allFlows []binding.Flow
	// flowCacheMap keeps the flowCache items we will add to the cache on bundle success.
	flowCacheMap := map[string]flowCache{}
	for flowCacheKey, flows := range keyToFlows {
		_, ok := cache.Load(flowCacheKey)
		// If a flow cache entry already exists for the key, skip it.
		if ok {
			klog.V(2).InfoS("Flows with this cache key are already installed", "key", flowCacheKey)
			continue
		}
		fCache := flowCache{}
		for _, flow := range flows {
			allFlows = append(allFlows, flow)
			fCache[flow.MatchString()] = flow
		}
		flowCacheMap[flowCacheKey] = fCache
	}
	if len(allFlows) == 0 {
		return nil
	}
	err := c.ofEntryOperations.AddAll(allFlows)
	if err != nil {
		return err
	}
	// Add the installed flows into the flow cache.
	for flowCacheKey, flowCache := range flowCacheMap {
		cache.Store(flowCacheKey, flowCache)
	}
	return nil
}

// modifyFlows sets the flows of flowCategoryCache be exactly same as the provided slice for the given flowCacheKey.
func (c *client) modifyFlows(cache *flowCategoryCache, flowCacheKey string, flows []binding.Flow) error {
	oldFlowCacheI, ok := cache.Load(flowCacheKey)
	fCache := flowCache{}
	var err error
	if !ok {
		for _, flow := range flows {
			fCache[flow.MatchString()] = flow
		}

		err = c.ofEntryOperations.AddAll(flows)
	} else {
		var adds, mods, dels []binding.Flow
		oldFlowCache := oldFlowCacheI.(flowCache)
		for _, flow := range flows {
			matchString := flow.MatchString()
			if _, ok := oldFlowCache[matchString]; ok {
				mods = append(mods, flow)
			} else {
				adds = append(adds, flow)
			}
			fCache[matchString] = flow
		}
		for k, v := range oldFlowCache {
			if _, ok := fCache[k]; !ok {
				dels = append(dels, v)
			}
		}
		err = c.ofEntryOperations.BundleOps(adds, mods, dels)
	}
	if err != nil {
		return err
	}

	// Modify the flows in the flow cache.
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

// InstallNodeFlows installs flows for peer Nodes. Parameter remoteGatewayMAC is only for Windows.
func (c *client) InstallNodeFlows(hostname string,
	peerConfigs map[*net.IPNet]net.IP,
	tunnelPeerIP net.IP,
	ipsecTunOFPort uint32,
	remoteGatewayMAC net.HardwareAddr) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	var flows []binding.Flow
	localGatewayMAC := c.nodeConfig.GatewayConfig.MAC

	for peerPodCIDR, peerGatewayIP := range peerConfigs {
		if peerGatewayIP.To4() != nil {
			// Since broadcast is not supported in IPv6, ARP should happen only with IPv4 address, and ARP responder flows
			// only work for IPv4 addresses.
			flows = append(flows, c.arpResponderFlow(peerGatewayIP, cookie.Node))
		}
		if c.encapMode.NeedsEncapToPeer(tunnelPeerIP, c.nodeConfig.NodeTransportIPAddr) {
			// tunnelPeerIP is the Node Internal Address. In a dual-stack setup, whether this address is an IPv4 address or an
			// IPv6 one is decided by the address family of Node Internal Address.
			flows = append(flows, c.l3FwdFlowToRemote(localGatewayMAC, *peerPodCIDR, tunnelPeerIP, cookie.Node))
		} else {
			flows = append(flows, c.l3FwdFlowToRemoteViaRouting(localGatewayMAC, remoteGatewayMAC, cookie.Node, tunnelPeerIP, peerPodCIDR)...)
		}
	}

	if ipsecTunOFPort != 0 {
		// When IPSec tunnel is enabled, packets received from the remote Node are
		// input from the Node's IPSec tunnel port, not the default tunnel port. So,
		// add a separate tunnelClassifierFlow for the IPSec tunnel port.
		flows = append(flows, c.tunnelClassifierFlow(ipsecTunOFPort, cookie.Node))
	}

	// For Windows Noencap Mode, the OVS flows for Node need be be exactly same as the provided 'flows' slice because
	// the Node flows may be processed more than once if the MAC annotation is updated.
	return c.modifyFlows(c.nodeFlowCache, hostname, flows)
}

func (c *client) UninstallNodeFlows(hostname string) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	return c.deleteFlows(c.nodeFlowCache, hostname)
}

func (c *client) InstallPodFlows(interfaceName string, podInterfaceIPs []net.IP, podInterfaceMAC net.HardwareAddr, ofPort uint32) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	localGatewayMAC := c.nodeConfig.GatewayConfig.MAC
	flows := []binding.Flow{
		c.podClassifierFlow(ofPort, cookie.Pod),
		c.l2ForwardCalcFlow(podInterfaceMAC, ofPort, false, cookie.Pod),
	}

	// Add support for IPv4 ARP responder.
	podInterfaceIPv4 := util.GetIPv4Addr(podInterfaceIPs)
	if podInterfaceIPv4 != nil {
		flows = append(flows, c.arpSpoofGuardFlow(podInterfaceIPv4, podInterfaceMAC, ofPort, cookie.Pod))
	}
	// Add IP SpoofGuard flows for all validate IPs.
	flows = append(flows, c.podIPSpoofGuardFlow(podInterfaceIPs, podInterfaceMAC, ofPort, cookie.Pod)...)
	// Add L3 Routing flows to rewrite Pod's dst MAC for all validate IPs.
	flows = append(flows, c.l3FwdFlowToPod(localGatewayMAC, podInterfaceIPs, podInterfaceMAC, cookie.Pod)...)

	if c.encapMode.IsNetworkPolicyOnly() {
		// In policy-only mode, traffic to local Pod is routed based on destination IP.
		flows = append(flows,
			c.l3FwdFlowRouteToPod(podInterfaceIPs, podInterfaceMAC, cookie.Pod)...,
		)
	}
	return c.addFlows(c.podFlowCache, interfaceName, flows)
}

func (c *client) UninstallPodFlows(interfaceName string) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	return c.deleteFlows(c.podFlowCache, interfaceName)
}

func (c *client) getFlowKeysFromCache(cache *flowCategoryCache, cacheKey string) []string {
	fCacheI, ok := cache.Load(cacheKey)
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

func (c *client) GetPodFlowKeys(interfaceName string) []string {
	return c.getFlowKeysFromCache(c.podFlowCache, interfaceName)
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

func generateEndpointFlowCacheKey(endpointIP string, endpointPort int, protocol binding.Protocol) string {
	return fmt.Sprintf("E%s%s%x", endpointIP, protocol, endpointPort)
}

func generateServicePortFlowCacheKey(svcIP net.IP, svcPort uint16, protocol binding.Protocol) string {
	return fmt.Sprintf("S%s%s%x", svcIP, protocol, svcPort)
}

func (c *client) InstallEndpointFlows(protocol binding.Protocol, endpoints []proxy.Endpoint) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	// keyToFlows is a map from the flows' cache key to the flows.
	keyToFlows := map[string][]binding.Flow{}
	for _, endpoint := range endpoints {
		var flows []binding.Flow
		endpointPort, _ := endpoint.Port()
		endpointIP := net.ParseIP(endpoint.IP())
		portVal := portToUint16(endpointPort)
		cacheKey := generateEndpointFlowCacheKey(endpoint.IP(), endpointPort, protocol)
		flows = append(flows, c.endpointDNATFlow(endpointIP, portVal, protocol))
		if endpoint.GetIsLocal() {
			flows = append(flows, c.hairpinSNATFlow(endpointIP))
		}
		keyToFlows[cacheKey] = flows
	}

	return c.addFlowsWithMultipleKeys(c.serviceFlowCache, keyToFlows)
}

func (c *client) UninstallEndpointFlows(protocol binding.Protocol, endpoint proxy.Endpoint) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	port, err := endpoint.Port()
	if err != nil {
		return fmt.Errorf("error when getting port: %w", err)
	}
	cacheKey := generateEndpointFlowCacheKey(endpoint.IP(), port, protocol)
	return c.deleteFlows(c.serviceFlowCache, cacheKey)
}

func (c *client) InstallServiceFlows(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol, affinityTimeout uint16) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	var flows []binding.Flow
	flows = append(flows, c.serviceLBFlow(groupID, svcIP, svcPort, protocol, affinityTimeout != 0))
	if affinityTimeout != 0 {
		flows = append(flows, c.serviceLearnFlow(groupID, svcIP, svcPort, protocol, affinityTimeout))
	}
	cacheKey := generateServicePortFlowCacheKey(svcIP, svcPort, protocol)
	return c.addFlows(c.serviceFlowCache, cacheKey, flows)
}

func (c *client) UninstallServiceFlows(svcIP net.IP, svcPort uint16, protocol binding.Protocol) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	cacheKey := generateServicePortFlowCacheKey(svcIP, svcPort, protocol)
	return c.deleteFlows(c.serviceFlowCache, cacheKey)
}

func (c *client) GetServiceFlowKeys(svcIP net.IP, svcPort uint16, protocol binding.Protocol, endpoints []proxy.Endpoint) []string {
	cacheKey := generateServicePortFlowCacheKey(svcIP, svcPort, protocol)
	flowKeys := c.getFlowKeysFromCache(c.serviceFlowCache, cacheKey)
	for _, ep := range endpoints {
		epPort, _ := ep.Port()
		cacheKey = generateEndpointFlowCacheKey(ep.IP(), epPort, protocol)
		flowKeys = append(flowKeys, c.getFlowKeysFromCache(c.serviceFlowCache, cacheKey)...)
	}
	return flowKeys
}

func (c *client) InstallClusterServiceFlows() error {
	flows := []binding.Flow{
		c.serviceNeedLBFlow(),
		c.sessionAffinityReselectFlow(),
		c.l2ForwardOutputServiceHairpinFlow(),
	}
	if c.IsIPv4Enabled() {
		flows = append(flows, c.serviceHairpinResponseDNATFlow(binding.ProtocolIP))
		flows = append(flows, c.serviceLBBypassFlows(binding.ProtocolIP)...)
	}
	if c.IsIPv6Enabled() {
		flows = append(flows, c.serviceHairpinResponseDNATFlow(binding.ProtocolIPv6))
		flows = append(flows, c.serviceLBBypassFlows(binding.ProtocolIPv6)...)
	}
	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return err
	}
	c.defaultServiceFlows = flows
	return nil
}

func (c *client) InstallClusterServiceCIDRFlows(serviceNets []*net.IPNet) error {
	flows := c.serviceCIDRDNATFlows(serviceNets)
	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return err
	}
	c.defaultServiceFlows = flows
	return nil
}

func (c *client) InstallGatewayFlows() error {
	gatewayConfig := c.nodeConfig.GatewayConfig
	gatewayIPs := []net.IP{}

	flows := []binding.Flow{
		c.gatewayClassifierFlow(cookie.Default),
		c.l2ForwardCalcFlow(gatewayConfig.MAC, config.HostGatewayOFPort, true, cookie.Default),
	}
	flows = append(flows, c.gatewayIPSpoofGuardFlows(cookie.Default)...)

	// Add ARP SpoofGuard flow for local gateway interface.
	if gatewayConfig.IPv4 != nil {
		gatewayIPs = append(gatewayIPs, gatewayConfig.IPv4)
		flows = append(flows, c.gatewayARPSpoofGuardFlow(gatewayConfig.IPv4, gatewayConfig.MAC, cookie.Default))
	}
	if gatewayConfig.IPv6 != nil {
		gatewayIPs = append(gatewayIPs, gatewayConfig.IPv6)
	}

	// Add flow to ensure the liveness check packet could be forwarded correctly.
	flows = append(flows, c.localProbeFlow(gatewayIPs, cookie.Default)...)
	flows = append(flows, c.l3FwdFlowToGateway(gatewayIPs, gatewayConfig.MAC, cookie.Default)...)

	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return err
	}
	c.gatewayFlows = flows
	return nil
}

func (c *client) InstallDefaultTunnelFlows() error {
	flows := []binding.Flow{
		c.tunnelClassifierFlow(config.DefaultTunOFPort, cookie.Default),
		c.l2ForwardCalcFlow(globalVirtualMAC, config.DefaultTunOFPort, true, cookie.Default),
	}
	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return err
	}
	c.defaultTunnelFlows = flows
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
	if err := c.ofEntryOperations.AddAll(c.decTTLFlows(cookie.Default)); err != nil {
		return fmt.Errorf("failed to install dec TTL flow on source Node: %v", err)
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
	if c.ovsMetersAreSupported {
		if err := c.genPacketInMeter(PacketInMeterIDNP, PacketInMeterRateNP).Add(); err != nil {
			return fmt.Errorf("failed to install OpenFlow meter entry (meterID:%d, rate:%d) for NetworkPolicy packet-in rate limiting: %v", PacketInMeterIDNP, PacketInMeterRateNP, err)
		}
		if err := c.genPacketInMeter(PacketInMeterIDTF, PacketInMeterRateTF).Add(); err != nil {
			return fmt.Errorf("failed to install OpenFlow meter entry (meterID:%d, rate:%d) for TraceFlow packet-in rate limiting: %v", PacketInMeterIDTF, PacketInMeterRateTF, err)
		}
	}
	return nil
}

func (c *client) Initialize(roundInfo types.RoundInfo, nodeConfig *config.NodeConfig, encapMode config.TrafficEncapModeType) (<-chan struct{}, error) {
	c.nodeConfig = nodeConfig
	c.encapMode = encapMode

	if config.IsIPv4Enabled(nodeConfig, encapMode) {
		c.ipProtocols = append(c.ipProtocols, binding.ProtocolIP)
	}
	if config.IsIPv6Enabled(nodeConfig, encapMode) {
		c.ipProtocols = append(c.ipProtocols, binding.ProtocolIPv6)
	}

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

	// In the normal case, there should be no existing meter entries. This is needed in case the
	// antrea-agent container is restarted (but not the antrea-ovs one), which will add meter
	// entries during initialization, but the meter entries added during the previous
	// initialization still exist. Trying to add an existing meter entry will cause an
	// OFPMMFC_METER_EXISTS error.
	if c.ovsMetersAreSupported {
		if err := c.bridge.DeleteMeterAll(); err != nil {
			return nil, fmt.Errorf("error when deleting all meter entries: %v", err)
		}
	}

	return connCh, c.initialize()
}

func (c *client) InstallExternalFlows() error {
	nodeIP := c.nodeConfig.NodeIPAddr.IP
	localGatewayMAC := c.nodeConfig.GatewayConfig.MAC

	var flows []binding.Flow
	if c.nodeConfig.PodIPv4CIDR != nil {
		flows = c.externalFlows(nodeIP, *c.nodeConfig.PodIPv4CIDR, localGatewayMAC)
	}
	if c.nodeConfig.PodIPv6CIDR != nil {
		flows = append(flows, c.externalFlows(nodeIP, *c.nodeConfig.PodIPv6CIDR, localGatewayMAC)...)
	}

	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return fmt.Errorf("failed to install flows for external communication: %v", err)
	}
	c.hostNetworkingFlows = append(c.hostNetworkingFlows, flows...)
	return nil
}

func (c *client) InstallSNATMarkFlows(snatIP net.IP, mark uint32) error {
	flows := c.snatMarkFlows(snatIP, mark)
	cacheKey := fmt.Sprintf("s%x", mark)
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	return c.addFlows(c.snatFlowCache, cacheKey, flows)
}

func (c *client) UninstallSNATMarkFlows(mark uint32) error {
	cacheKey := fmt.Sprintf("s%x", mark)
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	return c.deleteFlows(c.snatFlowCache, cacheKey)
}

func (c *client) InstallPodSNATFlows(ofPort uint32, snatIP net.IP, snatMark uint32) error {
	flows := []binding.Flow{c.snatRuleFlow(ofPort, snatIP, snatMark, c.nodeConfig.GatewayConfig.MAC)}
	cacheKey := fmt.Sprintf("p%x", ofPort)
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	return c.addFlows(c.snatFlowCache, cacheKey, flows)
}

func (c *client) UninstallPodSNATFlows(ofPort uint32) error {
	cacheKey := fmt.Sprintf("p%x", ofPort)
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	return c.deleteFlows(c.snatFlowCache, cacheKey)
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

	c.groupCache.Range(func(id, value interface{}) bool {
		group := value.(binding.Group)
		group.Reset()
		if err := group.Add(); err != nil {
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
	// Rewrites MAC to gw port if the packet received is unmatched by local Pod flows.
	flows := c.l3FwdFlowRouteToGW(c.nodeConfig.GatewayConfig.MAC, cookie.Default)
	// If IPv6 is enabled, this flow will never get hit.
	flows = append(flows,
		// Replies any ARP request with the same global virtual MAC.
		c.arpResponderStaticFlow(cookie.Default),
	)
	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return fmt.Errorf("failed to setup policy-only flows: %w", err)
	}
	return nil
}

func (c *client) SubscribePacketIn(reason uint8, pktInQueue *binding.PacketInQueue) error {
	return c.bridge.SubscribePacketIn(reason, pktInQueue)
}

func (c *client) SendTraceflowPacket(dataplaneTag uint8, packet *binding.Packet, inPort uint32, outPort int32) error {
	packetOutBuilder := c.bridge.BuildPacketOut()

	if packet.DestinationMAC == nil {
		packet.DestinationMAC = c.nodeConfig.GatewayConfig.MAC
	}
	// Set ethernet header
	packetOutBuilder = packetOutBuilder.SetDstMAC(packet.DestinationMAC).SetSrcMAC(packet.SourceMAC)

	// Set IP header
	packetOutBuilder = packetOutBuilder.SetDstIP(packet.DestinationIP).SetSrcIP(packet.SourceIP).SetTTL(packet.TTL)
	if !packet.IsIPv6 {
		packetOutBuilder = packetOutBuilder.SetIPFlags(packet.IPFlags)
	}

	// Set transport header
	switch packet.IPProto {
	case protocol.Type_ICMP, protocol.Type_IPv6ICMP:
		if packet.IPProto == protocol.Type_ICMP {
			packetOutBuilder = packetOutBuilder.SetIPProtocol(binding.ProtocolICMP)
		} else {
			packetOutBuilder = packetOutBuilder.SetIPProtocol(binding.ProtocolICMPv6)
		}
		packetOutBuilder = packetOutBuilder.SetICMPType(packet.ICMPType).
			SetICMPCode(packet.ICMPCode).
			SetICMPID(packet.ICMPEchoID).
			SetICMPSequence(packet.ICMPEchoSeq)
	case protocol.Type_TCP:
		if packet.IsIPv6 {
			packetOutBuilder = packetOutBuilder.SetIPProtocol(binding.ProtocolTCPv6)
		} else {
			packetOutBuilder = packetOutBuilder.SetIPProtocol(binding.ProtocolTCP)
		}
		tcpSrcPort := packet.SourcePort
		if tcpSrcPort == 0 {
			// #nosec G404: random number generator not used for security purposes.
			tcpSrcPort = uint16(rand.Uint32())
		}
		packetOutBuilder = packetOutBuilder.SetTCPDstPort(packet.DestinationPort).
			SetTCPSrcPort(tcpSrcPort).
			SetTCPFlags(packet.TCPFlags)
	case protocol.Type_UDP:
		if packet.IsIPv6 {
			packetOutBuilder = packetOutBuilder.SetIPProtocol(binding.ProtocolUDPv6)
		} else {
			packetOutBuilder = packetOutBuilder.SetIPProtocol(binding.ProtocolUDP)
		}
		packetOutBuilder = packetOutBuilder.SetUDPDstPort(packet.DestinationPort).
			SetUDPSrcPort(packet.SourcePort)
	default:
		packetOutBuilder = packetOutBuilder.SetIPProtocolValue(packet.IsIPv6, packet.IPProto)
	}

	packetOutBuilder = packetOutBuilder.SetInport(inPort)
	if outPort != -1 {
		packetOutBuilder = packetOutBuilder.SetOutport(uint32(outPort))
	}
	packetOutBuilder = packetOutBuilder.AddLoadAction(binding.NxmFieldIPToS, uint64(dataplaneTag), traceflowTagToSRange)

	packetOutObj := packetOutBuilder.Done()
	return c.bridge.SendPacketOut(packetOutObj)
}

func (c *client) InstallTraceflowFlows(dataplaneTag uint8, liveTraffic, droppedOnly, receiverOnly bool, packet *binding.Packet, ofPort uint32, timeoutSeconds uint16) error {
	cacheKey := fmt.Sprintf("%x", dataplaneTag)
	flows := []binding.Flow{}
	flows = append(flows, c.traceflowConnectionTrackFlows(dataplaneTag, receiverOnly, packet, ofPort, timeoutSeconds, cookie.Default)...)
	flows = append(flows, c.traceflowL2ForwardOutputFlows(dataplaneTag, liveTraffic, droppedOnly, timeoutSeconds, cookie.Default)...)
	flows = append(flows, c.traceflowNetworkPolicyFlows(dataplaneTag, timeoutSeconds, cookie.Default)...)
	return c.addFlows(c.tfFlowCache, cacheKey, flows)
}

func (c *client) UninstallTraceflowFlows(dataplaneTag uint8) error {
	cacheKey := fmt.Sprintf("%x", dataplaneTag)
	return c.deleteFlows(c.tfFlowCache, cacheKey)
}

// Add TLV map optClass 0x0104, optType 0x80 optLength 4 tunMetadataIndex 0 to store data plane tag
// in tunnel. Data plane tag will be stored to NXM_NX_TUN_METADATA0[28..31] when packet get encapsulated
// into geneve, and will be stored back to NXM_NX_REG9[28..31] when packet get decapsulated.
func (c *client) InitialTLVMap() error {
	return c.bridge.AddTLVMap(0x0104, 0x80, 4, 0)
}

func (c *client) IsIPv4Enabled() bool {
	return config.IsIPv4Enabled(c.nodeConfig, c.encapMode)
}

func (c *client) IsIPv6Enabled() bool {
	return config.IsIPv6Enabled(c.nodeConfig, c.encapMode)
}

// setBasePacketOutBuilder sets base IP properties of a packetOutBuilder which can have more packet data added.
func setBasePacketOutBuilder(packetOutBuilder binding.PacketOutBuilder, srcMAC string, dstMAC string, srcIP string, dstIP string, inPort uint32, outPort int32) (binding.PacketOutBuilder, error) {
	// Set ethernet header.
	parsedSrcMAC, err := net.ParseMAC(srcMAC)
	if err != nil {
		return nil, err
	}
	parsedDstMAC, err := net.ParseMAC(dstMAC)
	if err != nil {
		return nil, err
	}
	packetOutBuilder = packetOutBuilder.SetSrcMAC(parsedSrcMAC)
	packetOutBuilder = packetOutBuilder.SetDstMAC(parsedDstMAC)

	// Set IP header.
	parsedSrcIP := net.ParseIP(srcIP)
	parsedDstIP := net.ParseIP(dstIP)
	if parsedSrcIP == nil || parsedDstIP == nil {
		return nil, fmt.Errorf("invalid IP")
	}
	isIPv6 := parsedSrcIP.To4() == nil
	if isIPv6 != (parsedDstIP.To4() == nil) {
		return nil, fmt.Errorf("IP version mismatch")
	}
	packetOutBuilder = packetOutBuilder.SetSrcIP(parsedSrcIP)
	packetOutBuilder = packetOutBuilder.SetDstIP(parsedDstIP)

	packetOutBuilder = packetOutBuilder.SetTTL(128)

	packetOutBuilder = packetOutBuilder.SetInport(inPort)
	if outPort != -1 {
		packetOutBuilder = packetOutBuilder.SetOutport(uint32(outPort))
	}

	return packetOutBuilder, nil
}

// SendTCPReject generates TCP packet as a packet-out and sends it to OVS.
func (c *client) SendTCPPacketOut(
	srcMAC string,
	dstMAC string,
	srcIP string,
	dstIP string,
	inPort uint32,
	outPort int32,
	isIPv6 bool,
	tcpSrcPort uint16,
	tcpDstPort uint16,
	tcpAckNum uint32,
	tcpFlag uint8,
	isReject bool) error {
	// Generate a base IP PacketOutBuilder.
	packetOutBuilder, err := setBasePacketOutBuilder(c.bridge.BuildPacketOut(), srcMAC, dstMAC, srcIP, dstIP, inPort, outPort)
	if err != nil {
		return err
	}
	// Set protocol.
	if isIPv6 {
		packetOutBuilder = packetOutBuilder.SetIPProtocol(binding.ProtocolTCPv6)
	} else {
		packetOutBuilder = packetOutBuilder.SetIPProtocol(binding.ProtocolTCP)
	}
	// Set TCP header data.
	packetOutBuilder = packetOutBuilder.SetTCPSrcPort(tcpSrcPort)
	packetOutBuilder = packetOutBuilder.SetTCPDstPort(tcpDstPort)
	packetOutBuilder = packetOutBuilder.SetTCPAckNum(tcpAckNum)
	packetOutBuilder = packetOutBuilder.SetTCPFlags(tcpFlag)

	// Reject response packet should bypass ConnTrack
	if isReject {
		name := fmt.Sprintf("%s%d", binding.NxmFieldReg, marksReg)
		packetOutBuilder = packetOutBuilder.AddLoadAction(name, uint64(CustomReasonReject), CustomReasonMarkRange)
	}

	packetOutObj := packetOutBuilder.Done()
	return c.bridge.SendPacketOut(packetOutObj)
}

// SendICMPReject generates ICMP packet as a packet-out and send it to OVS.
func (c *client) SendICMPPacketOut(
	srcMAC string,
	dstMAC string,
	srcIP string,
	dstIP string,
	inPort uint32,
	outPort int32,
	isIPv6 bool,
	icmpType uint8,
	icmpCode uint8,
	icmpData []byte,
	isReject bool) error {
	// Generate a base IP PacketOutBuilder.
	packetOutBuilder, err := setBasePacketOutBuilder(c.bridge.BuildPacketOut(), srcMAC, dstMAC, srcIP, dstIP, inPort, outPort)
	if err != nil {
		return err
	}
	// Set protocol.
	if isIPv6 {
		packetOutBuilder = packetOutBuilder.SetIPProtocol(binding.ProtocolICMPv6)
	} else {
		packetOutBuilder = packetOutBuilder.SetIPProtocol(binding.ProtocolICMP)
	}
	// Set ICMP header data.
	packetOutBuilder = packetOutBuilder.SetICMPType(icmpType)
	packetOutBuilder = packetOutBuilder.SetICMPCode(icmpCode)
	packetOutBuilder = packetOutBuilder.SetICMPData(icmpData)

	// Reject response packet should bypass ConnTrack
	if isReject {
		name := fmt.Sprintf("%s%d", binding.NxmFieldReg, marksReg)
		packetOutBuilder = packetOutBuilder.AddLoadAction(name, uint64(CustomReasonReject), CustomReasonMarkRange)
	}

	packetOutObj := packetOutBuilder.Done()
	return c.bridge.SendPacketOut(packetOutObj)
}
