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

	"antrea.io/libOpenflow/protocol"
	ofutil "antrea.io/libOpenflow/util"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	utilip "antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/runtime"
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
	Initialize(roundInfo types.RoundInfo, config *config.NodeConfig, networkconfig *config.NetworkConfig) (<-chan struct{}, error)

	// InstallGatewayFlows sets up flows related to an OVS gateway port, the gateway must exist.
	InstallGatewayFlows() error

	// InstallClusterServiceCIDRFlows sets up the appropriate flows so that traffic can reach
	// the different Services running in the Cluster. This method needs to be invoked once with
	// the Cluster Service CIDR as a parameter.
	InstallClusterServiceCIDRFlows(serviceNets []*net.IPNet) error

	// InstallDefaultServiceFlows sets up the appropriate flows so that traffic can reach
	// the different Services running in the Cluster. This method needs to be invoked once.
	InstallDefaultServiceFlows(nodePortAddressesIPv4, nodePortAddressesIPv6 []net.IP) error

	// InstallDefaultTunnelFlows sets up the classification flow for the default (flow based) tunnel.
	InstallDefaultTunnelFlows() error

	// InstallNodeFlows should be invoked when a connection to a remote Node is going to be set
	// up. The hostname is used to identify the added flows. When IPsec tunnel is enabled,
	// ipsecTunOFPort must be set to the OFPort number of the IPsec tunnel port to the remote Node;
	// otherwise ipsecTunOFPort must be set to 0.
	// InstallNodeFlows has all-or-nothing semantics(call succeeds if all the flows are installed
	// successfully, otherwise no flows will be installed). Calls to InstallNodeFlows are idempotent.
	// Concurrent calls to InstallNodeFlows and / or UninstallNodeFlows are supported as long as they
	// are all for different hostnames.
	InstallNodeFlows(
		hostname string,
		peerConfigs map[*net.IPNet]net.IP,
		tunnelPeerIP *utilip.DualStackIPs,
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
	InstallPodFlows(interfaceName string, podInterfaceIPs []net.IP, podInterfaceMAC net.HardwareAddr, ofPort uint32, vlanID uint16) error

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

	// InstallServiceFlows installs flows for accessing Service NodePort, LoadBalancer and ClusterIP. It installs the
	// flow that uses the group/bucket to do service LB. If the affinityTimeout is not zero, it also installs the flow
	// which has a learn action to maintain the LB decision. The group with the groupID must be installed before,
	// otherwise the installation will fail. If the externalTrafficPolicy of NodePort/LoadBalancer is Local,
	// nodeLocalExternal will be true, otherwise it will be false.
	InstallServiceFlows(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol, affinityTimeout uint16, nodeLocalExternal bool, svcType v1.ServiceType) error
	// UninstallServiceFlows removes flows installed by InstallServiceFlows.
	UninstallServiceFlows(svcIP net.IP, svcPort uint16, protocol binding.Protocol) error

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

	// InstallBridgeUplinkFlows installs Openflow flows between bridge local port and uplink port to support host networking.
	InstallBridgeUplinkFlows() error

	// InstallExternalFlows sets up flows to enable Pods to communicate to
	// the external IP addresses. The flows identify the packets from local
	// Pods to the external IP address, and mark the packets to be SNAT'd
	// with the configured SNAT IPs. On Windows Node, the flows also perform
	// SNAT with the Openflow NAT action.
	InstallExternalFlows(exceptCIDRs []net.IPNet) error

	// InstallSNATMarkFlows installs flows for a local SNAT IP. On Linux, a
	// single flow is added to mark the packets tunnelled from remote Nodes
	// that should be SNAT'd with the SNAT IP.
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

	// GetTunnelVirtualMAC() returns GlobalVirtualMAC used for tunnel traffic.
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
	ReassignFlowPriorities(updates map[uint16]uint16, table uint8) error

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
	// SendTCPPacketOut sends TCP packet as a packet-out to OVS.
	SendTCPPacketOut(
		srcMAC string,
		dstMAC string,
		srcIP string,
		dstIP string,
		inPort uint32,
		outPort uint32,
		isIPv6 bool,
		tcpSrcPort uint16,
		tcpDstPort uint16,
		tcpAckNum uint32,
		tcpFlag uint8,
		mutatePacketOut func(builder binding.PacketOutBuilder) binding.PacketOutBuilder) error
	// SendICMPPacketOut sends ICMP packet as a packet-out to OVS.
	SendICMPPacketOut(
		srcMAC string,
		dstMAC string,
		srcIP string,
		dstIP string,
		inPort uint32,
		outPort uint32,
		isIPv6 bool,
		icmpType uint8,
		icmpCode uint8,
		icmpData []byte,
		mutatePacketOut func(builder binding.PacketOutBuilder) binding.PacketOutBuilder) error
	// SendUDPPacketOut sends UDP packet as a packet-out to OVS.
	SendUDPPacketOut(
		srcMAC string,
		dstMAC string,
		srcIP string,
		dstIP string,
		inPort uint32,
		outPort uint32,
		isIPv6 bool,
		udpSrcPort uint16,
		udpDstPort uint16,
		udpData []byte,
		mutatePacketOut func(builder binding.PacketOutBuilder) binding.PacketOutBuilder) error
	// NewDNSpacketInConjunction creates a policyRuleConjunction for the dns response interception flows.
	NewDNSpacketInConjunction(id uint32) error
	// AddAddressToDNSConjunction adds addresses to the toAddresses of the dns packetIn conjunction,
	// so that dns response packets sent towards these addresses will be intercepted and parsed by
	// the fqdnController.
	AddAddressToDNSConjunction(id uint32, addrs []types.Address) error
	// DeleteAddressFromDNSConjunction removes addresses from the toAddresses of the dns packetIn conjunction.
	DeleteAddressFromDNSConjunction(id uint32, addrs []types.Address) error
	// InstallMulticastInitialFlows installs OpenFlow to packetIn the IGMP messages and output the Multicast traffic to
	// antrea-gw0 so that local Pods could access external Multicast servers.
	InstallMulticastInitialFlows(pktInReason uint8) error
	// InstallMulticastFlow installs the flow to forward Multicast traffic normally, and output it to antrea-gw0
	// to ensure it can be forwarded to the external addresses.
	InstallMulticastFlow(multicastIP net.IP) error
	// UninstallMulticastFlow removes the flow matching the given multicastIP.
	UninstallMulticastFlow(multicastIP net.IP) error
	// SendIGMPQueryPacketOut sends the IGMPQuery packet as a packet-out to OVS from the gateway port.
	SendIGMPQueryPacketOut(
		dstMAC net.HardwareAddr,
		dstIP net.IP,
		outPort uint32,
		igmp ofutil.Message) error
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
	tunnelPeerIPs *utilip.DualStackIPs,
	ipsecTunOFPort uint32,
	remoteGatewayMAC net.HardwareAddr,
) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	var flows []binding.Flow
	localGatewayMAC := c.nodeConfig.GatewayConfig.MAC
	for peerPodCIDR, peerGatewayIP := range peerConfigs {
		isIPv6 := peerGatewayIP.To4() == nil
		tunnelPeerIP := tunnelPeerIPs.IPv4
		if isIPv6 {
			tunnelPeerIP = tunnelPeerIPs.IPv6
		} else {
			// Since broadcast is not supported in IPv6, ARP should happen only with IPv4 address, and ARP responder flows
			// only work for IPv4 addresses.
			// arpResponderFlow() adds a flow to resolve peer gateway IPs to GlobalVirtualMAC.
			// This flow replies to ARP requests sent from the local gateway asking for the MAC address of a remote peer gateway. It ensures that the local Node can reach any remote Pod.
			flows = append(flows, c.featurePodConnectivity.arpResponderFlow(peerGatewayIP, GlobalVirtualMAC))
		}
		// tunnelPeerIP is the Node Internal Address. In a dual-stack setup, one Node has 2 Node Internal
		// Addresses (IPv4 and IPv6) .
		if (!isIPv6 && c.networkConfig.NeedsTunnelToPeer(tunnelPeerIPs.IPv4, c.nodeConfig.NodeTransportIPv4Addr)) ||
			(isIPv6 && c.networkConfig.NeedsTunnelToPeer(tunnelPeerIPs.IPv6, c.nodeConfig.NodeTransportIPv6Addr)) {
			flows = append(flows, c.featurePodConnectivity.l3FwdFlowToRemoteViaTun(localGatewayMAC, *peerPodCIDR, tunnelPeerIP))
		} else {
			flows = append(flows, c.featurePodConnectivity.l3FwdFlowToRemoteViaRouting(localGatewayMAC, remoteGatewayMAC, tunnelPeerIP, peerPodCIDR)...)
		}
		if c.enableEgress {
			flows = append(flows, c.featureEgress.snatSkipNodeFlow(tunnelPeerIP))
		}
		if c.connectUplinkToBridge {
			// flow to catch traffic from AntreaFlexibleIPAM Pod to remote Per-Node IPAM Pod
			flows = append(flows, c.featurePodConnectivity.l3FwdFlowToRemoteViaUplink(remoteGatewayMAC, *peerPodCIDR, true))
		}
	}
	if ipsecTunOFPort != 0 {
		// When IPsec tunnel is enabled, packets received from the remote Node are
		// input from the Node's IPsec tunnel port, not the default tunnel port. So,
		// add a separate tunnelClassifierFlow for the IPsec tunnel port.
		flows = append(flows, c.featurePodConnectivity.tunnelClassifierFlow(ipsecTunOFPort))
	}

	// For Windows Noencap Mode, the OVS flows for Node need to be exactly same as the provided 'flows' slice because
	// the Node flows may be processed more than once if the MAC annotation is updated.
	return c.modifyFlows(c.featurePodConnectivity.nodeCachedFlows, hostname, flows)
}

func (c *client) UninstallNodeFlows(hostname string) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	return c.deleteFlows(c.featurePodConnectivity.nodeCachedFlows, hostname)
}

func (c *client) InstallPodFlows(interfaceName string, podInterfaceIPs []net.IP, podInterfaceMAC net.HardwareAddr, ofPort uint32, vlanID uint16) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	podInterfaceIPv4 := util.GetIPv4Addr(podInterfaceIPs)
	// TODO(gran): support IPv6
	isAntreaFlexibleIPAM := c.connectUplinkToBridge && c.nodeConfig.PodIPv4CIDR != nil && !c.nodeConfig.PodIPv4CIDR.Contains(podInterfaceIPv4)

	localGatewayMAC := c.nodeConfig.GatewayConfig.MAC
	flows := []binding.Flow{
		c.featurePodConnectivity.podClassifierFlow(ofPort, isAntreaFlexibleIPAM),
		c.featurePodConnectivity.l2ForwardCalcFlow(podInterfaceMAC, ofPort),
	}

	// Add support for IPv4 ARP responder.
	if podInterfaceIPv4 != nil {
		flows = append(flows, c.featurePodConnectivity.arpSpoofGuardFlow(podInterfaceIPv4, podInterfaceMAC, ofPort))
	}
	// Add IP SpoofGuard flows for all validate IPs.
	flows = append(flows, c.featurePodConnectivity.podIPSpoofGuardFlow(podInterfaceIPs, podInterfaceMAC, ofPort, vlanID)...)
	// Add L3 Routing flows to rewrite Pod's dst MAC for all validate IPs.
	flows = append(flows, c.featurePodConnectivity.l3FwdFlowToPod(localGatewayMAC, podInterfaceIPs, podInterfaceMAC, isAntreaFlexibleIPAM, vlanID)...)

	if c.networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		// In policy-only mode, traffic to local Pod is routed based on destination IP.
		flows = append(flows,
			c.featurePodConnectivity.l3FwdFlowRouteToPod(podInterfaceIPs, podInterfaceMAC)...,
		)
	}

	if isAntreaFlexibleIPAM {
		// Add Pod uplink classifier flows for AntreaFlexibleIPAM Pods.
		flows = append(flows, c.featurePodConnectivity.podUplinkClassifierFlows(podInterfaceMAC, vlanID)...)
		if vlanID > 0 {
			flows = append(flows, c.featurePodConnectivity.podVLANFlow(ofPort, vlanID))
		}
	}

	return c.addFlows(c.featurePodConnectivity.podCachedFlows, interfaceName, flows)
}

func (c *client) UninstallPodFlows(interfaceName string) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	return c.deleteFlows(c.featurePodConnectivity.podCachedFlows, interfaceName)
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
	return c.getFlowKeysFromCache(c.featurePodConnectivity.podCachedFlows, interfaceName)
}

func (c *client) InstallServiceGroup(groupID binding.GroupIDType, withSessionAffinity bool, endpoints []proxy.Endpoint) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	group := c.featureService.serviceEndpointGroup(groupID, withSessionAffinity, endpoints...)
	if err := group.Add(); err != nil {
		return fmt.Errorf("error when installing Service Endpoints Group: %w", err)
	}
	c.featureService.groupCache.Store(groupID, group)
	return nil
}

func (c *client) UninstallServiceGroup(groupID binding.GroupIDType) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	if !c.bridge.DeleteGroup(groupID) {
		return fmt.Errorf("group %d delete failed", groupID)
	}
	c.featureService.groupCache.Delete(groupID)
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
		flows = append(flows, c.featureService.endpointDNATFlow(endpointIP, portVal, protocol))
		if endpoint.GetIsLocal() {
			flows = append(flows, c.featureService.podHairpinSNATFlow(endpointIP))
		}
		keyToFlows[cacheKey] = flows
	}

	return c.addFlowsWithMultipleKeys(c.featureService.cachedFlows, keyToFlows)
}

func (c *client) UninstallEndpointFlows(protocol binding.Protocol, endpoint proxy.Endpoint) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	port, err := endpoint.Port()
	if err != nil {
		return fmt.Errorf("error when getting port: %w", err)
	}
	cacheKey := generateEndpointFlowCacheKey(endpoint.IP(), port, protocol)
	return c.deleteFlows(c.featureService.cachedFlows, cacheKey)
}

func (c *client) InstallServiceFlows(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol, affinityTimeout uint16, nodeLocalExternal bool, svcType v1.ServiceType) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	var flows []binding.Flow
	flows = append(flows, c.featureService.serviceLBFlow(groupID, svcIP, svcPort, protocol, affinityTimeout != 0, nodeLocalExternal, svcType))
	if affinityTimeout != 0 {
		flows = append(flows, c.featureService.serviceLearnFlow(groupID, svcIP, svcPort, protocol, affinityTimeout, nodeLocalExternal, svcType))
	}
	cacheKey := generateServicePortFlowCacheKey(svcIP, svcPort, protocol)
	return c.addFlows(c.featureService.cachedFlows, cacheKey, flows)
}

func (c *client) UninstallServiceFlows(svcIP net.IP, svcPort uint16, protocol binding.Protocol) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	cacheKey := generateServicePortFlowCacheKey(svcIP, svcPort, protocol)
	return c.deleteFlows(c.featureService.cachedFlows, cacheKey)
}

func (c *client) GetServiceFlowKeys(svcIP net.IP, svcPort uint16, protocol binding.Protocol, endpoints []proxy.Endpoint) []string {
	cacheKey := generateServicePortFlowCacheKey(svcIP, svcPort, protocol)
	flowKeys := c.getFlowKeysFromCache(c.featureService.cachedFlows, cacheKey)
	for _, ep := range endpoints {
		epPort, _ := ep.Port()
		cacheKey = generateEndpointFlowCacheKey(ep.IP(), epPort, protocol)
		flowKeys = append(flowKeys, c.getFlowKeysFromCache(c.featureService.cachedFlows, cacheKey)...)
	}
	return flowKeys
}

func (c *client) InstallDefaultServiceFlows(nodePortAddressesIPv4, nodePortAddressesIPv6 []net.IP) error {
	flows := []binding.Flow{
		c.featureService.serviceNeedLBFlow(),
		c.featureService.sessionAffinityReselectFlow(),
		c.featureService.l2ForwardOutputHairpinServiceFlow(),
	}

	if c.proxyAll {
		for _, ipProtocol := range c.ipProtocols {
			// These flows are used to match the first packet of NodePort. The flows will set a bit of a register to mark
			// the Service type of the packet as NodePort. The mark will be consumed in table serviceLBTable to match NodePort
			nodePortAddresses := nodePortAddressesIPv4
			if ipProtocol == binding.ProtocolIPv6 {
				nodePortAddresses = nodePortAddressesIPv6
			}
			flows = append(flows, c.featureService.nodePortMarkFlows(nodePortAddresses, ipProtocol)...)
		}
	}
	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return err
	}
	c.featureService.fixedFlows = flows
	return nil
}

func (c *client) InstallClusterServiceCIDRFlows(serviceNets []*net.IPNet) error {
	flows := c.featureService.serviceCIDRDNATFlows(serviceNets)
	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return err
	}
	c.featureService.fixedFlows = flows
	return nil
}

func (c *client) InstallGatewayFlows() error {
	gatewayConfig := c.nodeConfig.GatewayConfig

	flows := []binding.Flow{
		c.featurePodConnectivity.gatewayClassifierFlow(),
		c.featurePodConnectivity.l2ForwardCalcFlow(gatewayConfig.MAC, config.HostGatewayOFPort),
	}
	flows = append(flows, c.featurePodConnectivity.gatewayIPSpoofGuardFlows()...)

	// Add ARP SpoofGuard flow for local gateway interface.
	if gatewayConfig.IPv4 != nil {
		flows = append(flows, c.featurePodConnectivity.arpSpoofGuardFlow(gatewayConfig.IPv4, gatewayConfig.MAC, config.HostGatewayOFPort))
		if c.connectUplinkToBridge {
			flows = append(flows, c.featurePodConnectivity.arpSpoofGuardFlow(c.nodeConfig.NodeIPv4Addr.IP, gatewayConfig.MAC, config.HostGatewayOFPort))
		}
	}

	// Add flow to ensure the liveness check packet could be forwarded correctly.
	flows = append(flows, c.featurePodConnectivity.localProbeFlow(c.ovsDatapathType)...)
	flows = append(flows, c.featurePodConnectivity.l3FwdFlowToGateway()...)

	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return err
	}
	c.featurePodConnectivity.fixedFlows = append(c.featurePodConnectivity.fixedFlows, flows...)
	return nil
}

func (c *client) InstallDefaultTunnelFlows() error {
	flows := []binding.Flow{
		c.featurePodConnectivity.tunnelClassifierFlow(config.DefaultTunOFPort),
		c.featurePodConnectivity.l2ForwardCalcFlow(GlobalVirtualMAC, config.DefaultTunOFPort),
	}
	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		return err
	}
	c.featurePodConnectivity.fixedFlows = append(c.featurePodConnectivity.fixedFlows, flows...)
	return nil
}

func (c *client) initialize() error {
	if err := c.ofEntryOperations.AddAll(c.defaultFlows()); err != nil {
		return fmt.Errorf("failed to install default flows: %v", err)
	}

	for _, activeFeature := range c.activatedFeatures {
		if err := c.ofEntryOperations.AddAll(activeFeature.initFlows()); err != nil {
			return fmt.Errorf("failed to install feature %v initial flows: %v", activeFeature.getFeatureName(), err)
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

func (c *client) Initialize(roundInfo types.RoundInfo, nodeConfig *config.NodeConfig, networkConfig *config.NetworkConfig) (<-chan struct{}, error) {
	c.nodeConfig = nodeConfig
	c.networkConfig = networkConfig

	if networkConfig.IPv4Enabled {
		c.ipProtocols = append(c.ipProtocols, binding.ProtocolIP)
	}
	if networkConfig.IPv6Enabled {
		c.ipProtocols = append(c.ipProtocols, binding.ProtocolIPv6)
	}
	c.roundInfo = roundInfo
	c.cookieAllocator = cookie.NewAllocator(roundInfo.RoundNum)
	c.generatePipelines()
	c.realizePipelines()

	// Initiate connections to target OFswitch, and create tables on the switch.
	connCh := make(chan struct{})
	if err := c.bridge.Connect(maxRetryForOFSwitch, connCh); err != nil {
		return nil, err
	}

	// Ignore first notification, it is not a "reconnection".
	<-connCh

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

// generatePipelines generates table list for every pipeline from all activated features. Note that, tables are not realized
// in OVS bridge in this function.
func (c *client) generatePipelines() {
	c.featurePodConnectivity = newFeaturePodConnectivity(c.cookieAllocator,
		c.ipProtocols,
		c.nodeConfig,
		c.networkConfig,
		c.connectUplinkToBridge,
		c.enableMulticast)
	c.activatedFeatures = append(c.activatedFeatures, c.featurePodConnectivity)
	c.traceableFeatures = append(c.traceableFeatures, c.featurePodConnectivity)

	c.featureNetworkPolicy = newFeatureNetworkPolicy(c.cookieAllocator,
		c.ipProtocols,
		c.bridge,
		c.ovsMetersAreSupported,
		c.enableDenyTracking,
		c.enableAntreaPolicy,
		c.connectUplinkToBridge)
	c.activatedFeatures = append(c.activatedFeatures, c.featureNetworkPolicy)
	c.traceableFeatures = append(c.traceableFeatures, c.featureNetworkPolicy)

	c.featureService = newFeatureService(c.cookieAllocator,
		c.ipProtocols,
		c.nodeConfig,
		c.bridge,
		c.enableProxy,
		c.proxyAll,
		c.connectUplinkToBridge)
	c.activatedFeatures = append(c.activatedFeatures, c.featureService)
	c.traceableFeatures = append(c.traceableFeatures, c.featureService)

	if c.enableEgress {
		c.featureEgress = newFeatureEgress(c.cookieAllocator, c.ipProtocols, c.nodeConfig)
		c.activatedFeatures = append(c.activatedFeatures, c.featureEgress)
	}

	if c.enableMulticast {
		// TODO: add support for IPv6 protocol
		c.featureMulticast = newFeatureMulticast(c.cookieAllocator, []binding.Protocol{binding.ProtocolIP})
		c.activatedFeatures = append(c.activatedFeatures, c.featureMulticast)
	}
	c.featureTraceflow = newFeatureTraceflow()
	c.activatedFeatures = append(c.activatedFeatures, c.featureTraceflow)

	// Pipelines to generate.
	pipelineIDs := []binding.PipelineID{pipelineRoot, pipelineIP}
	if c.networkConfig.IPv4Enabled {
		pipelineIDs = append(pipelineIDs, pipelineARP)
		if c.enableMulticast {
			pipelineIDs = append(pipelineIDs, pipelineMulticast)
		}
	}

	// For every pipeline, get required tables from every active feature and store the required tables in a map to avoid
	// duplication.
	pipelineRequiredTablesMap := make(map[binding.PipelineID]map[*Table]struct{})
	for _, pipelineID := range pipelineIDs {
		pipelineRequiredTablesMap[pipelineID] = make(map[*Table]struct{})
	}
	pipelineRequiredTablesMap[pipelineRoot][PipelineRootClassifierTable] = struct{}{}

	for _, f := range c.activatedFeatures {
		for _, t := range f.getRequiredTables() {
			if _, ok := pipelineRequiredTablesMap[t.pipeline]; ok {
				pipelineRequiredTablesMap[t.pipeline][t] = struct{}{}
			}
		}
	}

	for pipelineID := firstPipeline; pipelineID <= lastPipeline; pipelineID++ {
		if _, ok := pipelineRequiredTablesMap[pipelineID]; !ok {
			continue
		}
		var requiredTables []*Table
		// Iterate the table order cache to generate a sorted table list with required tables.
		for _, table := range tableOrderCache[pipelineID] {
			if _, ok := pipelineRequiredTablesMap[pipelineID][table]; ok {
				requiredTables = append(requiredTables, table)
			}
		}
		if len(requiredTables) == 0 {
			klog.InfoS("There is no required table for the pipeline ID, skip generating pipeline", "pipeline", pipelineID)
			continue
		}
		// generate a pipeline from the required table list.
		c.pipelines[pipelineID] = generatePipeline(pipelineID, requiredTables)
	}
}

func (c *client) InstallExternalFlows(exceptCIDRs []net.IPNet) error {
	if c.enableEgress {
		flows := c.featureEgress.externalFlows(exceptCIDRs)
		if err := c.ofEntryOperations.AddAll(flows); err != nil {
			return fmt.Errorf("failed to install flows for external communication: %v", err)
		}
		c.featureEgress.fixedFlows = append(c.featureEgress.fixedFlows, flows...)
	}
	return nil
}

func (c *client) InstallSNATMarkFlows(snatIP net.IP, mark uint32) error {
	flow := c.featureEgress.snatIPFromTunnelFlow(snatIP, mark)
	cacheKey := fmt.Sprintf("s%x", mark)
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	return c.addFlows(c.featureEgress.cachedFlows, cacheKey, []binding.Flow{flow})
}

func (c *client) UninstallSNATMarkFlows(mark uint32) error {
	cacheKey := fmt.Sprintf("s%x", mark)
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	return c.deleteFlows(c.featureEgress.cachedFlows, cacheKey)
}

func (c *client) InstallPodSNATFlows(ofPort uint32, snatIP net.IP, snatMark uint32) error {
	flows := []binding.Flow{c.featureEgress.snatRuleFlow(ofPort, snatIP, snatMark, c.nodeConfig.GatewayConfig.MAC)}
	cacheKey := fmt.Sprintf("p%x", ofPort)
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	return c.addFlows(c.featureEgress.cachedFlows, cacheKey, flows)
}

func (c *client) UninstallPodSNATFlows(ofPort uint32) error {
	cacheKey := fmt.Sprintf("p%x", ofPort)
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	return c.deleteFlows(c.featureEgress.cachedFlows, cacheKey)
}

func (c *client) ReplayFlows() {
	c.replayMutex.Lock()
	defer c.replayMutex.Unlock()

	if err := c.initialize(); err != nil {
		klog.Errorf("Error during flow replay: %v", err)
	}

	c.featureService.replayGroups()

	for _, activeFeature := range c.activatedFeatures {
		if err := c.ofEntryOperations.AddAll(activeFeature.replayFlows()); err != nil {
			klog.ErrorS(err, "Error when replaying feature flows", "feature", activeFeature.getFeatureName())
		}
	}
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
	var flows []binding.Flow
	for _, f := range c.traceableFeatures {
		flows = append(flows, f.flowsToTrace(dataplaneTag,
			c.ovsMetersAreSupported,
			liveTraffic,
			droppedOnly,
			receiverOnly,
			packet,
			ofPort,
			timeoutSeconds)...)
	}
	return c.addFlows(c.featureTraceflow.cachedFlows, cacheKey, flows)
}

func (c *client) UninstallTraceflowFlows(dataplaneTag uint8) error {
	cacheKey := fmt.Sprintf("%x", dataplaneTag)
	return c.deleteFlows(c.featureTraceflow.cachedFlows, cacheKey)
}

// Add TLV map optClass 0x0104, optType 0x80 optLength 4 tunMetadataIndex 0 to store data plane tag
// in tunnel. Data plane tag will be stored to NXM_NX_TUN_METADATA0[28..31] when packet get encapsulated
// into geneve, and will be stored back to NXM_NX_REG9[28..31] when packet get decapsulated.
func (c *client) InitialTLVMap() error {
	return c.bridge.AddTLVMap(0x0104, 0x80, 4, 0)
}

// setBasePacketOutBuilder sets base IP properties of a packetOutBuilder which can have more packet data added.
func setBasePacketOutBuilder(packetOutBuilder binding.PacketOutBuilder, srcMAC string, dstMAC string, srcIP string, dstIP string, inPort uint32, outPort uint32) (binding.PacketOutBuilder, error) {
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
	if outPort != 0 {
		packetOutBuilder = packetOutBuilder.SetOutport(outPort)
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
	outPort uint32,
	isIPv6 bool,
	tcpSrcPort uint16,
	tcpDstPort uint16,
	tcpAckNum uint32,
	tcpFlag uint8,
	mutatePacketOut func(builder binding.PacketOutBuilder) binding.PacketOutBuilder) error {
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

	if mutatePacketOut != nil {
		packetOutBuilder = mutatePacketOut(packetOutBuilder)
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
	outPort uint32,
	isIPv6 bool,
	icmpType uint8,
	icmpCode uint8,
	icmpData []byte,
	mutatePacketOut func(builder binding.PacketOutBuilder) binding.PacketOutBuilder) error {
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

	if mutatePacketOut != nil {
		packetOutBuilder = mutatePacketOut(packetOutBuilder)
	}

	packetOutObj := packetOutBuilder.Done()
	return c.bridge.SendPacketOut(packetOutObj)
}

// SendUDPPacketOut generates UDP packet as a packet-out and sends it to OVS.
func (c *client) SendUDPPacketOut(
	srcMAC string,
	dstMAC string,
	srcIP string,
	dstIP string,
	inPort uint32,
	outPort uint32,
	isIPv6 bool,
	udpSrcPort uint16,
	udpDstPort uint16,
	udpData []byte,
	mutatePacketOut func(builder binding.PacketOutBuilder) binding.PacketOutBuilder) error {
	// Generate a base IP PacketOutBuilder.
	packetOutBuilder, err := setBasePacketOutBuilder(c.bridge.BuildPacketOut(), srcMAC, dstMAC, srcIP, dstIP, inPort, outPort)
	if err != nil {
		return err
	}
	// Set protocol.
	if isIPv6 {
		packetOutBuilder = packetOutBuilder.SetIPProtocol(binding.ProtocolUDPv6)
	} else {
		packetOutBuilder = packetOutBuilder.SetIPProtocol(binding.ProtocolUDP)
	}
	// Set UDP header data.
	packetOutBuilder = packetOutBuilder.SetUDPSrcPort(udpSrcPort).
		SetUDPDstPort(udpDstPort).
		SetUDPData(udpData)

	if mutatePacketOut != nil {
		packetOutBuilder = mutatePacketOut(packetOutBuilder)
	}

	packetOutObj := packetOutBuilder.Done()
	return c.bridge.SendPacketOut(packetOutObj)
}

func (c *client) InstallMulticastInitialFlows(pktInReason uint8) error {
	flows := c.featureMulticast.igmpPktInFlows(pktInReason)
	flows = append(flows, c.featureMulticast.externalMulticastReceiverFlow())
	cacheKey := fmt.Sprintf("multicast")
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	return c.addFlows(c.featureMulticast.mcastFlowCache, cacheKey, flows)
}

func (c *client) InstallMulticastFlow(multicastIP net.IP) error {
	flows := c.featureMulticast.localMulticastForwardFlow(multicastIP)
	cacheKey := fmt.Sprintf("multicast_%s", multicastIP.String())
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	return c.addFlows(c.featureMulticast.mcastFlowCache, cacheKey, flows)
}

func (c *client) UninstallMulticastFlow(multicastIP net.IP) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()
	cacheKey := fmt.Sprintf("multicast_%s", multicastIP.String())
	return c.deleteFlows(c.featureMulticast.mcastFlowCache, cacheKey)
}

func (c *client) SendIGMPQueryPacketOut(
	dstMAC net.HardwareAddr,
	dstIP net.IP,
	outPort uint32,
	igmp ofutil.Message) error {
	// Generate a base IP PacketOutBuilder.
	srcMAC := c.nodeConfig.GatewayConfig.MAC.String()
	srcIP := c.nodeConfig.GatewayConfig.IPv4.String()
	dstMACStr := dstMAC.String()
	dstIPStr := dstIP.String()
	packetOutBuilder, err := setBasePacketOutBuilder(c.bridge.BuildPacketOut(), srcMAC, dstMACStr, srcIP, dstIPStr, config.HostGatewayOFPort, outPort)
	if err != nil {
		return err
	}
	// Set protocol and L4 message.
	packetOutBuilder = packetOutBuilder.SetIPProtocol(binding.ProtocolIGMP).SetL4Packet(igmp)
	packetOutObj := packetOutBuilder.Done()
	return c.bridge.SendPacketOut(packetOutObj)
}

func (c *client) InstallBridgeUplinkFlows() error {
	if runtime.IsWindowsPlatform() || c.connectUplinkToBridge {
		podCIDRMap := make(map[binding.Protocol]net.IPNet)
		if c.nodeConfig.PodIPv4CIDR != nil {
			podCIDRMap[binding.ProtocolIP] = *c.nodeConfig.PodIPv4CIDR
		}
		//TODO: support IPv6
		flows := c.featurePodConnectivity.hostBridgeUplinkFlows(podCIDRMap)
		if c.connectUplinkToBridge {
			flows = append(flows, c.featurePodConnectivity.hostBridgeUplinkVLANFlows()...)
		}
		if err := c.ofEntryOperations.AddAll(flows); err != nil {
			return err
		}
		c.featurePodConnectivity.fixedFlows = append(c.featurePodConnectivity.fixedFlows, flows...)
	}
	return nil
}
