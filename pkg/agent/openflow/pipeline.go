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
	"strconv"
	"strings"
	"sync"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow/cookie"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

const (
	// Flow table id index
	classifierTable       binding.TableIDType = 0
	spoofGuardTable       binding.TableIDType = 10
	arpResponderTable     binding.TableIDType = 20
	conntrackTable        binding.TableIDType = 30
	conntrackStateTable   binding.TableIDType = 31
	dnatTable             binding.TableIDType = 40
	egressRuleTable       binding.TableIDType = 50
	egressDefaultTable    binding.TableIDType = 60
	l3ForwardingTable     binding.TableIDType = 70
	l2ForwardingCalcTable binding.TableIDType = 80
	ingressRuleTable      binding.TableIDType = 90
	ingressDefaultTable   binding.TableIDType = 100
	conntrackCommitTable  binding.TableIDType = 105
	l2ForwardingOutTable  binding.TableIDType = 110

	// Flow priority level
	priorityHigh   = uint16(210)
	priorityNormal = uint16(200)
	priorityLow    = uint16(190)
	prioritySNAT   = uint16(180)
	priorityMiss   = uint16(0)

	// Traffic marks
	markTrafficFromTunnel  = 0
	markTrafficFromGateway = 1
	markTrafficFromLocal   = 2
	markTrafficFromUplink  = 4
)

var (
	FlowTables = []struct {
		Number binding.TableIDType
		Name   string
	}{
		{classifierTable, "Classification"},
		{spoofGuardTable, "SpoofGuard"},
		{arpResponderTable, "ARPResponder"},
		{conntrackTable, "ConntrackZone"},
		{conntrackStateTable, "ContrackState"},
		{dnatTable, "DNAT"},
		{egressRuleTable, "EgressRule"},
		{egressDefaultTable, "EgressDefaultRule"},
		{l3ForwardingTable, "L3Forwarding"},
		{l2ForwardingCalcTable, "L2Forwarding"},
		{ingressRuleTable, "IngressRule"},
		{ingressDefaultTable, "IngressDefaultRule"},
		{conntrackCommitTable, "ConntrackCommit"},
		{l2ForwardingOutTable, "Output"},
	}
)

// GetFlowTableName returns the flow table name given the table number. An empty
// string is returned if the table cannot be found.
func GetFlowTableName(tableNumber binding.TableIDType) string {
	for _, t := range FlowTables {
		if t.Number == tableNumber {
			return t.Name
		}
	}
	return ""
}

// GetFlowTableNumber does a case insensitive lookup of the table name, and
// returns the flow table number if the table is found. Otherwise TableIDAll is
// returned if the table cannot be found.
func GetFlowTableNumber(tableName string) binding.TableIDType {
	for _, t := range FlowTables {
		if strings.EqualFold(t.Name, tableName) {
			return t.Number
		}
	}
	return binding.TableIDAll
}

type regType uint

func (rt regType) number() string {
	return fmt.Sprint(rt)
}

func (rt regType) nxm() string {
	return fmt.Sprintf("NXM_NX_REG%d", rt)
}

func (rt regType) reg() string {
	return fmt.Sprintf("reg%d", rt)
}

const (
	// marksReg stores traffic-source mark and pod-found mark.
	// traffic-source resides in [0..15], pod-found resides in [16].
	marksReg     regType = 0
	portCacheReg regType = 1
	swapReg      regType = 2

	ctZone = 0xfff0

	portFoundMark    = 0x1
	snatRequiredMark = 0x1

	gatewayCTMark = 0x20
	snatCTMark    = 0x40
)

var (
	// ofPortMarkRange takes the 16th bit of register marksReg to indicate if the ofPort number of an interface
	// is found or not. Its value is 0x1 if yes.
	ofPortMarkRange = binding.Range{16, 16}
	// ofPortRegRange takes a 32-bit range of register portCacheReg to cache the ofPort number of the interface.
	ofPortRegRange = binding.Range{0, 31}
	// snatMarkRange takes the 17th bit of register marksReg to indicate if the packet needs to be SNATed with Node's IP
	// or not. Its value is 0x1 if yes.
	snatMarkRange = binding.Range{17, 17}

	globalVirtualMAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")
	ReentranceMAC, _    = net.ParseMAC("de:ad:be:ef:de:ad")
)

type OFEntryOperations interface {
	Add(flow binding.Flow) error
	Modify(flow binding.Flow) error
	Delete(flow binding.Flow) error
	AddAll(flows []binding.Flow) error
	DeleteAll(flows []binding.Flow) error
	AddOFEntries(ofEntries []binding.OFEntry) error
	DeleteOFEntries(ofEntries []binding.OFEntry) error
}

type flowCache map[string]binding.Flow

type flowCategoryCache struct {
	sync.Map
}

type client struct {
	roundInfo                   types.RoundInfo
	cookieAllocator             cookie.Allocator
	bridge                      binding.Bridge
	pipeline                    map[binding.TableIDType]binding.Table
	nodeFlowCache, podFlowCache *flowCategoryCache // cache for corresponding deletions
	// "fixed" flows installed by the agent after initialization and which do not change during
	// the lifetime of the client.
	gatewayFlows, clusterServiceCIDRFlows, defaultTunnelFlows, hostNetworkingFlows []binding.Flow
	// ofEntryOperations is a wrapper interface for OpenFlow entry Add / Modify / Delete operations. It
	// enables convenient mocking in unit tests.
	ofEntryOperations OFEntryOperations
	// policyCache is a map from PolicyRule ID to policyRuleConjunction. It's guaranteed that one policyRuleConjunction
	// is processed by at most one goroutine at any given time.
	policyCache       sync.Map
	conjMatchFlowLock sync.Mutex // Lock for access globalConjMatchFlowCache
	// globalConjMatchFlowCache is a global map for conjMatchFlowContext. The key is a string generated from the
	// conjMatchFlowContext.
	globalConjMatchFlowCache map[string]*conjMatchFlowContext
	// replayMutex provides exclusive access to the OFSwitch to the ReplayFlows method.
	replayMutex sync.RWMutex
	nodeConfig  *config.NodeConfig
	encapMode   config.TrafficEncapModeType
	gatewayPort uint32 // OVSOFPort number
}

func (c *client) Add(flow binding.Flow) error {
	return c.bridge.AddFlowsInBundle([]binding.Flow{flow}, nil, nil)
}

func (c *client) Modify(flow binding.Flow) error {
	return c.bridge.AddFlowsInBundle(nil, []binding.Flow{flow}, nil)
}

func (c *client) Delete(flow binding.Flow) error {
	return c.bridge.AddFlowsInBundle(nil, nil, []binding.Flow{flow})
}

func (c *client) AddAll(flows []binding.Flow) error {
	return c.bridge.AddFlowsInBundle(flows, nil, nil)
}

func (c *client) DeleteAll(flows []binding.Flow) error {
	return c.bridge.AddFlowsInBundle(nil, nil, flows)
}

func (c *client) AddOFEntries(ofEntries []binding.OFEntry) error {
	return c.bridge.AddOFEntriesInBundle(ofEntries, nil, nil)
}

func (c *client) DeleteOFEntries(ofEntries []binding.OFEntry) error {
	return c.bridge.AddOFEntriesInBundle(nil, nil, ofEntries)
}

// defaultFlows generates the default flows of all tables.
func (c *client) defaultFlows() (flows []binding.Flow) {
	for _, table := range c.pipeline {
		flowBuilder := table.BuildFlow(priorityMiss)
		switch table.GetMissAction() {
		case binding.TableMissActionNext:
			flowBuilder = flowBuilder.Action().ResubmitToTable(table.GetNext())
		case binding.TableMissActionNormal:
			flowBuilder = flowBuilder.Action().Normal()
		case binding.TableMissActionDrop:
			flowBuilder = flowBuilder.Action().Drop()
		case binding.TableMissActionNone:
			fallthrough
		default:
			continue
		}
		flows = append(flows, flowBuilder.Cookie(c.cookieAllocator.Request(cookie.Default).Raw()).Done())
	}
	return flows
}

// tunnelClassifierFlow generates the flow to mark traffic comes from the tunnelOFPort.
func (c *client) tunnelClassifierFlow(tunnelOFPort uint32, category cookie.Category) binding.Flow {
	return c.pipeline[classifierTable].BuildFlow(priorityNormal).
		MatchInPort(tunnelOFPort).
		Action().LoadRegRange(int(marksReg), markTrafficFromTunnel, binding.Range{0, 15}).
		Action().ResubmitToTable(conntrackTable).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// gatewayClassifierFlow generates the flow to mark traffic comes from the gatewayOFPort.
func (c *client) gatewayClassifierFlow(gatewayOFPort uint32, category cookie.Category) binding.Flow {
	classifierTable := c.pipeline[classifierTable]
	return classifierTable.BuildFlow(priorityNormal).
		MatchInPort(gatewayOFPort).
		Action().LoadRegRange(int(marksReg), markTrafficFromGateway, binding.Range{0, 15}).
		Action().ResubmitToTable(classifierTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// podClassifierFlow generates the flow to mark traffic comes from the podOFPort.
func (c *client) podClassifierFlow(podOFPort uint32, category cookie.Category) binding.Flow {
	classifierTable := c.pipeline[classifierTable]
	return classifierTable.BuildFlow(priorityLow).
		MatchInPort(podOFPort).
		Action().LoadRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
		Action().ResubmitToTable(classifierTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// hostBridgeUplinkFlows generates the flows that forward traffic between bridge local port and uplink port to support
// host communicate with outside. These flows are only needed on windows platform.
func (c *client) hostBridgeUplinkFlows(uplinkPort uint32, bridgeLocalPort uint32, category cookie.Category) (flows []binding.Flow) {
	classifierTable := c.pipeline[classifierTable]
	flows = []binding.Flow{
		classifierTable.BuildFlow(priorityLow).MatchInPort(uplinkPort).
			Action().Output(int(bridgeLocalPort)).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		classifierTable.BuildFlow(priorityNormal).MatchInPort(bridgeLocalPort).
			Action().Output(int(uplinkPort)).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	}
	return flows
}

// connectionTrackFlows generates flows that redirect traffic to ct_zone and handle traffic according to ct_state:
// 1) commit new connections to ct_zone(0xfff0) in the conntrackCommitTable.
// 2) Add ct_mark on the packet if it is sent to the switch from the host gateway.
// 3) Allow traffic if it hits ct_mark and is sent from the host gateway.
// 4) Drop all invalid traffic.
// 5) Resubmit other traffic to the next table by the table-miss flow.
func (c *client) connectionTrackFlows(category cookie.Category) (flows []binding.Flow) {
	connectionTrackTable := c.pipeline[conntrackTable]
	connectionTrackStateTable := c.pipeline[conntrackStateTable]
	connectionTrackCommitTable := c.pipeline[conntrackCommitTable]
	flows = []binding.Flow{
		connectionTrackTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Action().CT(false, connectionTrackTable.GetNext(), ctZone).CTDone().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		connectionTrackStateTable.BuildFlow(priorityHigh).MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), markTrafficFromGateway, binding.Range{0, 15}).
			MatchCTMark(gatewayCTMark).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			Action().ResubmitToTable(connectionTrackStateTable.GetNext()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		connectionTrackStateTable.BuildFlow(priorityLow).MatchProtocol(binding.ProtocolIP).
			MatchCTStateInv(true).MatchCTStateTrk(true).
			Action().Drop().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		connectionTrackCommitTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), markTrafficFromGateway, binding.Range{0, 15}).
			MatchCTStateNew(true).MatchCTStateTrk(true).
			Action().CT(true, connectionTrackCommitTable.GetNext(), ctZone).LoadToMark(gatewayCTMark).CTDone().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		connectionTrackCommitTable.BuildFlow(priorityLow).MatchProtocol(binding.ProtocolIP).
			MatchCTStateNew(true).MatchCTStateTrk(true).
			Action().CT(true, connectionTrackCommitTable.GetNext(), ctZone).CTDone().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	}
	return
}

// reEntranceBypassCTFlow generates flow that bypass CT for traffic re-entering host network space.
// In host network space, we disable conntrack for re-entrance traffic so not to confuse conntrack
// in host namespace, This however has inverse effect on conntrack in Antrea conntrack zone as well,
// all subsequent re-entrance traffic becomes invalid.
func (c *client) reEntranceBypassCTFlow(gwPort, reentPort uint32, category cookie.Category) binding.Flow {
	conntrackCommitTable := c.pipeline[conntrackCommitTable]
	return conntrackCommitTable.BuildFlow(priorityHigh).MatchProtocol(binding.ProtocolIP).
		MatchRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
		MatchInPort(gwPort).MatchReg(int(portCacheReg), reentPort).
		Action().ResubmitToTable(conntrackCommitTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// ctRewriteDstMACFlow rewrites the destination MAC with local host gateway MAC if the packets has set ct_mark but not sent from the host gateway.
func (c *client) ctRewriteDstMACFlow(gatewayMAC net.HardwareAddr, category cookie.Category) binding.Flow {
	connectionTrackStateTable := c.pipeline[conntrackStateTable]
	macData, _ := strconv.ParseUint(strings.Replace(gatewayMAC.String(), ":", "", -1), 16, 64)
	return connectionTrackStateTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchCTMark(gatewayCTMark).
		MatchCTStateNew(false).MatchCTStateTrk(true).
		Action().LoadRange(binding.NxmFieldDstMAC, macData, binding.Range{0, 47}).
		Action().ResubmitToTable(connectionTrackStateTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// l2ForwardCalcFlow generates the flow that matches dst MAC and loads ofPort to reg.
func (c *client) l2ForwardCalcFlow(dstMAC net.HardwareAddr, ofPort uint32, category cookie.Category) binding.Flow {
	l2FwdCalcTable := c.pipeline[l2ForwardingCalcTable]
	return l2FwdCalcTable.BuildFlow(priorityNormal).
		MatchDstMAC(dstMAC).
		Action().LoadRegRange(int(portCacheReg), ofPort, ofPortRegRange).
		Action().LoadRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
		Action().ResubmitToTable(l2FwdCalcTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// l2ForwardOutputFlow generates the flow that outputs packets to OVS port after L2 forwarding calculation.
func (c *client) l2ForwardOutputFlow(category cookie.Category) binding.Flow {
	return c.pipeline[l2ForwardingOutTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
		Action().OutputRegRange(int(portCacheReg), ofPortRegRange).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// l2ForwardOutputReentInPortFlow generates the flow that forward re-entrance peer Node traffic via gw0.
// This flow supersedes default output flow because ovs by default auto-skips packets with output = input port.
func (c *client) l2ForwardOutputReentInPortFlow(gwPort uint32, category cookie.Category) binding.Flow {
	return c.pipeline[l2ForwardingOutTable].BuildFlow(priorityHigh).MatchProtocol(binding.ProtocolIP).
		MatchRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
		MatchInPort(gwPort).MatchReg(int(portCacheReg), gwPort).
		Action().SetSrcMAC(ReentranceMAC).
		Action().OutputInPort().
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// l3BypassMACRewriteFlow bypasses remaining l3forwarding flows if the MAC is set via ctRewriteDstMACFlow in
// conntrackState stage.
func (c *client) l3BypassMACRewriteFlow(gatewayMAC net.HardwareAddr, category cookie.Category) binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	return l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchCTMark(gatewayCTMark).
		MatchDstMAC(gatewayMAC).
		Action().ResubmitToTable(l3FwdTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// l3FlowsToPod generates the flow to rewrite MAC if the packet is received from tunnel port and destined for local Pods.
func (c *client) l3FlowsToPod(localGatewayMAC net.HardwareAddr, podInterfaceIP net.IP, podInterfaceMAC net.HardwareAddr, category cookie.Category) binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	// Rewrite src MAC to local gateway MAC, and rewrite dst MAC to pod MAC
	return l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchDstMAC(globalVirtualMAC).
		MatchDstIP(podInterfaceIP).
		Action().SetSrcMAC(localGatewayMAC).
		Action().SetDstMAC(podInterfaceMAC).
		Action().DecTTL().
		Action().ResubmitToTable(l3FwdTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// l3ToPodFromGwFlow generates the flow to rewrite MAC if the packet IP matches an local IP.
// This flow is used in policy only traffic mode.
func (c *client) l3ToPodFlow(podInterfaceIP net.IP, podInterfaceMAC net.HardwareAddr, category cookie.Category) binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	return l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchDstIP(podInterfaceIP).
		Action().SetDstMAC(podInterfaceMAC).
		Action().DecTTL().
		Action().ResubmitToTable(l3FwdTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// l3ToGWFlow generates the flow to rewrite MAC to gw port if the packet received is unmatched by local Pod flows.
// This flow is used in policy only traffic mode.
func (c *client) l3ToGWFlow(gwMAC net.HardwareAddr, category cookie.Category) binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	return l3FwdTable.BuildFlow(priorityLow).MatchProtocol(binding.ProtocolIP).
		Action().SetDstMAC(gwMAC).
		Action().DecTTL().
		Action().ResubmitToTable(l3FwdTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// l3ToGatewayFlow generates flow that rewrites MAC of the packet received from tunnel port and destined to local gateway.
func (c *client) l3ToGatewayFlow(localGatewayIP net.IP, localGatewayMAC net.HardwareAddr, category cookie.Category) binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	return l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchDstMAC(globalVirtualMAC).
		MatchDstIP(localGatewayIP).
		Action().SetDstMAC(localGatewayMAC).
		Action().ResubmitToTable(l3FwdTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// l3FwdFlowToRemote generates the L3 forward flow on source node to support traffic to remote pods/gateway.
func (c *client) l3FwdFlowToRemote(
	localGatewayMAC net.HardwareAddr,
	peerSubnet net.IPNet,
	tunnelPeer net.IP,
	tunOFPort uint32,
	category cookie.Category) binding.Flow {
	return c.pipeline[l3ForwardingTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchDstIPNet(peerSubnet).
		Action().DecTTL().
		// Rewrite src MAC to local gateway MAC and rewrite dst MAC to virtual MAC.
		Action().SetSrcMAC(localGatewayMAC).
		Action().SetDstMAC(globalVirtualMAC).
		// Load ofport of the tunnel interface.
		Action().LoadRegRange(int(portCacheReg), tunOFPort, ofPortRegRange).
		// Set MAC-known.
		Action().LoadRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
		// Flow based tunnel. Set tunnel destination.
		Action().SetTunnelDst(tunnelPeer).
		// Bypass l2ForwardingCalcTable and tables for ingress rules (which won't
		// apply to packets to remote Nodes).
		Action().ResubmitToTable(conntrackCommitTable).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// l3FwdFlowToRemoteViaGW generates the L3 forward flow on source node to support traffic to remote via gateway.
func (c *client) l3FwdFlowToRemoteViaGW(
	localGatewayMAC net.HardwareAddr,
	peerSubnet net.IPNet,
	category cookie.Category) binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	return l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchDstIPNet(peerSubnet).
		Action().DecTTL().
		Action().SetDstMAC(localGatewayMAC).
		Action().ResubmitToTable(l3FwdTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// arpResponderFlow generates the ARP responder flow entry that replies request comes from local gateway for peer
// gateway MAC.
func (c *client) arpResponderFlow(peerGatewayIP net.IP, category cookie.Category) binding.Flow {
	return c.pipeline[arpResponderTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolARP).
		MatchARPOp(1).
		MatchARPTpa(peerGatewayIP).
		Action().Move(binding.NxmFieldSrcMAC, binding.NxmFieldDstMAC).
		Action().SetSrcMAC(globalVirtualMAC).
		Action().LoadARPOperation(2).
		Action().Move(binding.NxmFieldARPSha, binding.NxmFieldARPTha).
		Action().SetARPSha(globalVirtualMAC).
		Action().Move(binding.NxmFieldARPSpa, binding.NxmFieldARPTpa).
		Action().SetARPSpa(peerGatewayIP).
		Action().OutputInPort().
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// arpResponderStaticFlow generates ARP reply for any ARP request with the same global virtual MAC.
// This flow is used in policy-only mode, where traffic are routed via IP not MAC.
func (c *client) arpResponderStaticFlow(category cookie.Category) binding.Flow {
	return c.pipeline[arpResponderTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolARP).
		MatchARPOp(1).
		Action().Move(binding.NxmFieldSrcMAC, binding.NxmFieldDstMAC).
		Action().SetSrcMAC(globalVirtualMAC).
		Action().LoadARPOperation(2).
		Action().Move(binding.NxmFieldARPSha, binding.NxmFieldARPTha).
		Action().SetARPSha(globalVirtualMAC).
		Action().Move(binding.NxmFieldARPTpa, swapReg.nxm()).
		Action().Move(binding.NxmFieldARPSpa, binding.NxmFieldARPTpa).
		Action().Move(swapReg.nxm(), binding.NxmFieldARPSpa).
		Action().OutputInPort().
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()

}

// podIPSpoofGuardFlow generates the flow to check IP traffic sent out from local pod. Traffic from host gateway interface
// will not be checked, since it might be pod to service traffic or host namespace traffic.
func (c *client) podIPSpoofGuardFlow(ifIP net.IP, ifMAC net.HardwareAddr, ifOFPort uint32, category cookie.Category) binding.Flow {
	ipPipeline := c.pipeline
	ipSpoofGuardTable := ipPipeline[spoofGuardTable]
	return ipSpoofGuardTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchInPort(ifOFPort).
		MatchSrcMAC(ifMAC).
		MatchSrcIP(ifIP).
		Action().ResubmitToTable(ipSpoofGuardTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// gatewayARPSpoofGuardFlow generates the flow to check ARP traffic sent out from the local gateway interface.
func (c *client) gatewayARPSpoofGuardFlow(gatewayOFPort uint32, gatewayIP net.IP, gatewayMAC net.HardwareAddr, category cookie.Category) binding.Flow {
	return c.pipeline[spoofGuardTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolARP).
		MatchInPort(gatewayOFPort).
		MatchARPSha(gatewayMAC).
		MatchARPSpa(gatewayIP).
		Action().ResubmitToTable(arpResponderTable).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// arpSpoofGuardFlow generates the flow to check ARP traffic sent out from local pods interfaces.
func (c *client) arpSpoofGuardFlow(ifIP net.IP, ifMAC net.HardwareAddr, ifOFPort uint32, category cookie.Category) binding.Flow {
	return c.pipeline[spoofGuardTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolARP).
		MatchInPort(ifOFPort).
		MatchARPSha(ifMAC).
		MatchARPSpa(ifIP).
		Action().ResubmitToTable(arpResponderTable).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// gatewayIPSpoofGuardFlow generates the flow to skip spoof guard checking for traffic sent from gateway interface.
func (c *client) gatewayIPSpoofGuardFlow(gatewayOFPort uint32, category cookie.Category) binding.Flow {
	ipPipeline := c.pipeline
	ipSpoofGuardTable := ipPipeline[spoofGuardTable]
	return ipSpoofGuardTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchInPort(gatewayOFPort).
		Action().ResubmitToTable(ipSpoofGuardTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// serviceCIDRDNATFlow generates flows to match dst IP in service CIDR and output to host gateway interface directly.
func (c *client) serviceCIDRDNATFlow(serviceCIDR *net.IPNet, gatewayMAC net.HardwareAddr, gatewayOFPort uint32, category cookie.Category) binding.Flow {
	return c.pipeline[dnatTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchDstIPNet(*serviceCIDR).
		Action().SetDstMAC(gatewayMAC).
		Action().LoadRegRange(int(portCacheReg), gatewayOFPort, ofPortRegRange).
		Action().LoadRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
		Action().ResubmitToTable(conntrackCommitTable).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// arpNormalFlow generates the flow to response arp in normal way if no flow in arpResponderTable is matched.
func (c *client) arpNormalFlow(category cookie.Category) binding.Flow {
	return c.pipeline[arpResponderTable].BuildFlow(priorityLow).MatchProtocol(binding.ProtocolARP).
		Action().Normal().
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// conjunctionActionFlow generates the flow to resubmit to a specific table if policyRuleConjunction ID is matched. Priority of
// conjunctionActionFlow is priorityLow.
func (c *client) conjunctionActionFlow(conjunctionID uint32, tableID binding.TableIDType, nextTable binding.TableIDType) binding.Flow {
	return c.pipeline[tableID].BuildFlow(priorityLow).MatchProtocol(binding.ProtocolIP).
		MatchConjID(conjunctionID).
		Action().ResubmitToTable(nextTable).
		Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
		Done()
}

func (c *client) Disconnect() error {
	return c.bridge.Disconnect()
}

func newFlowCategoryCache() *flowCategoryCache {
	return &flowCategoryCache{}
}

// establishedConnectionFlows generates flows to ensure established connections skip the NetworkPolicy rules.
func (c *client) establishedConnectionFlows(category cookie.Category) (flows []binding.Flow) {
	// egressDropTable checks the source address of packets, and drops packets sent from the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the established connections need not to be checked with the
	// egressRuleTable or the egressDropTable.
	egressDropTable := c.pipeline[egressDefaultTable]
	egressEstFlow := c.pipeline[egressRuleTable].BuildFlow(priorityHigh).MatchProtocol(binding.ProtocolIP).
		MatchCTStateNew(false).MatchCTStateEst(true).
		Action().ResubmitToTable(egressDropTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
	// ingressDropTable checks the destination address of packets, and drops packets sent to the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the established connections need not to be checked with the
	// ingressRuleTable or ingressDropTable.
	ingressDropTable := c.pipeline[ingressDefaultTable]
	ingressEstFlow := c.pipeline[ingressRuleTable].BuildFlow(priorityHigh).MatchProtocol(binding.ProtocolIP).
		MatchCTStateNew(false).MatchCTStateEst(true).
		Action().ResubmitToTable(ingressDropTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
	return []binding.Flow{egressEstFlow, ingressEstFlow}
}

func (c *client) addFlowMatch(fb binding.FlowBuilder, matchType int, matchValue interface{}) binding.FlowBuilder {
	switch matchType {
	case MatchDstIP:
		fb = fb.MatchProtocol(binding.ProtocolIP).MatchDstIP(matchValue.(net.IP))
	case MatchDstIPNet:
		fb = fb.MatchProtocol(binding.ProtocolIP).MatchDstIPNet(matchValue.(net.IPNet))
	case MatchSrcIP:
		fb = fb.MatchProtocol(binding.ProtocolIP).MatchSrcIP(matchValue.(net.IP))
	case MatchSrcIPNet:
		fb = fb.MatchProtocol(binding.ProtocolIP).MatchSrcIPNet(matchValue.(net.IPNet))
	case MatchDstOFPort:
		// ofport number in NXM_NX_REG1 is used in ingress rule to match packets sent to local Pod.
		fb = fb.MatchProtocol(binding.ProtocolIP).MatchReg(int(portCacheReg), uint32(matchValue.(int32)))
	case MatchSrcOFPort:
		fb = fb.MatchProtocol(binding.ProtocolIP).MatchInPort(uint32(matchValue.(int32)))
	case MatchTCPDstPort:
		fb = fb.MatchProtocol(binding.ProtocolTCP).MatchTCPDstPort(matchValue.(uint16))
	case MatchUDPDstPort:
		fb = fb.MatchProtocol(binding.ProtocolUDP).MatchUDPDstPort(matchValue.(uint16))
	case MatchSCTPDstPort:
		fb = fb.MatchProtocol(binding.ProtocolSCTP).MatchSCTPDstPort(matchValue.(uint16))
	}
	return fb
}

// conjunctionExceptionFlow generates the flow to resubmit to a specific table if both policyRuleConjunction ID and except address are matched.
// Keeping this for reference to generic exception flow.
func (c *client) conjunctionExceptionFlow(conjunctionID uint32, tableID binding.TableIDType, nextTable binding.TableIDType, matchKey int, matchValue interface{}) binding.Flow {
	fb := c.pipeline[tableID].BuildFlow(priorityNormal).MatchConjID(conjunctionID)
	return c.addFlowMatch(fb, matchKey, matchValue).
		Action().ResubmitToTable(nextTable).
		Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
		Done()
}

// conjunctiveMatchFlow generates the flow to set conjunctive actions if the match condition is matched.
func (c *client) conjunctiveMatchFlow(tableID binding.TableIDType, matchKey int, matchValue interface{}, actions ...*conjunctiveAction) binding.Flow {
	fb := c.pipeline[tableID].BuildFlow(priorityNormal)
	fb = c.addFlowMatch(fb, matchKey, matchValue)
	for _, act := range actions {
		fb.Action().Conjunction(act.conjID, act.clauseID, act.nClause)
	}
	return fb.Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).Done()
}

// defaultDropFlow generates the flow to drop packets if the match condition is matched.
func (c *client) defaultDropFlow(tableID binding.TableIDType, matchKey int, matchValue interface{}) binding.Flow {
	fb := c.pipeline[tableID].BuildFlow(priorityNormal)
	return c.addFlowMatch(fb, matchKey, matchValue).
		Action().Drop().
		Cookie(c.cookieAllocator.Request(cookie.Default).Raw()).
		Done()
}

// localProbeFlow generates the flow to resubmit packets to conntrackCommitTable. The packets are sent from Node to probe the liveness/readiness of local Pods.
func (c *client) localProbeFlow(localGatewayIP net.IP, category cookie.Category) binding.Flow {
	return c.pipeline[ingressRuleTable].BuildFlow(priorityHigh).
		MatchProtocol(binding.ProtocolIP).
		MatchSrcIP(localGatewayIP).
		Action().ResubmitToTable(conntrackCommitTable).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

func (c *client) bridgeAndUplinkFlows(uplinkOfport uint32, bridgeLocalPort int, nodeIP net.IP, localSubnet net.IPNet, category cookie.Category) []binding.Flow {
	snatIPRange := &binding.IPRange{nodeIP, nodeIP}
	vMACInt, _ := strconv.ParseUint(strings.Replace(globalVirtualMAC.String(), ":", "", -1), 16, 64)
	flows := []binding.Flow{
		// Resubmit the packet from the uplink interface to conntrackTable.
		c.pipeline[classifierTable].BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchInPort(uplinkOfport).
			Action().LoadRegRange(int(marksReg), markTrafficFromUplink, binding.Range{0, 15}).
			Action().ResubmitToTable(conntrackTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Resubmit the packet to conntrackTable if it enters the OVS pipeline from the bridge interface and is sent to
		// local Pods.
		c.pipeline[classifierTable].BuildFlow(priorityHigh).
			MatchProtocol(binding.ProtocolIP).
			MatchInPort(uint32(bridgeLocalPort)).
			MatchDstIPNet(localSubnet).
			Action().SetDstMAC(globalVirtualMAC).
			Action().ResubmitToTable(conntrackTable).
			Done(),
		// Enforce IP packet into the conntrack zone with SNAT. If the connection is SNATed, the reply packet should use
		// Pod IP as the destination, and then resubmit to conntrackStateTable.
		c.pipeline[conntrackTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Action().CT(false, conntrackStateTable, ctZone).NAT().CTDone().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Rewrite dMAC with the global vMAC if the packet is a reply to the Pod from the external address
		c.pipeline[conntrackStateTable].BuildFlow(priorityHigh).
			MatchProtocol(binding.ProtocolIP).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			MatchCTMark(snatCTMark).
			MatchRegRange(int(marksReg), markTrafficFromUplink, binding.Range{0, 15}).
			Action().LoadRange(binding.NxmFieldDstMAC, vMACInt, binding.Range{0, 47}).
			Action().ResubmitToTable(dnatTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Resubmit the packet sent from local Pod to the external IP address to dnatTable.
		c.pipeline[conntrackStateTable].BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			MatchCTMark(snatCTMark).
			Action().ResubmitToTable(dnatTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Output the non-SNAT packet to the bridge interface directly if it is received from the uplink interface.
		c.pipeline[conntrackStateTable].BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchInPort(uplinkOfport).
			Action().Output(bridgeLocalPort).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Resubmit the packet to L2ForwardingOutput table after the packet is SNATed. The "SNAT" packet has these
		// characters: 1) the ct_state is "+new+trk", 2) reg1[17] is set as 1; 3) Node IP is used as the target
		// source IP in NAT action, 4) ct_mark is set with 0x40 in the conn_track context.
		c.pipeline[conntrackCommitTable].BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchCTStateNew(true).MatchCTStateTrk(true).
			MatchRegRange(int(marksReg), snatRequiredMark, snatMarkRange).
			Action().CT(true, l2ForwardingOutTable, ctZone).
			SNAT(snatIPRange, nil).
			LoadToMark(snatCTMark).CTDone().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	}
	return flows
}

func (c *client) l3ToExternalFlows(nodeIP net.IP, localSubnet net.IPNet, outputPort int, category cookie.Category) []binding.Flow {
	flows := []binding.Flow{
		// Resubmit the packet to L2ForwardingCalc table if it is communicating to a Service.
		c.pipeline[l3ForwardingTable].BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
			MatchCTMark(gatewayCTMark).
			Action().ResubmitToTable(l2ForwardingCalcTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Resubmit the packet to L2ForwardingCalc table if it is sent to the Node IP(not to the host gateway). Since
		// the packet is using the host gateway's MAC as dst MAC, it will be sent out from "gw0". This flow entry is to
		// avoid SNAT on such packet, otherwise the source and destination IP are the same.
		c.pipeline[l3ForwardingTable].BuildFlow(priorityLow).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
			MatchDstIP(nodeIP).
			Action().ResubmitToTable(l2ForwardingCalcTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Resubmit the packet to L2ForwardingCalc table if it is a packet sent to a local Pod. This flow entry has a
		// low priority to avoid overlapping with those packets received from tunnel port.
		c.pipeline[l3ForwardingTable].BuildFlow(priorityLow).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
			MatchDstIPNet(localSubnet).
			Action().ResubmitToTable(l2ForwardingCalcTable).
			Done(),
		// Add SNAT mark on the packet that is not filtered by other flow entries in L3Forwarding table. This is the
		// table miss if SNAT feature is enabled.
		c.pipeline[l3ForwardingTable].BuildFlow(prioritySNAT).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
			Action().LoadRegRange(int(marksReg), snatRequiredMark, snatMarkRange).
			Action().ResubmitToTable(ingressRuleTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Output the SNATed packet to the specified port.
		c.pipeline[l2ForwardingOutTable].BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), snatRequiredMark, snatMarkRange).
			Action().Output(outputPort).
			Done(),
	}
	return flows
}

// NewClient is the constructor of the Client interface.
func NewClient(bridgeName, mgmtAddr string) Client {
	bridge := binding.NewOFBridge(bridgeName, mgmtAddr)
	c := &client{
		bridge: bridge,
		pipeline: map[binding.TableIDType]binding.Table{
			classifierTable:       bridge.CreateTable(classifierTable, spoofGuardTable, binding.TableMissActionDrop),
			spoofGuardTable:       bridge.CreateTable(spoofGuardTable, conntrackTable, binding.TableMissActionDrop),
			conntrackTable:        bridge.CreateTable(conntrackTable, conntrackStateTable, binding.TableMissActionNone),
			conntrackStateTable:   bridge.CreateTable(conntrackStateTable, dnatTable, binding.TableMissActionNext),
			dnatTable:             bridge.CreateTable(dnatTable, egressRuleTable, binding.TableMissActionNext),
			egressRuleTable:       bridge.CreateTable(egressRuleTable, egressDefaultTable, binding.TableMissActionNext),
			egressDefaultTable:    bridge.CreateTable(egressDefaultTable, l3ForwardingTable, binding.TableMissActionNext),
			l3ForwardingTable:     bridge.CreateTable(l3ForwardingTable, l2ForwardingCalcTable, binding.TableMissActionNext),
			l2ForwardingCalcTable: bridge.CreateTable(l2ForwardingCalcTable, ingressRuleTable, binding.TableMissActionNext),
			arpResponderTable:     bridge.CreateTable(arpResponderTable, binding.LastTableID, binding.TableMissActionDrop),
			ingressRuleTable:      bridge.CreateTable(ingressRuleTable, ingressDefaultTable, binding.TableMissActionNext),
			ingressDefaultTable:   bridge.CreateTable(ingressDefaultTable, conntrackCommitTable, binding.TableMissActionNext),
			conntrackCommitTable:  bridge.CreateTable(conntrackCommitTable, l2ForwardingOutTable, binding.TableMissActionNext),
			l2ForwardingOutTable:  bridge.CreateTable(l2ForwardingOutTable, binding.LastTableID, binding.TableMissActionDrop),
		},
		nodeFlowCache:            newFlowCategoryCache(),
		podFlowCache:             newFlowCategoryCache(),
		policyCache:              sync.Map{},
		globalConjMatchFlowCache: map[string]*conjMatchFlowContext{},
	}
	c.ofEntryOperations = c
	return c
}
