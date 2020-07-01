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
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"k8s.io/client-go/tools/cache"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow/cookie"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	"github.com/vmware-tanzu/antrea/third_party/proxy"
)

const (
	// Flow table id index
	classifierTable       binding.TableIDType = 0
	spoofGuardTable       binding.TableIDType = 10
	arpResponderTable     binding.TableIDType = 20
	serviceHairpinTable   binding.TableIDType = 29
	conntrackTable        binding.TableIDType = 30
	conntrackStateTable   binding.TableIDType = 31
	sessionAffinityTable  binding.TableIDType = 40
	dnatTable             binding.TableIDType = 40
	serviceLBTable        binding.TableIDType = 41
	endpointDNATTable     binding.TableIDType = 42
	cnpEgressRuleTable    binding.TableIDType = 45
	egressRuleTable       binding.TableIDType = 50
	egressDefaultTable    binding.TableIDType = 60
	l3ForwardingTable     binding.TableIDType = 70
	l2ForwardingCalcTable binding.TableIDType = 80
	cnpIngressRuleTable   binding.TableIDType = 85
	ingressRuleTable      binding.TableIDType = 90
	ingressDefaultTable   binding.TableIDType = 100
	conntrackCommitTable  binding.TableIDType = 105
	hairpinSNATTable      binding.TableIDType = 106
	l2ForwardingOutTable  binding.TableIDType = 110

	// Flow priority level
	priorityHigh   = uint16(210)
	priorityNormal = uint16(200)
	priorityLow    = uint16(190)
	prioritySNAT   = uint16(180)
	priorityMiss   = uint16(0)
	priorityTopCNP = uint16(64990)

	// Index for priority cache
	priorityIndex = "priority"

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
		{serviceHairpinTable, "ServiceHairpin"},
		{conntrackTable, "ConntrackZone"},
		{conntrackStateTable, "ConntrackState"},
		{dnatTable, "DNAT(SessionAffinity)"},
		{sessionAffinityTable, "SessionAffinity"},
		{serviceLBTable, "ServiceLB"},
		{endpointDNATTable, "EndpointDNAT"},
		{cnpEgressRuleTable, "CNPEgressRule"},
		{egressRuleTable, "EgressRule"},
		{egressDefaultTable, "EgressDefaultRule"},
		{l3ForwardingTable, "l3Forwarding"},
		{l2ForwardingCalcTable, "L2Forwarding"},
		{cnpIngressRuleTable, "CNPIngressRule"},
		{ingressRuleTable, "IngressRule"},
		{ingressDefaultTable, "IngressDefaultRule"},
		{conntrackCommitTable, "ConntrackCommit"},
		{hairpinSNATTable, "HairpinSNATTable"},
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
	marksReg        regType = 0
	portCacheReg    regType = 1
	swapReg         regType = 2
	endpointIPReg   regType = 3               // Use reg3 to store endpoint IP
	endpointPortReg regType = 4               // Use reg4[0..15] to store endpoint port
	serviceLearnReg         = endpointPortReg // Use reg4[16..18] to store endpoint selection states.
	// marksRegServiceNeedLB indicates a packet need to do service selection.
	marksRegServiceNeedLB uint32 = 0b001
	// marksRegServiceSelected indicates a packet has done service selection.
	marksRegServiceSelected uint32 = 0b010
	// marksRegServiceNeedLearn indicates a packet has done service selection and
	// the selection result needs to be cached.
	marksRegServiceNeedLearn uint32 = 0b011

	ctZone = 0xfff0

	portFoundMark    = 0b1
	snatRequiredMark = 0b1
	hairpinMark      = 0b1
	macRewriteMark   = 0b1

	gatewayCTMark = 0x20
	snatCTMark    = 0x40
	serviceCTMark = 0x21
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
	// hairpinMarkRange takes the 18th bit of register marksReg to indicate
	// if the packet needs DNAT to virtual IP or not. Its value is 0x1 if yes.
	hairpinMarkRange = binding.Range{18, 18}
	// macRewriteMarkRange takes the 19th bit of register marksReg to indicate
	// if the packet's MAC addresses need to be rewritten. Its value is 0x1 if yes.
	macRewriteMarkRange = binding.Range{19, 19}
	// endpointIPRegRange takes a 32-bit range of register endpointIPReg to store
	// the selected Service Endpoint IP.
	endpointIPRegRange = binding.Range{0, 31}
	// endpointPortRegRange takes a 16-bit range of register endpointPortReg to store
	// the selected Service Endpoint port.
	endpointPortRegRange = binding.Range{0, 15}
	// serviceLearnRegRange takes a 3-bit range of register serviceLearnReg to
	// indicate if the packet accessing a Service has already selected the Service
	// Endpoint, still needs to select an Endpoint, or if an Endpoint has already
	// been selected and the selection decision needs to be learned.
	serviceLearnRegRange = binding.Range{16, 18}

	globalVirtualMAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")
	ReentranceMAC, _    = net.ParseMAC("de:ad:be:ef:de:ad")
	hairpinIP           = net.ParseIP("169.254.169.252").To4()
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
	enableProxy                                   bool
	roundInfo                                     types.RoundInfo
	cookieAllocator                               cookie.Allocator
	bridge                                        binding.Bridge
	pipeline                                      map[binding.TableIDType]binding.Table
	nodeFlowCache, podFlowCache, serviceFlowCache *flowCategoryCache // cache for corresponding deletions
	// "fixed" flows installed by the agent after initialization and which do not change during
	// the lifetime of the client.
	gatewayFlows, defaultServiceFlows, defaultTunnelFlows, hostNetworkingFlows []binding.Flow
	// ofEntryOperations is a wrapper interface for OpenFlow entry Add / Modify / Delete operations. It
	// enables convenient mocking in unit tests.
	ofEntryOperations OFEntryOperations
	// policyCache is a storage that supports listing policyRuleConjunction with different indexers.
	// It's guaranteed that one policyRuleConjunction is processed by at most one goroutine at any given time.
	policyCache       cache.Indexer
	conjMatchFlowLock sync.Mutex // Lock for access globalConjMatchFlowCache
	groupCache        sync.Map
	// globalConjMatchFlowCache is a global map for conjMatchFlowContext. The key is a string generated from the
	// conjMatchFlowContext.
	globalConjMatchFlowCache map[string]*conjMatchFlowContext
	// replayMutex provides exclusive access to the OFSwitch to the ReplayFlows method.
	replayMutex sync.RWMutex
	nodeConfig  *config.NodeConfig
	encapMode   config.TrafficEncapModeType
	gatewayPort uint32 // OVSOFPort number
}

func (c *client) GetTunnelVirtualMAC() net.HardwareAddr {
	return globalVirtualMAC
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
			flowBuilder = flowBuilder.Action().GotoTable(table.GetNext())
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
		Action().LoadRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
		Action().GotoTable(conntrackTable).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// gatewayClassifierFlow generates the flow to mark traffic comes from the gatewayOFPort.
func (c *client) gatewayClassifierFlow(gatewayOFPort uint32, category cookie.Category) binding.Flow {
	classifierTable := c.pipeline[classifierTable]
	return classifierTable.BuildFlow(priorityNormal).
		MatchInPort(gatewayOFPort).
		Action().LoadRegRange(int(marksReg), markTrafficFromGateway, binding.Range{0, 15}).
		Action().GotoTable(classifierTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// podClassifierFlow generates the flow to mark traffic comes from the podOFPort.
func (c *client) podClassifierFlow(podOFPort uint32, category cookie.Category) binding.Flow {
	classifierTable := c.pipeline[classifierTable]
	return classifierTable.BuildFlow(priorityLow).
		MatchInPort(podOFPort).
		Action().LoadRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
		Action().GotoTable(classifierTable.GetNext()).
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
// 5) Let other traffic go to the sessionAffinityTable first and then the serviceLBTable.
//    The sessionAffinityTable is a side-effect table which means traffic will not
//    be resubmitted to any table. serviceLB does Endpoint selection for traffic
//    to a Service.
func (c *client) connectionTrackFlows(category cookie.Category) []binding.Flow {
	connectionTrackTable := c.pipeline[conntrackTable]
	connectionTrackStateTable := c.pipeline[conntrackStateTable]
	connectionTrackCommitTable := c.pipeline[conntrackCommitTable]
	var flows []binding.Flow
	if c.enableProxy {
		flows = append(flows,
			// Replace the default flow with multiple resubmits actions.
			connectionTrackStateTable.BuildFlow(priorityMiss).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Action().ResubmitToTable(sessionAffinityTable).
				Action().ResubmitToTable(serviceLBTable).
				Done(),
			// Enable NAT.
			connectionTrackTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
				Action().CT(false, connectionTrackTable.GetNext(), ctZone).NAT().CTDone().
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
			connectionTrackCommitTable.BuildFlow(priorityLow).MatchProtocol(binding.ProtocolIP).
				MatchCTStateTrk(true).
				MatchCTMark(serviceCTMark).
				MatchRegRange(int(serviceLearnReg), marksRegServiceSelected, serviceLearnRegRange).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Action().GotoTable(connectionTrackCommitTable.GetNext()).
				Done(),
		)
	} else {
		flows = append(flows,
			connectionTrackTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
				Action().CT(false, connectionTrackTable.GetNext(), ctZone).CTDone().
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
		)
	}
	return append(flows,
		connectionTrackStateTable.BuildFlow(priorityHigh).MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), markTrafficFromGateway, binding.Range{0, 15}).
			MatchCTMark(gatewayCTMark).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			Action().GotoTable(connectionTrackStateTable.GetNext()).
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
	)
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
		Action().GotoTable(conntrackCommitTable.GetNext()).
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
		Action().GotoTable(connectionTrackStateTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// serviceLBBypassFlow makes packets that belong to a tracked connection bypass
// service LB tables and enter egressRuleTable directly.
func (c *client) serviceLBBypassFlow() binding.Flow {
	connectionTrackStateTable := c.pipeline[conntrackStateTable]
	return connectionTrackStateTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchCTMark(serviceCTMark).
		MatchCTStateNew(false).MatchCTStateTrk(true).
		Action().LoadRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
		Action().GotoTable(egressRuleTable).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Done()
}

// l2ForwardCalcFlow generates the flow that matches dst MAC and loads ofPort to reg.
func (c *client) l2ForwardCalcFlow(dstMAC net.HardwareAddr, ofPort uint32, category cookie.Category) binding.Flow {
	l2FwdCalcTable := c.pipeline[l2ForwardingCalcTable]
	return l2FwdCalcTable.BuildFlow(priorityNormal).
		MatchDstMAC(dstMAC).
		Action().LoadRegRange(int(portCacheReg), ofPort, ofPortRegRange).
		Action().LoadRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
		Action().GotoTable(l2FwdCalcTable.GetNext()).
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

// l2ForwardOutputServiceHairpinFlow uses in_port action for Service
// hairpin packets to avoid packets from being dropped by OVS.
func (c *client) l2ForwardOutputServiceHairpinFlow() binding.Flow {
	return c.pipeline[l2ForwardingOutTable].BuildFlow(priorityHigh).MatchProtocol(binding.ProtocolIP).
		MatchRegRange(int(marksReg), hairpinMark, hairpinMarkRange).
		Action().OutputInPort().
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Done()
}

// l3BypassMACRewriteFlow bypasses remaining l3forwarding flows if the MAC is set via ctRewriteDstMACFlow in
// conntrackState stage.
func (c *client) l3BypassMACRewriteFlow(gatewayMAC net.HardwareAddr, category cookie.Category) binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	return l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchCTMark(gatewayCTMark).
		MatchDstMAC(gatewayMAC).
		Action().GotoTable(l3FwdTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// l3FlowsToPod generates the flow to rewrite MAC if the packet is received from tunnel port and destined for local Pods.
func (c *client) l3FlowsToPod(localGatewayMAC net.HardwareAddr, podInterfaceIP net.IP, podInterfaceMAC net.HardwareAddr, category cookie.Category) binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	flowBuilder := l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP)
	if c.enableProxy {
		flowBuilder = flowBuilder.MatchRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange)
	} else {
		flowBuilder = flowBuilder.MatchDstMAC(globalVirtualMAC)
	}
	// Rewrite src MAC to local gateway MAC, and rewrite dst MAC to pod MAC
	return flowBuilder.
		MatchDstIP(podInterfaceIP).
		Action().SetSrcMAC(localGatewayMAC).
		Action().SetDstMAC(podInterfaceMAC).
		Action().DecTTL().
		Action().GotoTable(l3FwdTable.GetNext()).
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
		Action().GotoTable(l3FwdTable.GetNext()).
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
		Action().GotoTable(l3FwdTable.GetNext()).
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
		Action().GotoTable(l3FwdTable.GetNext()).
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
		Action().GotoTable(conntrackCommitTable).
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
		Action().GotoTable(l3FwdTable.GetNext()).
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
		Action().GotoTable(ipSpoofGuardTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// serviceHairpinResponseDNATFlow generates the flow which transforms destination
// IP of the hairpin packet to the source IP.
func (c *client) serviceHairpinResponseDNATFlow() binding.Flow {
	return c.pipeline[serviceHairpinTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchDstIP(hairpinIP).
		Action().Move("NXM_OF_IP_SRC", "NXM_OF_IP_DST").
		Action().LoadRegRange(int(marksReg), hairpinMark, hairpinMarkRange).
		Action().GotoTable(conntrackTable).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Done()
}

// gatewayARPSpoofGuardFlow generates the flow to check ARP traffic sent out from the local gateway interface.
func (c *client) gatewayARPSpoofGuardFlow(gatewayOFPort uint32, gatewayIP net.IP, gatewayMAC net.HardwareAddr, category cookie.Category) binding.Flow {
	return c.pipeline[spoofGuardTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolARP).
		MatchInPort(gatewayOFPort).
		MatchARPSha(gatewayMAC).
		MatchARPSpa(gatewayIP).
		Action().GotoTable(arpResponderTable).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// arpSpoofGuardFlow generates the flow to check ARP traffic sent out from local pods interfaces.
func (c *client) arpSpoofGuardFlow(ifIP net.IP, ifMAC net.HardwareAddr, ifOFPort uint32, category cookie.Category) binding.Flow {
	return c.pipeline[spoofGuardTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolARP).
		MatchInPort(ifOFPort).
		MatchARPSha(ifMAC).
		MatchARPSpa(ifIP).
		Action().GotoTable(arpResponderTable).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// gatewayIPSpoofGuardFlow generates the flow to skip spoof guard checking for traffic sent from gateway interface.
func (c *client) gatewayIPSpoofGuardFlow(gatewayOFPort uint32, category cookie.Category) binding.Flow {
	ipPipeline := c.pipeline
	ipSpoofGuardTable := ipPipeline[spoofGuardTable]
	return ipSpoofGuardTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchInPort(gatewayOFPort).
		Action().GotoTable(ipSpoofGuardTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// sessionAffinityReselectFlow generates the flow which resubmits the service accessing
// packet back to serviceLBTable if there is no endpointDNAT flow matched. This
// case will occur if an Endpoint is removed and is the learned Endpoint
// selection of the Service.
func (c *client) sessionAffinityReselectFlow() binding.Flow {
	return c.pipeline[endpointDNATTable].BuildFlow(priorityLow).
		MatchRegRange(int(serviceLearnReg), marksRegServiceSelected, serviceLearnRegRange).
		Action().LoadRegRange(int(serviceLearnReg), marksRegServiceNeedLB, serviceLearnRegRange).
		Action().ResubmitToTable(serviceLBTable).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Done()
}

// serviceCIDRDNATFlow generates flows to match dst IP in service CIDR and output to host gateway interface directly.
func (c *client) serviceCIDRDNATFlow(serviceCIDR *net.IPNet, gatewayMAC net.HardwareAddr, gatewayOFPort uint32) binding.Flow {
	return c.pipeline[dnatTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchDstIPNet(*serviceCIDR).
		Action().SetDstMAC(gatewayMAC).
		Action().LoadRegRange(int(portCacheReg), gatewayOFPort, ofPortRegRange).
		Action().LoadRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
		Action().GotoTable(conntrackCommitTable).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Done()
}

// serviceNeedLBFlow generates flows to mark packets as LB needed.
func (c *client) serviceNeedLBFlow() binding.Flow {
	return c.pipeline[sessionAffinityTable].BuildFlow(priorityMiss).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Action().LoadRegRange(int(serviceLearnReg), marksRegServiceNeedLB, serviceLearnRegRange).
		Done()
}

// arpNormalFlow generates the flow to response arp in normal way if no flow in arpResponderTable is matched.
func (c *client) arpNormalFlow(category cookie.Category) binding.Flow {
	return c.pipeline[arpResponderTable].BuildFlow(priorityLow).MatchProtocol(binding.ProtocolARP).
		Action().Normal().
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// conjunctionActionFlow generates the flow to jump to a specific table if policyRuleConjunction ID is matched. Priority of
// conjunctionActionFlow is created at priorityLow for k8s network policies, and *priority assigned by PriorityAssigner for CNP.
func (c *client) conjunctionActionFlow(conjunctionID uint32, tableID binding.TableIDType, nextTable binding.TableIDType, priority *uint16) binding.Flow {
	var ofPriority uint16
	if priority == nil {
		ofPriority = priorityLow
	} else {
		ofPriority = *priority
	}
	return c.pipeline[tableID].BuildFlow(ofPriority).MatchProtocol(binding.ProtocolIP).
		MatchConjID(conjunctionID).
		MatchPriority(ofPriority).
		Action().GotoTable(nextTable).
		Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
		Done()
}

// conjunctionActionFlow generates the flow to drop traffic if policyRuleConjunction ID is matched.
func (c *client) conjunctionActionDropFlow(conjunctionID uint32, tableID binding.TableIDType, priority *uint16) binding.Flow {
	ofPriority := *priority
	return c.pipeline[tableID].BuildFlow(ofPriority).MatchProtocol(binding.ProtocolIP).
		MatchConjID(conjunctionID).
		MatchPriority(ofPriority).
		Action().Drop().
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
		Action().GotoTable(egressDropTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
	cnpEgressEstFlow := c.pipeline[cnpEgressRuleTable].BuildFlow(priorityTopCNP).MatchProtocol(binding.ProtocolIP).
		MatchCTStateNew(false).MatchCTStateEst(true).
		Action().GotoTable(egressDropTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
	// ingressDropTable checks the destination address of packets, and drops packets sent to the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the established connections need not to be checked with the
	// ingressRuleTable or ingressDropTable.
	ingressDropTable := c.pipeline[ingressDefaultTable]
	ingressEstFlow := c.pipeline[ingressRuleTable].BuildFlow(priorityHigh).MatchProtocol(binding.ProtocolIP).
		MatchCTStateNew(false).MatchCTStateEst(true).
		Action().GotoTable(ingressDropTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
	cnpIngressEstFlow := c.pipeline[cnpIngressRuleTable].BuildFlow(priorityTopCNP).MatchProtocol(binding.ProtocolIP).
		MatchCTStateNew(false).MatchCTStateEst(true).
		Action().GotoTable(ingressDropTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
	return []binding.Flow{egressEstFlow, ingressEstFlow, cnpEgressEstFlow, cnpIngressEstFlow}
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
		fb = fb.MatchProtocol(binding.ProtocolTCP)
		portValue := matchValue.(uint16)
		if portValue > 0 {
			fb = fb.MatchTCPDstPort(portValue)
		}
	case MatchUDPDstPort:
		fb = fb.MatchProtocol(binding.ProtocolUDP)
		portValue := matchValue.(uint16)
		if portValue > 0 {
			fb = fb.MatchUDPDstPort(portValue)
		}
	case MatchSCTPDstPort:
		fb = fb.MatchProtocol(binding.ProtocolSCTP)
		portValue := matchValue.(uint16)
		if portValue > 0 {
			fb = fb.MatchSCTPDstPort(portValue)
		}
	}
	return fb
}

// conjunctionExceptionFlow generates the flow to jump to a specific table if both policyRuleConjunction ID and except address are matched.
// Keeping this for reference to generic exception flow.
func (c *client) conjunctionExceptionFlow(conjunctionID uint32, tableID binding.TableIDType, nextTable binding.TableIDType, matchKey int, matchValue interface{}) binding.Flow {
	fb := c.pipeline[tableID].BuildFlow(priorityNormal).MatchConjID(conjunctionID)
	return c.addFlowMatch(fb, matchKey, matchValue).
		Action().GotoTable(nextTable).
		Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
		Done()
}

// conjunctiveMatchFlow generates the flow to set conjunctive actions if the match condition is matched.
func (c *client) conjunctiveMatchFlow(tableID binding.TableIDType, matchKey int, matchValue interface{}, priority *uint16, actions ...*conjunctiveAction) binding.Flow {
	var ofPriority uint16
	if priority != nil {
		ofPriority = *priority
	} else {
		ofPriority = priorityNormal
	}
	fb := c.pipeline[tableID].BuildFlow(ofPriority)
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

// localProbeFlow generates the flow to forward packets to conntrackCommitTable. The packets are sent from Node to probe the liveness/readiness of local Pods.
func (c *client) localProbeFlow(localGatewayIP net.IP, category cookie.Category) binding.Flow {
	return c.pipeline[ingressRuleTable].BuildFlow(priorityHigh).
		MatchProtocol(binding.ProtocolIP).
		MatchSrcIP(localGatewayIP).
		Action().GotoTable(conntrackCommitTable).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

func (c *client) bridgeAndUplinkFlows(uplinkOfport uint32, bridgeLocalPort uint32, nodeIP net.IP, localSubnet net.IPNet, category cookie.Category) []binding.Flow {
	snatIPRange := &binding.IPRange{nodeIP, nodeIP}
	vMACInt, _ := strconv.ParseUint(strings.Replace(globalVirtualMAC.String(), ":", "", -1), 16, 64)
	ctStateNext := dnatTable
	if c.enableProxy {
		ctStateNext = endpointDNATTable
	}
	flows := []binding.Flow{
		// Forward the packet to conntrackTable if it enters the OVS pipeline from the uplink interface.
		c.pipeline[classifierTable].BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchInPort(uplinkOfport).
			Action().LoadRegRange(int(marksReg), markTrafficFromUplink, binding.Range{0, 15}).
			Action().GotoTable(conntrackTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Forward the packet to conntrackTable if it enters the OVS pipeline from the bridge interface and is sent to
		// local Pods.
		c.pipeline[classifierTable].BuildFlow(priorityHigh).
			MatchProtocol(binding.ProtocolIP).
			MatchInPort(bridgeLocalPort).
			MatchDstIPNet(localSubnet).
			Action().SetDstMAC(globalVirtualMAC).
			Action().GotoTable(conntrackTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Enforce IP packet into the conntrack zone with SNAT. If the connection is SNATed, the reply packet should use
		// Pod IP as the destination, and then is forwarded to conntrackStateTable.
		c.pipeline[conntrackTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Action().CT(false, conntrackStateTable, ctZone).NAT().CTDone().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Rewrite dMAC with the global vMAC if the packet is a reply to the Pod from the external address.
		c.pipeline[conntrackStateTable].BuildFlow(priorityHigh).
			MatchProtocol(binding.ProtocolIP).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			MatchCTMark(snatCTMark).
			MatchRegRange(int(marksReg), markTrafficFromUplink, binding.Range{0, 15}).
			Action().LoadRange(binding.NxmFieldDstMAC, vMACInt, binding.Range{0, 47}).
			Action().LoadRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
			Action().GotoTable(ctStateNext).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Forward the packet to dnatTable if it is sent from local Pod to the external IP address.
		c.pipeline[conntrackStateTable].BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			MatchCTMark(snatCTMark).
			Action().GotoTable(ctStateNext).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Output the non-SNAT packet to the bridge interface directly if it is received from the uplink interface.
		c.pipeline[conntrackStateTable].BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchInPort(uplinkOfport).
			Action().Output(int(bridgeLocalPort)).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Enforce the packet into L2ForwardingOutput table after the packet is SNATed. The "SNAT" packet has these
		// characteristics: 1) the ct_state is "+new+trk", 2) reg0[17] is set to 1; 3) Node IP is used as the target
		// source IP in NAT action, 4) ct_mark is set to 0x40 in the conn_track context.
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
		// Forward the packet to L2ForwardingCalc table if it is communicating to a Service.
		c.pipeline[l3ForwardingTable].BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
			MatchCTMark(gatewayCTMark).
			Action().GotoTable(l2ForwardingCalcTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Forward the packet to L2ForwardingCalc table if it is sent to the Node IP(not to the host gateway). Since
		// the packet is using the host gateway's MAC as dst MAC, it will be sent out from "gw0". This flow entry is to
		// avoid SNAT on such packet, otherwise the source and destination IP are the same.
		c.pipeline[l3ForwardingTable].BuildFlow(priorityLow).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
			MatchDstIP(nodeIP).
			Action().GotoTable(l2ForwardingCalcTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Forward the packet to L2ForwardingCalc table if it is a packet sent to a local Pod. This flow entry has a
		// low priority to avoid overlapping with those packets received from tunnel port.
		c.pipeline[l3ForwardingTable].BuildFlow(priorityLow).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
			MatchDstIPNet(localSubnet).
			Action().GotoTable(c.pipeline[l3ForwardingTable].GetNext()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Add SNAT mark on the packet that is not filtered by other flow entries in L3Forwarding table. This is the
		// table miss if SNAT feature is enabled.
		c.pipeline[l3ForwardingTable].BuildFlow(prioritySNAT).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
			Action().LoadRegRange(int(marksReg), snatRequiredMark, snatMarkRange).
			Action().GotoTable(ingressRuleTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Output the SNATed packet to the specified port.
		c.pipeline[l2ForwardingOutTable].BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), snatRequiredMark, snatMarkRange).
			Action().Output(outputPort).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	}
	return flows
}

// serviceLearnFlow generates the flow with learn action which adds new flows in
// sessionAffinityTable according to the Endpoint selection decision.
func (c *client) serviceLearnFlow(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol, affinityTimeout uint16) binding.Flow {
	// Using unique cookie ID here to avoid learned flow cascade deletion.
	cookieID := c.cookieAllocator.RequestWithObjectID(cookie.Service, uint32(groupID)).Raw()
	learnFlowBuilder := c.pipeline[serviceLBTable].BuildFlow(priorityLow).
		MatchRegRange(int(serviceLearnReg), marksRegServiceNeedLearn, serviceLearnRegRange).
		MatchDstIP(svcIP).
		Cookie(cookieID)
	learnFlowBuilderLearnAction := learnFlowBuilder.
		Action().Learn(sessionAffinityTable, priorityNormal, affinityTimeout, 0, cookieID).
		DeleteLearned()
	if protocol == binding.ProtocolTCP {
		learnFlowBuilder = learnFlowBuilder.MatchTCPDstPort(svcPort)
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedTCPDstPort()
	} else if protocol == binding.ProtocolUDP {
		learnFlowBuilder = learnFlowBuilder.MatchUDPDstPort(svcPort)
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedUDPDstPort()
	} else if protocol == binding.ProtocolSCTP {
		learnFlowBuilder = learnFlowBuilder.MatchSCTPDstPort(svcPort)
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedSCTPDstPort()
	}
	return learnFlowBuilderLearnAction.
		MatchLearnedDstIP().
		MatchLearnedSrcIP().
		LoadRegToReg(int(endpointIPReg), int(endpointIPReg), endpointIPRegRange, endpointIPRegRange).
		LoadRegToReg(int(endpointPortReg), int(endpointPortReg), endpointPortRegRange, endpointPortRegRange).
		LoadReg(int(serviceLearnReg), marksRegServiceSelected, serviceLearnRegRange).
		LoadReg(int(marksReg), macRewriteMark, macRewriteMarkRange).
		Done().
		Action().LoadRegRange(int(serviceLearnReg), marksRegServiceSelected, serviceLearnRegRange).
		Action().GotoTable(endpointDNATTable).
		Done()
}

// serviceLBFlow generates the flow which uses the specific group to do Endpoint
// selection.
func (c *client) serviceLBFlow(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol) binding.Flow {
	lbFlowBuilder := c.pipeline[serviceLBTable].BuildFlow(priorityNormal)
	if protocol == binding.ProtocolTCP {
		lbFlowBuilder = lbFlowBuilder.MatchTCPDstPort(svcPort)
	} else if protocol == binding.ProtocolUDP {
		lbFlowBuilder = lbFlowBuilder.MatchUDPDstPort(svcPort)
	} else if protocol == binding.ProtocolSCTP {
		lbFlowBuilder = lbFlowBuilder.MatchSCTPDstPort(svcPort)
	}
	lbFlow := lbFlowBuilder.
		MatchDstIP(svcIP).
		MatchRegRange(int(serviceLearnReg), marksRegServiceNeedLB, serviceLearnRegRange).
		Action().Group(groupID).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Done()
	return lbFlow
}

// endpointDNATFlow generates the flow which transforms the Service Cluster IP
// to the Endpoint IP according to the Endpoint selection decision which is stored
// in regs.
func (c *client) endpointDNATFlow(endpointIP net.IP, endpointPort uint16, protocol binding.Protocol) binding.Flow {
	ipVal := binary.BigEndian.Uint32(endpointIP)
	unionVal := (marksRegServiceSelected << endpointPortRegRange.Length()) + uint32(endpointPort)
	return c.pipeline[endpointDNATTable].BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		MatchProtocol(protocol).
		MatchReg(int(endpointIPReg), ipVal).
		MatchRegRange(int(endpointPortReg), unionVal, binding.Range{0, 18}).
		Action().CT(true, egressRuleTable, ctZone).
		DNAT(
			&binding.IPRange{StartIP: endpointIP, EndIP: endpointIP},
			&binding.PortRange{StartPort: endpointPort, EndPort: endpointPort},
		).
		LoadToMark(serviceCTMark).
		CTDone().
		Done()
}

// hairpinSNATFlow generates the flow which does SNAT for Service
// hairpin packets and loads the hairpin mark to markReg.
func (c *client) hairpinSNATFlow(endpointIP net.IP) binding.Flow {
	return c.pipeline[hairpinSNATTable].BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		MatchProtocol(binding.ProtocolIP).
		MatchDstIP(endpointIP).
		MatchSrcIP(endpointIP).
		Action().SetSrcIP(hairpinIP).
		Action().LoadRegRange(int(marksReg), hairpinMark, hairpinMarkRange).
		Action().GotoTable(l2ForwardingOutTable).
		Done()
}

// serviceEndpointGroup creates/modifies the group/buckets of Endpoints. If the
// withSessionAffinity is true, then buckets will resubmit packets back to
// serviceLBTable to trigger the learn flow, the learn flow will then send packets
// to endpointDNATTable. Otherwise, buckets will resubmit packets to
// endpointDNATTable directly.
func (c *client) serviceEndpointGroup(groupID binding.GroupIDType, withSessionAffinity bool, endpoints ...proxy.Endpoint) binding.Group {
	group := c.bridge.CreateGroup(groupID).ResetBuckets()
	var resubmitTableID binding.TableIDType
	var lbResultMark uint32
	if withSessionAffinity {
		resubmitTableID = serviceLBTable
		lbResultMark = marksRegServiceNeedLearn
	} else {
		resubmitTableID = endpointDNATTable
		lbResultMark = marksRegServiceSelected
	}

	for _, endpoint := range endpoints {
		endpointPort, _ := endpoint.Port()
		endpointIP := net.ParseIP(endpoint.IP()).To4()
		ipVal := binary.BigEndian.Uint32(endpointIP)
		portVal := uint16(endpointPort)
		group = group.Bucket().Weight(100).
			LoadReg(int(endpointIPReg), ipVal).
			LoadRegRange(int(endpointPortReg), uint32(portVal), endpointPortRegRange).
			LoadRegRange(int(serviceLearnReg), lbResultMark, serviceLearnRegRange).
			LoadRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
			ResubmitToTable(resubmitTableID).
			Done()
	}
	return group
}

// policyConjKeyFuncKeyFunc knows how to get key of a *policyRuleConjunction.
func policyConjKeyFunc(obj interface{}) (string, error) {
	conj := obj.(*policyRuleConjunction)
	return string(conj.id), nil
}

// priorityIndexFunc knows how to get priority of actionFlows in a *policyRuleConjunction.
// It's provided to cache.Indexer to build an index of policyRuleConjunction.
func priorityIndexFunc(obj interface{}) ([]string, error) {
	conj := obj.(*policyRuleConjunction)
	return conj.ActionFlowPriorities(), nil
}

func generatePipeline(bridge binding.Bridge, enableProxy bool) map[binding.TableIDType]binding.Table {
	if enableProxy {
		return map[binding.TableIDType]binding.Table{
			classifierTable:       bridge.CreateTable(classifierTable, spoofGuardTable, binding.TableMissActionDrop),
			spoofGuardTable:       bridge.CreateTable(spoofGuardTable, serviceHairpinTable, binding.TableMissActionDrop),
			arpResponderTable:     bridge.CreateTable(arpResponderTable, binding.LastTableID, binding.TableMissActionDrop),
			serviceHairpinTable:   bridge.CreateTable(serviceHairpinTable, conntrackTable, binding.TableMissActionNext),
			conntrackTable:        bridge.CreateTable(conntrackTable, conntrackStateTable, binding.TableMissActionNone),
			conntrackStateTable:   bridge.CreateTable(conntrackStateTable, endpointDNATTable, binding.TableMissActionNext),
			sessionAffinityTable:  bridge.CreateTable(sessionAffinityTable, binding.LastTableID, binding.TableMissActionNone),
			serviceLBTable:        bridge.CreateTable(serviceLBTable, endpointDNATTable, binding.TableMissActionNext),
			endpointDNATTable:     bridge.CreateTable(endpointDNATTable, cnpEgressRuleTable, binding.TableMissActionNext),
			cnpEgressRuleTable:    bridge.CreateTable(cnpEgressRuleTable, egressRuleTable, binding.TableMissActionNext),
			egressRuleTable:       bridge.CreateTable(egressRuleTable, egressDefaultTable, binding.TableMissActionNext),
			egressDefaultTable:    bridge.CreateTable(egressDefaultTable, l3ForwardingTable, binding.TableMissActionNext),
			l3ForwardingTable:     bridge.CreateTable(l3ForwardingTable, l2ForwardingCalcTable, binding.TableMissActionNext),
			l2ForwardingCalcTable: bridge.CreateTable(l2ForwardingCalcTable, cnpIngressRuleTable, binding.TableMissActionNext),
			cnpIngressRuleTable:   bridge.CreateTable(cnpIngressRuleTable, ingressRuleTable, binding.TableMissActionNext),
			ingressRuleTable:      bridge.CreateTable(ingressRuleTable, ingressDefaultTable, binding.TableMissActionNext),
			ingressDefaultTable:   bridge.CreateTable(ingressDefaultTable, conntrackCommitTable, binding.TableMissActionNext),
			conntrackCommitTable:  bridge.CreateTable(conntrackCommitTable, hairpinSNATTable, binding.TableMissActionNext),
			hairpinSNATTable:      bridge.CreateTable(hairpinSNATTable, l2ForwardingOutTable, binding.TableMissActionNext),
			l2ForwardingOutTable:  bridge.CreateTable(l2ForwardingOutTable, binding.LastTableID, binding.TableMissActionDrop),
		}
	}
	return map[binding.TableIDType]binding.Table{
		classifierTable:       bridge.CreateTable(classifierTable, spoofGuardTable, binding.TableMissActionDrop),
		spoofGuardTable:       bridge.CreateTable(spoofGuardTable, conntrackTable, binding.TableMissActionDrop),
		arpResponderTable:     bridge.CreateTable(arpResponderTable, binding.LastTableID, binding.TableMissActionDrop),
		conntrackTable:        bridge.CreateTable(conntrackTable, conntrackStateTable, binding.TableMissActionNone),
		conntrackStateTable:   bridge.CreateTable(conntrackStateTable, dnatTable, binding.TableMissActionNext),
		dnatTable:             bridge.CreateTable(dnatTable, cnpEgressRuleTable, binding.TableMissActionNext),
		cnpEgressRuleTable:    bridge.CreateTable(cnpEgressRuleTable, egressRuleTable, binding.TableMissActionNext),
		egressRuleTable:       bridge.CreateTable(egressRuleTable, egressDefaultTable, binding.TableMissActionNext),
		egressDefaultTable:    bridge.CreateTable(egressDefaultTable, l3ForwardingTable, binding.TableMissActionNext),
		l3ForwardingTable:     bridge.CreateTable(l3ForwardingTable, l2ForwardingCalcTable, binding.TableMissActionNext),
		l2ForwardingCalcTable: bridge.CreateTable(l2ForwardingCalcTable, cnpIngressRuleTable, binding.TableMissActionNext),
		cnpIngressRuleTable:   bridge.CreateTable(cnpIngressRuleTable, ingressRuleTable, binding.TableMissActionNext),
		ingressRuleTable:      bridge.CreateTable(ingressRuleTable, ingressDefaultTable, binding.TableMissActionNext),
		ingressDefaultTable:   bridge.CreateTable(ingressDefaultTable, conntrackCommitTable, binding.TableMissActionNext),
		conntrackCommitTable:  bridge.CreateTable(conntrackCommitTable, l2ForwardingOutTable, binding.TableMissActionNext),
		l2ForwardingOutTable:  bridge.CreateTable(l2ForwardingOutTable, binding.LastTableID, binding.TableMissActionDrop),
	}
}

// NewClient is the constructor of the Client interface.
func NewClient(bridgeName, mgmtAddr string, enableProxy bool) Client {
	bridge := binding.NewOFBridge(bridgeName, mgmtAddr)
	policyCache := cache.NewIndexer(
		policyConjKeyFunc,
		cache.Indexers{priorityIndex: priorityIndexFunc},
	)
	c := &client{
		bridge:                   bridge,
		pipeline:                 generatePipeline(bridge, enableProxy),
		nodeFlowCache:            newFlowCategoryCache(),
		podFlowCache:             newFlowCategoryCache(),
		serviceFlowCache:         newFlowCategoryCache(),
		policyCache:              policyCache,
		groupCache:               sync.Map{},
		globalConjMatchFlowCache: map[string]*conjMatchFlowContext{},
	}
	c.ofEntryOperations = c
	c.enableProxy = enableProxy
	return c
}
