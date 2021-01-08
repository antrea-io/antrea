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
	"time"

	"k8s.io/client-go/tools/cache"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/metrics"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow/cookie"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
	"github.com/vmware-tanzu/antrea/third_party/proxy"
)

const (
	// Flow table id index
	ClassifierTable              binding.TableIDType = 0
	uplinkTable                  binding.TableIDType = 5
	spoofGuardTable              binding.TableIDType = 10
	arpResponderTable            binding.TableIDType = 20
	ipv6Table                    binding.TableIDType = 21
	serviceHairpinTable          binding.TableIDType = 29
	conntrackTable               binding.TableIDType = 30
	conntrackStateTable          binding.TableIDType = 31
	sessionAffinityTable         binding.TableIDType = 40
	dnatTable                    binding.TableIDType = 40
	serviceLBTable               binding.TableIDType = 41
	endpointDNATTable            binding.TableIDType = 42
	AntreaPolicyEgressRuleTable  binding.TableIDType = 45
	DefaultTierEgressRuleTable   binding.TableIDType = 49
	EgressRuleTable              binding.TableIDType = 50
	EgressDefaultTable           binding.TableIDType = 60
	EgressMetricTable            binding.TableIDType = 61
	l3ForwardingTable            binding.TableIDType = 70
	l2ForwardingCalcTable        binding.TableIDType = 80
	AntreaPolicyIngressRuleTable binding.TableIDType = 85
	DefaultTierIngressRuleTable  binding.TableIDType = 89
	IngressRuleTable             binding.TableIDType = 90
	IngressDefaultTable          binding.TableIDType = 100
	IngressMetricTable           binding.TableIDType = 101
	conntrackCommitTable         binding.TableIDType = 105
	hairpinSNATTable             binding.TableIDType = 106
	L2ForwardingOutTable         binding.TableIDType = 110

	// Flow priority level
	priorityHigh            = uint16(210)
	priorityNormal          = uint16(200)
	priorityLow             = uint16(190)
	prioritySNAT            = uint16(180)
	priorityMiss            = uint16(0)
	priorityTopAntreaPolicy = uint16(64990)

	// Index for priority cache
	priorityIndex = "priority"

	// Traffic marks
	markTrafficFromTunnel  = 0
	markTrafficFromGateway = 1
	markTrafficFromLocal   = 2
	markTrafficFromUplink  = 4

	// IPv6 multicast prefix
	ipv6MulticastAddr = "FF00::/8"
	// IPv6 link-local prefix
	ipv6LinkLocalAddr = "FE80::/10"
)

var (
	// egressTables map records all IDs of tables related to
	// egress rules.
	egressTables = map[binding.TableIDType]struct{}{
		AntreaPolicyEgressRuleTable: {},
		EgressRuleTable:             {},
		EgressDefaultTable:          {},
	}

	FlowTables = []struct {
		Number binding.TableIDType
		Name   string
	}{
		{ClassifierTable, "Classification"},
		{uplinkTable, "Uplink"},
		{spoofGuardTable, "SpoofGuard"},
		{arpResponderTable, "ARPResponder"},
		{ipv6Table, "IPv6"},
		{serviceHairpinTable, "ServiceHairpin"},
		{conntrackTable, "ConntrackZone"},
		{conntrackStateTable, "ConntrackState"},
		{dnatTable, "DNAT(SessionAffinity)"},
		{sessionAffinityTable, "SessionAffinity"},
		{serviceLBTable, "ServiceLB"},
		{endpointDNATTable, "EndpointDNAT"},
		{AntreaPolicyEgressRuleTable, "AntreaPolicyEgressRule"},
		{EgressRuleTable, "EgressRule"},
		{EgressDefaultTable, "EgressDefaultRule"},
		{EgressMetricTable, "EgressMetric"},
		{l3ForwardingTable, "l3Forwarding"},
		{l2ForwardingCalcTable, "L2Forwarding"},
		{AntreaPolicyIngressRuleTable, "AntreaPolicyIngressRule"},
		{IngressRuleTable, "IngressRule"},
		{IngressDefaultTable, "IngressDefaultRule"},
		{IngressMetricTable, "IngressMetric"},
		{conntrackCommitTable, "ConntrackCommit"},
		{hairpinSNATTable, "HairpinSNATTable"},
		{L2ForwardingOutTable, "Output"},
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

func GetAntreaPolicyEgressTables() []binding.TableIDType {
	return []binding.TableIDType{
		AntreaPolicyEgressRuleTable,
		EgressDefaultTable,
	}
}

func GetAntreaPolicyIngressTables() []binding.TableIDType {
	return []binding.TableIDType{
		AntreaPolicyIngressRuleTable,
		IngressDefaultTable,
	}
}

func GetAntreaPolicyBaselineTierTables() []binding.TableIDType {
	return []binding.TableIDType{
		EgressDefaultTable,
		IngressDefaultTable,
	}
}

func GetAntreaPolicyMultiTierTables() []binding.TableIDType {
	return []binding.TableIDType{
		AntreaPolicyEgressRuleTable,
		AntreaPolicyIngressRuleTable,
	}
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
	// traffic-source resides in [0..15], pod-found resides in [16], Antrea Policy disposition Allow or Drop in [21]
	marksReg        regType = 0
	PortCacheReg    regType = 1
	swapReg         regType = 2
	endpointIPReg   regType = 3               // Use reg3 to store endpoint IP
	endpointPortReg regType = 4               // Use reg4[0..15] to store endpoint port
	serviceLearnReg         = endpointPortReg // Use reg4[16..18] to store endpoint selection states.
	EgressReg       regType = 5
	IngressReg      regType = 6
	TraceflowReg    regType = 9 // Use reg9[28..31] to store traceflow dataplaneTag.
	// CNPDropConjunctionIDReg reuses reg3 which will also be used for storing endpoint IP to store the rule ID. Since
	// the service selection will finish when a packet hitting NetworkPolicy related rules, there is no conflict.
	CNPDropConjunctionIDReg regType = 3
	endpointIPv6XXReg       regType = 3 // xxReg3 will occupy reg12-reg15
	// marksRegServiceNeedLB indicates a packet need to do service selection.
	marksRegServiceNeedLB uint32 = 0b001
	// marksRegServiceSelected indicates a packet has done service selection.
	marksRegServiceSelected uint32 = 0b010
	// marksRegServiceNeedLearn indicates a packet has done service selection and
	// the selection result needs to be cached.
	marksRegServiceNeedLearn uint32 = 0b011

	CtZone   = 0xfff0
	CtZoneV6 = 0xffe6

	portFoundMark    = 0b1
	snatRequiredMark = 0b1
	hairpinMark      = 0b1
	macRewriteMark   = 0b1
	cnpDropMark      = 0b1

	// gatewayCTMark is used to to mark connections initiated through the host gateway interface
	// (i.e. for which the first packet of the connection was received through the gateway).
	gatewayCTMark = 0x20
	snatCTMark    = 0x40
	ServiceCTMark = 0x21

	// disposition is loaded in marksReg [21]
	DispositionMarkReg regType = 0
	// disposition marks the flow action as either Allow or Drop
	DispositionAllow = 0b0
	DispositionDrop  = 0b1
)

var DispositionToString = map[uint32]string{
	DispositionAllow: "Allow",
	DispositionDrop:  "Drop",
}

var (
	// APDispositionMarkRange takes the 21 to 21 bits of register marksReg to indicate disposition of Antrea Policy.
	APDispositionMarkRange = binding.Range{21, 21}
	// ofPortMarkRange takes the 16th bit of register marksReg to indicate if the ofPort number of an interface
	// is found or not. Its value is 0x1 if yes.
	ofPortMarkRange = binding.Range{16, 16}
	// ofPortRegRange takes a 32-bit range of register PortCacheReg to cache the ofPort number of the interface.
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
	cnpDropMarkRange    = binding.Range{20, 20}
	// endpointIPRegRange takes a 32-bit range of register endpointIPReg to store
	// the selected Service Endpoint IP.
	endpointIPRegRange = binding.Range{0, 31}
	// the selected Service Endpoint IPv6.
	endpointIPv6XXRegRange = binding.Range{0, 127}
	// endpointPortRegRange takes a 16-bit range of register endpointPortReg to store
	// the selected Service Endpoint port.
	endpointPortRegRange = binding.Range{0, 15}
	// serviceLearnRegRange takes a 3-bit range of register serviceLearnReg to
	// indicate if the packet accessing a Service has already selected the Service
	// Endpoint, still needs to select an Endpoint, or if an Endpoint has already
	// been selected and the selection decision needs to be learned.
	serviceLearnRegRange = binding.Range{16, 18}
	// metricIngressRuleIDRange takes 0..31 range of ct_label to store the ingress rule ID.
	metricIngressRuleIDRange = binding.Range{0, 31}
	// metricEgressRuleIDRange takes 32..63 range of ct_label to store the egress rule ID.
	metricEgressRuleIDRange = binding.Range{32, 63}

	// traceflowTagToSRange stores dataplaneTag at range 2-7 in ToS field of IP header.
	// IPv4/v6 DSCP (bits 2-7) field supports exact match only.
	traceflowTagToSRange = binding.Range{2, 7}

	globalVirtualMAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")
	hairpinIP           = net.ParseIP("169.254.169.252").To4()
	hairpinIPv6         = net.ParseIP("fc00::aabb:ccdd:eeff").To16()
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
	enableAntreaPolicy                            bool
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
	// packetInHandlers stores handler to process PacketIn event. Each packetin reason can have multiple handlers registered.
	// When a packetin arrives, openflow send packet to registered handlers in this map.
	packetInHandlers map[uint8]map[string]PacketInHandler
	// Supported IP Protocols (IP or IPv6) on the current Node.
	ipProtocols []binding.Protocol
	// ovsctlClient is the interface for executing OVS "ovs-ofctl" and "ovs-appctl" commands.
	ovsctlClient ovsctl.OVSCtlClient
}

func (c *client) GetTunnelVirtualMAC() net.HardwareAddr {
	return globalVirtualMAC
}

func (c *client) Add(flow binding.Flow) error {
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		metrics.OVSFlowOpsLatency.WithLabelValues("add").Observe(float64(d.Milliseconds()))
	}()
	if err := c.bridge.AddFlowsInBundle([]binding.Flow{flow}, nil, nil); err != nil {
		metrics.OVSFlowOpsErrorCount.WithLabelValues("add").Inc()
		return err
	}
	metrics.OVSFlowOpsCount.WithLabelValues("add").Inc()
	return nil
}

func (c *client) Modify(flow binding.Flow) error {
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		metrics.OVSFlowOpsLatency.WithLabelValues("modify").Observe(float64(d.Milliseconds()))
	}()
	if err := c.bridge.AddFlowsInBundle(nil, []binding.Flow{flow}, nil); err != nil {
		metrics.OVSFlowOpsErrorCount.WithLabelValues("modify").Inc()
		return err
	}
	metrics.OVSFlowOpsCount.WithLabelValues("modify").Inc()
	return nil
}

func (c *client) Delete(flow binding.Flow) error {
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		metrics.OVSFlowOpsLatency.WithLabelValues("delete").Observe(float64(d.Milliseconds()))
	}()
	if err := c.bridge.AddFlowsInBundle(nil, nil, []binding.Flow{flow}); err != nil {
		metrics.OVSFlowOpsErrorCount.WithLabelValues("delete").Inc()
		return err
	}
	metrics.OVSFlowOpsCount.WithLabelValues("delete").Inc()
	return nil
}

func (c *client) AddAll(flows []binding.Flow) error {
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		metrics.OVSFlowOpsLatency.WithLabelValues("add").Observe(float64(d.Milliseconds()))
	}()
	if err := c.bridge.AddFlowsInBundle(flows, nil, nil); err != nil {
		metrics.OVSFlowOpsErrorCount.WithLabelValues("add").Inc()
		return err
	}
	metrics.OVSFlowOpsCount.WithLabelValues("add").Inc()
	return nil
}

func (c *client) DeleteAll(flows []binding.Flow) error {
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		metrics.OVSFlowOpsLatency.WithLabelValues("delete").Observe(float64(d.Milliseconds()))
	}()
	if err := c.bridge.AddFlowsInBundle(nil, nil, flows); err != nil {
		metrics.OVSFlowOpsErrorCount.WithLabelValues("delete").Inc()
		return err
	}
	metrics.OVSFlowOpsCount.WithLabelValues("delete").Inc()
	return nil
}

func (c *client) AddOFEntries(ofEntries []binding.OFEntry) error {
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		metrics.OVSFlowOpsLatency.WithLabelValues("add").Observe(float64(d.Milliseconds()))
	}()
	if err := c.bridge.AddOFEntriesInBundle(ofEntries, nil, nil); err != nil {
		metrics.OVSFlowOpsErrorCount.WithLabelValues("add").Inc()
		return err
	}
	metrics.OVSFlowOpsCount.WithLabelValues("add").Inc()
	return nil
}

func (c *client) DeleteOFEntries(ofEntries []binding.OFEntry) error {
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		metrics.OVSFlowOpsLatency.WithLabelValues("delete").Observe(float64(d.Milliseconds()))
	}()
	if err := c.bridge.AddOFEntriesInBundle(nil, nil, ofEntries); err != nil {
		metrics.OVSFlowOpsErrorCount.WithLabelValues("delete").Inc()
		return err
	}
	metrics.OVSFlowOpsCount.WithLabelValues("delete").Inc()
	return nil
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
	return c.pipeline[ClassifierTable].BuildFlow(priorityNormal).
		MatchInPort(tunnelOFPort).
		Action().LoadRegRange(int(marksReg), markTrafficFromTunnel, binding.Range{0, 15}).
		Action().LoadRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
		Action().GotoTable(conntrackTable).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// gatewayClassifierFlow generates the flow to mark traffic comes from the gatewayOFPort.
func (c *client) gatewayClassifierFlow(gatewayOFPort uint32, category cookie.Category) binding.Flow {
	classifierTable := c.pipeline[ClassifierTable]
	return classifierTable.BuildFlow(priorityNormal).
		MatchInPort(gatewayOFPort).
		Action().LoadRegRange(int(marksReg), markTrafficFromGateway, binding.Range{0, 15}).
		Action().GotoTable(classifierTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// podClassifierFlow generates the flow to mark traffic comes from the podOFPort.
func (c *client) podClassifierFlow(podOFPort uint32, category cookie.Category) binding.Flow {
	classifierTable := c.pipeline[ClassifierTable]
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
	flows = []binding.Flow{
		c.pipeline[ClassifierTable].BuildFlow(priorityNormal).
			MatchInPort(uplinkPort).
			Action().GotoTable(uplinkTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		c.pipeline[uplinkTable].BuildFlow(priorityMiss).
			Action().Output(int(bridgeLocalPort)).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		c.pipeline[ClassifierTable].BuildFlow(priorityNormal).MatchInPort(bridgeLocalPort).
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
	flows := c.conntrackBasicFlows(category)
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
				Action().CT(false, connectionTrackTable.GetNext(), CtZone).NAT().CTDone().
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
			connectionTrackTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIPv6).
				Action().CT(false, connectionTrackTable.GetNext(), CtZoneV6).NAT().CTDone().
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
			connectionTrackCommitTable.BuildFlow(priorityLow).MatchProtocol(binding.ProtocolIP).
				MatchCTStateTrk(true).
				MatchCTMark(ServiceCTMark, nil).
				MatchRegRange(int(serviceLearnReg), marksRegServiceSelected, serviceLearnRegRange).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Action().GotoTable(connectionTrackCommitTable.GetNext()).
				Done(),
			connectionTrackCommitTable.BuildFlow(priorityLow).MatchProtocol(binding.ProtocolIPv6).
				MatchCTStateTrk(true).
				MatchCTMark(ServiceCTMark, nil).
				MatchRegRange(int(serviceLearnReg), marksRegServiceSelected, serviceLearnRegRange).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Action().GotoTable(connectionTrackCommitTable.GetNext()).
				Done(),
		)
	} else {
		flows = append(flows, c.kubeProxyFlows(category)...)
	}

	// TODO: following flows should move to function "kubeProxyFlows". Since another PR(#1198) is trying
	//  to polish the relevant logic, code refactoring is needed after that PR is merged.
	for _, proto := range c.ipProtocols {
		ctZone := CtZone
		if proto == binding.ProtocolIPv6 {
			ctZone = CtZoneV6
		}
		flows = append(flows,
			// If a connection was initiated through the gateway (i.e. has gatewayCTMark) and
			// the packet is received on the gateway port, go to the next table directly. This
			// is to bypass the flow which is installed by ctRewriteDstMACFlow in the same
			// table, and which will rewrite the destination MAC address for traffic with the
			// gatewayCTMark, but which is flowing in the opposite direction.
			connectionTrackStateTable.BuildFlow(priorityHigh).MatchProtocol(proto).
				MatchRegRange(int(marksReg), markTrafficFromGateway, binding.Range{0, 15}).
				MatchCTMark(gatewayCTMark, nil).
				MatchCTStateNew(false).MatchCTStateTrk(true).
				Action().GotoTable(connectionTrackStateTable.GetNext()).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
			// Connections initiated through the gateway are marked with gatewayCTMark.
			connectionTrackCommitTable.BuildFlow(priorityNormal).MatchProtocol(proto).
				MatchRegRange(int(marksReg), markTrafficFromGateway, binding.Range{0, 15}).
				MatchCTStateNew(true).MatchCTStateTrk(true).
				Action().CT(true, connectionTrackCommitTable.GetNext(), ctZone).LoadToMark(gatewayCTMark).CTDone().
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
		)
	}
	return flows
}

func (c *client) conntrackBasicFlows(category cookie.Category) []binding.Flow {
	connectionTrackStateTable := c.pipeline[conntrackStateTable]
	connectionTrackCommitTable := c.pipeline[conntrackCommitTable]
	var flows []binding.Flow
	for _, proto := range c.ipProtocols {
		ctZone := CtZone
		if proto == binding.ProtocolIPv6 {
			ctZone = CtZoneV6
		}
		flows = append(flows,
			connectionTrackStateTable.BuildFlow(priorityLow).MatchProtocol(proto).
				MatchCTStateInv(true).MatchCTStateTrk(true).
				Action().Drop().
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
			connectionTrackCommitTable.BuildFlow(priorityLow).MatchProtocol(proto).
				MatchCTStateNew(true).MatchCTStateTrk(true).
				Action().CT(true, connectionTrackCommitTable.GetNext(), ctZone).CTDone().
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
		)
	}
	return flows
}

func (c *client) kubeProxyFlows(category cookie.Category) []binding.Flow {
	connectionTrackTable := c.pipeline[conntrackTable]
	var flows []binding.Flow
	for _, proto := range c.ipProtocols {
		ctZone := CtZone
		if proto == binding.ProtocolIPv6 {
			ctZone = CtZoneV6
		}
		flows = append(flows,
			connectionTrackTable.BuildFlow(priorityNormal).MatchProtocol(proto).
				Action().CT(false, connectionTrackTable.GetNext(), ctZone).CTDone().
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
		)
	}
	return flows
}

// TODO: Use DuplicateToBuilder or integrate this function into original one to avoid unexpected difference.
// traceflowConnectionTrackFlows generate Traceflow specific flows that bypass the drop flow in connectionTrackFlows to
// avoid unexpected packet drop in Traceflow.
func (c *client) traceflowConnectionTrackFlows(dataplaneTag uint8, category cookie.Category) binding.Flow {
	connectionTrackStateTable := c.pipeline[conntrackStateTable]
	flowBuilder := connectionTrackStateTable.BuildFlow(priorityLow + 2).
		MatchProtocol(binding.ProtocolIP).
		MatchIPDscp(dataplaneTag).
		SetHardTimeout(300).
		Cookie(c.cookieAllocator.Request(category).Raw())
	if c.enableProxy {
		flowBuilder = flowBuilder.
			Action().ResubmitToTable(sessionAffinityTable).
			Action().ResubmitToTable(serviceLBTable)
	} else {
		flowBuilder = flowBuilder.
			Action().ResubmitToTable(connectionTrackStateTable.GetNext())
	}
	return flowBuilder.Done()
}

// ctRewriteDstMACFlow rewrites the destination MAC address with the local host gateway MAC if the
// packet is marked with gatewayCTMark but was not received on the host gateway. In other words, it
// rewrites the destination MAC address for reply traffic for connections which were initiated
// through the gateway, to ensure that this reply traffic gets forwarded correctly (back to the host
// network namespace, through the gateway). In particular, it is necessary in the following 2 cases:
//  1) reply traffic for connections from a local Pod to a ClusterIP Service (when AntreaProxy is
//  disabled and kube-proxy is used). In this case the destination IP address of the reply traffic
//  is the Pod which initiated the connection to the Service (no SNAT). We need to make sure that
//  these packets are sent back through the gateway so that the source IP can be rewritten (Service
//  backend IP -> Service ClusterIP).
//  2) when hair-pinning is involved, i.e. for connections between 2 local Pods belonging to this
//  Node and for which NAT is performed. This applies regardless of whether AntreaProxy is enabled
//  or not, and thus also applies to Windows Nodes (for which AntreaProxy is enabled by default).
//  One example is a Pod accessing a NodePort Service for which externalTrafficPolicy is set to
//  Local, using the local Node's IP address.
func (c *client) ctRewriteDstMACFlows(gatewayMAC net.HardwareAddr, category cookie.Category) []binding.Flow {
	connectionTrackStateTable := c.pipeline[conntrackStateTable]
	macData, _ := strconv.ParseUint(strings.Replace(gatewayMAC.String(), ":", "", -1), 16, 64)
	var flows []binding.Flow
	for _, proto := range c.ipProtocols {
		flows = append(flows, connectionTrackStateTable.BuildFlow(priorityNormal).MatchProtocol(proto).
			MatchCTMark(gatewayCTMark, nil).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			Action().LoadRange(binding.NxmFieldDstMAC, macData, binding.Range{0, 47}).
			Action().GotoTable(connectionTrackStateTable.GetNext()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return flows
}

// serviceLBBypassFlow makes packets that belong to a tracked connection bypass
// service LB tables and enter egressRuleTable directly.
func (c *client) serviceLBBypassFlow(ipProtocol binding.Protocol) binding.Flow {
	connectionTrackStateTable := c.pipeline[conntrackStateTable]
	return connectionTrackStateTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
		MatchCTMark(ServiceCTMark, nil).
		MatchCTStateNew(false).MatchCTStateTrk(true).
		Action().LoadRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
		Action().GotoTable(EgressRuleTable).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Done()
}

// l2ForwardCalcFlow generates the flow that matches dst MAC and loads ofPort to reg.
func (c *client) l2ForwardCalcFlow(dstMAC net.HardwareAddr, ofPort uint32, category cookie.Category) binding.Flow {
	l2FwdCalcTable := c.pipeline[l2ForwardingCalcTable]
	return l2FwdCalcTable.BuildFlow(priorityNormal).
		MatchDstMAC(dstMAC).
		Action().LoadRegRange(int(PortCacheReg), ofPort, ofPortRegRange).
		Action().LoadRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
		Action().GotoTable(l2FwdCalcTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// l2ForwardOutputFlow generates the flow that outputs packets to OVS port after L2 forwarding calculation.
func (c *client) l2ForwardOutputFlow(category cookie.Category) binding.Flow {
	return c.pipeline[L2ForwardingOutTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
		MatchRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
		Action().OutputRegRange(int(PortCacheReg), ofPortRegRange).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// traceflowL2ForwardOutputFlows generates Traceflow specific flows that outputs traceflow packets to OVS port and Antrea
// Agent after L2forwarding calculation.
func (c *client) traceflowL2ForwardOutputFlows(dataplaneTag uint8, category cookie.Category) []binding.Flow {
	flows := []binding.Flow{}
	// Output and SendToController if output port is tunnel or gateway port.
	// The gw0 IP as Traceflow destination is not supported.
	if c.encapMode.SupportsEncap() {
		flows = append(flows, c.pipeline[L2ForwardingOutTable].BuildFlow(priorityNormal+3).
			MatchReg(int(PortCacheReg), config.DefaultTunOFPort).
			MatchIPDscp(dataplaneTag).
			SetHardTimeout(300).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
			Action().OutputRegRange(int(PortCacheReg), ofPortRegRange).
			Action().SendToController(uint8(PacketInReasonTF)).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	flows = append(flows, c.pipeline[L2ForwardingOutTable].BuildFlow(priorityNormal+3).
		MatchReg(int(PortCacheReg), config.HostGatewayOFPort).
		MatchIPDscp(dataplaneTag).
		SetHardTimeout(300).
		MatchProtocol(binding.ProtocolIP).
		MatchRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
		Action().OutputRegRange(int(PortCacheReg), ofPortRegRange).
		Action().SendToController(uint8(PacketInReasonTF)).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done())
	// Only SendToController if output port is Pod port.
	flows = append(flows, c.pipeline[L2ForwardingOutTable].BuildFlow(priorityNormal+2).
		MatchIPDscp(dataplaneTag).
		SetHardTimeout(300).
		MatchProtocol(binding.ProtocolIP).
		MatchRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
		Action().SendToController(uint8(PacketInReasonTF)).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done())
	return flows
}

// l2ForwardOutputServiceHairpinFlow uses in_port action for Service
// hairpin packets to avoid packets from being dropped by OVS.
func (c *client) l2ForwardOutputServiceHairpinFlow() binding.Flow {
	return c.pipeline[L2ForwardingOutTable].BuildFlow(priorityHigh).
		MatchRegRange(int(marksReg), hairpinMark, hairpinMarkRange).
		Action().OutputInPort().
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Done()
}

// l2ForwardOutputFlows generates the flow that outputs packets to OVS port after L2 forwarding calculation.
func (c *client) l2ForwardOutputFlows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	flows = append(flows,
		c.pipeline[L2ForwardingOutTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
			Action().OutputRegRange(int(PortCacheReg), ofPortRegRange).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		c.pipeline[L2ForwardingOutTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIPv6).
			MatchRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
			Action().OutputRegRange(int(PortCacheReg), ofPortRegRange).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	)
	return flows
}

// l3FlowsToPod generates the flow to rewrite MAC if the packet is received from tunnel port and destined for local Pods.
func (c *client) l3FlowsToPod(localGatewayMAC net.HardwareAddr, podInterfaceIPs []net.IP, podInterfaceMAC net.HardwareAddr, category cookie.Category) []binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	var flows []binding.Flow
	for _, ip := range podInterfaceIPs {
		ipProtocol := getIPProtocol(ip)
		flowBuilder := l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol)
		if c.enableProxy {
			flowBuilder = flowBuilder.MatchRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange)
		} else {
			flowBuilder = flowBuilder.MatchDstMAC(globalVirtualMAC)
		}
		// Rewrite src MAC to local gateway MAC, and rewrite dst MAC to pod MAC
		flows = append(flows, flowBuilder.MatchDstIP(ip).
			Action().SetSrcMAC(localGatewayMAC).
			Action().SetDstMAC(podInterfaceMAC).
			Action().DecTTL().
			Action().GotoTable(l3FwdTable.GetNext()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return flows
}

// l3ToPodFromGwFlow generates the flow to rewrite MAC if the packet IP matches an local IP.
// This flow is used in policy only traffic mode.
func (c *client) l3ToPodFlow(podInterfaceIPs []net.IP, podInterfaceMAC net.HardwareAddr, category cookie.Category) []binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	var flows []binding.Flow
	for _, ip := range podInterfaceIPs {
		ipProtocol := getIPProtocol(ip)
		flows = append(flows, l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
			MatchDstIP(ip).
			Action().SetDstMAC(podInterfaceMAC).
			Action().DecTTL().
			Action().GotoTable(l3FwdTable.GetNext()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return flows
}

// l3ToGWFlow generates the flow to rewrite MAC to gw port if the packet received is unmatched by local Pod flows.
// This flow is used in policy only traffic mode.
func (c *client) l3ToGWFlow(gwMAC net.HardwareAddr, category cookie.Category) []binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	var flows []binding.Flow
	for _, ipProto := range c.ipProtocols {
		flows = append(flows, l3FwdTable.BuildFlow(priorityLow).MatchProtocol(ipProto).
			Action().SetDstMAC(gwMAC).
			Action().DecTTL().
			Action().GotoTable(l3FwdTable.GetNext()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		)
	}
	return flows
}

// l3ToGatewayFlow generates flow that rewrites MAC of the packet received from tunnel port and destined to local gateway.
func (c *client) l3ToGatewayFlow(localGatewayIPs []net.IP, localGatewayMAC net.HardwareAddr, category cookie.Category) []binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	var flows []binding.Flow
	for _, ip := range localGatewayIPs {
		ipProtocol := getIPProtocol(ip)
		flows = append(flows, l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
			MatchDstMAC(globalVirtualMAC).
			MatchDstIP(ip).
			Action().SetDstMAC(localGatewayMAC).
			Action().GotoTable(l3FwdTable.GetNext()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return flows
}

// l3FwdFlowToRemote generates the L3 forward flow on source node to support traffic to remote pods/gateway.
func (c *client) l3FwdFlowToRemote(
	localGatewayMAC net.HardwareAddr,
	peerSubnet net.IPNet,
	tunnelPeer net.IP,
	tunOFPort uint32,
	category cookie.Category) binding.Flow {
	ipProto := getIPProtocol(peerSubnet.IP)
	return c.pipeline[l3ForwardingTable].BuildFlow(priorityNormal).MatchProtocol(ipProto).
		MatchDstIPNet(peerSubnet).
		Action().DecTTL().
		// Rewrite src MAC to local gateway MAC and rewrite dst MAC to virtual MAC.
		Action().SetSrcMAC(localGatewayMAC).
		Action().SetDstMAC(globalVirtualMAC).
		// Load ofport of the tunnel interface.
		Action().LoadRegRange(int(PortCacheReg), tunOFPort, ofPortRegRange).
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
	ipProto := getIPProtocol(peerSubnet.IP)
	l3FwdTable := c.pipeline[l3ForwardingTable]
	return l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(ipProto).
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
func (c *client) podIPSpoofGuardFlow(ifIPs []net.IP, ifMAC net.HardwareAddr, ifOFPort uint32, category cookie.Category) []binding.Flow {
	ipPipeline := c.pipeline
	ipSpoofGuardTable := ipPipeline[spoofGuardTable]
	var flows []binding.Flow
	for _, ifIP := range ifIPs {
		ipProtocol := getIPProtocol(ifIP)
		if ipProtocol == binding.ProtocolIP {
			flows = append(flows, ipSpoofGuardTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
				MatchInPort(ifOFPort).
				MatchSrcMAC(ifMAC).
				MatchSrcIP(ifIP).
				Action().GotoTable(ipSpoofGuardTable.GetNext()).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done())
		} else if ipProtocol == binding.ProtocolIPv6 {
			flows = append(flows, ipSpoofGuardTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
				MatchInPort(ifOFPort).
				MatchSrcMAC(ifMAC).
				MatchSrcIP(ifIP).
				Action().GotoTable(ipv6Table).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done())
		}
	}
	return flows
}

func getIPProtocol(ip net.IP) binding.Protocol {
	var ipProtocol binding.Protocol
	if ip.To4() != nil {
		ipProtocol = binding.ProtocolIP
	} else {
		ipProtocol = binding.ProtocolIPv6
	}
	return ipProtocol
}

// serviceHairpinResponseDNATFlow generates the flow which transforms destination
// IP of the hairpin packet to the source IP.
func (c *client) serviceHairpinResponseDNATFlow(ipProtocol binding.Protocol) binding.Flow {
	hpIP := hairpinIP
	from := "NXM_OF_IP_SRC"
	to := "NXM_OF_IP_DST"
	if ipProtocol == binding.ProtocolIPv6 {
		hpIP = hairpinIPv6
		from = "NXM_NX_IPV6_SRC"
		to = "NXM_NX_IPV6_DST"
	}
	return c.pipeline[serviceHairpinTable].BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
		MatchDstIP(hpIP).
		Action().Move(from, to).
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

// gatewayIPSpoofGuardFlow generates the flow to skip spoof guard checking for traffic sent from gateway interface.
func (c *client) gatewayIPSpoofGuardFlows(gatewayOFPort uint32, category cookie.Category) []binding.Flow {
	ipPipeline := c.pipeline
	ipSpoofGuardTable := ipPipeline[spoofGuardTable]
	var flows []binding.Flow
	for _, proto := range c.ipProtocols {
		nextTable := ipSpoofGuardTable.GetNext()
		if proto == binding.ProtocolIPv6 {
			nextTable = ipv6Table
		}
		flows = append(flows,
			ipSpoofGuardTable.BuildFlow(priorityNormal).MatchProtocol(proto).
				MatchInPort(gatewayOFPort).
				Action().GotoTable(nextTable).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
		)
	}
	return flows
}

// serviceCIDRDNATFlow generates flows to match dst IP in service CIDR and output to host gateway interface directly.
func (c *client) serviceCIDRDNATFlows(serviceCIDRs []*net.IPNet, gatewayOFPort uint32) []binding.Flow {
	var flows []binding.Flow
	for _, serviceCIDR := range serviceCIDRs {
		if serviceCIDR != nil {
			ipProto := getIPProtocol(serviceCIDR.IP)
			flows = append(flows, c.pipeline[dnatTable].BuildFlow(priorityNormal).MatchProtocol(ipProto).
				MatchDstIPNet(*serviceCIDR).
				Action().LoadRegRange(int(PortCacheReg), gatewayOFPort, ofPortRegRange).
				Action().LoadRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
				Action().GotoTable(conntrackCommitTable).
				Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
				Done())
		}
	}
	return flows
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

func (c *client) allowRulesMetricFlows(conjunctionID uint32, ingress bool) []binding.Flow {
	metricTableID := IngressMetricTable
	offset := 0
	// We use the 0..31 bits of the ct_label to store the ingress rule ID and use the 32..63 bits to store the
	// egress rule ID.
	labelRange := metricIngressRuleIDRange
	if !ingress {
		metricTableID = EgressMetricTable
		offset = 32
		labelRange = metricEgressRuleIDRange
	}
	metricFlow := func(isCTNew bool, protocol binding.Protocol) binding.Flow {
		return c.pipeline[metricTableID].BuildFlow(priorityNormal).
			MatchProtocol(protocol).
			MatchPriority(priorityNormal).
			MatchCTStateNew(isCTNew).
			MatchCTLabelRange(0, uint64(conjunctionID)<<offset, labelRange).
			Action().GotoTable(c.pipeline[metricTableID].GetNext()).
			Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
			Done()
	}
	var flows []binding.Flow
	// These two flows track the number of sessions in addition to the packet and byte counts.
	// The flow matching 'ct_state=+new' tracks the number of sessions and byte count of the first packet for each
	// session.
	// The flow matching 'ct_state=-new' tracks the byte/packet count of an established connection (both directions).
	for _, proto := range c.ipProtocols {
		flows = append(flows, metricFlow(true, proto), metricFlow(false, proto))
	}
	return flows
}

func (c *client) dropRuleMetricFlow(conjunctionID uint32, ingress bool) binding.Flow {
	metricTableID := IngressMetricTable
	if !ingress {
		metricTableID = EgressMetricTable
	}
	return c.pipeline[metricTableID].BuildFlow(priorityNormal).
		MatchPriority(priorityNormal).
		MatchRegRange(int(marksReg), cnpDropMark, cnpDropMarkRange).
		MatchReg(int(CNPDropConjunctionIDReg), conjunctionID).
		Action().Drop().
		Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
		Done()
}

// ipv6Flows generates the flows to allow IPv6 packets from link-local addresses and
// handle multicast packets, Neighbor Solicitation and ND Advertisement packets properly.
func (c *client) ipv6Flows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow

	_, ipv6LinkLocalIpnet, _ := net.ParseCIDR(ipv6LinkLocalAddr)
	_, ipv6MulticastIpnet, _ := net.ParseCIDR(ipv6MulticastAddr)
	flows = append(flows,
		// Allow IPv6 packets (e.g. Multicast Listener Report Message V2) which are sent from link-local addresses in spoofGuardTable,
		// so that these packets will not be dropped.
		c.pipeline[spoofGuardTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIPv6).
			MatchSrcIPNet(*ipv6LinkLocalIpnet).
			Action().GotoTable(ipv6Table).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Handle IPv6 Neighbor Solicitation and Neighbor Advertisement as a regular L2 learning Switch by using normal.
		c.pipeline[ipv6Table].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolICMPv6).
			MatchICMPv6Type(135).
			MatchICMPv6Code(0).
			Action().Normal().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		c.pipeline[ipv6Table].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolICMPv6).
			MatchICMPv6Type(136).
			MatchICMPv6Code(0).
			Action().Normal().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Handle IPv6 multicast packets as a regular L2 learning Switch by using normal.
		// It is used to ensure that all kinds of IPv6 multicast packets are properly handled (e.g. Multicast Listener Report Message V2).
		c.pipeline[ipv6Table].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIPv6).
			MatchDstIPNet(*ipv6MulticastIpnet).
			Action().Normal().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	)
	return flows
}

// conjunctionActionFlow generates the flow to jump to a specific table if policyRuleConjunction ID is matched. Priority of
// conjunctionActionFlow is created at priorityLow for k8s network policies, and *priority assigned by PriorityAssigner for AntreaPolicy.
func (c *client) conjunctionActionFlow(conjunctionID uint32, tableID binding.TableIDType, nextTable binding.TableIDType, priority *uint16, enableLogging bool) []binding.Flow {
	var ofPriority uint16
	if priority == nil {
		ofPriority = priorityLow
	} else {
		ofPriority = *priority
	}
	conjReg := IngressReg
	labelRange := metricIngressRuleIDRange
	if _, ok := egressTables[tableID]; ok {
		conjReg = EgressReg
		labelRange = metricEgressRuleIDRange
	}
	conjActionFlow := func(proto binding.Protocol) binding.Flow {
		ctZone := CtZone
		if proto == binding.ProtocolIPv6 {
			ctZone = CtZoneV6
		}
		if enableLogging {
			return c.pipeline[tableID].BuildFlow(ofPriority).MatchProtocol(proto).
				MatchConjID(conjunctionID).
				MatchPriority(ofPriority).
				Action().LoadRegRange(int(conjReg), conjunctionID, binding.Range{0, 31}).       // Traceflow.
				Action().LoadRegRange(int(marksReg), DispositionAllow, APDispositionMarkRange). // AntreaPolicy
				Action().SendToController(uint8(PacketInReasonNP)).
				Action().CT(true, nextTable, ctZone). // CT action requires commit flag if actions other than NAT without arguments are specified.
				LoadToLabelRange(uint64(conjunctionID), &labelRange).
				CTDone().
				Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
				Done()
		} else {
			return c.pipeline[tableID].BuildFlow(ofPriority).MatchProtocol(proto).
				MatchConjID(conjunctionID).
				MatchPriority(ofPriority).
				Action().LoadRegRange(int(conjReg), conjunctionID, binding.Range{0, 31}). // Traceflow.
				Action().CT(true, nextTable, ctZone).                                     // CT action requires commit flag if actions other than NAT without arguments are specified.
				LoadToLabelRange(uint64(conjunctionID), &labelRange).
				CTDone().
				Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
				Done()
		}
	}
	var flows []binding.Flow
	for _, proto := range c.ipProtocols {
		flows = append(flows, conjActionFlow(proto))
	}
	return flows
}

// conjunctionActionDropFlow generates the flow to mark the packet to be dropped if policyRuleConjunction ID is matched.
// Any matched flow will be dropped in corresponding metric tables.
func (c *client) conjunctionActionDropFlow(conjunctionID uint32, tableID binding.TableIDType, priority *uint16, enableLogging bool) binding.Flow {
	ofPriority := *priority
	metricTableID := IngressMetricTable
	if _, ok := egressTables[tableID]; ok {
		metricTableID = EgressMetricTable
	}
	// We do not drop the packet immediately but send the packet to the metric table to update the rule metrics.
	if enableLogging {
		return c.pipeline[tableID].BuildFlow(ofPriority).
			MatchConjID(conjunctionID).
			MatchPriority(ofPriority).
			Action().LoadRegRange(int(CNPDropConjunctionIDReg), conjunctionID, binding.Range{0, 31}).
			Action().LoadRegRange(int(marksReg), cnpDropMark, cnpDropMarkRange).
			Action().LoadRegRange(int(marksReg), DispositionDrop, APDispositionMarkRange). //Logging
			Action().SendToController(uint8(PacketInReasonNP)).
			Action().GotoTable(metricTableID).
			Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
			Done()
	} else {
		return c.pipeline[tableID].BuildFlow(ofPriority).
			MatchConjID(conjunctionID).
			MatchPriority(ofPriority).
			Action().LoadRegRange(int(CNPDropConjunctionIDReg), conjunctionID, binding.Range{0, 31}).
			Action().LoadRegRange(int(marksReg), cnpDropMark, cnpDropMarkRange).
			Action().GotoTable(metricTableID).
			Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
			Done()
	}
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
	egressDropTable := c.pipeline[EgressDefaultTable]
	// ingressDropTable checks the destination address of packets, and drops packets sent to the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the established connections need not to be checked with the
	// ingressRuleTable or ingressDropTable.
	ingressDropTable := c.pipeline[IngressDefaultTable]
	var allEstFlows []binding.Flow
	for _, ipProto := range c.ipProtocols {
		egressEstFlow := c.pipeline[EgressRuleTable].BuildFlow(priorityHigh).MatchProtocol(ipProto).
			MatchCTStateNew(false).MatchCTStateEst(true).
			Action().GotoTable(egressDropTable.GetNext()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done()
		ingressEstFlow := c.pipeline[IngressRuleTable].BuildFlow(priorityHigh).MatchProtocol(ipProto).
			MatchCTStateNew(false).MatchCTStateEst(true).
			Action().GotoTable(ingressDropTable.GetNext()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done()
		allEstFlows = append(allEstFlows, egressEstFlow, ingressEstFlow)
	}
	if !c.enableAntreaPolicy {
		return allEstFlows
	}
	apFlows := make([]binding.Flow, 0)
	for _, tableID := range GetAntreaPolicyEgressTables() {
		for _, ipProto := range c.ipProtocols {
			apEgressEstFlow := c.pipeline[tableID].BuildFlow(priorityTopAntreaPolicy).MatchProtocol(ipProto).
				MatchCTStateNew(false).MatchCTStateEst(true).
				Action().GotoTable(egressDropTable.GetNext()).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done()
			apFlows = append(apFlows, apEgressEstFlow)
		}

	}
	for _, tableID := range GetAntreaPolicyIngressTables() {
		for _, ipProto := range c.ipProtocols {
			apIngressEstFlow := c.pipeline[tableID].BuildFlow(priorityTopAntreaPolicy).MatchProtocol(ipProto).
				MatchCTStateNew(false).MatchCTStateEst(true).
				Action().GotoTable(ingressDropTable.GetNext()).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done()
			apFlows = append(apFlows, apIngressEstFlow)
		}

	}
	allEstFlows = append(allEstFlows, apFlows...)
	return allEstFlows
}

func (c *client) addFlowMatch(fb binding.FlowBuilder, matchKey *types.MatchKey, matchValue interface{}) binding.FlowBuilder {
	switch matchKey {
	case MatchDstOFPort:
		// ofport number in NXM_NX_REG1 is used in ingress rule to match packets sent to local Pod.
		fb = fb.MatchReg(int(PortCacheReg), uint32(matchValue.(int32)))
	case MatchSrcOFPort:
		fb = fb.MatchInPort(uint32(matchValue.(int32)))
	case MatchDstIP:
		fallthrough
	case MatchDstIPv6:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol()).MatchDstIP(matchValue.(net.IP))
	case MatchDstIPNet:
		fallthrough
	case MatchDstIPNetv6:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol()).MatchDstIPNet(matchValue.(net.IPNet))
	case MatchSrcIP:
		fallthrough
	case MatchSrcIPv6:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol()).MatchSrcIP(matchValue.(net.IP))
	case MatchSrcIPNet:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol()).MatchSrcIPNet(matchValue.(net.IPNet))
	case MatchSrcIPNetv6:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol()).MatchSrcIPNet(matchValue.(net.IPNet))
	case MatchDstOFPort:
		// ofport number in NXM_NX_REG1 is used in ingress rule to match packets sent to local Pod.
		fb = fb.MatchProtocol(matchKey.GetOFProtocol()).MatchReg(int(PortCacheReg), uint32(matchValue.(int32)))
	case MatchSrcOFPort:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol()).MatchInPort(uint32(matchValue.(int32)))
	case MatchTCPDstPort:
		fallthrough
	case MatchTCPv6DstPort:
		fallthrough
	case MatchUDPDstPort:
		fallthrough
	case MatchUDPv6DstPort:
		fallthrough
	case MatchSCTPDstPort:
		fallthrough
	case MatchSCTPv6DstPort:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol())
		portValue := matchValue.(uint16)
		if portValue > 0 {
			fb = fb.MatchDstPort(portValue, nil)
		}
	}
	return fb
}

// conjunctionExceptionFlow generates the flow to jump to a specific table if both policyRuleConjunction ID and except address are matched.
// Keeping this for reference to generic exception flow.
func (c *client) conjunctionExceptionFlow(conjunctionID uint32, tableID binding.TableIDType, nextTable binding.TableIDType, matchKey *types.MatchKey, matchValue interface{}) binding.Flow {
	conjReg := IngressReg
	if tableID == EgressRuleTable {
		conjReg = EgressReg
	}
	fb := c.pipeline[tableID].BuildFlow(priorityNormal).MatchConjID(conjunctionID)
	return c.addFlowMatch(fb, matchKey, matchValue).
		Action().LoadRegRange(int(conjReg), conjunctionID, binding.Range{0, 31}). // Traceflow.
		Action().GotoTable(nextTable).
		Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
		Done()
}

// conjunctiveMatchFlow generates the flow to set conjunctive actions if the match condition is matched.
func (c *client) conjunctiveMatchFlow(tableID binding.TableIDType, matchKey *types.MatchKey, matchValue interface{}, priority *uint16, actions ...*conjunctiveAction) binding.Flow {
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
func (c *client) defaultDropFlow(tableID binding.TableIDType, matchKey *types.MatchKey, matchValue interface{}) binding.Flow {
	fb := c.pipeline[tableID].BuildFlow(priorityNormal)
	return c.addFlowMatch(fb, matchKey, matchValue).
		Action().Drop().
		Cookie(c.cookieAllocator.Request(cookie.Default).Raw()).
		Done()
}

// localProbeFlow generates the flow to forward packets to conntrackCommitTable. The packets are sent from Node to probe the liveness/readiness of local Pods.
func (c *client) localProbeFlow(localGatewayIPs []net.IP, category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, ip := range localGatewayIPs {
		ipProtocol := getIPProtocol(ip)
		flows = append(flows, c.pipeline[IngressRuleTable].BuildFlow(priorityHigh).
			MatchProtocol(ipProtocol).
			MatchSrcIP(ip).
			Action().GotoTable(conntrackCommitTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return flows
}

func (c *client) bridgeAndUplinkFlows(uplinkOfport uint32, bridgeLocalPort uint32, nodeIP net.IP, localSubnet net.IPNet, category cookie.Category) []binding.Flow {
	snatIPRange := &binding.IPRange{StartIP: nodeIP, EndIP: nodeIP}
	vMACInt, _ := strconv.ParseUint(strings.Replace(globalVirtualMAC.String(), ":", "", -1), 16, 64)
	ctStateNext := dnatTable
	if c.enableProxy {
		ctStateNext = endpointDNATTable
	}
	flows := []binding.Flow{
		// Forward the packet to conntrackTable if it enters the OVS pipeline from the uplink interface.
		c.pipeline[uplinkTable].BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			Action().LoadRegRange(int(marksReg), markTrafficFromUplink, binding.Range{0, 15}).
			Action().GotoTable(conntrackTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Forward the packet to conntrackTable if it enters the OVS pipeline from the bridge interface and is sent to
		// local Pods. Set the packet with MAC rewrite mark, so that the dstMAC will be re-written with real MAC in
		// the L3Routing table, and it could be forwarded to the valid OVS interface.
		c.pipeline[ClassifierTable].BuildFlow(priorityHigh).
			MatchProtocol(binding.ProtocolIP).
			MatchInPort(bridgeLocalPort).
			MatchDstIPNet(localSubnet).
			Action().LoadRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
			Action().GotoTable(conntrackTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Enforce IP packet into the conntrack zone with SNAT. If the connection is SNATed, the reply packet should use
		// Pod IP as the destination, and then is forwarded to conntrackStateTable.
		c.pipeline[conntrackTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Action().CT(false, conntrackStateTable, CtZone).NAT().CTDone().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Rewrite dMAC with the global vMAC if the packet is a reply to the Pod from the external address.
		c.pipeline[conntrackStateTable].BuildFlow(priorityHigh).
			MatchProtocol(binding.ProtocolIP).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			MatchCTMark(snatCTMark, nil).
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
			MatchCTMark(snatCTMark, nil).
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
			Action().CT(true, L2ForwardingOutTable, CtZone).
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
			MatchCTMark(gatewayCTMark, nil).
			Action().GotoTable(l2ForwardingCalcTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Forward the packet to L2ForwardingCalc table if it is sent to the Node IP(not to the host gateway). Since
		// the packet is using the host gateway's MAC as dst MAC, it will be sent out from "antrea-gw0". This flow
		// entry is to avoid SNAT on such packet, otherwise the source and destination IP are the same.
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
			Action().GotoTable(IngressRuleTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Output the SNATed packet to the specified port.
		c.pipeline[L2ForwardingOutTable].BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), snatRequiredMark, snatMarkRange).
			Action().Output(outputPort).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	}
	return flows
}

// loadBalancerServiceFromOutsideFlow generates the flow to forward LoadBalancer service traffic from outside node
// to gateway. kube-proxy will then handle the traffic.
func (c *client) loadBalancerServiceFromOutsideFlow(uplinkPort uint32, gwPort uint32, svcIP net.IP, svcPort uint16, protocol binding.Protocol) binding.Flow {
	return c.pipeline[uplinkTable].BuildFlow(priorityHigh).
		MatchProtocol(protocol).
		MatchDstPort(svcPort, nil).
		MatchInPort(uplinkPort).
		MatchDstIP(svcIP).
		Action().Output(int(gwPort)).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Done()
}

// serviceLearnFlow generates the flow with learn action which adds new flows in
// sessionAffinityTable according to the Endpoint selection decision.
func (c *client) serviceLearnFlow(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol, affinityTimeout uint16) binding.Flow {
	// Using unique cookie ID here to avoid learned flow cascade deletion.
	cookieID := c.cookieAllocator.RequestWithObjectID(cookie.Service, uint32(groupID)).Raw()
	learnFlowBuilder := c.pipeline[serviceLBTable].BuildFlow(priorityLow).
		MatchRegRange(int(serviceLearnReg), marksRegServiceNeedLearn, serviceLearnRegRange).
		MatchDstIP(svcIP).
		MatchProtocol(protocol).
		MatchDstPort(svcPort, nil).
		Cookie(cookieID)
	// affinityTimeout is used as the OpenFlow "hard timeout": learned flow will be removed from
	// OVS after that time regarding of whether traffic is still hitting the flow. This is the
	// desired behavior based on the K8s spec. Note that existing connections will keep going to
	// the same endpoint because of connection tracking; and that is also the desired behavior.
	learnFlowBuilderLearnAction := learnFlowBuilder.
		Action().Learn(sessionAffinityTable, priorityNormal, 0, affinityTimeout, cookieID).
		DeleteLearned()
	ipProtocol := binding.ProtocolIP
	switch protocol {
	case binding.ProtocolTCP:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedTCPDstPort()
	case binding.ProtocolUDP:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedUDPDstPort()
	case binding.ProtocolSCTP:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedSCTPDstPort()
	case binding.ProtocolTCPv6:
		ipProtocol = binding.ProtocolIPv6
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedTCPv6DstPort()
	case binding.ProtocolUDPv6:
		ipProtocol = binding.ProtocolIPv6
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedUDPv6DstPort()
	case binding.ProtocolSCTPv6:
		ipProtocol = binding.ProtocolIPv6
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedSCTPv6DstPort()
	}
	if ipProtocol == binding.ProtocolIP {
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
	} else if ipProtocol == binding.ProtocolIPv6 {
		return learnFlowBuilderLearnAction.
			MatchLearnedDstIPv6().
			MatchLearnedSrcIPv6().
			LoadXXRegToXXReg(int(endpointIPv6XXReg), int(endpointIPv6XXReg), endpointIPv6XXRegRange, endpointIPv6XXRegRange).
			LoadRegToReg(int(endpointPortReg), int(endpointPortReg), endpointPortRegRange, endpointPortRegRange).
			LoadReg(int(serviceLearnReg), marksRegServiceSelected, serviceLearnRegRange).
			LoadReg(int(marksReg), macRewriteMark, macRewriteMarkRange).
			Done().
			Action().LoadRegRange(int(serviceLearnReg), marksRegServiceSelected, serviceLearnRegRange).
			Action().GotoTable(endpointDNATTable).
			Done()
	}
	return nil
}

// serviceLBFlow generates the flow which uses the specific group to do Endpoint
// selection.
func (c *client) serviceLBFlow(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol) binding.Flow {
	return c.pipeline[serviceLBTable].BuildFlow(priorityNormal).
		MatchProtocol(protocol).
		MatchDstPort(svcPort, nil).
		MatchDstIP(svcIP).
		MatchRegRange(int(serviceLearnReg), marksRegServiceNeedLB, serviceLearnRegRange).
		Action().Group(groupID).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Done()
}

// endpointDNATFlow generates the flow which transforms the Service Cluster IP
// to the Endpoint IP according to the Endpoint selection decision which is stored
// in regs.
func (c *client) endpointDNATFlow(endpointIP net.IP, endpointPort uint16, protocol binding.Protocol) binding.Flow {
	ipProtocol := getIPProtocol(endpointIP)
	unionVal := (marksRegServiceSelected << endpointPortRegRange.Length()) + uint32(endpointPort)
	table := c.pipeline[endpointDNATTable]

	flowBuilder := table.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		MatchRegRange(int(endpointPortReg), unionVal, binding.Range{0, 18}).
		MatchProtocol(protocol)
	ctZone := CtZone
	if ipProtocol == binding.ProtocolIP {
		ipVal := binary.BigEndian.Uint32(endpointIP.To4())
		flowBuilder = flowBuilder.MatchReg(int(endpointIPReg), ipVal).
			MatchRegRange(int(endpointPortReg), unionVal, binding.Range{0, 18})
	} else {
		ctZone = CtZoneV6
		ipVal := []byte(endpointIP)
		flowBuilder = flowBuilder.MatchXXReg(int(endpointIPv6XXReg), ipVal).
			MatchRegRange(int(endpointPortReg), unionVal, binding.Range{0, 18})
	}
	return flowBuilder.Action().CT(true, table.GetNext(), ctZone).
		DNAT(
			&binding.IPRange{StartIP: endpointIP, EndIP: endpointIP},
			&binding.PortRange{StartPort: endpointPort, EndPort: endpointPort},
		).
		LoadToMark(ServiceCTMark).
		CTDone().
		Done()
}

// hairpinSNATFlow generates the flow which does SNAT for Service
// hairpin packets and loads the hairpin mark to markReg.
func (c *client) hairpinSNATFlow(endpointIP net.IP) binding.Flow {
	ipProtocol := getIPProtocol(endpointIP)
	hpIP := hairpinIP
	if ipProtocol == binding.ProtocolIPv6 {
		hpIP = hairpinIPv6
	}
	return c.pipeline[hairpinSNATTable].BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		MatchProtocol(ipProtocol).
		MatchDstIP(endpointIP).
		MatchSrcIP(endpointIP).
		Action().SetSrcIP(hpIP).
		Action().LoadRegRange(int(marksReg), hairpinMark, hairpinMarkRange).
		Action().GotoTable(L2ForwardingOutTable).
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
		endpointIP := net.ParseIP(endpoint.IP())
		portVal := uint16(endpointPort)
		ipProtocol := getIPProtocol(endpointIP)
		if ipProtocol == binding.ProtocolIP {
			ipVal := binary.BigEndian.Uint32(endpointIP.To4())
			group = group.Bucket().Weight(100).
				LoadReg(int(endpointIPReg), ipVal).
				LoadRegRange(int(endpointPortReg), uint32(portVal), endpointPortRegRange).
				LoadRegRange(int(serviceLearnReg), lbResultMark, serviceLearnRegRange).
				LoadRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
				ResubmitToTable(resubmitTableID).
				Done()
		} else if ipProtocol == binding.ProtocolIPv6 {
			ipVal := []byte(endpointIP)
			group = group.Bucket().Weight(100).
				LoadXXReg(int(endpointIPv6XXReg), ipVal).
				LoadRegRange(int(endpointPortReg), uint32(portVal), endpointPortRegRange).
				LoadRegRange(int(serviceLearnReg), lbResultMark, serviceLearnRegRange).
				LoadRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
				ResubmitToTable(resubmitTableID).
				Done()
		}
	}
	return group
}

// policyConjKeyFuncKeyFunc knows how to get key of a *policyRuleConjunction.
func policyConjKeyFunc(obj interface{}) (string, error) {
	conj := obj.(*policyRuleConjunction)
	return fmt.Sprint(conj.id), nil
}

// priorityIndexFunc knows how to get priority of actionFlows in a *policyRuleConjunction.
// It's provided to cache.Indexer to build an index of policyRuleConjunction.
func priorityIndexFunc(obj interface{}) ([]string, error) {
	conj := obj.(*policyRuleConjunction)
	return conj.ActionFlowPriorities(), nil
}

func generatePipeline(bridge binding.Bridge, enableProxy, enableAntreaNP bool) map[binding.TableIDType]binding.Table {
	var egressEntryTable, IngressEntryTable binding.TableIDType
	if enableAntreaNP {
		egressEntryTable, IngressEntryTable = AntreaPolicyEgressRuleTable, AntreaPolicyIngressRuleTable
	} else {
		egressEntryTable, IngressEntryTable = EgressRuleTable, IngressRuleTable
	}
	var pipeline map[binding.TableIDType]binding.Table
	if enableProxy {
		pipeline = map[binding.TableIDType]binding.Table{
			ClassifierTable:       bridge.CreateTable(ClassifierTable, spoofGuardTable, binding.TableMissActionDrop),
			uplinkTable:           bridge.CreateTable(uplinkTable, spoofGuardTable, binding.TableMissActionNone),
			spoofGuardTable:       bridge.CreateTable(spoofGuardTable, serviceHairpinTable, binding.TableMissActionDrop),
			arpResponderTable:     bridge.CreateTable(arpResponderTable, binding.LastTableID, binding.TableMissActionDrop),
			ipv6Table:             bridge.CreateTable(ipv6Table, serviceHairpinTable, binding.TableMissActionNext),
			serviceHairpinTable:   bridge.CreateTable(serviceHairpinTable, conntrackTable, binding.TableMissActionNext),
			conntrackTable:        bridge.CreateTable(conntrackTable, conntrackStateTable, binding.TableMissActionNone),
			conntrackStateTable:   bridge.CreateTable(conntrackStateTable, endpointDNATTable, binding.TableMissActionNext),
			sessionAffinityTable:  bridge.CreateTable(sessionAffinityTable, binding.LastTableID, binding.TableMissActionNone),
			serviceLBTable:        bridge.CreateTable(serviceLBTable, endpointDNATTable, binding.TableMissActionNext),
			endpointDNATTable:     bridge.CreateTable(endpointDNATTable, egressEntryTable, binding.TableMissActionNext),
			EgressRuleTable:       bridge.CreateTable(EgressRuleTable, EgressDefaultTable, binding.TableMissActionNext),
			EgressDefaultTable:    bridge.CreateTable(EgressDefaultTable, EgressMetricTable, binding.TableMissActionNext),
			EgressMetricTable:     bridge.CreateTable(EgressMetricTable, l3ForwardingTable, binding.TableMissActionNext),
			l3ForwardingTable:     bridge.CreateTable(l3ForwardingTable, l2ForwardingCalcTable, binding.TableMissActionNext),
			l2ForwardingCalcTable: bridge.CreateTable(l2ForwardingCalcTable, IngressEntryTable, binding.TableMissActionNext),
			IngressRuleTable:      bridge.CreateTable(IngressRuleTable, IngressDefaultTable, binding.TableMissActionNext),
			IngressDefaultTable:   bridge.CreateTable(IngressDefaultTable, IngressMetricTable, binding.TableMissActionNext),
			IngressMetricTable:    bridge.CreateTable(IngressMetricTable, conntrackCommitTable, binding.TableMissActionNext),
			conntrackCommitTable:  bridge.CreateTable(conntrackCommitTable, hairpinSNATTable, binding.TableMissActionNext),
			hairpinSNATTable:      bridge.CreateTable(hairpinSNATTable, L2ForwardingOutTable, binding.TableMissActionNext),
			L2ForwardingOutTable:  bridge.CreateTable(L2ForwardingOutTable, binding.LastTableID, binding.TableMissActionDrop),
		}
	} else {
		pipeline = map[binding.TableIDType]binding.Table{
			ClassifierTable:       bridge.CreateTable(ClassifierTable, spoofGuardTable, binding.TableMissActionDrop),
			spoofGuardTable:       bridge.CreateTable(spoofGuardTable, conntrackTable, binding.TableMissActionDrop),
			arpResponderTable:     bridge.CreateTable(arpResponderTable, binding.LastTableID, binding.TableMissActionDrop),
			ipv6Table:             bridge.CreateTable(ipv6Table, conntrackTable, binding.TableMissActionNext),
			conntrackTable:        bridge.CreateTable(conntrackTable, conntrackStateTable, binding.TableMissActionNone),
			conntrackStateTable:   bridge.CreateTable(conntrackStateTable, dnatTable, binding.TableMissActionNext),
			dnatTable:             bridge.CreateTable(dnatTable, egressEntryTable, binding.TableMissActionNext),
			EgressRuleTable:       bridge.CreateTable(EgressRuleTable, EgressDefaultTable, binding.TableMissActionNext),
			EgressDefaultTable:    bridge.CreateTable(EgressDefaultTable, EgressMetricTable, binding.TableMissActionNext),
			EgressMetricTable:     bridge.CreateTable(EgressMetricTable, l3ForwardingTable, binding.TableMissActionNext),
			l3ForwardingTable:     bridge.CreateTable(l3ForwardingTable, l2ForwardingCalcTable, binding.TableMissActionNext),
			l2ForwardingCalcTable: bridge.CreateTable(l2ForwardingCalcTable, IngressEntryTable, binding.TableMissActionNext),
			IngressRuleTable:      bridge.CreateTable(IngressRuleTable, IngressDefaultTable, binding.TableMissActionNext),
			IngressDefaultTable:   bridge.CreateTable(IngressDefaultTable, IngressMetricTable, binding.TableMissActionNext),
			IngressMetricTable:    bridge.CreateTable(IngressMetricTable, conntrackCommitTable, binding.TableMissActionNext),
			conntrackCommitTable:  bridge.CreateTable(conntrackCommitTable, L2ForwardingOutTable, binding.TableMissActionNext),
			L2ForwardingOutTable:  bridge.CreateTable(L2ForwardingOutTable, binding.LastTableID, binding.TableMissActionDrop),
		}
	}
	if !enableAntreaNP {
		return pipeline
	}
	pipeline[AntreaPolicyEgressRuleTable] = bridge.CreateTable(AntreaPolicyEgressRuleTable, EgressRuleTable, binding.TableMissActionNext)
	pipeline[AntreaPolicyIngressRuleTable] = bridge.CreateTable(AntreaPolicyIngressRuleTable, IngressRuleTable, binding.TableMissActionNext)
	return pipeline
}

// NewClient is the constructor of the Client interface.
func NewClient(bridgeName, mgmtAddr string, enableProxy, enableAntreaPolicy bool) Client {
	bridge := binding.NewOFBridge(bridgeName, mgmtAddr)
	policyCache := cache.NewIndexer(
		policyConjKeyFunc,
		cache.Indexers{priorityIndex: priorityIndexFunc},
	)
	c := &client{
		bridge:                   bridge,
		pipeline:                 generatePipeline(bridge, enableProxy, enableAntreaPolicy),
		nodeFlowCache:            newFlowCategoryCache(),
		podFlowCache:             newFlowCategoryCache(),
		serviceFlowCache:         newFlowCategoryCache(),
		policyCache:              policyCache,
		groupCache:               sync.Map{},
		globalConjMatchFlowCache: map[string]*conjMatchFlowContext{},
		packetInHandlers:         map[uint8]map[string]PacketInHandler{},
		ovsctlClient:             ovsctl.NewClient(bridgeName),
	}
	c.ofEntryOperations = c
	c.enableProxy = enableProxy
	c.enableAntreaPolicy = enableAntreaPolicy
	return c
}
