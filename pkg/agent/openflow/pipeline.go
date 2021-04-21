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
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/contiv/libOpenflow/protocol"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/metrics"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow/cookie"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
	"github.com/vmware-tanzu/antrea/pkg/util/runtime"
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
	snatTable                    binding.TableIDType = 71
	l3DecTTLTable                binding.TableIDType = 72
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
		{l3ForwardingTable, "L3Forwarding"},
		{snatTable, "SNAT"},
		{l3DecTTLTable, "IPTTLDec"},
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
	// traffic-source resides in [0..15], pod-found resides in [16], Antrea Policy disposition in [21-22], Custom Reasons in [24-25]
	marksReg        regType = 0
	PortCacheReg    regType = 1
	swapReg         regType = 2
	endpointIPReg   regType = 3               // Use reg3 to store endpoint IP
	endpointPortReg regType = 4               // Use reg4[0..15] to store endpoint port
	serviceLearnReg         = endpointPortReg // Use reg4[16..18] to store endpoint selection states.
	EgressReg       regType = 5
	IngressReg      regType = 6
	TraceflowReg    regType = 9 // Use reg9[28..31] to store traceflow dataplaneTag.
	// CNPDenyConjIDReg reuses reg3 which will also be used for storing endpoint IP to store the rule ID. Since
	// the service selection will finish when a packet hitting NetworkPolicy related rules, there is no conflict.
	CNPDenyConjIDReg  regType = 3
	endpointIPv6XXReg regType = 3 // xxReg3 will occupy reg12-reg15
	// marksRegServiceNeedLB indicates a packet need to do service selection.
	marksRegServiceNeedLB uint32 = 0b001
	// marksRegServiceSelected indicates a packet has done service selection.
	marksRegServiceSelected uint32 = 0b010
	// marksRegServiceNeedLearn indicates a packet has done service selection and
	// the selection result needs to be cached.
	marksRegServiceNeedLearn uint32 = 0b011

	CtZone   = 0xfff0
	CtZoneV6 = 0xffe6

	portFoundMark = 0b1
	hairpinMark   = 0b1
	// macRewriteMark indicates the destination and source MACs of the
	// packet should be rewritten in the l3ForwardingTable.
	macRewriteMark = 0b1
	// cnpDenyMark indicates the packet is denied(Drop/Reject).
	cnpDenyMark = 0b1

	// gatewayCTMark is used to to mark connections initiated through the host gateway interface
	// (i.e. for which the first packet of the connection was received through the gateway).
	gatewayCTMark = 0x20
	ServiceCTMark = 0x21

	// disposition is loaded in marksReg [21-22]
	DispositionMarkReg regType = 0
	// disposition marks the flow action
	DispositionAllow = 0b00
	DispositionDrop  = 0b01
	DispositionRej   = 0b10

	// custom reason is loaded in marksReg [24-25]
	// The custom reason mark is used to indicate the reason(s) for sending the packet
	// to the controller. Reasons can be or-ed to indicate that the packets was sent
	// for multiple reasons.
	// For example, a value of 0b11 (CustomReasonLogging | CustomReasonReject) means
	// that the packet is sent to the controller both for NetworkPolicy logging and
	// because of a Reject action.
	CustomReasonMarkReg regType = 0
	// CustomReasonLogging is used when send packet-in to controller indicating this
	// packet need logging.
	CustomReasonLogging = 0b01
	// CustomReasonReject is not only used when send packet-in to controller indicating
	// that this packet should be rejected, but also used in the case that when
	// controller send reject packet as packet-out, we want reject response to bypass
	// the connTrack to avoid unexpected drop.
	CustomReasonReject = 0b10
)

var DispositionToString = map[uint32]string{
	DispositionAllow: "Allow",
	DispositionDrop:  "Drop",
	DispositionRej:   "Reject",
}

var (
	// ofPortMarkRange takes the 16th bit of register marksReg to indicate if the ofPort
	// number of an interface.
	// is found or not. Its value is 0x1 if yes.
	ofPortMarkRange = binding.Range{16, 16}
	// ofPortRegRange takes a 32-bit range of register PortCacheReg to cache the ofPort
	// number of the interface.
	ofPortRegRange = binding.Range{0, 31}
	// hairpinMarkRange takes the 18th bit of register marksReg to indicate
	// if the packet needs DNAT to virtual IP or not. Its value is 0x1 if yes.
	hairpinMarkRange = binding.Range{18, 18}
	// macRewriteMarkRange takes the 19th bit of register marksReg to indicate
	// if the packet's MAC addresses need to be rewritten. Its value is 0x1 if yes.
	macRewriteMarkRange = binding.Range{19, 19}
	// cnpDenyMarkRange takes the 20th bit of register marksReg to indicate
	// if the packet is denied(Drop/Reject). Its value is 0x1 if yes.
	cnpDenyMarkRange = binding.Range{20, 20}
	// APDispositionMarkRange takes the 21 to 22 bits of register marksReg to indicate
	// disposition of Antrea Policy. It could have more bits to support more disposition
	// that Antrea policy support in the future.
	APDispositionMarkRange = binding.Range{21, 22}
	// CustomReasonMarkRange takes the 24 to 25 bits of register marksReg to indicate
	// the reason of sending packet to the controller. It could have more bits to
	// support more customReason in the future.
	CustomReasonMarkRange = binding.Range{24, 25}
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

	// traceflowTagToSRange stores Traceflow dataplane tag to DSCP bits of
	// IP header ToS field.
	traceflowTagToSRange = binding.IPDSCPToSRange

	// snatPktMarkRange takes an 8-bit range of pkt_mark to store the ID of
	// a SNAT IP. The bit range must match SNATIPMarkMask.
	snatPktMarkRange = binding.Range{0, 7}

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

func portToUint16(port int) uint16 {
	if port > 0 && port <= math.MaxUint16 {
		return uint16(port) // lgtm[go/incorrect-integer-conversion]
	}
	klog.Errorf("Port value %d out-of-bounds", port)
	return 0
}

type client struct {
	enableProxy        bool
	enableAntreaPolicy bool
	enableEgress       bool
	roundInfo          types.RoundInfo
	cookieAllocator    cookie.Allocator
	bridge             binding.Bridge
	egressEntryTable   binding.TableIDType
	ingressEntryTable  binding.TableIDType
	pipeline           map[binding.TableIDType]binding.Table
	// Flow caches for corresponding deletions.
	nodeFlowCache, podFlowCache, serviceFlowCache, snatFlowCache, tfFlowCache *flowCategoryCache
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
	replayMutex   sync.RWMutex
	nodeConfig    *config.NodeConfig
	encapMode     config.TrafficEncapModeType
	gatewayOFPort uint32
	// ovsDatapathType is the type of the datapath used by the bridge.
	ovsDatapathType ovsconfig.OVSDatapathType
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
	if len(flows) == 0 {
		return nil
	}
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
func (c *client) gatewayClassifierFlow(category cookie.Category) binding.Flow {
	classifierTable := c.pipeline[ClassifierTable]
	return classifierTable.BuildFlow(priorityNormal).
		MatchInPort(config.HostGatewayOFPort).
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

// connectionTrackFlows generates flows that redirect traffic to ct_zone and handle traffic according to ct_state:
// 1) commit new connections to ct_zone(0xfff0) in the conntrackCommitTable.
// 2) Add ct_mark on the packet if it is sent to the switch from the host gateway.
// 3) Allow traffic if it hits ct_mark and is sent from the host gateway.
// 4) Drop all invalid traffic.
// 5) Let other traffic go to the sessionAffinityTable first and then the serviceLBTable.
//    The sessionAffinityTable is a side-effect table which means traffic will not
//    be resubmitted to any table. serviceLB does Endpoint selection for traffic
//    to a Service.
// 6) Add a flow to bypass reject response packet sent by the controller.
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
			// Add reject response packet bypass flow.
			c.conntrackBypassRejectFlow(proto),
		)
	}
	return flows
}

// conntrackBypassRejectFlow generates a flow which is used to bypass the reject
// response packet sent by the controller to avoid unexpected packet drop.
func (c *client) conntrackBypassRejectFlow(proto binding.Protocol) binding.Flow {
	connectionTrackStateTable := c.pipeline[conntrackStateTable]
	return connectionTrackStateTable.BuildFlow(priorityHigh).
		MatchProtocol(proto).
		MatchRegRange(int(marksReg), CustomReasonReject, CustomReasonMarkRange).
		Cookie(c.cookieAllocator.Request(cookie.Default).Raw()).
		Action().ResubmitToTable(connectionTrackStateTable.GetNext()).
		Done()
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

// TODO: Use DuplicateToBuilder or integrate this function into original one to avoid unexpected
// difference.
// traceflowConnectionTrackFlows generates Traceflow specific flows in the
// connectionTrackStateTable. When packet is not provided, the flows bypass the
// drop flow in connectionTrackFlows to avoid unexpected drop of the injected
// Traceflow packet, and to drop any Traceflow packet that has ct_state +rpl,
// which may happen when the Traceflow request destination is the Node's IP.
// When packet is provided, a flow is added to mark the first packet as the
// Traceflow packet, for the first connection that is initiated by srcOFPort
// and matches the provided packet.
func (c *client) traceflowConnectionTrackFlows(dataplaneTag uint8, packet *binding.Packet, srcOFPort uint32, timeout uint16, category cookie.Category) []binding.Flow {
	connectionTrackStateTable := c.pipeline[conntrackStateTable]
	var flows []binding.Flow
	if packet == nil {
		for _, ipProtocol := range c.ipProtocols {
			flowBuilder := connectionTrackStateTable.BuildFlow(priorityLow + 1).
				MatchProtocol(ipProtocol).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				Cookie(c.cookieAllocator.Request(category).Raw())
			if c.enableProxy {
				flowBuilder = flowBuilder.
					Action().ResubmitToTable(sessionAffinityTable).
					Action().ResubmitToTable(serviceLBTable)
			} else {
				flowBuilder = flowBuilder.
					Action().ResubmitToTable(connectionTrackStateTable.GetNext())
			}
			flows = append(flows, flowBuilder.Done())

			flows = append(flows, connectionTrackStateTable.BuildFlow(priorityLow+2).
				MatchProtocol(ipProtocol).
				MatchIPDSCP(dataplaneTag).
				MatchCTStateTrk(true).MatchCTStateRpl(true).
				SetHardTimeout(timeout).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Action().Drop().
				Done())
		}
	} else {
		flowBuilder := connectionTrackStateTable.BuildFlow(priorityLow).
			MatchInPort(srcOFPort).
			MatchCTStateNew(true).MatchCTStateTrk(true).
			SetHardTimeout(timeout).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Action().LoadIPDSCP(dataplaneTag)

		if packet.DestinationIP != nil {
			flowBuilder = flowBuilder.MatchDstIP(packet.DestinationIP)
		}
		// Match transport header
		switch packet.IPProto {
		case protocol.Type_ICMP:
			flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolICMP)
		case protocol.Type_IPv6ICMP:
			flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolICMPv6)
		case protocol.Type_TCP:
			if packet.IsIPv6 {
				flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolTCPv6)
			} else {
				flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolTCP)
			}
		case protocol.Type_UDP:
			if packet.IsIPv6 {
				flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolUDPv6)
			} else {
				flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolUDP)
			}
		default:
			flowBuilder = flowBuilder.MatchIPProtocolValue(packet.IsIPv6, packet.IPProto)

		}
		if packet.IPProto == protocol.Type_TCP || packet.IPProto == protocol.Type_UDP {
			if packet.DestinationPort != 0 {
				flowBuilder = flowBuilder.MatchDstPort(packet.DestinationPort, nil)
			}
			if packet.SourcePort != 0 {
				flowBuilder = flowBuilder.MatchSrcPort(packet.SourcePort, nil)
			}
		}

		if c.enableProxy {
			flowBuilder = flowBuilder.
				Action().ResubmitToTable(sessionAffinityTable).
				Action().ResubmitToTable(serviceLBTable)
		} else {
			flowBuilder = flowBuilder.
				Action().ResubmitToTable(connectionTrackStateTable.GetNext())
		}
		flows = []binding.Flow{flowBuilder.Done()}
	}
	return flows
}

func (c *client) traceflowNetworkPolicyFlows(dataplaneTag uint8, timeout uint16, category cookie.Category) []binding.Flow {
	flows := []binding.Flow{}
	c.conjMatchFlowLock.Lock()
	defer c.conjMatchFlowLock.Unlock()
	// Copy default drop rules.
	for _, ctx := range c.globalConjMatchFlowCache {
		if ctx.dropFlow != nil {
			copyFlowBuilder := ctx.dropFlow.CopyToBuilder(priorityNormal+2, false)
			if ctx.dropFlow.FlowProtocol() == "" {
				copyFlowBuilderIPv6 := ctx.dropFlow.CopyToBuilder(priorityNormal+2, false)
				copyFlowBuilderIPv6 = copyFlowBuilderIPv6.MatchProtocol(binding.ProtocolIPv6)
				flows = append(flows, copyFlowBuilderIPv6.MatchIPDSCP(dataplaneTag).
					SetHardTimeout(timeout).
					Cookie(c.cookieAllocator.Request(category).Raw()).
					Action().SendToController(uint8(PacketInReasonTF)).
					Done())
				copyFlowBuilder = copyFlowBuilder.MatchProtocol(binding.ProtocolIP)
			}
			flows = append(flows, copyFlowBuilder.MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Action().SendToController(uint8(PacketInReasonTF)).
				Done())
		}
	}
	// Copy Antrea NetworkPolicy drop rules.
	for _, conj := range c.policyCache.List() {
		for _, flow := range conj.(*policyRuleConjunction).metricFlows {
			if flow.IsDropFlow() {
				copyFlowBuilder := flow.CopyToBuilder(priorityNormal+2, false)
				// Generate both IPv4 and IPv6 flows if the original drop flow doesn't match IP/IPv6.
				// DSCP field is in IP/IPv6 headers so IP/IPv6 match is required in a flow.
				if flow.FlowProtocol() == "" {
					copyFlowBuilderIPv6 := flow.CopyToBuilder(priorityNormal+2, false)
					copyFlowBuilderIPv6 = copyFlowBuilderIPv6.MatchProtocol(binding.ProtocolIPv6)
					flows = append(flows, copyFlowBuilderIPv6.MatchIPDSCP(dataplaneTag).
						SetHardTimeout(timeout).
						Cookie(c.cookieAllocator.Request(category).Raw()).
						Action().SendToController(uint8(PacketInReasonTF)).
						Done())
					copyFlowBuilder = copyFlowBuilder.MatchProtocol(binding.ProtocolIP)
				}
				flows = append(flows, copyFlowBuilder.MatchIPDSCP(dataplaneTag).
					SetHardTimeout(timeout).
					Cookie(c.cookieAllocator.Request(category).Raw()).
					Action().SendToController(uint8(PacketInReasonTF)).
					Done())
			}
		}
	}
	return flows
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
	var flows []binding.Flow
	for _, proto := range c.ipProtocols {
		flows = append(flows, connectionTrackStateTable.BuildFlow(priorityNormal).MatchProtocol(proto).
			MatchCTMark(gatewayCTMark, nil).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			Action().SetDstMAC(gatewayMAC).
			Action().GotoTable(connectionTrackStateTable.GetNext()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return flows
}

// serviceLBBypassFlows makes packets that belong to a tracked connection bypass
// service LB tables and enter egressRuleTable directly.
func (c *client) serviceLBBypassFlows(ipProtocol binding.Protocol) []binding.Flow {
	connectionTrackStateTable := c.pipeline[conntrackStateTable]
	flows := []binding.Flow{
		// Tracked connections with the ServiceCTMark (load-balanced by AntreaProxy) receive
		// the macRewriteMark and are sent to egressRuleTable.
		connectionTrackStateTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
			MatchCTMark(ServiceCTMark, nil).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			Action().LoadRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
			Action().GotoTable(EgressRuleTable).
			Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
			Done(),
		// Tracked connections without the ServiceCTMark are sent to egressRuleTable
		// directly. This is meant to match connections which were load-balanced by
		// kube-proxy before AntreaProxy got enabled.
		connectionTrackStateTable.BuildFlow(priorityLow).MatchProtocol(ipProtocol).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			Action().GotoTable(EgressRuleTable).
			Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
			Done(),
	}

	if runtime.IsWindowsPlatform() && ipProtocol == binding.ProtocolIP {
		// Handle the reply packets of the connection which are applied both DNAT and SNAT.
		// The packets have following characteristics:
		//   - Received from uplink
		//   - ct_state is "-new+trk"
		//   - ct_mark is set to 0x21(ServiceCTMark)
		// This flow resubmits the packets to the following table to avoid being forwarded
		// to the bridge port by default.
		flows = append(flows, c.pipeline[conntrackStateTable].BuildFlow(priorityHigh).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			MatchCTMark(ServiceCTMark, nil).
			MatchRegRange(int(marksReg), markTrafficFromUplink, binding.Range{0, 15}).
			Action().LoadRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
			Action().GotoTable(EgressRuleTable).
			Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
			Done())
	}
	return flows
}

// l2ForwardCalcFlow generates the flow that matches dst MAC and loads ofPort to reg.
func (c *client) l2ForwardCalcFlow(dstMAC net.HardwareAddr, ofPort uint32, skipIngressRules bool, category cookie.Category) binding.Flow {
	l2FwdCalcTable := c.pipeline[l2ForwardingCalcTable]
	nextTable := l2FwdCalcTable.GetNext()
	if !skipIngressRules {
		// Go to ingress NetworkPolicy tables for traffic to local Pods.
		nextTable = c.ingressEntryTable
	}
	return l2FwdCalcTable.BuildFlow(priorityNormal).
		MatchDstMAC(dstMAC).
		Action().LoadRegRange(int(PortCacheReg), ofPort, ofPortRegRange).
		Action().LoadRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
		Action().GotoTable(nextTable).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
	// Broadcast, multicast, and unknown unicast packets will be dropped by
	// the default flow of L2ForwardingOutTable.
}

// traceflowL2ForwardOutputFlows generates Traceflow specific flows that outputs traceflow packets
// to OVS port and Antrea Agent after L2forwarding calculation.
func (c *client) traceflowL2ForwardOutputFlows(dataplaneTag uint8, liveTraffic, droppedOnly bool, timeout uint16, category cookie.Category) []binding.Flow {
	flows := []binding.Flow{}
	l2FwdOutTable := c.pipeline[L2ForwardingOutTable]
	for _, ipProtocol := range c.ipProtocols {
		if c.encapMode.SupportsEncap() {
			// SendToController and Output if output port is tunnel port.
			fb1 := l2FwdOutTable.BuildFlow(priorityNormal+3).
				MatchReg(int(PortCacheReg), config.DefaultTunOFPort).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				MatchProtocol(ipProtocol).
				MatchRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
				Action().OutputRegRange(int(PortCacheReg), ofPortRegRange).
				Cookie(c.cookieAllocator.Request(category).Raw())
			// For injected packets, only SendToController if output port is local
			// gateway. In encapMode, a Traceflow packet going out of the gateway
			// port (i.e. exiting the overlay) essentially means that the Traceflow
			// request is complete.
			fb2 := l2FwdOutTable.BuildFlow(priorityNormal+2).
				MatchReg(int(PortCacheReg), config.HostGatewayOFPort).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				MatchProtocol(ipProtocol).
				MatchRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
				Cookie(c.cookieAllocator.Request(category).Raw())

			// Do not send to controller if captures only dropped packet.
			if !droppedOnly {
				fb1 = fb1.Action().SendToController(uint8(PacketInReasonTF))
				fb2 = fb2.Action().SendToController(uint8(PacketInReasonTF))
			}
			if liveTraffic {
				// Clear the loaded DSCP bits before output.
				fb2 = fb2.Action().LoadIPDSCP(0).
					Action().OutputRegRange(int(PortCacheReg), ofPortRegRange)
			}
			flows = append(flows, fb1.Done(), fb2.Done())
		} else {
			// SendToController and Output if output port is local gateway. Unlike in
			// encapMode, inter-Node Pod-to-Pod traffic is expected to go out of the
			// gateway port on the way to its destination.
			fb1 := l2FwdOutTable.BuildFlow(priorityNormal+2).
				MatchReg(int(PortCacheReg), config.HostGatewayOFPort).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				MatchProtocol(ipProtocol).
				MatchRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
				Action().OutputRegRange(int(PortCacheReg), ofPortRegRange).
				Cookie(c.cookieAllocator.Request(category).Raw())
			if !droppedOnly {
				fb1 = fb1.Action().SendToController(uint8(PacketInReasonTF))
			}
			flows = append(flows, fb1.Done())
		}
		// Only SendToController if output port is local gateway and destination IP is gateway.
		gatewayIP := c.nodeConfig.GatewayConfig.IPv4
		if ipProtocol == binding.ProtocolIPv6 {
			gatewayIP = c.nodeConfig.GatewayConfig.IPv6
		}
		if gatewayIP != nil {
			fb := l2FwdOutTable.BuildFlow(priorityNormal+3).
				MatchReg(int(PortCacheReg), config.HostGatewayOFPort).
				MatchDstIP(gatewayIP).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				MatchProtocol(ipProtocol).
				MatchRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
				Cookie(c.cookieAllocator.Request(category).Raw())
			if !droppedOnly {
				fb = fb.Action().SendToController(uint8(PacketInReasonTF))
			}
			if liveTraffic {
				fb = fb.Action().LoadIPDSCP(0).
					Action().OutputRegRange(int(PortCacheReg), ofPortRegRange)
			}
			flows = append(flows, fb.Done())
		}
		// Only SendToController if output port is Pod port.
		fb := l2FwdOutTable.BuildFlow(priorityNormal+2).
			MatchIPDSCP(dataplaneTag).
			SetHardTimeout(timeout).
			MatchProtocol(ipProtocol).
			MatchRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
			Cookie(c.cookieAllocator.Request(category).Raw())
		if !droppedOnly {
			fb = fb.Action().SendToController(uint8(PacketInReasonTF))
		}
		if liveTraffic {
			fb = fb.Action().LoadIPDSCP(0).
				Action().OutputRegRange(int(PortCacheReg), ofPortRegRange)
		}
		flows = append(flows, fb.Done())
	}
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

// l2ForwardOutputFlows generates the flows that output packets to OVS port after L2 forwarding calculation.
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

// l3FwdFlowToPod generates the L3 forward flows for traffic from tunnel to a
// local Pod. It rewrites the destination MAC (should be globalVirtualMAC) to
// the Pod interface MAC, and rewrites the source MAC to the gateway interface
// MAC.
func (c *client) l3FwdFlowToPod(localGatewayMAC net.HardwareAddr, podInterfaceIPs []net.IP, podInterfaceMAC net.HardwareAddr, category cookie.Category) []binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	var flows []binding.Flow
	for _, ip := range podInterfaceIPs {
		ipProtocol := getIPProtocol(ip)
		flows = append(flows, l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
			MatchRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
			MatchDstIP(ip).
			Action().SetSrcMAC(localGatewayMAC).
			// Rewrite src MAC to local gateway MAC, and rewrite dst MAC to pod MAC
			Action().SetDstMAC(podInterfaceMAC).
			Action().GotoTable(l3DecTTLTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return flows
}

// l3FwdFlowRouteToPod generates the flows to route the traffic to a Pod based on
// the destination IP. It rewrites the destination MAC of the packets to the Pod
// interface MAC. The flow is used in the networkPolicyOnly mode for the traffic
// from the gateway to a local Pod.
func (c *client) l3FwdFlowRouteToPod(podInterfaceIPs []net.IP, podInterfaceMAC net.HardwareAddr, category cookie.Category) []binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	var flows []binding.Flow
	for _, ip := range podInterfaceIPs {
		ipProtocol := getIPProtocol(ip)
		flows = append(flows, l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
			MatchDstIP(ip).
			Action().SetDstMAC(podInterfaceMAC).
			Action().GotoTable(l3DecTTLTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return flows
}

// l3FwdFlowRouteToGW generates the flows to route the traffic to the gateway
// interface. It rewrites the destination MAC of the packets to the gateway
// interface MAC. The flow is used in the networkPolicyOnly mode for the traffic
// from a local Pod to remote Pods, Nodes, or external network.
func (c *client) l3FwdFlowRouteToGW(gwMAC net.HardwareAddr, category cookie.Category) []binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	var flows []binding.Flow
	for _, ipProto := range c.ipProtocols {
		flows = append(flows, l3FwdTable.BuildFlow(priorityLow).MatchProtocol(ipProto).
			Action().SetDstMAC(gwMAC).
			Action().GotoTable(l3FwdTable.GetNext()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		)
	}
	return flows
}

// l3FwdFlowToGateway generates the L3 forward flows for traffic from tunnel to
// the local gateway. It rewrites the destination MAC (should be
// globalVirtualMAC) of the packets to the gateway interface MAC.
func (c *client) l3FwdFlowToGateway(localGatewayIPs []net.IP, localGatewayMAC net.HardwareAddr, category cookie.Category) []binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	var flows []binding.Flow
	for _, ip := range localGatewayIPs {
		ipProtocol := getIPProtocol(ip)
		flows = append(flows, l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
			MatchRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
			MatchDstIP(ip).
			Action().SetDstMAC(localGatewayMAC).
			Action().GotoTable(l3FwdTable.GetNext()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return flows
}

// l3FwdFlowToRemote generates the L3 forward flow for traffic to a remote Node
// (Pods or gateway) through the tunnel.
func (c *client) l3FwdFlowToRemote(
	localGatewayMAC net.HardwareAddr,
	peerSubnet net.IPNet,
	tunnelPeer net.IP,
	category cookie.Category) binding.Flow {
	ipProto := getIPProtocol(peerSubnet.IP)
	return c.pipeline[l3ForwardingTable].BuildFlow(priorityNormal).MatchProtocol(ipProto).
		MatchDstIPNet(peerSubnet).
		// Rewrite src MAC to local gateway MAC and rewrite dst MAC to virtual MAC.
		Action().SetSrcMAC(localGatewayMAC).
		Action().SetDstMAC(globalVirtualMAC).
		// Flow based tunnel. Set tunnel destination.
		Action().SetTunnelDst(tunnelPeer).
		Action().GotoTable(l3DecTTLTable).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// l3FwdFlowToRemoteViaGW generates the L3 forward flow to support traffic to
// remote via gateway. It is used when the cross-Node traffic does not require
// encapsulation (in noEncap, networkPolicyOnly, or hybrid mode).
func (c *client) l3FwdFlowToRemoteViaGW(
	localGatewayMAC net.HardwareAddr,
	peerSubnet net.IPNet,
	category cookie.Category) binding.Flow {
	ipProto := getIPProtocol(peerSubnet.IP)
	l3FwdTable := c.pipeline[l3ForwardingTable]
	return l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(ipProto).
		MatchDstIPNet(peerSubnet).
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
func (c *client) gatewayARPSpoofGuardFlow(gatewayIP net.IP, gatewayMAC net.HardwareAddr, category cookie.Category) binding.Flow {
	return c.pipeline[spoofGuardTable].BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolARP).
		MatchInPort(config.HostGatewayOFPort).
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
func (c *client) gatewayIPSpoofGuardFlows(category cookie.Category) []binding.Flow {
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
				MatchInPort(config.HostGatewayOFPort).
				Action().GotoTable(nextTable).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
		)
	}
	return flows
}

// serviceCIDRDNATFlow generates flows to match dst IP in service CIDR and output to host gateway interface directly.
func (c *client) serviceCIDRDNATFlows(serviceCIDRs []*net.IPNet) []binding.Flow {
	var flows []binding.Flow
	for _, serviceCIDR := range serviceCIDRs {
		if serviceCIDR != nil {
			ipProto := getIPProtocol(serviceCIDR.IP)
			flows = append(flows, c.pipeline[dnatTable].BuildFlow(priorityNormal).MatchProtocol(ipProto).
				MatchDstIPNet(*serviceCIDR).
				Action().LoadRegRange(int(PortCacheReg), config.HostGatewayOFPort, ofPortRegRange).
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

func (c *client) denyRuleMetricFlow(conjunctionID uint32, ingress bool) binding.Flow {
	metricTableID := IngressMetricTable
	if !ingress {
		metricTableID = EgressMetricTable
	}
	return c.pipeline[metricTableID].BuildFlow(priorityNormal).
		MatchRegRange(int(marksReg), cnpDenyMark, cnpDenyMarkRange).
		MatchReg(int(CNPDenyConjIDReg), conjunctionID).
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
				Action().LoadRegRange(int(conjReg), conjunctionID, binding.Range{0, 31}).         // Traceflow.
				Action().LoadRegRange(int(marksReg), DispositionAllow, APDispositionMarkRange).   // AntreaPolicy.
				Action().LoadRegRange(int(marksReg), CustomReasonLogging, CustomReasonMarkRange). // Enable logging.
				Action().SendToController(uint8(PacketInReasonNP)).
				Action().CT(true, nextTable, ctZone). // CT action requires commit flag if actions other than NAT without arguments are specified.
				LoadToLabelRange(uint64(conjunctionID), &labelRange).
				CTDone().
				Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
				Done()
		} else {
			return c.pipeline[tableID].BuildFlow(ofPriority).MatchProtocol(proto).
				MatchConjID(conjunctionID).
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

// conjunctionActionDenyFlow generates the flow to mark the packet to be denied
// (dropped or rejected) if policyRuleConjunction ID is matched.
// Any matched flow will be dropped in corresponding metric tables.
func (c *client) conjunctionActionDenyFlow(conjunctionID uint32, tableID binding.TableIDType, priority *uint16, disposition uint32, enableLogging bool) binding.Flow {
	ofPriority := *priority
	metricTableID := IngressMetricTable
	if _, ok := egressTables[tableID]; ok {
		metricTableID = EgressMetricTable
	}

	flowBuilder := c.pipeline[tableID].BuildFlow(ofPriority).
		MatchConjID(conjunctionID).
		Action().LoadRegRange(int(CNPDenyConjIDReg), conjunctionID, binding.Range{0, 31}).
		Action().LoadRegRange(int(marksReg), cnpDenyMark, cnpDenyMarkRange)

	if enableLogging {
		customReason := CustomReasonLogging
		if disposition == DispositionRej {
			customReason += CustomReasonReject
		}
		flowBuilder = flowBuilder.
			Action().LoadRegRange(int(marksReg), disposition, APDispositionMarkRange).
			Action().LoadRegRange(int(marksReg), uint32(customReason), CustomReasonMarkRange).
			Action().SendToController(uint8(PacketInReasonNP))
	} else if disposition == DispositionRej {
		flowBuilder = flowBuilder.
			Action().LoadRegRange(int(marksReg), CustomReasonReject, CustomReasonMarkRange). // Do the rejection.
			Action().SendToController(uint8(PacketInReasonNP))
	}

	// We do not drop the packet immediately but send the packet to the metric table to update the rule metrics.
	return flowBuilder.Action().GotoTable(metricTableID).
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
		portValue := matchValue.(types.BitRange)
		if portValue.Value > 0 {
			fb = fb.MatchDstPort(portValue.Value, portValue.Mask)
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

// localProbeFlow generates the flow to forward locally generated packets to conntrackCommitTable, bypassing ingress
// rules of Network Policies. The packets are sent by kubelet to probe the liveness/readiness of local Pods.
// On Linux and when OVS kernel datapath is used, it identifies locally generated packets by matching the
// HostLocalSourceMark, otherwise it matches the source IP. The difference is because:
// 1. On Windows, kube-proxy userspace mode is used, and currently there is no way to distinguish kubelet generated
//    traffic from kube-proxy proxied traffic.
// 2. pkt_mark field is not properly supported for OVS userspace (netdev) datapath.
// Note that there is a defect in the latter way that NodePort Service access by external clients will be masqueraded as
// a local gateway IP to bypass Network Policies. See https://github.com/vmware-tanzu/antrea/issues/280.
// TODO: Fix it after replacing kube-proxy with AntreaProxy.
func (c *client) localProbeFlow(localGatewayIPs []net.IP, category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	if runtime.IsWindowsPlatform() || c.ovsDatapathType == ovsconfig.OVSDatapathNetdev {
		for _, ip := range localGatewayIPs {
			ipProtocol := getIPProtocol(ip)
			flows = append(flows, c.pipeline[IngressRuleTable].BuildFlow(priorityHigh).
				MatchProtocol(ipProtocol).
				MatchSrcIP(ip).
				Action().GotoTable(conntrackCommitTable).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done())
		}
	} else {
		flows = append(flows, c.pipeline[IngressRuleTable].BuildFlow(priorityHigh).
			MatchPktMark(types.HostLocalSourceMark, &types.HostLocalSourceMark).
			Action().GotoTable(conntrackCommitTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return flows
}

// snatCommonFlows installs the default flows for performing SNAT for traffic to
// the external network. The flows identify the packets to external, and send
// them to snatTable, where SNAT IPs are looked up for the packets.
func (c *client) snatCommonFlows(nodeIP net.IP, localSubnet net.IPNet, localGatewayMAC net.HardwareAddr, category cookie.Category) []binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	nextTable := l3FwdTable.GetNext()
	ipProto := getIPProtocol(localSubnet.IP)
	flows := []binding.Flow{
		// First install flows for traffic that should bypass SNAT.
		// This flow is for traffic to the local Pod subnet.
		l3FwdTable.BuildFlow(priorityNormal).
			MatchProtocol(ipProto).
			MatchRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
			MatchDstIPNet(localSubnet).
			Action().GotoTable(nextTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// This flow is for the traffic to the local Node IP.
		l3FwdTable.BuildFlow(priorityNormal).
			MatchProtocol(ipProto).
			MatchRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
			MatchDstIP(nodeIP).
			Action().GotoTable(nextTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// This flow is for the return traffic of connections to a local
		// Pod through the gateway interface (so gatewayCTMark is set).
		// For example, the return traffic of a connection from an IP
		// address (not the Node's management IP or gateway interface IP
		// which are covered by other flows already) of the local Node
		// to a local Pod. It might also catch the Service return
		// traffic from a local server Pod, but this case is also
		// covered by other flows (the flows matching the local and
		// remote Pod subnets) anyway.
		l3FwdTable.BuildFlow(priorityNormal).
			MatchProtocol(ipProto).
			MatchRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
			MatchCTMark(gatewayCTMark, nil).
			Action().GotoTable(nextTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),

		// Send the traffic to external to snatTable.
		l3FwdTable.BuildFlow(priorityLow).
			MatchProtocol(ipProto).
			MatchRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
			Action().GotoTable(snatTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// For the traffic tunneled from remote Nodes, rewrite the
		// destination MAC to the gateway interface MAC.
		l3FwdTable.BuildFlow(priorityLow).
			MatchProtocol(ipProto).
			MatchRegRange(int(marksReg), markTrafficFromTunnel, binding.Range{0, 15}).
			Action().SetDstMAC(localGatewayMAC).
			Action().GotoTable(snatTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),

		// Drop the traffic from remote Nodes if no matched SNAT policy.
		c.pipeline[snatTable].BuildFlow(priorityLow).
			MatchProtocol(ipProto).
			MatchCTStateNew(true).MatchCTStateTrk(true).
			MatchRegRange(int(marksReg), markTrafficFromTunnel, binding.Range{0, 15}).
			Action().Drop().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	}
	return flows
}

// snatIPFromTunnelFlow generates a flow that marks SNAT packets tunnelled from
// remote Nodes. The SNAT IP matches the packet's tunnel destination IP.
func (c *client) snatIPFromTunnelFlow(snatIP net.IP, mark uint32) binding.Flow {
	ipProto := getIPProtocol(snatIP)
	return c.pipeline[snatTable].BuildFlow(priorityNormal).
		MatchProtocol(ipProto).
		MatchCTStateNew(true).MatchCTStateTrk(true).
		MatchTunnelDst(snatIP).
		Action().LoadPktMarkRange(mark, snatPktMarkRange).
		Action().GotoTable(l3DecTTLTable).
		Cookie(c.cookieAllocator.Request(cookie.SNAT).Raw()).
		Done()
}

// snatRuleFlow generates a flow that applies the SNAT rule for a local Pod. If
// the SNAT IP exists on the lcoal Node, it sets the packet mark with the ID of
// the SNAT IP, for the traffic from the ofPort to external; if the SNAT IP is
// on a remote Node, it tunnels the packets to the SNAT IP.
func (c *client) snatRuleFlow(ofPort uint32, snatIP net.IP, snatMark uint32, localGatewayMAC net.HardwareAddr) binding.Flow {
	ipProto := getIPProtocol(snatIP)
	snatTable := c.pipeline[snatTable]
	if snatMark != 0 {
		// Local SNAT IP.
		return snatTable.BuildFlow(priorityNormal).
			MatchProtocol(ipProto).
			MatchCTStateNew(true).MatchCTStateTrk(true).
			MatchInPort(ofPort).
			Action().LoadPktMarkRange(snatMark, snatPktMarkRange).
			Action().GotoTable(snatTable.GetNext()).
			Cookie(c.cookieAllocator.Request(cookie.SNAT).Raw()).
			Done()
	} else {
		// SNAT IP should be on a remote Node.
		return snatTable.BuildFlow(priorityNormal).
			MatchProtocol(ipProto).
			MatchInPort(ofPort).
			Action().SetSrcMAC(localGatewayMAC).
			Action().SetDstMAC(globalVirtualMAC).
			// Set tunnel destination to the SNAT IP.
			Action().SetTunnelDst(snatIP).
			Action().GotoTable(l3DecTTLTable).
			Cookie(c.cookieAllocator.Request(cookie.SNAT).Raw()).
			Done()
	}
}

// loadBalancerServiceFromOutsideFlow generates the flow to forward LoadBalancer service traffic from outside node
// to gateway. kube-proxy will then handle the traffic.
// This flow is for Windows Node only.
func (c *client) loadBalancerServiceFromOutsideFlow(svcIP net.IP, svcPort uint16, protocol binding.Protocol) binding.Flow {
	return c.pipeline[uplinkTable].BuildFlow(priorityHigh).
		MatchProtocol(protocol).
		MatchDstPort(svcPort, nil).
		MatchRegRange(int(marksReg), markTrafficFromUplink, binding.Range{0, 15}).
		MatchDstIP(svcIP).
		Action().Output(config.HostGatewayOFPort).
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
func (c *client) serviceLBFlow(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol, withSessionAffinity bool) binding.Flow {
	var lbResultMark uint32
	if withSessionAffinity {
		lbResultMark = marksRegServiceNeedLearn
	} else {
		lbResultMark = marksRegServiceSelected
	}

	return c.pipeline[serviceLBTable].BuildFlow(priorityNormal).
		MatchProtocol(protocol).
		MatchDstPort(svcPort, nil).
		MatchDstIP(svcIP).
		MatchRegRange(int(serviceLearnReg), marksRegServiceNeedLB, serviceLearnRegRange).
		Action().LoadRegRange(int(serviceLearnReg), lbResultMark, serviceLearnRegRange).
		Action().LoadRegRange(int(marksReg), macRewriteMark, macRewriteMarkRange).
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
	if withSessionAffinity {
		resubmitTableID = serviceLBTable
	} else {
		resubmitTableID = endpointDNATTable
	}

	for _, endpoint := range endpoints {
		endpointPort, _ := endpoint.Port()
		endpointIP := net.ParseIP(endpoint.IP())
		portVal := portToUint16(endpointPort)
		ipProtocol := getIPProtocol(endpointIP)
		if ipProtocol == binding.ProtocolIP {
			ipVal := binary.BigEndian.Uint32(endpointIP.To4())
			group = group.Bucket().Weight(100).
				LoadReg(int(endpointIPReg), ipVal).
				LoadRegRange(int(endpointPortReg), uint32(portVal), endpointPortRegRange).
				ResubmitToTable(resubmitTableID).
				Done()
		} else if ipProtocol == binding.ProtocolIPv6 {
			ipVal := []byte(endpointIP)
			group = group.Bucket().Weight(100).
				LoadXXReg(int(endpointIPv6XXReg), ipVal).
				LoadRegRange(int(endpointPortReg), uint32(portVal), endpointPortRegRange).
				ResubmitToTable(resubmitTableID).
				Done()
		}
	}
	return group
}

// decTTLFlows decrements TTL by one for the packets forwarded across Nodes.
// The TTL decrement should be skipped for the packets which enter OVS pipeline
// from the gateway interface, as the host IP stack should have decremented the
// TTL already for such packets.
func (c *client) decTTLFlows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	decTTLTable := c.pipeline[l3DecTTLTable]
	for _, proto := range c.ipProtocols {
		flows = append(flows,
			// Skip packets from the gateway interface.
			decTTLTable.BuildFlow(priorityHigh).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(proto).
				MatchRegRange(int(marksReg), markTrafficFromGateway, binding.Range{0, 15}).
				Action().GotoTable(decTTLTable.GetNext()).
				Done(),
			decTTLTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(proto).
				Action().DecTTL().
				Action().GotoTable(decTTLTable.GetNext()).
				Done(),
		)
	}
	return flows
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

func (c *client) generatePipeline() {
	bridge := c.bridge
	c.pipeline = map[binding.TableIDType]binding.Table{
		ClassifierTable:       bridge.CreateTable(ClassifierTable, spoofGuardTable, binding.TableMissActionDrop),
		arpResponderTable:     bridge.CreateTable(arpResponderTable, binding.LastTableID, binding.TableMissActionDrop),
		conntrackTable:        bridge.CreateTable(conntrackTable, conntrackStateTable, binding.TableMissActionNone),
		EgressRuleTable:       bridge.CreateTable(EgressRuleTable, EgressDefaultTable, binding.TableMissActionNext),
		EgressDefaultTable:    bridge.CreateTable(EgressDefaultTable, EgressMetricTable, binding.TableMissActionNext),
		EgressMetricTable:     bridge.CreateTable(EgressMetricTable, l3ForwardingTable, binding.TableMissActionNext),
		l3ForwardingTable:     bridge.CreateTable(l3ForwardingTable, l2ForwardingCalcTable, binding.TableMissActionNext),
		l3DecTTLTable:         bridge.CreateTable(l3DecTTLTable, l2ForwardingCalcTable, binding.TableMissActionNext),
		l2ForwardingCalcTable: bridge.CreateTable(l2ForwardingCalcTable, conntrackCommitTable, binding.TableMissActionNext),
		IngressRuleTable:      bridge.CreateTable(IngressRuleTable, IngressDefaultTable, binding.TableMissActionNext),
		IngressDefaultTable:   bridge.CreateTable(IngressDefaultTable, IngressMetricTable, binding.TableMissActionNext),
		IngressMetricTable:    bridge.CreateTable(IngressMetricTable, conntrackCommitTable, binding.TableMissActionNext),
		L2ForwardingOutTable:  bridge.CreateTable(L2ForwardingOutTable, binding.LastTableID, binding.TableMissActionDrop),
	}
	if c.enableProxy {
		c.pipeline[spoofGuardTable] = bridge.CreateTable(spoofGuardTable, serviceHairpinTable, binding.TableMissActionDrop)
		c.pipeline[ipv6Table] = bridge.CreateTable(ipv6Table, serviceHairpinTable, binding.TableMissActionNext)
		c.pipeline[serviceHairpinTable] = bridge.CreateTable(serviceHairpinTable, conntrackTable, binding.TableMissActionNext)
		c.pipeline[conntrackStateTable] = bridge.CreateTable(conntrackStateTable, endpointDNATTable, binding.TableMissActionNext)
		c.pipeline[sessionAffinityTable] = bridge.CreateTable(sessionAffinityTable, binding.LastTableID, binding.TableMissActionNone)
		c.pipeline[serviceLBTable] = bridge.CreateTable(serviceLBTable, endpointDNATTable, binding.TableMissActionNext)
		c.pipeline[endpointDNATTable] = bridge.CreateTable(endpointDNATTable, c.egressEntryTable, binding.TableMissActionNext)
		c.pipeline[conntrackCommitTable] = bridge.CreateTable(conntrackCommitTable, hairpinSNATTable, binding.TableMissActionNext)
		c.pipeline[hairpinSNATTable] = bridge.CreateTable(hairpinSNATTable, L2ForwardingOutTable, binding.TableMissActionNext)
	} else {
		c.pipeline[spoofGuardTable] = bridge.CreateTable(spoofGuardTable, conntrackTable, binding.TableMissActionDrop)
		c.pipeline[ipv6Table] = bridge.CreateTable(ipv6Table, conntrackTable, binding.TableMissActionNext)
		c.pipeline[conntrackStateTable] = bridge.CreateTable(conntrackStateTable, dnatTable, binding.TableMissActionNext)
		c.pipeline[dnatTable] = bridge.CreateTable(dnatTable, c.egressEntryTable, binding.TableMissActionNext)
		c.pipeline[conntrackCommitTable] = bridge.CreateTable(conntrackCommitTable, L2ForwardingOutTable, binding.TableMissActionNext)
	}
	// The default SNAT is implemented with OVS on Windows.
	if c.enableEgress || runtime.IsWindowsPlatform() {
		c.pipeline[snatTable] = bridge.CreateTable(snatTable, l2ForwardingCalcTable, binding.TableMissActionNext)
	}
	if runtime.IsWindowsPlatform() {
		c.pipeline[uplinkTable] = bridge.CreateTable(uplinkTable, spoofGuardTable, binding.TableMissActionNone)
	}
	if c.enableAntreaPolicy {
		c.pipeline[AntreaPolicyEgressRuleTable] = bridge.CreateTable(AntreaPolicyEgressRuleTable, EgressRuleTable, binding.TableMissActionNext)
		c.pipeline[AntreaPolicyIngressRuleTable] = bridge.CreateTable(AntreaPolicyIngressRuleTable, IngressRuleTable, binding.TableMissActionNext)
	}
}

// NewClient is the constructor of the Client interface.
func NewClient(bridgeName, mgmtAddr string, ovsDatapathType ovsconfig.OVSDatapathType, enableProxy, enableAntreaPolicy, enableEgress bool) Client {
	bridge := binding.NewOFBridge(bridgeName, mgmtAddr)
	policyCache := cache.NewIndexer(
		policyConjKeyFunc,
		cache.Indexers{priorityIndex: priorityIndexFunc},
	)
	c := &client{
		bridge:                   bridge,
		enableProxy:              enableProxy,
		enableAntreaPolicy:       enableAntreaPolicy,
		enableEgress:             enableEgress,
		nodeFlowCache:            newFlowCategoryCache(),
		podFlowCache:             newFlowCategoryCache(),
		serviceFlowCache:         newFlowCategoryCache(),
		tfFlowCache:              newFlowCategoryCache(),
		policyCache:              policyCache,
		groupCache:               sync.Map{},
		globalConjMatchFlowCache: map[string]*conjMatchFlowContext{},
		packetInHandlers:         map[uint8]map[string]PacketInHandler{},
		ovsctlClient:             ovsctl.NewClient(bridgeName),
		ovsDatapathType:          ovsDatapathType,
	}
	c.ofEntryOperations = c
	if enableAntreaPolicy {
		c.egressEntryTable, c.ingressEntryTable = AntreaPolicyEgressRuleTable, AntreaPolicyIngressRuleTable
	} else {
		c.egressEntryTable, c.ingressEntryTable = EgressRuleTable, IngressRuleTable
	}
	if enableEgress {
		c.snatFlowCache = newFlowCategoryCache()
	}
	c.generatePipeline()
	return c
}
