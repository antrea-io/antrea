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
	"sort"
	"sync"
	"time"

	"antrea.io/libOpenflow/openflow13"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/ofnet/ofctrl"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	"antrea.io/antrea/pkg/agent/types"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/util/runtime"
	"antrea.io/antrea/third_party/proxy"
)

var (
	//      _   _   _             _   _               _
	//     / \ | |_| |_ ___ _ __ | |_(_) ___  _ __   | |
	//    / _ \| __| __/ _ \ '_ \| __| |/ _ \| '_ \  | |
	//   / ___ \ |_| ||  __/ | | | |_| | (_) | | | | |_|
	//  /_/   \_\__|\__\___|_| |_|\__|_|\___/|_| |_| (_)
	//
	// Before adding a new table in FlexiblePipeline, please read the following instructions carefully.
	//
	// - Double confirm the necessity of adding a new table, and consider reusing an existing table to implement the
	//   functionality alternatively.
	// - Choose a name that can help users to understand the function of the table.
	// - Choose a stage. Existing stageIDs are defined in file pkg/agent/openflow/framework.go. If you want to add a new
	//   stage, please discuss with maintainers or OVS pipeline developers of Antrea.
	// - Choose a pipeline. Existing pipelineIDs are defined in file pkg/agent/openflow/framework.go. If you want to add
	//   a new pipeline, please discuss with maintainers or OVS pipeline developers of Antrea.
	// - Decide where to add the new table in the pipeline. The order table declaration decides the order of tables in the
	//   stage. For example:
	//     * If you want to add a table called `FooTable` between `SpoofGuardTable` and `IPv6Table` in pipelineIP, then
	//       the table should be declared after `SpoofGuardTable` and before `IPv6Table`:
	//       ```go
	//          SpoofGuardTable  = newTable("SpoofGuard", stageValidation, pipelineIP)
	//          FooTable         = newTable("Foo", stageValidation, pipelineIP)
	//          IPv6Table        = newTable("IPv6", stageValidation, pipelineIP)
	//       ```
	//      * If you want to add a table called `FooTable` just before `ARPResponderTable` in pipelineARP, then the table
	//        should be declared before `ARPResponderTable`:
	//       ```go
	//          FooTable          = newTable("Foo", stageOutput, binding.PipelineARP)
	//          ARPResponderTable = newTable("ARPResponder", stageOutput, binding.PipelineARP)
	//       ```
	//       * If you want to add a table called `FooTable` just after `ConntrackStateTable` in pipelineARP, then the
	//         table should be declared after `ConntrackStateTable`:
	//       ```go
	//          SNATConntrackTable  = newTable("SNATConntrackZone", stageConntrackState, pipelineIP)
	//          ConntrackTable      = newTable("ConntrackZone", stageConntrackState, pipelineIP)
	//          ConntrackStateTable = newTable("ConntrackState", stageConntrackState, pipelineIP)
	//          FooTable            = newTable("Foo", stageConntrackState, pipelineIP)
	//       ```
	//  - Reference the new table in a feature in file pkg/agent/openflow/framework.go. The table can be referenced by multiple
	//    features if multiple features need to install flows in the table. Note that, if the newly added table is not
	//    referenced by any feature or the features referencing the table are all inactivated, then the table will not
	//    be realized in OVS; if at least one feature referencing the table is activated, then the table will be realized
	//    at the desired position in OVS pipeline.
	//  - By default, the miss action of the new table is to forward packets to next table. If the miss action needs to
	//    drop packets, add argument defaultDrop when creating the new table.
	//
	// How to forward packet between tables with a proper action in FlexiblePipeline?
	//
	// |   table A   | |   table B   | |   table C   | |   table D   | |   table E   | |   table F   | |   table G   |
	// |   stage S1  | |                           stage S2                          | |          stage S4           |
	//
	//  - NextTable is used to forward packets to the next table. E.g. A -> B, B -> C, C -> D, etc.
	//  - GotoTable is used to forward packets to a specific table, and the target table ID should be greater than the
	//    current table ID. Within a stage, GotoTable should be used to forward packets to a specific table, e.g. B -> D,
	//    C -> E. Today we do not have the case, but if in future there is a case that a packet needs to be forwarded to
	//    a table in another stage directly, e.g. A -> C, B -> G, GotoTable can also be used.
	//  - GotoStage is used to forward packets to a specific stage. Note that, packets are forwarded to the first table of
	//    the target stage, and the first table ID of the target stage should be greater than the current table ID. E.g.
	//    A -> S4 (F), D -> S4 (F) are fine, but D -> S1 (A), F -> S2 (B) are not allowed. It is recommended to use
	//    GotoStage to forward packets across stages.
	//  - ResubmitToTables is used to forward packets to one or multiple tables. It should be used only when the target
	//    table ID is smaller than the current table ID, like E -> B; or when forwarding packets to multiple tables,
	//    like B - > D E; otherwise, in all other cases GotoTable should be used.

	// Tables of PipelineRoot are declared below.

	// PipelineRootClassifierTable is the only table of pipelineRoot at this moment and its table ID should be 0. Packets
	// are forwarded to pipelineIP or pipelineARP in this table.
	PipelineRootClassifierTable = newTable("PipelineRootClassifier", stageStart, pipelineRoot, defaultDrop)

	// Tables of pipelineARP are declared below.

	// Tables in stageValidation:
	ARPSpoofGuardTable = newTable("ARPSpoofGuard", stageValidation, pipelineARP)

	// Tables in stageOutput:
	ARPResponderTable = newTable("ARPResponder", stageOutput, pipelineARP)

	// Tables of pipelineIP are declared below.

	// Tables in stageClassifier:
	ClassifierTable = newTable("Classifier", stageClassifier, pipelineIP, defaultDrop)

	// Tables in stageValidation:
	SpoofGuardTable           = newTable("SpoofGuard", stageValidation, pipelineIP, defaultDrop)
	IPv6Table                 = newTable("IPv6", stageValidation, pipelineIP)
	PipelineIPClassifierTable = newTable("PipelineIPClassifier", stageValidation, pipelineIP)

	// Tables in stageConntrackState:
	SNATConntrackTable  = newTable("SNATConntrackZone", stageConntrackState, pipelineIP)
	ConntrackTable      = newTable("ConntrackZone", stageConntrackState, pipelineIP)
	ConntrackStateTable = newTable("ConntrackState", stageConntrackState, pipelineIP)

	// Tables in stagePreRouting:
	// When proxy is enabled.
	PreRoutingClassifierTable = newTable("PreRoutingClassifier", stagePreRouting, pipelineIP)
	NodePortMarkTable         = newTable("NodePortMark", stagePreRouting, pipelineIP)
	SessionAffinityTable      = newTable("SessionAffinity", stagePreRouting, pipelineIP)
	ServiceLBTable            = newTable("ServiceLB", stagePreRouting, pipelineIP)
	EndpointDNATTable         = newTable("EndpointDNAT", stagePreRouting, pipelineIP)
	// When proxy is disabled.
	DNATTable = newTable("DNAT", stagePreRouting, pipelineIP)

	// Tables in stageEgressSecurity:
	AntreaPolicyEgressRuleTable = newTable("AntreaPolicyEgressRule", stageEgressSecurity, pipelineIP)
	EgressRuleTable             = newTable("EgressRule", stageEgressSecurity, pipelineIP)
	EgressDefaultTable          = newTable("EgressDefaultRule", stageEgressSecurity, pipelineIP)
	EgressMetricTable           = newTable("EgressMetric", stageEgressSecurity, pipelineIP)

	// Tables in stageRouting:
	L3ForwardingTable = newTable("L3Forwarding", stageRouting, pipelineIP)
	EgressMarkTable   = newTable("EgressMark", stageRouting, pipelineIP)
	L3DecTTLTable     = newTable("L3DecTTL", stageRouting, pipelineIP)

	// Tables in stagePostRouting:
	ServiceMarkTable         = newTable("ServiceMark", stagePostRouting, pipelineIP)
	SNATConntrackCommitTable = newTable("SNATConntrackCommit", stagePostRouting, pipelineIP)

	// Tables in stageSwitching:
	L2ForwardingCalcTable = newTable("L2ForwardingCalc", stageSwitching, pipelineIP)

	// Tables in stageIngressSecurity:
	IngressSecurityClassifierTable = newTable("IngressSecurityClassifier", stageIngressSecurity, pipelineIP)
	AntreaPolicyIngressRuleTable   = newTable("AntreaPolicyIngressRule", stageIngressSecurity, pipelineIP)
	IngressRuleTable               = newTable("IngressRule", stageIngressSecurity, pipelineIP)
	IngressDefaultTable            = newTable("IngressDefaultRule", stageIngressSecurity, pipelineIP)
	IngressMetricTable             = newTable("IngressMetric", stageIngressSecurity, pipelineIP)

	// Tables in stageConntrack:
	ConntrackCommitTable = newTable("ConntrackCommit", stageConntrack, pipelineIP)

	// Tables in stageOutput:
	VLANTable            = newTable("VLAN", stageOutput, pipelineIP)
	L2ForwardingOutTable = newTable("Output", stageOutput, pipelineIP)

	// Tables of pipelineMulticast are declared below. Do don't declare any tables of other pipelines here!

	// Tables in stageRouting:
	MulticastTable = newTable("Multicast", stageRouting, pipelineMulticast)

	// Flow priority level
	priorityHigh            = uint16(210)
	priorityNormal          = uint16(200)
	priorityLow             = uint16(190)
	priorityMiss            = uint16(0)
	priorityTopAntreaPolicy = uint16(64990)
	priorityDNSIntercept    = uint16(64991)
	priorityDNSBypass       = uint16(64992)

	// Index for priority cache
	priorityIndex = "priority"

	// IPv6 multicast prefix
	ipv6MulticastAddr = "FF00::/8"
	// IPv6 link-local prefix
	ipv6LinkLocalAddr = "FE80::/10"

	// Operation field values in ARP packets
	arpOpRequest = uint16(1)
	arpOpReply   = uint16(2)

	tableNameIndex = "tableNameIndex"
)

type ofAction int32

const (
	add ofAction = iota
	mod
	del
)

func (a ofAction) String() string {
	switch a {
	case add:
		return "add"
	case mod:
		return "modify"
	case del:
		return "delete"
	default:
		return "unknown"
	}
}

// tableCache caches the OpenFlow tables used in pipelines, and it supports using the table ID and name as the index to query the OpenFlow table.
var tableCache = cache.NewIndexer(tableIDKeyFunc, cache.Indexers{tableNameIndex: tableNameIndexFunc})

func tableNameIndexFunc(obj interface{}) ([]string, error) {
	table := obj.(*Table)
	return []string{table.GetName()}, nil
}

func tableIDKeyFunc(obj interface{}) (string, error) {
	table := obj.(*Table)
	return fmt.Sprintf("%d", table.GetID()), nil
}

func getTableByID(id uint8) binding.Table {
	obj, exists, _ := tableCache.GetByKey(fmt.Sprintf("%d", id))
	if !exists {
		return nil
	}
	return obj.(*Table).ofTable
}

// GetFlowTableName returns the flow table name given the table ID. An empty
// string is returned if the table cannot be found.
func GetFlowTableName(tableID uint8) string {
	table := getTableByID(tableID)
	if table == nil {
		return ""
	}
	return table.GetName()
}

// GetFlowTableID does a case insensitive lookup of the table name, and
// returns the flow table number if the table is found. Otherwise TableIDAll is
// returned if the table cannot be found.
func GetFlowTableID(tableName string) uint8 {
	objs, _ := tableCache.ByIndex(tableNameIndex, tableName)
	if len(objs) == 0 {
		return binding.TableIDAll
	}
	return objs[0].(binding.Table).GetID()
}

func GetTableList() []binding.Table {
	tables := make([]binding.Table, 0)
	for _, obj := range tableCache.List() {
		t := obj.(binding.Table)
		tables = append(tables, t)
	}
	return tables
}

func GetAntreaPolicyEgressTables() []*Table {
	return []*Table{
		AntreaPolicyEgressRuleTable,
		EgressDefaultTable,
	}
}

func GetAntreaPolicyIngressTables() []*Table {
	return []*Table{
		AntreaPolicyIngressRuleTable,
		IngressDefaultTable,
	}
}

func GetAntreaPolicyBaselineTierTables() []*Table {
	return []*Table{
		EgressDefaultTable,
		IngressDefaultTable,
	}
}

func GetAntreaPolicyMultiTierTables() []*Table {
	return []*Table{
		AntreaPolicyEgressRuleTable,
		AntreaPolicyIngressRuleTable,
	}
}

const (
	CtZone       = 0xfff0
	CtZoneV6     = 0xffe6
	SNATCtZone   = 0xfff1
	SNATCtZoneV6 = 0xffe7

	// disposition values used in AP
	DispositionAllow = 0b00
	DispositionDrop  = 0b01
	DispositionRej   = 0b10
	DispositionPass  = 0b11

	// CustomReasonLogging is used when send packet-in to controller indicating this
	// packet need logging.
	CustomReasonLogging = 0b01
	// CustomReasonReject is not only used when send packet-in to controller indicating
	// that this packet should be rejected, but also used in the case that when
	// controller send reject packet as packet-out, we want reject response to bypass
	// the connTrack to avoid unexpected drop.
	CustomReasonReject = 0b10
	// CustomReasonDeny is used when sending packet-in message to controller indicating
	// that the corresponding connection has been dropped or rejected. It can be consumed
	// by the Flow Exporter to export flow records for connections denied by network
	// policy rules.
	CustomReasonDeny = 0b100
	CustomReasonDNS  = 0b1000
	CustomReasonIGMP = 0b10000

	// EtherTypeDot1q is used when adding 802.1Q VLAN header in OVS action
	EtherTypeDot1q = 0x8100
)

var DispositionToString = map[uint32]string{
	DispositionAllow: "Allow",
	DispositionDrop:  "Drop",
	DispositionRej:   "Reject",
	DispositionPass:  "Pass",
}

var (
	// traceflowTagToSRange stores Traceflow dataplane tag to DSCP bits of
	// IP header ToS field.
	traceflowTagToSRange = binding.IPDSCPToSRange

	// snatPktMarkRange takes an 8-bit range of pkt_mark to store the ID of
	// a SNAT IP. The bit range must match SNATIPMarkMask.
	snatPktMarkRange = &binding.Range{0, 7}

	GlobalVirtualMAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")
)

type OFEntryOperations interface {
	Add(flow binding.Flow) error
	Modify(flow binding.Flow) error
	Delete(flow binding.Flow) error
	AddAll(flows []binding.Flow) error
	ModifyAll(flows []binding.Flow) error
	BundleOps(adds []binding.Flow, mods []binding.Flow, dels []binding.Flow) error
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
	enableProxy           bool
	proxyAll              bool
	enableAntreaPolicy    bool
	enableDenyTracking    bool
	enableEgress          bool
	enableMulticast       bool
	connectUplinkToBridge bool
	roundInfo             types.RoundInfo
	cookieAllocator       cookie.Allocator
	bridge                binding.Bridge

	featurePodConnectivity *featurePodConnectivity
	featureService         *featureService
	featureEgress          *featureEgress
	featureNetworkPolicy   *featureNetworkPolicy
	featureMulticast       *featureMulticast
	activatedFeatures      []feature

	featureTraceflow  *featureTraceflow
	traceableFeatures []traceableFeature

	pipelines map[binding.PipelineID]binding.Pipeline

	// ofEntryOperations is a wrapper interface for OpenFlow entry Add / Modify / Delete operations. It
	// enables convenient mocking in unit tests.
	ofEntryOperations OFEntryOperations
	// replayMutex provides exclusive access to the OFSwitch to the ReplayFlows method.
	replayMutex   sync.RWMutex
	nodeConfig    *config.NodeConfig
	networkConfig *config.NetworkConfig
	egressConfig  *config.EgressConfig
	serviceConfig *config.ServiceConfig
	// ovsMetersAreSupported indicates whether the OVS datapath supports OpenFlow meters.
	ovsMetersAreSupported bool
	// packetInHandlers stores handler to process PacketIn event. Each packetin reason can have multiple handlers registered.
	// When a packetin arrives, openflow send packet to registered handlers in this map.
	packetInHandlers map[uint8]map[string]PacketInHandler
	// Supported IP Protocols (IP or IPv6) on the current Node.
	ipProtocols []binding.Protocol
	// ovsctlClient is the interface for executing OVS "ovs-ofctl" and "ovs-appctl" commands.
	ovsctlClient ovsctl.OVSCtlClient
}

func (c *client) GetTunnelVirtualMAC() net.HardwareAddr {
	return GlobalVirtualMAC
}

func (c *client) changeAll(flowsMap map[ofAction][]binding.Flow) error {
	if len(flowsMap) == 0 {
		return nil
	}

	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		for k, v := range flowsMap {
			if len(v) != 0 {
				metrics.OVSFlowOpsLatency.WithLabelValues(k.String()).Observe(float64(d.Milliseconds()))
			}
		}
	}()

	if err := c.bridge.AddFlowsInBundle(flowsMap[add], flowsMap[mod], flowsMap[del]); err != nil {
		for k, v := range flowsMap {
			if len(v) != 0 {
				metrics.OVSFlowOpsErrorCount.WithLabelValues(k.String()).Inc()
			}
		}
		return err
	}
	for k, v := range flowsMap {
		if len(v) != 0 {
			metrics.OVSFlowOpsCount.WithLabelValues(k.String()).Inc()
		}
	}
	return nil
}

func (c *client) Add(flow binding.Flow) error {
	return c.AddAll([]binding.Flow{flow})
}

func (c *client) Modify(flow binding.Flow) error {
	return c.ModifyAll([]binding.Flow{flow})
}

func (c *client) Delete(flow binding.Flow) error {
	return c.DeleteAll([]binding.Flow{flow})
}

func (c *client) AddAll(flows []binding.Flow) error {
	return c.changeAll(map[ofAction][]binding.Flow{add: flows})
}

func (c *client) ModifyAll(flows []binding.Flow) error {
	return c.changeAll(map[ofAction][]binding.Flow{mod: flows})
}

func (c *client) DeleteAll(flows []binding.Flow) error {
	return c.changeAll(map[ofAction][]binding.Flow{del: flows})
}

func (c *client) BundleOps(adds []binding.Flow, mods []binding.Flow, dels []binding.Flow) error {
	return c.changeAll(map[ofAction][]binding.Flow{add: adds, mod: mods, del: dels})
}

func (c *client) changeOFEntries(ofEntries []binding.OFEntry, action ofAction) error {
	if len(ofEntries) == 0 {
		return nil
	}
	var adds, mods, dels []binding.OFEntry
	if action == add {
		adds = ofEntries
	} else if action == mod {
		mods = ofEntries
	} else if action == del {
		dels = ofEntries
	} else {
		return fmt.Errorf("OF Entries Action not exists: %s", action)
	}
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		metrics.OVSFlowOpsLatency.WithLabelValues(action.String()).Observe(float64(d.Milliseconds()))
	}()
	if err := c.bridge.AddOFEntriesInBundle(adds, mods, dels); err != nil {
		metrics.OVSFlowOpsErrorCount.WithLabelValues(action.String()).Inc()
		return err
	}
	metrics.OVSFlowOpsCount.WithLabelValues(action.String()).Inc()
	return nil
}

func (c *client) AddOFEntries(ofEntries []binding.OFEntry) error {
	return c.changeOFEntries(ofEntries, add)
}

func (c *client) DeleteOFEntries(ofEntries []binding.OFEntry) error {
	return c.changeOFEntries(ofEntries, del)
}

func (c *client) defaultFlows() []binding.Flow {
	cookieID := c.cookieAllocator.Request(cookie.Default).Raw()
	var flows []binding.Flow
	for id, pipeline := range c.pipelines {
		// This generates the default flow for every table in every pipeline.
		for _, table := range pipeline.ListAllTables() {
			flowBuilder := table.BuildFlow(priorityMiss).Cookie(cookieID)
			switch table.GetMissAction() {
			case binding.TableMissActionNext:
				flowBuilder = flowBuilder.Action().NextTable()
			case binding.TableMissActionNormal:
				flowBuilder = flowBuilder.Action().Normal()
			case binding.TableMissActionDrop:
				flowBuilder = flowBuilder.Action().Drop()
			case binding.TableMissActionNone:
				fallthrough
			default:
				continue
			}
			flows = append(flows, flowBuilder.Done())
		}

		switch id {
		case pipelineIP:
			// This generates the flow to match IPv4 / IPv6 packets and forward them to the first table of pipelineIP in
			// PipelineRootClassifierTable.
			for _, ipProtocol := range c.ipProtocols {
				flows = append(flows, pipelineClassifyFlow(cookieID, ipProtocol, pipeline))
			}
		case pipelineARP:
			// This generates the flow to match ARP packets and forward them to the first table of pipelineARP in
			// PipelineRootClassifierTable.
			flows = append(flows, pipelineClassifyFlow(cookieID, binding.ProtocolARP, pipeline))
		case pipelineMulticast:
			// This generates the flow to match multicast packets and forward them to the first table of pipelineMulticast
			// in PipelineIPClassifierTable. Note that, PipelineIPClassifierTable is in stageValidation of pipeline for IP. In another word,
			// pipelineMulticast is forked from PipelineIPClassifierTable in pipelineIP.
			flows = append(flows, multicastPipelineClassifyFlow(cookieID, pipeline))
		}
	}

	return flows
}

// tunnelClassifierFlow generates the flow to mark the packets from tunnel port.
func (f *featurePodConnectivity) tunnelClassifierFlow(tunnelOFPort uint32) binding.Flow {
	return ClassifierTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchInPort(tunnelOFPort).
		Action().LoadRegMark(FromTunnelRegMark, RewriteMACRegMark).
		Action().GotoStage(stageConntrackState).
		Done()
}

// gatewayClassifierFlow generates the flow to mark the packets from the Antrea gateway port.
func (f *featurePodConnectivity) gatewayClassifierFlow() binding.Flow {
	return ClassifierTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchInPort(config.HostGatewayOFPort).
		Action().LoadRegMark(FromGatewayRegMark).
		Action().GotoStage(stageValidation).
		Done()
}

// podClassifierFlow generates the flow to mark the packets from a local Pod port.
func (f *featurePodConnectivity) podClassifierFlow(podOFPort uint32, isAntreaFlexibleIPAM bool) binding.Flow {
	regMarksToLoad := []*binding.RegMark{FromLocalRegMark}
	if isAntreaFlexibleIPAM {
		regMarksToLoad = append(regMarksToLoad, AntreaFlexibleIPAMRegMark, RewriteMACRegMark)
	}
	return ClassifierTable.ofTable.BuildFlow(priorityLow).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchInPort(podOFPort).
		Action().LoadRegMark(regMarksToLoad...).
		Action().GotoStage(stageValidation).
		Done()
}

// podUplinkClassifierFlows generates the flows to mark the packets with target destination MAC address from uplink/bridge
// port, which are needed when uplink is connected to OVS bridge and Antrea IPAM is configured.
func (f *featurePodConnectivity) podUplinkClassifierFlows(dstMAC net.HardwareAddr, vlanID uint16) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	nonVLAN := true
	if vlanID > 0 {
		nonVLAN = false
	}
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows,
			// This generates the flow to mark the packets from uplink port.
			ClassifierTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchInPort(config.UplinkOFPort).
				MatchDstMAC(dstMAC).
				MatchVLAN(nonVLAN, vlanID, nil).
				MatchProtocol(ipProtocol).
				Action().LoadRegMark(f.ipCtZoneTypeRegMarks[ipProtocol], FromUplinkRegMark).
				Action().LoadToRegField(VLANIDField, uint32(vlanID)).
				Action().GotoStage(stageConntrackState).
				Done(),
		)
		if vlanID == 0 {
			flows = append(flows,
				// This generates the flow to mark the packets from bridge local port.
				ClassifierTable.ofTable.BuildFlow(priorityHigh).
					Cookie(cookieID).
					MatchInPort(config.BridgeOFPort).
					MatchDstMAC(dstMAC).
					MatchVLAN(true, 0, nil).
					MatchProtocol(ipProtocol).
					Action().LoadRegMark(f.ipCtZoneTypeRegMarks[ipProtocol], FromBridgeRegMark).
					Action().GotoStage(stageConntrackState).
					Done(),
			)
		}
	}
	return flows
}

// conntrackFlows generates the flows about conntrack for feature PodConnectivity.
func (f *featurePodConnectivity) conntrackFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows,
			// This generates the flow to transform the destination IP of request packets or source IP of reply packets
			// from tracked connections in CT zone.
			ConntrackTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				Action().CT(false, ConntrackTable.GetNext(), f.ctZones[ipProtocol], f.ctZoneSrcField).
				NAT().
				CTDone().
				Done(),
			// This generates the flow to match the packets of tracked non-Service connection and forward them to
			// stageEgressSecurity directly to bypass stagePreRouting. The first packet of non-Service connection passes
			// through stagePreRouting, and the subsequent packets go to stageEgressSecurity directly.
			ConntrackStateTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(false).
				MatchCTStateTrk(true).
				Action().GotoStage(stageEgressSecurity).
				Done(),
			// This generates the flow to drop invalid packets.
			ConntrackStateTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateInv(true).
				MatchCTStateTrk(true).
				Action().Drop().
				Done(),
			// This generates the flow to match the first packet of non-Service connection and mark the source of the connection
			// by copying PktSourceField to ConnSourceCTMarkField.
			ConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				Action().CT(true, ConntrackCommitTable.GetNext(), f.ctZones[ipProtocol], f.ctZoneSrcField).
				MoveToCtMarkField(PktSourceField, ConnSourceCTMarkField).
				CTDone().
				Done(),
		)
	}
	// This generates default flow to match the first packet of a new connection and forward it to stagePreRouting.
	flows = append(flows, ConntrackStateTable.ofTable.BuildFlow(priorityMiss).
		Cookie(cookieID).
		Action().GotoStage(stagePreRouting).
		Done())

	return flows
}

// conntrackFlows generates the flows about conntrack for feature Service.
func (f *featureService) conntrackFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows,
			// This generates the flow to mark tracked DNATed Service connection with RewriteMACRegMark (load-balanced by
			// AntreaProxy) and forward the packets to stageEgressSecurity directly to bypass stagePreRouting.
			ConntrackStateTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTMark(ServiceCTMark).
				MatchCTStateNew(false).
				MatchCTStateTrk(true).
				Action().LoadRegMark(RewriteMACRegMark).
				Action().GotoStage(stageEgressSecurity).
				Done(),
			// This generates the flow to avoid committing Service connections (with ServiceCTMark) another time. They
			// have been committed in EndpointDNATTable, using the same CT zone.
			ConntrackCommitTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTMark(ServiceCTMark).
				Action().GotoStage(stageOutput).
				Done(),
		)
	}
	return flows
}

// snatConntrackFlows generates the flows about conntrack of SNAT connection for feature Service.
func (f *featureService) snatConntrackFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows,
			// This generates the flow to transform destination IP of reply packets from tracked SNATed Service connection
			// committed in SNAT CT zone.
			SNATConntrackTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				Action().CT(false, SNATConntrackTable.GetNext(), f.snatCtZones[ipProtocol], nil).
				NAT().
				CTDone().
				Done(),

			// SNAT should be performed for the following connections:
			// - Hairpin Service connection initiated through a local Pod, and SNAT should be performed with the Antrea
			//   gateway IP.
			// - Hairpin Service connection initiated through the Antrea gateway, and SNAT should be performed with a
			//   virtual IP.
			// - Nodeport / LoadBalancer connection initiated through the Antrea gateway and externalTrafficPolicy is
			//   Cluster, and SNAT should be performed with the Antrea gateway IP.
			// Note that, for Service connections that require SNAT, ServiceCTMark is loaded in SNAT CT zone when performing
			// SNAT since ServiceCTMark loaded in DNAT CT zone cannot be read in SNAT CT zone. For Service connections,
			// ServiceCTMark (loaded in DNAT / SNAT CT zone) is used to bypass ConntrackCommitTable which is used to commit
			// non-Service connections. For hairpin connections, HairpinCTMark is also loaded in SNAT CT zone when performing
			// SNAT since HairpinCTMark loaded in DNAT CT zone also cannot be read in SNAT CT zone. HairpinCTMark is used
			// to output packets of hairpin connections in L2ForwardingOutTable.

			// This generates the flow to match the first packet of hairpin Service connection initiated through the Antrea
			// gateway with ConnSNATCTMark and HairpinCTMark, then perform SNAT in SNAT CT zone with a virtual IP.
			SNATConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(FromGatewayRegMark).
				MatchCTMark(HairpinCTMark).
				Action().CT(true, SNATConntrackCommitTable.GetNext(), f.snatCtZones[ipProtocol], nil).
				SNAT(&binding.IPRange{StartIP: f.virtualIPs[ipProtocol], EndIP: f.virtualIPs[ipProtocol]}, nil).
				LoadToCtMark(ServiceCTMark, HairpinCTMark).
				CTDone().
				Done(),
			// This generates the flow to match the first packet of hairpin Service connection initiated through a Pod with
			// ConnSNATCTMark and HairpinCTMark, then perform SNAT in SNAT CT zone with the Antrea gateway IP.
			SNATConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(FromLocalRegMark).
				MatchCTMark(HairpinCTMark).
				Action().CT(true, SNATConntrackCommitTable.GetNext(), f.snatCtZones[ipProtocol], nil).
				SNAT(&binding.IPRange{StartIP: f.gatewayIPs[ipProtocol], EndIP: f.gatewayIPs[ipProtocol]}, nil).
				LoadToCtMark(ServiceCTMark, HairpinCTMark).
				CTDone().
				Done(),
			// This generates the flow to match the first packet of NodePort / LoadBalancer connection (non-hairpin) initiated
			// through the Antrea gateway with ConnSNATCTMark, then perform SNAT in SNAT CT zone with the Antrea gateway IP.
			SNATConntrackCommitTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(FromGatewayRegMark).
				MatchCTMark(ConnSNATCTMark).
				Action().CT(true, SNATConntrackCommitTable.GetNext(), f.snatCtZones[ipProtocol], nil).
				SNAT(&binding.IPRange{StartIP: f.gatewayIPs[ipProtocol], EndIP: f.gatewayIPs[ipProtocol]}, nil).
				LoadToCtMark(ServiceCTMark).
				CTDone().
				Done(),
			// This generates the flow to match the subsequent request packets of connection whose first request packet has
			// been committed in SNAT CT zone, then commit the packets in SNAT CT zone again to perform SNAT.
			// For example:
			/*
				* 192.168.77.1 is the IP address of client.
				* 192.168.77.100 is the IP address of K8s Node.
				* 30001 is the NodePort port.
				* 10.10.0.1 is the IP address of Antrea gateway.
				* 10.10.0.3 is the IP of NodePort Service Endpoint.

				* packet 1 (request)
					* client                     192.168.77.1:12345->192.168.77.100:30001
					* CT zone SNAT 65521         192.168.77.1:12345->192.168.77.100:30001
					* CT zone DNAT 65520         192.168.77.1:12345->192.168.77.100:30001
					* CT commit DNAT zone 65520  192.168.77.1:12345->192.168.77.100:30001  =>  192.168.77.1:12345->10.10.0.3:80
					* CT commit SNAT zone 65521  192.168.77.1:12345->10.10.0.3:80          =>  10.10.0.1:12345->10.10.0.3:80
					* output
				  * packet 2 (reply)
					* Pod                         10.10.0.3:80->10.10.0.1:12345
					* CT zone SNAT 65521          10.10.0.3:80->10.10.0.1:12345            =>  10.10.0.3:80->192.168.77.1:12345
					* CT zone DNAT 65520          10.10.0.3:80->192.168.77.1:12345         =>  192.168.77.1:30001->192.168.77.1:12345
					* output
				  * packet 3 (request)
					* client                     192.168.77.1:12345->192.168.77.100:30001
					* CT zone SNAT 65521         192.168.77.1:12345->192.168.77.100:30001
					* CT zone DNAT 65520         192.168.77.1:12345->10.10.0.3:80
					* CT zone SNAT 65521         192.168.77.1:12345->10.10.0.3:80          =>  10.10.0.1:12345->10.10.0.3:80
					* output
				  * packet ...
			*/
			// As a result, subsequent request packets like packet 3 will only perform SNAT when they pass through SNAT
			// CT zone the second time, after they are DNATed in DNAT CT zone.
			SNATConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTMark(ConnSNATCTMark).
				MatchCTStateNew(false).
				MatchCTStateTrk(true).
				MatchCTStateRpl(false).
				Action().CT(false, SNATConntrackCommitTable.GetNext(), f.snatCtZones[ipProtocol], nil).
				NAT().
				CTDone().
				Done(),
		)
	}
	return flows
}

// dnsResponseBypassConntrackFlow generates the flow to bypass the dns response packetout from conntrack, to avoid unexpected
// packet drop. This flow should be installed on the first table of stageConntrackState.
func (f *featureNetworkPolicy) dnsResponseBypassConntrackFlow(table binding.Table) binding.Flow {
	return table.BuildFlow(priorityHigh).
		MatchRegFieldWithValue(CustomReasonField, CustomReasonDNS).
		Cookie(f.cookieAllocator.Request(cookie.Default).Raw()).
		Action().GotoStage(stageSwitching).
		Done()
}

// dnsResponseBypassPacketInFlow generates the flow to bypass the dns packetIn conjunction flow for dns response packetOut.
// This packetOut should be sent directly to the requesting client without being intercepted again.
func (f *featureNetworkPolicy) dnsResponseBypassPacketInFlow() binding.Flow {
	// TODO: use a unified register bit to mark packetOuts. The pipeline does not need to be
	// aware of why the packetOut is being set by the controller, it just needs to be aware that
	// this is a packetOut message and that some pipeline stages (conntrack, policy enforcement)
	// should therefore be skipped.
	return AntreaPolicyIngressRuleTable.ofTable.BuildFlow(priorityDNSBypass).
		Cookie(f.cookieAllocator.Request(cookie.Default).Raw()).
		MatchRegFieldWithValue(CustomReasonField, CustomReasonDNS).
		Action().GotoStage(stageOutput).
		Done()
}

// TODO: Use DuplicateToBuilder or integrate this function into original one to avoid unexpected difference.
// flowsToTrace generates Traceflow specific flows in the connectionTrackStateTable or L2ForwardingCalcTable for featurePodConnectivity.
// When packet is not provided, the flows bypass the drop flow in conntrackStateFlow to avoid unexpected drop of the
// injected Traceflow packet, and to drop any Traceflow packet that has ct_state +rpl, which may happen when the Traceflow
// request destination is the Node's IP. When packet is provided, a flow is added to mark - the first packet of the first
// connection that matches the provided packet - as the Traceflow packet. The flow is added in connectionTrackStateTable
// when receiverOnly is false and it also matches in_port to be the provided ofPort (the sender Pod); otherwise when
// receiverOnly is true, the flow is added into L2ForwardingCalcTable and matches the destination MAC (the receiver Pod MAC).
func (f *featurePodConnectivity) flowsToTrace(dataplaneTag uint8,
	ovsMetersAreSupported,
	liveTraffic,
	droppedOnly,
	receiverOnly bool,
	packet *binding.Packet,
	ofPort uint32,
	timeout uint16) []binding.Flow {
	cookieID := f.cookieAllocator.Request(cookie.Traceflow).Raw()
	var flows []binding.Flow
	if packet == nil {
		for _, ipProtocol := range f.ipProtocols {
			flows = append(flows,
				ConntrackStateTable.ofTable.BuildFlow(priorityLow+1).
					Cookie(cookieID).
					MatchProtocol(ipProtocol).
					MatchIPDSCP(dataplaneTag).
					SetHardTimeout(timeout).
					Action().GotoStage(stagePreRouting).
					Done(),
				ConntrackStateTable.ofTable.BuildFlow(priorityLow+2).
					Cookie(cookieID).
					MatchProtocol(ipProtocol).
					MatchCTStateTrk(true).
					MatchCTStateRpl(true).
					MatchIPDSCP(dataplaneTag).
					SetHardTimeout(timeout).
					Action().Drop().
					Done(),
			)
		}
	} else {
		var flowBuilder binding.FlowBuilder
		if !receiverOnly {
			flowBuilder = ConntrackStateTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchInPort(ofPort).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				Action().LoadIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				Action().GotoStage(stagePreRouting)
			if packet.DestinationIP != nil {
				flowBuilder = flowBuilder.MatchDstIP(packet.DestinationIP)
			}
		} else {
			flowBuilder = L2ForwardingCalcTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchDstMAC(packet.DestinationMAC).
				Action().LoadToRegField(TargetOFPortField, ofPort).
				Action().LoadRegMark(OFPortFoundRegMark).
				Action().LoadIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				Action().GotoStage(stageIngressSecurity)
			if packet.SourceIP != nil {
				flowBuilder = flowBuilder.MatchSrcIP(packet.SourceIP)
			}
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
		flows = append(flows, flowBuilder.Done())
	}

	// Do not send to controller if captures only dropped packet.
	ifDroppedOnly := func(fb binding.FlowBuilder) binding.FlowBuilder {
		if !droppedOnly {
			if ovsMetersAreSupported {
				fb = fb.Action().Meter(PacketInMeterIDTF)
			}
			fb = fb.Action().SendToController(uint8(PacketInReasonTF))
		}
		return fb
	}
	// Clear the loaded DSCP bits before output.
	ifLiveTraffic := func(fb binding.FlowBuilder) binding.FlowBuilder {
		if liveTraffic {
			return fb.Action().LoadIPDSCP(0).
				Action().OutputToRegField(TargetOFPortField)
		}
		return fb
	}

	// This generates Traceflow specific flows that outputs traceflow non-hairpin packets to OVS port and Antrea Agent after
	// L2forwarding calculation.
	for _, ipProtocol := range f.ipProtocols {
		if f.networkConfig.TrafficEncapMode.SupportsEncap() {
			// SendToController and Output if output port is tunnel port.
			fb := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal+3).
				Cookie(cookieID).
				MatchRegFieldWithValue(TargetOFPortField, config.DefaultTunOFPort).
				MatchProtocol(ipProtocol).
				MatchRegMark(OFPortFoundRegMark).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				Action().OutputToRegField(TargetOFPortField)
			fb = ifDroppedOnly(fb)
			flows = append(flows, fb.Done())
			// For injected packets, only SendToController if output port is local gateway. In encapMode, a Traceflow
			// packet going out of the gateway port (i.e. exiting the overlay) essentially means that the Traceflow
			// request is complete.
			fb = L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal+2).
				Cookie(cookieID).
				MatchRegFieldWithValue(TargetOFPortField, config.HostGatewayOFPort).
				MatchProtocol(ipProtocol).
				MatchRegMark(OFPortFoundRegMark).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout)
			fb = ifDroppedOnly(fb)
			fb = ifLiveTraffic(fb)
			flows = append(flows, fb.Done())
		} else {
			// SendToController and Output if output port is local gateway. Unlike in encapMode, inter-Node Pod-to-Pod
			// traffic is expected to go out of the gateway port on the way to its destination.
			fb := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal+2).
				Cookie(cookieID).
				MatchRegFieldWithValue(TargetOFPortField, config.HostGatewayOFPort).
				MatchProtocol(ipProtocol).
				MatchRegMark(OFPortFoundRegMark).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				Action().OutputToRegField(TargetOFPortField)
			fb = ifDroppedOnly(fb)
			flows = append(flows, fb.Done())
		}
		// Only SendToController if output port is local gateway and destination IP is gateway.
		gatewayIP := f.gatewayIPs[ipProtocol]
		if gatewayIP != nil {
			fb := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal+3).
				Cookie(cookieID).
				MatchRegFieldWithValue(TargetOFPortField, config.HostGatewayOFPort).
				MatchProtocol(ipProtocol).
				MatchDstIP(gatewayIP).
				MatchRegMark(OFPortFoundRegMark).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout)
			fb = ifDroppedOnly(fb)
			fb = ifLiveTraffic(fb)
			flows = append(flows, fb.Done())
		}
		// Only SendToController if output port is Pod port.
		fb := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal + 2).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchRegMark(OFPortFoundRegMark).
			MatchIPDSCP(dataplaneTag).
			SetHardTimeout(timeout)
		fb = ifDroppedOnly(fb)
		fb = ifLiveTraffic(fb)
		flows = append(flows, fb.Done())
	}

	return flows
}

// flowsToTrace is used to generate flows for Traceflow in featureService.
func (f *featureService) flowsToTrace(dataplaneTag uint8,
	ovsMetersAreSupported,
	liveTraffic,
	droppedOnly,
	receiverOnly bool,
	packet *binding.Packet,
	ofPort uint32,
	timeout uint16) []binding.Flow {
	cookieID := f.cookieAllocator.Request(cookie.Traceflow).Raw()
	var flows []binding.Flow
	// Do not send to controller if captures only dropped packet.
	ifDroppedOnly := func(fb binding.FlowBuilder) binding.FlowBuilder {
		if !droppedOnly {
			if ovsMetersAreSupported {
				fb = fb.Action().Meter(PacketInMeterIDTF)
			}
			fb = fb.Action().SendToController(uint8(PacketInReasonTF))
		}
		return fb
	}
	// Clear the loaded DSCP bits before output.
	ifLiveTraffic := func(fb binding.FlowBuilder) binding.FlowBuilder {
		if liveTraffic {
			return fb.Action().LoadIPDSCP(0).
				Action().OutputToRegField(TargetOFPortField)
		}
		return fb
	}

	// This generates Traceflow specific flows that outputs hairpin traceflow packets to OVS port and Antrea Agent after
	// L2forwarding calculation.
	for _, ipProtocol := range f.ipProtocols {
		if f.enableProxy {
			// Only SendToController for hairpin traffic.
			// This flow must have higher priority than the one installed by l2ForwardOutputHairpinServiceFlow.
			fb := L2ForwardingOutTable.ofTable.BuildFlow(priorityHigh + 2).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTMark(HairpinCTMark).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout)
			fb = ifDroppedOnly(fb)
			fb = ifLiveTraffic(fb)
			flows = append(flows, fb.Done())
		}
	}
	return flows
}

// flowsToTrace is used to generate flows for Traceflow from globalConjMatchFlowCache and policyCache.
func (f *featureNetworkPolicy) flowsToTrace(dataplaneTag uint8,
	ovsMetersAreSupported,
	liveTraffic,
	droppedOnly,
	receiverOnly bool,
	packet *binding.Packet,
	ofPort uint32,
	timeout uint16) []binding.Flow {
	cookieID := f.cookieAllocator.Request(cookie.Traceflow).Raw()
	var flows []binding.Flow
	f.conjMatchFlowLock.Lock()
	defer f.conjMatchFlowLock.Unlock()
	for _, ctx := range f.globalConjMatchFlowCache {
		if ctx.dropFlow != nil {
			copyFlowBuilder := ctx.dropFlow.CopyToBuilder(priorityNormal+2, false)
			if ctx.dropFlow.FlowProtocol() == "" {
				copyFlowBuilderIPv6 := ctx.dropFlow.CopyToBuilder(priorityNormal+2, false)
				copyFlowBuilderIPv6 = copyFlowBuilderIPv6.MatchProtocol(binding.ProtocolIPv6)
				if f.ovsMetersAreSupported {
					copyFlowBuilderIPv6 = copyFlowBuilderIPv6.Action().Meter(PacketInMeterIDTF)
				}
				flows = append(flows, copyFlowBuilderIPv6.MatchIPDSCP(dataplaneTag).
					Cookie(cookieID).
					SetHardTimeout(timeout).
					Action().SendToController(uint8(PacketInReasonTF)).
					Done())
				copyFlowBuilder = copyFlowBuilder.MatchProtocol(binding.ProtocolIP)
			}
			if f.ovsMetersAreSupported {
				copyFlowBuilder = copyFlowBuilder.Action().Meter(PacketInMeterIDTF)
			}
			flows = append(flows, copyFlowBuilder.MatchIPDSCP(dataplaneTag).
				Cookie(cookieID).
				SetHardTimeout(timeout).
				Action().SendToController(uint8(PacketInReasonTF)).
				Done())
		}
	}
	// Copy Antrea NetworkPolicy drop rules.
	for _, conj := range f.policyCache.List() {
		for _, flow := range conj.(*policyRuleConjunction).metricFlows {
			if flow.IsDropFlow() {
				copyFlowBuilder := flow.CopyToBuilder(priorityNormal+2, false)
				// Generate both IPv4 and IPv6 flows if the original drop flow doesn't match IP/IPv6.
				// DSCP field is in IP/IPv6 headers so IP/IPv6 match is required in a flow.
				if flow.FlowProtocol() == "" {
					copyFlowBuilderIPv6 := flow.CopyToBuilder(priorityNormal+2, false)
					copyFlowBuilderIPv6 = copyFlowBuilderIPv6.MatchProtocol(binding.ProtocolIPv6)
					if f.ovsMetersAreSupported {
						copyFlowBuilderIPv6 = copyFlowBuilderIPv6.Action().Meter(PacketInMeterIDTF)
					}
					flows = append(flows, copyFlowBuilderIPv6.MatchIPDSCP(dataplaneTag).
						SetHardTimeout(timeout).
						Cookie(cookieID).
						Action().SendToController(uint8(PacketInReasonTF)).
						Done())
					copyFlowBuilder = copyFlowBuilder.MatchProtocol(binding.ProtocolIP)
				}
				if f.ovsMetersAreSupported {
					copyFlowBuilder = copyFlowBuilder.Action().Meter(PacketInMeterIDTF)
				}
				flows = append(flows, copyFlowBuilder.MatchIPDSCP(dataplaneTag).
					SetHardTimeout(timeout).
					Cookie(cookieID).
					Action().SendToController(uint8(PacketInReasonTF)).
					Done())
			}
		}
	}
	return flows
}

// l2ForwardCalcFlow generates the flow to match the destination MAC and load the target ofPort to TargetOFPortField.
func (f *featurePodConnectivity) l2ForwardCalcFlow(dstMAC net.HardwareAddr, ofPort uint32) binding.Flow {
	return L2ForwardingCalcTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchDstMAC(dstMAC).
		Action().LoadToRegField(TargetOFPortField, ofPort).
		Action().LoadRegMark(OFPortFoundRegMark).
		Action().NextTable().
		Done()
}

// l2ForwardOutputHairpinServiceFlow generates the flow to output the packet of hairpin Service connection with IN_PORT
// action.
func (f *featureService) l2ForwardOutputHairpinServiceFlow() binding.Flow {
	return L2ForwardingOutTable.ofTable.BuildFlow(priorityHigh).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchCTMark(HairpinCTMark).
		Action().OutputInPort().
		Done()
}

// l2ForwardOutputFlow generates the flow to output the packets to target OVS port according to the value of TargetOFPortField.
func (f *featurePodConnectivity) l2ForwardOutputFlow() binding.Flow {
	return L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchRegMark(OFPortFoundRegMark).
		Action().OutputToRegField(TargetOFPortField).
		Done()
}

// l3FwdFlowToPod generates the flows to match the packets destined for a local Pod. For a per-Node IPAM Pod, the flow
// rewrites destination MAC to the Pod interface's MAC, and rewrites source MAC to Antrea gateway interface's MAC. For
// an Antrea IPAM Pod, the flow only rewrites the destination MAC to the Pod interface's MAC.
func (f *featurePodConnectivity) l3FwdFlowToPod(localGatewayMAC net.HardwareAddr,
	podInterfaceIPs []net.IP,
	podInterfaceMAC net.HardwareAddr,
	isAntreaFlexibleIPAM bool,
	vlanID uint16) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ip := range podInterfaceIPs {
		ipProtocol := getIPProtocol(ip)
		if isAntreaFlexibleIPAM {
			// This generates the flow to match the packets destined for a local Antrea IPAM Pod.
			flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchRegFieldWithValue(VLANIDField, uint32(vlanID)).
				MatchProtocol(ipProtocol).
				MatchDstIP(ip).
				Action().SetDstMAC(podInterfaceMAC).
				Action().GotoTable(L3DecTTLTable.GetID()).
				Done())
		} else {
			// This generates the flow to match the packets with RewriteMACRegMark and destined for a local per-Node IPAM Pod.
			regMarksToMatch := []*binding.RegMark{RewriteMACRegMark}
			if f.connectUplinkToBridge {
				// Only overwrite MAC for untagged traffic which destination is a local per-Node IPAM Pod.
				regMarksToMatch = append(regMarksToMatch, binding.NewRegMark(VLANIDField, 0))
			}
			flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegMark(regMarksToMatch...).
				MatchDstIP(ip).
				Action().SetSrcMAC(localGatewayMAC).
				Action().SetDstMAC(podInterfaceMAC).
				Action().GotoTable(L3DecTTLTable.GetID()).
				Done())
		}
	}
	return flows
}

// l3FwdFlowRouteToPod generates the flows to match the packets destined for a Pod based on the destination IPs. It rewrites
// destination MAC to the Pod interface's MAC. The flows are only used in networkPolicyOnly mode.
func (f *featurePodConnectivity) l3FwdFlowRouteToPod(podInterfaceIPs []net.IP, podInterfaceMAC net.HardwareAddr) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ip := range podInterfaceIPs {
		ipProtocol := getIPProtocol(ip)
		flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchDstIP(ip).
			Action().SetDstMAC(podInterfaceMAC).
			Action().GotoTable(L3DecTTLTable.GetID()).
			Done())
	}
	return flows
}

// l3FwdFlowRouteToGW generates the flows to match the packets destined for the Antrea gateway. It rewrites destination MAC
// to the Antrea gateway interface's MAC. The flows are used in networkPolicyOnly mode to match the packets sourced from a
// local Pod and destined for remote Pods, Nodes, or external network.
func (f *featurePodConnectivity) l3FwdFlowRouteToGW() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityLow).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			Action().SetDstMAC(f.nodeConfig.GatewayConfig.MAC).
			Action().LoadRegMark(ToGatewayRegMark).
			Action().GotoTable(L3DecTTLTable.GetID()).
			Done(),
		)
	}
	return flows
}

// l3FwdFlowToGateway generates the flows to match the packets destined for the Antrea gateway.
func (f *featurePodConnectivity) l3FwdFlowToGateway() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for ipProtocol, gatewayIP := range f.gatewayIPs {
		flows = append(flows,
			// This generates the flow to match the packets destined for Antrea gateway.
			L3ForwardingTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchDstIP(gatewayIP).
				Action().SetDstMAC(f.nodeConfig.GatewayConfig.MAC).
				Action().LoadRegMark(ToGatewayRegMark).
				Action().GotoTable(L3DecTTLTable.GetID()).
				Done(),
			// This generates the flow to match the reply packets of connection with FromGatewayCTMark.
			L3ForwardingTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTMark(FromGatewayCTMark).
				MatchCTStateRpl(true).
				MatchCTStateTrk(true).
				Action().SetDstMAC(f.nodeConfig.GatewayConfig.MAC).
				Action().LoadRegMark(ToGatewayRegMark).
				Action().GotoTable(L3DecTTLTable.GetID()).
				Done(),
		)
	}
	return flows
}

// l3FwdFlowToRemoteViaTun generates the flow to match the packets destined for remote Pods via tunnel.
func (f *featurePodConnectivity) l3FwdFlowToRemoteViaTun(localGatewayMAC net.HardwareAddr, peerSubnet net.IPNet, tunnelPeer net.IP) binding.Flow {
	ipProtocol := getIPProtocol(peerSubnet.IP)
	return L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(ipProtocol).
		MatchDstIPNet(peerSubnet).
		Action().SetSrcMAC(localGatewayMAC).  // Rewrite src MAC to local gateway MAC.
		Action().SetDstMAC(GlobalVirtualMAC). // Rewrite dst MAC to virtual MAC.
		Action().SetTunnelDst(tunnelPeer).    // Flow based tunnel. Set tunnel destination.
		Action().LoadRegMark(ToTunnelRegMark).
		Action().GotoTable(L3DecTTLTable.GetID()).
		Done()
}

// l3FwdFlowToRemoteViaGW generates the flow to match the packets destined for remote Pods via the Antrea gateway. It is
// used when the cross-Node connections that do not require encapsulation (in noEncap, networkPolicyOnly, or hybrid mode).
func (f *featurePodConnectivity) l3FwdFlowToRemoteViaGW(localGatewayMAC net.HardwareAddr, peerSubnet net.IPNet) binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	ipProtocol := getIPProtocol(peerSubnet.IP)
	var regMarksToMatch []*binding.RegMark
	if f.connectUplinkToBridge {
		regMarksToMatch = append(regMarksToMatch, NotAntreaFlexibleIPAMRegMark) // Exclude the packets from Antrea IPAM Pods.
	}
	// This generates the flow to match the packets destined for remote Pods. Note that, this flow is installed in Linux Nodes
	// or Windows Nodes whose remote Node's transport interface MAC is unknown.
	return L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
		Cookie(cookieID).
		MatchProtocol(ipProtocol).
		MatchDstIPNet(peerSubnet).
		MatchRegMark(regMarksToMatch...).
		Action().SetDstMAC(localGatewayMAC).
		Action().LoadRegMark(ToGatewayRegMark).
		Action().GotoTable(L3DecTTLTable.GetID()). // Traffic to in-cluster destination should skip EgressMark table.
		Done()
}

// l3FwdFlowToRemoteViaUplink generates the flow to match the packets destined for remote Pods via uplink. It is used
// when the cross-Node connections that do not require encapsulation (in noEncap, networkPolicyOnly, hybrid mode).
func (f *featurePodConnectivity) l3FwdFlowToRemoteViaUplink(remoteGatewayMAC net.HardwareAddr,
	peerSubnet net.IPNet,
	isAntreaFlexibleIPAM bool) binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	ipProtocol := getIPProtocol(peerSubnet.IP)
	if !isAntreaFlexibleIPAM {
		// This generates the flow to match the packets destined for remote Pods via uplink directly without passing
		// through the Antrea gateway by rewriting destination MAC to remote Node Antrea gateway's MAC. Note that,
		// this flow is only installed in Windows Nodes。
		return L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchRegMark(NotAntreaFlexibleIPAMRegMark).
			MatchDstIPNet(peerSubnet).
			Action().SetSrcMAC(f.nodeConfig.UplinkNetConfig.MAC).
			Action().SetDstMAC(remoteGatewayMAC).
			Action().LoadRegMark(ToUplinkRegMark).
			Action().GotoTable(L3DecTTLTable.GetID()).
			Done()
	}
	// This generates the flow to match the packets sourced Antrea IPAM Pods and destined for remote Pods, and rewrite
	// the destination MAC to remote Node Antrea gateway's MAC. Note that, this flow is only used in Linux when AntreaIPAM
	// is enabled.
	return L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
		Cookie(cookieID).
		MatchRegFieldWithValue(VLANIDField, 0).
		MatchProtocol(ipProtocol).
		MatchRegMark(AntreaFlexibleIPAMRegMark).
		MatchDstIPNet(peerSubnet).
		Action().SetDstMAC(remoteGatewayMAC).
		Action().LoadRegMark(ToUplinkRegMark).
		Action().GotoTable(L3DecTTLTable.GetID()).
		Done()
}

// arpResponderFlow generates the flow to reply to the ARP request with a MAC address for the target IP address.
func (f *featurePodConnectivity) arpResponderFlow(ipAddr net.IP, macAddr net.HardwareAddr) binding.Flow {
	return ARPResponderTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(binding.ProtocolARP).
		MatchARPOp(arpOpRequest).
		MatchARPTpa(ipAddr).
		Action().Move(binding.NxmFieldSrcMAC, binding.NxmFieldDstMAC).
		Action().SetSrcMAC(macAddr).
		Action().LoadARPOperation(arpOpReply).
		Action().Move(binding.NxmFieldARPSha, binding.NxmFieldARPTha).
		Action().SetARPSha(macAddr).
		Action().Move(binding.NxmFieldARPSpa, binding.NxmFieldARPTpa).
		Action().SetARPSpa(ipAddr).
		Action().OutputInPort().
		Done()
}

// arpResponderStaticFlow generates the flow to reply to any ARP request with the same global virtual MAC. It is used
// in policy-only mode, where traffic are routed via IP not MAC.
func (f *featurePodConnectivity) arpResponderStaticFlow() binding.Flow {
	return ARPResponderTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(binding.ProtocolARP).
		MatchARPOp(arpOpRequest).
		Action().Move(binding.NxmFieldSrcMAC, binding.NxmFieldDstMAC).
		Action().SetSrcMAC(GlobalVirtualMAC).
		Action().LoadARPOperation(arpOpReply).
		Action().Move(binding.NxmFieldARPSha, binding.NxmFieldARPTha).
		Action().SetARPSha(GlobalVirtualMAC).
		Action().Move(binding.NxmFieldARPTpa, SwapField.GetNXFieldName()).
		Action().Move(binding.NxmFieldARPSpa, binding.NxmFieldARPTpa).
		Action().Move(SwapField.GetNXFieldName(), binding.NxmFieldARPSpa).
		Action().OutputInPort().
		Done()
}

// podIPSpoofGuardFlow generates the flow to check IP packets from local Pods. Packets from the Antrea gateway will not be
// checked, since it might be Pod to Service connection or host namespace connection.
func (f *featurePodConnectivity) podIPSpoofGuardFlow(ifIPs []net.IP, ifMAC net.HardwareAddr, ifOFPort uint32, vlanID uint16) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	targetTables := make(map[binding.Protocol]uint8)
	// - When IPv4 is enabled only, IPv6Table is not initialized. All packets should be forwarded to the next table of
	//   SpoofGuardTable.
	// - When IPv6 is enabled only, IPv6Table is initialized, and it is the next table of SpoofGuardTable. All packets
	//   should be to IPv6Table.
	// - When both IPv4 and IPv6 are enabled, IPv4 packets should skip IPv6Table (which is the next table of SpoofGuardTable)
	//   to avoid unnecessary overhead.
	if len(f.ipProtocols) == 1 {
		targetTables[f.ipProtocols[0]] = SpoofGuardTable.GetNext()
	} else {
		targetTables[binding.ProtocolIP] = IPv6Table.GetNext()
		targetTables[binding.ProtocolIPv6] = IPv6Table.GetID()
	}

	for _, ifIP := range ifIPs {
		var regMarksToLoad []*binding.RegMark
		ipProtocol := getIPProtocol(ifIP)
		if f.connectUplinkToBridge {
			regMarksToLoad = append(regMarksToLoad, f.ipCtZoneTypeRegMarks[ipProtocol], binding.NewRegMark(VLANIDField, uint32(vlanID)))
		}
		flows = append(flows, SpoofGuardTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchInPort(ifOFPort).
			MatchSrcMAC(ifMAC).
			MatchSrcIP(ifIP).
			Action().LoadRegMark(regMarksToLoad...).
			Action().GotoTable(targetTables[ipProtocol]).
			Done())
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

// arpSpoofGuardFlow generates the flow to check the ARP packets sourced from local Pods or the Antrea gateway.
func (f *featurePodConnectivity) arpSpoofGuardFlow(ifIP net.IP, ifMAC net.HardwareAddr, ifOFPort uint32) binding.Flow {
	return ARPSpoofGuardTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(binding.ProtocolARP).
		MatchInPort(ifOFPort).
		MatchARPSha(ifMAC).
		MatchARPSpa(ifIP).
		Action().NextTable().
		Done()
}

// sessionAffinityReselectFlow generates the flow which resubmits the Service accessing packet back to ServiceLBTable
// if there is no endpointDNAT flow matched. This case will occur if an Endpoint is removed and is the learned Endpoint
// selection of the Service.
func (f *featureService) sessionAffinityReselectFlow() binding.Flow {
	return EndpointDNATTable.ofTable.BuildFlow(priorityLow).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchRegMark(EpSelectedRegMark).
		Action().LoadRegMark(EpToSelectRegMark).
		Action().ResubmitToTables(ServiceLBTable.GetID()).
		Done()
}

// gatewayIPSpoofGuardFlows generates the flow to skip spoof guard checking for packets from the Antrea gateway.
func (f *featurePodConnectivity) gatewayIPSpoofGuardFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	targetTables := make(map[binding.Protocol]uint8)
	// - When IPv4 is enabled only, IPv6Table is not initialized. All packets should be forwarded to the next table of
	//   SpoofGuardTable.
	// - When IPv6 is enabled only, IPv6Table is initialized, and it is the next table of SpoofGuardTable. All packets
	//   should be to IPv6Table.
	// - When both IPv4 and IPv6 are enabled, IPv4 packets should skip IPv6Table (which is the next table of SpoofGuardTable)
	//   to avoid unnecessary overhead.
	if len(f.ipProtocols) == 1 {
		targetTables[f.ipProtocols[0]] = SpoofGuardTable.GetNext()
	} else {
		targetTables[binding.ProtocolIP] = IPv6Table.GetNext()
		targetTables[binding.ProtocolIPv6] = IPv6Table.GetID()
	}

	for _, ipProtocol := range f.ipProtocols {
		var regMarksToLoad []*binding.RegMark
		// Set CtZoneTypeField based on ipProtocol and keep VLANIDField=0
		if f.connectUplinkToBridge {
			regMarksToLoad = append(regMarksToLoad, f.ipCtZoneTypeRegMarks[ipProtocol])
		}
		flows = append(flows, SpoofGuardTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchInPort(config.HostGatewayOFPort).
			Action().LoadRegMark(regMarksToLoad...).
			Action().GotoTable(targetTables[ipProtocol]).
			Done(),
		)
	}
	return flows
}

// serviceCIDRDNATFlows generates the flows to match destination IP in Service CIDR and output to the Antrea gateway directly.
func (f *featureService) serviceCIDRDNATFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for ipProtocol, serviceCIDR := range f.serviceCIDRs {
		flows = append(flows, DNATTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchDstIPNet(serviceCIDR).
			Action().LoadToRegField(TargetOFPortField, config.HostGatewayOFPort).
			Action().LoadRegMark(OFPortFoundRegMark).
			Action().GotoStage(stageConntrack).
			Done())
	}
	return flows
}

// serviceNeedLBFlow generates the default flow to mark packets with EpToSelectRegMark.
func (f *featureService) serviceNeedLBFlow() binding.Flow {
	return SessionAffinityTable.ofTable.BuildFlow(priorityMiss).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		Action().LoadRegMark(EpToSelectRegMark).
		Done()
}

// arpNormalFlow generates the flow to reply to the ARP request packets in normal way if no flow in ARPResponderTable is matched.
func (f *featurePodConnectivity) arpNormalFlow() binding.Flow {
	return ARPResponderTable.ofTable.BuildFlow(priorityLow).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(binding.ProtocolARP).
		Action().Normal().
		Done()
}

func (f *featureNetworkPolicy) allowRulesMetricFlows(conjunctionID uint32, ingress bool) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	metricTable := IngressMetricTable
	offset := 0
	// We use the 0..31 bits of the ct_label to store the ingress rule ID and use the 32..63 bits to store the
	// egress rule ID.
	field := IngressRuleCTLabel
	if !ingress {
		metricTable = EgressMetricTable
		offset = 32
		field = EgressRuleCTLabel
	}
	metricFlow := func(isCTNew bool, protocol binding.Protocol) binding.Flow {
		return metricTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(protocol).
			MatchCTStateNew(isCTNew).
			MatchCTLabelField(0, uint64(conjunctionID)<<offset, field).
			Action().NextTable().
			Done()
	}
	var flows []binding.Flow
	// These two flows track the number of sessions in addition to the packet and byte counts.
	// The flow matching 'ct_state=+new' tracks the number of sessions and byte count of the first packet for each
	// session.
	// The flow matching 'ct_state=-new' tracks the byte/packet count of an established connection (both directions).
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows, metricFlow(true, ipProtocol), metricFlow(false, ipProtocol))
	}
	return flows
}

func (f *featureNetworkPolicy) denyRuleMetricFlow(conjunctionID uint32, ingress bool) binding.Flow {
	metricTable := IngressMetricTable
	if !ingress {
		metricTable = EgressMetricTable
	}
	return metricTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchRegMark(CnpDenyRegMark).
		MatchRegFieldWithValue(CNPDenyConjIDField, conjunctionID).
		Action().Drop().
		Done()
}

// ipv6Flows generates the flows to allow IPv6 packets from link-local addresses and handle multicast packets, Neighbor
// Solicitation and ND Advertisement packets properly.
func (f *featurePodConnectivity) ipv6Flows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	_, ipv6LinkLocalIpnet, _ := net.ParseCIDR(ipv6LinkLocalAddr)
	_, ipv6MulticastIpnet, _ := net.ParseCIDR(ipv6MulticastAddr)
	flows = append(flows,
		// Allow IPv6 packets (e.g. Multicast Listener Report Message V2) which are sent from link-local addresses in
		// SpoofGuardTable, so that these packets will not be dropped.
		SpoofGuardTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(binding.ProtocolIPv6).
			MatchSrcIPNet(*ipv6LinkLocalIpnet).
			Action().GotoTable(IPv6Table.GetID()).
			Done(),
		// Handle IPv6 Neighbor Solicitation and Neighbor Advertisement as a regular L2 learning Switch by using normal.
		IPv6Table.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(binding.ProtocolICMPv6).
			MatchICMPv6Type(135).
			MatchICMPv6Code(0).
			Action().Normal().
			Done(),
		IPv6Table.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(binding.ProtocolICMPv6).
			MatchICMPv6Type(136).
			MatchICMPv6Code(0).
			Action().Normal().
			Done(),
		// Handle IPv6 multicast packets as a regular L2 learning Switch by using normal.
		// It is used to ensure that all kinds of IPv6 multicast packets are properly handled (e.g. Multicast Listener
		// Report Message V2).
		IPv6Table.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(binding.ProtocolIPv6).
			MatchDstIPNet(*ipv6MulticastIpnet).
			Action().Normal().
			Done(),
	)
	return flows
}

// conjunctionActionFlow generates the flow to jump to a specific table if policyRuleConjunction ID is matched. Priority of
// conjunctionActionFlow is created at priorityLow for k8s network policies, and *priority assigned by PriorityAssigner for AntreaPolicy.
func (f *featureNetworkPolicy) conjunctionActionFlow(conjunctionID uint32, table binding.Table, nextTable uint8, priority *uint16, enableLogging bool) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var ofPriority uint16
	if priority == nil {
		ofPriority = priorityLow
	} else {
		ofPriority = *priority
	}
	conjReg := TFIngressConjIDField
	labelField := IngressRuleCTLabel
	tableID := table.GetID()
	if _, ok := f.egressTables[tableID]; ok {
		conjReg = TFEgressConjIDField
		labelField = EgressRuleCTLabel
	}
	conjActionFlow := func(proto binding.Protocol) binding.Flow {
		ctZone := CtZone
		if proto == binding.ProtocolIPv6 {
			ctZone = CtZoneV6
		}
		if enableLogging {
			fb := table.BuildFlow(ofPriority).MatchProtocol(proto).
				MatchConjID(conjunctionID)
			if f.ovsMetersAreSupported {
				fb = fb.Action().Meter(PacketInMeterIDNP)
			}
			return fb.
				Action().LoadToRegField(conjReg, conjunctionID).                           // Traceflow.
				Action().LoadRegMark(DispositionAllowRegMark, CustomReasonLoggingRegMark). // AntreaPolicy, Enable logging.
				Action().SendToController(uint8(PacketInReasonNP)).
				Action().CT(true, nextTable, ctZone, f.ctZoneSrcField). // CT action requires commit flag if actions other than NAT without arguments are specified.
				LoadToLabelField(uint64(conjunctionID), labelField).
				CTDone().
				Cookie(cookieID).
				Done()
		}
		return table.BuildFlow(ofPriority).MatchProtocol(proto).
			MatchConjID(conjunctionID).
			Action().LoadToRegField(conjReg, conjunctionID).        // Traceflow.
			Action().CT(true, nextTable, ctZone, f.ctZoneSrcField). // CT action requires commit flag if actions other than NAT without arguments are specified.
			LoadToLabelField(uint64(conjunctionID), labelField).
			CTDone().
			Cookie(cookieID).
			Done()
	}
	var flows []binding.Flow
	for _, proto := range f.ipProtocols {
		flows = append(flows, conjActionFlow(proto))
	}
	return flows
}

// conjunctionActionDenyFlow generates the flow to mark the packet to be denied (dropped or rejected) if policyRuleConjunction
// ID is matched. Any matched flow will be dropped in corresponding metric tables.
func (f *featureNetworkPolicy) conjunctionActionDenyFlow(conjunctionID uint32, table binding.Table, priority *uint16, disposition uint32, enableLogging bool) binding.Flow {
	ofPriority := *priority
	metricTable := IngressMetricTable
	tableID := table.GetID()
	if _, ok := f.egressTables[tableID]; ok {
		metricTable = EgressMetricTable
	}

	flowBuilder := table.BuildFlow(ofPriority).
		MatchConjID(conjunctionID).
		Action().LoadToRegField(CNPDenyConjIDField, conjunctionID).
		Action().LoadRegMark(CnpDenyRegMark)

	var customReason int
	if f.enableDenyTracking {
		customReason += CustomReasonDeny
		flowBuilder = flowBuilder.
			Action().LoadToRegField(APDispositionField, disposition)
	}
	if enableLogging {
		customReason += CustomReasonLogging
		flowBuilder = flowBuilder.
			Action().LoadToRegField(APDispositionField, disposition)
	}
	if disposition == DispositionRej {
		customReason += CustomReasonReject
	}

	if enableLogging || f.enableDenyTracking || disposition == DispositionRej {
		if f.ovsMetersAreSupported {
			flowBuilder = flowBuilder.Action().Meter(PacketInMeterIDNP)
		}
		flowBuilder = flowBuilder.
			Action().LoadToRegField(CustomReasonField, uint32(customReason)).
			Action().SendToController(uint8(PacketInReasonNP))
	}

	// We do not drop the packet immediately but send the packet to the metric table to update the rule metrics.
	return flowBuilder.Action().GotoTable(metricTable.GetID()).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		Done()
}

func (f *featureNetworkPolicy) conjunctionActionPassFlow(conjunctionID uint32, table binding.Table, priority *uint16, enableLogging bool) binding.Flow {
	ofPriority := *priority
	conjReg := TFIngressConjIDField
	nextTable := IngressRuleTable
	tableID := table.GetID()
	if _, ok := f.egressTables[tableID]; ok {
		conjReg = TFEgressConjIDField
		nextTable = EgressRuleTable
	}
	flowBuilder := table.BuildFlow(ofPriority).MatchConjID(conjunctionID).
		Action().LoadToRegField(conjReg, conjunctionID)
	if enableLogging {
		flowBuilder = flowBuilder.
			Action().LoadRegMark(DispositionPassRegMark, CustomReasonLoggingRegMark).
			Action().SendToController(uint8(PacketInReasonNP))
	}
	return flowBuilder.Action().GotoTable(nextTable.GetID()).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		Done()
}

func (c *client) Disconnect() error {
	return c.bridge.Disconnect()
}

func newFlowCategoryCache() *flowCategoryCache {
	return &flowCategoryCache{}
}

// establishedConnectionFlows generates flows to ensure established connections skip the NetworkPolicy rules.
func (f *featureNetworkPolicy) establishedConnectionFlows() []binding.Flow {
	// egressDropTable checks the source address of packets, and drops packets sent from the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the established connections need not to be checked with the
	// egressRuleTable or the egressDropTable.
	egressDropTable := EgressDefaultTable
	// ingressDropTable checks the destination address of packets, and drops packets sent to the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the established connections need not to be checked with the
	// ingressRuleTable or ingressDropTable.
	ingressDropTable := IngressDefaultTable
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var allEstFlows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		egressEstFlow := EgressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(false).
			MatchCTStateEst(true).
			Action().GotoTable(egressDropTable.GetNext()).
			Done()
		ingressEstFlow := IngressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(false).
			MatchCTStateEst(true).
			Action().GotoTable(ingressDropTable.GetNext()).
			Done()
		allEstFlows = append(allEstFlows, egressEstFlow, ingressEstFlow)
	}
	if !f.enableAntreaPolicy {
		return allEstFlows
	}
	var apFlows []binding.Flow
	for _, table := range GetAntreaPolicyEgressTables() {
		for _, ipProtocol := range f.ipProtocols {
			apEgressEstFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(false).
				MatchCTStateEst(true).
				Action().GotoTable(egressDropTable.GetNext()).
				Done()
			apFlows = append(apFlows, apEgressEstFlow)
		}
	}
	for _, table := range GetAntreaPolicyIngressTables() {
		for _, ipProtocol := range f.ipProtocols {
			apIngressEstFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(false).
				MatchCTStateEst(true).
				Action().GotoTable(ingressDropTable.GetNext()).
				Done()
			apFlows = append(apFlows, apIngressEstFlow)
		}
	}
	allEstFlows = append(allEstFlows, apFlows...)
	return allEstFlows
}

// relatedConnectionFlows generates flows to ensure related connections skip the NetworkPolicy rules.
func (f *featureNetworkPolicy) relatedConnectionFlows() []binding.Flow {
	// egressDropTable checks the source address of packets, and drops packets sent from the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the related connections need not to be checked with the
	// egressRuleTable or the egressDropTable.
	egressDropTable := EgressDefaultTable
	// ingressDropTable checks the destination address of packets, and drops packets sent to the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the related connections need not to be checked with the
	// ingressRuleTable or ingressDropTable.
	ingressDropTable := IngressDefaultTable
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		egressRelFlow := EgressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(false).
			MatchCTStateRel(true).
			Action().GotoTable(egressDropTable.GetNext()).
			Done()
		ingressRelFlow := IngressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(false).
			MatchCTStateRel(true).
			Action().GotoTable(ingressDropTable.GetNext()).
			Done()
		flows = append(flows, egressRelFlow, ingressRelFlow)
	}
	if !f.enableAntreaPolicy {
		return flows
	}
	for _, table := range GetAntreaPolicyEgressTables() {
		for _, ipProto := range f.ipProtocols {
			apEgressRelFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(cookieID).
				MatchProtocol(ipProto).
				MatchCTStateNew(false).
				MatchCTStateRel(true).
				Action().GotoTable(egressDropTable.GetNext()).
				Done()
			flows = append(flows, apEgressRelFlow)
		}
	}
	for _, table := range GetAntreaPolicyIngressTables() {
		for _, ipProto := range f.ipProtocols {
			apIngressRelFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(cookieID).
				MatchProtocol(ipProto).
				MatchCTStateNew(false).
				MatchCTStateRel(true).
				Action().GotoTable(ingressDropTable.GetNext()).
				Done()
			flows = append(flows, apIngressRelFlow)
		}
	}
	return flows
}

// rejectBypassNetworkpolicyFlows generates flows to ensure reject responses generated by the controller skip the
// NetworkPolicy rules.
func (f *featureNetworkPolicy) rejectBypassNetworkpolicyFlows() []binding.Flow {
	// egressDropTable checks the source address of packets, and drops packets sent from the AppliedToGroup but not
	// matching the NetworkPolicy rules. Generated reject responses need not to be checked with the
	// egressRuleTable or the egressDropTable.
	egressDropTable := EgressDefaultTable
	// ingressDropTable checks the destination address of packets, and drops packets sent to the AppliedToGroup but not
	// matching the NetworkPolicy rules. Generated reject responses need not to be checked with the
	// ingressRuleTable or ingressDropTable.
	ingressDropTable := IngressDefaultTable
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		egressRejFlow := EgressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchRegFieldWithValue(CustomReasonField, CustomReasonReject).
			Action().GotoTable(egressDropTable.GetNext()).
			Done()
		ingressRejFlow := IngressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchRegFieldWithValue(CustomReasonField, CustomReasonReject).
			Action().GotoTable(ingressDropTable.GetID()).
			Done()
		flows = append(flows, egressRejFlow, ingressRejFlow)
	}
	if !f.enableAntreaPolicy {
		return flows
	}
	for _, table := range GetAntreaPolicyEgressTables() {
		for _, ipProtocol := range f.ipProtocols {
			apEgressRejFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegFieldWithValue(CustomReasonField, CustomReasonReject).
				Action().GotoTable(egressDropTable.GetNext()).
				Done()
			flows = append(flows, apEgressRejFlow)
		}
	}
	for _, table := range GetAntreaPolicyIngressTables() {
		for _, ipProtocol := range f.ipProtocols {
			apIngressRejFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegFieldWithValue(CustomReasonField, CustomReasonReject).
				Action().GotoTable(ingressDropTable.GetNext()).
				Done()
			flows = append(flows, apIngressRejFlow)
		}
	}
	return flows
}

func (f *featureNetworkPolicy) addFlowMatch(fb binding.FlowBuilder, matchKey *types.MatchKey, matchValue interface{}) binding.FlowBuilder {
	switch matchKey {
	case MatchDstOFPort:
		// ofport number in NXM_NX_REG1 is used in ingress rule to match packets sent to local Pod.
		fb = fb.MatchRegFieldWithValue(TargetOFPortField, uint32(matchValue.(int32)))
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
	case MatchTCPSrcPort:
		fallthrough
	case MatchTCPv6SrcPort:
		fallthrough
	case MatchUDPSrcPort:
		fallthrough
	case MatchUDPv6SrcPort:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol())
		portValue := matchValue.(types.BitRange)
		if portValue.Value > 0 {
			fb = fb.MatchSrcPort(portValue.Value, portValue.Mask)
		}
	case MatchICMPType:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol())
		if matchValue != nil {
			fb = fb.MatchICMPType(uint8(*matchValue.(*int32)))
		}
	case MatchICMPCode:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol())
		if matchValue != nil {
			fb = fb.MatchICMPCode(uint8(*matchValue.(*int32)))
		}
	case MatchICMPv6Type:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol())
		if matchValue != nil {
			fb = fb.MatchICMPv6Type(uint8(*matchValue.(*int32)))
		}
	case MatchICMPv6Code:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol())
		if matchValue != nil {
			fb = fb.MatchICMPv6Code(uint8(*matchValue.(*int32)))
		}
	case MatchServiceGroupID:
		fb = fb.MatchRegFieldWithValue(ServiceGroupIDField, matchValue.(uint32))
	}
	return fb
}

// conjunctionExceptionFlow generates the flow to jump to a specific table if both policyRuleConjunction ID and except address are matched.
// Keeping this for reference to generic exception flow.
func (f *featureNetworkPolicy) conjunctionExceptionFlow(conjunctionID uint32, tableID uint8, nextTable uint8, matchKey *types.MatchKey, matchValue interface{}) binding.Flow {
	conjReg := TFIngressConjIDField
	if tableID == EgressRuleTable.GetID() {
		conjReg = TFEgressConjIDField
	}
	fb := getTableByID(tableID).BuildFlow(priorityNormal).MatchConjID(conjunctionID)
	return f.addFlowMatch(fb, matchKey, matchValue).
		Action().LoadToRegField(conjReg, conjunctionID). // Traceflow.
		Action().GotoTable(nextTable).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		Done()
}

// conjunctiveMatchFlow generates the flow to set conjunctive actions if the match condition is matched.
func (f *featureNetworkPolicy) conjunctiveMatchFlow(tableID uint8, matchPairs []matchPair, priority *uint16, actions []*conjunctiveAction) binding.Flow {
	var ofPriority uint16
	if priority != nil {
		ofPriority = *priority
	} else {
		ofPriority = priorityNormal
	}
	fb := getTableByID(tableID).BuildFlow(ofPriority)
	for _, eachMatchPair := range matchPairs {
		fb = f.addFlowMatch(fb, eachMatchPair.matchKey, eachMatchPair.matchValue)
	}
	if f.deterministic {
		sort.Sort(conjunctiveActionsInOrder(actions))
	}
	for _, act := range actions {
		fb.Action().Conjunction(act.conjID, act.clauseID, act.nClause)
	}
	return fb.Cookie(f.cookieAllocator.Request(f.category).Raw()).Done()
}

// defaultDropFlow generates the flow to drop packets if the match condition is matched.
func (f *featureNetworkPolicy) defaultDropFlow(table binding.Table, matchPairs []matchPair) binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	fb := table.BuildFlow(priorityNormal)
	for _, eachMatchPair := range matchPairs {
		fb = f.addFlowMatch(fb, eachMatchPair.matchKey, eachMatchPair.matchValue)
	}
	if f.enableDenyTracking {
		return fb.Action().Drop().
			Action().LoadRegMark(DispositionDropRegMark, CustomReasonDenyRegMark).
			Action().SendToController(uint8(PacketInReasonNP)).
			Cookie(cookieID).
			Done()
	}
	return fb.Action().Drop().
		Cookie(cookieID).
		Done()
}

// dnsPacketInFlow generates the flow to send dns response packets of fqdn policy selected Pods to the fqdnController for
// processing.
func (f *featureNetworkPolicy) dnsPacketInFlow(conjunctionID uint32) binding.Flow {
	return AntreaPolicyIngressRuleTable.ofTable.BuildFlow(priorityDNSIntercept).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchConjID(conjunctionID).
		Action().LoadToRegField(CustomReasonField, CustomReasonDNS).
		Action().SendToController(uint8(PacketInReasonNP)).
		Done()
}

// localProbeFlows generates the flows to forward locally generated request packets to stageConntrack directly, bypassing
// ingress rules of Network Policies. The packets are sent by kubelet to probe the liveness/readiness of local Pods.
// On Linux and when OVS kernel datapath is used, the probe packets are identified by matching the HostLocalSourceMark.
// On Windows or when OVS userspace (netdev) datapath is used, we need a different approach because:
// 1. On Windows, kube-proxy userspace mode is used, and currently there is no way to distinguish kubelet generated traffic
//    from kube-proxy proxied traffic.
// 2. pkt_mark field is not properly supported for OVS userspace (netdev) datapath.
// When proxyAll is disabled, the probe packets are identified by matching the source IP is the Antrea gateway IP;
// otherwise, the packets are identified by matching both the Antrea gateway IP and NotServiceCTMark. Note that, when
// proxyAll is disabled, currently there is no way to distinguish kubelet generated traffic from kube-proxy proxied traffic
// only by matching the Antrea gateway IP. There is a defect that NodePort Service access by external clients will be
// masqueraded as the Antrea gateway IP to bypass NetworkPolicies. See https://github.com/antrea-io/antrea/issues/280.
func (f *featurePodConnectivity) localProbeFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	if runtime.IsWindowsPlatform() {
		var ctMarksToMatch []*binding.CtMark
		if f.proxyAll {
			ctMarksToMatch = append(ctMarksToMatch, NotServiceCTMark)
		}
		for ipProtocol, gatewayIP := range f.gatewayIPs {
			flows = append(flows, IngressSecurityClassifierTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateRpl(false).
				MatchCTStateTrk(true).
				MatchSrcIP(gatewayIP).
				MatchCTMark(ctMarksToMatch...).
				Action().GotoStage(stageConntrack).
				Done())
		}
	} else {
		for _, ipProtocol := range f.ipProtocols {
			flows = append(flows, IngressSecurityClassifierTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateRpl(false).
				MatchCTStateTrk(true).
				MatchPktMark(types.HostLocalSourceMark, &types.HostLocalSourceMark).
				Action().GotoStage(stageConntrack).
				Done())
		}
	}
	return flows
}

// ingressClassifierFlows generates the flows to classify the packets from local Pods or the Antrea gateway to different
// tables within stageIngressSecurity.
func (f *featureNetworkPolicy) ingressClassifierFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	return []binding.Flow{
		// This generates the flow to match the packets to the Antrea gateway and forward them to IngressMetricTable.
		IngressSecurityClassifierTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchRegMark(ToGatewayRegMark).
			Action().GotoTable(IngressMetricTable.GetID()).
			Done(),
		// This generates the flow to match the packets to tunnel and forward them to IngressMetricTable.
		IngressSecurityClassifierTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchRegMark(ToTunnelRegMark).
			Action().GotoTable(IngressMetricTable.GetID()).
			Done(),
		// This generates the flow to match the packets to uplink and forward them to IngressMetricTable.
		IngressSecurityClassifierTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchRegMark(ToUplinkRegMark).
			Action().GotoTable(IngressMetricTable.GetID()).
			Done(),
	}
}

// snatSkipNodeFlow generates the flow to skip SNAT for connection destined for the transport IP of a remote Node.
func (f *featureEgress) snatSkipNodeFlow(nodeIP net.IP) binding.Flow {
	ipProtocol := getIPProtocol(nodeIP)
	return EgressMarkTable.ofTable.BuildFlow(priorityHigh).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(ipProtocol).
		MatchDstIP(nodeIP).
		Action().LoadRegMark(ToGatewayRegMark).
		Action().GotoStage(stageSwitching).
		Done()
}

// snatIPFromTunnelFlow generates the flow that marks SNAT packets tunnelled from remote Nodes. The SNAT IP matches the
// packet's tunnel destination IP.
func (f *featureEgress) snatIPFromTunnelFlow(snatIP net.IP, mark uint32) binding.Flow {
	ipProtocol := getIPProtocol(snatIP)
	return EgressMarkTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(ipProtocol).
		MatchCTStateNew(true).
		MatchCTStateTrk(true).
		MatchTunnelDst(snatIP).
		Action().LoadPktMarkRange(mark, snatPktMarkRange).
		Action().LoadRegMark(ToGatewayRegMark).
		Action().GotoStage(stageSwitching).
		Done()
}

// snatRuleFlow generates the flow that applies the SNAT rule for a local Pod. If the SNAT IP exists on the local Node,
// it sets the packet mark with the ID of the SNAT IP, for the traffic from local Pods to external; if the SNAT IP is
// on a remote Node, it tunnels the packets to the remote Node.
func (f *featureEgress) snatRuleFlow(ofPort uint32, snatIP net.IP, snatMark uint32, localGatewayMAC net.HardwareAddr) binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	ipProtocol := getIPProtocol(snatIP)
	if snatMark != 0 {
		// Local SNAT IP.
		return EgressMarkTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(true).
			MatchCTStateTrk(true).
			MatchInPort(ofPort).
			Action().LoadPktMarkRange(snatMark, snatPktMarkRange).
			Action().LoadRegMark(ToGatewayRegMark).
			Action().GotoStage(stageSwitching).
			Done()
	}
	// SNAT IP should be on a remote Node.
	return EgressMarkTable.ofTable.BuildFlow(priorityNormal).
		Cookie(cookieID).
		MatchProtocol(ipProtocol).
		MatchInPort(ofPort).
		Action().SetSrcMAC(localGatewayMAC).
		Action().SetDstMAC(GlobalVirtualMAC).
		Action().SetTunnelDst(snatIP). // Set tunnel destination to the SNAT IP.
		Action().LoadRegMark(ToTunnelRegMark).
		Action().GotoStage(stageSwitching).
		Done()
}

// nodePortMarkFlows generates the flows to mark the first packet of Service NodePort connection with ToNodePortAddressRegMark,
// which indicates the Service type is NodePort.
func (f *featureService) nodePortMarkFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for ipProtocol, nodePortAddresses := range f.nodePortAddresses {
		// This generates a flow for every NodePort IP. The flows are used to mark the first packet of NodePort connection
		// from a local Pod.
		for i := range nodePortAddresses {
			flows = append(flows,
				NodePortMarkTable.ofTable.BuildFlow(priorityNormal).
					Cookie(cookieID).
					MatchProtocol(ipProtocol).
					MatchDstIP(nodePortAddresses[i]).
					Action().LoadRegMark(ToNodePortAddressRegMark).
					Done())
		}
		// This generates the flow for the virtual IP. The flow is used to mark the first packet of NodePort connection from
		// the Antrea gateway (the connection is performed DNAT with the virtual IP in host netns).
		flows = append(flows,
			NodePortMarkTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchDstIP(f.virtualIPs[ipProtocol]).
				Action().LoadRegMark(ToNodePortAddressRegMark).
				Done())
	}

	return flows
}

// serviceLearnFlow generates the flow with learn action which adds new flows in SessionAffinityTable according to the
// Endpoint selection decision.
func (f *featureService) serviceLearnFlow(groupID binding.GroupIDType,
	svcIP net.IP,
	svcPort uint16,
	protocol binding.Protocol,
	affinityTimeout uint16,
	nodeLocalExternal bool,
	svcType v1.ServiceType) binding.Flow {
	// Using unique cookie ID here to avoid learned flow cascade deletion.
	cookieID := f.cookieAllocator.RequestWithObjectID(f.category, uint32(groupID)).Raw()
	var flowBuilder binding.FlowBuilder
	if svcType == v1.ServiceTypeNodePort {
		unionVal := (ToNodePortAddressRegMark.GetValue() << ServiceEPStateField.GetRange().Length()) + EpToLearnRegMark.GetValue()
		flowBuilder = ServiceLBTable.ofTable.BuildFlow(priorityLow).
			Cookie(cookieID).
			MatchProtocol(protocol).
			MatchRegFieldWithValue(NodePortUnionField, unionVal).
			MatchDstPort(svcPort, nil)
	} else {
		flowBuilder = ServiceLBTable.ofTable.BuildFlow(priorityLow).
			Cookie(cookieID).
			MatchProtocol(protocol).
			MatchRegMark(EpToLearnRegMark).
			MatchDstIP(svcIP).
			MatchDstPort(svcPort, nil)
	}

	// affinityTimeout is used as the OpenFlow "hard timeout": learned flow will be removed from
	// OVS after that time regarding of whether traffic is still hitting the flow. This is the
	// desired behavior based on the K8s spec. Note that existing connections will keep going to
	// the same endpoint because of connection tracking; and that is also the desired behavior.
	learnFlowBuilderLearnAction := flowBuilder.
		Action().Learn(SessionAffinityTable.GetID(), priorityNormal, 0, affinityTimeout, cookieID).
		DeleteLearned()
	switch protocol {
	case binding.ProtocolTCP:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedTCPDstPort()
	case binding.ProtocolUDP:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedUDPDstPort()
	case binding.ProtocolSCTP:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedSCTPDstPort()
	case binding.ProtocolTCPv6:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedTCPv6DstPort()
	case binding.ProtocolUDPv6:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedUDPv6DstPort()
	case binding.ProtocolSCTPv6:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedSCTPv6DstPort()
	}
	// If externalTrafficPolicy of NodePort/LoadBalancer is Cluster, the learned flow which
	// is used to match the first packet of NodePort/LoadBalancer also requires SNAT.
	if (svcType == v1.ServiceTypeNodePort || svcType == v1.ServiceTypeLoadBalancer) && !nodeLocalExternal {
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.LoadRegMark(ToClusterServiceRegMark)
	}

	ipProtocol := getIPProtocol(svcIP)
	if ipProtocol == binding.ProtocolIP {
		return learnFlowBuilderLearnAction.
			MatchLearnedDstIP().
			MatchLearnedSrcIP().
			LoadFieldToField(EndpointIPField, EndpointIPField).
			LoadFieldToField(EndpointPortField, EndpointPortField).
			LoadRegMark(EpSelectedRegMark).
			LoadRegMark(RewriteMACRegMark).
			Done().
			Action().LoadRegMark(EpSelectedRegMark).
			Action().NextTable().
			Done()
	} else if ipProtocol == binding.ProtocolIPv6 {
		return learnFlowBuilderLearnAction.
			MatchLearnedDstIPv6().
			MatchLearnedSrcIPv6().
			LoadXXRegToXXReg(EndpointIP6Field, EndpointIP6Field).
			LoadFieldToField(EndpointPortField, EndpointPortField).
			LoadRegMark(EpSelectedRegMark).
			LoadRegMark(RewriteMACRegMark).
			Done().
			Action().LoadRegMark(EpSelectedRegMark).
			Action().NextTable().
			Done()
	}
	return nil
}

// serviceLBFlow generates the flow which uses the specific group to do Endpoint selection.
func (f *featureService) serviceLBFlow(groupID binding.GroupIDType,
	svcIP net.IP,
	svcPort uint16,
	protocol binding.Protocol,
	withSessionAffinity,
	nodeLocalExternal bool,
	serviceType v1.ServiceType) binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var lbResultMark *binding.RegMark
	if withSessionAffinity {
		lbResultMark = EpToLearnRegMark
	} else {
		lbResultMark = EpSelectedRegMark
	}
	regMarksToMatch := []*binding.RegMark{lbResultMark, RewriteMACRegMark}
	var flowBuilder binding.FlowBuilder
	if serviceType == v1.ServiceTypeNodePort {
		// If externalTrafficPolicy of NodePort is Cluster, the first packet of NodePort requires SNAT, so nodeLocalExternal
		// will be false, and ServiceNeedSNATRegMark will be set. If externalTrafficPolicy of NodePort is Local, the first
		// packet of NodePort doesn't require SNAT, ServiceNeedSNATRegMark won't be set.
		unionVal := (ToNodePortAddressRegMark.GetValue() << ServiceEPStateField.GetRange().Length()) + EpToSelectRegMark.GetValue()
		if !nodeLocalExternal {
			regMarksToMatch = append(regMarksToMatch, ToClusterServiceRegMark)
		}
		flowBuilder = ServiceLBTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(protocol).
			MatchRegFieldWithValue(NodePortUnionField, unionVal).
			MatchDstPort(svcPort, nil).
			Action().LoadRegMark(regMarksToMatch...)
	} else {
		if serviceType == v1.ServiceTypeLoadBalancer && !nodeLocalExternal {
			regMarksToMatch = append(regMarksToMatch, ToClusterServiceRegMark)
		}
		// If Service type is LoadBalancer, as above NodePort.
		flowBuilder = ServiceLBTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(protocol).
			MatchDstPort(svcPort, nil).
			MatchDstIP(svcIP).
			MatchRegMark(EpToSelectRegMark).
			Action().LoadRegMark(regMarksToMatch...)
	}
	return flowBuilder.
		Action().LoadToRegField(ServiceGroupIDField, uint32(groupID)).
		Action().Group(groupID).Done()
}

// endpointDNATFlow generates the flow which transforms the Service Cluster IP to the Endpoint IP according to the Endpoint
// selection decision which is stored in regs.
func (f *featureService) endpointDNATFlow(endpointIP net.IP, endpointPort uint16, protocol binding.Protocol) binding.Flow {
	unionVal := (EpSelectedRegMark.GetValue() << EndpointPortField.GetRange().Length()) + uint32(endpointPort)
	flowBuilder := EndpointDNATTable.ofTable.BuildFlow(priorityNormal).
		MatchProtocol(protocol).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchRegFieldWithValue(EpUnionField, unionVal)
	ipProtocol := getIPProtocol(endpointIP)

	if ipProtocol == binding.ProtocolIP {
		ipVal := binary.BigEndian.Uint32(endpointIP.To4())
		flowBuilder = flowBuilder.MatchRegFieldWithValue(EndpointIPField, ipVal)
	} else {
		ipVal := []byte(endpointIP)
		flowBuilder = flowBuilder.MatchXXReg(EndpointIP6Field.GetRegID(), ipVal)
	}

	return flowBuilder.Action().
		CT(true, EndpointDNATTable.GetNext(), f.dnatCtZones[ipProtocol], f.ctZoneSrcField).
		DNAT(
			&binding.IPRange{StartIP: endpointIP, EndIP: endpointIP},
			&binding.PortRange{StartPort: endpointPort, EndPort: endpointPort},
		).
		LoadToCtMark(ServiceCTMark).
		MoveToCtMarkField(PktSourceField, ConnSourceCTMarkField).
		CTDone().
		Done()
}

// serviceEndpointGroup creates/modifies the group/buckets of Endpoints. If the withSessionAffinity is true, then buckets
// will resubmit packets back to ServiceLBTable to trigger the learn flow, the learn flow will then send packets to
// EndpointDNATTable. Otherwise, buckets will resubmit packets to EndpointDNATTable directly.
func (f *featureService) serviceEndpointGroup(groupID binding.GroupIDType, withSessionAffinity bool, endpoints ...proxy.Endpoint) binding.Group {
	group := f.bridge.CreateGroup(groupID).ResetBuckets()
	var resubmitTableID uint8
	if withSessionAffinity {
		resubmitTableID = ServiceLBTable.GetID()
	} else {
		resubmitTableID = EndpointDNATTable.GetID()
	}
	for _, endpoint := range endpoints {
		endpointPort, _ := endpoint.Port()
		endpointIP := net.ParseIP(endpoint.IP())
		portVal := portToUint16(endpointPort)
		ipProtocol := getIPProtocol(endpointIP)

		if ipProtocol == binding.ProtocolIP {
			ipVal := binary.BigEndian.Uint32(endpointIP.To4())
			group = group.Bucket().Weight(100).
				LoadToRegField(EndpointIPField, ipVal).
				LoadToRegField(EndpointPortField, uint32(portVal)).
				ResubmitToTable(resubmitTableID).
				Done()
		} else if ipProtocol == binding.ProtocolIPv6 {
			ipVal := []byte(endpointIP)
			group = group.Bucket().Weight(100).
				LoadXXReg(EndpointIP6Field.GetRegID(), ipVal).
				LoadToRegField(EndpointPortField, uint32(portVal)).
				ResubmitToTable(resubmitTableID).
				Done()
		}
	}
	return group
}

// decTTLFlows generates the flow to process TTL. For the packets forwarded across Nodes, TTL should be decremented by one;
// for packets which enter OVS pipeline from the Antrea gateway, as the host IP stack should have decremented the TTL
// already for such packets, TTL should not be decremented again.
func (f *featurePodConnectivity) decTTLFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows,
			// Skip packets from the gateway interface.
			L3DecTTLTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegMark(FromGatewayRegMark).
				Action().NextTable().
				Done(),
			L3DecTTLTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				Action().DecTTL().
				Action().NextTable().
				Done(),
		)
	}
	return flows
}

// externalFlows generates the flows to perform SNAT for the packets of connection to the external network. The flows identify
// the packets to external network, and send them to EgressMarkTable, where SNAT IPs are looked up for the packets.
func (f *featureEgress) externalFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows,
			// This generates the flow to match the packets sourced from local Pods and destined for external network, then
			// forward them to EgressMarkTable.
			L3ForwardingTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateRpl(false).
				MatchCTStateTrk(true).
				MatchRegMark(FromLocalRegMark).
				Action().GotoTable(EgressMarkTable.GetID()).
				Done(),
			// This generates the flow to match the packets sourced from tunnel and destined for external network, then
			// forward them to EgressMarkTable.
			L3ForwardingTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateRpl(false).
				MatchCTStateTrk(true).
				MatchRegMark(FromTunnelRegMark).
				Action().SetDstMAC(f.gatewayMAC).
				Action().GotoTable(EgressMarkTable.GetID()).
				Done(),
			// This generates the default flow to drop the packets from remote Nodes and there is no matched SNAT policy.
			EgressMarkTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(FromTunnelRegMark).
				Action().Drop().
				Done(),
			// This generates the flow to bypass the packets destined for local Node.
			f.snatSkipNodeFlow(f.nodeIPs[ipProtocol]),
		)
		// This generates the flows to bypass the packets sourced from local Pods and destined for the except CIDRs for Egress.
		for _, cidr := range f.exceptCIDRs[ipProtocol] {
			flows = append(flows, EgressMarkTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchDstIPNet(cidr).
				Action().LoadRegMark(ToGatewayRegMark).
				Action().GotoStage(stageSwitching).
				Done())
		}
	}
	// This generates the flow to match the packets of tracked Egress connection and forward them to stageSwitching.
	flows = append(flows, EgressMarkTable.ofTable.BuildFlow(priorityMiss).
		Cookie(cookieID).
		Action().LoadRegMark(ToGatewayRegMark).
		Action().GotoStage(stageSwitching).
		Done())

	return flows
}

// policyConjKeyFunc knows how to get key of a *policyRuleConjunction.
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

// genPacketInMeter generates a meter entry with specific meterID and rate.
// `rate` is represented as number of packets per second.
// Packets which exceed the rate will be dropped.
func (c *client) genPacketInMeter(meterID binding.MeterIDType, rate uint32) binding.Meter {
	meter := c.bridge.CreateMeter(meterID, ofctrl.MeterBurst|ofctrl.MeterPktps).ResetMeterBands()
	meter = meter.MeterBand().
		MeterType(ofctrl.MeterDrop).
		Rate(rate).
		Burst(2 * rate).
		Done()
	return meter
}

func generatePipeline(pipelineID binding.PipelineID, requiredTables []*Table) binding.Pipeline {
	var ofTables []binding.Table
	for _, table := range requiredTables {
		// Generate a sequencing ID for the flow table.
		tableID := binding.NextTableID()
		// Initialize a flow table.
		table.ofTable = binding.NewOFTable(tableID, table.name, table.stage, pipelineID, table.missAction)
		ofTables = append(ofTables, table.ofTable)
		tableCache.Add(table)
	}
	return binding.NewPipeline(pipelineID, ofTables)
}

// realizePipelines sets next ID and missing action for every flow table in every pipeline and realize it on OVS bridge.
func (c *client) realizePipelines() {
	for _, pipeline := range c.pipelines {
		tables := pipeline.ListAllTables()
		for i := range tables {
			var nextID uint8
			var missAction binding.MissActionType
			if pipeline.IsLastTable(tables[i]) {
				// For the last table in a pipeline, set the miss action to TableMissActionDrop and next ID to LastTableID.
				nextID = binding.LastTableID
				missAction = binding.TableMissActionDrop
			} else {
				nextID = tables[i+1].GetID()
				// For a table (not the last one) in a pipeline, set the next ID to the next table ID. If the miss action
				// of the table is TableMissActionNone, set the miss action to TableMissActionNext.
				if tables[i].GetMissAction() != binding.TableMissActionNone {
					missAction = tables[i].GetMissAction()
				} else {
					missAction = binding.TableMissActionNext
				}
			}
			tables[i].SetNext(nextID)
			tables[i].SetMissAction(missAction)
			// Realize the table on OVS bridge.
			c.bridge.CreateTable(tables[i], nextID, missAction)
		}
	}
}

func pipelineClassifyFlow(cookieID uint64, protocol binding.Protocol, pipeline binding.Pipeline) binding.Flow {
	targetTable := pipeline.GetFirstTable()
	return PipelineRootClassifierTable.ofTable.BuildFlow(priorityNormal).
		Cookie(cookieID).
		MatchProtocol(protocol).
		Action().GotoTable(targetTable.GetID()).
		Done()
}

// igmpPktInFlows generates the flow to load CustomReasonIGMPRegMark to mark the IGMP packet in MulticastTable and sends
// it to antrea-agent on MulticastTable.
func (f *featureMulticast) igmpPktInFlows(reason uint8) []binding.Flow {
	flows := []binding.Flow{
		// Set a custom reason for the IGMP packets, and then send it to antrea-agent and forward it normally in the
		// OVS bridge, so that the OVS multicast db cache can be updated, and antrea-agent can identify the local multicast
		// group and its members in the meanwhile.
		// Do not set dst IP address because IGMPv1 report message uses target multicast group as IP destination in
		// the packet.
		MulticastTable.ofTable.BuildFlow(priorityHigh).
			Cookie(f.cookieAllocator.Request(f.category).Raw()).
			MatchProtocol(binding.ProtocolIGMP).
			MatchRegMark(FromLocalRegMark).
			Action().LoadRegMark(CustomReasonIGMPRegMark).
			Action().SendToController(reason).
			Action().Normal().
			Done(),
	}
	return flows
}

// localMulticastForwardFlow generates the flow to forward multicast packets with OVS action "normal", and outputs
// it to Antrea gateway in the meanwhile, so that the packet can be forwarded to local Pods which have joined the Multicast
// group and to the external receivers. For external multicast packets accessing to the given multicast IP also hits the
// flow, and the packet is not sent back to Antrea gateway because OVS datapath will drop it when it finds the output
// port is the same as the input port.
func (f *featureMulticast) localMulticastForwardFlow(multicastIP net.IP) []binding.Flow {
	return []binding.Flow{
		MulticastTable.ofTable.BuildFlow(priorityNormal).
			Cookie(f.cookieAllocator.Request(f.category).Raw()).
			MatchProtocol(binding.ProtocolIP).
			MatchDstIP(multicastIP).
			Action().Output(config.HostGatewayOFPort).
			Action().Normal().
			Done(),
	}
}

// externalMulticastReceiverFlow generates the flow to output multicast packets to Antrea gateway, so that local Pods can
// send multicast packets to access the external receivers. For the case that one or more local Pods have joined the target
// multicast group, it is handled by the flows created by function "localMulticastForwardFlow" after local Pods report the
// IGMP membership.
func (f *featureMulticast) externalMulticastReceiverFlow() binding.Flow {
	return MulticastTable.ofTable.BuildFlow(priorityLow).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(binding.ProtocolIP).
		MatchDstIPNet(*mcastCIDR).
		Action().Output(config.HostGatewayOFPort).
		Done()
}

// NewClient is the constructor of the Client interface.
func NewClient(bridgeName string,
	mgmtAddr string,
	enableProxy bool,
	enableAntreaPolicy bool,
	enableEgress bool,
	enableDenyTracking bool,
	proxyAll bool,
	connectUplinkToBridge bool,
	enableMulticast bool) Client {
	bridge := binding.NewOFBridge(bridgeName, mgmtAddr)
	c := &client{
		bridge:                bridge,
		enableProxy:           enableProxy,
		proxyAll:              proxyAll,
		enableAntreaPolicy:    enableAntreaPolicy,
		enableDenyTracking:    enableDenyTracking,
		enableEgress:          enableEgress,
		enableMulticast:       enableMulticast,
		connectUplinkToBridge: connectUplinkToBridge,
		pipelines:             make(map[binding.PipelineID]binding.Pipeline),
		packetInHandlers:      map[uint8]map[string]PacketInHandler{},
		ovsctlClient:          ovsctl.NewClient(bridgeName),
		ovsMetersAreSupported: ovsMetersAreSupported(),
	}
	c.ofEntryOperations = c
	return c
}

type conjunctiveActionsInOrder []*conjunctiveAction

func (sl conjunctiveActionsInOrder) Len() int      { return len(sl) }
func (sl conjunctiveActionsInOrder) Swap(i, j int) { sl[i], sl[j] = sl[j], sl[i] }
func (sl conjunctiveActionsInOrder) Less(i, j int) bool {
	if sl[i].conjID != sl[j].conjID {
		return sl[i].conjID < sl[j].conjID
	}
	if sl[i].clauseID != sl[j].clauseID {
		return sl[i].clauseID < sl[j].clauseID
	}
	return sl[i].nClause < sl[j].nClause
}

// l3FwdFlowToLocalPodCIDR generates the flow to match the packets to local per-Node IPAM Pods.
func (f *featurePodConnectivity) l3FwdFlowToLocalPodCIDR() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	regMarksToMatch := []*binding.RegMark{NotRewriteMACRegMark}
	if f.connectUplinkToBridge {
		regMarksToMatch = append(regMarksToMatch, binding.NewRegMark(VLANIDField, 0))
	}
	for ipProtocol, cidr := range f.localCIDRs {
		// This generates the flow to match the packets destined for local Pods without RewriteMACRegMark.
		flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityLow).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchDstIPNet(cidr).
			MatchRegMark(regMarksToMatch...).
			Action().GotoStage(stageSwitching).
			Done())
	}
	return flows
}

// l3FwdFlowToNode generates the flows to match the packets destined for local Node.
func (f *featurePodConnectivity) l3FwdFlowToNode() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var regMarksToMatch []*binding.RegMark
	if f.connectUplinkToBridge {
		regMarksToMatch = append(regMarksToMatch, binding.NewRegMark(VLANIDField, 0))
	}
	var flows []binding.Flow
	for ipProtocol, nodeIP := range f.nodeIPs {
		flows = append(flows,
			// This generates the flow to match the packets sourced from local Antrea Pods and destined for local Node
			// via bridge local port.
			L3ForwardingTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchDstIP(nodeIP).
				MatchRegMark(AntreaFlexibleIPAMRegMark).
				MatchRegMark(regMarksToMatch...).
				Action().SetDstMAC(f.nodeConfig.UplinkNetConfig.MAC).
				Action().GotoStage(stageSwitching).
				Done(),
			// When Node bridge local port and uplink port connect to OVS, this generates the flow to match the reply
			// packets of connection initiated through the bridge local port with FromBridgeCTMark.
			L3ForwardingTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTMark(FromBridgeCTMark).
				MatchRegMark(regMarksToMatch...).
				MatchCTStateRpl(true).
				MatchCTStateTrk(true).
				Action().SetDstMAC(f.nodeConfig.UplinkNetConfig.MAC).
				Action().GotoStage(stageSwitching).
				Done())
	}
	return flows
}

// l3FwdFlowToExternal generates the flow to match the packets destined for external network.
func (f *featurePodConnectivity) l3FwdFlowToExternal() binding.Flow {
	// TODO: load ToUplinkRegMark for packets from Antrea IPAM Pod.
	return L3ForwardingTable.ofTable.BuildFlow(priorityMiss).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		Action().LoadRegMark(ToGatewayRegMark).
		Action().GotoStage(stageSwitching).
		Done()
}

// hostBridgeLocalFlows generates the flows to match the packets forwarded between bridge local port and uplink port.
func (f *featurePodConnectivity) hostBridgeLocalFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	return []binding.Flow{
		// This generates the flow to forward the packets from uplink port to bridge local port.
		ClassifierTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchInPort(config.UplinkOFPort).
			Action().Output(config.BridgeOFPort).
			Done(),
		// This generates the flow to forward the packets from bridge local port to uplink port.
		ClassifierTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchInPort(config.BridgeOFPort).
			Action().Output(config.UplinkOFPort).
			Done(),
	}
}

// hostBridgeUplinkVLANFlows generates the flows to match VLAN packets from uplink port.
func (f *featurePodConnectivity) hostBridgeUplinkVLANFlows() []binding.Flow {
	vlanMask := uint16(openflow13.OFPVID_PRESENT)
	return []binding.Flow{
		VLANTable.ofTable.BuildFlow(priorityLow).
			Cookie(f.cookieAllocator.Request(f.category).Raw()).
			MatchInPort(config.UplinkOFPort).
			MatchVLAN(false, 0, &vlanMask).
			Action().PopVLAN().
			Action().NextTable().
			Done(),
	}
}

// podVLANFlows generates the flows to match the packets from Pod and set VLAN ID.
func (f *featurePodConnectivity) podVLANFlow(podOFPort uint32, vlanID uint16) binding.Flow {
	return VLANTable.ofTable.BuildFlow(priorityLow).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchInPort(podOFPort).
		MatchRegMark(OutputToUplinkRegMark).
		Action().PushVLAN(EtherTypeDot1q).
		Action().SetVLAN(vlanID).
		Action().NextTable().
		Done()
}

// preRoutingClassifierFlows generates the flow to classify packets in stagePreRouting.
func (f *featureService) preRoutingClassifierFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow

	targetTables := []uint8{SessionAffinityTable.GetID(), ServiceLBTable.GetID()}
	if f.proxyAll {
		targetTables = append([]uint8{NodePortMarkTable.GetID()}, targetTables...)
	}
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows,
			// This generates the default flow to match the first packet of a connection.
			PreRoutingClassifierTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				Action().ResubmitToTables(targetTables...).
				Done(),
		)
	}

	return flows
}

// l3FwdFlowsToExternalEndpoint generates the flows to forward the packets of Service connection to external network.
func (f *featureService) l3FwdFlowsToExternalEndpoint() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	if f.connectUplinkToBridge {
		flows = append(flows,
			// When AntreaIPAM is enabled, this generates the flow to match the packets sourced from per-Node IPAM Pod and
			// destined for external network.
			L3ForwardingTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchRegMark(RewriteMACRegMark, NotAntreaFlexibleIPAMRegMark).
				MatchCTMark(ServiceCTMark).
				Action().SetDstMAC(f.gatewayMAC).
				Action().LoadRegMark(ToGatewayRegMark).
				Action().GotoTable(L3DecTTLTable.GetID()).
				Done(),
			// When AntreaIPAM is enabled, this generates the flow to match the packets sourced from Antrea IPAM Pod and
			// destined for external network.
			L3ForwardingTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchRegMark(AntreaFlexibleIPAMRegMark).
				MatchCTMark(ServiceCTMark).
				Action().GotoTable(L3DecTTLTable.GetID()).
				Done(),
		)
	} else {
		// This generates the flow to match the packets sourced from per-Node IPAM Pod and destined for external network.
		flows = append(flows,
			L3ForwardingTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchRegMark(RewriteMACRegMark).
				MatchCTMark(ServiceCTMark).
				Action().SetDstMAC(f.gatewayMAC).
				Action().LoadRegMark(ToGatewayRegMark).
				Action().GotoTable(L3DecTTLTable.GetID()).
				Done(),
		)
	}
	return flows
}

// podHairpinSNATFlow generates the flow to match the first packet of hairpin connection initiated through a local Pod.
// ConnSNATCTMark and HairpinCTMark will be loaded in DNAT CT zone.
func (f *featureService) podHairpinSNATFlow(endpoint net.IP) binding.Flow {
	ipProtocol := getIPProtocol(endpoint)
	return ServiceMarkTable.ofTable.BuildFlow(priorityLow).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(ipProtocol).
		MatchCTStateNew(true).
		MatchCTStateTrk(true).
		MatchSrcIP(endpoint).
		MatchDstIP(endpoint).
		Action().CT(true, ServiceMarkTable.GetNext(), f.dnatCtZones[ipProtocol], f.ctZoneSrcField).
		LoadToCtMark(ConnSNATCTMark, HairpinCTMark).
		CTDone().
		Done()
}

// gatewaySNATFlows generate the flows to match the first packet of Service connection initiated through the Antrea gateway,
// and the connection requires SNAT.
func (f *featureService) gatewaySNATFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		// This generates the flow to match the first packet of hairpin connection initiated through the Antrea gateway.
		// ConnSNATCTMark and HairpinCTMark will be loaded in DNAT CT zone.
		flows = append(flows, ServiceMarkTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(true).
			MatchCTStateTrk(true).
			MatchRegMark(FromGatewayRegMark, ToGatewayRegMark).
			Action().CT(true, ServiceMarkTable.GetNext(), f.dnatCtZones[ipProtocol], f.ctZoneSrcField).
			LoadToCtMark(ConnSNATCTMark, HairpinCTMark).
			CTDone().
			Done())

		var pktDstRegMarks []*binding.RegMark
		if f.networkConfig.TrafficEncapMode.SupportsEncap() {
			pktDstRegMarks = append(pktDstRegMarks, ToTunnelRegMark)
		}
		if f.networkConfig.TrafficEncapMode.SupportsNoEncap() && runtime.IsWindowsPlatform() {
			pktDstRegMarks = append(pktDstRegMarks, ToUplinkRegMark)
		}
		for _, pktDstRegMark := range pktDstRegMarks {
			// This generates the flow to match the first packet of NodePort / LoadBalancer connection initiated through the
			// Antrea gateway and externalTrafficPolicy of the Service is Cluster, and the selected Endpoint is on a remote
			// Node, then ConnSNATCTMark will be loaded in DNAT CT zone, indicating that SNAT is required for the connection.
			flows = append(flows, ServiceMarkTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(FromGatewayRegMark, pktDstRegMark, ToClusterServiceRegMark).
				Action().CT(true, ServiceMarkTable.GetNext(), f.dnatCtZones[ipProtocol], f.ctZoneSrcField).
				LoadToCtMark(ConnSNATCTMark).
				CTDone().
				Done())
		}
	}

	return flows
}

func getCachedFlows(cache *flowCategoryCache) []binding.Flow {
	var flows []binding.Flow
	cache.Range(func(key, value interface{}) bool {
		fCache := value.(flowCache)
		for _, flow := range fCache {
			flow.Reset()
			flows = append(flows, flow)
		}
		return true
	})
	return flows
}

func getZoneSrcField(connectUplinkToBridge bool) *binding.RegField {
	if connectUplinkToBridge {
		return CtZoneField
	}
	return nil
}
