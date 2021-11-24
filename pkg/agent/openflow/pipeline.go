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
	"math"
	"net"
	"sort"
	"sync"
	"time"

	"antrea.io/ofnet/ofctrl"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	"antrea.io/antrea/pkg/agent/types"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/ovs/ovsctl"
)

var (
	PipelineClassifierTable      = newFeatureTable("PipelineClassification")
	ARPSpoofGuardTable           = newFeatureTable("ARPSpoofGuard")
	ARPResponderTable            = newFeatureTable("ARPResponder")
	ClassifierTable              = newFeatureTable("Classification")
	UplinkTable                  = newFeatureTable("Uplink")
	SpoofGuardTable              = newFeatureTable("SpoofGuard")
	IPv6Table                    = newFeatureTable("IPv6")
	NodePortProbeTable           = newFeatureTable("NodePortProbe")
	SNATConntrackTable           = newFeatureTable("SNATConntrackZone")
	ConntrackTable               = newFeatureTable("ConntrackZone")
	ConntrackStateTable          = newFeatureTable("ConntrackState")
	SessionAffinityTable         = newFeatureTable("SessionAffinity")
	DNATTable                    = newFeatureTable("DNAT")
	ServiceLBTable               = newFeatureTable("ServiceLB")
	EndpointDNATTable            = newFeatureTable("EndpointDNAT")
	AntreaPolicyEgressRuleTable  = newFeatureTable("AntreaPolicyEgressRule")
	EgressRuleTable              = newFeatureTable("EgressRule")
	EgressDefaultTable           = newFeatureTable("EgressDefaultRule")
	EgressMetricTable            = newFeatureTable("EgressMetric")
	L3ForwardingTable            = newFeatureTable("L3Forwarding")
	ServiceHairpinMarkTable      = newFeatureTable("ServiceHairpinMark")
	L3DecTTLTable                = newFeatureTable("IPTTLDec")
	SNATTable                    = newFeatureTable("SNATTable")
	SNATConntrackCommitTable     = newFeatureTable("SNATConntrackCommit")
	L2ForwardingCalcTable        = newFeatureTable("L2Forwarding")
	AntreaPolicyIngressRuleTable = newFeatureTable("AntreaPolicyIngressRule")
	IngressRuleTable             = newFeatureTable("IngressRule")
	IngressDefaultTable          = newFeatureTable("IngressDefaultRule")
	IngressMetricTable           = newFeatureTable("IngressMetric")
	ConntrackCommitTable         = newFeatureTable("ConntrackCommit")
	L2ForwardingOutTable         = newFeatureTable("L2ForwardingOut")

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

var (
	// egressTables map records all IDs of tables related to
	// egress rules.
	egressTables = map[uint8]struct{}{}

	// tableCache caches the OpenFlow tables used in the pipeline, and it supports using the table ID and name as the index to query the OpenFlow table.
	tableCache = cache.NewIndexer(tableIDKeyFunc, cache.Indexers{tableNameIndex: tableNameIndexFunc})
)

func tableNameIndexFunc(obj interface{}) ([]string, error) {
	ft := obj.(*FeatureTable)
	return []string{ft.GetName()}, nil
}

func tableIDKeyFunc(obj interface{}) (string, error) {
	ft := obj.(*FeatureTable)
	return fmt.Sprintf("%d", ft.GetID()), nil
}

func getTableByID(id uint8) binding.Table {
	obj, exists, _ := tableCache.GetByKey(fmt.Sprintf("%d", id))
	if !exists {
		return nil
	}
	return obj.(*FeatureTable).ofTable
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

func GetAntreaPolicyEgressTables() []*FeatureTable {
	return []*FeatureTable{
		AntreaPolicyEgressRuleTable,
		EgressDefaultTable,
	}
}

func GetAntreaPolicyIngressTables() []*FeatureTable {
	return []*FeatureTable{
		AntreaPolicyIngressRuleTable,
		IngressDefaultTable,
	}
}

func GetAntreaPolicyBaselineTierTables() []*FeatureTable {
	return []*FeatureTable{
		EgressDefaultTable,
		IngressDefaultTable,
	}
}

func GetAntreaPolicyMultiTierTables() []*FeatureTable {
	return []*FeatureTable{
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
)

var DispositionToString = map[uint32]string{
	DispositionAllow: "Allow",
	DispositionDrop:  "Drop",
	DispositionRej:   "Reject",
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
	enableWireGuard       bool
	connectUplinkToBridge bool
	roundInfo             types.RoundInfo
	cookieAllocator       cookie.Allocator
	bridge                binding.Bridge

	featurePodConnectivity *featurePodConnectivity
	featureService         *featureService
	featureEgress          *featureEgress
	featureNetworkPolicy   *featureNetworkPolicy
	featureTraceflow       *featureTraceflow

	pipelines   map[ofProtocol]binding.Pipeline
	ipProtocols []binding.Protocol

	// ofEntryOperations is a wrapper interface for OpenFlow entry Add / Modify / Delete operations. It
	// enables convenient mocking in unit tests.
	ofEntryOperations OFEntryOperations
	// replayMutex provides exclusive access to the OFSwitch to the ReplayFlows method.
	replayMutex   sync.RWMutex
	nodeConfig    *config.NodeConfig
	networkConfig *config.NetworkConfig
	egressConfig  *config.EgressConfig
	gatewayOFPort uint32
	// ovsDatapathType is the type of the datapath used by the bridge.
	ovsDatapathType ovsconfig.OVSDatapathType
	// ovsMetersAreSupported indicates whether the OVS datapath supports OpenFlow meters.
	ovsMetersAreSupported bool
	// ovsctlClient is the interface for executing OVS "ovs-ofctl" and "ovs-appctl" commands.
	ovsctlClient ovsctl.OVSCtlClient
	// deterministic represents whether to generate flows deterministically.
	// For example, if a flow has multiple actions, setting it to true can get consistent flow.
	// Enabling it may carry a performance impact. It's disabled by default and should only be used in testing.
	deterministic bool
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

// defaultFlows generates the default flows of all tables.
func defaultFlows(pipeline binding.Pipeline, category uint64) []binding.Flow {
	var flows []binding.Flow
	for _, table := range pipeline.ListAllTables() {
		flowBuilder := table.BuildFlow(priorityMiss)
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
		flows = append(flows, flowBuilder.Cookie(category).Done())
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

func (c *client) Disconnect() error {
	return c.bridge.Disconnect()
}

func newFlowCategoryCache() *flowCategoryCache {
	return &flowCategoryCache{}
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

func generatePipeline(templates []*pipelineTemplate) binding.Pipeline {
	pipelineID := binding.NewPipelineID()
	sortedTableMap := make(map[binding.StageID][]binding.Table)

	// PipelineClassifierTable ID is always 0, and it is the first table for all pipelines. Create PipelineClassifierTable
	// on the bridge when building a pipeline.
	if PipelineClassifierTable.ofTable == nil {
		PipelineClassifierTable.ofTable = binding.NewOFTable(binding.NextTableID(), PipelineClassifierTable.name, binding.ClassifierStage, binding.AllPipelines)
	}
	for i := binding.ClassifierStage; i <= binding.LastStage; i++ {
		tableMap := make(map[*FeatureTable]uint8, 0)

		for _, template := range templates {
			if tables, found := template.stageTables[i]; found {
				for _, tr := range tables {
					t := tr.table
					p := tr.priority
					op, ok := tableMap[t]
					if !ok {
						t.features = sets.NewInt(int(template.feature))
						tableMap[t] = p
						continue
					}
					if op < p {
						tableMap[t] = p
						t.features.Insert(int(template.feature))
					}
				}
			}
		}
		if len(tableMap) == 0 {
			continue
		}

		// Sort the tables according to the priority in the same stage.
		type tablePriority struct {
			*FeatureTable
			priority uint8
		}
		tempSlice := make([]tablePriority, 0)
		for t, p := range tableMap {
			tempSlice = append(tempSlice, tablePriority{t, p})
		}
		sort.Slice(tempSlice, func(i, j int) bool {
			return tempSlice[i].priority > tempSlice[j].priority
		})

		tableSlice := make([]binding.Table, 0)
		for id := range tempSlice {
			// Generate the sequencing IDs for tables.
			tableID := binding.NextTableID()
			ft := tempSlice[id].FeatureTable
			ft.ofTable = binding.NewOFTable(tableID, ft.name, i, pipelineID)
			addTableToCache(ft)
			tableSlice = append(tableSlice, ft.ofTable)
		}
		sortedTableMap[i] = tableSlice
	}
	return binding.NewPipeline(pipelineID, sortedTableMap)
}

func createPipelineOnBridge(bridge binding.Bridge, pipelines map[ofProtocol]binding.Pipeline) {
	bridge.CreateTable(PipelineClassifierTable.ofTable, binding.LastTableID, binding.TableMissActionDrop)
	for _, pipeline := range pipelines {
		tables := pipeline.ListAllTables()
		for i, t := range tables {
			var nextID uint8
			var missAction binding.MissActionType
			if pipeline.IsLastTable(t) {
				nextID = binding.LastTableID
				missAction = binding.TableMissActionDrop
			} else {
				nextID = tables[i+1].GetID()
				missAction = binding.TableMissActionNext
			}
			tables[i].SetNext(nextID)
			bridge.CreateTable(t, nextID, missAction)
		}
	}
}

func pipelineClassifyFlow(protocol binding.Protocol, pipeline binding.Pipeline) binding.Flow {
	targetTable := pipeline.GetFirstTable()
	return PipelineClassifierTable.ofTable.BuildFlow(priorityNormal).
		MatchProtocol(protocol).
		Action().ResubmitToTables(targetTable.GetID()).
		Done()
}

// NewClient is the constructor of the Client interface.
func NewClient(bridgeName string,
	mgmtAddr string,
	ovsDatapathType ovsconfig.OVSDatapathType,
	enableProxy bool,
	enableAntreaPolicy bool,
	enableEgress bool,
	enableDenyTracking bool,
	proxyAll bool,
	connectUplinkToBridge bool) Client {
	bridge := binding.NewOFBridge(bridgeName, mgmtAddr)
	c := &client{
		bridge:                bridge,
		enableProxy:           enableProxy,
		proxyAll:              proxyAll,
		enableAntreaPolicy:    enableAntreaPolicy,
		enableDenyTracking:    enableDenyTracking,
		enableEgress:          enableEgress,
		connectUplinkToBridge: connectUplinkToBridge,
		pipelines:             make(map[ofProtocol]binding.Pipeline),
		ovsctlClient:          ovsctl.NewClient(bridgeName),
		ovsDatapathType:       ovsDatapathType,
		ovsMetersAreSupported: ovsMetersAreSupported(ovsDatapathType),
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

func addTableToCache(ft *FeatureTable) {
	_, exists, _ := tableCache.GetByKey(fmt.Sprintf("%d", ft.GetID()))
	if !exists {
		tableCache.Add(ft)
	}
}
