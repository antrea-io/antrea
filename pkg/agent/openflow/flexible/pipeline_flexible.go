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

package flexible

import (
	"fmt"
	"math"
	"net"
	"sort"
	"sync"
	"time"

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

func addTableToCache(ft *FeatureTable) {
	_, exists, _ := tableCache.GetByKey(fmt.Sprintf("%d", ft.GetID()))
	if !exists {
		tableCache.Add(ft)
	}
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

func portToUint16(port int) uint16 {
	if port > 0 && port <= math.MaxUint16 {
		return uint16(port) // lgtm[go/incorrect-integer-conversion]
	}
	klog.Errorf("Port value %d out-of-bounds", port)
	return 0
}

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

func buildPipeline(templates []*pipelineTemplate) binding.Pipeline {
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

func pipelineDefaultFlows(pipeline binding.Pipeline, category uint64) []binding.Flow {
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
