// Copyright 2021 Antrea Authors
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
	"net"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"

	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type featureID int

const (
	Shared featureID = iota
	PodConnectivity
	VMConnectivity
	NetworkPolicy
	Service
	Egress
	Traceflow
)

type ofProtocol int

const (
	ofProtocolIP ofProtocol = iota
	ofProtocolARP
)

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

var (
	PipelineClassifierTable      = newFeatureTable("PipelineClassification")
	ClassifierTable              = newFeatureTable("Classification")
	UplinkTable                  = newFeatureTable("Uplink")
	SpoofGuardTable              = newFeatureTable("SpoofGuard")
	ARPSpoofGuardTable           = newFeatureTable("ARPSpoofGuard")
	ARPResponderTable            = newFeatureTable("ARPResponder")
	IPv6Table                    = newFeatureTable("IPv6")
	NodePortProbeTable           = newFeatureTable("NodePortProbe")
	ServiceHairpinReplyTable     = newFeatureTable("ServiceHairpinReply")
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
	ServiceHairpinRequestTable   = newFeatureTable("ServiceHairpinRequest")
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

	tableNameIndex = "tableNameIndex"

	// Operation field values in ARP packets
	arpOpRequest = uint16(1)
	arpOpReply   = uint16(2)

	// traceflowTagToSRange stores Traceflow dataplane tag to DSCP bits of
	// IP header ToS field.
	traceflowTagToSRange = binding.IPDSCPToSRange

	GlobalVirtualMAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")

	DispositionToString = map[uint32]string{
		DispositionAllow: "Allow",
		DispositionDrop:  "Drop",
		DispositionRej:   "Reject",
	}
)

type flowCache map[string]binding.Flow

type flowCategoryCache struct {
	sync.Map
}

func newFlowCategoryCache() *flowCategoryCache {
	return &flowCategoryCache{}
}

type FeatureTable struct {
	name     string
	ofTable  binding.Table
	features sets.Int
}

func newFeatureTable(tableName string) *FeatureTable {
	return &FeatureTable{
		name: tableName,
	}
}

func (c *FeatureTable) GetID() uint8 {
	return c.ofTable.GetID()
}

func (c *FeatureTable) GetNext() uint8 {
	return c.ofTable.GetNext()
}

func (c *FeatureTable) GetName() string {
	return c.ofTable.GetName()
}

func (c *FeatureTable) GetOFTable() binding.Table {
	return c.ofTable
}

// SetOFTable is only used for test code.
func (c *FeatureTable) SetOFTable(id uint8) {
	c.ofTable = binding.NewOFTable(id, c.name, 0, 0)
}

// A table with a higher priority is assigned with a lower tableID, which means a packet should enter the table
// before others with lower priorities in the same stage.
type tableRequest struct {
	table    *FeatureTable
	priority uint8
}

type pipelineTemplate struct {
	// Declare the tables and the corresponding priorities in the expected stage.
	// If it is expected to enforce a packet to enter other tables in the same stage after leaving the current table,
	// use a higher priority in the tableRequest.
	stageTables map[binding.StageID][]tableRequest
	feature     featureID
}

type feature interface {
	getFeatureID() featureID
	getTemplate(protocol ofProtocol) *pipelineTemplate
}
