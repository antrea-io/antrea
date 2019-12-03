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
	"sync"

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
	l2ForwardingOutTable  binding.TableIDType = 110

	// Flow priority level
	priorityHigh   = 210
	priorityNormal = 200
	priorityLow    = 190
	priorityMiss   = 80

	// Traffic marks
	markTrafficFromTunnel  = 0
	markTrafficFromGateway = 1
	markTrafficFromLocal   = 2
)

var (
	// ofPortMarkRange takes the 16th bit of register marksReg to indicate if the ofPort number of an interface
	// is found or not. Its value is 0x1 if yes.
	ofPortMarkRange = binding.Range{16, 16}
	// ofPortRegRange takes a 32-bit range of register portCacheReg to cache the ofPort number of the interface.
	ofPortRegRange = binding.Range{0, 31}
)

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

func i2h(data int64) string {
	return fmt.Sprintf("0x%x", data)
}

const (
	emptyPlaceholderStr = ""
	// marksReg stores traffic-source mark and pod-found mark.
	// traffic-source resides in [0..15], pod-found resides in [16].
	marksReg     regType = 0
	portCacheReg regType = 1

	ctZone = 0xfff0

	portFoundMark = 0x1
	gatewayCTMark = 0x20
)

var (
	globalVirtualMAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")
)

//go:generate mockgen -copyright_file ../../../hack/boilerplate/license_header.go.txt -package=testing -destination testing/mock_operations.go github.com/vmware-tanzu/antrea/pkg/agent/openflow FlowOperations

type FlowOperations interface {
	Add(flow binding.Flow) error
	Modify(flow binding.Flow) error
	Delete(flow binding.Flow) error
}

type flowCache map[string]binding.Flow

type flowCategoryCache struct {
	sync.Map
}

type client struct {
	bridge                                    binding.Bridge
	pipeline                                  map[binding.TableIDType]binding.Table
	nodeFlowCache, podFlowCache, serviceCache *flowCategoryCache // cache for corresponding deletions
	flowOperations                            FlowOperations
	// policyCache is a map from PolicyRule ID to policyRuleConjunction. It's guaranteed that one policyRuleConjunction
	// is processed by at most one goroutine at any given time.
	policyCache       sync.Map
	conjMatchFlowLock sync.Mutex // Lock for access globalConjMatchFlowCache
	// globalConjMatchFlowCache is a global map for conjMatchFlowContext. The key is a string generated from the
	// conjMatchFlowContext.
	globalConjMatchFlowCache map[string]*conjMatchFlowContext
}

func (c *client) Add(flow binding.Flow) error {
	return flow.Add()
}

func (c *client) Modify(flow binding.Flow) error {
	return flow.Modify()
}

func (c *client) Delete(flow binding.Flow) error {
	return flow.Delete()
}

// defaultFlows generates the default flows of all tables.
func (c *client) defaultFlows() (flows []binding.Flow) {
	for _, table := range c.pipeline {
		flowBuilder := table.BuildFlow().Priority(priorityMiss).MatchProtocol(binding.ProtocolIP)
		switch table.GetMissAction() {
		case binding.TableMissActionNext:
			flowBuilder = flowBuilder.Action().Resubmit(emptyPlaceholderStr, table.GetNext())
		case binding.TableMissActionNormal:
			flowBuilder = flowBuilder.Action().Normal()
		case binding.TableMissActionDrop:
			fallthrough
		default:
			flowBuilder = flowBuilder.Action().Drop()
		}
		flows = append(flows, flowBuilder.Done())
	}
	return flows
}

// tunnelClassifierFlow generates the flow to mark traffic comes from the tunnelOFPort.
func (c *client) tunnelClassifierFlow(tunnelOFPort uint32) binding.Flow {
	return c.pipeline[classifierTable].BuildFlow().Priority(priorityNormal).
		MatchInPort(tunnelOFPort).
		Action().LoadRegRange(int(marksReg), markTrafficFromTunnel, binding.Range{0, 15}).
		Action().Resubmit(emptyPlaceholderStr, conntrackTable).
		Done()
}

// gatewayClassifierFlow generates the flow to mark traffic comes from the gatewayOFPort.
func (c *client) gatewayClassifierFlow(gatewayOFPort uint32) binding.Flow {
	classifierTable := c.pipeline[classifierTable]
	return classifierTable.BuildFlow().Priority(priorityNormal).
		MatchInPort(gatewayOFPort).
		Action().LoadRegRange(int(marksReg), markTrafficFromGateway, binding.Range{0, 15}).
		Action().Resubmit(emptyPlaceholderStr, classifierTable.GetNext()).
		Done()
}

// podClassifierFlow generates the flow to mark traffic comes from the podOFPort.
func (c *client) podClassifierFlow(podOFPort uint32) binding.Flow {
	classifierTable := c.pipeline[classifierTable]
	return classifierTable.BuildFlow().Priority(priorityLow).
		MatchInPort(podOFPort).
		Action().LoadRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
		Action().Resubmit(emptyPlaceholderStr, classifierTable.GetNext()).
		Done()
}

// connectionTrackFlows generates flows that redirect traffic to ct_zone and handle traffic according to ct_state:
// 1) commit new connections to ct that sent from non-gateway.
// 2) Add ct_mark on traffic replied from the host gateway.
// 3) Cache src MAC if traffic comes from the host gateway and rewrite the dst MAC on traffic replied from Pod to the
// cached MAC.
// 4) Drop all invalid traffic.
func (c *client) connectionTrackFlows() (flows []binding.Flow) {
	connectionTrackTable := c.pipeline[conntrackTable]
	baseConnectionTrackFlow := connectionTrackTable.BuildFlow().MatchProtocol(binding.ProtocolIP).Priority(priorityNormal).
		Action().CT(false, connectionTrackTable.GetNext(), ctZone).CTDone().
		Done()
	flows = append(flows, baseConnectionTrackFlow)

	connectionTrackStateTable := c.pipeline[conntrackStateTable]
	gatewayReplyFlow := connectionTrackStateTable.BuildFlow().MatchProtocol(binding.ProtocolIP).Priority(priorityHigh).
		MatchRegRange(int(marksReg), markTrafficFromGateway, binding.Range{0, 15}).
		MatchCTMark(i2h(gatewayCTMark)).
		MatchCTState("-new+trk").
		Action().Resubmit(emptyPlaceholderStr, connectionTrackStateTable.GetNext()).
		Done()
	flows = append(flows, gatewayReplyFlow)

	gatewaySendFlow := connectionTrackStateTable.BuildFlow().MatchProtocol(binding.ProtocolIP).Priority(priorityNormal).
		MatchRegRange(int(marksReg), markTrafficFromGateway, binding.Range{0, 15}).
		MatchCTState("+new+trk").
		Action().CT(true, connectionTrackStateTable.GetNext(), ctZone).LoadToMark(gatewayCTMark).MoveToLabel(binding.NxmFieldSrcMAC, &binding.Range{0, 47}, &binding.Range{0, 47}).CTDone().
		Done()
	flows = append(flows, gatewaySendFlow)

	podReplyGatewayFlow := connectionTrackStateTable.BuildFlow().MatchProtocol(binding.ProtocolIP).Priority(priorityNormal).
		MatchCTMark(i2h(gatewayCTMark)).
		MatchCTState("-new+trk").
		Action().MoveRange(binding.NxmFieldCtLabel, binding.NxmFieldDstMAC, binding.Range{0, 47}, binding.Range{0, 47}).
		Action().Resubmit(emptyPlaceholderStr, connectionTrackStateTable.GetNext()).
		Done()
	flows = append(flows, podReplyGatewayFlow)

	nonGatewaySendFlow := connectionTrackStateTable.BuildFlow().MatchProtocol(binding.ProtocolIP).Priority(priorityLow).
		MatchCTState("+new+trk").
		Action().CT(true, connectionTrackStateTable.GetNext(), ctZone).CTDone().
		Done()
	flows = append(flows, nonGatewaySendFlow)

	invCTFlow := connectionTrackStateTable.BuildFlow().MatchProtocol(binding.ProtocolIP).Priority(priorityNormal).
		MatchCTState("+new+inv").
		Action().Drop().
		Done()
	flows = append(flows, invCTFlow)

	return flows
}

// l2ForwardCalcFlow generates the flow that matches dst MAC and loads ofPort to reg.
func (c *client) l2ForwardCalcFlow(dstMAC net.HardwareAddr, ofPort uint32) binding.Flow {
	l2FwdCalcTable := c.pipeline[l2ForwardingCalcTable]
	return l2FwdCalcTable.BuildFlow().Priority(priorityNormal).
		MatchDstMAC(dstMAC).
		Action().LoadRegRange(int(portCacheReg), ofPort, ofPortRegRange).
		Action().LoadRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
		Action().Resubmit(emptyPlaceholderStr, l2FwdCalcTable.GetNext()).
		Done()
}

// l2ForwardOutputFlow generates the flow that outputs packets to OVS port after L2 forwarding calculation.
func (c *client) l2ForwardOutputFlow() binding.Flow {
	return c.pipeline[l2ForwardingOutTable].BuildFlow().
		Priority(priorityNormal).
		MatchProtocol(binding.ProtocolIP).
		MatchRegRange(int(marksReg), portFoundMark, ofPortMarkRange).
		Action().OutputRegRange(int(portCacheReg), ofPortRegRange).
		Done()
}

// l3FlowsToPod generates the flow to rewrite MAC if the packet is received from tunnel port and destined for local Pods.
func (c *client) l3FlowsToPod(localGatewayMAC net.HardwareAddr, podInterfaceIP net.IP, podInterfaceMAC net.HardwareAddr) binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	// Rewrite src MAC to local gateway MAC, and rewrite dst MAC to pod MAC
	return l3FwdTable.BuildFlow().MatchProtocol(binding.ProtocolIP).Priority(priorityNormal).
		MatchDstMAC(globalVirtualMAC).
		MatchDstIP(podInterfaceIP).
		Action().SetSrcMAC(localGatewayMAC).
		Action().SetDstMAC(podInterfaceMAC).
		Action().DecTTL().
		Action().Resubmit(emptyPlaceholderStr, l3FwdTable.GetNext()).
		Done()
}

// l3ToGatewayFlow generates flow that rewrites MAC of the packet received from tunnel port and destined to local gateway.
func (c *client) l3ToGatewayFlow(localGatewayIP net.IP, localGatewayMAC net.HardwareAddr) binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	return l3FwdTable.BuildFlow().MatchProtocol(binding.ProtocolIP).Priority(priorityNormal).
		MatchDstIP(localGatewayIP).
		Action().SetDstMAC(localGatewayMAC).
		Action().Resubmit(emptyPlaceholderStr, l3FwdTable.GetNext()).
		Done()
}

// l3FwdFlowToRemote generates the L3 forward flow on source node to support traffic to remote pods/gateway.
func (c *client) l3FwdFlowToRemote(localGatewayMAC net.HardwareAddr, peerSubnet net.IPNet, tunnelPeer net.IP) binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	// Rewrite src MAC to local gateway MAC and rewrite dst MAC to virtual MAC
	return l3FwdTable.BuildFlow().MatchProtocol(binding.ProtocolIP).Priority(priorityNormal).
		MatchDstIPNet(peerSubnet).
		Action().DecTTL().
		Action().SetSrcMAC(localGatewayMAC).
		Action().SetDstMAC(globalVirtualMAC).
		Action().SetTunnelDst(tunnelPeer).
		Action().Resubmit(emptyPlaceholderStr, l3FwdTable.GetNext()).
		Done()
}

// arpResponderFlow generates the ARP responder flow entry that replies request comes from local gateway for peer
// gateway MAC.
func (c *client) arpResponderFlow(peerGatewayIP net.IP) binding.Flow {
	return c.pipeline[arpResponderTable].BuildFlow().
		MatchProtocol(binding.ProtocolARP).Priority(priorityNormal).
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
		Done()
}

// podIPSpoofGuardFlow generates the flow to check IP traffic sent out from local pod. Traffic from host gateway interface
// will not be checked, since it might be pod to service traffic or host namespace traffic.
func (c *client) podIPSpoofGuardFlow(ifIP net.IP, ifMAC net.HardwareAddr, ifOFPort uint32) binding.Flow {
	ipPipeline := c.pipeline
	ipSpoofGuardTable := ipPipeline[spoofGuardTable]
	return ipSpoofGuardTable.BuildFlow().MatchProtocol(binding.ProtocolIP).Priority(priorityNormal).
		MatchInPort(ifOFPort).
		MatchSrcMAC(ifMAC).
		MatchSrcIP(ifIP).
		Action().Resubmit(emptyPlaceholderStr, ipSpoofGuardTable.GetNext()).
		Done()
}

// gatewayARPSpoofGuardFlow generates the flow to skip ARP UP check on packets sent out from the local gateway interface.
func (c *client) gatewayARPSpoofGuardFlow(gatewayOFPort uint32) binding.Flow {
	return c.pipeline[spoofGuardTable].BuildFlow().MatchProtocol(binding.ProtocolARP).Priority(priorityNormal).
		MatchInPort(gatewayOFPort).
		Action().Resubmit(emptyPlaceholderStr, arpResponderTable).
		Done()
}

// arpSpoofGuardFlow generates the flow to check ARP traffic sent out from local pods interfaces.
func (c *client) arpSpoofGuardFlow(ifIP net.IP, ifMAC net.HardwareAddr, ifOFPort uint32) binding.Flow {
	return c.pipeline[spoofGuardTable].BuildFlow().MatchProtocol(binding.ProtocolARP).Priority(priorityNormal).
		MatchInPort(ifOFPort).
		MatchARPSha(ifMAC).
		MatchARPSpa(ifIP).
		Action().Resubmit(emptyPlaceholderStr, arpResponderTable).
		Done()
}

// gatewayIPSpoofGuardFlow generates the flow to skip spoof guard checking for traffic sent from gateway interface.
func (c *client) gatewayIPSpoofGuardFlow(gatewayOFPort uint32) binding.Flow {
	ipPipeline := c.pipeline
	ipSpoofGuardTable := ipPipeline[spoofGuardTable]
	return ipSpoofGuardTable.BuildFlow().Priority(priorityNormal).
		MatchProtocol(binding.ProtocolIP).
		MatchInPort(gatewayOFPort).
		Action().Resubmit(emptyPlaceholderStr, ipSpoofGuardTable.GetNext()).
		Done()
}

// serviceCIDRDNATFlow generates flows to match dst IP in service CIDR and output to host gateway interface directly.
func (c *client) serviceCIDRDNATFlow(serviceCIDR *net.IPNet, gatewayOFPort uint32) binding.Flow {
	return c.pipeline[dnatTable].BuildFlow().MatchProtocol(binding.ProtocolIP).Priority(priorityNormal).
		MatchDstIPNet(*serviceCIDR).
		Action().Output(int(gatewayOFPort)).
		Done()
}

// arpNormalFlow generates the flow to response arp in normal way if no flow in arpResponderTable is matched.
func (c *client) arpNormalFlow() binding.Flow {
	return c.pipeline[arpResponderTable].BuildFlow().
		MatchProtocol(binding.ProtocolARP).Priority(priorityLow).
		Action().Normal().Done()
}

// conjunctionActionFlow generates the flow to resubmit to a specific table if policyRuleConjunction ID is matched. Priority of
// conjunctionActionFlow is priorityLow.
func (c *client) conjunctionActionFlow(conjunctionID uint32, tableID binding.TableIDType, nextTable binding.TableIDType) binding.Flow {
	return c.pipeline[tableID].BuildFlow().
		MatchProtocol(binding.ProtocolIP).Priority(priorityLow).
		MatchConjID(conjunctionID).
		Action().Resubmit(emptyPlaceholderStr, nextTable).Done()
}

func (c *client) Disconnect() error {
	return c.bridge.Disconnect()
}

func newFlowCategoryCache() *flowCategoryCache {
	return &flowCategoryCache{}
}

// establishedConnectionFlows generates flows to ensure established connections skip the NetworkPolicy rules.
func (c *client) establishedConnectionFlows() (flows []binding.Flow) {
	// egressDropTable checks the source address of packets, and drops packets sent from the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the established connections need not to be checked with the
	// egressRuleTable or the egressDropTable.
	egressDropTable := c.pipeline[egressDefaultTable]
	egressEstFlow := c.pipeline[egressRuleTable].BuildFlow().MatchProtocol(binding.ProtocolIP).Priority(priorityHigh).
		MatchCTState("-new+est").
		Action().Resubmit(emptyPlaceholderStr, egressDropTable.GetNext()).Done()
	// ingressDropTable checks the destination address of packets, and drops packets sent to the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the established connections need not to be checked with the
	// ingressRuleTable or ingressDropTable.
	ingressDropTable := c.pipeline[ingressDefaultTable]
	ingressEstFlow := c.pipeline[ingressRuleTable].BuildFlow().MatchProtocol(binding.ProtocolIP).Priority(priorityHigh).
		MatchCTState("-new+est").
		Action().Resubmit(emptyPlaceholderStr, ingressDropTable.GetNext()).Done()
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
		fb = fb.MatchProtocol(binding.ProtocolIP).MatchRegRange(int(portCacheReg), uint32(matchValue.(int32)), ofPortRegRange)
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
func (c *client) conjunctionExceptionFlow(conjunctionID uint32, tableID binding.TableIDType, nextTable binding.TableIDType, matchKey int, matchValue interface{}) binding.Flow {
	fb := c.pipeline[tableID].BuildFlow().Priority(priorityNormal).MatchConjID(conjunctionID)
	return c.addFlowMatch(fb, matchKey, matchValue).
		Action().Resubmit(emptyPlaceholderStr, nextTable).Done()
}

// conjunctiveMatchFlow generates the flow to set conjunctive actions if the match condition is matched.
func (c *client) conjunctiveMatchFlow(tableID binding.TableIDType, matchKey int, matchValue interface{}, actions ...*conjunctiveAction) binding.Flow {
	fb := c.pipeline[tableID].BuildFlow().Priority(priorityNormal)
	fb = c.addFlowMatch(fb, matchKey, matchValue)
	for _, act := range actions {
		fb.Action().Conjunction(act.conjID, act.clauseID, act.nClause)
	}
	return fb.Done()
}

// defaultDropFlow generates the flow to drop packets if the match condition is matched.
func (c *client) defaultDropFlow(tableID binding.TableIDType, matchKey int, matchValue interface{}) binding.Flow {
	fb := c.pipeline[tableID].BuildFlow().Priority(priorityNormal)
	return c.addFlowMatch(fb, matchKey, matchValue).
		Action().Drop().Done()
}

// localProbeFlow generates the flow to resubmit packets to l2ForwardingOutTable. The packets are sent from Node to probe the liveness/readiness of local Pods.
func (c *client) localProbeFlow(localGatewayIP net.IP) binding.Flow {
	return c.pipeline[ingressRuleTable].BuildFlow().Priority(priorityHigh).
		MatchProtocol(binding.ProtocolIP).
		MatchSrcIP(localGatewayIP).
		Action().Resubmit(emptyPlaceholderStr, l2ForwardingOutTable).Done()
}

// NewClient is the constructor of the Client interface.
func NewClient(bridgeName string) Client {
	bridge := binding.NewBridge(bridgeName)
	c := &client{
		bridge: bridge,
		pipeline: map[binding.TableIDType]binding.Table{
			classifierTable:       bridge.CreateTable(classifierTable, spoofGuardTable, binding.TableMissActionNext),
			spoofGuardTable:       bridge.CreateTable(spoofGuardTable, conntrackTable, binding.TableMissActionDrop),
			conntrackTable:        bridge.CreateTable(conntrackTable, conntrackStateTable, binding.TableMissActionNext),
			conntrackStateTable:   bridge.CreateTable(conntrackStateTable, dnatTable, binding.TableMissActionNext),
			dnatTable:             bridge.CreateTable(dnatTable, egressRuleTable, binding.TableMissActionNext),
			l3ForwardingTable:     bridge.CreateTable(l3ForwardingTable, l2ForwardingCalcTable, binding.TableMissActionNext),
			l2ForwardingCalcTable: bridge.CreateTable(l2ForwardingCalcTable, ingressRuleTable, binding.TableMissActionNext),
			l2ForwardingOutTable:  bridge.CreateTable(l2ForwardingOutTable, binding.LastTableID, binding.TableMissActionDrop),
			arpResponderTable:     bridge.CreateTable(arpResponderTable, binding.LastTableID, binding.TableMissActionDrop),
			egressRuleTable:       bridge.CreateTable(egressRuleTable, egressDefaultTable, binding.TableMissActionNext),
			egressDefaultTable:    bridge.CreateTable(egressDefaultTable, l3ForwardingTable, binding.TableMissActionNext),
			ingressRuleTable:      bridge.CreateTable(ingressRuleTable, ingressDefaultTable, binding.TableMissActionNext),
			ingressDefaultTable:   bridge.CreateTable(ingressDefaultTable, l2ForwardingOutTable, binding.TableMissActionNext),
		},
		nodeFlowCache:            newFlowCategoryCache(),
		podFlowCache:             newFlowCategoryCache(),
		serviceCache:             newFlowCategoryCache(),
		policyCache:              sync.Map{},
		globalConjMatchFlowCache: map[string]*conjMatchFlowContext{},
	}
	c.flowOperations = c
	return c
}
