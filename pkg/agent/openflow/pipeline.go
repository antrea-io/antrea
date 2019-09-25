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
	priorityMiss   = 80
	priorityNormal = 200

	// Traffic marks
	markTrafficFromTunnel  = 0
	markTrafficFromGateway = 1
	markTrafficFromLocal   = 2
)

var (
	// ofportMarkRange takes the 16th bit of register marksReg to indicate if the ofport number of an interface
	// is found or not. Its value is 0x1 if yes.
	ofportMarkRange = binding.Range{16, 16}
	// ofportRegRange takes a 32-bit range of register portCacheReg to cache the ofport number of the interface.
	ofportRegRange = binding.Range{0, 31}
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

	ctMarkField  = "ct_mark"
	ctStateFiled = "ct_state"
	inPortField  = "in_port"

	portFoundMark = 0x1
	gatewayCTMark = 0x20

	ipProtocol   = "ip"
	arpProtocol  = "arp"
	icmpProtocol = "icmp"

	globalVirtualMAC = "aa:bb:cc:dd:ee:ff"
)

type client struct {
	bridge                                    binding.Bridge
	pipeline                                  map[binding.TableIDType]binding.Table
	nodeFlowCache, podFlowCache, serviceCache map[string][]binding.Flow // cache for correspond deletions
	policyCache                               map[uint32]*conjunction   // cache for conjunction
}

// defaultFlows generates the default flows of all tables.
func (c *client) defaultFlows() (flows []binding.Flow) {
	for _, table := range c.pipeline {
		flowBuilder := table.BuildFlow().Priority(priorityMiss).MatchProtocol(ipProtocol)
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
		MatchField(inPortField, fmt.Sprint(tunnelOFPort)).
		Action().LoadRange(marksReg.reg(), markTrafficFromTunnel, binding.Range{0, 15}).
		Action().Resubmit(emptyPlaceholderStr, conntrackTable).
		Done()
}

// gatewayClassifierFlow generates the flow to mark traffic comes from the gatewayOFPort.
func (c *client) gatewayClassifierFlow(gatewayOFPort uint32) binding.Flow {
	classifierTable := c.pipeline[classifierTable]
	return classifierTable.BuildFlow().Priority(priorityNormal).
		MatchField(inPortField, fmt.Sprint(gatewayOFPort)).
		Action().LoadRange(marksReg.reg(), markTrafficFromGateway, binding.Range{0, 15}).
		Action().Resubmit(emptyPlaceholderStr, classifierTable.GetNext()).
		Done()
}

// podClassifierFlow generates the flow to mark traffic comes from the podOFPort.
func (c *client) podClassifierFlow(podOFPort uint32) binding.Flow {
	classifierTable := c.pipeline[classifierTable]
	return classifierTable.BuildFlow().Priority(priorityNormal-10).
		MatchField(inPortField, fmt.Sprint(podOFPort)).
		Action().LoadRange(marksReg.reg(), markTrafficFromLocal, binding.Range{0, 15}).
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
	baseConnectionTrackFlow := connectionTrackTable.BuildFlow().MatchProtocol(ipProtocol).Priority(priorityNormal).
		Action().CT(false, connectionTrackTable.GetNext(), ctZone).
		Done()
	flows = append(flows, baseConnectionTrackFlow)

	connectionTrackStateTable := c.pipeline[conntrackStateTable]
	gatewayReplyFlow := connectionTrackStateTable.BuildFlow().MatchProtocol(ipProtocol).Priority(priorityNormal+10).
		MatchFieldRange(marksReg.reg(), fmt.Sprint(markTrafficFromGateway), binding.Range{0, 15}).
		MatchField(ctMarkField, i2h(gatewayCTMark)).
		MatchField(ctStateFiled, "-new+trk").
		Action().Resubmit(emptyPlaceholderStr, connectionTrackStateTable.GetNext()).
		Done()
	flows = append(flows, gatewayReplyFlow)

	gatewaySendFlow := connectionTrackStateTable.BuildFlow().MatchProtocol(ipProtocol).Priority(priorityNormal).
		MatchFieldRange(marksReg.reg(), fmt.Sprint(markTrafficFromGateway), binding.Range{0, 15}).
		MatchField(ctStateFiled, "+new+trk").
		Action().
		CT(
			true,
			connectionTrackStateTable.GetNext(),
			ctZone,
			fmt.Sprintf("load:0x%x->%s", gatewayCTMark, "NXM_NX_CT_MARK[]"),
			fmt.Sprintf("move:NXM_OF_ETH_SRC[]->NXM_NX_CT_LABEL[0..47]"),
		).
		Done()
	flows = append(flows, gatewaySendFlow)

	podReplyGatewayFlow := connectionTrackStateTable.BuildFlow().MatchProtocol(ipProtocol).Priority(priorityNormal).
		MatchField(ctMarkField, i2h(gatewayCTMark)).
		MatchField(ctStateFiled, "-new+trk").
		Action().MoveRange("NXM_NX_CT_LABEL", "NXM_OF_ETH_DST", binding.Range{0, 47}, binding.Range{0, 47}).
		Action().Resubmit(emptyPlaceholderStr, connectionTrackStateTable.GetNext()).
		Done()
	flows = append(flows, podReplyGatewayFlow)

	nonGatewaySendFlow := connectionTrackStateTable.BuildFlow().MatchProtocol(ipProtocol).Priority(priorityNormal-10).
		MatchField(ctStateFiled, "+new+trk").
		Action().CT(true, connectionTrackStateTable.GetNext(), ctZone).
		Done()
	flows = append(flows, nonGatewaySendFlow)

	invCTFlow := connectionTrackStateTable.BuildFlow().MatchProtocol(ipProtocol).Priority(priorityNormal).
		MatchField(ctStateFiled, "+new+inv").
		Action().Drop().
		Done()
	flows = append(flows, invCTFlow)

	return flows
}

// l2ForwardCalcFlow generates the flow that matches dst MAC and loads ofPort to reg.
func (c *client) l2ForwardCalcFlow(dstMAC string, ofPort uint32) binding.Flow {
	l2FwdCalcTable := c.pipeline[l2ForwardingCalcTable]
	return l2FwdCalcTable.BuildFlow().Priority(priorityNormal).
		MatchField("dl_dst", dstMAC).
		Action().LoadRange(portCacheReg.nxm(), ofPort, ofportRegRange).
		Action().LoadRange(marksReg.nxm(), portFoundMark, ofportMarkRange).
		Action().Resubmit(emptyPlaceholderStr, l2FwdCalcTable.GetNext()).
		Done()
}

// l2ForwardOutputFlow generates the flow that outputs packets to OVS port after L2 forwarding calculation.
func (c *client) l2ForwardOutputFlow() binding.Flow {
	return c.pipeline[l2ForwardingOutTable].BuildFlow().
		Priority(priorityNormal).
		MatchProtocol(ipProtocol).
		MatchFieldRange(marksReg.reg(), i2h(portFoundMark), ofportMarkRange).
		Action().OutputFieldRange(portCacheReg.nxm(), ofportRegRange).
		Done()
}

// l3FlowsToPod generates the flow to rewrite MAC if the packet is received from tunnel port and destined for local Pods.
func (c *client) l3FlowsToPod(localGatewayMAC string, podInterfaceIP string, podInterfaceMAC string) binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	// Rewrite src MAC to local gateway MAC, and rewrite dst MAC to pod MAC
	return l3FwdTable.BuildFlow().MatchProtocol(ipProtocol).Priority(priorityNormal).
		MatchField("dl_dst", globalVirtualMAC).
		MatchField("nw_dst", podInterfaceIP).
		Action().SetField("dl_src", localGatewayMAC).
		Action().SetField("dl_dst", podInterfaceMAC).
		Action().DecTTL().
		Action().Resubmit(emptyPlaceholderStr, l3FwdTable.GetNext()).
		Done()
}

// l3ToGatewayFlow generates flow that rewrites MAC of the packet received from tunnel port and destined to local gateway.
func (c *client) l3ToGatewayFlow(localGatewayIP string, localGatewayMAC string) binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	return l3FwdTable.BuildFlow().MatchProtocol(ipProtocol).Priority(priorityNormal).
		MatchField("nw_dst", localGatewayIP).
		Action().SetField("dl_dst", localGatewayMAC).
		Action().Resubmit(emptyPlaceholderStr, l3FwdTable.GetNext()).
		Done()
}

// l3FwdFlowToRemote generates the L3 forward flow on source node to support traffic to remote pods/gateway.
func (c *client) l3FwdFlowToRemote(localGatewayMAC, peerSubnet, peerTunnel string) binding.Flow {
	l3FwdTable := c.pipeline[l3ForwardingTable]
	// Rewrite src MAC to local gateway MAC and rewrite dst MAC to virtual MAC
	return l3FwdTable.BuildFlow().MatchProtocol(ipProtocol).Priority(priorityNormal).
		MatchField("nw_dst", peerSubnet).
		Action().DecTTL().
		Action().SetField("dl_src", localGatewayMAC).
		Action().SetField("dl_dst", globalVirtualMAC).
		Action().SetField("tun_dst", peerTunnel).
		Action().Resubmit(emptyPlaceholderStr, l3FwdTable.GetNext()).
		Done()
}

// arpResponderFlow generates the ARP responder flow entry that replies request comes from local gateway for peer
// gateway MAC.
func (c *client) arpResponderFlow(peerGatewayIP string) binding.Flow {
	return c.pipeline[arpResponderTable].BuildFlow().
		MatchProtocol(arpProtocol).Priority(priorityNormal).
		MatchField("arp_op", "1").
		MatchField("arp_tpa", peerGatewayIP).
		Action().Move("NXM_OF_ETH_SRC", "NXM_OF_ETH_DST").
		Action().SetField("dl_src", globalVirtualMAC).
		Action().Load("NXM_OF_ARP_OP", 2).
		Action().Move("NXM_NX_ARP_SHA", "NXM_NX_ARP_THA").
		Action().SetField("arp_sha", globalVirtualMAC).
		Action().Move("NXM_OF_ARP_SPA", "NXM_OF_ARP_TPA").
		Action().SetField("arp_spa", peerGatewayIP).
		Action().OutputInPort().
		Done()
}

// podIPSpoofGuardFlow generates the flow to check IP traffic sent out from local pod. Traffic from host gateway interface
// will not be checked, since it might be pod to service traffic or host namespace traffic.
func (c *client) podIPSpoofGuardFlow(ifIP string, ifMAC string, ifOfPort uint32) binding.Flow {
	ipPipeline := c.pipeline
	ipSpoofGuardTable := ipPipeline[spoofGuardTable]
	return ipSpoofGuardTable.BuildFlow().MatchProtocol(ipProtocol).Priority(priorityNormal).
		MatchField("in_port", fmt.Sprint(ifOfPort)).
		MatchField("dl_src", ifMAC).
		MatchField("nw_src", ifIP).
		Action().Resubmit(emptyPlaceholderStr, ipSpoofGuardTable.GetNext()).
		Done()
}

// gatewayARPSpoofGuardFlow generates the flow to skip ARP UP check on packets sent out from the local gateway interface.
func (c *client) gatewayARPSpoofGuardFlow(gatewayOFPort uint32) binding.Flow {
	return c.pipeline[spoofGuardTable].BuildFlow().MatchProtocol(arpProtocol).Priority(priorityNormal).
		MatchField("in_port", fmt.Sprint(gatewayOFPort)).
		Action().Resubmit(emptyPlaceholderStr, arpResponderTable).
		Done()
}

// arpSpoofGuardFlow generates the flow to check ARP traffic sent out from local pods interfaces.
func (c *client) arpSpoofGuardFlow(ifIP string, ifMAC string, ifOFPort uint32) binding.Flow {
	return c.pipeline[spoofGuardTable].BuildFlow().MatchProtocol(arpProtocol).Priority(priorityNormal).
		MatchField("in_port", fmt.Sprint(ifOFPort)).
		MatchField("arp_sha", ifMAC).
		MatchField("arp_spa", ifIP).
		Action().Resubmit(emptyPlaceholderStr, arpResponderTable).
		Done()
}

// gatewayIPSpoofGuardFlow generates the flow to skip spoof guard checking for traffic sent from gateway interface.
func (c *client) gatewayIPSpoofGuardFlow(gatewayOFPort uint32) binding.Flow {
	ipPipeline := c.pipeline
	ipSpoofGuardTable := ipPipeline[spoofGuardTable]
	return ipSpoofGuardTable.BuildFlow().Priority(priorityNormal).
		MatchProtocol(ipProtocol).
		MatchField("in_port", fmt.Sprint(gatewayOFPort)).
		Action().Resubmit(emptyPlaceholderStr, ipSpoofGuardTable.GetNext()).
		Done()
}

// serviceCIDRDNATFlow generates flows to match dst IP in service CIDR and output to host gateway interface directly.
func (c *client) serviceCIDRDNATFlow(serviceCIDR *net.IPNet, gatewayOFPort uint32) binding.Flow {
	return c.pipeline[dnatTable].BuildFlow().MatchProtocol(ipProtocol).Priority(priorityNormal).
		MatchField("nw_dst", serviceCIDR.String()).
		Action().Output(int(gatewayOFPort)).
		Done()
}

// arpNormalFlow generates the flow to response arp in normal way if no flow in arpResponderTable is matched.
func (c *client) arpNormalFlow() binding.Flow {
	return c.pipeline[arpResponderTable].BuildFlow().
		MatchProtocol(arpProtocol).Priority(priorityNormal - 10).
		Action().Normal().Done()
}

// conjunctionActionFlow generates the flow to resubmit to a specific table if conjunctive matches are matched.
func (c *client) conjunctionActionFlow(conjunctionID uint32, tableID binding.TableIDType, nextTable binding.TableIDType) binding.Flow {
	return c.pipeline[tableID].BuildFlow().
		MatchProtocol(ipProtocol).Priority(priorityNormal).
		MatchField("conj_id", fmt.Sprintf("%d", conjunctionID)).
		Action().Resubmit(emptyPlaceholderStr, nextTable).Done()
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
		nodeFlowCache: map[string][]binding.Flow{},
		podFlowCache:  map[string][]binding.Flow{},
		serviceCache:  map[string][]binding.Flow{},
		policyCache:   map[uint32]*conjunction{},
	}
	return c
}
