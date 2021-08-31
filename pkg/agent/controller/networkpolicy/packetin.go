// Copyright 2020 Antrea Authors
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

package networkpolicy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"antrea.io/libOpenflow/openflow13"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/ofnet/ofctrl"
	"github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/ip"
)

const (
	IPv4HdrLen uint16 = 20
	IPv6HdrLen uint16 = 40

	ICMPUnusedHdrLen uint16 = 4

	TCPAck uint8 = 0b010000
	TCPRst uint8 = 0b000100

	ICMPDstUnreachableType         uint8 = 3
	ICMPDstHostAdminProhibitedCode uint8 = 10

	ICMPv6DstUnreachableType     uint8 = 1
	ICMPv6DstAdminProhibitedCode uint8 = 1
)

// HandlePacketIn is the packetin handler registered to openflow by Antrea network
// policy agent controller. It performs the appropriate operations based on which
// bits are set in the "custom reasons" field of the packet received from OVS.
func (c *Controller) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	if pktIn == nil {
		return errors.New("empty packetin for Antrea Policy")
	}

	matches := pktIn.GetMatches()
	// Get custom reasons in this packet-in.
	match := getMatchRegField(matches, openflow.CustomReasonField)
	customReasons, err := getInfoInReg(match, openflow.CustomReasonField.GetRange().ToNXRange())
	if err != nil {
		return fmt.Errorf("received error while unloading customReason from reg: %v", err)
	}

	// Use reasons to choose operations.
	var checkCustomReason = func(customReasonMark *binding.RegMark) bool {
		return customReasons&customReasonMark.GetValue() == customReasonMark.GetValue()
	}
	if checkCustomReason(openflow.CustomReasonLoggingRegMark) {
		if err := c.logPacket(pktIn); err != nil {
			return err
		}
	}
	if checkCustomReason(openflow.CustomReasonRejectRegMark) {
		if err := c.rejectRequest(pktIn); err != nil {
			return err
		}
	}
	if checkCustomReason(openflow.CustomReasonDenyRegMark) {
		if err := c.storeDenyConnection(pktIn); err != nil {
			return err
		}
	}
	return nil
}

// getMatchRegField returns match to the regNum register.
func getMatchRegField(matchers *ofctrl.Matchers, field *binding.RegField) *ofctrl.MatchField {
	return matchers.GetMatchByName(field.GetNXFieldName())
}

// getMatch receives ofctrl matchers and table id, match field.
// Modifies match field to Ingress/Egress register based on tableID.
func getMatch(matchers *ofctrl.Matchers, tableID uint8, disposition uint32) *ofctrl.MatchField {
	// Get match from CNPDenyConjIDReg if disposition is not allow.
	if disposition != openflow.DispositionAllow {
		return getMatchRegField(matchers, openflow.CNPDenyConjIDField)
	}
	// Get match from ingress/egress reg if disposition is allow
	for _, table := range append(openflow.GetAntreaPolicyEgressTables(), openflow.EgressRuleTable) {
		if tableID == table.GetID() {
			return getMatchRegField(matchers, openflow.TFEgressConjIDField)
		}
	}
	for _, table := range append(openflow.GetAntreaPolicyIngressTables(), openflow.IngressRuleTable) {
		if tableID == table.GetID() {
			return getMatchRegField(matchers, openflow.TFIngressConjIDField)
		}
	}
	return nil
}

// getInfoInReg unloads and returns data stored in the match field.
func getInfoInReg(regMatch *ofctrl.MatchField, rng *openflow13.NXRange) (uint32, error) {
	regValue, ok := regMatch.GetValue().(*ofctrl.NXRegister)
	if !ok {
		return 0, errors.New("register value cannot be retrieved")
	}
	if rng != nil {
		return ofctrl.GetUint32ValueWithRange(regValue.Data, rng), nil
	}
	return regValue.Data, nil
}

// getNetworkPolicyInfo fills in tableName, npName, ofPriority, disposition of logInfo ob.
func getNetworkPolicyInfo(pktIn *ofctrl.PacketIn, c *Controller, ob *logInfo) error {
	matchers := pktIn.GetMatches()
	var match *ofctrl.MatchField
	// Get table name
	tableID := pktIn.TableId
	ob.tableName = openflow.GetFlowTableName(tableID)

	// Get disposition Allow or Drop
	match = getMatchRegField(matchers, openflow.APDispositionField)
	info, err := getInfoInReg(match, openflow.APDispositionField.GetRange().ToNXRange())
	if err != nil {
		return fmt.Errorf("received error while unloading disposition from reg: %v", err)
	}
	ob.disposition = openflow.DispositionToString[info]

	// Set match to corresponding ingress/egress reg according to disposition
	match = getMatch(matchers, tableID, info)

	// Get Network Policy full name and OF priority of the conjunction
	info, err = getInfoInReg(match, nil)
	if err != nil {
		return fmt.Errorf("received error while unloading conjunction id from reg: %v", err)
	}
	ob.npRef, ob.ofPriority = c.ofClient.GetPolicyInfoFromConjunction(info)

	return nil
}

// getPacketInfo fills in srcIP, destIP, pktLength, protocol of logInfo ob.
func getPacketInfo(pktIn *ofctrl.PacketIn, ob *logInfo) error {
	var prot uint8
	switch ipPkt := pktIn.Data.Data.(type) {
	case *protocol.IPv4:
		ob.srcIP = ipPkt.NWSrc.String()
		ob.destIP = ipPkt.NWDst.String()
		ob.pktLength = ipPkt.Length
		prot = ipPkt.Protocol
	case *protocol.IPv6:
		ob.srcIP = ipPkt.NWSrc.String()
		ob.destIP = ipPkt.NWDst.String()
		ob.pktLength = ipPkt.Length
		prot = ipPkt.NextHeader
	default:
		return errors.New("unsupported packet-in: should be a valid IPv4 or IPv6 packet")
	}

	ob.protocolStr = ip.IPProtocolNumberToString(prot, "UnknownProtocol")

	return nil
}

// logPacket retrieves information from openflow reg, controller cache, packet-in
// packet to log. Log is deduplicated for non-Allow packets from record in logDeduplication.
// Deduplication is safe guarded by logRecordDedupMap mutex.
func (c *Controller) logPacket(pktIn *ofctrl.PacketIn) error {
	ob := new(logInfo)

	// Get Network Policy log info
	err := getNetworkPolicyInfo(pktIn, c, ob)
	if err != nil {
		return fmt.Errorf("received error while retrieving NetworkPolicy info: %v", err)
	}
	// Get packet log info
	err = getPacketInfo(pktIn, ob)
	if err != nil {
		return fmt.Errorf("received error while retrieving NetworkPolicy info: %v", err)
	}

	// Log the ob info to corresponding file w/ deduplication
	c.antreaPolicyLogger.LogDedupPacket(ob)
	return nil
}

// rejectRequest sends reject response to the requesting client, based on the
// packet-in message.
func (c *Controller) rejectRequest(pktIn *ofctrl.PacketIn) error {
	// Get ethernet data.
	srcMAC := pktIn.Data.HWDst.String()
	dstMAC := pktIn.Data.HWSrc.String()

	var (
		srcIP  string
		dstIP  string
		prot   uint8
		isIPv6 bool
	)
	switch ipPkt := pktIn.Data.Data.(type) {
	case *protocol.IPv4:
		// Get IP data.
		srcIP = ipPkt.NWDst.String()
		dstIP = ipPkt.NWSrc.String()
		prot = ipPkt.Protocol
		isIPv6 = false
	case *protocol.IPv6:
		// Get IP data.
		srcIP = ipPkt.NWDst.String()
		dstIP = ipPkt.NWSrc.String()
		prot = ipPkt.NextHeader
		isIPv6 = true
	}

	sIface, srcFound := c.ifaceStore.GetInterfaceByIP(srcIP)
	dIface, dstFound := c.ifaceStore.GetInterfaceByIP(dstIP)
	isSvcTraffic := c.isServiceTraffic(pktIn, c.antreaProxyEnabled, dstMAC, dstFound)
	packetOutType := binding.GetPacketOutType(isSvcTraffic, c.antreaProxyEnabled, srcFound, dstFound)
	inPort, outPort := getRejectOFPort(packetOutType, sIface, dIface)

	if prot == protocol.Type_TCP {
		// Get TCP data.
		oriTCPSrcPort, oriTCPDstPort, oriTCPSeqNum, _, _, err := binding.GetTCPHeaderData(pktIn.Data.Data)
		if err != nil {
			return err
		}
		// While sending TCP reject packet-out, switch original src/dst port,
		// set the ackNum as original seqNum+1 and set the flag as ack+rst.
		return c.ofClient.SendTCPPacketOut(
			srcMAC,
			dstMAC,
			srcIP,
			dstIP,
			inPort,
			outPort,
			isIPv6,
			oriTCPDstPort,
			oriTCPSrcPort,
			oriTCPSeqNum+1,
			TCPAck|TCPRst,
			packetOutType)
	}
	// Use ICMP host administratively prohibited for ICMP, UDP, SCTP reject.
	icmpType := ICMPDstUnreachableType
	icmpCode := ICMPDstHostAdminProhibitedCode
	ipHdrLen := IPv4HdrLen
	if isIPv6 {
		icmpType = ICMPv6DstUnreachableType
		icmpCode = ICMPv6DstAdminProhibitedCode
		ipHdrLen = IPv6HdrLen
	}
	ipHdr, _ := pktIn.Data.Data.MarshalBinary()
	icmpData := make([]byte, int(ICMPUnusedHdrLen+ipHdrLen+8))
	// Put ICMP unused header in Data prop and set it to zero.
	binary.BigEndian.PutUint32(icmpData[:ICMPUnusedHdrLen], 0)
	copy(icmpData[ICMPUnusedHdrLen:], ipHdr[:ipHdrLen+8])
	return c.ofClient.SendICMPPacketOut(
		srcMAC,
		dstMAC,
		srcIP,
		dstIP,
		inPort,
		outPort,
		isIPv6,
		icmpType,
		icmpCode,
		icmpData,
		packetOutType)
}

// isServiceTraffic uses ServiceEPStateField to decide if this is a Service
// traffic, when AntreaProxy is enabled. And when AntreaProxy is disabled, if the
// destination IP of the reject response packet is on the local Node, but the
// source MAC is antrea-gw's MAC, then this is a rejection of Service traffic.
// Because this response is heading to kube-proxy.
func (c *Controller) isServiceTraffic(pktIn *ofctrl.PacketIn, antreaProxyEnabled bool, dstMAC string, isDstLocal bool) bool {
	if antreaProxyEnabled {
		matches := pktIn.GetMatches()
		match := getMatchRegField(matches, openflow.ServiceEPStateField)
		if match != nil {
			svcEpstate, err := getInfoInReg(match, openflow.ServiceEPStateField.GetRange().ToNXRange())
			return err == nil && svcEpstate&openflow.EpSelectedRegMark.GetValue() == openflow.EpSelectedRegMark.GetValue()
		}
	}
	gwIfaces := c.ifaceStore.GetInterfacesByType(interfacestore.GatewayInterface)
	return isDstLocal && dstMAC == gwIfaces[0].MAC.String()
}

// getRejectOFPort sets the inPort and outPort of a packetOut based on the packetOutType.
func getRejectOFPort(packetOutType binding.PacketOutType, sIface, dIface *interfacestore.InterfaceConfig) (uint32, uint32) {
	inPort := uint32(config.HostGatewayOFPort)
	outPort := uint32(0)
	switch packetOutType {
	case binding.RejectPodLocal:
		inPort = uint32(sIface.OFPort)
		outPort = uint32(dIface.OFPort)
	case binding.RejectServiceLocal:
		inPort = uint32(sIface.OFPort)
	case binding.RejectPodRemoteToLocal:
		inPort = config.HostGatewayOFPort
		outPort = uint32(dIface.OFPort)
	case binding.RejectServiceRemoteToLocal:
		inPort = config.HostGatewayOFPort
	case binding.RejectLocalToRemote:
		inPort = uint32(sIface.OFPort)
	case binding.RejectNoAPServiceLocal:
		inPort = uint32(sIface.OFPort)
		outPort = config.HostGatewayOFPort
	case binding.RejectNoAPServiceRemoteToLocal:
		inPort = config.DefaultTunOFPort
		outPort = config.HostGatewayOFPort
	}
	return inPort, outPort
}

func (c *Controller) storeDenyConnection(pktIn *ofctrl.PacketIn) error {
	packet, err := binding.ParsePacketIn(pktIn)
	if err != nil {
		return fmt.Errorf("error in parsing packetin: %v", err)
	}

	// Get 5-tuple information
	tuple := flowexporter.Tuple{
		SourcePort:      packet.SourcePort,
		DestinationPort: packet.DestinationPort,
		Protocol:        packet.IPProto,
	}
	if packet.IsIPv6 {
		tuple.SourceAddress = packet.SourceIP.To16()
		tuple.DestinationAddress = packet.DestinationIP.To16()
	} else {
		tuple.SourceAddress = packet.SourceIP.To4()
		tuple.DestinationAddress = packet.DestinationIP.To4()
	}

	// Generate deny connection and add to deny connection store
	denyConn := flowexporter.Connection{}
	denyConn.FlowKey = tuple
	denyConn.DestinationServiceAddress = tuple.DestinationAddress
	denyConn.DestinationServicePort = tuple.DestinationPort

	// No need to obtain connection info again if it already exists in denyConnectionStore.
	if conn, exist := c.denyConnStore.GetConnByKey(flowexporter.NewConnectionKey(&denyConn)); exist {
		c.denyConnStore.AddOrUpdateConn(conn, time.Now(), uint64(packet.IPLength))
		return nil
	}

	matchers := pktIn.GetMatches()
	var match *ofctrl.MatchField
	// Get table ID
	tableID := pktIn.TableId
	// Get disposition Allow, Drop or Reject
	match = getMatchRegField(matchers, openflow.APDispositionField)
	id, err := getInfoInReg(match, openflow.APDispositionField.GetRange().ToNXRange())
	if err != nil {
		return fmt.Errorf("error when getting disposition from reg: %v", err)
	}
	disposition := openflow.DispositionToString[id]

	// Set match to corresponding ingress/egress reg according to disposition
	match = getMatch(matchers, tableID, id)
	if match != nil {
		ruleID, err := getInfoInReg(match, nil)
		if err != nil {
			return fmt.Errorf("error when obtaining rule id from reg: %v", err)
		}
		policy := c.GetNetworkPolicyByRuleFlowID(ruleID)
		rule := c.GetRuleByFlowID(ruleID)
		if policy == nil || rule == nil {
			klog.V(4).Infof("Cannot find NetworkPolicy or rule that has ruleID %v", ruleID)
		}
		// Get name and namespace for Antrea Network Policy or Antrea Cluster Network Policy
		if isAntreaPolicyIngressTable(tableID) {
			denyConn.IngressNetworkPolicyName = policy.Name
			denyConn.IngressNetworkPolicyNamespace = policy.Namespace
			denyConn.IngressNetworkPolicyType = flowexporter.PolicyTypeToUint8(policy.Type)
			denyConn.IngressNetworkPolicyRuleName = rule.Name
			denyConn.IngressNetworkPolicyRuleAction = flowexporter.RuleActionToUint8(disposition)
		} else if isAntreaPolicyEgressTable(tableID) {
			denyConn.EgressNetworkPolicyName = policy.Name
			denyConn.EgressNetworkPolicyNamespace = policy.Namespace
			denyConn.EgressNetworkPolicyType = flowexporter.PolicyTypeToUint8(policy.Type)
			denyConn.EgressNetworkPolicyRuleName = rule.Name
			denyConn.EgressNetworkPolicyRuleAction = flowexporter.RuleActionToUint8(disposition)
		}
	} else {
		// For K8s NetworkPolicy implicit drop action, we cannot get name/namespace.
		if tableID == openflow.IngressDefaultTable.GetID() {
			denyConn.IngressNetworkPolicyType = registry.PolicyTypeK8sNetworkPolicy
			denyConn.IngressNetworkPolicyRuleAction = flowexporter.RuleActionToUint8(disposition)
		} else if tableID == openflow.EgressDefaultTable.GetID() {
			denyConn.EgressNetworkPolicyType = registry.PolicyTypeK8sNetworkPolicy
			denyConn.EgressNetworkPolicyRuleAction = flowexporter.RuleActionToUint8(disposition)
		}
	}
	c.denyConnStore.AddOrUpdateConn(&denyConn, time.Now(), uint64(packet.IPLength))
	return nil
}

func isAntreaPolicyIngressTable(tableID uint8) bool {
	for _, table := range openflow.GetAntreaPolicyIngressTables() {
		if table.GetID() == tableID {
			return true
		}
	}
	return false
}

func isAntreaPolicyEgressTable(tableID uint8) bool {
	for _, table := range openflow.GetAntreaPolicyEgressTables() {
		if table.GetID() == tableID {
			return true
		}
	}
	return false
}
