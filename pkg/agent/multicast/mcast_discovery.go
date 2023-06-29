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

package multicast

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

const (
	IGMPProtocolNumber = 2
)

var (
	// igmpMaxResponseTime is the maximum time allowed before sending a responding report which is used for the
	// "Max Resp Code" field in the IGMP query message. It is also the maximum time to wait for the IGMP report message
	// when checking the last group member.
	igmpMaxResponseTime = time.Second * 10
	// igmpQueryDstMac is the MAC address used in the dst MAC field in the IGMP query message
	igmpQueryDstMac, _ = net.ParseMAC("01:00:5e:00:00:01")
	// igmpReportDstMac is the MAC address used in the dst MAC field in the IGMP report message
	igmpReportDstMac, _ = net.ParseMAC("01:00:5e:00:00:16")
)

type IGMPSnooper struct {
	ofClient      openflow.Client
	ifaceStore    interfacestore.InterfaceStore
	eventCh       chan *mcastGroupEvent
	validator     types.McastNetworkPolicyController
	queryInterval time.Duration
	queryVersions []uint8
	// igmpReportANNPStats is a map that saves AntreaNetworkPolicyStats of IGMP report packets.
	// The map can be interpreted as
	// map[UID of the AntreaNetworkPolicy]map[name of AntreaNetworkPolicy rule]statistics of rule.
	igmpReportANNPStats      map[apitypes.UID]map[string]*types.RuleMetric
	igmpReportANNPStatsMutex sync.Mutex
	// Similar to igmpReportANNPStats, it stores ACNP stats for IGMP reports.
	igmpReportACNPStats      map[apitypes.UID]map[string]*types.RuleMetric
	igmpReportACNPStatsMutex sync.Mutex
	encapEnabled             bool
}

func (s *IGMPSnooper) parseSrcInterface(pktIn *ofctrl.PacketIn) (*interfacestore.InterfaceConfig, error) {
	matches := pktIn.GetMatches()
	ofPortField := matches.GetMatchByName(binding.OxmFieldInPort)
	if ofPortField == nil {
		return nil, errors.New("in_port field not found")
	}
	ofPort := ofPortField.GetValue().(uint32)
	ifaceConfig, found := s.ifaceStore.GetInterfaceByOFPort(ofPort)
	if !found {
		return nil, errors.New("target Pod not found")
	}
	return ifaceConfig, nil
}

func (s *IGMPSnooper) queryIGMP(group net.IP) error {
	for _, version := range s.queryVersions {
		igmp, err := generateIGMPQueryPacket(group, version, s.queryInterval)
		if err != nil {
			return err
		}
		// outPort sets the output port of the packetOut message. We expect the message to go through OVS pipeline
		// from table0. The final OpenFlow message will use a standard OpenFlow port number OFPP_TABLE = 0xfffffff9 corrected
		// by ofnet.
		outPort := uint32(0)
		if err := s.ofClient.SendIGMPQueryPacketOut(igmpQueryDstMac, types.McastAllHosts, outPort, igmp); err != nil {
			return err
		}
		klog.V(2).InfoS("Sent packetOut for IGMP query", "group", group.String(), "version", version, "outPort", outPort)
	}
	return nil
}

func (s *IGMPSnooper) validate(event *mcastGroupEvent, igmpType uint8, packetInData protocol.Ethernet) (bool, error) {
	if s.validator == nil {
		// Return true directly if there is no validator.
		return true, nil
	}
	// MulticastValidator only validates the IGMP report message sent from Pods. The report message received from tunnel
	// port is sent from Antrea Agent on a different Node, and returns true directly.
	if event.iface.Type == interfacestore.TunnelInterface {
		return true, nil
	}
	if event.iface.Type != interfacestore.ContainerInterface {
		return true, fmt.Errorf("interface is not container")
	}

	ruleInfo, err := s.validator.GetIGMPNPRuleInfo(event.iface.PodName, event.iface.PodNamespace, event.group, igmpType)
	if err != nil {
		// It shall drop the packet if function Validate returns error
		klog.ErrorS(err, "Failed to validate multicast group event")
		return false, err
	}

	if ruleInfo != nil {
		klog.V(2).InfoS("Got NetworkPolicy action for IGMP report", "RuleAction", ruleInfo.RuleAction, "uuid", ruleInfo.UUID, "Name", ruleInfo.Name)
		s.addToIGMPReportNPStatsMap(*ruleInfo, uint64(packetInData.Len()))
		if ruleInfo.RuleAction == v1beta1.RuleActionDrop {
			return false, nil
		}
	}

	return true, nil
}

func (s *IGMPSnooper) validatePacketAndNotify(event *mcastGroupEvent, igmpType uint8, packetInData protocol.Ethernet) {
	allow, err := s.validate(event, igmpType, packetInData)
	if err != nil {
		// Antrea Agent does not remove the Pod from the OpenFlow group bucket immediately when an error is returned,
		// but it will be removed when after timeout (Controller.mcastGroupTimeout)
		return
	}
	if !allow {
		// If any rule is desired to drop the traffic, Antrea Agent removes the Pod from
		// the OpenFlow group bucket directly
		event.eType = groupLeave
	}
	s.eventCh <- event
}

func (s *IGMPSnooper) addToIGMPReportNPStatsMap(item types.IGMPNPRuleInfo, packetLen uint64) {
	updateRuleStats := func(igmpReportStatsMap map[apitypes.UID]map[string]*types.RuleMetric, uuid apitypes.UID, name string) {
		if igmpReportStatsMap[uuid] == nil {
			igmpReportStatsMap[uuid] = make(map[string]*types.RuleMetric)
		}
		if igmpReportStatsMap[uuid][name] == nil {
			igmpReportStatsMap[uuid][name] = &types.RuleMetric{}
		}
		t := igmpReportStatsMap[uuid][name]
		t.Packets += 1
		t.Bytes += packetLen
	}
	ruleType := *item.NPType
	if ruleType == v1beta2.AntreaNetworkPolicy {
		s.igmpReportANNPStatsMutex.Lock()
		updateRuleStats(s.igmpReportANNPStats, item.UUID, item.Name)
		s.igmpReportANNPStatsMutex.Unlock()
	} else if ruleType == v1beta2.AntreaClusterNetworkPolicy {
		s.igmpReportACNPStatsMutex.Lock()
		updateRuleStats(s.igmpReportACNPStats, item.UUID, item.Name)
		s.igmpReportACNPStatsMutex.Unlock()
	}
}

// WARNING: This func will reset the saved stats.
func (s *IGMPSnooper) collectStats() (igmpANNPStats, igmpACNPStats map[apitypes.UID]map[string]*types.RuleMetric) {
	s.igmpReportANNPStatsMutex.Lock()
	igmpANNPStats = s.igmpReportANNPStats
	s.igmpReportANNPStats = make(map[apitypes.UID]map[string]*types.RuleMetric)
	s.igmpReportANNPStatsMutex.Unlock()
	s.igmpReportACNPStatsMutex.Lock()
	igmpACNPStats = s.igmpReportACNPStats
	s.igmpReportACNPStats = make(map[apitypes.UID]map[string]*types.RuleMetric)
	s.igmpReportACNPStatsMutex.Unlock()
	return igmpANNPStats, igmpACNPStats
}

func (s *IGMPSnooper) sendIGMPReport(groupRecordType uint8, groups []net.IP) error {
	igmp, err := s.generateIGMPReportPacket(groupRecordType, groups)
	if err != nil {
		return err
	}
	if err := s.ofClient.SendIGMPRemoteReportPacketOut(igmpReportDstMac, types.IGMPv3Router, igmp); err != nil {
		return err
	}
	klog.V(2).InfoS("Sent packetOut for IGMP v3 report", "groups", groups)
	return nil
}

func (s *IGMPSnooper) generateIGMPReportPacket(groupRecordType uint8, groups []net.IP) (util.Message, error) {
	records := make([]protocol.IGMPv3GroupRecord, len(groups))
	for i, group := range groups {
		records[i] = protocol.IGMPv3GroupRecord{
			Type:             groupRecordType,
			MulticastAddress: group,
		}
	}
	return &protocol.IGMPv3MembershipReport{
		Type:           protocol.IGMPv3Report,
		Checksum:       0,
		NumberOfGroups: uint16(len(records)),
		GroupRecords:   records,
	}, nil
}

func (s *IGMPSnooper) sendIGMPJoinReport(groups []net.IP) error {
	return s.sendIGMPReport(protocol.IGMPIsEx, groups)
}

func (s *IGMPSnooper) sendIGMPLeaveReport(groups []net.IP) error {
	return s.sendIGMPReport(protocol.IGMPToIn, groups)
}

func (s *IGMPSnooper) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	now := time.Now()
	iface, err := s.parseSrcInterface(pktIn)
	if err != nil {
		return err
	}
	klog.V(2).InfoS("Received PacketIn for IGMP packet", "in_port", iface.OFPort)
	podName := "unknown"
	var srcNode net.IP
	if iface.Type == interfacestore.ContainerInterface {
		podName = iface.PodName
	} else if iface.Type == interfacestore.TunnelInterface {
		var err error
		srcNode, err = s.parseSrcNode(pktIn)
		if err != nil {
			return err
		}
	}
	pktData := new(protocol.Ethernet)
	if err := pktData.UnmarshalBinary(pktIn.Data.(*util.Buffer).Bytes()); err != nil {
		return fmt.Errorf("failed to parse ethernet packet from packet-in message: %v", err)
	}
	igmp, err := parseIGMPPacket(*pktData)
	if err != nil {
		return err
	}
	igmpType := igmp.GetMessageType()
	switch igmpType {
	case protocol.IGMPv1Report:
		fallthrough
	case protocol.IGMPv2Report:
		mgroup := igmp.(*protocol.IGMPv1or2).GroupAddress
		klog.V(2).InfoS("Received IGMPv1or2 Report message", "group", mgroup.String(), "interface", iface.InterfaceName, "pod", podName)
		event := &mcastGroupEvent{
			group: mgroup,
			eType: groupJoin,
			time:  now,
			iface: iface,
		}
		s.validatePacketAndNotify(event, igmpType, *pktData)
	case protocol.IGMPv3Report:
		msg := igmp.(*protocol.IGMPv3MembershipReport)
		for _, gr := range msg.GroupRecords {
			mgroup := gr.MulticastAddress
			klog.V(2).InfoS("Received IGMPv3 Report message", "group", mgroup.String(), "interface", iface.InterfaceName, "pod", podName, "recordType", gr.Type, "sourceCount", gr.NumberOfSources)
			evtType := groupJoin
			if (gr.Type == protocol.IGMPIsIn || gr.Type == protocol.IGMPToIn) && gr.NumberOfSources == 0 {
				evtType = groupLeave
			}
			event := &mcastGroupEvent{
				group:   mgroup,
				eType:   evtType,
				time:    now,
				iface:   iface,
				srcNode: srcNode,
			}
			s.validatePacketAndNotify(event, igmpType, *pktData)
		}
	case protocol.IGMPv2LeaveGroup:
		mgroup := igmp.(*protocol.IGMPv1or2).GroupAddress
		klog.V(2).InfoS("Received IGMPv2 Leave message", "group", mgroup.String(), "interface", iface.InterfaceName, "pod", podName)
		event := &mcastGroupEvent{
			group: mgroup,
			eType: groupLeave,
			time:  now,
			iface: iface,
		}
		s.eventCh <- event
	}
	return nil
}

func (s *IGMPSnooper) parseSrcNode(pktIn *ofctrl.PacketIn) (net.IP, error) {
	matches := pktIn.GetMatches()
	tunSrcField := matches.GetMatchByName(binding.NxmFieldTunIPv4Src)
	if tunSrcField == nil {
		return nil, errors.New("in_port field not found")
	}
	tunSrc := tunSrcField.GetValue().(net.IP)
	return tunSrc, nil
}

func generateIGMPQueryPacket(group net.IP, version uint8, queryInterval time.Duration) (util.Message, error) {
	// The max response time field in IGMP protocol uses a value in units of 1/10 second.
	// See https://datatracker.ietf.org/doc/html/rfc2236 and https://datatracker.ietf.org/doc/html/rfc3376
	respTime := uint8(igmpMaxResponseTime.Seconds() * 10)
	switch version {
	case 1:
		return &protocol.IGMPv1or2{
			Type:            protocol.IGMPQuery,
			MaxResponseTime: 0,
			Checksum:        0,
			GroupAddress:    group,
		}, nil
	case 2:
		return &protocol.IGMPv1or2{
			Type:            protocol.IGMPQuery,
			MaxResponseTime: respTime,
			Checksum:        0,
			GroupAddress:    group,
		}, nil
	case 3:
		return &protocol.IGMPv3Query{
			Type:                     protocol.IGMPQuery,
			MaxResponseTime:          respTime,
			GroupAddress:             group,
			SuppressRouterProcessing: false,
			RobustnessValue:          0,
			IntervalTime:             uint8(queryInterval.Seconds()),
			NumberOfSources:          0,
		}, nil
	}
	return nil, fmt.Errorf("unsupported IGMP version %d", version)
}

func parseIGMPPacket(pkt protocol.Ethernet) (protocol.IGMPMessage, error) {
	if pkt.Ethertype != protocol.IPv4_MSG {
		return nil, errors.New("not IPv4 packet")
	}
	ipPacket, ok := pkt.Data.(*protocol.IPv4)
	if !ok {
		return nil, errors.New("failed to parse IPv4 packet")
	}
	if ipPacket.Protocol != IGMPProtocolNumber {
		return nil, errors.New("not IGMP packet")
	}
	data, _ := ipPacket.Data.MarshalBinary()
	igmpLength := ipPacket.Length - uint16(4*ipPacket.IHL)
	if igmpLength == 8 {
		igmp := new(protocol.IGMPv1or2)
		if err := igmp.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return igmp, nil
	}
	switch data[0] {
	case protocol.IGMPQuery:
		igmp := new(protocol.IGMPv3Query)
		if err := igmp.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return igmp, nil
	case protocol.IGMPv3Report:
		igmp := new(protocol.IGMPv3MembershipReport)
		if err := igmp.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return igmp, nil
	default:
		return nil, errors.New("unknown IGMP packet")
	}
}

func newSnooper(ofClient openflow.Client, ifaceStore interfacestore.InterfaceStore, eventCh chan *mcastGroupEvent, queryInterval time.Duration, igmpQueryVersions []uint8, multicastValidator types.McastNetworkPolicyController, encapEnabled bool) *IGMPSnooper {
	snooper := &IGMPSnooper{ofClient: ofClient, ifaceStore: ifaceStore, eventCh: eventCh, validator: multicastValidator, queryInterval: queryInterval, queryVersions: igmpQueryVersions, encapEnabled: encapEnabled}
	snooper.igmpReportACNPStats = make(map[apitypes.UID]map[string]*types.RuleMetric)
	snooper.igmpReportANNPStats = make(map[apitypes.UID]map[string]*types.RuleMetric)
	ofClient.RegisterPacketInHandler(uint8(openflow.PacketInCategoryIGMP), snooper)
	return snooper
}
