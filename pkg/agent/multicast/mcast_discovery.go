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
	"time"

	"antrea.io/libOpenflow/openflow13"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
)

const (
	IGMPProtocolNumber = 2
)

const (
	// queryInterval is the interval to send IGMP query messages.
	queryInterval = time.Second * 125
	// mcastGroupTimeout is the timeout to detect a group as stale if no IGMP report is received within the time.
	mcastGroupTimeout = queryInterval * 3
)

var (
	// igmpMaxResponseTime is the maximum time allowed before sending a responding report which is used for the
	// "Max Resp Code" field in the IGMP query message. It is also the maximum time to wait for the IGMP report message
	// when checking the last group member.
	igmpMaxResponseTime = time.Second * 10
	// igmpQueryDstMac is the MAC address used in the dst MAC field in the IGMP query message
	igmpQueryDstMac, _ = net.ParseMAC("01:00:5e:00:00:01")
	mcastAllHosts      = net.ParseIP("224.0.0.1").To4()
)

type IGMPSnooper struct {
	ofClient   openflow.Client
	ifaceStore interfacestore.InterfaceStore
	eventCh    chan *mcastGroupEvent
}

func (s *IGMPSnooper) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	matches := pktIn.GetMatches()
	// Get custom reasons in this packet-in.
	match := matches.GetMatchByName(openflow.CustomReasonField.GetNXFieldName())
	customReasons, err := getInfoInReg(match, openflow.CustomReasonField.GetRange().ToNXRange())
	if err != nil {
		klog.ErrorS(err, "Received error while unloading customReason from OVS reg", "regField", openflow.CustomReasonField.GetName())
		return err
	}
	if customReasons&openflow.CustomReasonIGMP == openflow.CustomReasonIGMP {
		return s.processPacketIn(pktIn)
	}
	return nil
}

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

func (s *IGMPSnooper) parseSrcInterface(pktIn *ofctrl.PacketIn) (*interfacestore.InterfaceConfig, error) {
	matches := pktIn.GetMatches()
	ofPortField := matches.GetMatchByName("OXM_OF_IN_PORT")
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

func (s *IGMPSnooper) queryIGMP(group net.IP, version uint8) error {
	igmp, err := generateIGMPQueryPacket(group, version)
	if err != nil {
		return err
	}
	if err := s.ofClient.SendIGMPQueryPacketOut(igmpQueryDstMac, mcastAllHosts, openflow13.P_NORMAL, igmp); err != nil {
		return err
	}
	klog.V(2).InfoS("Sent packetOut form IGMP query", "group", group.String(), "version", version)
	return nil
}

func (s *IGMPSnooper) processPacketIn(pktIn *ofctrl.PacketIn) error {
	now := time.Now()
	iface, err := s.parseSrcInterface(pktIn)
	if err != nil {
		return err
	}
	klog.V(2).InfoS("Received PacketIn for IGMP packet", "in_port", iface.OFPort)
	igmp, err := parseIGMPPacket(pktIn.Data)
	if err != nil {
		return err
	}
	switch igmp.GetMessageType() {
	case protocol.IGMPv1Report:
		fallthrough
	case protocol.IGMPv2Report:
		mgroup := igmp.(*protocol.IGMPv1or2).GroupAddress
		klog.InfoS("Received IGMPv1or2 Report message", "group", mgroup.String(), "interface", iface.PodName)
		event := &mcastGroupEvent{
			group: mgroup,
			eType: groupJoin,
			time:  now,
			iface: iface,
		}
		s.eventCh <- event
	case protocol.IGMPv3Report:
		msg := igmp.(*protocol.IGMPv3MembershipReport)
		for _, gr := range msg.GroupRecords {
			mgroup := gr.MulticastAddress
			klog.InfoS("Received IGMPv3 Report message", "group", mgroup.String(), "interface", iface.PodName)
			event := &mcastGroupEvent{
				group: mgroup,
				eType: groupJoin,
				time:  now,
				iface: iface,
			}
			s.eventCh <- event
		}

	case protocol.IGMPv2LeaveGroup:
		mgroup := igmp.(*protocol.IGMPv1or2).GroupAddress
		klog.InfoS("Received IGMPv2 Leave message", "group", mgroup.String(), "interface", iface.PodName)
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

func generateIGMPQueryPacket(group net.IP, version uint8) (util.Message, error) {
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
		return nil, errors.New("unknown igmp packet")
	}
}

func newSnooper(ofClient openflow.Client, ifaceStore interfacestore.InterfaceStore, eventCh chan *mcastGroupEvent) *IGMPSnooper {
	d := &IGMPSnooper{ofClient: ofClient, ifaceStore: ifaceStore, eventCh: eventCh}
	ofClient.RegisterPacketInHandler(uint8(openflow.PacketInReasonMC), "MulticastGroupDiscovery", d)
	return d
}
