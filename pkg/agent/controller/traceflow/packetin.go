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

package traceflow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	"k8s.io/utils/pointer"

	"antrea.io/antrea/pkg/agent/openflow"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

var skipTraceflowUpdateErr = errors.New("skip Traceflow update")

func (c *Controller) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	if !c.traceflowListerSynced() {
		return errors.New("Traceflow controller is not started")
	}
	oldTf, nodeResult, packet, err := c.parsePacketIn(pktIn)
	if err == skipTraceflowUpdateErr {
		return nil
	}
	if err != nil {
		return fmt.Errorf("parsePacketIn error: %v", err)
	}

	// Retry when update CRD conflict which caused by multiple agents updating one CRD at same time.
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		tf, err := c.traceflowLister.Get(oldTf.Name)
		if err != nil {
			return fmt.Errorf("get Traceflow failed: %w", err)
		}
		update := tf.DeepCopy()
		update.Status.Results = append(update.Status.Results, *nodeResult)
		if packet != nil {
			update.Status.CapturedPacket = packet
		}
		_, err = c.crdClient.CrdV1beta1().Traceflows().UpdateStatus(context.TODO(), update, v1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("update Traceflow failed: %w", err)
		}
		klog.InfoS("Updated Traceflow", "tf", klog.KObj(tf), "status", update.Status)
		return nil
	})
	if err != nil {
		return fmt.Errorf("Traceflow update error: %w", err)
	}
	return nil
}

func (c *Controller) parsePacketIn(pktIn *ofctrl.PacketIn) (*crdv1beta1.Traceflow, *crdv1beta1.NodeResult, *crdv1beta1.Packet, error) {
	matchers := pktIn.GetMatches()

	// Get data plane tag.
	// Directly read data plane tag from packet.
	var err error
	var tag uint8
	var ctNwDst, ctNwSrc, ipDst, ipSrc, ns, srcPod string
	etherData := new(protocol.Ethernet)
	if err := etherData.UnmarshalBinary(pktIn.Data.(*util.Buffer).Bytes()); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse Ethernet packet from packet-in message: %v", err)
	}
	if etherData.Ethertype == protocol.IPv4_MSG {
		ipPacket, ok := etherData.Data.(*protocol.IPv4)
		if !ok {
			return nil, nil, nil, errors.New("invalid traceflow IPv4 packet")
		}
		tag = ipPacket.DSCP
		ctNwDst, err = getCTDstValue(matchers, false)
		if err != nil {
			return nil, nil, nil, err
		}
		ctNwSrc, err = getCTSrcValue(matchers, false)
		if err != nil {
			return nil, nil, nil, err
		}
		ipDst = ipPacket.NWDst.String()
		ipSrc = ipPacket.NWSrc.String()
	} else if etherData.Ethertype == protocol.IPv6_MSG {
		ipv6Packet, ok := etherData.Data.(*protocol.IPv6)
		if !ok {
			return nil, nil, nil, errors.New("invalid traceflow IPv6 packet")
		}
		tag = ipv6Packet.TrafficClass >> 2
		ctNwDst, err = getCTDstValue(matchers, true)
		if err != nil {
			return nil, nil, nil, err
		}
		ctNwSrc, err = getCTSrcValue(matchers, true)
		if err != nil {
			return nil, nil, nil, err
		}
		ipDst = ipv6Packet.NWDst.String()
		ipSrc = ipv6Packet.NWSrc.String()
	} else {
		return nil, nil, nil, fmt.Errorf("unsupported traceflow packet Ethertype: %d", etherData.Ethertype)
	}

	firstPacket := false
	c.runningTraceflowsMutex.RLock()
	tfState, exists := c.runningTraceflows[int8(tag)]
	if exists {
		firstPacket = !tfState.receivedPacket
		tfState.receivedPacket = true
	}
	c.runningTraceflowsMutex.RUnlock()
	if !exists {
		return nil, nil, nil, fmt.Errorf("Traceflow for dataplane tag %d not found in cache", tag)
	}

	var capturedPacket *crdv1beta1.Packet
	if tfState.liveTraffic {
		// Live Traceflow only considers the first packet of each
		// connection. However, it is possible for 2 connections to
		// match the Live Traceflow flows in OVS (before the flows can
		// be uninstalled below), leading to 2 Packet In messages being
		// processed. If we don't ignore all additional Packet Ins, we
		// can end up with duplicate Node observations in the Traceflow
		// Status. This situation is more likely when the Live TraceFlow
		// request does not specify source / destination ports.
		if !firstPacket {
			klog.InfoS("An additional Traceflow packet was received unexpectedly for Live Traceflow, ignoring it")
			return nil, nil, nil, skipTraceflowUpdateErr
		}
		// Uninstall the OVS flows after receiving the first packet, to
		// avoid capturing too many matched packets.
		c.ofClient.UninstallTraceflowFlows(tag)
		// Report the captured dropped packet, if the Traceflow is for
		// the dropped packet only; report too if only the receiver
		// captures packets in the Traceflow (live-traffic Traceflow
		// that has only destination Pod set); otherwise only the sender
		// should report the first captured packet.
		if tfState.isSender || tfState.receiverOnly || tfState.droppedOnly {
			capturedPacket = parseCapturedPacket(pktIn)
		}
	}

	tf, err := c.traceflowLister.Get(tfState.name)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get Traceflow %s CRD: %v", tfState.name, err)
	}
	ns = tf.Spec.Source.Namespace
	srcPod = tf.Spec.Source.Pod

	obs := []crdv1beta1.Observation{}
	tableID := pktIn.TableId
	if tfState.isSender {
		ob := new(crdv1beta1.Observation)
		ob.Component = crdv1beta1.ComponentSpoofGuard
		ob.Action = crdv1beta1.ActionForwarded
		obs = append(obs, *ob)
	} else {
		ob := new(crdv1beta1.Observation)
		ob.Component = crdv1beta1.ComponentForwarding
		ob.Action = crdv1beta1.ActionReceived
		obs = append(obs, *ob)
	}

	// Collect Service connections.
	// - For packet is DNATed only, the final state is that ipDst != ctNwDst (in DNAT CT zone).
	// - For packet is both DNATed and SNATed, the first state is also ipDst != ctNwDst (in DNAT CT zone), but the final
	//   state is that ipSrc != ctNwSrc (in SNAT CT zone). The state in DNAT CT zone cannot be recognized in SNAT CT zone.
	if !tfState.receiverOnly {
		if isValidCtNw(ctNwDst) && ipDst != ctNwDst || isValidCtNw(ctNwSrc) && ipSrc != ctNwSrc {
			ob := &crdv1beta1.Observation{
				Component:       crdv1beta1.ComponentLB,
				Action:          crdv1beta1.ActionForwarded,
				TranslatedDstIP: ipDst,
			}
			if isValidCtNw(ctNwSrc) && ipSrc != ctNwSrc {
				ob.TranslatedSrcIP = ipSrc
			}
			obs = append(obs, *ob)
		}
		// Collect egress conjunctionID and get NetworkPolicy from cache.
		if match := getMatchRegField(matchers, openflow.TFEgressConjIDField); match != nil {
			egressInfo, err := getRegValue(match, nil)
			if err != nil {
				return nil, nil, nil, err
			}
			ob := getNetworkPolicyObservation(tableID, false)
			npRef := c.networkPolicyQuerier.GetNetworkPolicyByRuleFlowID(egressInfo)
			if npRef != nil {
				ob.NetworkPolicy = npRef.ToString()
				ruleRef := c.networkPolicyQuerier.GetRuleByFlowID(egressInfo)
				if ruleRef != nil {
					ob.NetworkPolicyRule = ruleRef.Name
				}
			}
			obs = append(obs, *ob)
		}
	}

	// Collect ingress conjunctionID and get NetworkPolicy from cache.
	if match := getMatchRegField(matchers, openflow.TFIngressConjIDField); match != nil {
		ingressInfo, err := getRegValue(match, nil)
		if err != nil {
			return nil, nil, nil, err
		}
		ob := getNetworkPolicyObservation(tableID, true)
		npRef := c.networkPolicyQuerier.GetNetworkPolicyByRuleFlowID(ingressInfo)
		if npRef != nil {
			ob.NetworkPolicy = npRef.ToString()
			ruleRef := c.networkPolicyQuerier.GetRuleByFlowID(ingressInfo)
			if ruleRef != nil {
				ob.NetworkPolicyRule = ruleRef.Name
			}
		}
		obs = append(obs, *ob)
	}

	// Get drop table.
	if tableID == openflow.EgressMetricTable.GetID() || tableID == openflow.IngressMetricTable.GetID() {
		ob := getNetworkPolicyObservation(tableID, tableID == openflow.IngressMetricTable.GetID())
		if match := getMatchRegField(matchers, openflow.APConjIDField); match != nil {
			notAllowConjInfo, err := getRegValue(match, nil)
			if err != nil {
				return nil, nil, nil, err
			}
			if ruleRef := c.networkPolicyQuerier.GetRuleByFlowID(notAllowConjInfo); ruleRef != nil {
				if npRef := ruleRef.PolicyRef; npRef != nil {
					ob.NetworkPolicy = npRef.ToString()
					ob.NetworkPolicyRule = ruleRef.Name
				}
				if ruleRef.Action != nil && *ruleRef.Action == crdv1beta1.RuleActionReject {
					ob.Action = crdv1beta1.ActionRejected
				}
			}
		}
		obs = append(obs, *ob)
	} else if tableID == openflow.EgressDefaultTable.GetID() || tableID == openflow.IngressDefaultTable.GetID() {
		ob := getNetworkPolicyObservation(tableID, tableID == openflow.IngressDefaultTable.GetID())
		obs = append(obs, *ob)
	}

	// Get output table.
	if tableID == openflow.OutputTable.GetID() {
		ob := new(crdv1beta1.Observation)
		tunnelDstIP := ""
		// decide according to packet.
		isIPv6 := etherData.Ethertype == protocol.IPv6_MSG
		if match := getMatchTunnelDstField(matchers, isIPv6); match != nil {
			tunnelDstIP, err = getTunnelDstValue(match)
			if err != nil {
				return nil, nil, nil, err
			}
		}
		var outputPort uint32
		if match := getMatchRegField(matchers, openflow.TargetOFPortField); match != nil {
			outputPort, err = getRegValue(match, nil)
			if err != nil {
				return nil, nil, nil, err
			}
		}
		gatewayIP := c.nodeConfig.GatewayConfig.IPv4
		if etherData.Ethertype == protocol.IPv6_MSG {
			gatewayIP = c.nodeConfig.GatewayConfig.IPv6
		}
		gwPort := c.nodeConfig.GatewayConfig.OFPort
		tunPort := c.nodeConfig.TunnelOFPort
		if c.networkConfig.TrafficEncapMode.SupportsEncap() && outputPort == tunPort {
			var isRemoteEgress uint32
			if match := getMatchRegField(matchers, openflow.RemoteSNATRegMark.GetField()); match != nil {
				isRemoteEgress, err = getRegValue(match, openflow.RemoteSNATRegMark.GetField().GetRange().ToNXRange())
				if err != nil {
					return nil, nil, nil, err
				}
			}
			if isRemoteEgress == 1 { // an Egress packet, currently on source Node and forwarded to Egress Node.
				egressName, egressIP, egressNode, err := c.egressQuerier.GetEgress(ns, srcPod)
				if err != nil {
					return nil, nil, nil, err
				}
				obEgress := getEgressObservation(false, egressIP, egressName, egressNode)
				obs = append(obs, *obEgress)
			}
			ob.TunnelDstIP = tunnelDstIP
			ob.Action = crdv1beta1.ActionForwarded
		} else if ipDst == gatewayIP.String() && outputPort == gwPort {
			ob.Action = crdv1beta1.ActionDelivered
		} else if c.networkConfig.TrafficEncapMode.SupportsEncap() && outputPort == gwPort {
			var pktMark uint32
			if match := getMatchPktMarkField(matchers); match != nil {
				pktMark, err = getMarkValue(match)
				if err != nil {
					return nil, nil, nil, err
				}
			}
			if pktMark != 0 { // Egress packet on Egress Node
				egressName, egressIP, egressNode := "", "", ""
				if tunnelDstIP == "" { // Egress Node is Source Node of this Egress packet
					egressName, egressIP, egressNode, err = c.egressQuerier.GetEgress(ns, srcPod)
					if err != nil {
						return nil, nil, nil, err
					}
				} else {
					egressIP, err = c.egressQuerier.GetEgressIPByMark(pktMark)
					if err != nil {
						return nil, nil, nil, err
					}
				}
				obEgress := getEgressObservation(true, egressIP, egressName, egressNode)
				obs = append(obs, *obEgress)
			}
			ob.Action = crdv1beta1.ActionForwardedOutOfOverlay
		} else if outputPort == gwPort { // noEncap
			ob.Action = crdv1beta1.ActionForwarded
		} else {
			// Output port is Pod port, packet is delivered.
			ob.Action = crdv1beta1.ActionDelivered
		}
		ob.ComponentInfo = openflow.OutputTable.GetName()
		ob.Component = crdv1beta1.ComponentForwarding
		obs = append(obs, *ob)
	}

	nodeResult := crdv1beta1.NodeResult{Node: c.nodeConfig.Name, Timestamp: time.Now().Unix(), Observations: obs}
	return tf, &nodeResult, capturedPacket, nil
}

func getMatchPktMarkField(matchers *ofctrl.Matchers) *ofctrl.MatchField {
	return matchers.GetMatchByName("NXM_NX_PKT_MARK")
}

func getMatchRegField(matchers *ofctrl.Matchers, field *binding.RegField) *ofctrl.MatchField {
	return openflow.GetMatchFieldByRegID(matchers, field.GetRegID())
}

func getMatchTunnelDstField(matchers *ofctrl.Matchers, isIPv6 bool) *ofctrl.MatchField {
	if isIPv6 {
		return matchers.GetMatchByName("NXM_NX_TUN_IPV6_DST")
	}
	return matchers.GetMatchByName("NXM_NX_TUN_IPV4_DST")
}

func getMarkValue(match *ofctrl.MatchField) (uint32, error) {
	mark, ok := match.GetValue().(uint32)
	if !ok {
		return 0, errors.New("mark value cannot be got")
	}
	return mark, nil
}

func getRegValue(regMatch *ofctrl.MatchField, rng *openflow15.NXRange) (uint32, error) {
	regValue, ok := regMatch.GetValue().(*ofctrl.NXRegister)
	if !ok {
		return 0, errors.New("register value cannot be got")
	}
	if rng != nil {
		return ofctrl.GetUint32ValueWithRange(regValue.Data, rng), nil
	}
	return regValue.Data, nil
}

func getTunnelDstValue(regMatch *ofctrl.MatchField) (string, error) {
	regValue, ok := regMatch.GetValue().(net.IP)
	if !ok {
		return "", errors.New("tunnel destination value cannot be got")
	}
	return regValue.String(), nil
}

func getCTDstValue(matchers *ofctrl.Matchers, isIPv6 bool) (string, error) {
	var match *ofctrl.MatchField
	if isIPv6 {
		match = matchers.GetMatchByName("NXM_NX_CT_IPV6_DST")
	} else {
		match = matchers.GetMatchByName("NXM_NX_CT_NW_DST")
	}
	if match == nil {
		return "", nil
	}
	regValue, ok := match.GetValue().(net.IP)
	if !ok {
		return "", errors.New("packet-in conntrack destination value cannot be retrieved from metadata")
	}
	return regValue.String(), nil
}

func getCTSrcValue(matchers *ofctrl.Matchers, isIPv6 bool) (string, error) {
	var match *ofctrl.MatchField
	if isIPv6 {
		match = matchers.GetMatchByName("NXM_NX_CT_IPV6_SRC")
	} else {
		match = matchers.GetMatchByName("NXM_NX_CT_NW_SRC")
	}
	if match == nil {
		return "", nil
	}
	regValue, ok := match.GetValue().(net.IP)
	if !ok {
		return "", errors.New("packet-in conntrack source value cannot be retrieved from metadata")
	}
	return regValue.String(), nil
}

func getNetworkPolicyObservation(tableID uint8, ingress bool) *crdv1beta1.Observation {
	ob := new(crdv1beta1.Observation)
	ob.Component = crdv1beta1.ComponentNetworkPolicy
	if ingress {
		switch tableID {
		case openflow.IngressMetricTable.GetID():
			// Packet dropped by ANP/default drop rule
			ob.ComponentInfo = openflow.IngressMetricTable.GetName()
			ob.Action = crdv1beta1.ActionDropped
		case openflow.IngressDefaultTable.GetID():
			// Packet dropped by ANP/default drop rule
			ob.ComponentInfo = openflow.IngressDefaultTable.GetName()
			ob.Action = crdv1beta1.ActionDropped
		default:
			ob.ComponentInfo = openflow.IngressRuleTable.GetName()
			ob.Action = crdv1beta1.ActionForwarded
		}
	} else {
		switch tableID {
		case openflow.EgressMetricTable.GetID():
			// Packet dropped by ANP/default drop rule
			ob.ComponentInfo = openflow.EgressMetricTable.GetName()
			ob.Action = crdv1beta1.ActionDropped
		case openflow.EgressDefaultTable.GetID():
			// Packet dropped by ANP/default drop rule
			ob.ComponentInfo = openflow.EgressDefaultTable.GetName()
			ob.Action = crdv1beta1.ActionDropped
		default:
			ob.ComponentInfo = openflow.EgressRuleTable.GetName()
			ob.Action = crdv1beta1.ActionForwarded
		}
	}
	return ob
}

func isValidCtNw(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	// Reserved by IETF [RFC3513][RFC4291]
	_, cidr, _ := net.ParseCIDR("0000::/8")
	if cidr.Contains(ip) {
		return false
	}
	return true
}

func parseCapturedPacket(pktIn *ofctrl.PacketIn) *crdv1beta1.Packet {
	pkt, _ := binding.ParsePacketIn(pktIn)
	capturedPacket := crdv1beta1.Packet{SrcIP: pkt.SourceIP.String(), DstIP: pkt.DestinationIP.String(), Length: int32(pkt.IPLength)}
	if pkt.IsIPv6 {
		ipProto := int32(pkt.IPProto)
		capturedPacket.IPv6Header = &crdv1beta1.IPv6Header{NextHeader: &ipProto, HopLimit: int32(pkt.TTL)}
	} else {
		capturedPacket.IPHeader = &crdv1beta1.IPHeader{Protocol: int32(pkt.IPProto), TTL: int32(pkt.TTL), Flags: int32(pkt.IPFlags)}
	}
	if pkt.IPProto == protocol.Type_TCP {
		capturedPacket.TransportHeader.TCP = &crdv1beta1.TCPHeader{SrcPort: int32(pkt.SourcePort), DstPort: int32(pkt.DestinationPort), Flags: pointer.Int32(int32(pkt.TCPFlags))}
	} else if pkt.IPProto == protocol.Type_UDP {
		capturedPacket.TransportHeader.UDP = &crdv1beta1.UDPHeader{SrcPort: int32(pkt.SourcePort), DstPort: int32(pkt.DestinationPort)}
	} else if pkt.IPProto == protocol.Type_ICMP || pkt.IPProto == protocol.Type_IPv6ICMP {
		capturedPacket.TransportHeader.ICMP = &crdv1beta1.ICMPEchoRequestHeader{ID: int32(pkt.ICMPEchoID), Sequence: int32(pkt.ICMPEchoSeq)}
	}
	return &capturedPacket
}

func getEgressObservation(isEgressNode bool, egressIP, egressName, egressNode string) *crdv1beta1.Observation {
	ob := new(crdv1beta1.Observation)
	ob.Component = crdv1beta1.ComponentEgress
	ob.EgressIP = egressIP
	ob.Egress = egressName
	ob.EgressNode = egressNode
	if isEgressNode {
		ob.Action = crdv1beta1.ActionMarkedForSNAT
	} else {
		ob.Action = crdv1beta1.ActionForwardedToEgressNode
	}
	return ob
}
