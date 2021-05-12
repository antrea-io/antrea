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

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

func (c *Controller) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	if !c.traceflowListerSynced() {
		return errors.New("traceflow controller is not started")
	}
	oldTf, nodeResult, packet, err := c.parsePacketIn(pktIn)
	if err != nil {
		klog.Errorf("parsePacketIn error: %+v", err)
		return err
	}

	// Retry when update CRD conflict which caused by multiple agents updating one CRD at same time.
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		tf, err := c.traceflowInformer.Lister().Get(oldTf.Name)
		if err != nil {
			klog.Warningf("Get traceflow failed: %+v", err)
			return err
		}
		update := tf.DeepCopy()
		update.Status.Results = append(update.Status.Results, *nodeResult)
		if packet != nil {
			update.Status.CapturedPacket = packet
		}
		_, err = c.traceflowClient.CrdV1alpha1().Traceflows().UpdateStatus(context.TODO(), update, v1.UpdateOptions{})
		if err != nil {
			klog.Warningf("Update traceflow failed: %+v", err)
			return err
		}
		klog.Infof("Updated traceflow %s: %+v", tf.Name, update.Status)
		return nil
	})
	if err != nil {
		klog.Errorf("Update traceflow error: %+v", err)
	}
	return err
}

func (c *Controller) parsePacketIn(pktIn *ofctrl.PacketIn) (*crdv1alpha1.Traceflow, *crdv1alpha1.NodeResult, *crdv1alpha1.Packet, error) {
	matchers := pktIn.GetMatches()

	// Get data plane tag.
	// Directly read data plane tag from packet.
	var err error
	var tag uint8
	var ctNwDst, ipDst string
	if pktIn.Data.Ethertype == protocol.IPv4_MSG {
		ipPacket, ok := pktIn.Data.Data.(*protocol.IPv4)
		if !ok {
			return nil, nil, nil, errors.New("invalid traceflow IPv4 packet")
		}
		tag = ipPacket.DSCP
		ctNwDst, err = getCTDstValue(matchers, false)
		if err != nil {
			return nil, nil, nil, err
		}
		ipDst = ipPacket.NWDst.String()
	} else if pktIn.Data.Ethertype == protocol.IPv6_MSG {
		ipv6Packet, ok := pktIn.Data.Data.(*protocol.IPv6)
		if !ok {
			return nil, nil, nil, errors.New("invalid traceflow IPv6 packet")
		}
		tag = ipv6Packet.TrafficClass >> 2
		ctNwDst, err = getCTDstValue(matchers, true)
		if err != nil {
			return nil, nil, nil, err
		}
		ipDst = ipv6Packet.NWDst.String()
	} else {
		return nil, nil, nil, fmt.Errorf("unsupported traceflow packet Ethertype: %d", pktIn.Data.Ethertype)
	}

	firstPacket := false
	c.runningTraceflowsMutex.RLock()
	tfState, exists := c.runningTraceflows[tag]
	if exists {
		firstPacket = !tfState.receivedPacket
		tfState.receivedPacket = true
	}
	c.runningTraceflowsMutex.RUnlock()
	if !exists {
		return nil, nil, nil, fmt.Errorf("Traceflow for dataplane tag %d not found in cache", tag)
	}

	var capturedPacket *crdv1alpha1.Packet
	if tfState.liveTraffic && firstPacket {
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

	obs := []crdv1alpha1.Observation{}
	tableID := pktIn.TableId
	if tfState.isSender {
		ob := new(crdv1alpha1.Observation)
		ob.Component = crdv1alpha1.ComponentSpoofGuard
		ob.Action = crdv1alpha1.ActionForwarded
		obs = append(obs, *ob)
	} else {
		ob := new(crdv1alpha1.Observation)
		ob.Component = crdv1alpha1.ComponentForwarding
		ob.Action = crdv1alpha1.ActionReceived
		obs = append(obs, *ob)
	}

	// Collect Service DNAT.
	if !tfState.receiverOnly {
		if isValidCtNw(ctNwDst) && ipDst != ctNwDst {
			ob := &crdv1alpha1.Observation{
				Component:       crdv1alpha1.ComponentLB,
				Action:          crdv1alpha1.ActionForwarded,
				TranslatedDstIP: ipDst,
			}
			obs = append(obs, *ob)
		}

		// Collect egress conjunctionID and get NetworkPolicy from cache.
		if match := getMatchRegField(matchers, uint32(openflow.EgressReg)); match != nil {
			egressInfo, err := getRegValue(match, nil)
			if err != nil {
				return nil, nil, nil, err
			}
			ob := getNetworkPolicyObservation(tableID, false)
			npRef := c.networkPolicyQuerier.GetNetworkPolicyByRuleFlowID(egressInfo)
			if npRef != nil {
				ob.NetworkPolicy = npRef.ToString()
			}
			obs = append(obs, *ob)
		}
	}

	// Collect ingress conjunctionID and get NetworkPolicy from cache.
	if match := getMatchRegField(matchers, uint32(openflow.IngressReg)); match != nil {
		ingressInfo, err := getRegValue(match, nil)
		if err != nil {
			return nil, nil, nil, err
		}
		ob := getNetworkPolicyObservation(tableID, true)
		npRef := c.networkPolicyQuerier.GetNetworkPolicyByRuleFlowID(ingressInfo)
		if npRef != nil {
			ob.NetworkPolicy = npRef.ToString()
		}
		obs = append(obs, *ob)
	}

	// Get drop table.
	if tableID == uint8(openflow.EgressMetricTable) || tableID == uint8(openflow.IngressMetricTable) {
		ob := getNetworkPolicyObservation(tableID, tableID == uint8(openflow.IngressMetricTable))
		if match := getMatchRegField(matchers, uint32(openflow.CNPDenyConjIDReg)); match != nil {
			notAllowConjInfo, err := getRegValue(match, nil)
			if err != nil {
				return nil, nil, nil, err
			}
			if ruleRef := c.networkPolicyQuerier.GetRuleByFlowID(notAllowConjInfo); ruleRef != nil {
				if npRef := ruleRef.PolicyRef; npRef != nil {
					ob.NetworkPolicy = npRef.ToString()
				}
				if ruleRef.Action != nil && *ruleRef.Action == crdv1alpha1.RuleActionReject {
					ob.Action = crdv1alpha1.ActionRejected
				}
			}
		}
		obs = append(obs, *ob)
	} else if tableID == uint8(openflow.EgressDefaultTable) || tableID == uint8(openflow.IngressDefaultTable) {
		ob := getNetworkPolicyObservation(tableID, tableID == uint8(openflow.IngressDefaultTable))
		obs = append(obs, *ob)
	}

	// Get output table.
	if tableID == uint8(openflow.L2ForwardingOutTable) {
		ob := new(crdv1alpha1.Observation)
		tunnelDstIP := ""
		isIPv6 := c.nodeConfig.NodeIPAddr.IP.To4() == nil
		if match := getMatchTunnelDstField(matchers, isIPv6); match != nil {
			tunnelDstIP, err = getTunnelDstValue(match)
			if err != nil {
				return nil, nil, nil, err
			}
		}
		var outputPort uint32
		if match := getMatchRegField(matchers, uint32(openflow.PortCacheReg)); match != nil {
			outputPort, err = getRegValue(match, nil)
			if err != nil {
				return nil, nil, nil, err
			}
		}
		gatewayIP := c.nodeConfig.GatewayConfig.IPv4
		if pktIn.Data.Ethertype == protocol.IPv6_MSG {
			gatewayIP = c.nodeConfig.GatewayConfig.IPv6
		}
		if c.networkConfig.TrafficEncapMode.SupportsEncap() && outputPort == config.DefaultTunOFPort {
			ob.TunnelDstIP = tunnelDstIP
			ob.Action = crdv1alpha1.ActionForwarded
		} else if ipDst == gatewayIP.String() && outputPort == config.HostGatewayOFPort {
			ob.Action = crdv1alpha1.ActionDelivered
		} else if c.networkConfig.TrafficEncapMode.SupportsEncap() && outputPort == config.HostGatewayOFPort {
			ob.Action = crdv1alpha1.ActionForwardedOutOfOverlay
		} else if outputPort == config.HostGatewayOFPort { // noEncap
			ob.Action = crdv1alpha1.ActionForwarded
		} else {
			// Output port is Pod port, packet is delivered.
			ob.Action = crdv1alpha1.ActionDelivered
		}
		ob.ComponentInfo = openflow.GetFlowTableName(binding.TableIDType(tableID))
		ob.Component = crdv1alpha1.ComponentForwarding
		obs = append(obs, *ob)
	}

	nodeResult := crdv1alpha1.NodeResult{Node: c.nodeConfig.Name, Timestamp: time.Now().Unix(), Observations: obs}
	return tf, &nodeResult, capturedPacket, nil
}

func getMatchRegField(matchers *ofctrl.Matchers, regNum uint32) *ofctrl.MatchField {
	return matchers.GetMatchByName(fmt.Sprintf("NXM_NX_REG%d", regNum))
}

func getMatchTunnelDstField(matchers *ofctrl.Matchers, isIPv6 bool) *ofctrl.MatchField {
	if isIPv6 {
		return matchers.GetMatchByName(fmt.Sprintf("NXM_NX_TUN_IPV6_DST"))
	}
	return matchers.GetMatchByName(fmt.Sprintf("NXM_NX_TUN_IPV4_DST"))
}

func getRegValue(regMatch *ofctrl.MatchField, rng *openflow13.NXRange) (uint32, error) {
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

func getNetworkPolicyObservation(tableID uint8, ingress bool) *crdv1alpha1.Observation {
	ob := new(crdv1alpha1.Observation)
	ob.Component = crdv1alpha1.ComponentNetworkPolicy
	if ingress {
		switch tableID {
		case uint8(openflow.IngressMetricTable), uint8(openflow.IngressDefaultTable):
			// Packet dropped by ANP/default drop rule
			ob.ComponentInfo = openflow.GetFlowTableName(binding.TableIDType(tableID))
			ob.Action = crdv1alpha1.ActionDropped
		default:
			ob.ComponentInfo = openflow.GetFlowTableName(openflow.IngressRuleTable)
			ob.Action = crdv1alpha1.ActionForwarded
		}
	} else {
		switch tableID {
		case uint8(openflow.EgressMetricTable), uint8(openflow.EgressDefaultTable):
			// Packet dropped by ANP/default drop rule
			ob.ComponentInfo = openflow.GetFlowTableName(binding.TableIDType(tableID))
			ob.Action = crdv1alpha1.ActionDropped
		default:
			ob.ComponentInfo = openflow.GetFlowTableName(openflow.EgressRuleTable)
			ob.Action = crdv1alpha1.ActionForwarded
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

func parseCapturedPacket(pktIn *ofctrl.PacketIn) *crdv1alpha1.Packet {
	pkt, _ := binding.ParsePacketIn(pktIn)
	capturedPacket := crdv1alpha1.Packet{SrcIP: pkt.SourceIP.String(), DstIP: pkt.DestinationIP.String(), Length: pkt.IPLength}
	if pkt.IsIPv6 {
		ipProto := int32(pkt.IPProto)
		capturedPacket.IPv6Header = &crdv1alpha1.IPv6Header{NextHeader: &ipProto, HopLimit: int32(pkt.TTL)}
	} else {
		capturedPacket.IPHeader.Protocol = int32(pkt.IPProto)
		capturedPacket.IPHeader.TTL = int32(pkt.TTL)
		capturedPacket.IPHeader.Flags = int32(pkt.IPFlags)
	}
	if pkt.IPProto == protocol.Type_TCP {
		capturedPacket.TransportHeader.TCP = &crdv1alpha1.TCPHeader{SrcPort: int32(pkt.SourcePort), DstPort: int32(pkt.DestinationPort), Flags: int32(pkt.TCPFlags)}
	} else if pkt.IPProto == protocol.Type_UDP {
		capturedPacket.TransportHeader.UDP = &crdv1alpha1.UDPHeader{SrcPort: int32(pkt.SourcePort), DstPort: int32(pkt.DestinationPort)}
	} else if pkt.IPProto == protocol.Type_ICMP || pkt.IPProto == protocol.Type_IPv6ICMP {
		capturedPacket.TransportHeader.ICMP = &crdv1alpha1.ICMPEchoRequestHeader{ID: int32(pkt.ICMPEchoID), Sequence: int32(pkt.ICMPEchoSeq)}
	}
	return &capturedPacket
}
