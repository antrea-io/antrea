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
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	opsv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

func (c *Controller) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	if !c.traceflowListerSynced() {
		return errors.New("traceflow controller is not started")
	}
	oldTf, nodeResult, err := c.parsePacketIn(pktIn)
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
		_, err = c.traceflowClient.OpsV1alpha1().Traceflows().UpdateStatus(context.TODO(), update, v1.UpdateOptions{})
		if err != nil {
			klog.Warningf("Update traceflow failed: %+v", err)
			return err
		}
		klog.Infof("Updated traceflow %s: %+v", tf.Name, nodeResult)
		return nil
	})
	if err != nil {
		klog.Errorf("Update traceflow error: %+v", err)
	}
	return err
}

func (c *Controller) parsePacketIn(pktIn *ofctrl.PacketIn) (*opsv1alpha1.Traceflow, *opsv1alpha1.NodeResult, error) {
	matchers := pktIn.GetMatches()
	var match *ofctrl.MatchField

	// Get data plane tag.
	// Directly read data plane tag from packet.
	var tag uint8
	if pktIn.Data.Ethertype == protocol.IPv4_MSG {
		ipPacket, ok := pktIn.Data.Data.(*protocol.IPv4)
		if !ok {
			return nil, nil, errors.New("invalid traceflow IPv4 packet")
		}
		tag = ipPacket.DSCP
	} else if pktIn.Data.Ethertype == protocol.IPv6_MSG {
		ipv6Packet, ok := pktIn.Data.Data.(*protocol.IPv6)
		if !ok {
			return nil, nil, errors.New("invalid traceflow IPv6 packet")
		}
		tag = ipv6Packet.TrafficClass >> 2
	} else {
		return nil, nil, fmt.Errorf("unsupported traceflow packet Ethertype: %d", pktIn.Data.Ethertype)
	}

	// Get traceflow CRD from cache by data plane tag.
	tf, err := c.GetRunningTraceflowCRD(uint8(tag))
	if err != nil {
		return nil, nil, err
	}

	obs := make([]opsv1alpha1.Observation, 0)
	isSender := c.isSender(uint8(tag))
	tableID := pktIn.TableId

	if isSender {
		ob := new(opsv1alpha1.Observation)
		ob.Component = opsv1alpha1.SpoofGuard
		ob.Action = opsv1alpha1.Forwarded
		obs = append(obs, *ob)
	} else {
		ob := new(opsv1alpha1.Observation)
		ob.Component = opsv1alpha1.Forwarding
		ob.Action = opsv1alpha1.Received
		ob.ComponentInfo = openflow.GetFlowTableName(openflow.ClassifierTable)
		obs = append(obs, *ob)
	}

	// Collect Service DNAT.
	ctNwDst := ""
	ipDst := ""
	switch pktIn.Data.Ethertype {
	case protocol.IPv4_MSG:
		ipPacket, ok := pktIn.Data.Data.(*protocol.IPv4)
		if !ok {
			return nil, nil, errors.New("invalid traceflow IPv4 packet")
		}
		ctNwDst, err = getCTDstValue(matchers, false)
		if err != nil {
			return nil, nil, err
		}
		ipDst = ipPacket.NWDst.String()
	case protocol.IPv6_MSG:
		ipPacket, ok := pktIn.Data.Data.(*protocol.IPv6)
		if !ok {
			return nil, nil, errors.New("invalid traceflow IPv6 packet")
		}
		ctNwDst, err = getCTDstValue(matchers, true)
		if err != nil {
			return nil, nil, err
		}
		ipDst = ipPacket.NWDst.String()
	default:
		return nil, nil, fmt.Errorf("unsupported traceflow packet ether type %d", pktIn.Data.Ethertype)
	}
	if isValidCtNw(ctNwDst) && ipDst != ctNwDst {
		ob := &opsv1alpha1.Observation{
			Component:       opsv1alpha1.LB,
			Action:          opsv1alpha1.Forwarded,
			TranslatedDstIP: ipDst,
		}
		obs = append(obs, *ob)
	}

	// Collect egress conjunctionID and get NetworkPolicy from cache.
	if match = getMatchRegField(matchers, uint32(openflow.EgressReg)); match != nil {
		egressInfo, err := getRegValue(match, nil)
		if err != nil {
			return nil, nil, err
		}
		ob := getNetworkPolicyObservation(tableID, false)
		npRef := c.networkPolicyQuerier.GetNetworkPolicyByRuleFlowID(egressInfo)
		if npRef != nil {
			ob.NetworkPolicy = npRef.ToString()
		}
		obs = append(obs, *ob)
	}

	// Collect ingress conjunctionID and get NetworkPolicy from cache.
	if match = getMatchRegField(matchers, uint32(openflow.IngressReg)); match != nil {
		ingressInfo, err := getRegValue(match, nil)
		if err != nil {
			return nil, nil, err
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
		if match = getMatchRegField(matchers, uint32(openflow.CNPDenyConjIDReg)); match != nil {
			notAllowConjInfo, err := getRegValue(match, nil)
			if err != nil {
				return nil, nil, err
			}
			npRef := c.networkPolicyQuerier.GetNetworkPolicyByRuleFlowID(notAllowConjInfo)
			if npRef != nil {
				ob.NetworkPolicy = npRef.ToString()
			}
		}
		obs = append(obs, *ob)
	} else if tableID == uint8(openflow.EgressDefaultTable) || tableID == uint8(openflow.IngressDefaultTable) {
		ob := getNetworkPolicyObservation(tableID, tableID == uint8(openflow.IngressDefaultTable))
		obs = append(obs, *ob)
	}

	// Get output table.
	if tableID == uint8(openflow.L2ForwardingOutTable) {
		ob := new(opsv1alpha1.Observation)
		tunnelDstIP := ""
		isIPv6 := c.nodeConfig.NodeIPAddr.IP.To4() == nil
		if match = getMatchTunnelDstField(matchers, isIPv6); match != nil {
			tunnelDstIP, err = getTunnelDstValue(match)
			if err != nil {
				return nil, nil, err
			}
		}
		var outputPort uint32
		if match = getMatchRegField(matchers, uint32(openflow.PortCacheReg)); match != nil {
			outputPort, err = getRegValue(match, nil)
			if err != nil {
				return nil, nil, err
			}
		}
		gatewayIP := c.nodeConfig.GatewayConfig.IPv4
		if pktIn.Data.Ethertype == protocol.IPv6_MSG {
			gatewayIP = c.nodeConfig.GatewayConfig.IPv6
		}
		if c.networkConfig.TrafficEncapMode.SupportsEncap() && outputPort == config.DefaultTunOFPort {
			ob.TunnelDstIP = tunnelDstIP
			ob.Action = opsv1alpha1.Forwarded
		} else if ipDst == gatewayIP.String() && outputPort == config.HostGatewayOFPort {
			ob.Action = opsv1alpha1.Delivered
		} else if c.networkConfig.TrafficEncapMode.SupportsEncap() && outputPort == config.HostGatewayOFPort {
			ob.Action = opsv1alpha1.ForwardedOutOfOverlay
		} else if outputPort == config.HostGatewayOFPort { // noEncap
			ob.Action = opsv1alpha1.Forwarded
		} else {
			// Output port is Pod port, packet is delivered.
			ob.Action = opsv1alpha1.Delivered
		}
		ob.ComponentInfo = openflow.GetFlowTableName(binding.TableIDType(tableID))
		ob.Component = opsv1alpha1.Forwarding
		obs = append(obs, *ob)
	}

	nodeResult := opsv1alpha1.NodeResult{Node: c.nodeConfig.Name, Timestamp: time.Now().Unix(), Observations: obs}
	return tf, &nodeResult, nil
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

func getNetworkPolicyObservation(tableID uint8, ingress bool) *opsv1alpha1.Observation {
	ob := new(opsv1alpha1.Observation)
	ob.Component = opsv1alpha1.NetworkPolicy
	if ingress {
		switch tableID {
		case uint8(openflow.IngressMetricTable), uint8(openflow.IngressDefaultTable):
			// Packet dropped by ANP/default drop rule
			ob.ComponentInfo = openflow.GetFlowTableName(binding.TableIDType(tableID))
			ob.Action = opsv1alpha1.Dropped
		default:
			ob.ComponentInfo = openflow.GetFlowTableName(openflow.IngressRuleTable)
			ob.Action = opsv1alpha1.Forwarded
		}
	} else {
		switch tableID {
		case uint8(openflow.EgressMetricTable), uint8(openflow.EgressDefaultTable):
			// Packet dropped by ANP/default drop rule
			ob.ComponentInfo = openflow.GetFlowTableName(binding.TableIDType(tableID))
			ob.Action = opsv1alpha1.Dropped
		default:
			ob.ComponentInfo = openflow.GetFlowTableName(openflow.EgressRuleTable)
			ob.Action = opsv1alpha1.Forwarded
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
