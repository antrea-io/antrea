// Copyright 2025 Antrea Authors.
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

package connections

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/vmware/go-ipfix/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/util/ip"
)

var serviceProtocolMap = map[uint8]corev1.Protocol{
	6:   corev1.ProtocolTCP,
	17:  corev1.ProtocolUDP,
	132: corev1.ProtocolSCTP,
}

func lookupServiceProtocol(protoID uint8) (corev1.Protocol, error) {
	serviceProto, found := serviceProtocolMap[protoID]
	if !found {
		return "", fmt.Errorf("unknown protocol identifier: %d", protoID)
	}
	return serviceProto, nil
}

func (s *ConnStore) fillPodInfo(conn *connection.Connection) *connection.Connection {
	if conn == nil {
		return nil
	}

	if s.podStore == nil {
		klog.V(4).Info("Pod store is not available to retrieve local Pods information.")
		return nil
	}
	// sourceIP/destinationIP are mapped only to local pods and not remote pods.
	srcIP := conn.FlowKey.SourceAddress.String()
	dstIP := conn.FlowKey.DestinationAddress.String()

	srcPod, srcFound := s.podStore.GetPodByIPAndTime(srcIP, conn.StartTime)
	dstPod, dstFound := s.podStore.GetPodByIPAndTime(dstIP, conn.StartTime)
	if !srcFound && !dstFound {
		return nil
	}

	if srcFound {
		conn.SourcePodName = srcPod.Name
		conn.SourcePodNamespace = srcPod.Namespace
		conn.SourcePodUID = string(srcPod.UID)
	}
	if dstFound {
		conn.DestinationPodName = dstPod.Name
		conn.DestinationPodNamespace = dstPod.Namespace
		conn.DestinationPodUID = string(dstPod.UID)
	}

	return conn
}

func (s *ConnStore) fillServiceInfo(conn *connection.Connection) *connection.Connection {
	if conn == nil {
		return nil
	}

	if conn.Mark&openflow.ServiceCTMark.GetRange().ToNXRange().ToUint32Mask() != openflow.ServiceCTMark.GetValue() {
		return conn
	}

	clusterIP := conn.OriginalDestinationAddress.String()
	svcPort := conn.OriginalDestinationPort

	// What's the difference between the commented block and this? When it's an
	// conntrack connection it only supports very specific ones?
	protocol := ip.IPProtocolNumberToString(conn.FlowKey.Protocol, "UnknownProtocol")
	// protocol, err := lookupServiceProtocol(conn.FlowKey.Protocol)
	// if err != nil {
	// 	klog.InfoS("Could not retrieve Service protocol", "error", err)
	// 	return conn
	// }

	serviceStr := fmt.Sprintf("%s:%d/%s", clusterIP, svcPort, protocol)

	// resolve destination Service information
	if s.antreaProxier != nil {
		servicePortName, exists := s.antreaProxier.GetServiceByIP(serviceStr)
		if exists {
			conn.DestinationServicePortName = servicePortName.String()
		} else {
			klog.InfoS("Could not retrieve the Service info from antrea-agent-proxier", "serviceStr", serviceStr)
		}
	}

	return conn
}

func (s *ConnStore) fillNetworkPolicyMetadataInfo(conn *connection.Connection) *connection.Connection {
	if conn == nil {
		return nil
	}

	if conn.StartTime.Before(s.networkPolicyReadyTime) {
		return nil
	}

	if len(conn.Labels) == 0 {
		return conn
	}

	// Retrieve NetworkPolicy Name and Namespace by using the ingress and egress
	// IDs stored in the connection label.
	if klog.V(4).Enabled() {
		klog.InfoS("Setting NetworkPolicy metadata from connection labels", "labels", hex.EncodeToString(conn.Labels))
	}
	ingressOfID := binary.BigEndian.Uint32(conn.Labels[12:16])
	if ingressOfID != 0 {
		policy := s.networkPolicyQuerier.GetNetworkPolicyByRuleFlowID(ingressOfID)
		rule := s.networkPolicyQuerier.GetRuleByFlowID(ingressOfID)
		if policy == nil || rule == nil {
			// This should not happen because the rule flow ID to rule mapping is
			// preserved for max(5s, flowPollInterval) even after the rule deletion.
			klog.InfoS("Cannot find NetworkPolicy or rule", "ingressOfID", ingressOfID)
		} else {
			conn.IngressNetworkPolicyName = policy.Name
			conn.IngressNetworkPolicyNamespace = policy.Namespace
			conn.IngressNetworkPolicyUID = string(policy.UID)
			conn.IngressNetworkPolicyType = utils.PolicyTypeToUint8(policy.Type)
			conn.IngressNetworkPolicyRuleName = rule.Name
			conn.IngressNetworkPolicyRuleAction = registry.NetworkPolicyRuleActionAllow
		}
	}

	egressOfID := binary.BigEndian.Uint32(conn.Labels[8:12])
	if egressOfID != 0 {
		policy := s.networkPolicyQuerier.GetNetworkPolicyByRuleFlowID(egressOfID)
		rule := s.networkPolicyQuerier.GetRuleByFlowID(egressOfID)
		if policy == nil || rule == nil {
			// This should not happen because the rule flow ID to rule mapping is
			// preserved for max(5s, flowPollInterval) even after the rule deletion.
			klog.InfoS("Cannot find NetworkPolicy or rule", "egressOfID", egressOfID)
		} else {
			conn.EgressNetworkPolicyName = policy.Name
			conn.EgressNetworkPolicyNamespace = policy.Namespace
			conn.EgressNetworkPolicyUID = string(policy.UID)
			conn.EgressNetworkPolicyType = utils.PolicyTypeToUint8(policy.Type)
			conn.EgressNetworkPolicyRuleName = rule.Name
			conn.EgressNetworkPolicyRuleAction = registry.NetworkPolicyRuleActionAllow
		}
	}

	return conn
}

func (s *ConnStore) fillEgressInfo(conn *connection.Connection) *connection.Connection {
	if conn == nil {
		return nil
	}

	if conn.FlowType == utils.FlowTypeUnsupported {
		return conn
	}

	if conn.FlowType != utils.FlowTypeToExternal {
		return conn
	}

	if conn.SourcePodNamespace == "" || conn.SourcePodName == "" {
		return conn
	}

	egress, err := s.egressQuerier.GetEgress(conn.SourcePodNamespace, conn.SourcePodName)
	if err != nil {
		// Egress is not enabled or no Egress is applied to this Pod
		return conn
	}
	conn.EgressName = egress.Name
	conn.EgressUID = string(egress.UID)
	conn.EgressIP = egress.EgressIP
	conn.EgressNodeName = egress.EgressNode

	klog.V(5).InfoS("Filling Egress Info for flow", "Egress", conn.EgressName, "EgressIP", conn.EgressIP, "EgressNode", conn.EgressNodeName, "SourcePod", klog.KRef(conn.SourcePodNamespace, conn.SourcePodName))
	return conn
}

func (s *ConnStore) fillFlowType(conn *connection.Connection) *connection.Connection {
	if conn == nil {
		return nil
	}

	if s.isNetworkPolicyOnly {
		if conn.SourcePodName == "" || conn.DestinationPodName == "" {
			conn.FlowType = utils.FlowTypeInterNode
		} else {
			conn.FlowType = utils.FlowTypeIntraNode
		}
		return conn
	}

	if s.nodeRouteController == nil {
		klog.V(5).InfoS("Can't find flow type without nodeRouteController")
		conn.FlowType = utils.FlowTypeUnspecified
		return conn
	}

	srcIsPod, srcIsGw := s.nodeRouteController.LookupIPInPodSubnets(conn.FlowKey.SourceAddress)
	dstIsPod, dstIsGw := s.nodeRouteController.LookupIPInPodSubnets(conn.FlowKey.DestinationAddress)

	switch {
	case srcIsGw || dstIsGw:
		// This matches what we do in filterAntreaConns but is more general as we consider
		// remote gateways as well.
		klog.V(5).InfoS("Flows where the source or destination IP is a gateway IP will not be exported")
		conn.FlowType = utils.FlowTypeUnsupported
	case !srcIsPod:
		klog.V(5).InfoS("Flows where the source is not a Pod will not be exported")
		conn.FlowType = utils.FlowTypeUnsupported
	case !dstIsPod:
		conn.FlowType = utils.FlowTypeToExternal
	case conn.SourcePodName == "" || conn.DestinationPodName == "":
		conn.FlowType = utils.FlowTypeInterNode
	default:
		conn.FlowType = utils.FlowTypeIntraNode
	}
	return conn
}
