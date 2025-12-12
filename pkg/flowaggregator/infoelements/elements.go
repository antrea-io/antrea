// Copyright 2022 Antrea Authors
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

package infoelements

var (
	IANAInfoElementsCommon = []string{
		"flowStartSeconds",
		"flowEndSeconds",
		"flowEndReason",
		"sourceTransportPort",
		"destinationTransportPort",
		"protocolIdentifier",
		"packetTotalCount",
		"octetTotalCount",
		"packetDeltaCount",
		"octetDeltaCount",
	}

	IANAReverseInfoElements = []string{
		"reversePacketTotalCount",
		"reverseOctetTotalCount",
		"reversePacketDeltaCount",
		"reverseOctetDeltaCount",
	}

	StatsElementList = []string{
		"octetDeltaCount",
		"octetTotalCount",
		"packetDeltaCount",
		"packetTotalCount",
		"reverseOctetDeltaCount",
		"reverseOctetTotalCount",
		"reversePacketDeltaCount",
		"reversePacketTotalCount",
	}
	AntreaSourceStatsElementList = []string{
		"octetDeltaCountFromSourceNode",
		"octetTotalCountFromSourceNode",
		"packetDeltaCountFromSourceNode",
		"packetTotalCountFromSourceNode",
		"reverseOctetDeltaCountFromSourceNode",
		"reverseOctetTotalCountFromSourceNode",
		"reversePacketDeltaCountFromSourceNode",
		"reversePacketTotalCountFromSourceNode",
	}
	AntreaDestinationStatsElementList = []string{
		"octetDeltaCountFromDestinationNode",
		"octetTotalCountFromDestinationNode",
		"packetDeltaCountFromDestinationNode",
		"packetTotalCountFromDestinationNode",
		"reverseOctetDeltaCountFromDestinationNode",
		"reverseOctetTotalCountFromDestinationNode",
		"reversePacketDeltaCountFromDestinationNode",
		"reversePacketTotalCountFromDestinationNode",
	}

	AntreaLabelsElementList = []string{
		"sourcePodLabels",
		"destinationPodLabels",
	}
	AntreaFlowEndSecondsElementList = []string{
		"flowEndSecondsFromSourceNode",
		"flowEndSecondsFromDestinationNode",
	}
	AntreaThroughputElementList = []string{
		"throughput",
		"reverseThroughput",
	}
	AntreaSourceThroughputElementList = []string{
		"throughputFromSourceNode",
		"reverseThroughputFromSourceNode",
	}
	AntreaDestinationThroughputElementList = []string{
		"throughputFromDestinationNode",
		"reverseThroughputFromDestinationNode",
	}

	IANAProxyModeElementList = []string{
		"originalObservationDomainId",
		"originalExporterIPv4Address",
		"originalExporterIPv6Address",
		"flowDirection",
	}
)

func IANAInfoElements(isIPv6 bool) []string {
	var ies []string
	if isIPv6 {
		ies = append(IANAInfoElementsCommon, "sourceIPv6Address", "destinationIPv6Address")
	} else {
		ies = append(IANAInfoElementsCommon, "sourceIPv4Address", "destinationIPv4Address")
	}
	return ies
}

func AntreaInfoElements(includeK8sNames, includeK8sUIDs, isIPv6 bool) []string {
	ies := make([]string, 0)
	if includeK8sNames {
		ies = append(ies, "sourcePodName", "sourcePodNamespace")
	}
	if includeK8sUIDs {
		ies = append(ies, "sourcePodUUID")
	}
	if includeK8sNames {
		ies = append(ies, "sourceNodeName")
	}
	if includeK8sUIDs {
		ies = append(ies, "sourceNodeUUID")
	}
	if includeK8sNames {
		ies = append(ies, "destinationPodName", "destinationPodNamespace")
	}
	if includeK8sUIDs {
		ies = append(ies, "destinationPodUUID")
	}
	if includeK8sNames {
		ies = append(ies, "destinationNodeName")
	}
	if includeK8sUIDs {
		ies = append(ies, "destinationNodeUUID")
	}
	ies = append(ies, "destinationServicePort")
	if includeK8sNames {
		ies = append(ies, "destinationServicePortName")
	}
	if includeK8sUIDs {
		ies = append(ies, "destinationServiceUUID")
	}
	if includeK8sNames {
		ies = append(ies, "ingressNetworkPolicyName", "ingressNetworkPolicyNamespace")
	}
	if includeK8sUIDs {
		ies = append(ies, "ingressNetworkPolicyUUID")
	}
	ies = append(ies, "ingressNetworkPolicyType")
	// rule name is meaningless unless either the policy name or UID is included.
	if includeK8sNames || includeK8sUIDs {
		ies = append(ies, "ingressNetworkPolicyRuleName")
	}
	ies = append(ies, "ingressNetworkPolicyRuleAction")
	if includeK8sNames {
		ies = append(ies, "egressNetworkPolicyName", "egressNetworkPolicyNamespace")
	}
	if includeK8sUIDs {
		ies = append(ies, "egressNetworkPolicyUUID")
	}
	ies = append(ies, "egressNetworkPolicyType")
	if includeK8sNames || includeK8sUIDs {
		ies = append(ies, "egressNetworkPolicyRuleName")
	}
	ies = append(ies, "egressNetworkPolicyRuleAction")
	ies = append(ies, "tcpState", "flowType")
	if includeK8sNames {
		ies = append(ies, "egressName")
	}
	if includeK8sUIDs {
		ies = append(ies, "egressUUID")
	}
	ies = append(ies, "egressIP")
	if includeK8sNames {
		ies = append(ies, "egressNodeName")
	}
	if includeK8sUIDs {
		ies = append(ies, "egressNodeUUID")
	}
	if isIPv6 {
		ies = append(ies, "destinationClusterIPv6")
	} else {
		ies = append(ies, "destinationClusterIPv4")
	}
	return ies
}
