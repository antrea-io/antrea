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
	IANAInfoElementsIPv4    = append(IANAInfoElementsCommon, []string{"sourceIPv4Address", "destinationIPv4Address"}...)
	IANAInfoElementsIPv6    = append(IANAInfoElementsCommon, []string{"sourceIPv6Address", "destinationIPv6Address"}...)
	IANAReverseInfoElements = []string{
		"reversePacketTotalCount",
		"reverseOctetTotalCount",
		"reversePacketDeltaCount",
		"reverseOctetDeltaCount",
	}

	AntreaInfoElementsCommon = []string{
		"sourcePodName",
		"sourcePodNamespace",
		"sourceNodeName",
		"destinationPodName",
		"destinationPodNamespace",
		"destinationNodeName",
		"destinationServicePort",
		"destinationServicePortName",
		"ingressNetworkPolicyName",
		"ingressNetworkPolicyNamespace",
		"ingressNetworkPolicyType",
		"ingressNetworkPolicyRuleName",
		"ingressNetworkPolicyRuleAction",
		"egressNetworkPolicyName",
		"egressNetworkPolicyNamespace",
		"egressNetworkPolicyType",
		"egressNetworkPolicyRuleName",
		"egressNetworkPolicyRuleAction",
		"tcpState",
		"flowType",
		"egressName",
		"egressIP",
		"appProtocolName",
		"httpVals",
		"egressNodeName",
	}
	AntreaInfoElementsIPv4 = append(AntreaInfoElementsCommon, []string{"destinationClusterIPv4"}...)
	AntreaInfoElementsIPv6 = append(AntreaInfoElementsCommon, []string{"destinationClusterIPv6"}...)

	NonStatsElementList = []string{
		"flowEndSeconds",
		"flowEndReason",
		"tcpState",
		"httpVals",
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
)
