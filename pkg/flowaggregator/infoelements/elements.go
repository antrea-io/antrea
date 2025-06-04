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

import (
	"iter"

	"antrea.io/antrea/pkg/apis/ipfix"
)

func FlowExporterElements(isIPv6 bool) iter.Seq2[int, ipfix.InfoElement] {
	return ipfix.AllInfoElementsIter(isIPv6)
}

var (
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

	IANAProxyModeElementList = []string{
		"originalObservationDomainId",
		"originalExporterIPv4Address",
		"originalExporterIPv6Address",
		"flowDirection",
	}
)
