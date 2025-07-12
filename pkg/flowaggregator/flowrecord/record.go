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
package flowrecord
import (
	"encoding/json"
	"fmt"
	"net"
	"time"
	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)
type FlowRecord struct {
	FlowStartSeconds                     time.Time
	FlowEndSeconds                       time.Time
	FlowEndSecondsFromSourceNode         time.Time
	FlowEndSecondsFromDestinationNode    time.Time
	FlowEndReason                        uint8
	SourceIP                             string
	DestinationIP                        string
	SourceTransportPort                  uint16
	DestinationTransportPort             uint16
	ProtocolIdentifier                   uint8
	PacketTotalCount                     uint64
	OctetTotalCount                      uint64
	PacketDeltaCount                     uint64
	OctetDeltaCount                      uint64
	ReversePacketTotalCount              uint64
	ReverseOctetTotalCount               uint64
	ReversePacketDeltaCount              uint64
	ReverseOctetDeltaCount               uint64
	SourcePodName                        string
	SourcePodNamespace                   string
	SourceNodeName                       string
	DestinationPodName                   string
	DestinationPodNamespace              string
	DestinationNodeName                  string
	DestinationClusterIP                 string
	DestinationServicePort               uint16
	DestinationServicePortName           string
	IngressNetworkPolicyName             string
	IngressNetworkPolicyNamespace        string
	IngressNetworkPolicyRuleName         string
	IngressNetworkPolicyRuleAction       uint8
	IngressNetworkPolicyType             uint8
	EgressNetworkPolicyName              string
	EgressNetworkPolicyNamespace         string
	EgressNetworkPolicyRuleName          string
	EgressNetworkPolicyRuleAction        uint8
	EgressNetworkPolicyType              uint8
	TcpState                             string
	FlowType                             uint8
	SourcePodLabels                      string
	DestinationPodLabels                 string
	Throughput                           uint64
	ReverseThroughput                    uint64
	ThroughputFromSourceNode             uint64
	ThroughputFromDestinationNode        uint64
	ReverseThroughputFromSourceNode      uint64
	ReverseThroughputFromDestinationNode uint64
	EgressName                           string
	EgressIP                             string
	AppProtocolName                      string
	HttpVals                             string
	EgressNodeName                       string
}
// GetFlowRecord converts flowpb.Flow to FlowRecord.
// It assumes that record.Aggregation is set, so it should only be used in Aggregate mode.
func GetFlowRecord(record *flowpb.Flow) (*FlowRecord, error) {
	if record.Aggregation == nil {
		return nil, fmt.Errorf("aggregation section is unset")
	}
	var sourcePodLabels, destinationPodLabels string
	if record.K8S.SourcePodLabels != nil {
		// flow.K8S.SourcePodLabels.Labels can be nil or an empty map
		// both cases should be treated the same
		if len(record.K8S.SourcePodLabels.Labels) > 0 {
			b, err := json.Marshal(record.K8S.SourcePodLabels.Labels)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal sourcePodLabels: %w", err)
			} else {
				sourcePodLabels = string(b)
			}
		} else {
			sourcePodLabels = "{}"
		}
	}
	if record.K8S.DestinationPodLabels != nil {
		if len(record.K8S.DestinationPodLabels.Labels) > 0 {
			b, err := json.Marshal(record.K8S.DestinationPodLabels.Labels)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal destinationPodLabels: %w", err)
			} else {
				destinationPodLabels = string(b)
			}
		} else {
			destinationPodLabels = "{}"
		}
	}
	ipAddressAsString := func(bytes []byte) string {
		if len(bytes) == 0 {
			return ""
		}
		return net.IP(bytes).String()
	}
	return &FlowRecord{
		FlowStartSeconds:                  record.StartTs.AsTime(),
		FlowEndSeconds:                    record.EndTs.AsTime(),
		FlowEndSecondsFromSourceNode:      record.Aggregation.EndTsFromSource.AsTime(),
		FlowEndSecondsFromDestinationNode: record.Aggregation.EndTsFromDestination.AsTime(),
		FlowEndReason:                     uint8(record.EndReason),
		SourceIP:                          ipAddressAsString(record.Ip.Source),
		DestinationIP:                     ipAddressAsString(record.Ip.Destination),
		SourceTransportPort:               uint16(record.Transport.SourcePort),
		DestinationTransportPort:          uint16(record.Transport.DestinationPort),
		ProtocolIdentifier:                uint8(record.Transport.ProtocolNumber),
		PacketTotalCount:                  record.Stats.PacketTotalCount,
		OctetTotalCount:                   record.Stats.OctetTotalCount,
		PacketDeltaCount:                  record.Stats.PacketDeltaCount,
		OctetDeltaCount:                   record.Stats.OctetDeltaCount,
		ReversePacketTotalCount:           record.ReverseStats.PacketTotalCount,
		ReverseOctetTotalCount:            record.ReverseStats.OctetTotalCount,
		ReversePacketDeltaCount:           record.ReverseStats.PacketDeltaCount,
		ReverseOctetDeltaCount:            record.ReverseStats.OctetDeltaCount,
		SourcePodName:                     record.K8S.SourcePodName,
		SourcePodNamespace:                record.K8S.SourcePodNamespace,
		SourceNodeName:                    record.K8S.SourceNodeName,
		DestinationPodName:                record.K8S.DestinationPodName,
		DestinationPodNamespace:           record.K8S.DestinationPodNamespace,
		DestinationNodeName:               record.K8S.DestinationNodeName,
		DestinationClusterIP:              ipAddressAsString(record.K8S.DestinationClusterIp),
		DestinationServicePort:            uint16(record.K8S.DestinationServicePort),
		DestinationServicePortName:        record.K8S.DestinationServicePortName,
		IngressNetworkPolicyName:          record.K8S.IngressNetworkPolicyName,
		IngressNetworkPolicyNamespace:     record.K8S.IngressNetworkPolicyNamespace,
		IngressNetworkPolicyRuleName:      record.K8S.IngressNetworkPolicyRuleName,
		IngressNetworkPolicyRuleAction:    uint8(record.K8S.IngressNetworkPolicyRuleAction),
		IngressNetworkPolicyType:          uint8(record.K8S.IngressNetworkPolicyType),
		EgressNetworkPolicyName:           record.K8S.EgressNetworkPolicyName,
		EgressNetworkPolicyNamespace:      record.K8S.EgressNetworkPolicyNamespace,
		EgressNetworkPolicyRuleName:       record.K8S.EgressNetworkPolicyRuleName,
		EgressNetworkPolicyRuleAction:     uint8(record.K8S.EgressNetworkPolicyRuleAction),
		EgressNetworkPolicyType:           uint8(record.K8S.EgressNetworkPolicyType),
		// handles the case where the protocol is not TCP
		TcpState:                             record.Transport.GetTCP().GetStateName(),
		FlowType:                             uint8(record.K8S.FlowType),
		SourcePodLabels:                      sourcePodLabels,
		DestinationPodLabels:                 destinationPodLabels,
		Throughput:                           record.Aggregation.Throughput,
		ReverseThroughput:                    record.Aggregation.ReverseThroughput,
		ThroughputFromSourceNode:             record.Aggregation.ThroughputFromSource,
		ReverseThroughputFromSourceNode:      record.Aggregation.ReverseThroughputFromSource,
		ThroughputFromDestinationNode:        record.Aggregation.ThroughputFromDestination,
		ReverseThroughputFromDestinationNode: record.Aggregation.ReverseThroughputFromDestination,
		EgressName:                           record.K8S.EgressName,
		EgressIP:                             ipAddressAsString(record.K8S.EgressIp),
		AppProtocolName:                      record.App.ProtocolName,
		HttpVals:                             string(record.App.HttpVals),
		EgressNodeName:                       record.K8S.EgressNodeName,
	}, nil
}
