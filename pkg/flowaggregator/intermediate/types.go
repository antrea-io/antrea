// Copyright 2025 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package intermediate

import (
<<<<<<< HEAD
	flowpb "antrea.io/antrea/apis/pkg/apis/flow/v1alpha1"
=======
	flowpb "antrea.io/antrea/pkg/apis/flow/v1alpha1"
>>>>>>> origin/main
)

type FlowKey struct {
	SourceAddress      string
	DestinationAddress string
	Protocol           uint8
	SourcePort         uint16
	DestinationPort    uint16
}

type AggregationFlowRecord struct {
	Record *flowpb.Flow
	// Flow record contains mapping to its reference in priority queue.
	PriorityQueueItem *ItemToExpire
	// ReadyToSend is an indicator that we received all required records for the
	// given flow, i.e., records from source and destination nodes for the case
	// inter-node flow and record from the node for the case of intra-node flow.
	ReadyToSend               bool
	waitForReadyToSendRetries int
	// areCorrelatedFieldsFilled is an indicator for IPFIX Mediator to check whether K8s
	// metadata are filled for flow record. It is always true for Intra-Node
	// and ToExternal flows and only applicable for Inter-Node flows that are
	// not required to be correlated. (e.g. flows with Egress deny rule applied)
	areCorrelatedFieldsFilled bool
	// Some fields could be filled externally on aggregation records once before
	// exporting them in IPFIX mediator, e.g., metadata of a flow.
	// areExternalFieldsFilled is an indicator for IPFIX Mediator to check whether
	// these fields has been filled or not before exporting. This field is set to
	// false when creating new AggregationFlowRecord. Setting and utilizing this
	// field is upto the user and not used in go-ipfix library code.
	areExternalFieldsFilled bool
	// isIPv4 indicates whether the source and destination addresses are IPv4 or
	// IPv6 in the aggregated flow record.
	isIPv4 bool
}

type AggregationElements struct {
	NonStatsElements                   []string
	StatsElements                      []string
	AggregatedSourceStatsElements      []string
	AggregatedDestinationStatsElements []string
	AntreaFlowEndSecondsElements       []string
	ThroughputElements                 []string
	SourceThroughputElements           []string
	DestinationThroughputElements      []string
}

type FlowKeyRecordMapCallBack func(key FlowKey, record *AggregationFlowRecord) error
