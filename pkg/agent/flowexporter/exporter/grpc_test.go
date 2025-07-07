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

package exporter

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowexportertesting "antrea.io/antrea/pkg/agent/flowexporter/testing"
	flowpb "antrea.io/antrea/pkg/apis/flow/v1alpha1"
)

// TODO: more comprehensive testing needed

func TestGRPCExporterCreateMessage(t *testing.T) {
	conn := flowexportertesting.GetConnection(false, true, 302, 6, "ESTABLISHED")
	exp := &grpcExporter{
		nodeName:    "this-node",
		obsDomainID: 0xabcd,
	}
	msg := exp.createMessage(conn)
	expectedMsg := &flowpb.Flow{
		Ipfix: &flowpb.IPFIX{
			ObservationDomainId: 0xabcd,
		},
		StartTs:   timestamppb.New(time.Time{}),
		EndTs:     timestamppb.New(time.Time{}),
		EndReason: flowpb.FlowEndReason_FLOW_END_REASON_IDLE_TIMEOUT,
		Ip: &flowpb.IP{
			Version:     flowpb.IPVersion_IP_VERSION_4,
			Source:      netip.MustParseAddr("1.2.3.4").AsSlice(),
			Destination: netip.MustParseAddr("4.3.2.1").AsSlice(),
		},
		Transport: &flowpb.Transport{
			SourcePort:      65280,
			DestinationPort: 255,
			ProtocolNumber:  6,
			Protocol: &flowpb.Transport_TCP{
				TCP: &flowpb.TCP{
					StateName: "ESTABLISHED",
				},
			},
		},
		K8S: &flowpb.Kubernetes{
			FlowType:                      flowpb.FlowType_FLOW_TYPE_INTER_NODE,
			SourcePodNamespace:            "ns",
			SourcePodName:                 "pod",
			SourceNodeName:                "this-node",
			EgressNetworkPolicyNamespace:  "ns",
			EgressNetworkPolicyName:       "np",
			EgressNetworkPolicyType:       flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_K8S,
			EgressNetworkPolicyRuleAction: flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_ALLOW,
			DestinationServicePortName:    "service",
		},
		Stats: &flowpb.Stats{
			PacketTotalCount: 0xab,
			PacketDeltaCount: 0xab,
			OctetTotalCount:  0xabcd,
			OctetDeltaCount:  0xabcd,
		},
		ReverseStats: &flowpb.Stats{
			PacketTotalCount: 0xa,
			PacketDeltaCount: 0xa,
			OctetTotalCount:  0xab,
			OctetDeltaCount:  0xab,
		},
		App: &flowpb.App{},
	}
	msg.Ipfix.ExportTime = nil // need to reset this field as createMessage will use the current time from the system clock
	assert.Empty(t, cmp.Diff(expectedMsg, msg, protocmp.Transform()))
}
