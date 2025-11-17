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

package testing

import (
	"net/netip"
	"time"

	"github.com/google/uuid"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
)

func GetConnection(isIPv6 bool, isPresent bool, statusFlag uint32, protoID uint8, tcpState string) *connection.Connection {
	var tuple connection.Tuple
	if !isIPv6 {
		tuple = connection.Tuple{SourceAddress: netip.MustParseAddr("1.2.3.4"), DestinationAddress: netip.MustParseAddr("4.3.2.1"), Protocol: protoID, SourcePort: 65280, DestinationPort: 255}
	} else {
		srcIP := netip.MustParseAddr("2001:0:3238:dfe1:63::fefb")
		dstIP := netip.MustParseAddr("2001:0:3238:dfe1:63::fefc")
		tuple = connection.Tuple{SourceAddress: srcIP, DestinationAddress: dstIP, Protocol: protoID, SourcePort: 65280, DestinationPort: 255}
	}
	conn := &connection.Connection{
		StartTime:                      time.Time{},
		StopTime:                       time.Time{},
		StatusFlag:                     statusFlag,
		OriginalPackets:                0xab,
		OriginalBytes:                  0xabcd,
		ReversePackets:                 0xa,
		ReverseBytes:                   0xab,
		FlowKey:                        tuple,
		IsPresent:                      isPresent,
		SourcePodNamespace:             "ns",
		SourcePodName:                  "pod",
		SourcePodUID:                   uuid.New().String(),
		DestinationPodNamespace:        "",
		DestinationPodName:             "",
		IngressNetworkPolicyName:       "",
		IngressNetworkPolicyNamespace:  "",
		IngressNetworkPolicyType:       utils.PolicyTypeUnspecified,
		IngressNetworkPolicyRuleName:   "",
		IngressNetworkPolicyRuleAction: utils.NetworkPolicyRuleActionNoAction,
		EgressNetworkPolicyName:        "np",
		EgressNetworkPolicyNamespace:   "ns",
		EgressNetworkPolicyUID:         uuid.New().String(),
		EgressNetworkPolicyType:        utils.PolicyTypeK8sNetworkPolicy,
		EgressNetworkPolicyRuleName:    "",
		EgressNetworkPolicyRuleAction:  utils.NetworkPolicyRuleActionAllow,
		DestinationServicePortName:     "service",
		TCPState:                       tcpState,
		FlowType:                       utils.FlowTypeInterNode,
		EgressName:                     "my-egress",
		EgressUID:                      uuid.New().String(),
		EgressNodeName:                 "egress-node",
	}
	return conn
}

func GetDenyConnection(isIPv6 bool, protoID uint8) *connection.Connection {
	var tuple, _ connection.Tuple
	if !isIPv6 {
		tuple = connection.Tuple{SourceAddress: netip.MustParseAddr("1.2.3.4"), DestinationAddress: netip.MustParseAddr("4.3.2.1"), Protocol: protoID, SourcePort: 65280, DestinationPort: 255}
	} else {
		srcIP := netip.MustParseAddr("2001:0:3238:dfe1:63::fefb")
		dstIP := netip.MustParseAddr("2001:0:3238:dfe1:63::fefc")
		tuple = connection.Tuple{SourceAddress: srcIP, DestinationAddress: dstIP, Protocol: protoID, SourcePort: 65280, DestinationPort: 255}
	}
	now := time.Now()
	conn := &connection.Connection{
		FlowKey:         tuple,
		SourcePodName:   "pod",
		IsDenyFlow:      true,
		StartTime:       now,
		StopTime:        now,
		OriginalPackets: 1,
	}
	return conn
}
