// Copyright 2020 Antrea Authors
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

package flowexporter

import (
	"strconv"

	"github.com/vmware/go-ipfix/pkg/registry"

	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

const (
	connectionDyingFlag = uint32(1 << 9)
)

// NewConnectionKey creates 5-tuple of flow as connection key
func NewConnectionKey(conn *Connection) ConnectionKey {
	return ConnectionKey{conn.FlowKey.SourceAddress.String(),
		strconv.FormatUint(uint64(conn.FlowKey.SourcePort), 10),
		conn.FlowKey.DestinationAddress.String(),
		strconv.FormatUint(uint64(conn.FlowKey.DestinationPort), 10),
		strconv.FormatUint(uint64(conn.FlowKey.Protocol), 10),
	}
}

func IsConnectionDying(conn *Connection) bool {
	// "TIME_WAIT" state indicates local endpoint has closed the connection.
	// "CLOSE" state indicates closing RST flag is set and connection is closed.
	if conn.TCPState == "TIME_WAIT" || conn.TCPState == "CLOSE" {
		return true
	}
	// connections in other protocol with dying bit set
	if conn.TCPState == "" && (conn.StatusFlag&connectionDyingFlag != 0) {
		return true
	}
	// Connection no longer exists in conntrack table.
	if !conn.IsPresent {
		return true
	}
	return false
}

// RuleActionToUint8 converts network policy rule action to uint8.
func RuleActionToUint8(action string) uint8 {
	switch action {
	case "Allow":
		return registry.NetworkPolicyRuleActionAllow
	case "Drop":
		return registry.NetworkPolicyRuleActionDrop
	case "Reject":
		return registry.NetworkPolicyRuleActionReject
	default:
		return registry.NetworkPolicyRuleActionNoAction
	}
}

// policyTypeToUint8 converts NetworkPolicy type to uint8
func PolicyTypeToUint8(policyType v1beta2.NetworkPolicyType) uint8 {
	switch policyType {
	case v1beta2.K8sNetworkPolicy:
		return registry.PolicyTypeK8sNetworkPolicy
	case v1beta2.AntreaNetworkPolicy:
		return registry.PolicyTypeAntreaNetworkPolicy
	case v1beta2.AntreaClusterNetworkPolicy:
		return registry.PolicyTypeAntreaClusterNetworkPolicy
	default:
		return registry.PolicyTypeK8sNetworkPolicy
	}
}
