// Copyright 2023 Antrea Authors
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

package flowlogger

import (
	"github.com/vmware/go-ipfix/pkg/registry"

	"antrea.io/antrea/pkg/util/ip"
)

func PrettyPrintRuleAction(action uint8) string {
	switch action {
	case registry.NetworkPolicyRuleActionNoAction:
		return ""
	case registry.NetworkPolicyRuleActionAllow:
		return "Allow"
	case registry.NetworkPolicyRuleActionDrop:
		return "Drop"
	case registry.NetworkPolicyRuleActionReject:
		return "Reject"
	default:
		return "Invalid"
	}
}

func PrettyPrintPolicyType(policyType uint8) string {
	switch policyType {
	case 0:
		return ""
	case registry.PolicyTypeK8sNetworkPolicy:
		return "K8sNetworkPolicy"
	case registry.PolicyTypeAntreaNetworkPolicy:
		return "AntreaNetworkPolicy"
	case registry.PolicyTypeAntreaClusterNetworkPolicy:
		return "AntreaClusterNetworkPolicy"
	default:
		return "Invalid"
	}
}

func PrettyPrintProtocolIdentifier(protocolID uint8) string {
	return ip.IPProtocolNumberToString(protocolID, "Unknown Protocol")
}
