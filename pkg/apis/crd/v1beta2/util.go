// Copyright 2026 Antrea Authors
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

package v1beta2

import utilnet "k8s.io/utils/net"

func GetEgressCondition(conditions []EgressCondition, conditionType EgressConditionType) *EgressCondition {
	for idx := range conditions {
		if conditions[idx].Type == conditionType {
			return &conditions[idx]
		}
	}
	return nil
}

func CompareSubnetInfo(a, b *SubnetInfo, ignoringGateway bool) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if !ignoringGateway && a.Gateway != b.Gateway {
		return false
	}
	return a.VLAN == b.VLAN && a.PrefixLength == b.PrefixLength
}

func CompareExternalIPPoolSubnetInfo(a, b *ExternalIPPoolSubnetInfo, ignoringGateway bool) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if !ignoringGateway && a.Gateway != b.Gateway {
		return false
	}
	if a.VLAN != b.VLAN || a.PrefixLength != b.PrefixLength || len(a.Gateways) != len(b.Gateways) {
		return false
	}
	for _, gatewayA := range a.Gateways {
		found := false
		for _, gatewayB := range b.Gateways {
			if utilnet.IPFamilyOfString(gatewayA.Gateway) != utilnet.IPFamilyOfString(gatewayB.Gateway) {
				continue
			}
			if gatewayA.PrefixLength == gatewayB.PrefixLength && (ignoringGateway || gatewayA.Gateway == gatewayB.Gateway) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
