// Copyright 2023 Antrea Authors
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

package v1beta1

import utilnet "k8s.io/utils/net"

func GetEgressCondition(conditions []EgressCondition, conditionType EgressConditionType) *EgressCondition {
	for idx := range conditions {
		c := &conditions[idx]
		if c.Type == conditionType {
			return c
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
	if !ignoringGateway {
		if a.Gateway != b.Gateway {
			return false
		}
	}
	if a.VLAN != b.VLAN || a.PrefixLength != b.PrefixLength || len(a.IPFamilySubnets) != len(b.IPFamilySubnets) {
		return false
	}
	for _, subnetA := range a.IPFamilySubnets {
		found := false
		for _, subnetB := range b.IPFamilySubnets {
			if utilnet.IPFamilyOfString(subnetA.Gateway) != utilnet.IPFamilyOfString(subnetB.Gateway) {
				continue
			}
			if subnetA.PrefixLength == subnetB.PrefixLength && (ignoringGateway || subnetA.Gateway == subnetB.Gateway) {
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
