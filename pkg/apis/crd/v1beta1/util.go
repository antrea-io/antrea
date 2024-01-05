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

func GetEgressCondition(conditions []EgressCondition, conditionType EgressConditionType) *EgressCondition {
	for _, c := range conditions {
		if c.Type == conditionType {
			return &c
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
	return a.VLAN == b.VLAN && a.PrefixLength == b.PrefixLength
}
