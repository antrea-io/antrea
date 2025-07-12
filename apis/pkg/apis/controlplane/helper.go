// Copyright 2020 Antrea Authors
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

package controlplane

import "fmt"

func (r *NetworkPolicyReference) ToString() string {
	if r.Type == AntreaClusterNetworkPolicy {
		return fmt.Sprintf("%s:%s", r.Type, r.Name)
	}
	return fmt.Sprintf("%s:%s/%s", r.Type, r.Namespace, r.Name)
}

func (r *GroupReference) ToGroupName() string {
	if r.Namespace == "" {
		return r.Name
	}
	return fmt.Sprintf("%s/%s", r.Namespace, r.Name)
}

// ToTypedString returns the Group or ClusterGroup namespaced name as a string along with its type.
// Typed strings are typically used in log messages.
func (r *GroupReference) ToTypedString() string {
	if r.Namespace == "" {
		return fmt.Sprintf("ClusterGroup:%s", r.Name)
	}
	return fmt.Sprintf("Group:%s/%s", r.Namespace, r.Name)
}

func IsSourceAntreaNativePolicy(npRef *NetworkPolicyReference) bool {
	return npRef.Type == AntreaClusterNetworkPolicy || npRef.Type == AntreaNetworkPolicy
}
