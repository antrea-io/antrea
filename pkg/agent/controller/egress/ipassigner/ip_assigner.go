// Copyright 2021 Antrea Authors
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

package ipassigner

import "k8s.io/apimachinery/pkg/util/sets"

// IPAssigner provides methods to assign or unassign IP.
type IPAssigner interface {
	// AssignIP ensures the provided IP is assigned to the system.
	AssignIP(ip string) error
	// UnassignIP ensures the provided IP is not assigned to the system.
	UnassignIP(ip string) error
	// AssignedIPs return the IPs that are assigned to the system by this IPAssigner.
	AssignedIPs() sets.String
}
