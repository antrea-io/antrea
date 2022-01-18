// Copyright 2022 Antrea Authors
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

package types

import (
	"strings"
)

type AgentRole string

const (
	CNIAgent AgentRole = "NODE"
	VMAgent  AgentRole = "VM"
	BMAgent  AgentRole = "BM"
)

func GetAgentRole(role string) AgentRole {
	return AgentRole(strings.ToUpper(role))
}

func IsValidRole(role string) bool {
	for _, r := range []string{
		string(CNIAgent), string(VMAgent), string(BMAgent),
	} {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	return false
}
