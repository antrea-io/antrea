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

package config

import "strings"

type LoadBalancerMode int

const (
	LoadBalancerModeNAT LoadBalancerMode = iota
	LoadBalancerModeDSR
	LoadBalancerModeInvalid = -1
)

var (
	loadBalancerModeStrs = [...]string{
		"NAT",
		"DSR",
	}
)

// GetLoadBalancerModeFromStr returns true and LoadBalancerMode corresponding to input string.
// Otherwise, false and undefined value is returned
func GetLoadBalancerModeFromStr(str string) (bool, LoadBalancerMode) {
	for idx, ms := range loadBalancerModeStrs {
		if strings.EqualFold(ms, str) {
			return true, LoadBalancerMode(idx)
		}
	}
	return false, LoadBalancerModeInvalid
}

// String returns value in string.
func (m LoadBalancerMode) String() string {
	if m == LoadBalancerModeInvalid {
		return "invalid"
	}
	return loadBalancerModeStrs[m]
}
