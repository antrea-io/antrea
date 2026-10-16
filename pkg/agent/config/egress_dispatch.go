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

package config

import "strings"

// EgressDispatch is how the Node of a Pod sends the Egress traffic of the Pod to the Egress Node, when the Egress IP
// is on another Node, in noEncap mode.
type EgressDispatch int

const (
	// EgressDispatchTunnel encapsulates the traffic and sends it through the tunnel interface.
	EgressDispatchTunnel EgressDispatch = iota
	// EgressDispatchL2 sends the traffic unchanged to the MAC address of the Egress Node, with the l2 dispatch.
	EgressDispatchL2
	EgressDispatchInvalid = -1
)

var (
	egressDispatchStrs = [...]string{
		"tunnel",
		"l2",
	}
)

// GetEgressDispatchFromStr returns true and the EgressDispatch corresponding to the input string, which is not case
// sensitive. Otherwise, false and EgressDispatchInvalid are returned.
func GetEgressDispatchFromStr(str string) (bool, EgressDispatch) {
	for idx, ds := range egressDispatchStrs {
		if strings.EqualFold(ds, str) {
			return true, EgressDispatch(idx)
		}
	}
	return false, EgressDispatchInvalid
}

// String returns the value in string.
func (d EgressDispatch) String() string {
	if d == EgressDispatchInvalid {
		return "invalid"
	}
	return egressDispatchStrs[d]
}
