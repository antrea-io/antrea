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

// DSRDispatch is how the ingress Node sends the traffic of a DSR Service to the Node hosting the selected Endpoint.
type DSRDispatch int

const (
	// DSRDispatchTunnel encapsulates the traffic and sends it through the tunnel interface.
	DSRDispatchTunnel DSRDispatch = iota
	// DSRDispatchL2 sends the traffic unmodified to the MAC address of the Node, which must be in the local
	// transport subnet.
	DSRDispatchL2
	DSRDispatchInvalid = -1
)

var (
	dsrDispatchStrs = [...]string{
		"tunnel",
		"l2",
	}
)

// GetDSRDispatchFromStr returns true and the DSRDispatch corresponding to the input string. Otherwise, false and an
// undefined value are returned.
func GetDSRDispatchFromStr(str string) (bool, DSRDispatch) {
	for idx, ds := range dsrDispatchStrs {
		if strings.EqualFold(ds, str) {
			return true, DSRDispatch(idx)
		}
	}
	return false, DSRDispatchInvalid
}

// String returns the value in string.
func (d DSRDispatch) String() string {
	if d == DSRDispatchInvalid {
		return "invalid"
	}
	return dsrDispatchStrs[d]
}
