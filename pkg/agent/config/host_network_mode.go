// Copyright 2025 Antrea Authors
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

type HostNetworkMode int

const (
	HostNetworkModeIPTables HostNetworkMode = iota
	HostNetworkModeNFTables
	HostNetworkModeInvalid = -1
)

var (
	hostNetworkModeStrs = [...]string{
		"iptables",
		"nftables",
	}
)

// GetHostNetworkModeFromStr returns true and HostNetworkMode corresponding to input string.
// Otherwise, false and undefined value is returned
func GetHostNetworkModeFromStr(str string) (bool, HostNetworkMode) {
	for idx, ms := range hostNetworkModeStrs {
		if strings.EqualFold(ms, str) {
			return true, HostNetworkMode(idx)
		}
	}
	return false, HostNetworkModeInvalid
}

// String returns value in string.
func (m HostNetworkMode) String() string {
	if m == HostNetworkModeInvalid {
		return "invalid"
	}
	return hostNetworkModeStrs[m]
}
