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

package config

import (
	"strings"
)

type TrafficEncryptionModeType int

const (
	TrafficEncryptionModeNone TrafficEncryptionModeType = iota
	TrafficEncryptionModeIPSec
	TrafficEncryptionModeWireGuard
	TrafficEncryptionModeInvalid = -1
)

var (
	encryptionModeStrs = [...]string{
		"None",
		"IPsec",
		"WireGuard",
	}
)

// GetTrafficEncryptionModeFromStr returns true and TrafficEncryptionModeType corresponding to input string.
// Otherwise, false and undefined value is returned
func GetTrafficEncryptionModeFromStr(str string) (bool, TrafficEncryptionModeType) {
	for idx, ms := range encryptionModeStrs {
		if strings.EqualFold(ms, str) {
			return true, TrafficEncryptionModeType(idx)
		}
	}
	return false, TrafficEncryptionModeInvalid
}

func GetTrafficEncryptionModes() []TrafficEncryptionModeType {
	return []TrafficEncryptionModeType{
		TrafficEncryptionModeNone,
		TrafficEncryptionModeIPSec,
		TrafficEncryptionModeWireGuard,
	}
}

// String returns value in string.
func (m TrafficEncryptionModeType) String() string {
	if m == TrafficEncryptionModeInvalid {
		return "invalid"
	}
	return encryptionModeStrs[m]
}
