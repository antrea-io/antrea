// Copyright 2019 Antrea Authors
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
	"net"
	"strings"
)

type TrafficEncapModeType int

const (
	TrafficEncapModeEncap TrafficEncapModeType = iota
	TrafficEncapModeNoEncap
	TrafficEncapModeHybrid
	TrafficEncapModeNetworkPolicyOnly
	TrafficEncapModeInvalid = -1
)

var (
	modeStrs = [...]string{
		"Encap",
		"NoEncap",
		"Hybrid",
		"NetworkPolicyOnly",
	}
)

// GetTrafficEncapModeFromStr returns true and TrafficEncapModeType corresponding to input string.
// Otherwise, false and undefined value is returned
func GetTrafficEncapModeFromStr(str string) (bool, TrafficEncapModeType) {
	for idx, ms := range modeStrs {
		if strings.EqualFold(ms, str) {
			return true, TrafficEncapModeType(idx)
		}
	}
	return false, TrafficEncapModeInvalid
}

func GetTrafficEncapModes() []TrafficEncapModeType {
	return []TrafficEncapModeType{
		TrafficEncapModeEncap,
		TrafficEncapModeNoEncap,
		TrafficEncapModeHybrid,
		TrafficEncapModeNetworkPolicyOnly,
	}
}

// String returns value in string.
func (m TrafficEncapModeType) String() string {
	return modeStrs[m]
}

// IsNetworkPolicyOnly returns true if TrafficEncapModeType is network policy only.
func (m TrafficEncapModeType) IsNetworkPolicyOnly() bool {
	return m == TrafficEncapModeNetworkPolicyOnly
}

// SupportsNoEncap returns true if TrafficEncapModeType supports noEncap.
func (m TrafficEncapModeType) SupportsNoEncap() bool {
	return m == TrafficEncapModeNoEncap || m == TrafficEncapModeHybrid || m.IsNetworkPolicyOnly()
}

// SupportsEncap returns true if TrafficEncapModeType supports encap.
func (m TrafficEncapModeType) SupportsEncap() bool {
	return m == TrafficEncapModeEncap || m == TrafficEncapModeHybrid
}

// NeedsEncapToPeer returns true if Pod traffic to peer Node needs to be encapsulated.
func (m TrafficEncapModeType) NeedsEncapToPeer(peerIP net.IP, localIP *net.IPNet) bool {
	return (m == TrafficEncapModeEncap) || (m == TrafficEncapModeHybrid && !localIP.Contains(peerIP))
}

// NeedsRoutingToPeer returns true if Pod traffic to peer Node needs underlying routing support.
func (m TrafficEncapModeType) NeedsRoutingToPeer(peerIP net.IP, localIP *net.IPNet) bool {
	return m == TrafficEncapModeNoEncap && !localIP.Contains(peerIP)
}
