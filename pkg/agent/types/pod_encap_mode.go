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

package types

import (
	"net"
	"strings"
)

type PodEncapMode int

const (
	PodEncapModeEncap PodEncapMode = iota
	PodEncapModeNoEncap
	PodEncapModeNoEncapMasq
	PodEncapModeHybrid
	PodEncapModeInvald = -1
)

var modeStrs = [...]string{
	"Encap",
	"NoEncap",
	"NoEncapMasq",
	"Hybrid",
}

// GetPodEncapModeFromStr returns true and PodEncapMode responding to input string.
// Otherwise, false and undefined value is returned
func GetPodEncapModeFromStr(str string) (bool, PodEncapMode) {
	for idx, ms := range modeStrs {
		if strings.ToLower(ms) == strings.ToLower(str) {
			return true, PodEncapMode(idx)
		}
	}
	return false, PodEncapModeInvald
}

func GetPodEncapModes() []PodEncapMode {
	return []PodEncapMode{
		PodEncapModeEncap,
		PodEncapModeNoEncap,
		PodEncapModeNoEncapMasq,
		PodEncapModeHybrid,
	}
}

func (m PodEncapMode) String() string {
	return modeStrs[m]
}

func (m PodEncapMode) SupportsNoEncap() bool {
	return m == PodEncapModeNoEncap || m == PodEncapModeNoEncapMasq || m == PodEncapModeHybrid
}

func (m PodEncapMode) SupportsEncap() bool {
	return m == PodEncapModeEncap || m == PodEncapModeHybrid
}

func (m PodEncapMode) UseTunnel(peerIP net.IP, localIP *net.IPNet) bool {
	return (m == PodEncapModeEncap) || (m == PodEncapModeHybrid && !localIP.Contains(peerIP))
}
