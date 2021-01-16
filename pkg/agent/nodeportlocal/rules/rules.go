// +build !windows

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

package rules

// PodPortRules is an interface to abstract operations on rules for Pods
type PodPortRules interface {
	Init() error
	AddRule(port int, podip string) error
	DeleteRule(port int, podip string) error
	GetAllRules() (map[int]DestinationPodIPPort, error)
	DeleteAllRules() error
}

// InitRules initializes rules based on the underlying implementation
func InitRules() PodPortRules {
	// Currently we only support IPTABLES. Later this can be extended based on the system capability.
	return NewIPTableRules()
}
